#!/usr/bin/env python3

import os
import hashlib
import json
import shutil
import tempfile
import subprocess
import re
import time
from pathlib import Path
from datetime import datetime

TPOT_DATA = Path("/your/directory/to/tpot/data")  # Update this path to your TPOT data directory
YARA_RESULTS_DIR = Path("/your/directory/to/yara/results")  # Update this path to your YARA results directory
MALWARE_DIR = YARA_RESULTS_DIR / "your/directory/to/malware_files"  # Update this path to your malware files directory
METADATA_DIR = YARA_RESULTS_DIR / "your/directory/to/scan_metadata"  # Update this path to your scan metadata directory
HASH_DB = Path("/your/directory/to/processed_hashes.json")  # Update this path to your processed hashes database

LOKI_PATH = "your/directory/to/loki.py"  # Update this path to your Loki script
PYTHON_PATH = "your/directory/to/python3"  # Update this path to your Python executable

SCAN_RECENT_HOURS = 72
MAX_FILES_PER_SCAN = 100  # Max files per Loki scan

def load_processed_hashes():
    if HASH_DB.exists():
        try:
            return set(json.loads(HASH_DB.read_text().strip() or "[]"))
        except:
            return set()
    return set()

def save_processed_hashes(hashes):
    try:
        temp_fd, temp_path = tempfile.mkstemp(dir=HASH_DB.parent, prefix='.hash_', suffix='.json')
        with os.fdopen(temp_fd, 'w') as f:
            json.dump(list(hashes), f, indent=2)
        os.replace(temp_path, HASH_DB)
    except:
        pass

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None

def get_new_files(base_dir, hours, processed_hashes):
    """Get list of new files directly (not grouped by directory)"""
    print(f" Finding new files (last {hours}h)...")

    minutes = hours * 60

    try:
        result = subprocess.run(
            ['find', str(base_dir), '-type', 'f', '-mmin', f'-{minutes}',
             '!', '-name', '.*', '!', '-name', '*.result.json', '!', '-name', '*.llm.json'],
            capture_output=True, text=True, timeout=180
        )
        recent_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
    except:
        return []

    print(f"  Found {len(recent_files):,} recent files")

    new_files = []
    checked = 0

    # for each file f in D do:
    for filepath in recent_files:
        checked += 1
        if checked % 10000 == 0:
            print(f"  Checked: {checked:,}/{len(recent_files):,}")
        
        file_hash = get_file_hash(filepath) # h <-- SHA256(f)
        if file_hash and file_hash not in processed_hashes: # if h ∉ H then
            new_files.append(filepath)

    print(f" Found {len(new_files):,} new files")
    return new_files

def scan_batch_in_temp_dir(files_batch):
    """
    Copy files to temp directory and scan ONLY those files
    This avoids scanning entire source directory!
    """

    # Create temp directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Copy files to temp dir
        file_mapping = {}  # temp_name -> original_path

        for i, filepath in enumerate(files_batch):
            # Create unique temp filename
            ext = os.path.splitext(filepath)[1]
            temp_name = f"file_{i:05d}{ext}"
            temp_file = temp_path / temp_name

            try:
                shutil.copy2(filepath, temp_file)
                file_mapping[temp_name] = filepath
            except Exception as e:
                print(f"  Copy error: {e}")
                continue

        if not file_mapping:
            return {}

        # Scan temp directory
        cmd = [PYTHON_PATH, LOKI_PATH, "-p", str(temp_path), "--intense", "--noprocscan", "--printall"]

        try:
            timeout = min(60 + len(file_mapping) * 2, 300)  # 2 sec/file, max 5 min

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=os.path.dirname(LOKI_PATH)
            )

            stdout = result.stdout

        except subprocess.TimeoutExpired:
            print(f"  Timeout after {timeout}s")
            return {}
        except Exception as e:
            print(f" Error: {e}")
            return {}

        # Parse results
        detections = parse_loki_output(stdout)

        # Map temp filenames back to original paths
        original_detections = {}
        for detected_path, info in detections.items():
            temp_name = os.path.basename(detected_path)
            if temp_name in file_mapping:
                original_path = file_mapping[temp_name]
                original_detections[original_path] = info

        return original_detections

def parse_loki_output(output_text):
    """Parse Loki output"""
    results = {}

    if not output_text:
        return results

    lines = output_text.split('\n')
    current_level = None

    for line_num, line in enumerate(lines):
        line = line.strip()

        level_match = re.match(r'^\[(ALERT|WARNING|NOTICE)\]$', line, re.IGNORECASE)
        if level_match:
            current_level = level_match.group(1).upper()
            continue

        file_match = re.match(r'^FILE:\s*(.+?)(?:\s+SCORE:|\s*$)', line)
        if file_match:
            filepath = file_match.group(1).strip()
            alert_level = current_level if current_level else "WARNING"

            score = 0
            file_type = "UNKNOWN"
            rules = []

            score_match = re.search(r'SCORE:\s*(\d+)', line)
            if score_match:
                score = int(score_match.group(1))

            type_match = re.search(r'TYPE:\s*(\S+)', line)
            if type_match:
                file_type = type_match.group(1)

            for offset in range(1, min(20, len(lines) - line_num)):
                next_line = lines[line_num + offset].strip()
                reason_match = re.search(r'REASON_\d+:\s*Yara Rule MATCH:\s*(\S+)', next_line)
                if reason_match:
                    rule_name = reason_match.group(1)
                    if rule_name not in rules:
                        rules.append(rule_name)
                if next_line.startswith('FILE:') or \
                   re.match(r'^\[(ALERT|WARNING|NOTICE|INFO|RESULT)\]$', next_line):
                    break

            if rules or score >= 70:
                results[filepath] = {
                    "alert_level": alert_level,
                    "score": score,
                    "file_type": file_type,
                    "rules": rules if rules else ["loki_detection"],
                }

            current_level = None

    return results

def process_files_batch(files_batch, processed_hashes):
    """Process a batch of files"""

    print(f"\n Scanning batch of {len(files_batch)} files...")

    # Scan in temp directory
    detections = scan_batch_in_temp_dir(files_batch) # result ← LokiScan(f, R)

    malware_count = 0
    clean_count = 0

    # Process each file
    for filepath in files_batch:
        file_hash = get_file_hash(filepath)

        if not file_hash:
            continue

        filename = os.path.basename(filepath)

        # Check if detected
        if filepath in detections:     #if result.matched then
            detection_info = detections[filepath]

            # Save malware
            dest = MALWARE_DIR / filename
            counter = 1
            while dest.exists():
                name, ext = os.path.splitext(filename)
                dest = MALWARE_DIR / f"{name}_{counter}{ext}"
                counter += 1

            try:   #Copy f to malware_files/
                shutil.copy2(filepath, dest)
                malware_count += 1

                meta = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_path": str(filepath),
                    "file_hash": file_hash,
                    "file_size": os.path.getsize(filepath),
                    "detection": detection_info
                }
                #SaveMetadata(result) to scan_metadata/
                (METADATA_DIR / f"{file_hash[:16]}.json").write_text(json.dumps(meta, indent=2))

                print(f" {filename}: {detection_info['alert_level']} | Score: {detection_info['score']}")
                if detection_info.get('rules'):
                    print(f"     Rules: {', '.join(detection_info['rules'][:3])}")
            except Exception as e:
                print(f" Save error: {e}")
        else:
            clean_count += 1

        # H ← H ∪ {h}
        processed_hashes.add(file_hash)

    print(f" Results: {malware_count} malware, {clean_count} clean")
    return malware_count, clean_count

def main():
    start_time = time.time()

    print("="*70)
    print("SMART YARA SCANNER - Temp Directory Approach")
    print(f"Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    processed_hashes = load_processed_hashes()
    print(f"\n Already scanned: {len(processed_hashes):,} files")

    # Get new files
    new_files = get_new_files(TPOT_DATA, SCAN_RECENT_HOURS, processed_hashes)

    if not new_files:
        print("\n No new files to scan")
        return

    print(f"\n Total new files: {len(new_files):,}")
    print(f" Starting batch scan...\n")

    total_malware = 0
    total_clean = 0

    # Process in batches
    for i in range(0, len(new_files), MAX_FILES_PER_SCAN):
        batch = new_files[i:i + MAX_FILES_PER_SCAN]
        batch_num = i // MAX_FILES_PER_SCAN + 1
        total_batches = (len(new_files) + MAX_FILES_PER_SCAN - 1) // MAX_FILES_PER_SCAN

        print(f"[Batch {batch_num}/{total_batches}]", end=" ")

        malware, clean = process_files_batch(batch, processed_hashes)
        total_malware += malware
        total_clean += clean

        # Save progress
        if batch_num % 5 == 0:
            save_processed_hashes(processed_hashes)
            elapsed = time.time() - start_time
            rate = (total_malware + total_clean) / elapsed if elapsed > 0 else 0
            print(f"\n Progress: {total_malware} malware | {rate:.1f} files/sec\n")

    # Final save
    save_processed_hashes(processed_hashes)
    elapsed = time.time() - start_time

    print(f"\n{'='*70}")
    print(" COMPLETE")
    print(f"{'='*70}")
    print(f"  Files scanned: {total_malware + total_clean:,}")
    print(f"  Malware: {total_malware}")
    print(f"  Clean: {total_clean}")
    print(f"  Time: {elapsed:.1f}s")
    if total_malware + total_clean > 0:
        print(f" Speed: {(total_malware + total_clean)/elapsed:.1f} files/sec")
    print(f"  Total tracked: {len(processed_hashes):,}")
    print(f"{'='*70}")

if __name__ == "__main__":
    MALWARE_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Interrupted")
    except Exception as e:
        print(f"\n {e}")
        import traceback
        traceback.print_exc()