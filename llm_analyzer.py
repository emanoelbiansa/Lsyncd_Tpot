#!/usr/bin/env python3
import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path
import hashlib

# OpenAI
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("[ERROR] OpenAI package not installed!")
    print("        Install with: pip install openai")

# ── Config ─────────────────────────────────────
YARA_MATCHED_DIR = "/your/directory/path/for/yara_matched_files/"  # Directory where YARA-matched files are stored
LLM_ANALYSIS_DIR = "/your/directory/path/for/llm_analysis/"  # Directory to save LLM analysis results
PROCESSED_DIR    = "/your/directory/path/for/processed_files/"  # Directory to move processed files
METADATA_DIR     = "/your/directory/path/for/scan_metadata/"  # Directory where scan metadata is stored (for fallback)

# OpenAI Config
OPENAI_API_KEY = "your-openai-api-key"  # Set via: export OPENAI_API_KEY=sk-...
OPENAI_MODEL = "gpt-4o"

# Logging
LOG_FILE = "/your/directory/path/for/llm_analyzer.log" # Directory to store llm_analyzer logs

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── OpenAI Client ──────────────────────────────
if OPENAI_AVAILABLE and OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)
    log.info("OpenAI client initialized")
else:
    client = None
    if not OPENAI_API_KEY:
        log.error("OPENAI_API_KEY not set! Set it with: export OPENAI_API_KEY=sk-...")


# ── Helper Functions ───────────────────────────
def get_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest()
    }

#content ← ReadContent(f)
def read_file_content(filepath, max_bytes=5000):
    """Read file content (text or hex dump for binary)"""
    try:
        # Try as text
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(max_bytes)
            return content, "text"
    except:
        # Read as binary and hex dump
        with open(filepath, 'rb') as f:
            binary_data = f.read(max_bytes)
            hex_dump = binary_data.hex()
            # Also try to extract printable strings
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in binary_data)
            return f"HEX: {hex_dump[:1000]}\n\nPRINTABLE: {printable}", "binary"

#ctx ← LoadYARAContext(f)
def load_yara_result(filepath):
    result_file = filepath + ".result.json"
    if os.path.exists(result_file):
        with open(result_file, 'r') as f:
            return json.load(f)

    # Fallback: cari di scan_metadata/ pakai hash
    try:
        file_hash = get_file_hash(filepath)['sha256']
        meta_file = os.path.join(METADATA_DIR, f"{file_hash[:16]}.json")
        if os.path.exists(meta_file):
            with open(meta_file, 'r') as f:
                data = json.load(f)
                # Kembalikan dalam format yang diharapkan llm_analyzer
                return {"loki": data.get("detection", {})}
    except:
        pass

    return None


# ── LLM Analysis ───────────────────────────────
def analyze_with_llm(filepath, yara_result=None):
    """
    Send file to OpenAI for semantic analysis
    Returns: dict with MITRE tactics, techniques, risk score, etc.
    """
    if not client:
        log.error("OpenAI client not available")
        return {"error": "OpenAI client not initialized"}

    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    # Read file content
    content, content_type = read_file_content(filepath)

    # Build context from YARA results
    yara_context = ""
    if yara_result:
        loki_data = yara_result.get('loki', {})
        yara_context = f"""
YARA Detection Results:
- Alert Level: {loki_data.get('alert_level', 'UNKNOWN')}
- Score: {loki_data.get('score', 0)}
- Rules Matched: {', '.join(loki_data.get('rules', []))}
- File Type: {loki_data.get('file_type', 'UNKNOWN')}
"""

    # prompt ← BuildPrompt(content, ctx)
    prompt = f"""You are an expert malware analyst with extensive threat intelligence knowledge and deep understanding of the MITRE ATT&CK framework.

Analyze this honeypot-captured file. Be SPECIFIC about malware families.

**File Information:**
- Filename: {filename}
- Size: {file_size} bytes
- Content Type: {content_type}

{yara_context}

**File Content:**
```
{content}
```

**ANALYSIS REQUIREMENTS:**

1. **Malware Family Identification:**
   - If you recognize patterns: NAME THE SPECIFIC FAMILY
     Examples: "Mirai botnet variant", "c99 webshell", "Gafgyt/BASHLITE", "PHP.Backdoor.WSO"
   - Honeypot context clues:
     * SSH brute-force files → often botnet recruitment scripts
     * PHP/JSP files with shell_exec → likely webshells (identify: c99, r57, WSO, b374k, China Chopper, etc.)
     * ELF binaries with scanner code → IoT malware (Mirai, Hajime, etc.)
   - If uncertain but patterns exist: "Suspected [Family] - [key indicator]"
   - Generic fallback: "Generic [Type]" (e.g., "Generic Linux botnet", "Generic PHP backdoor")
   - Only use "Unknown" if TRULY unidentifiable

2. **MITRE ATT&CK Mapping (CRITICAL - Be Comprehensive!):**

   Map ALL observed malicious behaviors to MITRE tactics and techniques. Consider:

   **Common Tactics for Honeypot Captures:**
   - TA0001 Initial Access - How did attacker get in?
   - TA0002 Execution - What code runs?
   - TA0003 Persistence - Does it install backdoors?
   - TA0004 Privilege Escalation - Any privilege abuse?
   - TA0005 Defense Evasion - Obfuscation, encoding, anti-detection?
   - TA0006 Credential Access - Password dumping, brute-force?
   - TA0007 Discovery - System/network reconnaissance?
   - TA0008 Lateral Movement - Spreading to other systems?
   - TA0009 Collection - Data harvesting?
   - TA0010 Exfiltration - Data stealing?
   - TA0011 Command and Control - C2 communication?
   - TA0040 Impact - Destructive actions, ransomware, DDoS?

   **Common Techniques by File Type:**

   Web Shells (PHP/JSP/ASPX):
   - T1190: Exploit Public-Facing Application (Initial Access)
   - T1505.003: Web Shell (Persistence)
   - T1059.004: Unix Shell (if shell_exec, system, passthru)
   - T1027: Obfuscated Files or Information (if base64, eval)
   - T1071.001: Web Protocols (C2 via HTTP)
   - T1083: File and Directory Discovery (if file listing functions)
   - T1005: Data from Local System (if file read capabilities)

   Botnet/IoT Malware (ELF binaries):
   - T1078: Valid Accounts (if brute-force credentials)
   - T1110: Brute Force (password attacks)
   - T1059.004: Unix Shell (command execution)
   - T1046: Network Service Scanning (port scanning)
   - T1021: Remote Services (SSH, Telnet abuse)
   - T1071.001: Application Layer Protocol (C2)
   - T1498: Network Denial of Service (DDoS capability)
   - T1562.001: Impair Defenses: Disable or Modify Tools

   Cryptocurrency Miners:
   - T1496: Resource Hijacking
   - T1053: Scheduled Task/Job (cron persistence)
   - T1036: Masquerading (fake process names)

   **Extract from actual file content:**
   - Look for: network functions → T1071 (C2), T1071.001 (HTTP), T1071.004 (DNS)
   - Look for: file operations → T1083 (Discovery), T1005 (Collection), T1074 (Staging)
   - Look for: process creation → T1059 (Command Interpreter)
   - Look for: persistence mechanisms → T1053 (Cron), T1136 (Create Account), T1543 (Systemd)
   - Look for: credential functions → T1003 (Credential Dumping), T1555 (Credentials from Password Stores)

   **Be specific with subtechniques when applicable:**
   - Use T1059.004 for Unix Shell (not just T1059)
   - Use T1071.001 for HTTP C2 (not just T1071)
   - Use T1505.003 for Web Shell (not just T1505)

3. **IOC Extraction:**
   Parse file content for:
   - IP addresses (IPv4/IPv6)
   - Domain names
   - URLs (C2 servers, download sites)
   - Email addresses
   - File paths mentioned in code
   - Registry keys (for Windows malware)
   - Mutex names
   - Service names

4. **Technical Analysis:**
   Identify specific malicious functions:
   - PHP: shell_exec, system, eval, base64_decode, exec, passthru, proc_open
   - Python: os.system, subprocess, socket
   - Shell: wget, curl, nc, chmod, crontab
   - Network: socket, connect, bind, listen, sendto

**OUTPUT FORMAT (JSON SCHEMA):**
{{
  "malware_family": "<SPECIFIC name or 'Generic [Type]' or 'Unknown'>",
  "malware_variant": "<version/variant or null>",
  "attack_type": "<Botnet|Webshell|Ransomware|Miner|RAT|Trojan|Worm|Exploit|Backdoor|Downloader>",
  "attack_vector": "<SSH brute-force|Web exploit|RCE|File upload|SQL injection|Phishing|etc>",
  "risk_score": <0-100>,
  "confidence": "HIGH|MEDIUM|LOW",

  "attack_summary": "<3-4 sentences describing: 1) What is this malware? 2) What does it do? 3) How does it spread/persist? 4) What's the impact?>",

  "technical_analysis": {{
    "file_type_detected": "<ELF|PHP|Python|Shell|Perl|Ruby|ASP|ASPX|JSP|etc>",
    "malicious_functions": ["function1", "function2", "function3"],
    "communication_protocol": "<HTTP|HTTPS|IRC|DNS|TCP|UDP|custom|null>",
    "c2_infrastructure": "<description of C2 method or null>",
    "encryption_used": <true|false>,
    "obfuscation_detected": <true|false>,
    "obfuscation_methods": ["base64", "hex encoding", "string concatenation", "etc"]
  }},

  "mitre_tactics": [
    {{
      "id": "TA00XX",
      "name": "<Tactic Name>",
      "confidence": "HIGH|MEDIUM|LOW",
      "evidence": "<Brief explanation of why this tactic applies>"
    }}
  ],

  "mitre_techniques": [
    {{
      "id": "T1XXX",
      "name": "<Technique Name>",
      "subtechnique": "<T1XXX.YYY or null>",
      "subtechnique_name": "<Subtechnique name or null>",
      "evidence": "<Specific code/behavior that indicates this technique>"
    }}
  ],

  "iocs": {{
    "ips": ["x.x.x.x"],
    "domains": ["malicious.com"],
    "urls": ["http://evil.com/payload"],
    "file_hashes": ["{get_file_hash(filepath)['md5']}"],
    "file_paths": ["/tmp/malware", "/var/www/backdoor.php"],
    "email_addresses": [],
    "mutexes": [],
    "registry_keys": []
  }},

  "recommended_actions": [
    "<Immediate action 1>",
    "<Immediate action 2>",
    "<Investigation step 1>",
    "<Prevention measure 1>",
    "<Long-term remediation 1>"
  ]
}}

**IMPORTANT:**
- Include 1 MITRE tactics based on actual malware behavior
- Include 1 MITRE techniques with specific evidence
- Extract ALL observable IOCs from file content
- Be specific with technique IDs (use subtechniques like T1059.004, not just T1059)
- Provide evidence/reasoning for each MITRE mapping
- Do NOT use example values - analyze the ACTUAL file content
"""

    try:
        log.info(f"Sending to OpenAI: {filename}")
        # Send prompt to LLM via OpenAI API
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity malware analyst. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=2000
        )

        # response ← QueryGPT4o(prompt, K)
        llm_output = response.choices[0].message.content.strip()

        # Remove markdown code fences if present
        if llm_output.startswith("```json"):
            llm_output = llm_output[7:]
        if llm_output.startswith("```"):
            llm_output = llm_output[3:]
        if llm_output.endswith("```"):
            llm_output = llm_output[:-3]
        llm_output = llm_output.strip()

        # Parse JSON
        analysis = json.loads(llm_output)

        log.info(f"  Analysis complete: {filename}")
        log.info(f"  Family: {analysis.get('malware_family', 'Unknown')}")
        log.info(f"  Risk: {analysis.get('risk_score', 0)}/100")
        log.info(f"  MITRE Tactics: {len(analysis.get('mitre_tactics', []))}")

        return analysis

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse LLM JSON response: {e}")
        log.debug(f"Raw response: {llm_output[:500]}")
        return {
            "error": "JSON parse error",
            "raw_response": llm_output[:1000],
            "malware_family": "Unknown",
            "risk_score": 0
        }
    except Exception as e:
        log.error(f"LLM analysis error: {e}")
        return {
            "error": str(e),
            "malware_family": "Unknown",
            "risk_score": 0
        }


# ── Save Analysis ──────────────────────────────
# SaveJSON(response) to llm_analysis/
def save_analysis(filepath, analysis, yara_result=None):
    """Save LLM analysis to JSON file"""
    filename = os.path.basename(filepath)
    output_file = os.path.join(LLM_ANALYSIS_DIR, filename + ".llm.json")

    # Build complete report
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "file": {
            "name": filename,
            "path": filepath,
            "size": os.path.getsize(filepath),
            "sha256": get_file_hash(filepath)
        },
        "yara": yara_result,
        "llm_analysis": analysis
    }

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    log.info(f"Saved analysis: {output_file}")
    return output_file


# ── Move Processed File ───────────────────────
# Move f to llm_processed/
def move_to_processed(filepath):
    """Move file to processed directory after analysis"""
    filename = os.path.basename(filepath)
    dest = os.path.join(PROCESSED_DIR, filename)

    # Also move .result.json if exists
    result_file = filepath + ".result.json"

    os.rename(filepath, dest)

    if os.path.exists(result_file):
        os.rename(result_file, dest + ".result.json")

    log.info(f"Moved to processed: {filename}")


# ── Main Processing Loop ───────────────────────
def process_yara_matched_files():
    log.info("="*60)
    log.info("LLM Analyzer Started")
    log.info(f"Model: {OPENAI_MODEL}")
    log.info("="*60)

    # Get all files (exclude .result.json and .llm.json)
    files = [
        f for f in os.listdir(YARA_MATCHED_DIR)
        if os.path.isfile(os.path.join(YARA_MATCHED_DIR, f))
        and not f.endswith('.result.json')
        and not f.endswith('.llm.json')
    ]

    if not files:
        log.info("No files to analyze")
        return

    log.info(f"Found {len(files)} files to analyze")

    analyzed = 0
    failed = 0

    # for each file f in malware_files/ do
    for filename in files:
        filepath = os.path.join(YARA_MATCHED_DIR, filename)

        try:
            log.info(f"\n{'='*60}")
            log.info(f"Analyzing: {filename}")
            log.info(f"{'='*60}")

            # Load YARA results
            yara_result = load_yara_result(filepath)

            # Analyze with LLM
            analysis = analyze_with_llm(filepath, yara_result)

            # Save analysis
            save_analysis(filepath, analysis, yara_result)

            # Move to processed
            move_to_processed(filepath)

            analyzed += 1

            # Rate limiting (avoid API limits)
            time.sleep(2)

        except Exception as e:
            log.error(f"Failed to process {filename}: {e}", exc_info=True)
            failed += 1

    log.info(f"\n{'='*60}")
    log.info(f"Analysis Complete!")
    log.info(f"Analyzed: {analyzed}, Failed: {failed}")
    log.info(f"{'='*60}\n")


# ── Entry Point ────────────────────────────────
if __name__ == "__main__":
    # Create directories
    for d in [YARA_MATCHED_DIR, LLM_ANALYSIS_DIR, PROCESSED_DIR]:
        os.makedirs(d, exist_ok=True)

    # Check prerequisites
    if not OPENAI_AVAILABLE:
        log.error("OpenAI package not installed. Install with: pip install openai")
        exit(1)

    if not OPENAI_API_KEY:
        log.error("OPENAI_API_KEY not set!")
        log.error("Set it with: export OPENAI_API_KEY=sk-your-key-here")
        exit(1)

    # Run analysis
    process_yara_matched_files()