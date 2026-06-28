#!/usr/bin/env python3
import os
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
import hashlib
import time

# Elasticsearch
try:
    from elasticsearch import Elasticsearch
    from elasticsearch import helpers
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    print("[ERROR] Elasticsearch package not installed!")
    print("        Install with: pip install elasticsearch")

# ── Configuration ──────────────────────────────
LLM_ANALYSIS_DIR = Path(os.getenv("LLM_ANALYSIS_DIR", "/your/directory/path/result"))
FAILED_DIR = Path(os.getenv("FAILED_DIR", "/your/directory/path/failed"))
LLM_INDEXED_DIR = Path(os.getenv("LLM_INDEXED_DIR", "/your/directory/path/llm_indexed"))

ES_URL = os.getenv("ES_URL", "http://<elasticsearch_ip>:9200")
ES_INDEX_PREFIX = os.getenv("ES_INDEX", "<es_index>")

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
CHECK_ES_DUPLICATES = os.getenv("CHECK_ES_DUPLICATES", "true").lower() == "true"

LOG_FILE = Path(os.getenv("LOG_FILE", "/your/log/directory/path"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── Elasticsearch Connection ───────────────────
def create_es_client():
    try:
        es = Elasticsearch([ES_URL])

        if es.ping():
            log.info(f" Connected to Elasticsearch at {ES_URL}")
            info = es.info()
            version = info.get('version', {}).get('number', 'unknown')
            log.info(f" Elasticsearch version: {version}")
            return es
        else:
            log.error(f" Cannot ping Elasticsearch at {ES_URL}")
            return None

    except Exception as e:
        log.error(f"Failed to connect to Elasticsearch: {e}")
        return None

# ── Index Template ─────────────────────────────
def create_index_template(es):
    """Create index template with optimized mappings"""
    template = {
        "index_patterns": [f"{ES_INDEX_PREFIX}-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "refresh_interval": "30s"
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "indexed_at": {"type": "date"},
                    "file": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "path": {"type": "keyword"},
                            "size": {"type": "long"},
                            "sha256": {"type": "keyword"},
                            "md5": {"type": "keyword"}
                        }
                    },
                    "yara": {
                        "properties": {
                            "alert_level": {"type": "keyword"},
                            "score": {"type": "integer"},
                            "rules": {"type": "keyword"},
                            "file_type": {"type": "keyword"},
                            "matched": {"type": "boolean"}
                        }
                    },
                    "llm_analysis": {
                        "properties": {
                            "malware_family": {"type": "keyword"},
                            "threat_actor": {"type": "keyword"},
                            "attack_type": {"type": "keyword"},
                            "risk_score": {"type": "integer"},
                            "confidence": {"type": "keyword"},
                            "attack_summary": {
                                "type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}
                            },
                            "capabilities": {"type": "keyword"},
                            "recommended_actions": {"type": "text"},
                            "error": {"type": "text"},
                            "mitre_tactics": {
                                "type": "nested",
                                "properties": {
                                    "id": {"type": "keyword"},
                                    "name": {"type": "keyword"},
                                    "confidence": {"type": "keyword"}
                                }
                            },
                            "mitre_techniques": {
                                "type": "nested",
                                "properties": {
                                    "id": {"type": "keyword"},
                                    "name": {"type": "keyword"},
                                    "subtechnique": {"type": "keyword"}
                                }
                            },
                            "iocs": {
                                "properties": {
                                    "ips": {"type": "ip"},
                                    "domains": {"type": "keyword"},
                                    "urls": {"type": "keyword"},
                                    "file_hashes": {"type": "keyword"},
                                    "file_paths": {"type": "keyword"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        es.indices.put_index_template(
            name=f"{ES_INDEX_PREFIX}_template",
            body=template
        )
        log.info("✅ Index template created/updated")
        return True

    except Exception as e:
        log.error(f"Failed to create index template: {e}")
        return False

# ── Document Processing ────────────────────────
def calculate_doc_id(file_data):
    file_info = file_data.get("file", {})

    # Handle nested sha256 dict from LLM analyzer
    sha256_field = file_info.get("sha256")
    if isinstance(sha256_field, dict):
        sha256 = sha256_field.get("sha256")
    else:
        sha256 = sha256_field

    # Fallback to MD5 or generate from content
    if not sha256:
        md5_field = file_info.get("md5")
        if isinstance(md5_field, dict):
            return md5_field.get("md5")
        return md5_field or hashlib.sha256(json.dumps(file_data, sort_keys=True).encode()).hexdigest()

    return sha256

def normalize_file_info(file_info):
    normalized = file_info.copy()

    # Flatten sha256
    if isinstance(normalized.get("sha256"), dict):
        normalized["sha256"] = normalized["sha256"].get("sha256")

    # Flatten md5
    if isinstance(normalized.get("md5"), dict):
        normalized["md5"] = normalized["md5"].get("md5")

    return normalized

def process_llm_file(filepath):
    """Process single LLM analysis file into ES document"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log.error(f"Invalid JSON in {filepath}: {e}")
        raise
    except Exception as e:
        log.error(f"Error reading {filepath}: {e}")
        raise

    # Normalize file info
    file_info = normalize_file_info(data.get("file", {}))

    # Build document
    doc = {
        "@timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "indexed_at": datetime.utcnow().isoformat(),
        "file": file_info,
        "yara": data.get("yara", {}),
        "llm_analysis": data.get("llm_analysis", {})
    }

    # Calculate document ID
    doc_id = calculate_doc_id(data)

    return doc, doc_id

def validate_document(doc):
    """Validate document before indexing"""
    required_fields = ["@timestamp", "file"]

    for field in required_fields:
        if field not in doc:
            return False, f"Missing required field: {field}"

    # Validate file hash exists
    file_info = doc.get("file", {})
    if not file_info.get("sha256") and not file_info.get("md5"):
        return False, "Missing file hash (SHA256 or MD5)"

    return True, None

# ── Duplicate Detection ────────────────────────
def document_exists(es, index_pattern, doc_id):
    """Check if document exists in Elasticsearch"""
    try:
        result = es.count(
            index=index_pattern,
            body={"query": {"term": {"_id": doc_id}}}
        )
        return result['count'] > 0

    except Exception as e:
        log.debug(f"Error checking document existence: {e}")
        return False

# ── Bulk Indexing ──────────────────────────────
def index_documents_batch(es, documents, index_name):
    """Index documents in batch with error handling"""
    if not documents:
        return 0, []

    actions = []
    for doc, doc_id, filepath in documents:
        valid, error = validate_document(doc)
        if not valid:
            log.warning(f"Invalid document {filepath.name}: {error}")
            continue

        actions.append({
            "_index": index_name,
            "_id": doc_id,
            "_source": doc
        })

    if not actions:
        log.warning("No valid documents to index")
        return 0, []

    try:
        success, errors = helpers.bulk(
            es,
            actions,
            raise_on_error=False
        )

        log.info(f" Indexed {success}/{len(actions)} documents")

        failed_files = []
        if errors:
            log.warning(f"⚠️ {len(errors)} documents failed")
            for error in errors:
                error_info = error.get('index', {})
                doc_id = error_info.get('_id', 'unknown')
                error_msg = error_info.get('error', {})
                log.error(f"Failed to index {doc_id}: {error_msg}")

                for doc, did, fpath in documents:
                    if did == doc_id:
                        failed_files.append(fpath)
                        break

        return success, failed_files

    except Exception as e:
        log.error(f"Bulk index error: {e}")
        return 0, [fpath for _, _, fpath in documents]

# ── File Management ────────────────────────────
def move_to_failed(filepath):
    """Move failed file to failed directory"""
    try:
        FAILED_DIR.mkdir(parents=True, exist_ok=True)

        filename = filepath.name
        dest = FAILED_DIR / filename

        counter = 1
        while dest.exists():
            stem = filepath.stem
            suffix = filepath.suffix
            dest = FAILED_DIR / f"{stem}_{counter}{suffix}"
            counter += 1

        shutil.move(str(filepath), str(dest))
        log.info(f"Moved to failed: {filename}")

    except Exception as e:
        log.error(f"Error moving {filepath.name} to failed: {e}")

def cleanup_processed_file(filepath): #Move r to llm_indexed/
    """Move file to llm_indexed after successful indexing"""
    try:
        LLM_INDEXED_DIR.mkdir(parents=True, exist_ok=True)
        dest = LLM_INDEXED_DIR / filepath.name
        shutil.copy2(str(filepath), str(dest))
        filepath.unlink()
        log.debug(f"Archived to llm_indexed: {filepath.name}")
    except Exception as e:
        log.error(f"Error archiving {filepath.name}: {e}")

# ── Main Processing ────────────────────────────
def process_llm_analysis():
    """Main processing function"""
    log.info("=" * 60)
    log.info("Elasticsearch Pusher Started")
    log.info(f"ES URL: {ES_URL}")
    log.info(f"Index Prefix: {ES_INDEX_PREFIX}")
    log.info(f"Batch Size: {BATCH_SIZE}")
    log.info("=" * 60)

    es = create_es_client()
    if not es:
        log.error("Cannot proceed without Elasticsearch connection")
        return

    create_index_template(es)
    #for each report r in llm_analysis/ do
    analysis_files = list(LLM_ANALYSIS_DIR.glob("*.llm.json"))

    if not analysis_files:
        log.info("No files found in analysis directory")
        return

    log.info(f"Found {len(analysis_files)} files to process")

    index_name = f"{ES_INDEX_PREFIX}-{datetime.utcnow().strftime('%Y.%m')}"
    index_pattern = f"{ES_INDEX_PREFIX}-*"

    total_processed = 0
    total_skipped = 0
    total_failed = 0

    batch = []
    #id ← SHA256(r)
    for filepath in analysis_files:
        try:
            doc, doc_id = process_llm_file(filepath)
            # if id ∉ Elasticsearch then
            if CHECK_ES_DUPLICATES:
                if document_exists(es, index_pattern, doc_id):
                    log.debug(f"Skipping (already in ES): {filepath.name}")
                    cleanup_processed_file(filepath) #Move r to llm_indexed/
                    total_skipped += 1
                    continue

            batch.append((doc, doc_id, filepath))
            # BulkIndex(r, index="llm-analysis-YYYY.MM")
            if len(batch) >= BATCH_SIZE:
                success, failed_files = index_documents_batch(es, batch, index_name)
                total_processed += success

                for doc, doc_id, fpath in batch:
                    if fpath not in failed_files:
                        cleanup_processed_file(fpath)

                for fpath in failed_files:
                    move_to_failed(fpath)
                    total_failed += 1

                batch = []

        except Exception as e:
            log.error(f"Error processing {filepath.name}: {e}")
            move_to_failed(filepath)
            total_failed += 1

    if batch:
        success, failed_files = index_documents_batch(es, batch, index_name)
        total_processed += success

        for doc, doc_id, fpath in batch:
            if fpath not in failed_files:
                cleanup_processed_file(fpath)

        for fpath in failed_files:
            move_to_failed(fpath)
            total_failed += 1

    log.info("")
    log.info("=" * 60)
    log.info("Processing Complete!")
    log.info(f"Total Files: {len(analysis_files)}")
    log.info(f"✅ Indexed: {total_processed}")
    log.info(f"⏭️  Skipped (duplicates): {total_skipped}")
    log.info(f"❌ Failed: {total_failed}")
    log.info("=" * 60)

# ── Entry Point ────────────────────────────────
if __name__ == "__main__":
    LLM_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    FAILED_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not ES_AVAILABLE:
        log.error("Elasticsearch package not installed")
        log.error("Install with: pip install elasticsearch")
        exit(1)

    try:
        process_llm_analysis()
    except KeyboardInterrupt:
        log.info("\n⚠️ Interrupted by user")
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        exit(1)