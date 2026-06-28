# Honeypot Analysis Pipeline

An automated end-to-end pipeline for analyzing artifacts collected from a live T-Pot honeypot deployment.

This project extends the default T-Pot workflow by synchronizing captured artifacts using **Lsyncd**, performing **YARA-based artifact screening**, enriching suspicious artifacts through **GPT-4o contextual analysis**, and indexing the generated threat intelligence into **Elasticsearch** for visualization with Kibana.

The proposed architecture was developed as part of the research:

> **An Automated Honeypot Artifact Analysis Pipeline using YARA, GPT-4o, MITRE ATT&CK, and ELK Stack**

---

# Pipeline Overview

```
                   T-Pot Honeypot
                   ┌─────────────┐
                   │   Artifacts │
                   └──────┬──────┘
                          │
                     Lsyncd + Rsync
                          │
                          ▼
                 Analysis Server
                          │
                  yara_scan.py
                          │
                  YARA Matched Files
                          │
                  llm_analysis.py
                          │
             MITRE ATT&CK Threat Intelligence
                          │
                   es_indexer.py
                          │
                          ▼
                  Elasticsearch
                          │
                          ▼
                       Kibana
```

---

# Repository Structure

```
honeypot-analysis-pipeline/
│
├── scripts/
│   ├── yara_scan.py
│   ├── llm_analysis.py
│   └── es_indexer.py
│
├── lsyncd.conf.lua
├── README.md
└── requirements.txt
```

---

# Components

## Lsyncd

Lsyncd continuously monitors the T-Pot artifact directory and synchronizes newly captured files to the analysis server using Rsync.

Unlike periodic synchronization, Lsyncd enables near real-time artifact delivery while minimizing synchronization latency.

---

## yara_scan.py

This script performs the first-stage analysis of synchronized artifacts.

Features:

- scans newly synchronized artifacts
- uses the continuously maintained Neo23x0 YARA rule repository
- detects suspicious files based on YARA signatures
- forwards only YARA-flagged artifacts for further analysis

Within the proposed pipeline, **YARA serves as the initial triage layer**, reducing unnecessary LLM requests and focusing contextual analysis on artifacts that already exhibit preliminary indicators of malicious behavior.

---

## llm_analysis.py

This module performs contextual threat analysis using GPT-4o.

For each YARA-flagged artifact, GPT-4o generates:

- malware family description
- behavioral summary
- attack objectives
- MITRE ATT&CK tactics
- MITRE ATT&CK techniques
- security recommendations

The generated output is structured as JSON.

---

## es_indexer.py

Indexes the generated threat intelligence into Elasticsearch.

Indexed results can be explored through Kibana dashboards together with the operational logs collected from the honeypot.

---

# Workflow

1. T-Pot captures malicious artifacts.
2. Lsyncd synchronizes artifacts to the analysis server.
3. `yara_scan.py` scans synchronized artifacts using the Neo23x0 YARA rules.
4. Only YARA-matched artifacts are forwarded to GPT-4o.
5. `llm_analysis.py` generates contextual threat intelligence and maps findings to the MITRE ATT&CK framework.
6. `es_indexer.py` stores the structured results in Elasticsearch.
7. Kibana visualizes both operational logs and enriched artifact intelligence.

---

# Design Rationale

The proposed pipeline intentionally separates rule-based detection from contextual LLM analysis.

Rather than sending every synchronized artifact to GPT-4o, YARA performs an initial rule-based triage to identify suspicious artifacts. This design:

- reduces unnecessary GPT-4o API requests,
- minimizes analysis of benign artifacts,
- lowers processing overhead,
- focuses contextual reasoning on artifacts with preliminary evidence of malicious behavior.

Meanwhile, Logstash continues forwarding JSON log data directly to Elasticsearch, allowing operational monitoring and artifact enrichment to operate as complementary pipelines.

---

# Requirements

- Ubuntu Server
- T-Pot CE
- Lsyncd
- Rsync
- Python 3.10+
- yara-python
- OpenAI API
- Elasticsearch
- Kibana

---

# Citation

If you use this repository in your research, please cite the accompanying publication.
