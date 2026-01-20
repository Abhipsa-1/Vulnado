📌 Overview
AI VulnGuard is an AI-driven cybersecurity intelligence platform that ingests public vulnerability data, enriches it with threat intelligence, and maps vulnerabilities to real-world attack tactics using the MITRE ATT&CK framework.
The goal of this project is to automate vulnerability analysis, prioritize security risks, and provide actionable remediation insights in a structured, scalable, and explainable manner.

🎯 Key Objectives
Ingest vulnerability data from trusted public sources
Normalize and enrich CVE information
Map vulnerabilities to MITRE ATT&CK tactics and techniques
Enable risk-aware vulnerability prioritization
Build a foundation for AI-based remediation recommendations

🧠 High-Level System Architecture
# VulnGurad-AI
AI-Powered Cyber Vulnerability Intelligence &amp; Remediation Framework
┌─────────────────────────────────────────┐
│ NVD Feeds | CVE | MITRE ATT&CK          │
└──────────────────────┬──────────────────┘
                       ↓
┌─────────────────────────────────────────┐
│ Data Ingestion Layer                   │
│ • NVD API / Feeds                      │
│ • CVE Metadata Extraction              │
│ • Scheduled Jobs                       │
└──────────────────────┬──────────────────┘
                       ↓
┌─────────────────────────────────────────┐
│ Data Preprocessing Layer               │
│ • Data Cleaning                        │
│ • CVE Parsing                          │
│ • Text Normalization                   │
└──────────────────────┬──────────────────┘
                       ↓
┌─────────────────────────────────────────┐
│ Intelligence Layer                     │
│ • CVE Risk Analysis                    │
│ • MITRE ATT&CK Mapping                 │
│ • Knowledge Enrichment                 │
└──────────────────────┬──────────────────┘
                       ↓
┌─────────────────────────────────────────┐
│ Visualization / Analysis Layer         │
│ • Dashboards                           │
│ • Query & Insights                     │
└─────────────────────────────────────────┘


📁 Repository Structure (GitHub)
AI-VulnGuard/
│
├── data/
│   ├── raw/
│   │   └── cve_raw.json
│   ├── processed/
│   │   └── cve_cleaned.csv
│
├── ingestion/
│   ├── fetch_nvd.py
│   ├── scraper.py
│   └── scheduler.py
│
├── preprocessing/
│   ├── clean_text.py
│   ├── parse_cve.py
│
├── ai_engine/
│   ├── nlp_classifier.py
│   ├── risk_model.py
│   ├── attack_mapper.py
│   └── knowledge_graph.py
│
├── remediation/
│   └── recommendation_engine.py
│
├── ui/
│   ├── dashboard/
│   └── chatbot/
│
├── README.md
├── requirements.txt
└── config.yaml
