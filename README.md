📌 Overview
AI Vulnado is an AI-driven cybersecurity intelligence platform that ingests public vulnerability data, enriches it with threat intelligence, and maps vulnerabilities to real-world attack tactics using the MITRE ATT&CK framework.
The goal of this project is to automate vulnerability analysis, prioritize security risks, and provide actionable remediation insights in a structured, scalable, and explainable manner.

🎯 Key Objectives
Ingest vulnerability data from trusted public sources
Normalize and enrich CVE information
Map vulnerabilities to MITRE ATT&CK tactics and techniques
Enable risk-aware vulnerability prioritization
Build a foundation for AI-based remediation recommendations

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        EXTERNAL DATA SOURCES                    │
│                                                                 │
│   NVD 2.0 REST API          MITRE ATT&CK           GitHub GSA  │
│   (CVEs, CVSS scores)    (STIX 2.1, techniques)  (GraphQL API) │
│         │                       │                      │        │
└─────────┼───────────────────────┼──────────────────────┼────────┘
          │                       │                      │
          ▼                       ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DATA PIPELINE (8 Stages)                    │
│                                                                 │
│  Stage 00: Ingestion  →  Stage 01: Validation                   │
│  Stage 02: Transformation (entity chunks)                       │
│  Stage 03: BERT Semantic Mapping                                │
│            all-MiniLM-L6-v2 embeddings                         │
│            cosine_similarity(CVE desc, MITRE technique desc)    │
│            threshold=0.32 → MAPS_TO relationship + score        │
│  Stage 04: Graph Ingestion (Neontology ORM → Neo4j)             │
│  Stage 05: RAG System (ChromaDB + sentence-transformers)        │
│  Stage 07: LLaMA Fine-tuning (training_dataset.jsonl)           │
│  Stage 08: Inference Engine                                     │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     NEO4J KNOWLEDGE GRAPH                       │
│                                                                 │
│   (CVE) ──[MAPS_TO {score}]──────────────► (MITRE Technique)   │
│   (CVE) ──[HAS_GSA_ADVISORY]─────────────► (GSA Advisory)      │
│                                                                 │
│   2,000+ nodes  │  CVE + MITRE + GSA  │  bolt://localhost:7687  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   REAL-TIME SYNC (APScheduler)                  │
│                                                                 │
│   sync_nvd()    ── every 2h  (incremental, last-sync window)   │
│   sync_gsa()    ── every 6h  (full fetch, top 100)             │
│   sync_mitre()  ── every 24h (full STIX refresh)               │
│                                                                 │
│   → HistoricalStore (append-only daily JSON, dedup by ID)       │
│   → Neo4j MERGE upsert (batches of 500)                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FLASK WEB APPLICATION                      │
│                                                                 │
│   POST /api/chat      → VulnerabilityBot → Neo4j query          │
│   GET  /api/status    → scheduler state + sync freshness        │
│   POST /api/sync/trigger → manual sync trigger                  │
│   GET  /             → Chat UI (sync status bar + chatbot)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AWS CLOUD INFRASTRUCTURE                   │
│                                                                 │
│   Route 53 (vulnado.in)                                         │
│       │                                                         │
│       ▼                                                         │
│   EC2 t3.medium (us-east-1)                                     │
│   ├── Nginx  :443/:80  (TLS + rate limiting + reverse proxy)    │
│   ├── Flask  :5000     (app process, nohup)                     │
│   └── Neo4j  :7687     (Docker ← ECR: vulnado-neo4j)            │
│                                                                 │
│   ECR  → Docker image registry (vulnado, vulnado-neo4j)         │
│   S3   → Deployment file transfer                               │
│   CloudWatch → Container logs + billing alarms                  │
│   IAM  → EC2 role (ECR pull/push, S3, CloudWatch)               │
└─────────────────────────────────────────────────────────────────┘
```

## 🔮 Roadmap — Agentic AI Layer

```
Current: Deterministic pipeline
  query → regex intent → fixed Cypher → template answer

Next:    ReAct Agent loop
  query → LLM reasons → calls Neo4j tools → observes → reasons → answer

Tools:
  lookup_cve(cve_id)              find_cves_by_package(package)
  get_mitre_for_cve(cve_id)       get_critical_cves_since(days)
  search_by_keyword(text)

LLM: Groq llama-3.1-8b-instant (API, no GPU required on EC2)
```
