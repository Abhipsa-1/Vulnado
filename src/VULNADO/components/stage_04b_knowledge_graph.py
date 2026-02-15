# ingest/ingest_cve.py
import json
import os
from pathlib import Path
from stage_03_schema import CVE, GSA, MITRE
from stage_03_schema import HasGSAAdvisory, MapsToMITRE
from stage_03_schema import init_graph


def ingest_cves(path: str):
    with open(path) as f:
        data = json.load(f)

    records = []
    for item in data:
        records.append({
            "cve_id": item["cve_id"],
            "description": item.get("description"),
            "severity": item.get("severity")
        })

    CVE.merge_records(records)

def ingest_gsa(path: str):
    with open(path) as f:
        data = json.load(f)

    records = []
    for item in data:
        records.append({
            "ghsa_id": item["ghsa_id"],
            "package_name": item.get("package_name"),
            "fixed_version": item.get("fixed_version")
        })

    GSA.merge_records(records)

def ingest_mitre(path: str):
    with open(path) as f:
        data = json.load(f)

    records = []
    for item in data:
        records.append({
            "technique_id": item["technique_id"],
            "technique_name": item.get("technique_name"),
            "technique_description": item.get("technique_description"),
            "tactic": item.get("tactic")
        })

    MITRE.merge_records(records)

def ingest_cve_gsa(path: str):
    with open(path) as f:
        data = json.load(f)

    records = []
    for item in data:
        records.append({
            "source": item["cve_id"],
            "target": item["ghsa_id"]
        })

    HasGSAAdvisory.merge_records(records)


def ingest_cve_mitre(path: str):
    with open(path) as f:
        data = json.load(f)

    records = []
    for cve_id, techniques in data.items():
        for tech_id, score in techniques:
            records.append({
                "source": cve_id,
                "target": tech_id,
                "score": score
            })

    MapsToMITRE.merge_records(records)

BASE_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/normalized")
# OUTPUT_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/enitity_chunks")
# entity_chunks_path= OUTPUT_PATH / "entity_chunks.json"

# OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
def main():
    init_graph()
    ingest_cves(BASE_PATH/"cve_core_fields.json")
    ingest_gsa(BASE_PATH/"gsa_fix_fields.json")
    ingest_mitre(BASE_PATH/"mitre_attack_patterns.json")
    ingest_cve_gsa(BASE_PATH/"cve_gsa_mappings.json")
    ingest_cve_mitre(BASE_PATH/"cve_mitre_mappings.json")

if __name__ == "__main__":
    main()