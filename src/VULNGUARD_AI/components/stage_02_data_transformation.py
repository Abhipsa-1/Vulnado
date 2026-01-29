import json
import re
from pathlib import Path
from typing import List, Dict
import nltk
from nltk.tokenize import sent_tokenize
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

nltk.download("punkt")

BASE_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/normalized")
OUTPUT_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/enitity_chunks")
entity_chunks_path= OUTPUT_PATH / "entity_chunks.json"

OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

from typing import List, Dict
#chunking baseds on entities
def chunk_cve_entities(cve_records: List[Dict]) -> List[Dict]:
    chunks = []

    for cve in cve_records:
        affected = cve.get("affected_software", [])
        affected_text = []

        for sw in affected:
            affected_text.append(
                f"Vendor: {sw.get('vendor')}, "
                f"Product: {sw.get('product')}, "
                f"Version: {sw.get('version')}"
            )

        chunk_text = f"""
        CVE ID: {cve.get('cve_id')}
        Severity: {cve.get('severity')}
        Description: {cve.get('description')}
        Affected Software:
        {'; '.join(affected_text)}
        References:
        {'; '.join(cve.get('references', []))}
        """.strip()

        chunks.append({
            "chunk_type": "CVE",
            "entity_id": cve.get("cve_id"),
            "text": chunk_text,
            "metadata": {
                "severity": cve.get("severity")
            }
        })

    return chunks

def chunk_gsa_entities(gsa_records: List[Dict]) -> List[Dict]:
    chunks = []

    for gsa in gsa_records:
        chunk_text = f"""
        GSA ID: {gsa.get('gsa_id')}
        CVE ID: {gsa.get('cve_id')}
        Package Name: {gsa.get('package_name')}
        Severity: {gsa.get('severity')}
        Vulnerable Versions: {gsa.get('vulnerable_versions')}
        Fixed Version: {gsa.get('fixed_version')}
        References:
        {'; '.join(gsa.get('references', []))}
        """.strip()

        chunks.append({
            "chunk_type": "GSA",
            "entity_id": gsa.get("cve_id"),
            "text": chunk_text,
            "metadata": {
                "package": gsa.get("package_name"),
                "severity": gsa.get("severity")
            }
        })

    return chunks

def chunk_mitre_entities(mitre_records: List[Dict]) -> List[Dict]:
    chunks = []

    for technique in mitre_records:
        chunk_text = f"""
        Technique ID: {technique.get('technique_id')}
        Technique Name: {technique.get('technique_name')}
        Description: {technique.get('technique_description')}
        Tactics: {', '.join(technique.get('tactic', []))}
        Platforms: {', '.join(technique.get('platforms', []))}
        """.strip()

        chunks.append({
            "chunk_type": "MITRE",
            "entity_id": technique.get("technique_id"),
            "text": chunk_text,
            "metadata": {
                "tactics": technique.get("tactic", []),
                "platforms": technique.get("platforms", [])
            }
        })

    return chunks

#preserve entity inforkmation in chunks
def map_cves_to_mitre(entity_chunks_path: str, top_k: int = 3):
    """
    Maps CVE chunks to MITRE technique chunks using semantic embeddings.

    Args:
        entity_chunks_path (str): path to entity_chunks.json
        top_k (int): number of MITRE techniques to return per CVE

    Returns:
        dict: {CVE_ID: [(MITRE_ID, similarity_score)]}
    """

    # Load entity chunks
    with open(entity_chunks_path, "r") as f:
        chunks = json.load(f)

    # Separate CVE and MITRE chunks
    cve_chunks = [c for c in chunks if c["chunk_type"] == "CVE"]
    mitre_chunks = [c for c in chunks if c["chunk_type"] == "MITRE"]

    if not cve_chunks or not mitre_chunks:
        raise ValueError("CVE or MITRE chunks missing from entity_chunks.json")

    # Load embedding model
    model = SentenceTransformer("all-MiniLM-L6-v2")

    # Prepare MITRE embeddings
    mitre_ids = [m["entity_id"] for m in mitre_chunks]
    mitre_texts = [m["text"] for m in mitre_chunks]
    mitre_embeddings = model.encode(mitre_texts, normalize_embeddings=True)

    results = {}

    # Process each CVE
    for cve in cve_chunks:
        cve_id = cve["entity_id"]
        cve_text = cve["text"]

        cve_embedding = model.encode([cve_text], normalize_embeddings=True)

        similarities = cosine_similarity(cve_embedding, mitre_embeddings)[0]

        ranked = sorted(
            [(mid, float(score)) for mid, score in zip(mitre_ids, similarities)],
            key=lambda x: x[1],
            reverse=True
        )

        results[cve_id] = ranked[:top_k]

    return results


#map cve to gsa 
def map_cve_to_gsa(entity_chunks):
    cve_map = {}
    gsa_map = {}

    for chunk in entity_chunks:
        if chunk["chunk_type"] == "CVE":
            cve_map[chunk["entity_id"]] = chunk
        elif chunk["chunk_type"] == "GSA":
            gsa_map[chunk["entity_id"]] = chunk

    mappings = {}

    for cve_id, cve_data in cve_map.items():
        mappings[cve_id] = {
            "cve": cve_data,
            "gsa": gsa_map.get(cve_id)  # None if not found
        }

    return mappings


def main():
    entity_chunks = []

    # CVE chunks
    with open(BASE_PATH/"cve/cve_core_fields.json")as f:
        cve_data=json.load(f)
    cve_chunks = chunk_cve_entities(cve_data)
    entity_chunks.extend(cve_chunks)

    #GSA / GSA chunks
    with open(BASE_PATH/"gsa/gsa_fix_fields.json")as f:
        gsa_data=json.load(f)
    gsa_chunks = chunk_gsa_entities(gsa_data)
    entity_chunks.extend(gsa_chunks)

    # MITRE ATT&CK chunks
    with open(BASE_PATH/"mitre/mitre_attack_patterns.json")as f:
        mitre_data=json.load(f)
    mitre_chunks = chunk_mitre_entities(mitre_data)
    entity_chunks.extend(mitre_chunks)

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_PATH / "entity_chunks.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(entity_chunks, f, indent=2)

    print(f"Saved {len(entity_chunks)} entity-based chunks to {output_file}")

    with open(OUTPUT_PATH / "cve_mitre_mappings.json", "w") as f:
        json.dump(map_cves_to_mitre(entity_chunks_path, top_k=3),f,indent=2)
    print(f"Saved entity-based chunks to {output_file} and CVE-MITRE mapped")

    with open(OUTPUT_PATH/"cve_gsa_mappings.json", "w") as f:
        json.dump(map_cve_to_gsa(entity_chunks),f,indent=2)
    print(f"Saved CVE-GSA mappings to {OUTPUT_PATH/'cve_gsa_mappings.json'}")

if __name__ == "__main__":
    main()


