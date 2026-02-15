import json
import re
from pathlib import Path
from typing import List, Dict
import nltk
import requests
from nltk.tokenize import sent_tokenize
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

nltk.download("punkt")

BASE_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/normalized")
OUTPUT_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/entity_chunks")
# entity_chunks_path= OUTPUT_PATH / "entity_chunks.json"

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

        chunk_text = (
            f"CVE ID: {cve.get('cve_id')}\n"
            f"Severity: {cve.get('severity')}\n"
            f"Description: {cve.get('description')}\n"
            f"CWE ID: {cve.get('cwe_ids')}\n"
            f"Base Score: {cve.get('base_score')}\n"
            f"Attack Vector: {cve.get('attack_vector')}\n"
            f"Attack Complexity: {cve.get('attack_complexity')}\n"
            f"Affected Software: {'; '.join(affected_text)}"
        ).strip()

        chunks.append({
            "chunk_type": "CVE",
            "entity_id": cve.get("cve_id"),
            "text": chunk_text
        })

    return chunks


def fetch_gsa_data(max_records: int = 100) -> List[Dict]:
    """
    Fetch GitHub Security Advisory (GSA) data from the GitHub API.
    
    Args:
        max_records: Maximum number of records to fetch (default: 100)
    
    Returns:
        List of dictionaries containing GSA data
    """
    
    gsa_records = []
    url = "https://api.github.com/graphql"
    
    # GraphQL query to fetch security advisories
    query = """
    query {
        securityAdvisories(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {
            edges {
                node {
                    ghsaId
                    cveId
                    summary
                    description
                    severity
                    publishedAt
                    updatedAt
                    permalink
                    references {
                        url
                    }
                }
            }
        }
    }
    """
    
    try:
        headers = {
            "Content-Type": "application/json",
        }
        # Note: For authenticated requests, add: "Authorization": f"Bearer {GITHUB_TOKEN}"
        
        response = requests.post(url, json={"query": query}, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if "errors" in data:
            print(f"GraphQL Error: {data['errors']}")
            return []
        
        if "data" in data and "securityAdvisories" in data["data"]:
            advisories = data["data"]["securityAdvisories"]["edges"]
            
            for advisory in advisories[:max_records]:
                node = advisory.get("node", {})
                references = [ref.get("url", "") for ref in node.get("references", [])]
                
                record = {
                    "gsa_id": node.get("ghsaId", ""),
                    "cve_id": node.get("cveId", ""),
                    "summary": node.get("summary", ""),
                    "description": node.get("description", ""),
                    "severity": node.get("severity", ""),
                    "package_name": "",  # Not directly available in query, can be added if needed
                    "vulnerable_versions": "",  # Not directly available, parse from description if needed
                    "references": references,
                    "published_at": node.get("publishedAt", ""),
                    "updated_at": node.get("updatedAt", ""),
                    "permalink": node.get("permalink", "")
                }
                gsa_records.append(record)
        
        print(f"Fetched {len(gsa_records)} GSA records from GitHub API")
        return gsa_records
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching GSA data from API: {e}")
        print("Falling back to local file if available...")
        return []


def chunk_gsa_entities(gsa_records: List[Dict]) -> List[Dict]:
    chunks = []

    for gsa in gsa_records:
        # Format CWEs properly
        cwes = gsa.get('cwes', [])
        if isinstance(cwes, list) and cwes:
            if isinstance(cwes[0], dict):
                # If cwes is a list of dicts with cwe_id and name
                cwe_text = '; '.join([f"{cwe.get('cwe_id', '')}: {cwe.get('name', '')}" for cwe in cwes])
            else:
                # If cwes is a simple list of strings
                cwe_text = '; '.join(cwes)
        else:
            cwe_text = ""
        
        chunk_text = f"""
        GSA ID: {gsa.get('ghsa_id')}
        CVE ID: {gsa.get('cve_id')}
        Summary: {gsa.get('summary')}
        Package Name: {gsa.get('package_name')}
        Severity: {gsa.get('severity')}
        Vulnerable Versions: {gsa.get('vulnerable_versions')}
        Description: {gsa.get('description')}
        Fixed Version: {gsa.get('fixed_version')}
        CWEs: {cwe_text}
        References:
        {'; '.join(gsa.get('references', []))}
        """.strip()

        chunks.append({
            "chunk_type": "GSA",
            "entity_id": gsa.get("ghsa_id"),
            "text": chunk_text,
            "metadata": {
                "package": gsa.get("package_name"),
                "severity": gsa.get("severity"),
                "cwes": cwes
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
                "platforms": technique.get("platforms", []),
                "description": technique.get("technique_description", "")
            }
        })

    return chunks

def main():
    entity_chunks = []

    # CVE chunks
    with open(BASE_PATH/"cve/cve_core_fields.json")as f:
        cve_data=json.load(f)
    cve_chunks = chunk_cve_entities(cve_data)
    entity_chunks.extend(cve_chunks)

    # GSA / GSA chunks - fetch from API, fallback to local file
    gsa_data = fetch_gsa_data(max_records=100)
    
    # If API fetch fails or returns empty, try loading from local file
    if not gsa_data and (BASE_PATH/"gsa"/"gsa_fix_fields.json").exists():
        try:
            with open(BASE_PATH/"gsa"/"gsa_fix_fields.json") as f:
                gsa_data = json.load(f)
            print(f"Loaded {len(gsa_data)} GSA records from local file")
        except Exception as e:
            print(f"Error loading GSA from local file: {e}")
            gsa_data = []
    
    if gsa_data:
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

    # with open(OUTPUT_PATH / "cve_mitre_mappings.json", "w") as f:
    #     json.dump(map_cves_to_mitre(entity_chunks_path, top_k=3),f,indent=2)
    # print(f"Saved entity-based chunks to {output_file} and CVE-MITRE mapped")

    # with open(OUTPUT_PATH/"cve_gsa_mappings.json", "w") as f:
    #     json.dump(map_cve_to_gsa(entity_chunks),f,indent=2)
    # print(f"Saved CVE-GSA mappings to {OUTPUT_PATH/'cve_gsa_mappings.json'}")

if __name__ == "__main__":
    main()