"""
One-off script: compute BERT-based CVE→MITRE MAPS_TO relationships
and write them into EC2 Neo4j via SSH tunnel.

Run from local machine (where sentence-transformers is installed):
  python3 scripts/run_bert_mapping.py

Requires SSH tunnel open:
  ssh -i ~/.ssh/vulnado-deployment-key.pem -fNL 7688:localhost:7687 ubuntu@54.160.171.179
"""

import re
import sys
import time
import numpy as np
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

# ── Config ──────────────────────────────────────────────────────────────────
NEO4J_URI      = "bolt://localhost:7688"   # via SSH tunnel
NEO4J_USER     = "neo4j"
NEO4J_PASSWORD = "vulnado-password-2026"

SIMILARITY_THRESHOLD = 0.32
TOP_K                = 3
BATCH_SIZE           = 200    # CVEs per Neo4j write batch
MODEL_NAME           = "all-MiniLM-L6-v2"

# ── Helpers ──────────────────────────────────────────────────────────────────

def preprocess(text: str) -> str:
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", "", text)
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def fetch_all(driver, query, params=None):
    with driver.session() as session:
        result = session.run(query, **(params or {}))
        return [dict(r) for r in result]


def write_batch(driver, relationships):
    query = """
    UNWIND $rows AS r
    MATCH (c:CVE   {cve_id:       r.cve_id})
    MATCH (m:MITRE {technique_id: r.technique_id})
    MERGE (c)-[rel:MAPS_TO]->(m)
    SET rel.score      = r.score,
        rel.mapped_by  = 'bulk_bert_local',
        rel.mapped_at  = datetime()
    """
    with driver.session() as session:
        session.run(query, rows=relationships)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Connecting to Neo4j via SSH tunnel (bolt://localhost:7688)...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    driver.verify_connectivity()
    print("✓ Connected\n")

    # ── 1. Fetch CVEs ────────────────────────────────────────────────────────
    print("Fetching CVE nodes...")
    cve_rows = fetch_all(driver,
        "MATCH (c:CVE) WHERE c.description IS NOT NULL AND c.description <> '' "
        "RETURN c.cve_id AS cve_id, c.description AS description"
    )
    print(f"  {len(cve_rows)} CVEs with descriptions\n")

    # ── 2. Fetch MITRE ───────────────────────────────────────────────────────
    print("Fetching MITRE technique nodes...")
    mitre_rows = fetch_all(driver,
        "MATCH (m:MITRE) WHERE m.description IS NOT NULL AND m.description <> '' "
        "RETURN m.technique_id AS technique_id, m.description AS description"
    )
    print(f"  {len(mitre_rows)} MITRE techniques with descriptions\n")

    if not cve_rows or not mitre_rows:
        print("✗ Not enough data to map. Exiting.")
        sys.exit(1)

    # ── 3. Preprocess ────────────────────────────────────────────────────────
    print("Preprocessing texts...")
    cve_data   = [(r["cve_id"],       preprocess(r["description"])) for r in cve_rows   if preprocess(r["description"])]
    mitre_data = [(r["technique_id"], preprocess(r["description"])) for r in mitre_rows if preprocess(r["description"])]
    print(f"  CVE: {len(cve_data)}  MITRE: {len(mitre_data)}\n")

    # ── 4. Embed ─────────────────────────────────────────────────────────────
    print(f"Loading BERT model: {MODEL_NAME}...")
    model = SentenceTransformer(MODEL_NAME)

    print("Generating CVE embeddings...")
    t0 = time.time()
    cve_embeddings = model.encode(
        [t for _, t in cve_data], show_progress_bar=True, convert_to_numpy=True
    )
    print(f"  Done in {time.time()-t0:.1f}s\n")

    print("Generating MITRE embeddings...")
    t0 = time.time()
    mitre_embeddings = model.encode(
        [t for _, t in mitre_data], show_progress_bar=True, convert_to_numpy=True
    )
    print(f"  Done in {time.time()-t0:.1f}s\n")

    # ── 5. Compute similarities + build relationships ─────────────────────
    print(f"Computing cosine similarities (threshold={SIMILARITY_THRESHOLD}, top_k={TOP_K})...")
    print(f"  Processing {len(cve_data)} CVEs × {len(mitre_data)} MITRE techniques...")

    relationships = []
    t0 = time.time()

    # Vectorised: compute all similarities at once (1829 × 735 = 1.3M pairs)
    all_sims = cosine_similarity(cve_embeddings, mitre_embeddings)  # shape (n_cves, n_mitre)

    for idx_cve, (cve_id, _) in enumerate(cve_data):
        sims = all_sims[idx_cve]
        top_indices = np.argsort(sims)[::-1][:TOP_K]
        for idx_mitre in top_indices:
            score = float(sims[idx_mitre])
            if score >= SIMILARITY_THRESHOLD:
                relationships.append({
                    "cve_id":       cve_id,
                    "technique_id": mitre_data[idx_mitre][0],
                    "score":        round(score, 4),
                })

    elapsed = time.time() - t0
    print(f"  {len(relationships)} relationships found in {elapsed:.1f}s\n")

    if not relationships:
        print("⚠ No relationships above threshold. Check your data.")
        sys.exit(0)

    # ── 6. Write to Neo4j in batches ─────────────────────────────────────
    print(f"Writing {len(relationships)} MAPS_TO relationships to Neo4j...")
    total_written = 0
    for i in range(0, len(relationships), BATCH_SIZE):
        batch = relationships[i:i + BATCH_SIZE]
        write_batch(driver, batch)
        total_written += len(batch)
        print(f"  Written {total_written}/{len(relationships)}...", end="\r")

    print(f"\n✓ Done — {total_written} MAPS_TO relationships written\n")

    # ── 7. Verify ────────────────────────────────────────────────────────
    count = fetch_all(driver, "MATCH ()-[r:MAPS_TO]->() RETURN count(r) AS cnt")
    print(f"✓ Total MAPS_TO relationships in Neo4j: {count[0]['cnt']}")

    # CVEs with at least one mapping
    mapped = fetch_all(driver,
        "MATCH (c:CVE)-[:MAPS_TO]->() RETURN count(DISTINCT c) AS cnt"
    )
    print(f"✓ CVEs with ≥1 MITRE mapping: {mapped[0]['cnt']} / {len(cve_data)}")

    driver.close()
    print("\n✓ Mapping complete. Tunnel can be closed.")


if __name__ == "__main__":
    main()
