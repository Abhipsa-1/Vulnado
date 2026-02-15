from neo4j import GraphDatabase
import json
from pathlib import Path

# ============================
# CONFIGURATION
# ============================

OUTPUT_PATH = Path("/Users/abhipsa/Documents/VulnGuard AI/enitity_chunks")
OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

cve_gsa_mapping = OUTPUT_PATH / "cve_gsa_mappings.json"
cve_mitre_mapping = OUTPUT_PATH / "cve_mitre_mappings.json"
CVE_GSA_JSON = Path("/Users/abhipsa/Documents/VulnGuard AI/neo4j")
CVE_GSA_JSON.mkdir(parents=True, exist_ok=True)

NEO4J_URI = "neo4j+ssc://e023f02b.databases.neo4j.io"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Mo_q36wZ3-VJtjgE5RtRUOIbS4uFP2O83Ne1krlay9A"

if not all([NEO4J_URI, NEO4J_USER, NEO4J_PASS]):
    raise EnvironmentError("Neo4j environment variables are not set")

# ============================
# NEO4J INGESTOR
# ============================

class Neo4jIngestor:
    def __init__(self):
        try:
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASS)
            )
        except Exception as e:
            print(f"Error connecting to Neo4j: {e}")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def ingest_cve_gsa(self, mappings):
        if not self.driver:
            print("Neo4j driver not initialized.")
            return

        query = """
        MERGE (c:CVE {id: $cve_id})
        SET c.severity = $severity
        MERGE (g:GSA {id: $gsa_id})
        SET g.package = $package
        MERGE (c)-[:HAS_GSA_ADVISORY]->(g)
        """

        with self.driver.session() as session:
            for cve_id, record in mappings.items():
                cve_data = record.get("cve")
                gsa_data = record.get("gsa")
                if not cve_data or not gsa_data:
                    continue
                session.run(
                    query,
                    cve_id=cve_data.get("entity_id"),
                    severity=cve_data.get("metadata", {}).get("severity"),
                    gsa_id=gsa_data.get("entity_id"),
                    package=gsa_data.get("metadata", {}).get("package")
                )

    def fetch_all_mappings(self):
        if not self.driver:
            print("Neo4j driver not initialized.")
            return []
        
        query = """
        MATCH (c:CVE)-[:HAS_GSA_ADVISORY]->(g:GSA)
        RETURN
            c.id AS cve_id,
            g.id AS gsa_id,
            g.package AS package,
            c.severity AS severity
        """

        try:
            with self.driver.session() as session:
                result = session.run(query)
                return [record.data() for record in result]
        except Exception as e:
            print(f"Error fetching from Neo4j: {e}")
            return []
        
    def fetch_cve_mitre_mappings(self):
        query = """
        MATCH (c:CVE)-[r:MAPS_TO]->(m:MITRE)
        RETURN
            c.id AS cve_id,
            m.technique_id AS mitre_technique,
            r.score AS similarity_score
        ORDER BY similarity_score DESC
        """

        with self.driver.session() as session:
            result = session.run(query)
            return [record.data() for record in result]


    def ingest_cve_mitre(self, cve_mitre_mappings: dict):
        if not self.driver:
            print("Neo4j driver not initialized.")
            return

        query = """
        MERGE (c:CVE {id: $cve_id})
        MERGE (m:MITRE {technique_id: $tech_id})
        MERGE (c)-[r:MAPS_TO]->(m)
        SET r.score = $score
        """

        with self.driver.session() as session:
            for cve_id, techniques in cve_mitre_mappings.items():
                for tech_id, score in techniques:
                    session.run(
                        query,
                        cve_id=cve_id,
                        tech_id=tech_id,
                        score=score
                    )
# ============================
# MAIN EXECUTION
# ============================

if __name__ == "__main__":

    ingestor = Neo4jIngestor()

    # Load CVE-GSA mappings from JSON
    if not cve_gsa_mapping.exists():
        print(f"Mapping file {cve_gsa_mapping} does not exist.")
        cve_gsa_mappings = {}
    else:
        try:
            with open(cve_gsa_mapping, "r") as f:
                cve_gsa_mappings = json.load(f)
        except json.JSONDecodeError:
            print(f"Invalid JSON in {cve_gsa_mapping}")
            cve_gsa_mappings = {}
        except Exception as e:
            print(f"Error reading {cve_gsa_mapping}: {e}")
            cve_gsa_mappings = {}

    if cve_gsa_mappings:
        ingestor.ingest_cve_gsa(cve_gsa_mappings)
        print("Data successfully ingested into Neo4j")
    else:
        print("No mappings to ingest.")

    # Fetch back from Neo4j
    mappings_from_db = ingestor.fetch_all_mappings()

    # Export fetched data
    try:
        with open(CVE_GSA_JSON / "cve_gsa_mappings.json", "w") as f:
            json.dump(mappings_from_db, f, indent=2)
        print(f"Exported {len(mappings_from_db)} mappings")
    except Exception as e:
        print(f"Error writing export file: {e}")

   

    # ============================
# INGEST CVE → MITRE MAPPINGS
# ============================

    if not cve_mitre_mapping.exists():
        print(f"MITRE mapping file {cve_mitre_mapping} does not exist.")
        cve_mitre_mappings = {}
    else:
        try:
            with open(cve_mitre_mapping, "r") as f:
                cve_mitre_mappings = json.load(f)
        except json.JSONDecodeError:
            print(f"Invalid JSON in {cve_mitre_mapping}")
            cve_mitre_mappings = {}
        except Exception as e:
            print(f"Error reading {cve_mitre_mapping}: {e}")
            cve_mitre_mappings = {}

    if cve_mitre_mappings:
        ingestor.ingest_cve_mitre(cve_mitre_mappings)
        print("CVE–MITRE mappings successfully ingested")
    else:
        print("No CVE–MITRE mappings to ingest.")

     # Fetch back from Neo4j
    mappings_from_db_mitre = ingestor.fetch_cve_mitre_mappings()

    # Export fetched data
    try:
        with open(CVE_GSA_JSON / "cve_mitre_mappings.json", "w") as f:
            json.dump(mappings_from_db_mitre, f, indent=2)
        print(f"Exported {len(mappings_from_db_mitre)} mappings")
    except Exception as e:
        print(f"Error writing export file: {e}")


    ingestor.close()