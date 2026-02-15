# """
# Stage 03: Schema Definition and Neo4j Data Ingestion
# Reads normalized data from CVE, MITRE, and GSA JSON files and pushes to Neo4j
# """

import json
import sys
import os
import warnings
from pathlib import Path
from typing import Optional, List, Dict
from neontology.basenode import BaseNode
from neontology.baserelationship import BaseRelationship
from neontology import init_neontology
from neontology.graphengines import Neo4jConfig
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import re
import string
from nltk.corpus import stopwords
from nltk.tokenize import sent_tokenize, word_tokenize
import nltk

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

# ==================== NLP Preprocessing Functions ====================

def preprocess_text(text: str) -> str:
    """Advanced text preprocessing for better NLP analysis"""
    if not text:
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove URLs
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)
    
    # Remove special characters and punctuation but keep spaces
    text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def get_bert_embeddings(texts: List[str], model_name: str = 'all-MiniLM-L6-v2') -> np.ndarray:
    """Generate BERT embeddings for a list of texts
    
    Uses sentence-transformers for efficient semantic embeddings
    all-MiniLM-L6-v2: Lightweight, fast model (33M params)
    all-mpnet-base-v2: Higher quality but slower (109M params)
    """
    try:
        print(f"   Loading BERT model: {model_name}...")
        model = SentenceTransformer(model_name)
        print(f"   Generating embeddings for {len(texts)} texts...")
        embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
        return embeddings
    except Exception as e:
        print(f"✗ Error generating BERT embeddings: {e}")
        raise


# ==================== Schema Definitions ====================

class CVE(BaseNode):
    """CVE Node - Represents a Common Vulnerabilities and Exposures"""
    __primarylabel__ = "CVE"
    __primaryproperty__ = "cve_id"
    __secondaryproperties__ = [
        "description", "severity", "base_score", "attack_vector", 
        "attack_complexity"
    ]

    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    base_score: Optional[float] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    cwe_ids: Optional[str] = None  # Store as JSON string
    affected_software: Optional[str] = None  # Store as JSON string
    references: Optional[str] = None  # Store as JSON string


class MITRE(BaseNode):
    """MITRE ATT&CK Node - Represents a technique or tactic"""
    __primarylabel__ = "MITRE"
    __primaryproperty__ = "technique_id"
    __secondaryproperties__ = [
        "technique_name", "technique_description"
    ]

    technique_id: str
    technique_name: Optional[str] = None
    technique_description: Optional[str] = None
    tactic: Optional[str] = None  # Store as JSON string
    platforms: Optional[str] = None  # Store as JSON string


class GSA(BaseNode):
    """GSA Node - Represents a GitHub Security Advisory"""
    __primarylabel__ = "GSA"
    __primaryproperty__ = "ghsa_id"
    __secondaryproperties__ = [
        "cve_id", "summary", "severity", "package_name", 
        "vulnerable_versions", "fixed_version"
    ]

    ghsa_id: str
    cve_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    package_name: Optional[str] = None
    vulnerable_versions: Optional[str] = None
    fixed_version: Optional[str] = None
    cwes: Optional[str] = None  # Store as JSON string
    references: Optional[str] = None  # Store as JSON string


class MapsToMITRE(BaseRelationship):
    """Relationship: CVE maps to MITRE technique"""
    __relationshiptype__ = "MAPS_TO"

    source: CVE
    target: MITRE
    score: Optional[float] = None


class HasGSAAdvisory(BaseRelationship):
    """Relationship: CVE has a GSA advisory"""
    __relationshiptype__ = "HAS_GSA_ADVISORY"

    source: CVE
    target: GSA

class CVEToMITREGSA(BaseRelationship):
    """Relationship: CVE maps to MITRE technique and GSA advisory"""
    __relationshiptype__ = "CVE_TO_MITRE_GSA"

    source: CVE
    target: MITRE
    target_gsa: GSA





# ==================== Data Loading Functions ====================

def load_normalized_data(base_path: str = "/Users/abhipsa/Documents/VulnGuard AI/normalized"):
    """Load all normalized JSON data from disk"""
    base_path = Path(base_path)
    
    data = {}
    
    # Load CVE data
    cve_file = base_path / "cve" / "cve_core_fields.json"
    if cve_file.exists():
        with open(cve_file) as f:
            data["cves"] = json.load(f)
        print(f"✓ Loaded {len(data['cves'])} CVE records")
    else:
        print(f"✗ CVE file not found: {cve_file}")
        data["cves"] = []
    
    # Load MITRE data
    mitre_file = base_path / "mitre" / "mitre_attack_patterns.json"
    if mitre_file.exists():
        with open(mitre_file) as f:
            data["mitre"] = json.load(f)
        print(f"✓ Loaded {len(data['mitre'])} MITRE records")
    else:
        print(f"✗ MITRE file not found: {mitre_file}")
        data["mitre"] = []
    
    # Load GSA data
    gsa_file = base_path / "gsa" / "gsa_fix_fields.json"
    if gsa_file.exists():
        with open(gsa_file) as f:
            data["gsa"] = json.load(f)
        print(f"✓ Loaded {len(data['gsa'])} GSA records")
    else:
        print(f"✗ GSA file not found: {gsa_file}")
        data["gsa"] = []
    
    return data


def ingest_cves(cve_records: List[Dict]):
    """Ingest CVE records into Neo4j"""
    if not cve_records:
        print("⚠ No CVE records to ingest")
        return
    
    try:
        # Prepare records for Neontology
        cve_nodes = []
        for cve in cve_records:
            node = {
                "cve_id": cve.get("cve_id"),
                "description": cve.get("description"),
                "severity": cve.get("severity"),
                "base_score": float(cve.get("base_score", 0)) if cve.get("base_score") else None,
                "attack_vector": cve.get("attack_vector"),
                "attack_complexity": cve.get("attack_complexity"),
                "cwe_ids": json.dumps(cve.get("cwe_ids", [])) if cve.get("cwe_ids") else None,
                "affected_software": json.dumps(cve.get("affected_software", [])) if cve.get("affected_software") else None,
                "references": json.dumps(cve.get("references", [])) if cve.get("references") else None
            }
            cve_nodes.append(node)
        
        CVE.merge_records(cve_nodes)
        print(f"Ingested {len(cve_nodes)} CVE nodes into Neo4j")
    except Exception as e:
        print(f" Error ingesting CVE records: {e}")


def ingest_mitre(mitre_records: List[Dict]):
    """Ingest MITRE records into Neo4j"""
    if not mitre_records:
        print("⚠ No MITRE records to ingest")
        return
    
    try:
        # Prepare records for Neontology
        mitre_nodes = []
        for technique in mitre_records:
            node = {
                "technique_id": technique.get("technique_id"),
                "technique_name": technique.get("technique_name"),
                "technique_description": technique.get("technique_description"),
                "tactic": json.dumps(technique.get("tactic", [])) if technique.get("tactic") else None,
                "platforms": json.dumps(technique.get("platforms", [])) if technique.get("platforms") else None
            }
            mitre_nodes.append(node)
        
        MITRE.merge_records(mitre_nodes)
        print(f"✓ Ingested {len(mitre_nodes)} MITRE nodes into Neo4j")
    except Exception as e:
        print(f"✗ Error ingesting MITRE records: {e}")
        import traceback
        traceback.print_exc()


def ingest_gsa(gsa_records: List[Dict]):
    """Ingest GSA records into Neo4j"""
    if not gsa_records:
        print("⚠ No GSA records to ingest")
        return
    
    try:
        # Prepare records for Neontology
        gsa_nodes = []
        for advisory in gsa_records:
            node = {
                "ghsa_id": advisory.get("ghsa_id") or advisory.get("gsa_id"),
                "cve_id": advisory.get("cve_id"),
                "summary": advisory.get("summary"),
                "description": advisory.get("description"),
                "severity": advisory.get("severity"),
                "package_name": advisory.get("package_name"),
                "vulnerable_versions": advisory.get("vulnerable_versions"),
                "fixed_version": advisory.get("fixed_version"),
                "cwes": json.dumps(advisory.get("cwes", [])) if advisory.get("cwes") else None,
                "references": json.dumps(advisory.get("references", [])) if advisory.get("references") else None
            }
            gsa_nodes.append(node)
        
        GSA.merge_records(gsa_nodes)
        print(f"✓ Ingested {len(gsa_nodes)} GSA nodes into Neo4j")
    except Exception as e:
        print(f"✗ Error ingesting GSA records: {e}")
        import traceback
        traceback.print_exc()


def create_cve_gsa_relationships(gsa_records: List[Dict]):
    """Create HasGSAAdvisory relationships between CVE and GSA nodes"""
    if not gsa_records:
        return
    
    try:
        relationships = []
        for advisory in gsa_records:
            cve_id = advisory.get("cve_id")
            ghsa_id = advisory.get("ghsa_id") or advisory.get("gsa_id")
            
            if cve_id and ghsa_id:
                rel = {
                    "source": cve_id,
                    "target": ghsa_id
                }
                relationships.append(rel)
        
        if relationships:
            HasGSAAdvisory.merge_records(relationships)
            print(f"✓ Created {len(relationships)} CVE-GSA relationships")
    except Exception as e:
        print(f"✗ Error creating CVE-GSA relationships: {e}")
        import traceback
        traceback.print_exc()

def create_cve_mitre_relationships(mappings: List[Dict]):
    """Create MapsToMITRE relationships between CVE and MITRE nodes"""
    if not mappings:
        return
    
    try:
        relationships = []
        for mapping in mappings:
            cve_id = mapping.get("cve_id")
            technique_id = mapping.get("technique_id")
            score = mapping.get("score")
            
            if cve_id and technique_id:
                rel = {
                    "source": cve_id,
                    "target": technique_id,
                    "score": float(score) if score is not None else None
                }
                relationships.append(rel)
        
        if relationships:
            MapsToMITRE.merge_records(relationships)
            print(f"✓ Created {len(relationships)} CVE-MITRE relationships")
    except Exception as e:
        print(f"✗ Error creating CVE-MITRE relationships: {e}")
        import traceback
        traceback.print_exc()

def mitre_cve_relationship(mitre_records: List[Dict], cve_records: List[Dict]):
    """Create CVE-MITRE relationships using BERT embeddings with top-K matching
    
    Args:
        mitre_records: List of MITRE technique records
        cve_records: List of CVE records
        
    Uses:
        - MITRE technique_description vs CVE description
        - similarity_threshold: 0.32
        - top_k: 3 (top 3 MITRE matches per CVE)
    """
    if not mitre_records or not cve_records:
        print("⚠ Missing required data for mitre_cve_relationship")
        return
    
    try:
        print("   Building CVE-MITRE relationships using BERT semantic similarity (top-k=3)...")
        relationships = []
        
        # Collect and preprocess descriptions
        cve_data = []  # List of (cve_id, preprocessed_text)
        mitre_data = []  # List of (technique_id, preprocessed_text)
        
        print("   Preprocessing CVE descriptions...")
        for cve in cve_records:
            cve_id = cve.get("cve_id")
            description = cve.get("description", "")
            if cve_id and description:
                preprocessed = preprocess_text(description)
                if preprocessed:
                    cve_data.append((cve_id, preprocessed))
        
        print("   Preprocessing MITRE technique descriptions...")
        for mitre in mitre_records:
            technique_id = mitre.get('technique_id')
            technique_desc = mitre.get("technique_description", "")
            if technique_id and technique_desc:
                preprocessed = preprocess_text(technique_desc)
                if preprocessed:
                    mitre_data.append((technique_id, preprocessed))
        
        print(f"\n   Data collected: CVE={len(cve_data)}, MITRE={len(mitre_data)}")
        
        if not (cve_data and mitre_data):
            print(f"⚠ Insufficient data for relationship creation")
            return
        
        # Extract texts for embedding
        cve_texts = [text for _, text in cve_data]
        mitre_texts = [text for _, text in mitre_data]
        
        # Generate BERT embeddings
        print("\n   Generating BERT embeddings...")
        print("   • CVE descriptions...")
        cve_embeddings = get_bert_embeddings(cve_texts)
        
        print("   • MITRE technique descriptions...")
        mitre_embeddings = get_bert_embeddings(mitre_texts)
        
        # Parameters
        similarity_threshold = 0.32
        top_k = 3
        
        print(f"\n   Computing semantic similarities (threshold={similarity_threshold}, top_k={top_k})...")
        
        # For each CVE, find top-k similar MITRE techniques
        for idx_cve, (cve_id, _) in enumerate(cve_data):
            # Calculate similarity between this CVE and all MITRE techniques
            similarities = []
            
            for idx_mitre, (mitre_id, _) in enumerate(mitre_data):
                similarity = cosine_similarity(
                    cve_embeddings[idx_cve:idx_cve+1],
                    mitre_embeddings[idx_mitre:idx_mitre+1]
                )[0][0]
                
                if similarity >= similarity_threshold:
                    similarities.append((mitre_id, similarity))
            
            # Sort by similarity and get top-k
            similarities.sort(key=lambda x: x[1], reverse=True)
            top_matches = similarities[:top_k]
            
            # Create relationships for top matches
            for mitre_id, score in top_matches:
                rel = {
                    "source": cve_id,
                    "target": mitre_id,
                    "score": float(round(score, 4))
                }
                relationships.append(rel)
        
        # Ingest relationships
        if relationships:
            MapsToMITRE.merge_records(relationships)
            print(f"\n✓ Created {len(relationships)} CVE-MITRE relationships")
            print(f"  • Similarity threshold: {similarity_threshold}")
            print(f"  • Top-K matches per CVE: {top_k}")
            print(f"  • Using: MITRE technique_description vs CVE description")
        else:
            print(f"⚠ No semantic matches found above threshold ({similarity_threshold})")
            
    except Exception as e:
        print(f"✗ Error creating CVE-MITRE relationships: {e}")
        import traceback
        traceback.print_exc()
    
  
        
    
    


# # ==================== Initialization ====================

def init_graph():
    """Initialize Neo4j connection with provided credentials"""
    config = Neo4jConfig(
        uri="neo4j://localhost:7687",
        username="neo4j",
        password="testpassword"
    )
   
    init_neontology(config)
    print("Neo4j Graph initialized with credentials")


# # ==================== Main Pipeline ====================

def main():
    """Main execution pipeline"""
    print("\n" + "="*60)
    print("Stage 03: Schema & Neo4j Data Ingestion")
    print("="*60 + "\n")
    
    try:
        # Step 1: Initialize Neo4j connection
        print("Step 1: Initializing Neo4j connection...")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                init_graph()
        except Exception as e:
            print(f"✗ Failed to initialize Neo4j: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Step 2: Load normalized data
        print("\nStep 2: Loading normalized data...")
        try:
            data = load_normalized_data()
        except Exception as e:
            print(f"✗ Failed to load normalized data: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Step 3: Ingest CVE data
        print("\nStep 3: Ingesting CVE data...")
        ingest_cves(data.get("cves", []))
        
        # Step 4: Ingest MITRE data
        print("\nStep 4: Ingesting MITRE data...")
        ingest_mitre(data.get("mitre", []))
        
        # Step 5: Ingest GSA data
        print("\nStep 5: Ingesting GSA data...")
        ingest_gsa(data.get("gsa", []))
        
        # Step 6: Create relationships
        print("\nStep 6: Creating relationships...")
        create_cve_gsa_relationships(data.get("gsa", []))
        mitre_cve_relationship(data.get("mitre", []), data.get("cves", []))

        print("\n" + "="*60)
        print("✓ Data ingestion pipeline completed successfully!")
        print("="*60 + "\n")
    
    except Exception as e:
        print(f"\n✗ Unexpected error in main pipeline: {e}")
        import traceback
        traceback.print_exc()
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
        # Exit cleanly without running destructors to avoid Neo4j shutdown errors
        print("\n✓ Exiting successfully...")
        os._exit(0)
    except KeyboardInterrupt:
        print("\n\n✗ Pipeline interrupted by user")
        os._exit(130)
    except Exception as e:
        print(f"\n\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        os._exit(1)
