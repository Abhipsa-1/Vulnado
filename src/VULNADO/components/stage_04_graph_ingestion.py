"""
Stage 04: Neo4j Data Fetching and Preparation for Model Training
Fetches all data from Neo4j graph database and prepares it for Llama model training
"""

import json
import sys
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from neo4j import GraphDatabase
import traceback
from datetime import datetime
from VULNADO.config.configuration import get_config

# ==================== Logging Setup ====================

def setup_logging(log_dir: str = None) -> logging.Logger:
    """Setup comprehensive logging for the data fetching process"""
    if log_dir is None:
        config = get_config()
        log_dir = config.logging.log_dir
    
    # Create logs directory if it doesn't exist
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    # File handler
    log_file = Path(log_dir) / f"stage_04_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    return logger


logger = setup_logging()

# ==================== Neo4j Connection Handler ====================

class Neo4jConnectionHandler:
    """Handles Neo4j database connections with error handling"""
    
    def __init__(self, uri: str, username: str, password: str):
        """Initialize Neo4j connection handler
        
        Args:
            uri: Neo4j connection URI (e.g., neo4j://localhost:7687)
            username: Database username
            password: Database password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        logger.info(f"Initializing Neo4j connection to {uri}")
    
    def connect(self) -> bool:
        """Establish connection to Neo4j
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                connection_timeout=30
            )
            
            # Test connection
            with self.driver.session() as session:
                result = session.run("RETURN 'Neo4j is alive' AS message")
                message = result.single()["message"]
                logger.info(f"✓ Neo4j connection successful: {message}")
                return True
                
        except Exception as e:
            logger.error(f"✗ Failed to connect to Neo4j: {e}")
            logger.debug(traceback.format_exc())
            return False
    
    def close(self):
        """Close Neo4j connection"""
        try:
            if self.driver:
                self.driver.close()
                logger.info("Neo4j connection closed")
        except Exception as e:
            logger.error(f"Error closing Neo4j connection: {e}")
    
    def execute_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Cypher query and return results
        
        Args:
            query: Cypher query string
            parameters: Query parameters dictionary
            
        Returns:
            List of result dictionaries
        """
        try:
            if not self.driver:
                logger.error("Driver not initialized")
                return []
            
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                records = [dict(record) for record in result]
                logger.debug(f"Query executed, returned {len(records)} records")
                return records
                
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            logger.debug(traceback.format_exc())
            return []


# ==================== Data Fetching Functions ====================

def fetch_cve_nodes(neo4j_handler: Neo4jConnectionHandler) -> List[Dict]:
    """Fetch all CVE nodes from Neo4j
    
    Args:
        neo4j_handler: Neo4j connection handler
        
    Returns:
        List of CVE node dictionaries
    """
    logger.info("Fetching CVE nodes from Neo4j...")
    
    query = """
    MATCH (cve:CVE)
    RETURN cve.cve_id as cve_id,
           cve.description as description,
           cve.severity as severity,
           cve.base_score as base_score,
           cve.attack_vector as attack_vector,
           cve.attack_complexity as attack_complexity,
           cve.cwe_ids as cwe_ids,
           cve.affected_software as affected_software,
           cve.references as references
    LIMIT 10000
    """
    
    try:
        records = neo4j_handler.execute_query(query)
        logger.info(f"✓ Fetched {len(records)} CVE nodes")
        return records
    except Exception as e:
        logger.error(f"Error fetching CVE nodes: {e}")
        return []


def fetch_mitre_nodes(neo4j_handler: Neo4jConnectionHandler) -> List[Dict]:
    """Fetch all MITRE nodes from Neo4j
    
    Args:
        neo4j_handler: Neo4j connection handler
        
    Returns:
        List of MITRE node dictionaries
    """
    logger.info("Fetching MITRE nodes from Neo4j...")
    
    query = """
    MATCH (mitre:MITRE)
    RETURN mitre.technique_id as technique_id,
           mitre.technique_name as technique_name,
           mitre.technique_description as technique_description,
           mitre.tactic as tactic,
           mitre.platforms as platforms
    LIMIT 10000
    """
    
    try:
        records = neo4j_handler.execute_query(query)
        logger.info(f"✓ Fetched {len(records)} MITRE nodes")
        return records
    except Exception as e:
        logger.error(f"Error fetching MITRE nodes: {e}")
        return []


def fetch_gsa_nodes(neo4j_handler: Neo4jConnectionHandler) -> List[Dict]:
    """Fetch all GSA nodes from Neo4j
    
    Args:
        neo4j_handler: Neo4j connection handler
        
    Returns:
        List of GSA node dictionaries
    """
    logger.info("Fetching GSA nodes from Neo4j...")
    
    query = """
    MATCH (gsa:GSA)
    RETURN gsa.ghsa_id as ghsa_id,
           gsa.cve_id as cve_id,
           gsa.summary as summary,
           gsa.description as description,
           gsa.severity as severity,
           gsa.package_name as package_name,
           gsa.vulnerable_versions as vulnerable_versions,
           gsa.fixed_version as fixed_version,
           gsa.cwes as cwes,
           gsa.references as references
    LIMIT 10000
    """
    
    try:
        records = neo4j_handler.execute_query(query)
        logger.info(f"✓ Fetched {len(records)} GSA nodes")
        return records
    except Exception as e:
        logger.error(f"Error fetching GSA nodes: {e}")
        return []


def fetch_relationships(neo4j_handler: Neo4jConnectionHandler) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Fetch all relationships from Neo4j
    
    Args:
        neo4j_handler: Neo4j connection handler
        
    Returns:
        Tuple of (cve_gsa_rels, cve_mitre_rels, cve_mitre_gsa_rels)
    """
    logger.info("Fetching relationships from Neo4j...")
    
    # CVE-GSA relationships
    query_cve_gsa = """
    MATCH (cve:CVE)-[rel:HAS_GSA_ADVISORY]->(gsa:GSA)
    RETURN cve.cve_id as source_cve,
           gsa.ghsa_id as target_gsa,
           type(rel) as relationship_type
    LIMIT 10000
    """
    
    # CVE-MITRE relationships
    query_cve_mitre = """
    MATCH (cve:CVE)-[rel:MAPS_TO]->(mitre:MITRE)
    RETURN cve.cve_id as source_cve,
           mitre.technique_id as target_mitre,
           rel.score as score,
           type(rel) as relationship_type
    LIMIT 100000
    """
    
    # CVE-MITRE-GSA relationships
    query_cve_mitre_gsa = """
    MATCH (cve:CVE)-[rel:CVE_TO_MITRE_GSA]->(mitre:MITRE)
    RETURN cve.cve_id as source_cve,
           mitre.technique_id as target_mitre,
           rel.cve_mitre_score as cve_mitre_score,
           rel.gsa_mitre_score as gsa_mitre_score,
           rel.cve_gsa_score as cve_gsa_score,
           type(rel) as relationship_type
    LIMIT 100000
    """
    
    try:
        cve_gsa_rels = neo4j_handler.execute_query(query_cve_gsa)
        logger.info(f"✓ Fetched {len(cve_gsa_rels)} CVE-GSA relationships")
        
        cve_mitre_rels = neo4j_handler.execute_query(query_cve_mitre)
        logger.info(f"✓ Fetched {len(cve_mitre_rels)} CVE-MITRE relationships")
        
        cve_mitre_gsa_rels = neo4j_handler.execute_query(query_cve_mitre_gsa)
        logger.info(f"✓ Fetched {len(cve_mitre_gsa_rels)} CVE-MITRE-GSA relationships")
        
        return cve_gsa_rels, cve_mitre_rels, cve_mitre_gsa_rels
        
    except Exception as e:
        logger.error(f"Error fetching relationships: {e}")
        return [], [], []


# ==================== Data Saving Functions ====================

def save_data_to_file(data: Dict, output_dir: str = None) -> bool:
    """Save fetched data to JSON files
    
    Args:
        data: Dictionary containing all fetched data
        output_dir: Directory to save files
        
    Returns:
        bool: True if successful, False otherwise
    """
    if output_dir is None:
        config = get_config()
        output_dir = config.models.training_data_dir
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"Saving data to {output_dir}...")
        
        # Save each component
        components = {
            'cve_nodes': 'cve_nodes.json',
            'mitre_nodes': 'mitre_nodes.json',
            'gsa_nodes': 'gsa_nodes.json',
            'cve_gsa_relationships': 'cve_gsa_relationships.json',
            'cve_mitre_relationships': 'cve_mitre_relationships.json',
            'cve_mitre_gsa_relationships': 'cve_mitre_gsa_relationships.json'
        }
        
        for key, filename in components.items():
            if key in data:
                filepath = Path(output_dir) / filename
                with open(filepath, 'w') as f:
                    json.dump(data[key], f, indent=2)
                logger.info(f"✓ Saved {len(data[key])} records to {filename}")
        
        # Save summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_cve_nodes': len(data.get('cve_nodes', [])),
            'total_mitre_nodes': len(data.get('mitre_nodes', [])),
            'total_gsa_nodes': len(data.get('gsa_nodes', [])),
            'total_cve_gsa_relationships': len(data.get('cve_gsa_relationships', [])),
            'total_cve_mitre_relationships': len(data.get('cve_mitre_relationships', [])),
            'total_cve_mitre_gsa_relationships': len(data.get('cve_mitre_gsa_relationships', []))
        }
        
        summary_path = Path(output_dir) / 'summary.json'
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"✓ Saved summary to summary.json")
        
        logger.info("✓ All data saved successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error saving data: {e}")
        logger.debug(traceback.format_exc())
        return False


def create_training_dataset(data: Dict, output_file: str = None) -> bool:
    """Create a unified training dataset for Llama model
    
    Args:
        data: Dictionary containing all fetched data
        output_file: Path to save training dataset
        
    Returns:
        bool: True if successful, False otherwise
    """
    if output_file is None:
        config = get_config()
        output_file = config.models.training_dataset_file
    
    try:
        logger.info("Creating unified training dataset...")
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        training_samples = []
        
        # Create training samples from CVE-MITRE relationships
        cve_nodes = {node['cve_id']: node for node in data.get('cve_nodes', [])}
        mitre_nodes = {node['technique_id']: node for node in data.get('mitre_nodes', [])}
        
        for rel in data.get('cve_mitre_relationships', []):
            try:
                cve_id = rel.get('source_cve')
                mitre_id = rel.get('target_mitre')
                score = rel.get('score', 0)
                
                if cve_id in cve_nodes and mitre_id in mitre_nodes:
                    cve = cve_nodes[cve_id]
                    mitre = mitre_nodes[mitre_id]
                    
                    sample = {
                        'instruction': f"Map the CVE vulnerability to MITRE ATT&CK techniques",
                        'input': f"CVE ID: {cve_id}\nDescription: {cve.get('description', 'N/A')}\nSeverity: {cve.get('severity', 'N/A')}",
                        'output': f"MITRE Technique: {mitre_id}\nName: {mitre.get('technique_name', 'N/A')}\nDescription: {mitre.get('technique_description', 'N/A')}\nRelevance Score: {score}",
                        'metadata': {
                            'cve_id': cve_id,
                            'mitre_id': mitre_id,
                            'score': score
                        }
                    }
                    training_samples.append(sample)
            except Exception as e:
                logger.warning(f"Error processing relationship: {e}")
                continue
        
        # Save training dataset in JSONL format
        with open(output_file, 'w') as f:
            for sample in training_samples:
                f.write(json.dumps(sample) + '\n')
        
        logger.info(f"✓ Created training dataset with {len(training_samples)} samples")
        logger.info(f"✓ Saved to {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating training dataset: {e}")
        logger.debug(traceback.format_exc())
        return False


# ==================== Main Execution ====================

def main():
    """Main execution pipeline"""
    print("\n" + "="*70)
    print("Stage 04: Neo4j Data Fetching and Preparation for Model Training")
    print("="*70 + "\n")
    
    neo4j_handler = None
    
    try:
        # Step 1: Connect to Neo4j
        logger.info("\nStep 1: Connecting to Neo4j...")
        neo4j_handler = Neo4jConnectionHandler(
            uri="neo4j://localhost:7687",
            username="neo4j",
            password="testpassword"
        )
        
        if not neo4j_handler.connect():
            logger.error("Failed to connect to Neo4j")
            return False
        
        # Step 2: Fetch all nodes
        logger.info("\nStep 2: Fetching nodes from Neo4j...")
        cve_nodes = fetch_cve_nodes(neo4j_handler)
        mitre_nodes = fetch_mitre_nodes(neo4j_handler)
        gsa_nodes = fetch_gsa_nodes(neo4j_handler)
        
        if not (cve_nodes or mitre_nodes or gsa_nodes):
            logger.error("No nodes fetched from Neo4j")
            return False
        
        # Step 3: Fetch all relationships
        logger.info("\nStep 3: Fetching relationships from Neo4j...")
        cve_gsa_rels, cve_mitre_rels, cve_mitre_gsa_rels = fetch_relationships(neo4j_handler)
        
        # Step 4: Prepare data dictionary
        logger.info("\nStep 4: Preparing data for export...")
        data = {
            'cve_nodes': cve_nodes,
            'mitre_nodes': mitre_nodes,
            'gsa_nodes': gsa_nodes,
            'cve_gsa_relationships': cve_gsa_rels,
            'cve_mitre_relationships': cve_mitre_rels,
            'cve_mitre_gsa_relationships': cve_mitre_gsa_rels
        }
        
        # Step 5: Save data to files
        logger.info("\nStep 5: Saving data to files...")
        if not save_data_to_file(data):
            logger.error("Failed to save data to files")
            return False
        
        # Step 6: Create training dataset
        logger.info("\nStep 6: Creating training dataset for Llama model...")
        if not create_training_dataset(data):
            logger.error("Failed to create training dataset")
            return False
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("✓ Data fetching and preparation completed successfully!")
        logger.info("="*70)
        logger.info(f"\nSummary:")
        logger.info(f"  • CVE Nodes: {len(cve_nodes)}")
        logger.info(f"  • MITRE Nodes: {len(mitre_nodes)}")
        logger.info(f"  • GSA Nodes: {len(gsa_nodes)}")
        logger.info(f"  • CVE-GSA Relationships: {len(cve_gsa_rels)}")
        logger.info(f"  • CVE-MITRE Relationships: {len(cve_mitre_rels)}")
        logger.info(f"  • CVE-MITRE-GSA Relationships: {len(cve_mitre_gsa_rels)}")
        config = get_config()
        logger.info(f"\nTraining data saved to: {config.models.training_data_dir}")
        logger.info("="*70 + "\n")
        
        return True
        
    except Exception as e:
        logger.error(f"Fatal error in main pipeline: {e}")
        logger.debug(traceback.format_exc())
        return False
        
    finally:
        # Cleanup
        if neo4j_handler:
            neo4j_handler.close()


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
