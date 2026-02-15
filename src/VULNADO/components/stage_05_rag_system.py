"""
Stage 05: RAG (Retrieval-Augmented Generation) System
Implements semantic retrieval from Neo4j knowledge graph to augment LLaMA training
Uses embeddings and vector similarity for context-aware vulnerability data retrieval
"""

import json
import sys
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from neo4j import GraphDatabase
import traceback
from datetime import datetime
import numpy as np

# Try to import optional dependencies
try:
    from sentence_transformers import SentenceTransformer, util
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except (ImportError, Exception) as e:
    # ChromaDB may fail to import due to Pydantic v1 compatibility issues with Python 3.14+
    HAS_CHROMADB = False
    if "ConfigError" in str(type(e).__name__):
        pass  # Pydantic compatibility issue - continue without ChromaDB


# ==================== Logging Setup ====================

def setup_logging(log_dir: str = "/Users/abhipsa/Documents/VulnGuard AI/logs") -> logging.Logger:
    """Setup comprehensive logging for RAG retrieval"""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers = []
    
    log_file = Path(log_dir) / f"stage_04b_rag_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"RAG Logging initialized. Log file: {log_file}")
    return logger


logger = setup_logging()


# ==================== Embedding Service ====================

class EmbeddingService:
    """Service for generating embeddings of vulnerability data"""
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """Initialize embedding service
        
        Args:
            model_name: HuggingFace model name for embeddings
        """
        self.model_name = model_name
        self.model = None
        self.device = 'cpu'
        
        if not HAS_SENTENCE_TRANSFORMERS:
            logger.warning("sentence-transformers not installed. Install with: pip install sentence-transformers")
            self.available = False
            return
        
        self.available = True
        
    def initialize(self) -> bool:
        """Load the embedding model
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Loading embedding model: {self.model_name}...")
            
            # Try to use GPU if available
            try:
                import torch
                if torch.cuda.is_available():
                    self.device = 'cuda'
                    logger.info(f"Using GPU for embeddings")
            except ImportError:
                pass
            
            self.model = SentenceTransformer(self.model_name, device=self.device)
            logger.info(f"✓ Embedding model loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            return False
    
    def encode(self, texts: List[str]) -> Optional[np.ndarray]:
        """Encode texts to embeddings
        
        Args:
            texts: List of text strings to encode
            
        Returns:
            numpy array of embeddings or None if error
        """
        if not self.available or self.model is None:
            logger.error("Embedding service not initialized")
            return None
        
        try:
            logger.debug(f"Encoding {len(texts)} texts...")
            embeddings = self.model.encode(texts, convert_to_numpy=True)
            logger.debug(f"✓ Encoded {len(texts)} texts, shape: {embeddings.shape}")
            return embeddings
            
        except Exception as e:
            logger.error(f"Error encoding texts: {e}")
            return None
    
    def semantic_search(self, query: str, corpus_embeddings: np.ndarray, 
                       corpus_texts: List[str], top_k: int = 5) -> List[Dict]:
        """Perform semantic search on corpus
        
        Args:
            query: Query text
            corpus_embeddings: Pre-computed embeddings of corpus
            corpus_texts: Original texts of corpus
            top_k: Number of top results to return
            
        Returns:
            List of dicts with 'text', 'score', 'index'
        """
        if not self.available or self.model is None:
            logger.error("Embedding service not initialized")
            return []
        
        try:
            # Encode query
            query_embedding = self.model.encode(query, convert_to_numpy=True)
            
            # Compute similarity scores
            cos_sim = util.pytorch_cos_sim(query_embedding, corpus_embeddings)
            
            # Get top k results
            top_k = min(top_k, len(corpus_texts))
            top_results = util.semantic_search(query_embedding, corpus_embeddings, top_k=top_k)
            
            results = []
            for result in top_results[0]:
                idx = result['corpus_id']
                score = result['score']
                results.append({
                    'text': corpus_texts[idx],
                    'score': float(score),
                    'index': idx
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error in semantic search: {e}")
            return []


# ==================== Vector Store Service ====================

class VectorStoreService:
    """Service for storing and retrieving embeddings using vector database"""
    
    def __init__(self, persist_dir: str = "/Users/abhipsa/Documents/VulnGuard AI/vectorstore"):
        """Initialize vector store service
        
        Args:
            persist_dir: Directory to persist vector store
        """
        self.persist_dir = persist_dir
        self.client = None
        
        if not HAS_CHROMADB:
            logger.warning("chromadb not installed. Install with: pip install chromadb")
            self.available = False
            return
        
        self.available = True
    
    def initialize(self) -> bool:
        """Initialize Chroma vector store
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Initializing Chroma vector store at {self.persist_dir}...")
            
            Path(self.persist_dir).mkdir(parents=True, exist_ok=True)
            
            self.client = chromadb.Client(Settings(
                chroma_db_impl="duckdb_parquet",
                persist_directory=self.persist_dir,
                anonymized_telemetry=False
            ))
            
            logger.info(f"✓ Chroma vector store initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            return False
    
    def create_collection(self, name: str, metadata: Dict = None) -> Optional[Any]:
        """Create a collection in the vector store
        
        Args:
            name: Collection name
            metadata: Optional metadata for collection
            
        Returns:
            Collection object or None if error
        """
        if not self.available or self.client is None:
            logger.error("Vector store not initialized")
            return None
        
        try:
            # Delete if exists
            try:
                self.client.delete_collection(name=name)
            except:
                pass
            
            collection = self.client.create_collection(
                name=name,
                metadata=metadata or {}
            )
            logger.info(f"✓ Created collection: {name}")
            return collection
            
        except Exception as e:
            logger.error(f"Error creating collection: {e}")
            return None
    
    def add_documents(self, collection: Any, embeddings: np.ndarray, 
                     documents: List[str], metadatas: List[Dict] = None,
                     ids: List[str] = None) -> bool:
        """Add documents with embeddings to collection
        
        Args:
            collection: Chroma collection object
            embeddings: numpy array of embeddings
            documents: List of document texts
            metadatas: Optional metadata for each document
            ids: Optional document IDs
            
        Returns:
            bool: True if successful, False otherwise
        """
        if collection is None:
            logger.error("Collection is None")
            return False
        
        try:
            logger.info(f"Adding {len(documents)} documents to collection...")
            
            if ids is None:
                ids = [f"doc_{i}" for i in range(len(documents))]
            
            if metadatas is None:
                metadatas = [{} for _ in range(len(documents))]
            
            collection.add(
                embeddings=embeddings.tolist(),
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"✓ Added {len(documents)} documents to collection")
            return True
            
        except Exception as e:
            logger.error(f"Error adding documents: {e}")
            return False
    
    def query(self, collection: Any, query_embeddings: np.ndarray, 
             n_results: int = 5) -> List[Dict]:
        """Query the collection for similar documents
        
        Args:
            collection: Chroma collection object
            query_embeddings: numpy array of query embeddings
            n_results: Number of results to return
            
        Returns:
            List of matching documents with metadata
        """
        if collection is None:
            logger.error("Collection is None")
            return []
        
        try:
            results = collection.query(
                query_embeddings=query_embeddings.tolist(),
                n_results=n_results
            )
            
            # Format results
            formatted_results = []
            for i, doc in enumerate(results['documents'][0]):
                formatted_results.append({
                    'document': doc,
                    'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                    'distance': results['distances'][0][i] if 'distances' in results else None,
                    'id': results['ids'][0][i] if results['ids'] else None
                })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error querying collection: {e}")
            return []


# ==================== Neo4j RAG Retriever ====================

class Neo4jRAGRetriever:
    """Retrieves and augments data from Neo4j for RAG"""
    
    def __init__(self, neo4j_uri: str, neo4j_username: str, neo4j_password: str):
        """Initialize Neo4j RAG retriever
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_username: Neo4j username
            neo4j_password: Neo4j password
        """
        self.uri = neo4j_uri
        self.username = neo4j_username
        self.password = neo4j_password
        self.driver = None
        
    def connect(self) -> bool:
        """Connect to Neo4j
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Connecting to Neo4j at {self.uri}...")
            
            # Handle different URI formats
            uri = self.uri
            
            # If HTTP browser URL (localhost:7474), convert to Bolt protocol
            if "localhost:7474" in uri or "127.0.0.1:7474" in uri:
                # Browser UI is on port 7474, but we need Bolt on port 7687
                logger.info("Detected HTTP browser endpoint, using Bolt protocol instead...")
                uri = uri.replace("http://localhost:7474", "neo4j://localhost:7687")
                uri = uri.replace("http://127.0.0.1:7474", "neo4j://127.0.0.1:7687")
            
            logger.info(f"Using connection URI: {uri}")
            
            self.driver = GraphDatabase.driver(
                uri,
                auth=(self.username, self.password),
                connection_timeout=30
            )
            
            with self.driver.session() as session:
                result = session.run("RETURN 'Neo4j is alive' AS message")
                message = result.single()["message"]
                logger.info(f"✓ Neo4j connection successful: {message}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            logger.info("\nTroubleshooting:")
            logger.info("  • Check Neo4j is running: http://localhost:7474/browser/")
            logger.info("  • Verify credentials (default: neo4j/testpassword)")
            logger.info("  • Ensure Bolt port 7687 is accessible")
            logger.info("  • Check firewall settings")
            return False
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def retrieve_cve_context(self, cve_id: str) -> Dict:
        """Retrieve complete context for a CVE
        
        Args:
            cve_id: CVE ID to retrieve context for
            
        Returns:
            Dictionary with CVE and related data
        """
        if not self.driver:
            logger.error("Driver not connected")
            return {}
        
        try:
            with self.driver.session() as session:
                # Get CVE node
                query = """
                MATCH (cve:CVE {cve_id: $cve_id})
                RETURN cve
                """
                
                result = session.run(query, cve_id=cve_id)
                cve_record = result.single()
                
                if not cve_record:
                    logger.warning(f"CVE not found: {cve_id}")
                    return {}
                
                cve_node = dict(cve_record['cve'])
                
                # Get related MITRE techniques
                query_mitre = """
                MATCH (cve:CVE {cve_id: $cve_id})-[rel:MAPS_TO]->(mitre:MITRE)
                RETURN mitre, rel.score as score
                ORDER BY rel.score DESC
                LIMIT 10
                """
                
                mitre_results = session.run(query_mitre, cve_id=cve_id)
                mitre_techniques = []
                for record in mitre_results:
                    mitre_techniques.append({
                        'technique': dict(record['mitre']),
                        'score': record['score']
                    })
                
                # Get related GSA advisories
                query_gsa = """
                MATCH (cve:CVE {cve_id: $cve_id})-[rel:HAS_GSA_ADVISORY]->(gsa:GSA)
                RETURN gsa
                LIMIT 10
                """
                
                gsa_results = session.run(query_gsa, cve_id=cve_id)
                gsa_advisories = [dict(record['gsa']) for record in gsa_results]
                
                return {
                    'cve': cve_node,
                    'mitre_techniques': mitre_techniques,
                    'gsa_advisories': gsa_advisories
                }
                
        except Exception as e:
            logger.error(f"Error retrieving CVE context: {e}")
            return {}
    
    def retrieve_similar_cves(self, cve_id: str, limit: int = 5) -> List[Dict]:
        """Retrieve similar CVEs based on graph connections
        
        Args:
            cve_id: CVE ID to find similar CVEs for
            limit: Maximum number of similar CVEs to retrieve
            
        Returns:
            List of similar CVE dictionaries
        """
        if not self.driver:
            logger.error("Driver not connected")
            return []
        
        try:
            with self.driver.session() as session:
                query = """
                MATCH (cve1:CVE {cve_id: $cve_id})-[:MAPS_TO]->(mitre:MITRE)<-[:MAPS_TO]-(cve2:CVE)
                WHERE cve1.cve_id <> cve2.cve_id
                RETURN DISTINCT cve2
                LIMIT $limit
                """
                
                results = session.run(query, cve_id=cve_id, limit=limit)
                similar_cves = [dict(record['cve2']) for record in results]
                
                logger.info(f"Found {len(similar_cves)} similar CVEs for {cve_id}")
                return similar_cves
                
        except Exception as e:
            logger.error(f"Error retrieving similar CVEs: {e}")
            return []


# ==================== RAG Context Generator ====================

class RAGContextGenerator:
    """Generates RAG-augmented training samples with retrieved context"""
    
    def __init__(self, embedding_service: EmbeddingService, 
                 neo4j_retriever: Neo4jRAGRetriever):
        """Initialize RAG context generator
        
        Args:
            embedding_service: EmbeddingService instance
            neo4j_retriever: Neo4jRAGRetriever instance
        """
        self.embedding_service = embedding_service
        self.neo4j_retriever = neo4j_retriever
    
    def generate_rag_augmented_sample(self, cve_id: str, mitre_id: str, 
                                     cve_description: str, score: float) -> Dict:
        """Generate a RAG-augmented training sample
        
        Args:
            cve_id: CVE ID
            mitre_id: MITRE technique ID
            cve_description: CVE description
            score: Mapping confidence score
            
        Returns:
            Dictionary with augmented training sample
        """
        # Retrieve context from Neo4j
        cve_context = self.neo4j_retriever.retrieve_cve_context(cve_id)
        
        if not cve_context:
            logger.warning(f"No context found for {cve_id}")
            return {
                'instruction': f"Map the CVE vulnerability to MITRE ATT&CK techniques",
                'input': f"CVE ID: {cve_id}\nDescription: {cve_description}",
                'output': f"MITRE Technique: {mitre_id}\nRelevance Score: {score}",
                'metadata': {
                    'cve_id': cve_id,
                    'mitre_id': mitre_id,
                    'score': score,
                    'has_context': False
                }
            }
        
        # Build augmented sample with retrieved context
        cve_data = cve_context.get('cve', {})
        mitre_techniques = cve_context.get('mitre_techniques', [])
        gsa_advisories = cve_context.get('gsa_advisories', [])
        
        # Format context sections
        context_parts = []
        
        if mitre_techniques:
            context_parts.append("Related MITRE Techniques:")
            for mt in mitre_techniques[:3]:
                tech = mt.get('technique', {})
                score_val = mt.get('score', 0)
                context_parts.append(f"  - {tech.get('technique_id', 'N/A')}: {tech.get('technique_name', 'N/A')} (score: {score_val})")
        
        if gsa_advisories:
            context_parts.append("\nRelated GSA Advisories:")
            for gsa in gsa_advisories[:2]:
                context_parts.append(f"  - {gsa.get('ghsa_id', 'N/A')}: {gsa.get('summary', 'N/A')}")
        
        context_str = "\n".join(context_parts) if context_parts else "No related context found"
        
        sample = {
            'instruction': f"Map the CVE vulnerability to MITRE ATT&CK techniques using contextual information",
            'input': f"""CVE ID: {cve_id}
Description: {cve_description}
Severity: {cve_data.get('severity', 'N/A')}
Base Score: {cve_data.get('base_score', 'N/A')}
Attack Vector: {cve_data.get('attack_vector', 'N/A')}

Retrieved Context:
{context_str}""",
            'output': f"MITRE Technique: {mitre_id}\nTechnique Name: {cve_context['mitre_techniques'][0]['technique'].get('technique_name', 'N/A') if mitre_techniques else 'N/A'}\nRelevance Score: {score}",
            'metadata': {
                'cve_id': cve_id,
                'mitre_id': mitre_id,
                'score': score,
                'has_context': True,
                'num_related_techniques': len(mitre_techniques),
                'num_related_advisories': len(gsa_advisories)
            }
        }
        
        return sample


# ==================== Main RAG Pipeline ====================

def main():
    """Main RAG retrieval pipeline"""
    print("\n" + "="*70)
    print("Stage 04B: RAG (Retrieval-Augmented Generation) Retrieval System")
    print("="*70 + "\n")
    
    try:
        # Check dependencies
        logger.info("\nStep 1: Checking dependencies...")
        if not HAS_SENTENCE_TRANSFORMERS:
            logger.warning("sentence-transformers not installed")
            logger.info("Install with: pip install sentence-transformers")
        
        if not HAS_CHROMADB:
            logger.warning("chromadb not installed")
            logger.info("Install with: pip install chromadb")
        
        # Initialize services
        logger.info("\nStep 2: Initializing services...")
        
        embedding_service = EmbeddingService()
        if not embedding_service.initialize():
            logger.warning("Embedding service initialization failed, continuing without embeddings")
        
        vector_store = VectorStoreService()
        if not vector_store.initialize():
            logger.warning("Vector store initialization failed, continuing without vector store")
        
        # Connect to Neo4j
        logger.info("\nStep 3: Connecting to Neo4j...")
        # Using HTTP browser endpoint (http://localhost:7474/browser/)
        # The driver will automatically convert this to Bolt protocol for connection
        neo4j_retriever = Neo4jRAGRetriever(
            neo4j_uri="http://localhost:7474",  # Browser endpoint
            neo4j_username="neo4j",
            neo4j_password="testpassword"
        )
        
        if not neo4j_retriever.connect():
            logger.error("Failed to connect to Neo4j")
            return False
        
        # Test retrievals
        logger.info("\nStep 4: Testing retrieval functionality...")
        test_cve = "CVE-2026-24049"
        context = neo4j_retriever.retrieve_cve_context(test_cve)
        if context:
            logger.info(f"✓ Successfully retrieved context for {test_cve}")
        else:
            logger.warning(f"Could not retrieve context for {test_cve} (may not exist in database)")
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("✓ RAG Retrieval System initialized successfully!")
        logger.info("="*70)
        logger.info(f"\nCapabilities:")
        logger.info(f"  ✓ Neo4j graph retrieval enabled")
        logger.info(f"  {'✓' if embedding_service.available else '✗'} Semantic embeddings")
        logger.info(f"  {'✓' if vector_store.available else '✗'} Vector store")
        logger.info(f"\nNext Steps:")
        logger.info(f"  1. Run stage_05_llama_training.py with RAG augmentation")
        logger.info(f"  2. Training data will be enriched with retrieved context")
        logger.info(f"="*70 + "\n")
        
        return True
        
    except Exception as e:
        logger.error(f"Fatal error in RAG pipeline: {e}")
        logger.debug(traceback.format_exc())
        return False
    
    finally:
        if 'neo4j_retriever' in locals():
            neo4j_retriever.close()


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
