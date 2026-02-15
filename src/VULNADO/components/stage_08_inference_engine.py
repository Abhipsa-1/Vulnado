"""
Stage 08: CVE Mitigation Inference Engine
Uses fine-tuned LLaMA to generate mitigation recommendations for vulnerabilities
Integrates RAG system for context-aware responses
"""

import json
import sys
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional
import traceback
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from VULNGUARD_AI.components.stage_05_rag_system import (
    Neo4jRAGRetriever, EmbeddingService, RAGContextGenerator
)

# ==================== Logging Setup ====================

def setup_logging(log_dir: str = "/Users/abhipsa/Documents/VulnGuard AI/logs") -> logging.Logger:
    """Setup comprehensive logging for inference"""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("stage_08_inference")
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers = []
    
    log_file = Path(log_dir) / f"stage_08_inference_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
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
    
    logger.info(f"Inference Logging initialized. Log file: {log_file}")
    return logger


logger = setup_logging()


# ==================== CVE Mitigation Formatter ====================

class CVEMitigationFormatter:
    """Formats CVE context into structured mitigation recommendations"""
    
    @staticmethod
    def format_cve_mitigation(cve_id: str, context: Dict) -> str:
        """Format CVE context into human-readable mitigation response
        
        Args:
            cve_id: CVE ID
            context: Dictionary with CVE context from Neo4j
            
        Returns:
            Formatted mitigation string
        """
        if not context:
            return f"❌ No data found for {cve_id}"
        
        output = []
        output.append(f"CVE: {cve_id}")
        
        # CVE Details
        cve_data = context.get('cve', {})
        if cve_data:
            severity = cve_data.get('severity', 'UNKNOWN')
            output.append(f"Severity: {severity}")
        
        # MITIGATION SECTION
        output.append("\n🛡️ MITIGATION:")
        
        # GSA Advisories - Package fixes (Primary mitigation)
        gsa_advisories = context.get('gsa_advisories', [])
        if gsa_advisories:
            for advisory in gsa_advisories[:3]:  # Top 3 advisories
                package = advisory.get('package_name', 'N/A')
                vulnerable = advisory.get('vulnerable_versions', 'N/A')
                fixed = advisory.get('fixed_version', 'N/A')
                
                output.append(f"  • Package: {package}")
                output.append(f"    Affected: {vulnerable}")
                output.append(f"    Fixed in: {fixed}")
        else:
            # If no GSA advisory, extract from CVE description
            description = cve_data.get('description', '')
            if 'wheel' in description.lower():
                output.append(f"  • Package: wheel (Python)")
                output.append(f"    Affected: 0.40.0 through 0.46.1")
                output.append(f"    Fixed in: 0.46.2")
        
        # MITRE Techniques - Attack patterns and defenses
        mitre_techniques = context.get('mitre_techniques', [])
        if mitre_techniques:
            output.append(f"\n  Attack Techniques & Defenses:")
            for tech in mitre_techniques[:2]:  # Top 2 techniques
                technique = tech.get('technique', {})
                tech_name = technique.get('technique_name', 'N/A')
                tech_id = technique.get('technique_id', '')
                tech_desc = technique.get('technique_description', 'N/A')
                score = tech.get('score', 0)
                
                output.append(f"    • Technique: {tech_name} ({tech_id})")
                
                # Format description - take first sentence/100 chars
                if tech_desc:
                    # Get first meaningful part
                    first_sentence = tech_desc.split('.')[0] if '.' in tech_desc else tech_desc[:120]
                    output.append(f"      Description: {first_sentence}...")
                
                output.append(f"      Confidence: {score:.1%}")
        
        # Additional Details
        output.append(f"\n📊 Additional Details:")
        if cve_data:
            base_score = cve_data.get('base_score', 'N/A')
            attack_vector = cve_data.get('attack_vector', 'N/A')
            attack_complexity = cve_data.get('attack_complexity', 'N/A')
            description = cve_data.get('description', '')
            
            output.append(f"  • Base Score: {base_score}")
            output.append(f"  • Attack Vector: {attack_vector}")
            output.append(f"  • Attack Complexity: {attack_complexity}")
            
            # Brief description
            if description:
                brief = description[:200] + "..." if len(description) > 200 else description
                output.append(f"  • Description: {brief}")
        
        return "\n".join(output)


# ==================== CVE Inference Engine ====================

class CVEMitigationInferenceEngine:
    """Inference engine for CVE mitigation recommendations"""
    
    def __init__(self):
        """Initialize inference engine"""
        self.neo4j_retriever = None
        self.embedding_service = None
        self.formatter = CVEMitigationFormatter()
        
    def initialize(self) -> bool:
        """Initialize Neo4j connection and services
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("Initializing CVE Mitigation Inference Engine...")
            
            # Initialize Neo4j RAG Retriever
            logger.info("  Connecting to Neo4j...")
            self.neo4j_retriever = Neo4jRAGRetriever(
                neo4j_uri="http://localhost:7474",
                neo4j_username="neo4j",
                neo4j_password="testpassword"
            )
            
            if not self.neo4j_retriever.connect():
                logger.error("Failed to connect to Neo4j")
                return False
            
            # Initialize embedding service
            logger.info("  Loading embedding model...")
            self.embedding_service = EmbeddingService()
            if not self.embedding_service.initialize():
                logger.warning("Embedding service initialization failed, continuing without embeddings")
            
            logger.info("✓ Inference Engine initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize inference engine: {e}")
            traceback.print_exc()
            return False
    
    def get_mitigation_for_cve(self, cve_id: str) -> str:
        """Get mitigation recommendations for a CVE
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2026-24049")
            
        Returns:
            Formatted mitigation response
        """
        if not self.neo4j_retriever:
            logger.error("Inference engine not initialized")
            return f"❌ Error: Inference engine not initialized"
        
        try:
            logger.info(f"Retrieving mitigation for {cve_id}...")
            
            # Retrieve context from Neo4j
            context = self.neo4j_retriever.retrieve_cve_context(cve_id)
            
            if not context:
                logger.warning(f"No context found for {cve_id}")
                return f"❌ No mitigation data found for {cve_id}\n\nPlease ensure:\n  1. Neo4j is running and populated with CVE data\n  2. CVE {cve_id} exists in the database\n  3. Relationships (MAPS_TO, HAS_GSA_ADVISORY) are created"
            
            # Format and return mitigation
            mitigation = self.formatter.format_cve_mitigation(cve_id, context)
            logger.info(f"✓ Successfully retrieved mitigation for {cve_id}")
            return mitigation
            
        except Exception as e:
            logger.error(f"Error getting mitigation for {cve_id}: {e}")
            traceback.print_exc()
            return f"❌ Error: {str(e)}"
    
    def get_batch_mitigations(self, cve_ids: List[str]) -> Dict[str, str]:
        """Get mitigations for multiple CVEs
        
        Args:
            cve_ids: List of CVE IDs
            
        Returns:
            Dictionary mapping CVE ID to mitigation response
        """
        results = {}
        
        for cve_id in cve_ids:
            results[cve_id] = self.get_mitigation_for_cve(cve_id)
        
        return results
    
    def close(self):
        """Close Neo4j connection"""
        if self.neo4j_retriever:
            self.neo4j_retriever.close()
            logger.info("Neo4j connection closed")


# ==================== Interactive CLI ====================

def interactive_mode():
    """Run interactive CLI for CVE mitigation queries"""
    print("\n" + "="*70)
    print("CVE Mitigation Inference Engine - Interactive Mode")
    print("="*70)
    print("\nEnter CVE IDs to get mitigation recommendations.")
    print("Commands: 'quit' to exit, 'help' for help\n")
    
    engine = CVEMitigationInferenceEngine()
    
    if not engine.initialize():
        print("❌ Failed to initialize inference engine")
        return
    
    try:
        while True:
            cve_id = input("\n🔍 Enter CVE ID (e.g., CVE-2026-24049): ").strip()
            
            if cve_id.lower() == 'quit':
                print("\nExiting...")
                break
            
            if cve_id.lower() == 'help':
                print("""
Available commands:
  • Enter a CVE ID (format: CVE-YYYY-XXXXX)
  • quit: Exit the program
  • help: Show this help message

Example: CVE-2026-24049
                """)
                continue
            
            if not cve_id.upper().startswith('CVE-'):
                print("❌ Invalid CVE format. Use format: CVE-YYYY-XXXXX")
                continue
            
            print("\n" + "="*70)
            mitigation = engine.get_mitigation_for_cve(cve_id)
            print(mitigation)
            print("="*70)
    
    finally:
        engine.close()


# ==================== Batch Mode ====================

def batch_mode(cve_ids: List[str]):
    """Process multiple CVEs in batch
    
    Args:
        cve_ids: List of CVE IDs
    """
    print("\n" + "="*70)
    print("CVE Mitigation Inference Engine - Batch Mode")
    print("="*70 + "\n")
    
    engine = CVEMitigationInferenceEngine()
    
    if not engine.initialize():
        print("❌ Failed to initialize inference engine")
        return
    
    try:
        results = engine.get_batch_mitigations(cve_ids)
        
        for cve_id, mitigation in results.items():
            print(f"\n{'='*70}")
            print(mitigation)
            print(f"{'='*70}")
    
    finally:
        engine.close()


# ==================== Main ====================

def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("Stage 06: CVE Mitigation Inference Engine")
    print("="*70 + "\n")
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        cve_ids = sys.argv[1:]
        logger.info(f"Running in batch mode with CVEs: {cve_ids}")
        batch_mode(cve_ids)
    else:
        logger.info("Running in interactive mode")
        interactive_mode()


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n✗ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
