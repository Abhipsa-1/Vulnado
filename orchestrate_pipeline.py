"""
Unified Pipeline Orchestrator: Neo4j Data Fetch → RAG Augmentation → LLaMA Training
Orchestrates the complete flow: data retrieval, RAG augmentation, and model training
"""

import json
import sys
import os
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional
import traceback
from datetime import datetime

# ==================== Logging Setup ====================

def setup_logging(log_dir: str = "/Users/abhipsa/Documents/VulnGuard AI/logs") -> logging.Logger:
    """Setup comprehensive logging for orchestration"""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("vulnguard_orchestrator")
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers = []
    
    log_file = Path(log_dir) / f"orchestrator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
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
    
    logger.info(f"Orchestration logging initialized. Log file: {log_file}")
    return logger


logger = setup_logging()

# ==================== Configuration ====================

PIPELINE_CONFIG = {
    'base_path': '/Users/abhipsa/Documents/VulnGuard AI',
    'src_path': '/Users/abhipsa/Documents/VulnGuard AI/src/VULNGUARD_AI/components',
    'stages': {
        'stage_04': {
            'name': 'Neo4j Data Fetching',
            'script': 'stage_04_data_fetch_neo4j.py',
            'enabled': True,
            'description': 'Fetch CVE, MITRE, GSA nodes and relationships from Neo4j'
        },
        'stage_04b': {
            'name': 'RAG Retrieval Setup',
            'script': 'stage_04b_rag_retrieval.py',
            'enabled': True,
            'description': 'Setup RAG system for context-aware retrieval'
        },
        'stage_05': {
            'name': 'LLaMA Training with RAG',
            'script': 'stage_05_llama_training_with_rag.py',
            'enabled': True,
            'description': 'Fine-tune LLaMA on RAG-augmented training data'
        }
    },
    'neo4j': {
        'uri': 'neo4j://localhost:7687',
        'username': 'neo4j',
        'password': 'testpassword'
    },
    'rag': {
        'enabled': True,
        'embedding_model': 'all-MiniLM-L6-v2',
        'use_vector_store': True
    },
    'output_dirs': {
        'training_data': '/Users/abhipsa/Documents/VulnGuard AI/training_data',
        'models': '/Users/abhipsa/Documents/VulnGuard AI/models',
        'vectorstore': '/Users/abhipsa/Documents/VulnGuard AI/vectorstore',
        'logs': '/Users/abhipsa/Documents/VulnGuard AI/logs'
    }
}


# ==================== Health Checks ====================

class PipelineHealthCheck:
    """Perform health checks before pipeline execution"""
    
    @staticmethod
    def check_directories() -> bool:
        """Check if required directories exist
        
        Returns:
            bool: True if all directories accessible, False otherwise
        """
        logger.info("Checking directories...")
        
        required_dirs = [
            PIPELINE_CONFIG['base_path'],
            PIPELINE_CONFIG['src_path'],
            PIPELINE_CONFIG['output_dirs']['logs']
        ]
        
        for dir_path in required_dirs:
            if not Path(dir_path).exists():
                logger.error(f"  ✗ Directory not found: {dir_path}")
                return False
            logger.info(f"  ✓ {dir_path}")
        
        return True
    
    @staticmethod
    def check_scripts() -> bool:
        """Check if all pipeline scripts exist
        
        Returns:
            bool: True if all scripts found, False otherwise
        """
        logger.info("Checking pipeline scripts...")
        
        src_path = PIPELINE_CONFIG['src_path']
        
        for stage_key, stage_info in PIPELINE_CONFIG['stages'].items():
            if stage_info['enabled']:
                script_path = Path(src_path) / stage_info['script']
                if not script_path.exists():
                    logger.error(f"  ✗ Script not found: {script_path}")
                    return False
                logger.info(f"  ✓ {stage_key}: {stage_info['script']}")
        
        return True
    
    @staticmethod
    def check_neo4j_connection() -> bool:
        """Check Neo4j connection
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        logger.info("Checking Neo4j connection...")
        
        try:
            from neo4j import GraphDatabase
            
            uri = PIPELINE_CONFIG['neo4j']['uri']
            username = PIPELINE_CONFIG['neo4j']['username']
            password = PIPELINE_CONFIG['neo4j']['password']
            
            driver = GraphDatabase.driver(uri, auth=(username, password), connection_timeout=10)
            
            with driver.session() as session:
                result = session.run("RETURN 'Neo4j is alive' AS message")
                message = result.single()["message"]
                logger.info(f"  ✓ Neo4j connected: {message}")
                driver.close()
                return True
                
        except Exception as e:
            logger.warning(f"  ✗ Neo4j connection failed: {e}")
            logger.info("     Continue anyway? (Neo4j may be starting up)")
            return False
    
    @staticmethod
    def check_dependencies() -> bool:
        """Check if required Python packages are installed
        
        Returns:
            bool: True if core dependencies available, False otherwise
        """
        logger.info("Checking dependencies...")
        
        required_packages = {
            'neo4j': 'Neo4j Driver',
            'pathlib': 'Pathlib',
            'json': 'JSON',
            'logging': 'Logging'
        }
        
        optional_packages = {
            'torch': 'PyTorch',
            'transformers': 'Hugging Face Transformers',
            'peft': 'PEFT',
            'sentence_transformers': 'Sentence Transformers (RAG)',
            'chromadb': 'ChromaDB (RAG)',
        }
        
        missing_required = []
        
        for package, name in required_packages.items():
            try:
                __import__(package)
                logger.info(f"  ✓ {name}")
            except ImportError:
                logger.error(f"  ✗ {name} not installed")
                missing_required.append(package)
        
        if missing_required:
            logger.error(f"Missing required packages: {', '.join(missing_required)}")
            return False
        
        logger.info("\nOptional packages:")
        for package, name in optional_packages.items():
            try:
                __import__(package)
                logger.info(f"  ✓ {name}")
            except (ImportError, Exception) as e:
                # ChromaDB may fail due to Pydantic v1 compatibility with Python 3.14
                if "ConfigError" in str(type(e).__name__):
                    logger.warning(f"  ⚠ {name} (Pydantic v1 compatibility issue - continuing)")
                else:
                    logger.warning(f"  ✗ {name} (optional, some features may be limited)")
        
        return True
    
    @staticmethod
    def check_training_data() -> bool:
        """Check if training data exists from stage 04
        
        Returns:
            bool: True if training data found, False otherwise
        """
        logger.info("Checking training data...")
        
        training_dir = Path(PIPELINE_CONFIG['output_dirs']['training_data'])
        training_file = training_dir / 'training_dataset.jsonl'
        
        if training_file.exists():
            # Count lines
            num_samples = sum(1 for _ in open(training_file))
            logger.info(f"  ✓ Training data found: {num_samples} samples")
            return True
        else:
            logger.warning(f"  ⚠ Training data not found: {training_file}")
            logger.info("     Will be generated by stage 04")
            return False
    
    @staticmethod
    def run_all_checks(skip_neo4j: bool = False) -> bool:
        """Run all health checks
        
        Args:
            skip_neo4j: Whether to skip Neo4j connection check
            
        Returns:
            bool: True if all critical checks pass, False otherwise
        """
        logger.info("\n" + "="*70)
        logger.info("PIPELINE HEALTH CHECK")
        logger.info("="*70 + "\n")
        
        checks = [
            ("Directories", PipelineHealthCheck.check_directories),
            ("Scripts", PipelineHealthCheck.check_scripts),
            ("Dependencies", PipelineHealthCheck.check_dependencies),
        ]
        
        if not skip_neo4j:
            checks.append(("Neo4j Connection", PipelineHealthCheck.check_neo4j_connection))
        
        checks.append(("Training Data", PipelineHealthCheck.check_training_data))
        
        results = {}
        for check_name, check_func in checks:
            try:
                result = check_func()
                results[check_name] = result
                logger.info(f"{check_name}: {'✓ PASS' if result else '✗ FAIL'}\n")
            except Exception as e:
                logger.error(f"{check_name}: ✗ ERROR - {e}\n")
                results[check_name] = False
        
        critical_passed = all([
            results.get('Directories', False),
            results.get('Scripts', False),
            results.get('Dependencies', False),
        ])
        
        return critical_passed


# ==================== Pipeline Executor ====================

class PipelineExecutor:
    """Executes pipeline stages in sequence"""
    
    def __init__(self):
        """Initialize pipeline executor"""
        self.stage_results = {}
        self.start_time = None
        self.end_time = None
    
    def execute_stage(self, stage_key: str, stage_info: Dict) -> bool:
        """Execute a single pipeline stage
        
        Args:
            stage_key: Stage identifier
            stage_info: Stage configuration dictionary
            
        Returns:
            bool: True if stage succeeded, False otherwise
        """
        if not stage_info['enabled']:
            logger.info(f"\n⊘ {stage_key}: {stage_info['name']} [DISABLED]")
            return True
        
        logger.info(f"\n{'='*70}")
        logger.info(f"STAGE: {stage_key}")
        logger.info(f"Name: {stage_info['name']}")
        logger.info(f"Description: {stage_info['description']}")
        logger.info(f"{'='*70}\n")
        
        script_path = Path(PIPELINE_CONFIG['src_path']) / stage_info['script']
        
        try:
            logger.info(f"Executing: {script_path}")
            
            # Run script using python subprocess
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(Path(PIPELINE_CONFIG['src_path']).parent.parent),
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Log output
            if result.stdout:
                logger.debug(f"STDOUT:\n{result.stdout}")
            
            if result.stderr:
                logger.debug(f"STDERR:\n{result.stderr}")
            
            if result.returncode == 0:
                logger.info(f"✓ {stage_key} completed successfully")
                self.stage_results[stage_key] = {
                    'status': 'SUCCESS',
                    'return_code': result.returncode
                }
                return True
            else:
                logger.error(f"✗ {stage_key} failed with return code {result.returncode}")
                self.stage_results[stage_key] = {
                    'status': 'FAILED',
                    'return_code': result.returncode,
                    'error': result.stderr
                }
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"✗ {stage_key} timed out after 1 hour")
            self.stage_results[stage_key] = {
                'status': 'TIMEOUT',
                'error': 'Pipeline stage exceeded 1 hour timeout'
            }
            return False
        except Exception as e:
            logger.error(f"✗ {stage_key} failed with error: {e}")
            logger.debug(traceback.format_exc())
            self.stage_results[stage_key] = {
                'status': 'ERROR',
                'error': str(e)
            }
            return False
    
    def execute_pipeline(self) -> bool:
        """Execute the complete pipeline
        
        Returns:
            bool: True if all stages succeeded, False otherwise
        """
        logger.info("\n" + "="*70)
        logger.info("VULNGUARD AI - UNIFIED PIPELINE ORCHESTRATION")
        logger.info("Neo4j Data Fetch → RAG Augmentation → LLaMA Training")
        logger.info("="*70 + "\n")
        
        self.start_time = datetime.now()
        
        # Execute stages in order
        execution_order = ['stage_04', 'stage_04b', 'stage_05']
        
        all_passed = True
        for stage_key in execution_order:
            if stage_key not in PIPELINE_CONFIG['stages']:
                continue
            
            stage_info = PIPELINE_CONFIG['stages'][stage_key]
            
            # Execute stage
            if not self.execute_stage(stage_key, stage_info):
                logger.error(f"\n✗ Pipeline halted at {stage_key}")
                all_passed = False
                
                # Ask if user wants to continue
                if stage_key != 'stage_05':  # Always continue to stage 05 even if stage 04b fails
                    logger.warning(f"Continue to next stage? (y/n)")
                    # For automation, we'll continue
                    logger.info("Continuing to next stage...")
            
            # Small delay between stages
            time.sleep(2)
        
        self.end_time = datetime.now()
        
        return all_passed
    
    def print_summary(self):
        """Print pipeline execution summary"""
        logger.info("\n" + "="*70)
        logger.info("PIPELINE EXECUTION SUMMARY")
        logger.info("="*70 + "\n")
        
        for stage_key, result in self.stage_results.items():
            status = result.get('status', 'UNKNOWN')
            status_icon = '✓' if status == 'SUCCESS' else '✗'
            logger.info(f"{status_icon} {stage_key}: {status}")
            
            if status != 'SUCCESS' and 'error' in result:
                logger.info(f"   Error: {result['error'][:100]}...")
        
        logger.info("")
        
        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            logger.info(f"Total Duration: {duration}")
        
        logger.info(f"\nNext Steps:")
        logger.info(f"  1. Verify training data in: {PIPELINE_CONFIG['output_dirs']['training_data']}")
        logger.info(f"  2. Configure and run fine-tuning:")
        logger.info(f"     - Uncomment training code in stage_05_llama_training_with_rag.py")
        logger.info(f"     - Ensure GPU is available")
        logger.info(f"     - Run: python {PIPELINE_CONFIG['src_path']}/stage_05_llama_training_with_rag.py")
        logger.info(f"  3. Monitor training progress in logs/")
        logger.info(f"\nFine-tuned model will be saved to: {PIPELINE_CONFIG['output_dirs']['models']}")
        logger.info("="*70 + "\n")


# ==================== Main ====================

def main():
    """Main orchestration pipeline"""
    
    try:
        # Health checks
        health_check = PipelineHealthCheck()
        if not health_check.run_all_checks(skip_neo4j=False):
            logger.error("\nCritical health checks failed. Cannot proceed.")
            return False
        
        # Execute pipeline
        executor = PipelineExecutor()
        success = executor.execute_pipeline()
        
        # Print summary
        executor.print_summary()
        
        return success
        
    except Exception as e:
        logger.error(f"\nFatal error in orchestration: {e}")
        logger.debug(traceback.format_exc())
        return False


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
