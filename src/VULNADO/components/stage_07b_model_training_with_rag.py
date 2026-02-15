"""
Stage 07B: Enhanced Llama Model Training Pipeline with RAG Integration
Pretrain and finetune Llama model for CVE-MITRE mapping using RAG-augmented training data
"""

import json
import sys
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional
import traceback
from datetime import datetime
from VULNADO.config.configuration import get_config

# ==================== Logging Setup ====================

def setup_logging(log_dir: str = None) -> logging.Logger:
    """Setup comprehensive logging for model training"""
    if log_dir is None:
        config = get_config()
        log_dir = config.logging.log_dir
    
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("stage_07b_llama_training")
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers = []
    
    log_file = Path(log_dir) / f"stage_07b_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
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
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    return logger


logger = setup_logging()

# ==================== Model Configuration ====================

MODEL_CONFIG = {
    'model_name': 'Llama-4-Maverick-17B-128E',
    'model_name_instruct': 'Llama-4-Maverick-17B-128E-Instruct',
    'model_download_url': 'https://llama4.llamameta.net/',
    'hidden_size': 4096,
    'num_hidden_layers': 32,
    'intermediate_size': 14336,
    'num_attention_heads': 32,
    'max_position_embeddings': 128000,
    'vocab_size': 128256,
}

config = get_config()
TRAINING_CONFIG = {
    'batch_size': 8,
    'learning_rate': 1e-5,
    'num_epochs': 3,
    'warmup_ratio': 0.1,
    'weight_decay': 0.01,
    'max_seq_length': 2048,
    'save_steps': 500,
    'eval_steps': 500,
    'output_dir': config.models.llama_finetuned_dir
}

RAG_CONFIG = {
    'use_rag': True,
    'embedding_model': 'all-MiniLM-L6-v2',
    'use_vector_store': True,
    'context_window': 512,
    'top_k_retrieval': 3
}


# ==================== Model Preparation Functions ====================

def check_dependencies() -> bool:
    """Check if required packages are installed
    
    Returns:
        bool: True if all dependencies available, False otherwise
    """
    logger.info("Checking dependencies...")
    
    required_packages = {
        'torch': 'PyTorch',
        'transformers': 'Hugging Face Transformers',
        'peft': 'PEFT (Parameter-Efficient Fine-Tuning)',
        'bitsandbytes': 'BitsAndBytes',
        'datasets': 'Datasets',
        'trl': 'Transformers Reinforcement Learning',
        'neo4j': 'Neo4j Driver'
    }
    
    optional_packages = {
        'sentence_transformers': 'Sentence Transformers (for RAG embeddings)',
        'chromadb': 'ChromaDB (for vector store)',
    }
    
    missing_packages = []
    
    for package, name in required_packages.items():
        try:
            __import__(package)
            logger.info(f"  ✓ {name} installed")
        except ImportError:
            logger.warning(f"  ✗ {name} not installed")
            missing_packages.append(package)
    
    logger.info("\nOptional packages for RAG:")
    for package, name in optional_packages.items():
        try:
            __import__(package)
            logger.info(f"  ✓ {name} installed")
        except (ImportError, Exception) as e:
            # ChromaDB may fail due to Pydantic v1 compatibility with Python 3.14
            if "ConfigError" in str(type(e).__name__):
                logger.warning(f"  ⚠ {name} import error (Pydantic v1 compatibility) - continuing without it")
            else:
                logger.warning(f"  ✗ {name} not installed (RAG features may be limited)")
    
    if missing_packages:
        logger.error(f"Missing required packages: {', '.join(missing_packages)}")
        logger.info("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True


def download_model(model_name: str = 'Llama-4-Maverick-17B-128E') -> bool:
    """Download Llama model
    
    Args:
        model_name: Model identifier
        
    Returns:
        bool: True if download successful, False otherwise
    """
    logger.info(f"Downloading model: {model_name}...")
    
    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM
        
        logger.info(f"  Loading tokenizer for {model_name}...")
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        logger.info(f"  ✓ Tokenizer loaded: {type(tokenizer).__name__}")
        
        logger.info(f"  Loading model {model_name}...")
        logger.info(f"  ⚠ This may take several minutes for a 17B parameter model...")
        
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            device_map='auto',
            torch_dtype='auto',
            load_in_4bit=True  # Quantize to 4-bit for memory efficiency
        )
        logger.info(f"  ✓ Model loaded: {type(model).__name__}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error downloading model: {e}")
        logger.debug(traceback.format_exc())
        return False


def prepare_training_data_with_rag(data_file: str, use_rag: bool = True) -> Optional[Dict]:
    """Prepare training data from JSONL file, optionally augmented with RAG
    
    Args:
        data_file: Path to training data JSONL file
        use_rag: Whether to augment data with RAG context
        
    Returns:
        Dictionary with training data, or None if error
    """
    logger.info(f"Preparing training data from {data_file}...")
    
    try:
        if not Path(data_file).exists():
            logger.error(f"Training data file not found: {data_file}")
            return None
        
        # Load JSONL data
        training_samples = []
        with open(data_file, 'r') as f:
            for line in f:
                if line.strip():
                    sample = json.loads(line)
                    training_samples.append(sample)
        
        logger.info(f"✓ Loaded {len(training_samples)} training samples")
        
        # RAG augmentation if requested
        if use_rag:
            logger.info("Augmenting training data with RAG context...")
            training_samples = augment_training_data_with_rag(training_samples)
        
        # Format for training
        formatted_data = []
        for sample in training_samples:
            # Handle both original and RAG-augmented formats
            if 'input' in sample and 'output' in sample:
                text = f"""Instruction: {sample.get('instruction', 'Map CVE to MITRE')}

Input:
{sample['input']}

Output:
{sample['output']}"""
            else:
                # Fallback for other formats
                text = json.dumps(sample)
            
            formatted_data.append({'text': text})
        
        logger.info(f"✓ Prepared {len(formatted_data)} formatted training samples")
        
        return {
            'samples': training_samples,
            'formatted': formatted_data,
            'count': len(training_samples)
        }
        
    except Exception as e:
        logger.error(f"Error preparing training data: {e}")
        logger.debug(traceback.format_exc())
        return None


def augment_training_data_with_rag(samples: List[Dict]) -> List[Dict]:
    """Augment training samples with RAG-retrieved context
    
    Args:
        samples: List of training samples
        
    Returns:
        List of augmented training samples
    """
    logger.info("Loading RAG retriever...")
    
    try:
        # Import RAG module
        config = get_config()
        sys.path.insert(0, config.project.src_dir)
        from VULNGUARD_AI.components.stage_05_rag_system import (
            Neo4jRAGRetriever, EmbeddingService, RAGContextGenerator
        )
        
        # Initialize RAG components
        neo4j_config = config.neo4j_service
        neo4j_retriever = Neo4jRAGRetriever(
            neo4j_uri=neo4j_config.uri,
            neo4j_username=neo4j_config.username,
            neo4j_password=neo4j_config.password
        )
        
        if not neo4j_retriever.connect():
            logger.warning("Could not connect to Neo4j for RAG, using original samples")
            return samples
        
        embedding_service = EmbeddingService()
        if not embedding_service.initialize():
            logger.warning("Could not initialize embeddings, continuing with basic RAG")
        
        rag_generator = RAGContextGenerator(embedding_service, neo4j_retriever)
        
        # Augment samples
        augmented_samples = []
        for i, sample in enumerate(samples):
            try:
                if 'metadata' in sample:
                    metadata = sample['metadata']
                    cve_id = metadata.get('cve_id')
                    mitre_id = metadata.get('mitre_id')
                    score = metadata.get('score', 0)
                    
                    # Get input text to extract description
                    input_text = sample.get('input', '')
                    description_match = input_text.split('Description:')[1].split('\n')[0].strip() if 'Description:' in input_text else ''
                    
                    # Generate RAG-augmented sample
                    augmented_sample = rag_generator.generate_rag_augmented_sample(
                        cve_id, mitre_id, description_match, score
                    )
                    augmented_samples.append(augmented_sample)
                    
                    if (i + 1) % 10 == 0:
                        logger.debug(f"Augmented {i + 1} samples with RAG context")
                
                else:
                    augmented_samples.append(sample)
                    
            except Exception as e:
                logger.debug(f"Error augmenting sample {i}: {e}, using original")
                augmented_samples.append(sample)
        
        logger.info(f"✓ Augmented {len(augmented_samples)} training samples with RAG context")
        neo4j_retriever.close()
        return augmented_samples
        
    except ImportError as e:
        logger.warning(f"Could not import RAG module: {e}")
        logger.info("Continuing with original training data (no RAG augmentation)")
        return samples
    except Exception as e:
        logger.error(f"Error in RAG augmentation: {e}")
        logger.debug(traceback.format_exc())
        logger.info("Continuing with original training data")
        return samples


# ==================== Training Pipeline ====================

def pretrain_model(model_name: str = 'Llama-4-Maverick-17B-128E') -> bool:
    """Setup pretraining for Llama model
    
    Note: Full pretraining requires significant computational resources.
    This function demonstrates the pipeline setup.
    
    Args:
        model_name: Model identifier
        
    Returns:
        bool: True if setup successful, False otherwise
    """
    logger.info(f"Setting up pretraining pipeline for {model_name}...")
    
    try:
        logger.info("  Model Information:")
        for key, value in MODEL_CONFIG.items():
            logger.info(f"    • {key}: {value}")
        
        logger.info("\n  Pretraining Configuration:")
        logger.warning("  ⚠ Full pretraining requires:")
        logger.warning("    • 8+ A100 GPUs with 80GB VRAM each")
        logger.warning("    • ~2-3 weeks of training time")
        logger.warning("    • Substantial compute budget ($100k+)")
        
        logger.info("\n  Recommended approach for this project:")
        logger.info("    1. Start with pretrained base model (already available)")
        logger.info("    2. Fine-tune on domain-specific CVE-MITRE data")
        logger.info("    3. Use LoRA for parameter-efficient fine-tuning")
        logger.info("    4. Augment training with RAG-retrieved context")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in pretraining setup: {e}")
        logger.debug(traceback.format_exc())
        return False


def finetune_model(data_file: str, model_name: str = 'Llama-4-Maverick-17B-128E-Instruct',
                   use_rag: bool = True) -> bool:
    """Finetune Llama model on CVE-MITRE training data with RAG augmentation
    
    Args:
        data_file: Path to training data JSONL file
        model_name: Model identifier for finetuning
        use_rag: Whether to use RAG augmentation
        
    Returns:
        bool: True if finetuning successful, False otherwise
    """
    logger.info(f"Starting fine-tuning of {model_name}...")
    logger.info(f"RAG Augmentation: {'Enabled' if use_rag else 'Disabled'}")
    
    try:
        # Check dependencies
        if not check_dependencies():
            logger.error("Required dependencies not installed")
            return False
        
        # Prepare data with RAG augmentation
        training_data = prepare_training_data_with_rag(data_file, use_rag=use_rag)
        if not training_data:
            logger.error("Failed to prepare training data")
            return False
        
        logger.info("\nFine-tuning Configuration:")
        logger.info(f"  • Batch size: {TRAINING_CONFIG['batch_size']}")
        logger.info(f"  • Learning rate: {TRAINING_CONFIG['learning_rate']}")
        logger.info(f"  • Number of epochs: {TRAINING_CONFIG['num_epochs']}")
        logger.info(f"  • Max sequence length: {TRAINING_CONFIG['max_seq_length']}")
        logger.info(f"  • Output directory: {TRAINING_CONFIG['output_dir']}")
        
        if use_rag:
            logger.info("\nRAG Configuration:")
            logger.info(f"  • Embedding model: {RAG_CONFIG['embedding_model']}")
            logger.info(f"  • Top-k retrieval: {RAG_CONFIG['top_k_retrieval']}")
            logger.info(f"  • Context window: {RAG_CONFIG['context_window']}")
        
        logger.info(f"\n  Training on {training_data['count']} samples...")
        
        # This is a template for the actual fine-tuning code
        # Uncomment when all dependencies are installed
        
        """
        from transformers import (
            AutoTokenizer,
            AutoModelForCausalLM,
            TrainingArguments,
            Trainer,
            DataCollatorForLanguageModeling
        )
        from peft import get_peft_model, LoraConfig, TaskType
        from datasets import Dataset
        
        # Load model and tokenizer
        logger.info(f"Loading model and tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            device_map='auto',
            torch_dtype='auto',
            load_in_4bit=True
        )
        
        # Setup LoRA for parameter-efficient fine-tuning
        logger.info(f"Setting up LoRA for parameter-efficient fine-tuning...")
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            bias='none',
            target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj']
        )
        model = get_peft_model(model, lora_config)
        
        # Create dataset
        dataset = Dataset.from_dict({
            'text': [s['text'] for s in training_data['formatted']]
        })
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=TRAINING_CONFIG['output_dir'],
            num_train_epochs=TRAINING_CONFIG['num_epochs'],
            per_device_train_batch_size=TRAINING_CONFIG['batch_size'],
            save_steps=TRAINING_CONFIG['save_steps'],
            eval_steps=TRAINING_CONFIG['eval_steps'],
            logging_steps=100,
            learning_rate=TRAINING_CONFIG['learning_rate'],
            warmup_ratio=TRAINING_CONFIG['warmup_ratio'],
            weight_decay=TRAINING_CONFIG['weight_decay'],
            fp16=True,
            gradient_accumulation_steps=4
        )
        
        # Trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=dataset,
            data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
            tokenizer=tokenizer,
        )
        
        # Start training
        logger.info("Starting training...")
        trainer.train()
        
        # Save model
        logger.info(f"Saving fine-tuned model to {TRAINING_CONFIG['output_dir']}...")
        model.save_pretrained(TRAINING_CONFIG['output_dir'])
        tokenizer.save_pretrained(TRAINING_CONFIG['output_dir'])
        """
        
        logger.info("✓ Fine-tuning pipeline prepared successfully")
        logger.info("\nTo execute fine-tuning, ensure all dependencies are installed:")
        logger.info("  pip install torch transformers peft bitsandbytes datasets trl")
        
        if use_rag:
            logger.info("  pip install sentence-transformers chromadb")
        
        logger.info("\nThen uncomment the training code in the finetune_model() function")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in fine-tuning: {e}")
        logger.debug(traceback.format_exc())
        return False


def evaluate_model(model_output_dir: str) -> bool:
    """Evaluate fine-tuned model on validation data
    
    Args:
        model_output_dir: Directory containing fine-tuned model
        
    Returns:
        bool: True if evaluation successful, False otherwise
    """
    logger.info(f"Evaluating model from {model_output_dir}...")
    
    try:
        # Load fine-tuned model
        logger.info("Loading fine-tuned model...")
        
        # Evaluation logic would go here
        logger.info("✓ Model evaluation pipeline prepared")
        
        return True
        
    except Exception as e:
        logger.error(f"Error evaluating model: {e}")
        logger.debug(traceback.format_exc())
        return False


# ==================== Main Pipeline ====================

def main():
    """Main execution pipeline with RAG integration"""
    print("\n" + "="*70)
    print("Stage 05: Llama Model Training Pipeline with RAG Integration")
    print("="*70 + "\n")
    
    try:
        # Step 1: Check dependencies
        logger.info("\nStep 1: Checking dependencies...")
        if not check_dependencies():
            logger.warning("Some dependencies missing, but continuing...")
        
        # Step 2: Setup pretraining (informational)
        logger.info("\nStep 2: Setting up pretraining pipeline...")
        pretrain_model()
        
        # Step 3: Prepare fine-tuning with RAG
        logger.info("\nStep 3: Preparing fine-tuning pipeline with RAG...")
        config = get_config()
        training_data_file = config.models.training_dataset_file
        
        if not Path(training_data_file).exists():
            logger.error(f"Training data file not found: {training_data_file}")
            logger.info("Run stage_04_data_fetch_neo4j.py first to generate training data")
            return False
        
        # Step 4: Fine-tune model with RAG
        logger.info("\nStep 4: Starting fine-tuning with RAG augmentation...")
        use_rag = RAG_CONFIG['use_rag']
        if not finetune_model(training_data_file, use_rag=use_rag):
            logger.error("Fine-tuning setup failed")
            return False
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("✓ Model training pipeline completed successfully!")
        logger.info("="*70)
        logger.info(f"\nNext Steps:")
        logger.info(f"  1. Install required packages:")
        logger.info(f"     pip install torch transformers peft bitsandbytes datasets trl")
        
        if use_rag:
            logger.info(f"  2. Install RAG dependencies:")
            logger.info(f"     pip install sentence-transformers chromadb")
        
        logger.info(f"  3. Uncomment training code in finetune_model()")
        logger.info(f"  4. Run this script again to start fine-tuning")
        logger.info(f"  5. Fine-tuned model will be saved to:")
        logger.info(f"     {TRAINING_CONFIG['output_dir']}")
        logger.info("="*70 + "\n")
        
        return True
        
    except Exception as e:
        logger.error(f"Fatal error in training pipeline: {e}")
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
