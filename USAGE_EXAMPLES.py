"""
VulnGuard AI - Usage Examples and Integration Guide
Demonstrates how to use the RAG + LLaMA training pipeline
"""

# ============================================================================
# EXAMPLE 1: Run the Complete Pipeline
# ============================================================================

"""
The simplest way to execute the entire pipeline:

cd /Users/abhipsa/Documents/VulnGuard\ AI
python orchestrate_pipeline.py

This will:
1. Check all prerequisites (directories, scripts, Neo4j, dependencies)
2. Run Stage 04 (fetch data from Neo4j)
3. Run Stage 04B (setup RAG retrieval system)
4. Run Stage 05 (train LLaMA with RAG augmentation)
5. Generate comprehensive logs and summary
"""


# ============================================================================
# EXAMPLE 2: Run Individual Stages
# ============================================================================

"""
If you want more control, run stages individually:

# Stage 04: Fetch data from Neo4j
cd /Users/abhipsa/Documents/VulnGuard\ AI/src/VULNGUARD_AI/components
python stage_04_data_fetch_neo4j.py

# Stage 04B: Setup RAG system
python stage_04b_rag_retrieval.py

# Stage 05: Train LLaMA with RAG
python stage_05_llama_training_with_rag.py
"""


# ============================================================================
# EXAMPLE 3: Programmatic Usage - Data Fetching
# ============================================================================

from neo4j import GraphDatabase
import json
from pathlib import Path

def example_fetch_neo4j_data():
    """Example: Manually fetch data from Neo4j"""
    
    # Connect to Neo4j
    uri = "neo4j://localhost:7687"
    username = "neo4j"
    password = "testpassword"
    
    driver = GraphDatabase.driver(uri, auth=(username, password))
    
    # Fetch CVE nodes
    with driver.session() as session:
        result = session.run("""
            MATCH (cve:CVE)
            RETURN cve.cve_id as cve_id,
                   cve.description as description,
                   cve.severity as severity
            LIMIT 10
        """)
        
        cves = []
        for record in result:
            cves.append({
                'id': record['cve_id'],
                'description': record['description'],
                'severity': record['severity']
            })
        
        print(f"Fetched {len(cves)} CVEs:")
        for cve in cves:
            print(f"  - {cve['id']}: {cve['severity']}")
    
    driver.close()


# ============================================================================
# EXAMPLE 4: Using RAG for Context Retrieval
# ============================================================================

def example_rag_retrieval():
    """Example: Retrieve context using RAG system"""
    
    import sys
    sys.path.insert(0, '/Users/abhipsa/Documents/VulnGuard AI/src')
    
    from VULNGUARD_AI.components.stage_04b_rag_retrieval import (
        Neo4jRAGRetriever,
        EmbeddingService,
        RAGContextGenerator
    )
    
    # Initialize retriever
    retriever = Neo4jRAGRetriever(
        neo4j_uri="neo4j://localhost:7687",
        neo4j_username="neo4j",
        neo4j_password="testpassword"
    )
    
    if not retriever.connect():
        print("Failed to connect to Neo4j")
        return
    
    # Get context for a CVE
    cve_id = "CVE-2023-0001"
    context = retriever.retrieve_cve_context(cve_id)
    
    if context:
        print(f"\nContext for {cve_id}:")
        print(f"  Description: {context['cve'].get('description', 'N/A')}")
        print(f"  Severity: {context['cve'].get('severity', 'N/A')}")
        print(f"  Related MITRE Techniques: {len(context['mitre_techniques'])}")
        print(f"  Related GSA Advisories: {len(context['gsa_advisories'])}")
        
        # Display related techniques
        for technique in context['mitre_techniques'][:3]:
            tech = technique['technique']
            score = technique['score']
            print(f"    - {tech.get('technique_id')}: {tech.get('technique_name')} (score: {score})")
    
    retriever.close()


# ============================================================================
# EXAMPLE 5: Using Embeddings for Semantic Search
# ============================================================================

def example_semantic_search():
    """Example: Perform semantic search on vulnerability data"""
    
    import sys
    sys.path.insert(0, '/Users/abhipsa/Documents/VulnGuard AI/src')
    
    from VULNGUARD_AI.components.stage_04b_rag_retrieval import EmbeddingService
    
    # Initialize embedding service
    embedding_service = EmbeddingService()
    if not embedding_service.initialize():
        print("Failed to initialize embeddings")
        return
    
    # Example vulnerability descriptions
    descriptions = [
        "SQL injection in user login form allows unauthorized database access",
        "Cross-site scripting vulnerability in comment section",
        "SQL injection in search functionality",
        "Remote code execution through file upload",
        "Buffer overflow in password processing"
    ]
    
    # Encode descriptions
    embeddings = embedding_service.encode(descriptions)
    
    # Search for similar
    query = "SQL injection vulnerability"
    results = embedding_service.semantic_search(
        query,
        embeddings,
        descriptions,
        top_k=3
    )
    
    print(f"\nTop results for query: '{query}'")
    for i, result in enumerate(results, 1):
        print(f"  {i}. {result['text']} (score: {result['score']:.3f})")


# ============================================================================
# EXAMPLE 6: Loading and Using Fine-Tuned Model
# ============================================================================

def example_inference_with_finetuned_model():
    """Example: Use fine-tuned LLaMA model for inference"""
    
    from transformers import AutoTokenizer, AutoModelForCausalLM
    
    model_path = "/Users/abhipsa/Documents/VulnGuard AI/models/llama_finetuned"
    
    # Load tokenizer and model
    print("Loading fine-tuned model...")
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        device_map='auto',
        torch_dtype='auto'
    )
    
    # Example CVEs to map
    cve_samples = [
        "CVE-2023-12345: SQL injection in login form",
        "CVE-2024-54321: Cross-site scripting in comments",
        "CVE-2023-98765: Buffer overflow in image processing"
    ]
    
    print("\nGenerating MITRE mappings:")
    for cve_desc in cve_samples:
        inputs = tokenizer(cve_desc, return_tensors="pt")
        outputs = model.generate(
            **inputs,
            max_new_tokens=50,
            temperature=0.7,
            top_p=0.9
        )
        
        prediction = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"\n{cve_desc}")
        print(f"Predicted mapping: {prediction}")


# ============================================================================
# EXAMPLE 7: Integration with Flask API
# ============================================================================

"""
Example Flask API for using the fine-tuned model:

from flask import Flask, request, jsonify
from transformers import AutoTokenizer, AutoModelForCausalLM

app = Flask(__name__)

# Load model once at startup
MODEL_PATH = "/Users/abhipsa/Documents/VulnGuard AI/models/llama_finetuned"
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForCausalLM.from_pretrained(MODEL_PATH, device_map='auto')

@app.route('/predict', methods=['POST'])
def predict():
    '''Predict MITRE techniques for a CVE'''
    
    data = request.json
    cve_description = data.get('cve_description')
    
    if not cve_description:
        return jsonify({'error': 'cve_description required'}), 400
    
    # Generate prediction
    inputs = tokenizer(cve_description, return_tensors="pt")
    outputs = model.generate(**inputs, max_new_tokens=50)
    prediction = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    return jsonify({
        'input': cve_description,
        'prediction': prediction
    })

if __name__ == '__main__':
    app.run(debug=False, port=5000)
"""


# ============================================================================
# EXAMPLE 8: Batch Processing Multiple CVEs
# ============================================================================

def example_batch_processing():
    """Example: Process multiple CVEs in batch"""
    
    import json
    from pathlib import Path
    
    # Load training dataset
    training_file = Path("/Users/abhipsa/Documents/VulnGuard AI/training_data/training_dataset.jsonl")
    
    if not training_file.exists():
        print("Training data not found. Run stage_04 first.")
        return
    
    # Process samples
    samples = []
    with open(training_file, 'r') as f:
        for i, line in enumerate(f):
            if i < 10:  # First 10 samples
                sample = json.loads(line)
                samples.append(sample)
    
    print(f"Loaded {len(samples)} samples")
    
    # Display augmentation info
    for i, sample in enumerate(samples, 1):
        metadata = sample.get('metadata', {})
        print(f"\nSample {i}:")
        print(f"  CVE: {metadata.get('cve_id', 'N/A')}")
        print(f"  MITRE: {metadata.get('mitre_id', 'N/A')}")
        print(f"  Has Context: {metadata.get('has_context', False)}")
        print(f"  Related Techniques: {metadata.get('num_related_techniques', 0)}")


# ============================================================================
# EXAMPLE 9: Evaluating Model Performance
# ============================================================================

def example_evaluate_model():
    """Example: Evaluate fine-tuned model on test data"""
    
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import json
    from pathlib import Path
    
    model_path = "/Users/abhipsa/Documents/VulnGuard AI/models/llama_finetuned"
    
    # Load model
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path, device_map='auto')
    
    # Load test data
    test_file = Path("/Users/abhipsa/Documents/VulnGuard AI/training_data/training_dataset.jsonl")
    
    correct = 0
    total = 0
    
    with open(test_file, 'r') as f:
        for i, line in enumerate(f):
            if i >= 100:  # Test on first 100
                break
            
            sample = json.loads(line)
            
            # Extract expected output
            expected = sample.get('output', '')
            
            # Generate prediction
            inputs = tokenizer(sample['input'][:100], return_tensors="pt")
            outputs = model.generate(**inputs, max_new_tokens=50)
            predicted = tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Simple check: does output start with expected MITRE ID?
            expected_mitre = expected.split(':')[0].strip()
            if expected_mitre in predicted:
                correct += 1
            
            total += 1
    
    accuracy = (correct / total * 100) if total > 0 else 0
    print(f"\nModel Evaluation Results:")
    print(f"  Samples tested: {total}")
    print(f"  Correct predictions: {correct}")
    print(f"  Accuracy: {accuracy:.2f}%")


# ============================================================================
# EXAMPLE 10: Custom Training with Different Configuration
# ============================================================================

"""
Example: Fine-tune with custom configuration

from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)
from peft import get_peft_model, LoraConfig, TaskType
from datasets import Dataset
import json

# Load training data
training_samples = []
with open('/Users/abhipsa/Documents/VulnGuard AI/training_data/training_dataset.jsonl', 'r') as f:
    for line in f:
        sample = json.loads(line)
        training_samples.append(sample)

# Create dataset
texts = [
    f"Instruction: {s['instruction']}\\n\\nInput:\\n{s['input']}\\n\\nOutput:\\n{s['output']}"
    for s in training_samples
]

dataset = Dataset.from_dict({'text': texts})

# Load model and tokenizer
tokenizer = AutoTokenizer.from_pretrained('Llama-4-Maverick-17B-128E-Instruct')
model = AutoModelForCausalLM.from_pretrained(
    'Llama-4-Maverick-17B-128E-Instruct',
    device_map='auto',
    torch_dtype='auto',
    load_in_4bit=True
)

# Apply LoRA
lora_config = LoraConfig(
    task_type=TaskType.CAUSAL_LM,
    r=16,
    lora_alpha=32,
    lora_dropout=0.1,
    target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj']
)
model = get_peft_model(model, lora_config)

# Training arguments
training_args = TrainingArguments(
    output_dir='/Users/abhipsa/Documents/VulnGuard AI/models/custom_training',
    num_train_epochs=5,  # More epochs for better quality
    per_device_train_batch_size=4,  # Smaller batch for better updates
    learning_rate=5e-6,  # Lower learning rate
    warmup_ratio=0.2,
    fp16=True,
    logging_steps=10,
    save_steps=500,
    gradient_accumulation_steps=4
)

# Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
    tokenizer=tokenizer
)

# Train
trainer.train()

# Save
model.save_pretrained('/Users/abhipsa/Documents/VulnGuard AI/models/custom_training')
tokenizer.save_pretrained('/Users/abhipsa/Documents/VulnGuard AI/models/custom_training')
"""


# ============================================================================
# EXAMPLE 11: Debugging - Check Pipeline Status
# ============================================================================

def example_check_pipeline_status():
    """Example: Check status of pipeline execution"""
    
    from pathlib import Path
    import json
    
    base_path = Path("/Users/abhipsa/Documents/VulnGuard AI")
    
    print("\n=== PIPELINE STATUS CHECK ===\n")
    
    # Check Stage 04 output
    training_data = base_path / "training_data"
    if training_data.exists():
        summary_file = training_data / "summary.json"
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)
            print("Stage 04 - Data Fetch: ✓ COMPLETE")
            print(f"  CVE nodes: {summary.get('total_cve_nodes', 0)}")
            print(f"  MITRE nodes: {summary.get('total_mitre_nodes', 0)}")
            print(f"  GSA nodes: {summary.get('total_gsa_nodes', 0)}")
        else:
            print("Stage 04 - Data Fetch: ✗ NOT COMPLETE")
    
    # Check Stage 04B output
    vectorstore = base_path / "vectorstore"
    if vectorstore.exists():
        print("Stage 04B - RAG Setup: ✓ COMPLETE")
        print(f"  Vectorstore size: {sum(f.stat().st_size for f in vectorstore.rglob('*'))/(1024**2):.1f} MB")
    else:
        print("Stage 04B - RAG Setup: ✗ NOT COMPLETE")
    
    # Check Stage 05 output
    models = base_path / "models" / "llama_finetuned"
    if models.exists():
        print("Stage 05 - Training: ✓ COMPLETE")
        print(f"  Model size: {sum(f.stat().st_size for f in models.rglob('*'))/(1024**3):.1f} GB")
    else:
        print("Stage 05 - Training: ✗ NOT COMPLETE")
    
    # Check logs
    logs = base_path / "logs"
    if logs.exists():
        log_files = list(logs.glob("*.log"))
        print(f"\nLog files: {len(log_files)}")
        if log_files:
            latest_log = max(log_files, key=lambda p: p.stat().st_mtime)
            print(f"  Latest: {latest_log.name}")


# ============================================================================
# EXAMPLE 12: Simple CLI Tool
# ============================================================================

def example_cli_tool():
    """Example: Simple CLI tool for pipeline interaction"""
    
    import argparse
    import subprocess
    import sys
    
    parser = argparse.ArgumentParser(
        description="VulnGuard AI Pipeline CLI"
    )
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Run command
    subparsers.add_parser('run', help='Run complete pipeline')
    
    # Status command
    subparsers.add_parser('status', help='Check pipeline status')
    
    # Logs command
    subparsers.add_parser('logs', help='Show recent logs')
    
    # Test command
    subparsers.add_parser('test', help='Run tests')
    
    args = parser.parse_args()
    
    if args.command == 'run':
        subprocess.run([
            sys.executable,
            '/Users/abhipsa/Documents/VulnGuard AI/orchestrate_pipeline.py'
        ])
    
    elif args.command == 'status':
        example_check_pipeline_status()
    
    elif args.command == 'logs':
        import subprocess
        subprocess.run(['tail', '-20', 'logs/stage_05_*.log'])
    
    elif args.command == 'test':
        example_semantic_search()
    
    else:
        parser.print_help()


# ============================================================================
# Main - Run Examples
# ============================================================================

if __name__ == "__main__":
    print("VulnGuard AI - Usage Examples")
    print("=" * 50)
    print("\nAvailable examples:")
    print("1. example_fetch_neo4j_data() - Fetch from Neo4j")
    print("2. example_rag_retrieval() - Use RAG context retrieval")
    print("3. example_semantic_search() - Semantic search on embeddings")
    print("4. example_inference_with_finetuned_model() - Run inference")
    print("5. example_batch_processing() - Batch processing")
    print("6. example_evaluate_model() - Model evaluation")
    print("7. example_check_pipeline_status() - Check pipeline status")
    print("8. example_cli_tool() - Interactive CLI")
    print("\nTo run an example:")
    print("  python this_file.py")
    print("\nThen uncomment the example function at the bottom to execute it")
