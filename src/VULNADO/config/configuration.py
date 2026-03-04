"""
Configuration module for VULNADO
Loads all settings from config/config.yaml
"""

import os
from pathlib import Path
from typing import Dict, Any
import yaml
from pydantic import BaseModel, Field


class PathConfig(BaseModel):
    """Path configuration"""
    root_dir: str
    src_dir: str
    config_dir: str


class DataSourcesConfig(BaseModel):
    """External data sources configuration"""
    nvd_api_url: str
    nvd_results_per_page: int = 2000
    nvd_days_back: int = 180
    mitre_url: str
    mitre_days_back: int = 180
    gsa_url: str
    gsa_per_page: int = 100
    gsa_max_pages: int = 18
    gsa_days_back: int = 180


class DataConfig(BaseModel):
    """Data paths configuration"""
    raw_dir: str
    processed_dir: str
    cve_base_dir: str
    cve_extract_dir: str
    normalized_dir: str
    normalized_cve_file: str
    normalized_gsa_file: str
    normalized_mitre_file: str
    entity_chunks_dir: str
    entity_chunks_file: str
    mitre_file: str
    gsa_file: str


class ModelsConfig(BaseModel):
    """Model and training paths configuration"""
    model_dir: str
    llama_finetuned_dir: str
    training_data_dir: str
    training_dataset_file: str
    cve_nodes_file: str
    gsa_nodes_file: str
    mitre_nodes_file: str
    cve_mitre_relationships_file: str
    cve_gsa_relationships_file: str
    cve_mitre_gsa_relationships_file: str
    training_summary_file: str


class VectorstoreConfig(BaseModel):
    """Vectorstore configuration"""
    persist_dir: str


class Neo4jConfig(BaseModel):
    """Neo4j configuration"""
    data_dir: str
    cve_gsa_mappings_file: str
    cve_mitre_mappings_file: str


class Neo4jServiceConfig(BaseModel):
    """Neo4j service connection configuration"""
    uri: str
    username: str
    password: str


class LoggingConfig(BaseModel):
    """Logging configuration"""
    log_dir: str
    log_level: str = "INFO"


class LLMConfig(BaseModel):
    """LLM configuration"""
    model_name: str
    device: str = "auto"
    torch_dtype: str = "float16"


class RAGConfig(BaseModel):
    """RAG configuration"""
    chunk_size: int = 512
    chunk_overlap: int = 128
    embedding_model: str
    max_context_length: int = 2048


class ChatbotConfig(BaseModel):
    """Chatbot configuration"""
    model_max_length: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    max_new_tokens: int = 512


class VulnadoConfig(BaseModel):
    """Main VULNADO configuration"""
    project: PathConfig
    data_sources: DataSourcesConfig
    data: DataConfig
    models: ModelsConfig
    vectorstore: VectorstoreConfig
    neo4j: Neo4jConfig
    neo4j_service: Neo4jServiceConfig
    logging: LoggingConfig
    llm: LLMConfig
    rag: RAGConfig
    chatbot: ChatbotConfig

    class Config:
        arbitrary_types_allowed = True


def load_config(config_path: str = None) -> VulnadoConfig:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to config.yaml. If None, uses default location
        
    Returns:
        VulnadoConfig: Loaded configuration object
    """
    if config_path is None:
        # Try to find config.yaml in the standard location
        config_path = Path(__file__).parent.parent.parent.parent / "config" / "config.yaml"
    
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config_dict = yaml.safe_load(f)
    
    return VulnadoConfig(**config_dict)


# Global configuration instance
_config = None


def get_config() -> VulnadoConfig:
    """
    Get the global configuration instance
    
    Returns:
        VulnadoConfig: Configuration object
    """
    global _config
    if _config is None:
        _config = load_config()
    return _config


def get_project_root() -> Path:
    """Get the project root directory"""
    config = get_config()
    return Path(config.project.root_dir)


def get_data_dir() -> Path:
    """Get the data directory"""
    config = get_config()
    return Path(config.data.raw_dir)


def get_log_dir() -> Path:
    """Get the logs directory"""
    config = get_config()
    return Path(config.logging.log_dir)


def get_training_data_dir() -> Path:
    """Get the training data directory"""
    config = get_config()
    return Path(config.models.training_data_dir)


def get_vectorstore_dir() -> Path:
    """Get the vectorstore directory"""
    config = get_config()
    return Path(config.vectorstore.persist_dir)


def get_neo4j_config() -> Dict[str, Any]:
    """Get Neo4j connection configuration"""
    config = get_config()
    return {
        "uri": config.neo4j_service.uri,
        "username": config.neo4j_service.username,
        "password": config.neo4j_service.password,
    }
