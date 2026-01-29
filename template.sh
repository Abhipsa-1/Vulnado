#!/bin/bash

PROJECT_NAME="VULNGUARD_AI"

echo "Creating VulnGuard-AI project structure in current directory..."

# GitHub workflows
mkdir -p .github/workflows
touch .github/workflows/.gitkeep

# Source structure
mkdir -p src/$PROJECT_NAME/{components,pipeline,entity,utils,config,constants,logger,exception}
touch src/$PROJECT_NAME/__init__.py

# Components (pipeline stages)
touch src/$PROJECT_NAME/components/__init__.py
touch src/$PROJECT_NAME/components/stage_00_data_ingestion.py
touch src/$PROJECT_NAME/components/stage_01_data_validation.py
touch src/$PROJECT_NAME/components/stage_02_data_transformation.py
touch src/$PROJECT_NAME/components/stage_03_feature_engineering.py
touch src/$PROJECT_NAME/components/stage_04_attack_mapping.py
touch src/$PROJECT_NAME/components/stage_05_model_training.py

# Pipeline
touch src/$PROJECT_NAME/pipeline/__init__.py
touch src/$PROJECT_NAME/pipeline/training_pipeline.py

# Entity
touch src/$PROJECT_NAME/entity/__init__.py
touch src/$PROJECT_NAME/entity/config_entity.py
touch src/$PROJECT_NAME/entity/artifact_entity.py

# Utils
touch src/$PROJECT_NAME/utils/__init__.py
touch src/$PROJECT_NAME/utils/utils.py

# Config
touch src/$PROJECT_NAME/config/__init__.py
touch src/$PROJECT_NAME/config/configuration.py

# Constants
touch src/$PROJECT_NAME/constants/__init__.py
touch src/$PROJECT_NAME/constants/constants.py

# Logger
touch src/$PROJECT_NAME/logger/__init__.py
touch src/$PROJECT_NAME/logger/log.py

# Exception handling
touch src/$PROJECT_NAME/exception/__init__.py
touch src/$PROJECT_NAME/exception/exception_handler.py

# Data directories
mkdir -p data/{raw,processed}

# Config & pipeline support files
mkdir -p config
touch config/config.yaml
touch params.yaml
touch dvc.yaml

# App & setup
touch app.py
touch setup.py
touch requirements.txt
touch README.md

# Research & templates
mkdir -p research
touch research/trials.py

mkdir -p templates
touch templates/index.html

echo "VulnGuard-AI project structure created successfully!"
