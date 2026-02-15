#!/bin/bash
# VulnGuard AI Virtual Environment Activation Script for Bash/Zsh
# This script can be run from any path to activate the project's virtual environment
# Usage: source activate.sh (from project root) or bash activate.sh

show_help() {
    cat << EOF
VulnGuard AI Virtual Environment Activation Script

USAGE:
    source activate.sh              # Activate from project root
    source activate.sh deactivate   # Deactivate venv
    source activate.sh help         # Show this help

DESCRIPTION:
    Activates the .venv virtual environment for the VulnGuard AI project.
    This script updates PATH, VIRTUAL_ENV, and other environment variables.

NOTES:
    - Run from the project root directory
    - Use source (source activate.sh) to apply changes to current shell
    - Make sure the script is executable: chmod +x activate.sh

EOF
}

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR"
VENV_PATH="$PROJECT_ROOT/.venv"
ACTIVATE_SCRIPT="$VENV_PATH/bin/activate"

# Check if help is requested
if [[ "$1" == "help" || "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    return 0 2>/dev/null || exit 0
fi

# Check if deactivate is requested
if [[ "$1" == "deactivate" ]]; then
    if command -v deactivate &> /dev/null; then
        deactivate
        echo "✓ Virtual environment deactivated"
    else
        echo "⚠ Virtual environment is not currently active"
    fi
    return 0 2>/dev/null || exit 0
fi

# Check if venv exists
if [ ! -d "$VENV_PATH" ]; then
    echo "✗ Virtual environment not found at: $VENV_PATH"
    echo "Please create a virtual environment first:"
    echo "  python3 -m venv .venv"
    return 1 2>/dev/null || exit 1
fi

# Activate virtual environment
if [ -f "$ACTIVATE_SCRIPT" ]; then
    source "$ACTIVATE_SCRIPT"
    echo "✓ Virtual environment activated: $VENV_PATH"
    python --version | sed 's/^/  Python: /'
    echo "  Executable: $(python -c 'import sys; print(sys.executable)')"
    echo ""
    echo "Next steps:"
    echo "  1. Install requirements: pip install -r requirements.txt"
    echo "  2. Run stages: python -m VULNGUARD_AI.components.stage_XX"
    echo "  3. Deactivate venv: source activate.sh deactivate"
    echo ""
else
    echo "✗ Activation script not found at: $ACTIVATE_SCRIPT"
    echo "Your virtual environment may be corrupted. Try recreating it:"
    echo "  rm -rf .venv"
    echo "  python3 -m venv .venv"
    return 1 2>/dev/null || exit 1
fi
