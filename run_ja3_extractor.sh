#!/bin/bash
# Script for automatic JA3 Extractor launch with virtual environment

# Define script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Create separate pycache directory
PYCACHE_DIR="$SCRIPT_DIR/__pycache__"
mkdir -p "$PYCACHE_DIR"

# Set Python to use separate pycache directory
export PYTHONPYCACHEPREFIX="$PYCACHE_DIR"

# Check virtual environment existence
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    echo "Installing dependencies..."
    source "$VENV_DIR/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements.txt"
else
    echo "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
fi

# Run main script
echo "Running JA3 Extractor..."
python "$SCRIPT_DIR/ja3_extractor.py" "$@"
