#!/bin/bash
APP_DIR="$(pwd)"
VENV_DIR="$APP_DIR/venv"
source "$VENV_DIR/bin/activate"
which python
python -c "import dash" || echo "failed"
