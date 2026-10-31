#!/usr/bin/env bash

# Silence EVERYTHING from this script
exec >/dev/null 2>&1

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="/Backup/vuln_intel/venv"
PORT=9008

# Activate venv
source "$VENV_DIR/bin/activate"

# Load .env vars safely
if [ -f "$APP_DIR/.env" ]; then
  set -a
  source "$APP_DIR/.env"
  set +a
fi

# Ensure Neo4j is running
if command -v neo4j &>/dev/null; then
  neo4j status | grep -q "running" || neo4j start
fi

# Free Dash port if needed
if lsof -i :"$PORT" &>/dev/null; then
  fuser -k "$PORT"/tcp
fi

# Log dir + run app (all output -> log file)
mkdir -p "$APP_DIR/logs"
exec python app.py > "$APP_DIR/logs/app.log" 2>&1
