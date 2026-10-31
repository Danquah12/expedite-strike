#!/usr/bin/env bash
# ================================================================
# Aegis External Assessment — Stop Script
# ================================================================
APP_DIR="/opt/vuln_intel/app"
PID_FILE="$APP_DIR/external_assessment.pid"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    log "Stopping External Assessment (PID $(cat "$PID_FILE"))..."
    kill "$(cat "$PID_FILE")"
    rm -f "$PID_FILE"
    log "✅ Stopped."
else
    log "No running External Assessment process found."
    pkill -f "external_assessment_app.py" 2>/dev/null && log "Killed orphan process." || true
fi
