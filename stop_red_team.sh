#!/usr/bin/env bash
# ================================================================
# Aegis Red Team Operations — Stop Script
# ================================================================
APP_DIR="/opt/vuln_intel/app"
PID_FILE="$APP_DIR/red_team.pid"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    log "Stopping Red Team Operations (PID $(cat "$PID_FILE"))..."
    kill "$(cat "$PID_FILE")"
    rm -f "$PID_FILE"
    log "✅ Stopped."
else
    log "No running Red Team process found."
    pkill -f "red_team_app.py" 2>/dev/null && log "Killed orphan process." || true
fi
