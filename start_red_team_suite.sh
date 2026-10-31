#!/usr/bin/env bash
# Aegis Red Team Suite — Start Script (port 9014)
set -euo pipefail
APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv/bin/python"
PID_FILE="$APP_DIR/red_team_suite.pid"
LOG_FILE="$APP_DIR/logs/red_team_suite.log"
PORT=9014
log() { echo "[$(date '+%H:%M:%S')] $*"; }
[ -f "$VENV" ] || { echo "[ERROR] venv missing"; exit 1; }
[ -f "$APP_DIR/red_team_suite_app.py" ] || { echo "[ERROR] app file missing"; exit 1; }
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    log "Stopping existing process (PID $(cat "$PID_FILE"))..."
    kill "$(cat "$PID_FILE")" 2>/dev/null || true; sleep 1; rm -f "$PID_FILE"
fi
pkill -f "red_team_suite_app.py" 2>/dev/null || true; sleep 1
mkdir -p "$APP_DIR/logs"
log "Starting Aegis Red Team Suite on port $PORT..."
cd "$APP_DIR"
nohup "$VENV" red_team_suite_app.py --port "$PORT" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
log "PID: $(cat "$PID_FILE") — log: $LOG_FILE"
log "Waiting for app to be ready..."
for i in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${PORT}/" -o /dev/null 2>/dev/null; then
        log "✅ Red Team Suite ready after ${i}s"; break; fi
    sleep 2; printf "."; done; echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Aegis Red Team Suite — Running                           ║"
echo "╠════════════════════════════════════════════════════════════╣"
printf "║  URL  →  http://%-42s║\n" "localhost:${PORT}/"
printf "║  PID  →  %-48s║\n" "$(cat "$PID_FILE")"
echo "╚════════════════════════════════════════════════════════════╝"
