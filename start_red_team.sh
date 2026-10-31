#!/usr/bin/env bash
# ================================================================
# Aegis Red Team Operations — Start Script (port 9013)
# ================================================================
set -euo pipefail

APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv/bin/python"
PID_FILE="$APP_DIR/red_team.pid"
LOG_FILE="$APP_DIR/logs/red_team.log"
PORT=9013

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

[ -f "$VENV" ]                      || die "Python venv not found at $VENV"
[ -f "$APP_DIR/red_team_app.py" ]   || die "App file missing: $APP_DIR/red_team_app.py"

# Stop any existing instance
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    log "Stopping existing Red Team process (PID $(cat "$PID_FILE"))..."
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
    rm -f "$PID_FILE"
fi
pkill -f "red_team_app.py" 2>/dev/null || true
sleep 1

mkdir -p "$APP_DIR/logs"

log "Starting Aegis Red Team Operations on port $PORT..."
cd "$APP_DIR"
nohup "$VENV" red_team_app.py --port "$PORT" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
log "App PID: $(cat "$PID_FILE") — log: $LOG_FILE"

log "Waiting for app to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${PORT}/" -o /dev/null 2>/dev/null; then
        log "✅ Red Team app ready after ${i}s"
        break
    fi
    sleep 1
    printf "."
done
echo ""

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Aegis Red Team Operations — Running                      ║"
echo "╠════════════════════════════════════════════════════════════╣"
printf "║  URL  →  http://%-42s║\n" "localhost:${PORT}/"
printf "║  PID  →  %-48s║\n" "$(cat "$PID_FILE")"
printf "║  Log  →  %-48s║\n" "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝"
