#!/usr/bin/env bash
# ================================================================
# Aegis External Assessment — Start Script (port 9012)
# ================================================================
set -euo pipefail

APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv/bin/python"
PID_FILE="$APP_DIR/external_assessment.pid"
LOG_FILE="$APP_DIR/logs/external_assessment.log"
PORT=9012

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ── Preflight checks ─────────────────────────────────────────────
[ -f "$VENV" ]          || die "Python venv not found at $VENV — run: python3 -m venv $APP_DIR/venv"
[ -f "$APP_DIR/external_assessment_app.py" ] || die "App file missing: $APP_DIR/external_assessment_app.py"

# ── Stop any existing instance ───────────────────────────────────
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    log "Stopping existing External Assessment process (PID $(cat "$PID_FILE"))..."
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
    rm -f "$PID_FILE"
fi
pkill -f "external_assessment_app.py" 2>/dev/null || true
sleep 1

# ── Create logs dir if needed ────────────────────────────────────
mkdir -p "$APP_DIR/logs"

# ── Start the app ────────────────────────────────────────────────
log "Starting Aegis External Assessment on port $PORT..."
cd "$APP_DIR"
nohup "$VENV" external_assessment_app.py --port "$PORT" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
log "App PID: $(cat "$PID_FILE") — log: $LOG_FILE"

# ── Wait for app to be ready (up to 30s) ────────────────────────
log "Waiting for app to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${PORT}/" -o /dev/null 2>/dev/null; then
        log "✅ External Assessment ready after ${i}s"
        break
    fi
    sleep 1
    printf "."
done
echo ""

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Aegis External Assessment — Running                      ║"
echo "╠════════════════════════════════════════════════════════════╣"
printf "║  URL  →  http://%-42s║\n" "localhost:${PORT}/"
printf "║  PID  →  %-48s║\n" "$(cat "$PID_FILE")"
printf "║  Log  →  %-48s║\n" "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝"
