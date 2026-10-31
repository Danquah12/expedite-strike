#!/usr/bin/env bash
# ================================================================
# Aegis SOC Platform — Production Startup Script
# Starts: Dash app (port 9009) + Nginx reverse proxy (80/443)
# ================================================================
set -euo pipefail

APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv/bin/python"
SSL_DIR="$APP_DIR/ssl"
NGINX_CONF="$SSL_DIR/nginx.conf"
NGINX_PID="$SSL_DIR/nginx.pid"
APP_PID="$SSL_DIR/app.pid"
APP_LOG="$SSL_DIR/app.log"

# ── helpers ──────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ── check prerequisites ──────────────────────────────────────────
[ -f "$VENV" ]       || die "Python venv not found at $VENV"
[ -f "$NGINX_CONF" ] || die "Nginx config not found at $NGINX_CONF"
[ -f "$SSL_DIR/aegis.crt" ] || die "SSL cert missing — run: openssl req ..."

# ── stop any existing processes ──────────────────────────────────
log "Stopping any existing Aegis processes..."
if [ -f "$NGINX_PID" ] && kill -0 "$(cat $NGINX_PID)" 2>/dev/null; then
    nginx -c "$NGINX_CONF" -s quit 2>/dev/null && log "Nginx stopped" || true
    rm -f "$NGINX_PID"
fi
if [ -f "$APP_PID" ] && kill -0 "$(cat $APP_PID)" 2>/dev/null; then
    kill "$(cat $APP_PID)" 2>/dev/null && log "App stopped" || true
    rm -f "$APP_PID"
fi
# Belt-and-suspenders: kill any leftover processes
pkill -f "python.*app.py" 2>/dev/null || true
sleep 1

# ── start Dash app ────────────────────────────────────────────────
log "Starting Aegis Dash app on port 9009..."
cd "$APP_DIR"
nohup "$VENV" app.py > "$APP_LOG" 2>&1 &
echo $! > "$APP_PID"
log "App PID: $(cat $APP_PID) — log: $APP_LOG"

# Wait for app to be ready (up to 40s)
log "Waiting for app to be ready..."
for i in $(seq 1 40); do
    if curl -sf http://127.0.0.1:9009/ -o /dev/null 2>/dev/null; then
        log "✅ Dash app is ready after ${i}s"
        break
    fi
    sleep 1
    printf "."
done
echo ""

# ── start Nginx ───────────────────────────────────────────────────
log "Testing nginx config..."
nginx -t -c "$NGINX_CONF" || die "Nginx config test failed"

log "Starting nginx reverse proxy..."
nginx -c "$NGINX_CONF"
log "✅ Nginx started (PID: $(cat $NGINX_PID 2>/dev/null || echo unknown))"

# ── summary ───────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      AEGIS SOC Platform — Production Running             ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  HTTP  → https redirect  :  http://localhost             ║"
echo "║  HTTPS → Aegis Dashboard : https://localhost             ║"
echo "║  Direct (dev only)       : http://localhost:9009         ║"
echo "║  App Log                 : $APP_LOG"
echo "║  Nginx Access Log        : $SSL_DIR/nginx-access.log"
echo "║  Nginx Error Log         : $SSL_DIR/nginx-error.log"
echo "╚══════════════════════════════════════════════════════════╝"
