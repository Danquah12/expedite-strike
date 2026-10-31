#!/usr/bin/env bash
# ================================================================
# Aegis SOC Platform — Stop Script
# ================================================================
APP_DIR="/opt/vuln_intel/app"
SSL_DIR="$APP_DIR/ssl"
NGINX_PID="$SSL_DIR/nginx.pid"
APP_PID="$SSL_DIR/app.pid"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Stopping Aegis SOC Platform..."

if [ -f "$NGINX_PID" ] && kill -0 "$(cat $NGINX_PID)" 2>/dev/null; then
    nginx -c "$SSL_DIR/nginx.conf" -s quit 2>/dev/null
    log "Nginx stopped"
fi

if [ -f "$APP_PID" ] && kill -0 "$(cat $APP_PID)" 2>/dev/null; then
    kill "$(cat $APP_PID)" 2>/dev/null
    log "App stopped (PID: $(cat $APP_PID))"
fi

pkill -f "python.*app.py" 2>/dev/null && log "Cleaned up remaining app processes" || true
rm -f "$NGINX_PID" "$APP_PID"
log "✅ Platform stopped"
