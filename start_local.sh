#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  Aegis Pentest Suite — Local Kali Startup Script
#  Run from your Kali terminal: bash /opt/vuln_intel/app/start_local.sh
# ═══════════════════════════════════════════════════════════

set -e
APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv/bin/python"
LOG="/tmp/aegis_local.log"
PID_FILE="/tmp/aegis_local.pid"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     AEGIS Security Operations Center        ║"
echo "║          Local Kali Startup Script           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Kill any existing instance ─────────────────────────────
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    kill "$OLD_PID" 2>/dev/null && echo "🔴 Stopped old instance (PID $OLD_PID)" || true
    rm -f "$PID_FILE"
fi
fuser -k 9009/tcp 2>/dev/null && echo "🔴 Cleared port 9009" || true
sleep 1

# ── Start PostgreSQL ────────────────────────────────────────
echo "▶ Starting PostgreSQL..."
pg_ctlcluster 18 main start 2>&1 | tail -2 || \
    sudo service postgresql start 2>&1 | tail -2 || \
    echo "  ⚠ PostgreSQL couldn't start (GRC features will be limited)"
sleep 2

# ── Start Neo4j ─────────────────────────────────────────────
echo "▶ Starting Neo4j..."
sudo neo4j start 2>&1 | tail -3 || \
    sudo service neo4j start 2>&1 | tail -2 || \
    echo "  ⚠ Neo4j couldn't start (graph features will use cached data)"
sleep 3

# ── Wait for Neo4j bolt port ───────────────────────────────
echo "▶ Waiting for Neo4j (bolt:7687)..."
for i in $(seq 1 20); do
    nc -z localhost 7687 2>/dev/null && echo "  ✅ Neo4j ready!" && break
    printf "."
    sleep 2
done
echo ""

# ── Launch Aegis ────────────────────────────────────────────
echo "▶ Launching Aegis app..."
cd "$APP_DIR"
nohup "$VENV" app.py > "$LOG" 2>&1 &
echo $! > "$PID_FILE"
echo "  PID: $(cat $PID_FILE)"

# ── Wait for Dash to bind ──────────────────────────────────
echo "▶ Waiting for Aegis to bind port 9009..."
for i in $(seq 1 30); do
    ss -tlnp 2>/dev/null | grep -q 9009 && \
        echo "  ✅ Aegis is UP!" && break || \
        nc -z localhost 9009 2>/dev/null && \
        echo "  ✅ Aegis is UP!" && break
    printf "."
    sleep 2
done
echo ""

# ── Final status ───────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
if nc -z localhost 9009 2>/dev/null; then
    echo "  ✅ AEGIS RUNNING"
    echo ""
    echo "  🌐 Local URL:   http://127.0.0.1:9009"
    echo "  🌐 Network URL: http://$(hostname -I | awk '{print $1}'):9009"
    echo "  📋 Log file:    $LOG"
    echo "  🔢 PID:         $(cat $PID_FILE)"
    echo ""
    echo "  To stop:  kill \$(cat $PID_FILE)"
    echo "  To tail:  tail -f $LOG"
else
    echo "  ❌ AEGIS DID NOT START — check log:"
    tail -20 "$LOG"
fi
echo "══════════════════════════════════════════════"
echo ""
