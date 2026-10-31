#!/bin/bash
set -e
echo "=== Aegis Premium Restart ==="
cd /opt/vuln_intel/app

# Kill any existing app
pkill -f "python.*app.py" 2>/dev/null || true
sleep 2

# Start fresh with nohup (detached from this shell)
nohup /opt/vuln_intel/app/venv/bin/python app.py \
    > /opt/vuln_intel/app/aegis_app.log 2>&1 &

echo "PID: $!"
echo "$!" > /opt/vuln_intel/app/aegis.pid

# Wait and confirm
sleep 6
if ss -tlnp | grep -q ":9009"; then
    echo "✅ App is listening on :9009"
else
    echo "❌ App failed to start on :9009"
    tail -20 /opt/vuln_intel/app/aegis_app.log
fi
