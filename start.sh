#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║     AEGIS — One-Command Start Script                        ║
# ║     Usage:  ./start.sh                                      ║
# ║     Stop:   ./start.sh stop                                 ║
# ║     Status: ./start.sh status                               ║
# ╚══════════════════════════════════════════════════════════════╝

APP=/opt/vuln_intel/app
PY=/opt/vuln_intel/app/venv/bin/python3
LOG=/tmp/aegis_logs

mkdir -p $LOG

# ── Service map: name → script → port ────────────────────────────
declare -A SCRIPTS=(
  [main]="app.py"
  [assessment]="external_assessment_app.py"
  [redteam]="red_team_app.py"
  [redteam-suite]="red_team_suite_app.py"
  [defence]="defence_app.py"
  [specialised]="specialised_app.py"
  [grc]="grc_app.py"
  [dfir]="dfir_app.py"
  [platform]="platform_app.py"
  [home]="home_app.py"
  [reports]="reports_app.py"
  [launchpad]="launchpad_server.py"
)
declare -A PORTS=(
  [main]="9011"
  [assessment]="9012"
  [redteam]="9013"
  [redteam-suite]="9014"
  [defence]="9015"
  [specialised]="9016"
  [grc]="9017"
  [dfir]="9018"
  [platform]="9019"
  [home]="9020"
  [reports]="9021"
  [launchpad]="9000"
)
ORDERED=(main assessment redteam redteam-suite defence specialised grc dfir platform home reports launchpad)

_is_running() {
  local port=${PORTS[$1]}
  ss -tlnp 2>/dev/null | grep -q ":$port "
}

case "${1:-start}" in

  start)
    echo "🚀 Starting Aegis platform..."
    echo ""
    # Start Cloudflare tunnel
    systemctl --user start aegis-tunnel 2>/dev/null
    echo "  ✅ aegis-tunnel (Cloudflare)"

    cd $APP
    for svc in "${ORDERED[@]}"; do
      script=${SCRIPTS[$svc]}
      port=${PORTS[$svc]}
      if _is_running $svc; then
        echo "  ⏭  $svc (already on :$port)"
        continue
      fi
      nohup $PY $APP/$script > $LOG/$svc.log 2>&1 &
      echo "  🟡 $svc (:$port) — starting..."
    done

    echo ""
    echo "⏳ Waiting 20s for services to initialise..."
    sleep 20
    echo ""
    $0 status
    ;;

  stop)
    echo "🛑 Stopping Aegis..."
    systemctl --user stop aegis-tunnel 2>/dev/null
    pkill -f "external_assessment_app\|red_team_app\|red_team_suite_app\|defence_app\|specialised_app\|grc_app\|dfir_app\|platform_app\|home_app\|reports_app\|launchpad_server" 2>/dev/null
    pkill -f "gunicorn.*app:server" 2>/dev/null
    echo "✅ All services stopped."
    ;;

  restart)
    $0 stop
    sleep 4
    $0 start
    ;;

  status)
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  MODULE            PORT   PID     STATUS                  ║"
    echo "╠════════════════════════════════════════════════════════════╣"
    for svc in "${ORDERED[@]}"; do
      port=${PORTS[$svc]}
      info=$(ss -tlnp 2>/dev/null | grep ":$port ")
      pid=$(echo "$info" | grep -oP 'pid=\K[0-9]+' | head -1)
      if [ -n "$info" ]; then
        printf "║  %-18s %-6s %-7s %-23s ║\n" "$svc" ":$port" "${pid:-?" "}" "✅ running"
      else
        printf "║  %-18s %-6s %-7s %-23s ║\n" "$svc" ":$port" "-" "❌ not running"
      fi
    done
    tun=$(systemctl --user is-active aegis-tunnel 2>/dev/null)
    printf "║  %-18s %-6s %-7s %-23s ║\n" "cloudflare-tunnel" "CF" "-" "$([ "$tun" = "active" ] && echo "✅ active" || echo "❌ $tun")"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  🌐  https://vulne.expediteconsults.com"
    ;;

  logs)
    svc="${2:-main}"
    logfile="$LOG/$svc.log"
    if [ -f "$logfile" ]; then
      echo "📋 Logs for $svc (Ctrl+C to exit):"
      tail -f "$logfile"
    else
      echo "No log found for '$svc'. Available:"
      ls $LOG/*.log 2>/dev/null | xargs -I{} basename {} .log
    fi
    ;;

  *)
    echo "Usage: ./start.sh [start|stop|restart|status|logs <service>]"
    echo "Services: ${!SCRIPTS[@]}"
    ;;
esac
