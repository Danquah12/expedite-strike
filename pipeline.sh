#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ÆGIS TACTICAL DEPLOYMENT PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════
# One-command deploy from Kali → Production Server
#
# Usage:
#   ./pipeline.sh              Full deploy (build + transfer + restart)
#   ./pipeline.sh --quick      Quick sync (transfer + restart, no rebuild)
#   ./pipeline.sh --code-only  Code sync only (no Docker rebuild)
#   ./pipeline.sh --status     Check production health
#   ./pipeline.sh --logs       Tail production logs
#   ./pipeline.sh --rollback   Rollback to previous deployment
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
PROD_HOST="203.161.52.21"
PROD_USER="root"
PROD_PASS='Datesexpo12@*&^%!@#$Ds'
PROD_DIR="/opt/aegis"
LOCAL_DIR="/opt/vuln_intel/app"
DOMAIN="aegis.expediteconsults.com"
ARCHIVE="/tmp/aegis-deploy.tar.gz"
BACKUP_ARCHIVE="/tmp/aegis-deploy-prev.tar.gz"

# ── Exclude patterns for archive ─────────────────────────────────────────────
EXCLUDES=(
    --exclude='.local' --exclude='.config' --exclude='node_modules'
    --exclude='data' --exclude='reports' --exclude='certs'
    --exclude='venv' --exclude='__pycache__' --exclude='.git'
    --exclude='*.log' --exclude='*.pyc' --exclude='*.bak'
    --exclude='*.bak.*' --exclude='backup-*' --exclude='backups'
    --exclude='scans' --exclude='scan_history' --exclude='outputs'
    --exclude='uploads' --exclude='*.pdf' --exclude='chunks'
    --exclude='*.sqlite3' --exclude='*.zip' --exclude='*.tar.gz'
    --exclude='*.saz' --exclude='11-*' --exclude='*_backup_*'
    --exclude='vault_keys.json' --exclude='.ssh_config'
    --exclude='pipeline.sh'
)

# ── Service registry ─────────────────────────────────────────────────────────
SERVICES=(
    "COMMAND:9000" "WATCHTOWER:9001" "BASTION:9021" "SPECTRE:9012"
    "VIPER:9013" "TRIDENT:9014" "RAMPART:9015" "ECHELON:9016"
    "BULWARK:9017" "CORSAIR:9018" "NEXUS:9019" "LEDGER:9020" "NGINX:80"
)

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helper functions ──────────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}⚔️  ════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}⚔️  ${BOLD}$1${NC}"
    echo -e "${CYAN}⚔️  ════════════════════════════════════════════════════════${NC}"
    echo ""
}

step() { echo -e "  ${BLUE}▸${NC} $1"; }
ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }

ssh_cmd() {
    sshpass -p "$PROD_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${PROD_USER}@${PROD_HOST}" "$1"
}

scp_cmd() {
    sshpass -p "$PROD_PASS" scp -o StrictHostKeyChecking=no "$1" "${PROD_USER}@${PROD_HOST}:$2"
}

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# ── Health check ──────────────────────────────────────────────────────────────
health_check() {
    banner "PRODUCTION HEALTH CHECK"
    local up=0 down=0
    for entry in "${SERVICES[@]}"; do
        NAME="${entry%%:*}"; PORT="${entry##*:}"
        HTTP=$(ssh_cmd "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://localhost:${PORT}/ 2>/dev/null" 2>/dev/null || echo "000")
        if [ "$HTTP" = "200" ] || [ "$HTTP" = "302" ]; then
            printf "  ${GREEN}✅ %-12s :%-5s %s${NC}\n" "$NAME" "$PORT" "$HTTP"
            up=$((up+1))
        else
            printf "  ${RED}❌ %-12s :%-5s %s${NC}\n" "$NAME" "$PORT" "$HTTP"
            down=$((down+1))
        fi
    done
    echo ""
    # External check
    EXT=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "http://${DOMAIN}/" 2>/dev/null || echo "000")
    echo -e "  🌐 ${DOMAIN} → HTTP ${EXT}"
    echo ""
    echo -e "  ${BOLD}Result: ${up} UP / ${down} DOWN${NC}"
}

# ── Build archive ─────────────────────────────────────────────────────────────
build_archive() {
    step "Building deployment archive..."
    cd "$LOCAL_DIR"
    
    # Backup previous archive for rollback
    [ -f "$ARCHIVE" ] && cp "$ARCHIVE" "$BACKUP_ARCHIVE"
    
    tar czf "$ARCHIVE" "${EXCLUDES[@]}" --warning=no-file-changed . 2>/dev/null || true
    SIZE=$(ls -lh "$ARCHIVE" | awk '{print $5}')
    ok "Archive built: ${SIZE}"
}

# ── Transfer ──────────────────────────────────────────────────────────────────
transfer() {
    step "Transferring to ${PROD_HOST}..."
    scp_cmd "$ARCHIVE" "/opt/"
    ok "Transfer complete"
}

# ── Extract on server ─────────────────────────────────────────────────────────
extract() {
    step "Extracting on production server..."
    ssh_cmd "
        cd ${PROD_DIR} && \
        tar xzf /opt/aegis-deploy.tar.gz && \
        mkdir -p reports data certs && \
        chmod -R 777 data/ 2>/dev/null
    "
    ok "Extracted to ${PROD_DIR}"
}

# ── Docker rebuild ────────────────────────────────────────────────────────────
rebuild() {
    step "Rebuilding Docker image (this may take a few minutes)..."
    ssh_cmd "cd ${PROD_DIR} && docker build -t aegis-platform:latest . 2>&1 | tail -5"
    ok "Image rebuilt"
}

# ── Restart services ──────────────────────────────────────────────────────────
restart_services() {
    step "Killing stale port bindings..."
    ssh_cmd "fuser -k 80/tcp 2>/dev/null; fuser -k 9000/tcp 2>/dev/null; sleep 2" 2>/dev/null || true
    
    step "Restarting all services..."
    ssh_cmd "cd ${PROD_DIR} && docker compose down 2>&1 | tail -3 && docker compose up -d 2>&1 | grep -E 'Created|Started|Error'"
    ok "All services restarted"
    
    step "Waiting 60s for initialization..."
    sleep 60
}

# ── Full deploy ───────────────────────────────────────────────────────────────
full_deploy() {
    banner "ÆGIS FULL DEPLOYMENT PIPELINE"
    echo -e "  📅 $(timestamp)"
    echo -e "  📍 ${LOCAL_DIR} → ${PROD_USER}@${PROD_HOST}:${PROD_DIR}"
    echo ""
    
    build_archive
    transfer
    extract
    rebuild
    restart_services
    health_check
    
    banner "DEPLOYMENT COMPLETE"
    echo -e "  🌐 ${GREEN}${BOLD}http://${DOMAIN}${NC}"
}

# ── Quick deploy (no rebuild) ─────────────────────────────────────────────────
quick_deploy() {
    banner "ÆGIS QUICK DEPLOY (skip rebuild)"
    echo -e "  📅 $(timestamp)"
    echo ""
    
    build_archive
    transfer
    extract
    restart_services
    health_check
    
    banner "QUICK DEPLOY COMPLETE"
}

# ── Code-only sync ────────────────────────────────────────────────────────────
code_only() {
    banner "ÆGIS CODE SYNC (no restart)"
    echo -e "  📅 $(timestamp)"
    echo ""
    
    build_archive
    transfer
    extract
    ok "Code synced — run './pipeline.sh --status' to verify"
}

# ── Rollback ──────────────────────────────────────────────────────────────────
rollback() {
    banner "ÆGIS ROLLBACK"
    if [ ! -f "$BACKUP_ARCHIVE" ]; then
        fail "No backup archive found at ${BACKUP_ARCHIVE}"
        exit 1
    fi
    
    step "Rolling back to previous deployment..."
    cp "$BACKUP_ARCHIVE" "$ARCHIVE"
    transfer
    extract
    rebuild
    restart_services
    health_check
    
    banner "ROLLBACK COMPLETE"
}

# ── Tail logs ─────────────────────────────────────────────────────────────────
tail_logs() {
    banner "ÆGIS PRODUCTION LOGS"
    ssh_cmd "cd ${PROD_DIR} && docker compose logs -f --tail 50"
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-}" in
    --quick)     quick_deploy ;;
    --code-only) code_only ;;
    --status)    health_check ;;
    --logs)      tail_logs ;;
    --rollback)  rollback ;;
    --help|-h)
        echo "ÆGIS Deployment Pipeline"
        echo ""
        echo "Usage: ./pipeline.sh [OPTION]"
        echo ""
        echo "  (no option)    Full deploy: build → transfer → rebuild → restart"
        echo "  --quick        Quick: transfer → restart (skip Docker rebuild)"
        echo "  --code-only    Sync code only (no restart)"
        echo "  --status       Check production health"
        echo "  --logs         Tail production logs"
        echo "  --rollback     Rollback to previous deployment"
        echo "  --help         Show this help"
        ;;
    *)           full_deploy ;;
esac
