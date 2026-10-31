#!/usr/bin/env bash
# =======================================================================
# setup_infrastructure.sh
# One-shot setup: PostgreSQL + HashiCorp Vault for vuln_intel platform
#
# Run once as a user with sudo:
#   chmod +x setup_infrastructure.sh && ./setup_infrastructure.sh
# =======================================================================

set -e
APP_DIR="/opt/vuln_intel/app"
VENV="$APP_DIR/venv"
PG_USER="vuln_admin"
PG_PASS="VuIntelPg2026!"
PG_DB="vuln_intel"
VAULT_VERSION="1.15.6"
VAULT_TOKEN="vuln-intel-root"

echo ""
echo "══════════════════════════════════════════════════"
echo "  vuln_intel  ·  Infrastructure Setup"
echo "══════════════════════════════════════════════════"

# ─── 1. PostgreSQL ───────────────────────────────────────────────
echo ""
echo "[1/5] Installing PostgreSQL ..."
sudo apt-get install -y postgresql postgresql-contrib

echo "[1/5] Starting PostgreSQL service ..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

echo "[1/5] Creating DB user and database ..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE USER $PG_USER WITH PASSWORD '$PG_PASS';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE DATABASE $PG_DB OWNER $PG_USER;"

echo "[1/5] Running schema migrations ..."
sudo -u postgres psql -d "$PG_DB" -f "$APP_DIR/cyber_range/services/db_init.sql"
echo "      ✅ PostgreSQL ready — postgresql://$PG_USER@localhost:5432/$PG_DB"

# ─── 2. Python packages ─────────────────────────────────────────
echo ""
echo "[2/5] Installing Python packages (psycopg2-binary, hvac, python-dotenv) ..."
source "$VENV/bin/activate"
pip install --quiet psycopg2-binary hvac python-dotenv
echo "      ✅ Python packages installed"

# ─── 3. HashiCorp Vault binary ──────────────────────────────────
echo ""
echo "[3/5] Installing HashiCorp Vault $VAULT_VERSION ..."
if ! command -v vault &>/dev/null; then
  curl -fsSL -o /tmp/vault.zip \
    "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip"
  sudo unzip -qo /tmp/vault.zip -d /usr/local/bin/
  sudo chmod +x /usr/local/bin/vault
  rm /tmp/vault.zip
fi
vault version
echo "      ✅ Vault binary ready"

# ─── 4. Vault dev server ────────────────────────────────────────
echo ""
echo "[4/5] Starting Vault dev server (background) ..."
pkill -f "vault server -dev" 2>/dev/null || true
sleep 1
nohup vault server -dev \
  -dev-root-token-id="$VAULT_TOKEN" \
  -dev-listen-address="127.0.0.1:8200" \
  > /tmp/vault_dev.log 2>&1 &

sleep 3
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="$VAULT_TOKEN"

vault status | grep -E "Initialized|Sealed|Version"
echo "      ✅ Vault running at http://127.0.0.1:8200 (log: /tmp/vault_dev.log)"

# ─── 5. Store secrets in Vault ──────────────────────────────────
echo ""
echo "[5/5] Storing secrets in Vault ..."

# Read OpenAI key from existing .env if present
OPENAI_KEY=$(grep -E "^OPENAI_API_KEY" "$APP_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" || echo "")

vault kv put secret/vuln_intel \
  openai_api_key="$OPENAI_KEY" \
  neo4j_uri="bolt://localhost:7687" \
  neo4j_user="neo4j" \
  neo4j_pass="Adomaa12@" \
  postgres_dsn="postgresql://$PG_USER:$PG_PASS@localhost:5432/$PG_DB"

echo "      ✅ Secrets stored in Vault path: secret/vuln_intel"

# ─── 6. Write env vars to .env ──────────────────────────────────
echo ""
echo "Writing runtime env vars to $APP_DIR/.env ..."
grep -q "VAULT_ADDR"  "$APP_DIR/.env" 2>/dev/null || echo "VAULT_ADDR=http://127.0.0.1:8200"  >> "$APP_DIR/.env"
grep -q "VAULT_TOKEN" "$APP_DIR/.env" 2>/dev/null || echo "VAULT_TOKEN=$VAULT_TOKEN"           >> "$APP_DIR/.env"
grep -q "POSTGRES_DSN" "$APP_DIR/.env" 2>/dev/null || echo "POSTGRES_DSN=postgresql://$PG_USER:$PG_PASS@localhost:5432/$PG_DB" >> "$APP_DIR/.env"

echo ""
echo "══════════════════════════════════════════════════"
echo "  ✅  Setup complete!"
echo ""
echo "  PostgreSQL : localhost:5432/$PG_DB"
echo "  Vault      : http://127.0.0.1:8200"
echo "  Token      : $VAULT_TOKEN  (dev mode — rotate for production)"
echo ""
echo "  Next: restart the app"
echo "    cd $APP_DIR && python app.py"
echo "══════════════════════════════════════════════════"
