#!/usr/bin/env bash
# ================================================================
# install_vault_service.sh
# Migrates from dev-mode Vault → persistent systemd service
#
# Run: sudo bash install_vault_service.sh
# ================================================================

set -e

APP_DIR="/opt/vuln_intel/app"
VAULT_DATA="/opt/vault/data"
VAULT_CONFIG="/etc/vault.d"
VAULT_KEYS="$APP_DIR/vault_keys.json"   # ← KEEP THIS FILE SAFE

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Vault  ·  Production Systemd Service Setup"
echo "══════════════════════════════════════════════════════"

# ─── Stop dev-mode Vault ────────────────────────────────────────
echo "[1/7] Stopping any running dev-mode Vault ..."
pkill -f "vault server -dev" 2>/dev/null && echo "      Stopped dev-mode Vault." || echo "      No dev-mode Vault running."
sleep 1

# ─── Create vault system user ───────────────────────────────────
echo "[2/7] Creating vault system user ..."
id vault &>/dev/null || sudo useradd --system --home /etc/vault.d --shell /bin/false vault
echo "      Done."

# ─── Create directories ─────────────────────────────────────────
echo "[3/7] Creating directories ..."
sudo mkdir -p "$VAULT_DATA" "$VAULT_CONFIG"
sudo chown -R vault:vault "$VAULT_DATA" "$VAULT_CONFIG"
sudo chmod 750 "$VAULT_DATA"
echo "      $VAULT_DATA"
echo "      $VAULT_CONFIG"

# ─── Install config file ────────────────────────────────────────
echo "[4/7] Installing Vault config ..."
sudo cp "$APP_DIR/vault.hcl" "$VAULT_CONFIG/vault.hcl"
sudo chown vault:vault "$VAULT_CONFIG/vault.hcl"
sudo chmod 640 "$VAULT_CONFIG/vault.hcl"
echo "      Installed to $VAULT_CONFIG/vault.hcl"

# ─── Install systemd unit ───────────────────────────────────────
echo "[5/7] Installing systemd service ..."
sudo cp "$APP_DIR/vault.service" /etc/systemd/system/vault.service
sudo systemctl daemon-reload
sudo systemctl enable vault
echo "      vault.service enabled"

# ─── Start Vault ────────────────────────────────────────────────
echo "[6/7] Starting Vault ..."
sudo systemctl start vault
sleep 3
sudo systemctl status vault --no-pager | head -6

export VAULT_ADDR="http://127.0.0.1:8200"

# ─── Initialise (only first time!) ──────────────────────────────
echo ""
echo "[7/7] Initialising Vault (first-time only) ..."
if vault status 2>&1 | grep -q "Initialized.*false"; then
    echo "      Running vault operator init ..."
    vault operator init -key-shares=3 -key-threshold=2 -format=json > "$VAULT_KEYS"
    chmod 600 "$VAULT_KEYS"
    echo "      ✅ Unseal keys saved to: $VAULT_KEYS"
    echo "      !! BACK THIS FILE UP SECURELY — losing it = losing all secrets !!"

    # Auto-unseal using saved keys (first 2 of 3)
    UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' "$VAULT_KEYS")
    UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' "$VAULT_KEYS")
    ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_KEYS")

    vault operator unseal "$UNSEAL_KEY_1"
    vault operator unseal "$UNSEAL_KEY_2"

    export VAULT_TOKEN="$ROOT_TOKEN"

    # Enable KV v2
    vault secrets enable -path=secret kv-v2 2>/dev/null || true

    # Re-populate secrets from .env
    OPENAI_KEY=$(grep -E "^OPENAI_API_KEY" "$APP_DIR/.env" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
    vault kv put secret/vuln_intel \
        openai_api_key="$OPENAI_KEY" \
        neo4j_uri="bolt://localhost:7687" \
        neo4j_user="neo4j" \
        neo4j_pass="Adomaa12@" \
        postgres_dsn="postgresql://vuln_admin:VuIntelPg2026!@localhost:5432/vuln_intel"

    # Update .env with root token
    sed -i '/^VAULT_TOKEN=/d' "$APP_DIR/.env"
    echo "VAULT_TOKEN=$ROOT_TOKEN" >> "$APP_DIR/.env"

    echo "      ✅ Vault initialised and secrets stored."
    echo "      Root token written to .env"
else
    echo "      Vault already initialised — skipping init."
    echo "      If sealed, run: bash $APP_DIR/vault_unseal.sh"
fi

# ─── Write unseal helper for reboots ────────────────────────────
cat > "$APP_DIR/vault_unseal.sh" << 'HEREDOC'
#!/usr/bin/env bash
# Run after every reboot: sudo bash /opt/vuln_intel/app/vault_unseal.sh
export VAULT_ADDR="http://127.0.0.1:8200"
KEYS_FILE="/opt/vuln_intel/app/vault_keys.json"
K1=$(jq -r '.unseal_keys_b64[0]' "$KEYS_FILE")
K2=$(jq -r '.unseal_keys_b64[1]' "$KEYS_FILE")
vault operator unseal "$K1"
vault operator unseal "$K2"
echo "✅ Vault unsealed"
HEREDOC
chmod +x "$APP_DIR/vault_unseal.sh"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  ✅  Vault systemd service active!"
echo ""
echo "  Status : sudo systemctl status vault"
echo "  Logs   : sudo journalctl -u vault -f"
echo "  Unseal : bash $APP_DIR/vault_unseal.sh  (after reboot)"
echo ""
echo "  ⚠️  vault_keys.json contains your unseal keys."
echo "      Copy it somewhere OFFLINE and secure."
echo "══════════════════════════════════════════════════════"
