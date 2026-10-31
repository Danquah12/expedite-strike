#!/usr/bin/env bash
# Run after every reboot: sudo bash /opt/vuln_intel/app/vault_unseal.sh
export VAULT_ADDR="http://127.0.0.1:8200"
KEYS_FILE="/opt/vuln_intel/app/vault_keys.json"
K1=$(jq -r '.unseal_keys_b64[0]' "$KEYS_FILE")
K2=$(jq -r '.unseal_keys_b64[1]' "$KEYS_FILE")
vault operator unseal "$K1"
vault operator unseal "$K2"
echo "✅ Vault unsealed"
