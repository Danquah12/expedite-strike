# ================================================================
# HashiCorp Vault — Production Configuration
# Location: /etc/vault.d/vault.hcl
# ================================================================

# Storage backend: file (persistent across reboots)
storage "file" {
  path = "/opt/vault/data"
}

# TCP Listener
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable   = true   # TLS handled by reverse proxy; keep true for localhost-only
}

# API address
api_addr = "http://127.0.0.1:8200"

# Cluster address (for HA — single node so not required but good practice)
cluster_addr = "http://127.0.0.1:8201"

# Disable mlock (required if running as non-root without IPC_LOCK capability)
disable_mlock = true

# UI (optional — accessible at http://127.0.0.1:8200/ui)
ui = true

# Log level
log_level = "warn"
