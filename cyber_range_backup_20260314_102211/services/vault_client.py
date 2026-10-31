# ================================================================
# vault_client.py  —  HashiCorp Vault secret fetcher
#
# Priority order for each secret:
#   1. Vault KV v2  (secret/data/vuln_intel)
#   2. Environment variable
#   3. .env file value
#   4. Hardcoded fallback (dev only)
#
# Usage:
#   from cyber_range.services.vault_client import secrets
#   openai_key = secrets.get("openai_api_key")
# ================================================================

import os
import logging
from pathlib import Path
from functools import lru_cache

log = logging.getLogger(__name__)

# ── Optional imports ─────────────────────────────────────────────
try:
    import hvac
    _HVAC_AVAILABLE = True
except ImportError:
    _HVAC_AVAILABLE = False
    log.warning("[Vault] hvac library not installed — falling back to env vars. "
                "Install with: pip install hvac")

try:
    from dotenv import dotenv_values
    _DOTENV_AVAILABLE = True
except ImportError:
    _DOTENV_AVAILABLE = False


# ── Configuration ────────────────────────────────────────────────
VAULT_ADDR    = os.getenv("VAULT_ADDR",  "http://127.0.0.1:8200")
VAULT_TOKEN   = os.getenv("VAULT_TOKEN", "vuln-intel-root")
VAULT_PATH    = "vuln_intel"
VAULT_MOUNT   = "secret"

# Mapping: vault_key → env_var_name → dev_fallback
_SECRET_MAP = {
    "openai_api_key":  ("OPENAI_API_KEY",   ""),
    "neo4j_uri":       ("NEO4J_URI",        "bolt://localhost:7687"),
    "neo4j_user":      ("NEO4J_USER",       "neo4j"),
    "neo4j_pass":      ("NEO4J_PASSWORD",   "Adomaa12@"),
    "postgres_dsn":    ("POSTGRES_DSN",     "postgresql://vuln_admin:VuIntelPg2026!@localhost:5432/vuln_intel"),
    "mailjet_key":     ("MAILJET_API_KEY",  ""),
    "mailjet_secret":  ("MAILJET_SECRET",   ""),
}


class VaultClient:
    """
    Thin wrapper around HashiCorp Vault KV v2.
    Transparent fallback to environment variables.
    """

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._vault_ok = False
        self._env_values: dict[str, str] = {}

        # Load .env file values
        env_file = Path(__file__).parents[2] / ".env"
        if _DOTENV_AVAILABLE and env_file.exists():
            self._env_values = dict(dotenv_values(env_file))

        # Try to connect to Vault
        if _HVAC_AVAILABLE:
            try:
                self._client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
                if self._client.is_authenticated():
                    self._vault_ok = True
                    log.info("[Vault] ✅ Connected to %s", VAULT_ADDR)
                    self._load_all()
                else:
                    log.warning("[Vault] ⚠ Token invalid — using env/fallback")
            except Exception as e:
                log.warning("[Vault] ⚠ Could not connect (%s) — using env/fallback", e)
        else:
            log.info("[Vault] Using environment variables only (hvac not installed)")

    def _load_all(self):
        """Bulk-load all secrets from Vault into local cache."""
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=VAULT_PATH, mount_point=VAULT_MOUNT
            )
            data = resp["data"]["data"]
            self._cache.update(data)
            log.info("[Vault] Loaded %d secrets from %s/%s",
                     len(data), VAULT_MOUNT, VAULT_PATH)
        except Exception as e:
            log.warning("[Vault] Failed to read secrets: %s", e)

    def get(self, key: str, default: str = "") -> str:
        """
        Resolve a secret value.
        Order: Vault cache → env var → .env file → _SECRET_MAP fallback → default
        """
        # 1. Vault cache
        if key in self._cache:
            return self._cache[key]

        # 2. Env var
        env_name, dev_fallback = _SECRET_MAP.get(key, (key.upper(), ""))
        env_val = os.getenv(env_name)
        if env_val:
            return env_val

        # 3. .env file
        dot_val = self._env_values.get(env_name)
        if dot_val:
            return dot_val

        # 4. Dev fallback
        if dev_fallback:
            return dev_fallback

        return default

    def get_all(self) -> dict:
        """Return a safe dict of all known secret keys (values masked)."""
        return {k: ("*" * 8 if self.get(k) else "<not set>")
                for k in _SECRET_MAP}

    def put(self, key: str, value: str) -> bool:
        """Write/update a secret in Vault (requires write token)."""
        if not self._vault_ok:
            log.warning("[Vault] Cannot write — Vault unavailable")
            return False
        try:
            existing = {}
            try:
                resp = self._client.secrets.kv.v2.read_secret_version(
                    path=VAULT_PATH, mount_point=VAULT_MOUNT
                )
                existing = resp["data"]["data"]
            except Exception:
                pass
            existing[key] = value
            self._client.secrets.kv.v2.create_or_update_secret(
                path=VAULT_PATH, secret=existing, mount_point=VAULT_MOUNT
            )
            self._cache[key] = value
            log.info("[Vault] Wrote secret: %s", key)
            return True
        except Exception as e:
            log.error("[Vault] Write failed: %s", e)
            return False

    @property
    def connected(self) -> bool:
        return self._vault_ok


# ── Module-level singleton ────────────────────────────────────────
secrets = VaultClient()


# ── Convenience getters ───────────────────────────────────────────
def get_neo4j_creds() -> tuple[str, str, str]:
    return (
        secrets.get("neo4j_uri"),
        secrets.get("neo4j_user"),
        secrets.get("neo4j_pass"),
    )

def get_openai_key() -> str:
    return secrets.get("openai_api_key")

def get_postgres_dsn() -> str:
    return secrets.get("postgres_dsn")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Vault status:", "✅ Connected" if secrets.connected else "⚠ Fallback mode")
    print("Secret map (masked):")
    for k, v in secrets.get_all().items():
        print(f"  {k:<20} = {v}")
    print("\nNeo4j URI:", get_neo4j_creds()[0])
    print("Postgres DSN:", get_postgres_dsn()[:40] + "...")
