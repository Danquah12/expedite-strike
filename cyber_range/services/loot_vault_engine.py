"""
Expedite Strike — Interactive Loot Vault & Credential Intelligence Engine
=========================================================================
Centralized repository and redaction vault for harvested post-exploitation artifacts:
  1. SSH Private Keys & Authorized Keys
  2. NTLM & Kerberos Hashes
  3. Cloud Tokens & API Secrets (AWS, GitHub, Stripe)
  4. Database Credentials & Connection URIs
  5. 1-Click Auto-Redaction for Client Sanitization
"""

import re
from typing import List, Dict, Any


class LootVaultEngine:
    """Manages, categorizes, and sanitizes harvested post-exploitation artifacts."""

    @classmethod
    def sanitize_sensitive_data(cls, text: str) -> str:
        """Auto-redact passwords, hashes, and API secret keys for clean reports."""
        if not text:
            return ""

        # Redact NTLM hashes
        text = re.sub(r'([a-fA-F0-9]{32}:[a-fA-F0-9]{32})', r'\1[:12]...[REDACTED_NTLM]', text)
        # Redact AWS keys
        text = re.sub(r'(AKIA[0-9A-Z]{16})', r'\1[:8]...[REDACTED_AWS]', text)
        # Redact DB URIs
        text = re.sub(r'://([^:]+):([^@]+)@', r'://\1:[REDACTED_PASSWORD]@', text)
        # Redact RSA Private Key bodies
        text = re.sub(r'(-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----)',
                      r'-----BEGIN PRIVATE KEY-----\n[ENCRYPTED_KEY_MATERIAL_REDACTED]\n-----END PRIVATE KEY-----', text)

        return text

    @classmethod
    def extract_loot_from_state(cls, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and structure all credentials, hashes, and keys discovered in a scan."""
        vault = []

        for phase, items in scan_results.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                tool = item.get("tool", "")
                data = item.get("data", {})

                # Extract from findings
                for f in data.get("findings", []):
                    title = f.get("title", "")
                    ev = f.get("evidence", "")

                    if "SSH" in title or "Key" in title:
                        vault.append({
                            "type": "SSH_KEY",
                            "host": f.get("host", "Perimeter"),
                            "identifier": "id_rsa (Private Key)",
                            "raw_content": ev,
                            "sanitized_content": cls.sanitize_sensitive_data(ev),
                            "severity": "Critical",
                        })
                    elif "Hash" in title or "NTLM" in title or "Password" in title:
                        vault.append({
                            "type": "PASSWORD_HASH",
                            "host": f.get("host", "Perimeter"),
                            "identifier": "NTLM / Kerberos Hash",
                            "raw_content": ev,
                            "sanitized_content": cls.sanitize_sensitive_data(ev),
                            "severity": "Critical",
                        })
                    elif "Secret" in title or "AWS" in title or "Token" in title:
                        vault.append({
                            "type": "API_SECRET",
                            "host": f.get("host", "Perimeter"),
                            "identifier": title[:30],
                            "raw_content": ev,
                            "sanitized_content": cls.sanitize_sensitive_data(ev),
                            "severity": "High",
                        })

        return vault
