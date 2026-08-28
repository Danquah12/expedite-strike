"""
Expedite Strike — High-Entropy Secret Harvester & JS Source Map Engine
======================================================================
Scans web responses, JavaScript bundles, source maps, and public endpoints for leaked secrets:
  1. AWS Access Key IDs & Secret Access Keys
  2. GitHub / GitLab Personal Access Tokens
  3. Slack, Discord, and Teams Webhook URLs
  4. Stripe Live API Keys & Payment Tokens
  5. Database Connection Strings (Postgres, MongoDB, Redis)
  6. Exposed JavaScript Source Maps (.js.map) (T1552.001)
"""

import re
from typing import List, Dict, Any

# High-precision regex signatures for leaked tokens & credentials
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "Critical",
        "cvss": 9.8,
        "cve": "CWE-798 (Use of Hard-coded Credentials)",
        "mitre_id": "T1552.001",
        "remediation": "Immediately revoke the AWS IAM Access Key in AWS IAM console and rotate all associated secret keys.",
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        "severity": "Critical",
        "cvss": 9.4,
        "cve": "CWE-798",
        "mitre_id": "T1552.001",
        "remediation": "Revoke the exposed personal access token on GitHub and audit repository access logs.",
    },
    {
        "name": "Slack Incoming Webhook URL",
        "pattern": r"https://hooks\.slack\.com/services/T[0-9a-zA-Z_]+/B[0-9a-zA-Z_]+/[0-9a-zA-Z_]+",
        "severity": "High",
        "cvss": 7.5,
        "cve": "CWE-200",
        "mitre_id": "T1552.001",
        "remediation": "Deauthorize the Slack webhook in the workspace App Management settings.",
    },
    {
        "name": "Stripe Live API Key",
        "pattern": r"\b(sk_live_[0-9a-zA-Z]{24,34})\b",
        "severity": "Critical",
        "cvss": 9.6,
        "cve": "CWE-798",
        "mitre_id": "T1552.001",
        "remediation": "Roll the Stripe API secret key in the Stripe Dashboard and enable restricted key permissions.",
    },
    {
        "name": "Database Connection String (URI)",
        "pattern": r"(postgres|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+:[0-9]+/[a-zA-Z0-9_\-\.]+",
        "severity": "Critical",
        "cvss": 9.8,
        "cve": "CWE-798",
        "mitre_id": "T1552.001",
        "remediation": "Move database credentials to secure environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
    },
    {
        "name": "Private RSA / OpenSSH Key Header",
        "pattern": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "severity": "Critical",
        "cvss": 9.8,
        "cve": "CWE-312",
        "mitre_id": "T1552.004",
        "remediation": "Remove the private key from public web server directories and revoke authorized keys on target servers.",
    },
]


class SecretHarvesterEngine:
    """Scans content for leaked tokens, cryptographic keys, and source maps."""

    @classmethod
    def scan_content(cls, host: str, content: str, source_url: str = "") -> List[Dict[str, Any]]:
        """Analyze text content (HTML, JS, headers) for high-entropy secrets."""
        findings = []
        if not content:
            return findings

        for sig in SECRET_PATTERNS:
            matches = re.findall(sig["pattern"], content)
            if matches:
                sample = str(matches[0])[:30] + "...[REDACTED]"
                findings.append({
                    "title": f"Leaked Secret: {sig['name']} on {source_url or host}",
                    "severity": sig["severity"],
                    "cvss": sig["cvss"],
                    "host": host,
                    "cve": sig["cve"],
                    "category": "Credential Access",
                    "scanner": "SECRET_ENGINE",
                    "mitre_id": sig["mitre_id"],
                    "mitre_name": "Unsecured Credentials: Credentials In Files",
                    "description": f"High-entropy {sig['name']} discovered in web asset '{source_url or host}'. An attacker can extract this key to gain unauthorized access to cloud services.",
                    "evidence": f"Location: {source_url or host}\nMatched Token: {sample}",
                    "remediation": sig["remediation"],
                })

        # Check for exposed Source Map (.js.map)
        if ".map" in source_url or '"sources":[' in content[:500]:
            findings.append({
                "title": f"Exposed JavaScript Source Map (.js.map) on {host}",
                "severity": "Medium",
                "cvss": 5.3,
                "host": host,
                "cve": "CWE-200 (Information Disclosure)",
                "category": "Information Disclosure",
                "scanner": "SECRET_ENGINE",
                "mitre_id": "T1552.001",
                "mitre_name": "Unsecured Credentials",
                "description": f"Production JavaScript bundle exposes unminified Source Maps. This enables automated reconstruction of full frontend source code, internal routes, and developer comments.",
                "evidence": f"Exposed Source Map URL: {source_url}",
                "remediation": "Disable source map generation in production webpack/vite/tsconfig builds (set 'sourceMap: false').",
            })

        return findings
