"""
secrets_plugin.py — Hardcoded Secrets / Credential Detection
Covers: AWS keys, private keys, generic passwords, API keys, tokens, and more.
"""
import re
from .base_plugin import BasePlugin


class SecretsPlugin(BasePlugin):
    name        = "Secrets Detector"
    description = "Detects hardcoded secrets, credentials, and private key material"
    engine_tag  = "Plugin-Secrets"

    # (pattern, rule_id, rule_name, severity, cwe, message, fix)
    RULES = [
        (
            r"AKIA[0-9A-Z]{16}",
            "PI-SEC-001", "AWS Access Key ID",
            "CRITICAL", "CWE-798",
            "Hardcoded AWS Access Key ID detected. Rotate the key immediately and store "
            "credentials in IAM roles or environment variables.",
            "os.environ['AWS_ACCESS_KEY_ID']",
        ),
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "PI-SEC-002", "Private Key Embedded in Source",
            "CRITICAL", "CWE-321",
            "Private key material found in source code. Remove it immediately, "
            "rotate the key pair, and load keys from secure storage at runtime.",
            "",
        ),
        (
            r'(?i)password\s*=\s*[\'"][^\'"]{4,}[\'"]',
            "PI-SEC-003", "Hardcoded Password",
            "CRITICAL", "CWE-798",
            "Password hardcoded in source. Move to environment variable or secrets vault.",
            "PASSWORD = os.environ['APP_PASSWORD']",
        ),
        (
            r'(?i)api[_-]?key\s*=\s*[\'"][^\'"]{8,}[\'"]',
            "PI-SEC-004", "Hardcoded API Key",
            "CRITICAL", "CWE-798",
            "API key hardcoded in source. Use environment variables or a secrets manager.",
            "API_KEY = os.environ['API_KEY']",
        ),
        (
            r'(?i)(?:auth|access|bearer)[_-]?token\s*=\s*[\'"][^\'"]{8,}[\'"]',
            "PI-SEC-005", "Hardcoded Auth Token",
            "CRITICAL", "CWE-798",
            "Authentication token hardcoded. Rotate and store securely.",
            "",
        ),
        (
            r'(?i)secret[_-]?key\s*=\s*[\'"][^\'"]{4,}[\'"]',
            "PI-SEC-006", "Hardcoded Secret Key",
            "CRITICAL", "CWE-798",
            "Secret key literal in source code — use environment variables.",
            "SECRET_KEY = os.environ['SECRET_KEY']",
        ),
        (
            r'(?i)(?:db|database)[_-]?pass(?:word)?\s*=\s*[\'"][^\'"]{4,}[\'"]',
            "PI-SEC-007", "Hardcoded Database Password",
            "CRITICAL", "CWE-798",
            "Database password hardcoded. Load from environment variable or vault.",
            "DB_PASS = os.environ['DB_PASSWORD']",
        ),
        (
            r'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}',
            "PI-SEC-008", "GitHub Personal Access Token",
            "CRITICAL", "CWE-798",
            "GitHub PAT detected in source. Revoke it immediately via GitHub settings.",
            "",
        ),
        (
            r'sk-[a-zA-Z0-9]{32,}',
            "PI-SEC-009", "OpenAI / Stripe Secret Key",
            "CRITICAL", "CWE-798",
            "API secret key with 'sk-' prefix detected (OpenAI, Stripe, etc.). "
            "Revoke and rotate immediately.",
            "",
        ),
    ]

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []
        lines = content.splitlines()
        for rule in self.RULES:
            pat, rid, rname, sev, cwe, msg, fix = rule
            compiled = re.compile(pat, re.MULTILINE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(self.make_finding(
                        rule_id=rid, rule=rname, severity=sev, cwe=cwe,
                        message=msg, line=i, code=line, fix=fix,
                        engine=self.engine_tag,
                    ))
        return findings
