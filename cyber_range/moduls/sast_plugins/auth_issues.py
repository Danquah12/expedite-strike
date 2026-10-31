"""
auth_issues.py — Authentication & JWT vulnerability plugin (CWE-287, CWE-345, CWE-798)
"""
import re
from .base_plugin import BasePlugin


class AuthIssuesPlugin(BasePlugin):
    name        = "Auth & JWT Vulnerability Detector"
    description = "Detects JWT misconfigurations, weak auth patterns, and session issues"
    engine_tag  = "Plugin-Auth"

    RULES = [
        (
            r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[\s*["\']none["\']',
            "PI-AUTH-001", "JWT None Algorithm",
            "CRITICAL", "CWE-345",
            "JWT decoded with 'none' algorithm — allows unsigned tokens and complete auth bypass. "
            "Always specify accepted algorithms explicitly (e.g., ['HS256']).",
            "jwt.decode(token, SECRET, algorithms=['HS256'])",
        ),
        (
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
            "PI-AUTH-002", "JWT Signature Verification Disabled",
            "CRITICAL", "CWE-345",
            "jwt.decode() called with verify=False skips signature verification — "
            "any token will be accepted.",
            "jwt.decode(token, SECRET, algorithms=['HS256'])",
        ),
        (
            r'(?:session|token|secret)\s*=\s*["\'][a-zA-Z0-9+/=]{4,}["\']',
            "PI-AUTH-003", "Hardcoded Session Secret / Token",
            "CRITICAL", "CWE-798",
            "Session secret or auth token hardcoded in source. "
            "Use environment variables or a secrets manager.",
            "SECRET = os.environ['SESSION_SECRET']",
        ),
        (
            r'password\s*==\s*["\']|["\']\s*==\s*password',
            "PI-AUTH-004", "Plaintext Password Comparison",
            "HIGH", "CWE-256",
            "Password compared as a plain string — must be hashed with bcrypt/argon2, "
            "then compared with a constant-time function.",
            "bcrypt.checkpw(password.encode(), stored_hash)",
        ),
        (
            r'is_authenticated\s*=\s*True|authenticated\s*=\s*True|admin\s*=\s*True',
            "PI-AUTH-005", "Hardcoded Authentication Flag",
            "HIGH", "CWE-287",
            "Authentication state set to True unconditionally — review whether this "
            "bypasses real auth checks.",
            "",
        ),
        (
            r'HS256.*secret.*["\']secret["\']|["\']mysecret["\']|["\']changeme["\']|["\']password["\']',
            "PI-AUTH-006", "Weak JWT Secret Key",
            "CRITICAL", "CWE-798",
            "JWT secret is a trivially guessable string. Use a randomly-generated "
            "256-bit secret stored in an environment variable.",
            "SECRET = os.environ['JWT_SECRET']  # min 32 random bytes",
        ),
        (
            r'session\.permanent\s*=\s*True|SESSION_COOKIE_HTTPONLY\s*=\s*False|'
            r'SESSION_COOKIE_SECURE\s*=\s*False',
            "PI-AUTH-007", "Insecure Session Cookie Configuration",
            "MEDIUM", "CWE-614",
            "Session cookie is missing Secure or HttpOnly flag, or is permanent. "
            "Set SESSION_COOKIE_SECURE=True and SESSION_COOKIE_HTTPONLY=True.",
            "app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True)",
        ),
    ]

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []
        lines = content.splitlines()
        for rule in self.RULES:
            pat, rid, rname, sev, cwe, msg, fix = rule
            compiled = re.compile(pat, re.IGNORECASE | re.MULTILINE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(self.make_finding(
                        rule_id=rid, rule=rname, severity=sev, cwe=cwe,
                        message=msg, line=i, code=line, fix=fix,
                        engine=self.engine_tag,
                    ))
        return findings
