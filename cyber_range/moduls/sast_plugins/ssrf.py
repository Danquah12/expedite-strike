"""
ssrf.py — Server-Side Request Forgery plugin
"""
import re
from .base_plugin import BasePlugin


class SSRFPlugin(BasePlugin):
    name        = "SSRF Detector"
    description = "Detects server-side HTTP requests built with user-controlled data"
    engine_tag  = "Plugin-SSRF"

    RULES = [
        (
            r'(?:requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get|'
            r'http\.get|fetch\s*\(|axios\.get|axios\.post)\s*\(\s*(?:url|uri|endpoint|'
            r'target|host|request|req|params|query)\b',
            "PI-SSRF-001", "HTTP Request with User-Controlled URL",
            "HIGH", "CWE-918",
            "HTTP request made to a URL derived from user input — allows SSRF attacks. "
            "Validate the URL against an allowlist of permitted hosts/schemes.",
            "ALLOWED = {'example.com'}\nif urlparse(url).hostname not in ALLOWED: raise ValueError",
        ),
        (
            r'(?:requests\.get|requests\.post|urllib\.request\.urlopen)\s*\(\s*f["\']',
            "PI-SSRF-002", "HTTP Request with f-string URL",
            "HIGH", "CWE-918",
            "HTTP request URL built with an f-string — may embed user data. "
            "Validate and restrict the target host.",
            "",
        ),
        (
            r'urllib\.parse\.urljoin\s*\(',
            "PI-SSRF-003", "urljoin with Possible User Input",
            "MEDIUM", "CWE-918",
            "urljoin can produce unexpected URLs if the second argument starts with '//' or a scheme. "
            "Validate the base and path separately.",
            "",
        ),
        (
            r'socket\.connect\s*\(',
            "PI-SSRF-004", "Raw Socket Connection",
            "MEDIUM", "CWE-918",
            "socket.connect() to a user-controlled host/port may allow SSRF or port scanning. "
            "Restrict allowable hosts.",
            "",
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
