"""
dependency_plugin.py — Known Vulnerable Dependency Scanner
Checks requirements.txt / package.json / pom.xml content for pinned vulnerable packages.
"""
import re
from .base_plugin import BasePlugin


class DependencyPlugin(BasePlugin):
    name        = "Vulnerable Dependency Scanner"
    description = "Detects references to known vulnerable packages and versions"
    engine_tag  = "Plugin-Deps"

    # (package_pattern, cve_or_advisory, rule_id, severity, message)
    KNOWN_VULNS = [
        # Python
        ("log4j",               "CVE-2021-44228", "PI-DEP-001", "CRITICAL",
         "Log4Shell — log4j RCE via JNDI lookup. Upgrade to log4j 2.17.1+."),
        ("django==1\\.2",       "Multiple CVEs",  "PI-DEP-002", "CRITICAL",
         "Django 1.2 is end-of-life with multiple unpatched vulnerabilities."),
        ("django==1\\.11",      "CVE-2021-35042", "PI-DEP-003", "HIGH",
         "Django 1.11 (EOL) — ReDoS and QuerySet injection vulnerabilities."),
        ("flask==0\\.",         "Multiple CVEs",  "PI-DEP-004", "HIGH",
         "Flask 0.x is EOL. Upgrade to Flask 2.x or later."),
        ("pyyaml[<==]*[0-4]\\.",  "CVE-2017-18342","PI-DEP-005","CRITICAL",
         "PyYAML < 5.1 — arbitrary code execution via yaml.load()."),
        ("requests[<==]*2\\.1[0-8]", "CVE-2018-18074","PI-DEP-006","MEDIUM",
         "Requests < 2.20 — Authorization header leak on redirect."),
        ("pillow[<==]*[0-8]\\.", "CVE-2021-27921","PI-DEP-007","HIGH",
         "Pillow < 9.0 — multiple buffer overflow and RCE vulnerabilities."),
        ("cryptography[<==]*[0-2]\\.", "CVE-2023-23931","PI-DEP-008","HIGH",
         "cryptography < 39 — Bleichenbacher vulnerability in RSA decryption."),
        # JavaScript / Node
        ("lodash[\"']?\\s*:\\s*[\"']?[0-3]\\.", "CVE-2019-10744","PI-DEP-009","HIGH",
         "lodash < 4.17.13 — prototype pollution vulnerability."),
        ("express[\"']?\\s*:\\s*[\"']?[0-3]\\.", "Multiple CVEs", "PI-DEP-010","HIGH",
         "Express < 4 is EOL with known security issues."),
        ("jquery[\"']?\\s*:\\s*[\"']?[0-2]\\.", "CVE-2019-11358","PI-DEP-011","HIGH",
         "jQuery < 3.4.0 — prototype pollution."),
        # Java / Maven
        ("struts2?.*2\\.3\\.","CVE-2017-5638", "PI-DEP-012","CRITICAL",
         "Apache Struts 2.3.x — RCE via malicious Content-Type header (Equifax breach)."),
        ("jackson-databind.*2\\.9\\.[0-9][^.]","CVE-2019-14379","PI-DEP-013","CRITICAL",
         "jackson-databind 2.9.x — multiple deserialization RCE gadgets."),
    ]

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []
        lines = content.splitlines()
        for pattern, cve, rid, sev, msg in self.KNOWN_VULNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(self.make_finding(
                        rule_id=rid,
                        rule=f"Vulnerable Dependency ({cve})",
                        severity=sev,
                        cwe="CWE-1035",
                        message=f"{msg} (Ref: {cve})",
                        line=i,
                        code=line,
                        fix=f"Check https://osv.dev for patched versions. Ref: {cve}",
                        engine=self.engine_tag,
                    ))
        return findings
