"""
xss.py — Cross-Site Scripting (XSS) plugin for the SAST scanner
"""
import re
from .base_plugin import BasePlugin


class XSSPlugin(BasePlugin):
    name        = "XSS Detector"
    description = "Detects unescaped output and dangerous HTML/JS injection patterns"
    engine_tag  = "Plugin-XSS"

    RULES = [
        (
            r'innerHTML\s*=\s*(?![\"\'][\"\'])',
            "PI-XSS-001", "Unsafe innerHTML Assignment",
            "HIGH", "CWE-79",
            "Assigning user-controlled data to innerHTML enables XSS. "
            "Use textContent or sanitise with DOMPurify.",
            "element.textContent = userInput;  // or DOMPurify.sanitize(userInput)",
        ),
        (
            r'document\.write\s*\(',
            "PI-XSS-002", "document.write Usage",
            "HIGH", "CWE-79",
            "document.write() can enable XSS if called with user-supplied data. Avoid it.",
            "",
        ),
        (
            r'outerHTML\s*=',
            "PI-XSS-003", "Unsafe outerHTML Assignment",
            "HIGH", "CWE-79",
            "outerHTML replaces an entire element and may execute injected scripts.",
            "",
        ),
        (
            r'eval\s*\(\s*(?:location|decodeURI|atob)',
            "PI-XSS-004", "DOM-Based XSS via eval",
            "CRITICAL", "CWE-79",
            "eval() with URL/encoded input is a classic DOM-based XSS vector.",
            "",
        ),
        (
            r'(?:render|output|echo|print)\s*\(?\s*(?:request|req|params|query)\.',
            "PI-XSS-005", "Reflected Output Without Escape",
            "HIGH", "CWE-79",
            "User-supplied request data rendered directly — escape all output with the "
            "framework's template engine auto-escaping.",
            "",
        ),
        (
            r'\.html\s*\(\s*(?![\"\'])',
            "PI-XSS-006", "jQuery .html() with Variable",
            "MEDIUM", "CWE-79",
            "jQuery .html() with a variable may execute injected scripts. Use .text() for plain text.",
            "$(elem).text(userInput);",
        ),
        (
            r'setInnerHTML|dangerouslySetInnerHTML',
            "PI-XSS-007", "React dangerouslySetInnerHTML",
            "HIGH", "CWE-79",
            "dangerouslySetInnerHTML bypasses React's XSS protection. "
            "Sanitise with DOMPurify before use.",
            "__html: DOMPurify.sanitize(userHtml)",
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
