"""
sql_injection.py — SQL Injection plugin for the SAST scanner
Detects string-concatenated SQL queries (classic SQLi pattern).
"""
import re
from .base_plugin import BasePlugin


class SQLInjectionPlugin(BasePlugin):
    name        = "SQL Injection Detector"
    description = "Detects string-concatenated SQL queries susceptible to injection"
    engine_tag  = "Plugin-SQLi"

    # (pattern, rule_id, rule_name, severity, cwe, message, fix_hint)
    RULES = [
        (
            r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s.*["\']?\s*\+',
            "PI-SQL-001", "SQL String Concatenation",
            "CRITICAL", "CWE-89",
            "SQL query built via string concatenation — vulnerable to SQL injection. "
            "Use parameterised queries / prepared statements.",
            "cursor.execute('SELECT ... WHERE id = ?', (user_input,))",
        ),
        (
            r'\.execute\s*\(\s*["\'].*%.*["\']',
            "PI-SQL-002", "SQL %-Format Injection",
            "CRITICAL", "CWE-89",
            "SQL query uses %-formatting with user data — use parameterised queries instead.",
            "cursor.execute('SELECT ... WHERE id = %s', (user_input,))",
        ),
        (
            r'query\s*=\s*["\'].*["\'\s]*\+\s*\w',
            "PI-SQL-003", "SQL Variable Concatenation",
            "HIGH", "CWE-89",
            "SQL query string is assembled by concatenating variables. Use an ORM or bind parameters.",
            "",
        ),
        (
            r'(?:query|sql)\s*\+=',
            "PI-SQL-004", "SQL Append Concatenation",
            "HIGH", "CWE-89",
            "SQL query is built with += — fragments may include unsanitised user input.",
            "",
        ),
        (
            r'(?:LIKE|IN)\s*\(\s*["\']?\s*\+|LIKE\s*["\']%',
            "PI-SQL-005", "SQL LIKE Pattern Injection",
            "MEDIUM", "CWE-89",
            "SQL LIKE clause may include user-controlled data — escape wildcards % and _.",
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
