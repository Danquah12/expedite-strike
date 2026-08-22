"""
path_traversal.py — Path Traversal / Directory Traversal plugin
"""
import re
from .base_plugin import BasePlugin


class PathTraversalPlugin(BasePlugin):
    name        = "Path Traversal Detector"
    description = "Detects file path operations that use user-controlled input unsafely"
    engine_tag  = "Plugin-PathTrav"

    RULES = [
        (
            r'open\s*\(\s*(?:request|req|params|query|user_input|user_data)',
            "PI-PT-001", "Unsafe File Open with User Input",
            "HIGH", "CWE-22",
            "File opened with user-controlled path — may allow directory traversal. "
            "Validate and canonicalise paths with os.path.realpath().",
            "safe = os.path.realpath(os.path.join(BASE_DIR, user_input))\n"
            "assert safe.startswith(BASE_DIR)",
        ),
        (
            r'\.\./|\.\.\\\\',
            "PI-PT-002", "Literal Path Traversal Sequence",
            "CRITICAL", "CWE-22",
            "Literal '../' or '..\\' sequence detected — possible path traversal in string literal.",
            "",
        ),
        (
            r'os\.path\.join\s*\(.*(?:request|req|params|query)',
            "PI-PT-003", "os.path.join with Request Data",
            "HIGH", "CWE-22",
            "os.path.join called with request-derived data. Resolve and validate the path "
            "against an allowed base directory before use.",
            "",
        ),
        (
            r'send_file\s*\(|send_from_directory\s*\(',
            "PI-PT-004", "Flask send_file / send_from_directory",
            "MEDIUM", "CWE-22",
            "Ensure the filename argument is validated and not user-controlled. "
            "Prefer send_from_directory with a fixed directory.",
            "send_from_directory(UPLOAD_FOLDER, secure_filename(user_input))",
        ),
        (
            r'readFile|fs\.read|readFileSync',
            "PI-PT-005", "Node.js fs Read with Potential User Path",
            "HIGH", "CWE-22",
            "fs.readFile/readFileSync may be called with user-controlled paths. "
            "Canonicalise with path.resolve() and validate against a whitelist.",
            "const safe = path.resolve(BASE, filename);\n"
            "if (!safe.startsWith(BASE)) throw new Error('Invalid path');",
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
