"""
deserialization.py — Insecure Deserialization plugin (CWE-502)
"""
import re
from .base_plugin import BasePlugin


class DeserializationPlugin(BasePlugin):
    name        = "Insecure Deserialization Detector"
    description = "Flags use of unsafe deserialization functions that can lead to RCE"
    engine_tag  = "Plugin-Deser"

    RULES = [
        (
            r'\bpickle\.loads?\s*\(',
            "PI-DES-001", "Pickle Deserialization",
            "CRITICAL", "CWE-502",
            "pickle.load/loads can execute arbitrary code when given attacker-controlled data. "
            "Use JSON or a safe schema validator instead.",
            "import json\ndata = json.loads(user_input)",
        ),
        (
            r'\byaml\.load\s*\(',
            "PI-DES-002", "Unsafe yaml.load",
            "CRITICAL", "CWE-502",
            "yaml.load() with arbitrary input can execute Python code via !!python/object. "
            "Use yaml.safe_load() instead.",
            "yaml.safe_load(stream)",
        ),
        (
            r'\beval\s*\(\s*(?:compile|__import__|request|req|params)',
            "PI-DES-003", "eval of Request Data",
            "CRITICAL", "CWE-502",
            "eval() on request-derived data enables arbitrary code execution.",
            "",
        ),
        (
            r'marshal\.loads?\s*\(',
            "PI-DES-004", "Marshal Deserialization",
            "CRITICAL", "CWE-502",
            "marshal is not safe for untrusted data — can trigger arbitrary code execution "
            "on specially crafted byte strings.",
            "",
        ),
        (
            r'ObjectInputStream|readObject\s*\(\s*\)',
            "PI-DES-005", "Java ObjectInputStream",
            "CRITICAL", "CWE-502",
            "Java ObjectInputStream.readObject() deserialises arbitrary class graphs. "
            "Use a serialisation allowlist or switch to JSON.",
            "",
        ),
        (
            r'JSON\.parse\s*\(.*eval|eval\s*\(.*JSON\.parse',
            "PI-DES-006", "eval + JSON.parse",
            "HIGH", "CWE-502",
            "Combining eval() and JSON.parse is dangerous — use JSON.parse alone.",
            "const obj = JSON.parse(userInput);",
        ),
        (
            r'unserialize\s*\(',
            "PI-DES-007", "PHP unserialize",
            "CRITICAL", "CWE-502",
            "PHP unserialize() on user input enables object injection / RCE. "
            "Use json_decode() instead.",
            "$data = json_decode($userInput, true);",
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
