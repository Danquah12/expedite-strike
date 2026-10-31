"""
command_injection.py — Command Injection / OS Command Execution plugin (CWE-78)
"""
import re
from .base_plugin import BasePlugin


class CommandInjectionPlugin(BasePlugin):
    name        = "Command Injection Detector"
    description = "Detects shell/OS command execution patterns that may be vulnerable to injection"
    engine_tag  = "Plugin-CmdInj"

    RULES = [
        (
            r'\bos\.system\s*\(',
            "PI-CMD-001", "os.system Usage",
            "HIGH", "CWE-78",
            "os.system() passes a string to the shell — susceptible to command injection if "
            "any part is user-controlled. Use subprocess with a list and shell=False.",
            "subprocess.run(['cmd', arg], shell=False, check=True)",
        ),
        (
            r'\bsubprocess\.Popen\s*\(',
            "PI-CMD-002", "subprocess.Popen",
            "HIGH", "CWE-78",
            "subprocess.Popen detected. Ensure shell=False and pass arguments as a list, "
            "not a formatted string.",
            "subprocess.Popen(['cmd', user_arg], shell=False)",
        ),
        (
            r'\bsubprocess\.call\s*\(',
            "PI-CMD-003", "subprocess.call",
            "HIGH", "CWE-78",
            "subprocess.call with shell=True or a string argument is vulnerable. "
            "Pass a list and set shell=False.",
            "subprocess.call(['cmd', arg], shell=False)",
        ),
        (
            r'\bsubprocess\.run\s*\([^)]*shell\s*=\s*True',
            "PI-CMD-004", "subprocess.run with shell=True",
            "CRITICAL", "CWE-78",
            "subprocess.run(..., shell=True) with user-controlled data enables command injection. "
            "Remove shell=True and pass arguments as a list.",
            "subprocess.run(['cmd', user_arg], shell=False)",
        ),
        (
            r'\bos\.popen\s*\(',
            "PI-CMD-005", "os.popen Usage",
            "HIGH", "CWE-78",
            "os.popen() is deprecated and invokes the shell. Replace with subprocess.",
            "result = subprocess.run(['cmd'], capture_output=True, text=True)",
        ),
        (
            r'\bexec\s*\(|__import__\s*\(',
            "PI-CMD-006", "exec / __import__ Abuse",
            "CRITICAL", "CWE-95",
            "exec() or __import__() with user-controlled input enables arbitrary code execution.",
            "",
        ),
        (
            r'shell_exec\s*\(|passthru\s*\(|system\s*\(\s*\$',
            "PI-CMD-007", "PHP Shell Execution",
            "CRITICAL", "CWE-78",
            "PHP shell execution function with potential user input. "
            "Avoid shell_exec/passthru/system or strictly whitelist inputs.",
            "",
        ),
        (
            r'child_process\.exec\s*\(|execSync\s*\(',
            "PI-CMD-008", "Node.js child_process.exec",
            "HIGH", "CWE-78",
            "Node's child_process.exec runs a shell and is vulnerable to injection. "
            "Use execFile or spawn with an argument array.",
            "const { execFile } = require('child_process');\nexecFile('cmd', [userArg]);",
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
