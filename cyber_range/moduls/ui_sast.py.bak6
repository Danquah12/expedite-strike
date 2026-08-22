"""
ui_sast.py — Static Application Security Testing Dashboard
=============================================================
Multi-engine SAST scanner with:
  • Semgrep (auto rules for Python, JS, Go, Java, PHP, Ruby, TS)
  • Bandit  (Python-specific deep analysis)
  • Built-in regex rules (secrets, SQLi, XSS, dangerous calls)
  • AI-powered remediation per finding
  • Export to JSON / CSV
"""

import os
import re
import sys
import json
import csv
import io
import uuid
import datetime
import tempfile
import threading
import subprocess
import traceback

import dash
from dash import html, dcc, callback, dash_table
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

# ─────────────────────────────────────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────────────────────────────────────
BG_DARK   = "#1c1e26"
PANEL_BG  = "#232530"
TEXT_COL  = "#a2a5b5"
CYAN      = "#42b9f5"
RED       = "#f54254"
ORANGE    = "#f5a742"
GREEN     = "#11c26f"
PURPLE    = "#9e54d4"
YELLOW    = "#f0c040"
CARD_STYLE  = {"backgroundColor": PANEL_BG, "border": "1px solid #333", "borderRadius": "10px"}
INPUT_STYLE = {"backgroundColor": "#111", "color": "#fff", "border": "1px solid #444", "borderRadius": "6px"}
LABEL_STYLE = {"color": TEXT_COL, "fontSize": "0.78rem", "marginBottom": "2px"}

# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY CONFIG
# ─────────────────────────────────────────────────────────────────────────────
SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLOR  = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     TEXT_COL,
}
SEV_ICON   = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _sev_badge(sev):
    color = SEV_COLOR.get(sev.upper(), TEXT_COL)
    return html.Span(sev, style={
        "backgroundColor": color + "22", "color": color,
        "border": f"1px solid {color}", "borderRadius": "4px",
        "fontSize": "0.72rem", "padding": "2px 7px", "fontWeight": "bold",
    })


# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN REGEX RULES (language-agnostic, fast, no install needed)
# ─────────────────────────────────────────────────────────────────────────────
REGEX_RULES = [
    # Secrets / credentials
    {"id": "SEC-001", "name": "Hardcoded Password",
     "pattern": r'(?i)(password|passwd|pwd|secret)\s*=\s*["\'][^"\']{4,}["\']',
     "severity": "CRITICAL", "cwe": "CWE-798",
     "message": "Hardcoded credential detected. Move secrets to environment variables or a vault."},
    {"id": "SEC-002", "name": "Hardcoded API Key / Token",
     "pattern": r'(?i)(api[_-]?key|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
     "severity": "CRITICAL", "cwe": "CWE-798",
     "message": "Hardcoded API key/token. Use environment variables or secrets management."},
    {"id": "SEC-003", "name": "AWS Access Key",
     "pattern": r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
     "severity": "HIGH", "cwe": "CWE-798",
     "message": "Potential AWS Access Key ID pattern detected."},
    # Dangerous functions
    {"id": "INJ-001", "name": "eval() Usage",
     "pattern": r'\beval\s*\(',
     "severity": "HIGH", "cwe": "CWE-95",
     "message": "eval() executes arbitrary code. Avoid or validate input strictly."},
    {"id": "INJ-002", "name": "exec() Usage",
     "pattern": r'\bexec\s*\(',
     "severity": "HIGH", "cwe": "CWE-95",
     "message": "exec() executes arbitrary code. Prefer explicit function calls."},
    {"id": "INJ-003", "name": "Shell Injection Risk",
     "pattern": r'(subprocess\.call|subprocess\.run|os\.system|os\.popen|shell_exec|system\s*\()\s*\(',
     "severity": "HIGH", "cwe": "CWE-78",
     "message": "Shell command execution detected. Ensure input is not user-controlled. Use shell=False."},
    # SQL Injection
    {"id": "SQL-001", "name": "SQL String Concatenation",
     "pattern": r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*["\'].*(\+|%s|\.format)|f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
     "severity": "HIGH", "cwe": "CWE-89",
     "message": "Possible SQL injection via string concatenation or format. Use parameterized queries."},
    {"id": "SQL-002", "name": "SQL Execute with Variable",
     "pattern": r'(?i)\.(execute|executemany)\s*\(\s*(?!["\']\s*(?:SELECT|INSERT|UPDATE|DELETE))[a-zA-Z_][a-zA-Z0-9_]*',
     "severity": "HIGH", "cwe": "CWE-89",
     "message": "execute() called with a variable — SQL injection risk if variable is user-controlled."},
    # Cryptography
    {"id": "CRY-001", "name": "Weak Hash: MD5",
     "pattern": r'(?i)(hashlib\.md5|\bmd5)\s*\(',
     "severity": "MEDIUM", "cwe": "CWE-327",
     "message": "MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords."},
    {"id": "CRY-002", "name": "Weak Hash: SHA1",
     "pattern": r'(?i)(hashlib\.sha1|\bsha1)\s*\(',
     "severity": "MEDIUM", "cwe": "CWE-327",
     "message": "SHA1 is deprecated for security use. Use SHA-256 or higher."},
    {"id": "CRY-003", "name": "Insecure Random",
     "pattern": r'\brandom\.(random|randint|choice|shuffle)\s*\(',
     "severity": "MEDIUM", "cwe": "CWE-338",
     "message": "random module is not cryptographically secure. Use secrets module for security tokens."},
    # XSS / Injection
    {"id": "XSS-001", "name": "innerHTML Assignment",
     "pattern": r'\.innerHTML\s*=',
     "severity": "HIGH", "cwe": "CWE-79",
     "message": "Direct innerHTML assignment enables XSS. Use textContent or sanitize input."},
    {"id": "XSS-002", "name": "document.write Usage",
     "pattern": r'document\.write\s*\(',
     "severity": "HIGH", "cwe": "CWE-79",
     "message": "document.write() can introduce XSS. Use DOM manipulation methods instead."},
    # Debug / config issues
    {"id": "CFG-001", "name": "Debug Mode Enabled",
     "pattern": r'(?i)debug\s*=\s*(true|1|yes)',
     "severity": "MEDIUM", "cwe": "CWE-94",
     "message": "Debug mode enabled. Ensure this is not deployed to production."},
    {"id": "CFG-002", "name": "CORS Allow All Origins",
     "pattern": r'(?i)(cors.*\*|allow[_-]?origin.*\*|Access-Control-Allow-Origin.*\*)',
     "severity": "MEDIUM", "cwe": "CWE-942",
     "message": "Wildcard CORS policy allows any origin. Restrict to trusted domains."},
    {"id": "CFG-003", "name": "Insecure SSL Verify Disabled",
     "pattern": r'(?i)(verify\s*=\s*False|ssl_verify\s*=\s*false|checkHostIP\s*=\s*no)',
     "severity": "HIGH", "cwe": "CWE-295",
     "message": "SSL certificate verification disabled. Vulnerable to MITM attacks."},
    # Path traversal
    {"id": "PATH-001", "name": "Path Traversal Risk",
     "pattern": r'(?i)(open|file|read|write)\s*\(.*\.\./|os\.path\.join\(.*request\.',
     "severity": "HIGH", "cwe": "CWE-22",
     "message": "Potential path traversal. Validate and sanitize all file path inputs."},
    # Deserialization
    {"id": "DES-001", "name": "Pickle Deserialization",
     "pattern": r'\bpickle\.(loads|load)\s*\(',
     "severity": "CRITICAL", "cwe": "CWE-502",
     "message": "pickle.loads() with untrusted data enables arbitrary code execution. Use JSON or signed serialization."},
    {"id": "DES-002", "name": "YAML Load Unsafe",
     "pattern": r'\byaml\.load\s*\([^)]*[^L]oad',
     "severity": "HIGH", "cwe": "CWE-502",
     "message": "yaml.load() with untrusted data is dangerous. Use yaml.safe_load() instead."},
    # JWT / token issues
    {"id": "SEC-004", "name": "JWT None Algorithm",
     "pattern": r'(?i)(algorithm|algorithms)\s*=\s*["\']none["\']',
     "severity": "CRITICAL", "cwe": "CWE-347",
     "message": "JWT 'none' algorithm disables signature verification. Always require HS256 or RS256."},
    {"id": "SEC-005", "name": "Hardcoded JWT Secret",
     "pattern": r'(?i)(jwt.secret|jwt_secret|jwt.key|jwt_key)\s*=\s*["\'][^"\']',
     "severity": "CRITICAL", "cwe": "CWE-798",
     "message": "Hardcoded JWT secret. Use environment variable or secrets manager."},
    # Command injection
    {"id": "INJ-004", "name": "Format String in Shell Command",
     "pattern": r'(?:os\.system|subprocess\.call)\s*\(\s*[f]?["\'].*\{',
     "severity": "CRITICAL", "cwe": "CWE-78",
     "message": "F-string or format() used in shell command — user input may reach the shell."},
    {"id": "INJ-005", "name": "Jinja2 Server-Side Template Injection",
     "pattern": r'(?i)(render_template_string|from_string)\s*\(',
     "severity": "CRITICAL", "cwe": "CWE-94",
     "message": "render_template_string() detected — SSTI risk if any user input reaches the template."},
    {"id": "INJ-006", "name": "Template String with Variable (SSTI)",
     "pattern": r'render_template_string\s*\(.*(%\s*[a-zA-Z_]|f["\']|format\s*\()',
     "severity": "CRITICAL", "cwe": "CWE-94",
     "message": "render_template_string called with f-string or % format — very high SSTI risk."},
    # SSRF
    {"id": "SSRF-001", "name": "SSRF Risk — requests with variable URL",
     "pattern": r'requests\.(get|post|put|delete|request)\s*\(\s*(?:url|target|host|endpoint|href|link|uri|dest)',
     "severity": "HIGH", "cwe": "CWE-918",
     "message": "requests.get/post called with a variable URL — SSRF risk if URL is user-controlled."},
    {"id": "SSRF-002", "name": "SSRF Risk — requests with request parameter",
     "pattern": r'requests\.(get|post|put|delete)\s*\(.*request\.',
     "severity": "HIGH", "cwe": "CWE-918",
     "message": "requests call with direct user-supplied URL — Server-Side Request Forgery."},
    # Insecure cookies
    {"id": "CFG-004", "name": "Cookie Missing Secure/HttpOnly Flag",
     "pattern": r'(?i)set.?cookie.*(?!secure)(?!httponly)',
     "severity": "MEDIUM", "cwe": "CWE-614",
     "message": "Cookie may be missing Secure or HttpOnly flags."},
    # Prototype pollution (JS)
    {"id": "INJ-006", "name": "Prototype Pollution Risk",
     "pattern": r'(?i)(__proto__|constructor\.prototype)\s*\[',
     "severity": "HIGH", "cwe": "CWE-1321",
     "message": "Possible prototype pollution. Validate and sanitize object property keys."},
    # Timing attacks
    {"id": "CRY-004", "name": "Non-Constant Time Comparison",
     "pattern": r'(?i)(password|token|secret|hash)\s*==\s*',
     "severity": "MEDIUM", "cwe": "CWE-208",
     "message": "Direct string comparison of secrets is vulnerable to timing attacks. Use hmac.compare_digest()."},
    # Open redirect
    {"id": "REDIR-001", "name": "Open Redirect Risk",
     "pattern": r'(?i)(redirect|location)\s*\(.*request\.',
     "severity": "MEDIUM", "cwe": "CWE-601",
     "message": "Redirect target derived from user input — potential open redirect."},
    # Logging sensitive data
    {"id": "LOG-001", "name": "Logging Sensitive Data",
     "pattern": r'(?i)(log|print|console\.log).*(?:password|token|secret|api.?key)',
     "severity": "MEDIUM", "cwe": "CWE-532",
     "message": "Sensitive data may be written to logs. Redact credentials before logging."},
]

# ── OWASP Top 10 CWE Mapping ──────────────────────────────────────────────────
OWASP_MAP = {
    # A01 Broken Access Control
    "CWE-22":"A01","CWE-59":"A01","CWE-200":"A01","CWE-284":"A01",
    "CWE-285":"A01","CWE-352":"A01","CWE-601":"A01","CWE-639":"A01",
    "CWE-862":"A01","CWE-863":"A01","CWE-913":"A01",
    # A02 Cryptographic Failures
    "CWE-261":"A02","CWE-310":"A02","CWE-319":"A02","CWE-326":"A02",
    "CWE-327":"A02","CWE-328":"A02","CWE-330":"A02","CWE-338":"A02",
    "CWE-347":"A02","CWE-523":"A02","CWE-759":"A02","CWE-916":"A02",
    # A03 Injection
    "CWE-20":"A03","CWE-74":"A03","CWE-77":"A03","CWE-78":"A03",
    "CWE-79":"A03","CWE-80":"A03","CWE-88":"A03","CWE-89":"A03",
    "CWE-90":"A03","CWE-94":"A03","CWE-95":"A03","CWE-943":"A03",
    "CWE-1321":"A03",
    # A04 Insecure Design
    "CWE-73":"A04","CWE-183":"A04","CWE-209":"A04","CWE-256":"A04",
    "CWE-311":"A04","CWE-312":"A04","CWE-313":"A04","CWE-434":"A04",
    # A05 Security Misconfiguration
    "CWE-16":"A05","CWE-260":"A05","CWE-315":"A05","CWE-520":"A05",
    "CWE-526":"A05","CWE-537":"A05","CWE-611":"A05","CWE-614":"A05",
    "CWE-942":"A05","CWE-1004":"A05",
    # A06 Vulnerable & Outdated Components
    "CWE-1035":"A06","CWE-1104":"A06",
    # A07 Identification & Auth Failures
    "CWE-255":"A07","CWE-259":"A07","CWE-287":"A07","CWE-295":"A07",
    "CWE-306":"A07","CWE-307":"A07","CWE-384":"A07","CWE-521":"A07",
    "CWE-613":"A07","CWE-640":"A07","CWE-798":"A07","CWE-208":"A07",
    # A08 Software & Data Integrity Failures
    "CWE-345":"A08","CWE-353":"A08","CWE-426":"A08","CWE-494":"A08",
    "CWE-502":"A08","CWE-565":"A08","CWE-829":"A08","CWE-915":"A08",
    # A09 Logging & Monitoring Failures
    "CWE-117":"A09","CWE-223":"A09","CWE-532":"A09","CWE-778":"A09",
    # A10 SSRF
    "CWE-918":"A10",
}
OWASP_CATEGORIES = {
    "A01": ("Broken Access Control",              "#e74c3c"),
    "A02": ("Cryptographic Failures",             "#e67e22"),
    "A03": ("Injection",                          "#e74c3c"),
    "A04": ("Insecure Design",                    "#f39c12"),
    "A05": ("Security Misconfiguration",          "#f1c40f"),
    "A06": ("Vulnerable Components",              "#27ae60"),
    "A07": ("ID & Auth Failures",                 "#e74c3c"),
    "A08": ("Software & Data Integrity",          "#e67e22"),
    "A09": ("Logging & Monitoring Failures",      "#3498db"),
    "A10": ("Server-Side Request Forgery",        "#9b59b6"),
}

# Language detection heuristics
LANG_PATTERNS = {
    "python":     [r"^\s*import\s+\w", r"^\s*def\s+\w+\s*\(", r"^\s*class\s+\w+\s*[:(]", r"print\s*\("],
    "javascript": [r"const\s+\w+\s*=", r"function\s+\w+\s*\(", r"=>\s*\{", r"require\s*\(", r"console\.log"],
    "java":       [r"public\s+class\s+\w+", r"import\s+java\.", r"System\.out\.print", r"@Override"],
    "php":        [r"<\?php", r"\$\w+\s*=", r"echo\s+[\$\"']"],
    "go":         [r"^package\s+\w+", r"^import\s+\"", r"func\s+\w+\s*\("],
    "ruby":       [r"^\s*def\s+\w+$", r"puts\s+", r"require\s+['\"]", r"\.each\s+do\s*\|"],
    "typescript": [r":\s*(string|number|boolean|any)\s*[=;,)]", r"interface\s+\w+\s*\{"],
    "c_cpp":      [r"#include\s*<", r"int\s+main\s*\(", r"printf\s*\(", r"std::"],
}

LANG_SEMGREP_RULESET = {
    "python":     ["p/python", "p/bandit", "p/owasp-top-ten"],
    "javascript": ["p/javascript", "p/nodejs", "p/owasp-top-ten", "p/xss"],
    "java":       ["p/java", "p/owasp-top-ten"],
    "typescript": ["p/typescript", "p/javascript"],
    "go":         ["p/golang"],
    "php":        ["p/php"],
    "ruby":       ["p/ruby"],
    "c_cpp":      ["p/c"],
}
LANG_EXTENSIONS = {
    "python": ".py", "javascript": ".js", "java": ".java",
    "typescript": ".ts", "go": ".go", "php": ".php",
    "ruby": ".rb", "c_cpp": ".c",
}


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINES
# ─────────────────────────────────────────────────────────────────────────────

def _detect_language(code: str, hint: str = "auto") -> str:
    if hint != "auto":
        return hint
    scores = {lang: 0 for lang in LANG_PATTERNS}
    for lang, patterns in LANG_PATTERNS.items():
        for p in patterns:
            if re.search(p, code, re.MULTILINE):
                scores[lang] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "python"


# ── Plugin engine imports ─────────────────────────────────────────────────
try:
    from sast_plugins import run_all_plugins as _plugin_runner
    from sast_plugins.risk_scoring import score_all_findings as _score_findings
    from sast_plugins.remediation_plugin import enrich_fixes as _enrich_fixes
    from sast_plugins.exploit_generator import enrich_with_exploits as _enrich_exploits
    _PLUGINS_AVAILABLE = True
except ImportError:
    _PLUGINS_AVAILABLE = False
    def _plugin_runner(fp, code, lang): return []
    def _score_findings(findings): return findings
    def _enrich_fixes(findings): return findings
    def _enrich_exploits(findings): return findings


def _ensure_tool(tool: str) -> bool:
    """Check if a tool is available; if not, try to install it."""
    if tool == "semgrep":
        pkg = "semgrep"
    elif tool == "bandit":
        pkg = "bandit"
    else:
        return False
    result = subprocess.run(["which", tool], capture_output=True, text=True)
    if result.returncode == 0:
        return True
    # Try installing
    venv_pip = os.path.join(sys.prefix, "bin", "pip")
    r = subprocess.run([venv_pip, "install", "-q", pkg],
                       capture_output=True, text=True, timeout=120)
    return r.returncode == 0


def _run_regex_scan(code: str) -> list:
    findings = []
    lines = code.splitlines()
    for rule in REGEX_RULES:
        pat = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
        for i, line in enumerate(lines, 1):
            if pat.search(line):
                findings.append({
                    "id":       rule["id"],
                    "rule":     rule["name"],
                    "severity": rule["severity"],
                    "cwe":      rule["cwe"],
                    "message":  rule["message"],
                    "line":     i,
                    "code":     line.strip()[:200],
                    "engine":   "Regex",
                    "fix":      "",
                })
    return findings


def _run_semgrep(code: str, language: str, tmpfile: str) -> list:
    if not _ensure_tool("semgrep"):
        return [{"id": "TOOL", "rule": "Semgrep not available",
                 "severity": "INFO", "cwe": "", "message": "Could not install semgrep.",
                 "line": 0, "code": "", "engine": "Semgrep", "fix": ""}]
    rulesets = LANG_SEMGREP_RULESET.get(language, ["p/owasp-top-ten"])
    findings = []
    for rs in rulesets[:2]:          # limit to 2 rulesets for speed
        try:
            r = subprocess.run(
                ["semgrep", "--config", rs, "--json", "--quiet", tmpfile],
                capture_output=True, text=True, timeout=60,
            )
            if r.stdout:
                data = json.loads(r.stdout)
                for res in data.get("results", []):
                    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}
                    sev = res.get("extra", {}).get("severity", "MEDIUM")
                    if sev not in SEV_ORDER:
                        sev = sev_map.get(sev.upper(), "MEDIUM")
                    findings.append({
                        "id":       res.get("check_id", "SG-??")[-20:],
                        "rule":     res.get("check_id", "unknown").split(".")[-1],
                        "severity": sev,
                        "cwe":      res.get("extra", {}).get("metadata", {}).get("cwe", [""])[0] if isinstance(
                            res.get("extra", {}).get("metadata", {}).get("cwe"), list) else "",
                        "message":  res.get("extra", {}).get("message", "")[:300],
                        "line":     res.get("start", {}).get("line", 0),
                        "code":     res.get("extra", {}).get("lines", "")[:200],
                        "engine":   f"Semgrep ({rs})",
                        "fix":      res.get("extra", {}).get("fix", ""),
                    })
        except Exception:
            pass
    return findings


def _run_bandit(code: str, tmpfile: str) -> list:
    if not _ensure_tool("bandit"):
        return []
    try:
        r = subprocess.run(
            ["bandit", "-r", tmpfile, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(r.stdout or "{}")
        findings = []
        sev_map  = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        for issue in data.get("results", []):
            sev = sev_map.get(issue.get("issue_severity", "MEDIUM"), "MEDIUM")
            findings.append({
                "id":       issue.get("test_id", "B-??"),
                "rule":     issue.get("test_name", "unknown"),
                "severity": sev,
                "cwe":      issue.get("issue_cwe", {}).get("link", "")[-10:] if issue.get("issue_cwe") else "",
                "message":  issue.get("issue_text", ""),
                "line":     issue.get("line_number", 0),
                "code":     issue.get("code", "")[:200],
                "engine":   "Bandit",
                "fix":      "",
            })
        return findings
    except Exception:
        return []


def _run_plugins(code: str, language: str, tmpfile: str) -> list:
    """Run all sast_plugins and normalise findings."""
    if not _PLUGINS_AVAILABLE:
        return []
    try:
        return _plugin_runner(tmpfile, code, language)
    except Exception:
        return []


def _full_scan(code: str, language: str) -> tuple:
    """Run all engines in parallel threads, merge results. Returns (findings, engine_counts)."""
    results     = []
    ext         = LANG_EXTENSIONS.get(language, ".py")
    containers  = [[] for _ in range(4)]
    labels      = ["Regex", "Semgrep", "Bandit", "Plugins"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, prefix="/tmp/sast_") as f:
        f.write(code)
        tmpfile = f.name

    def t0(): containers[0].extend(_run_regex_scan(code))
    def t1(): containers[1].extend(_run_semgrep(code, language, tmpfile))
    def t2():
        if language == "python":
            containers[2].extend(_run_bandit(code, tmpfile))
    def t3(): containers[3].extend(_run_plugins(code, language, tmpfile))

    threads = []
    for fn in [t0, t1, t2, t3]:
        th = threading.Thread(target=fn, daemon=True)
        th.start()
        threads.append(th)
    for th in threads:
        th.join(timeout=90)

    try:
        os.unlink(tmpfile)
    except Exception:
        pass

    engine_counts = {labels[i]: len(containers[i]) for i in range(3)}
    for c in containers:
        results.extend(c)
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    results.sort(key=lambda x: order.get(x.get("severity", "INFO"), 99))
    results = _score_findings(results)   # attach CVSS scores
    results = _enrich_fixes(results)     # fill empty fix fields
    results = _enrich_exploits(results)  # attach PoC payloads
    return results, engine_counts


# ─────────────────────────────────────────────────────────────────────────────
# CWE LINK HELPER
# ─────────────────────────────────────────────────────────────────────────────
def _cwe_link(cwe: str):
    if not cwe:
        return html.Span("—", style={"color": TEXT_COL})
    m = re.search(r"(\d+)", str(cwe))
    if m:
        num = m.group(1)
        return html.A(f"CWE-{num}", href=f"https://cwe.mitre.org/data/definitions/{num}.html",
                      target="_blank", style={"color": CYAN, "textDecoration": "none"})
    return html.Span(cwe, style={"color": TEXT_COL})


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY SUMMARY BADGES
# ─────────────────────────────────────────────────────────────────────────────
def _summary_bar(findings: list):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_key = f.get("severity", "INFO")
        counts[sev_key] = counts.get(sev_key, 0) + 1
    total  = sum(counts.values())
    badges = []

    def _badge(label, count, color):
        return dbc.Col(
            dbc.Card(
                html.Div([
                    html.Div(str(count), style={"fontSize": "1.8rem", "fontWeight": "bold",
                                                "color": color, "lineHeight": "1"}),
                    html.Div(label,      style={"fontSize": "0.72rem", "color": TEXT_COL}),
                ], style={"textAlign": "center", "padding": "10px 0"}),
                style={**CARD_STYLE, "borderTop": f"3px solid {color}"},
            ),
            width=True,
        )

    badges.append(_badge("TOTAL", total, "#888"))
    for sev in SEV_ORDER:
        badges.append(_badge(sev, counts.get(sev, 0), SEV_COLOR[sev]))
    return dbc.Row(badges, className="g-2 mb-3")


# ─────────────────────────────────────────────────────────────────────────────
# OWASP BREAKDOWN PANEL
# ─────────────────────────────────────────────────────────────────────────────
def _owasp_breakdown(findings: list) -> html.Div:
    """Map findings to OWASP Top 10 and render a compact horizontal-bar panel."""
    counts: dict[str, int] = {k: 0 for k in OWASP_CATEGORIES}
    unmapped = 0
    for f in findings:
        cwe = str(f.get("cwe", "") or "").upper().replace(" ", "")
        cat = OWASP_MAP.get(cwe)
        if cat:
            counts[cat] += 1
        else:
            unmapped += 1

    active = {k: v for k, v in counts.items() if v > 0}
    if not active:
        return html.Div()

    max_cnt = max(active.values()) or 1
    bars = []
    for cat_id, cnt in sorted(active.items(), key=lambda x: -x[1]):
        name, colour = OWASP_CATEGORIES[cat_id]
        pct = int(cnt / max_cnt * 100)
        bars.append(
            dbc.Col([
                html.Div([
                    html.Span(cat_id,  style={"color": colour, "fontWeight": "700",
                                              "fontSize": "9px", "minWidth": "26px"}),
                    html.Span(name,    style={"color": TEXT_COL, "fontSize": "9px",
                                              "marginLeft": "4px", "whiteSpace": "nowrap",
                                              "overflow": "hidden", "textOverflow": "ellipsis",
                                              "maxWidth": "120px", "display": "inline-block"}),
                    html.Span(f" ×{cnt}", style={"color": "#fff", "fontSize": "9px",
                                                  "fontWeight": "700", "marginLeft": "auto"}),
                ], style={"display": "flex", "alignItems": "center", "marginBottom": "3px"}),
                dbc.Progress(
                    value=pct,
                    style={"height": "4px", "backgroundColor": "#1a1c24", "borderRadius": "3px"},
                    color="danger" if cat_id in ("A01","A03","A07") else
                          "warning" if cat_id in ("A02","A04","A08") else
                          "info"    if cat_id in ("A09","A10") else "success",
                ),
            ], md=3, className="mb-1"),
        )

    return html.Div([
        html.Div([
            html.Span("📋 OWASP Top 10 Coverage",
                      style={"color": CYAN, "fontWeight": "700", "fontSize": "11px",
                             "textTransform": "uppercase", "letterSpacing": "0.8px"}),
            html.Span(f"{len(active)} categories affected  •  {unmapped} unmapped",
                      style={"color": TEXT_COL, "fontSize": "9px", "marginLeft": "12px"}),
        ], style={"marginBottom": "8px"}),
        dbc.Row(bars, className="g-2"),
    ], style={
        "backgroundColor": "#161820", "border": "1px solid #2a2d3a",
        "borderRadius": "10px", "padding": "12px 16px", "marginBottom": "14px",
    })


# ─────────────────────────────────────────────────────────────────────────────
# DIFF RENDERER (Enhancement 3)
# ─────────────────────────────────────────────────────────────────────────────
import difflib as _difflib

def _render_diff(original_code: str, patched_code: str) -> html.Div:
    """Render a unified diff between original_code and patched_code."""
    if not patched_code or not original_code:
        return html.Span()
    orig_lines   = original_code.splitlines(keepends=True)
    patch_lines  = patched_code.splitlines(keepends=True)
    diff_lines   = list(_difflib.unified_diff(
        orig_lines, patch_lines,
        fromfile="vulnerable", tofile="patched", lineterm="",
    ))
    if not diff_lines:
        return html.Div("✅ No diff — code is identical.",
                        style={"color": GREEN, "fontSize": "0.8rem"})
    els = []
    for ln in diff_lines:
        if ln.startswith("---") or ln.startswith("+++"):
            color, bg = "#888", "transparent"
        elif ln.startswith("-"):
            color, bg = RED,   "#2a0a0a"
        elif ln.startswith("+"):
            color, bg = GREEN, "#0a2a0a"
        elif ln.startswith("@@"):
            color, bg = CYAN,  "#0a1a2a"
        else:
            color, bg = "#ccc", "transparent"
        els.append(html.Div(ln.rstrip(),
                            style={"color": color, "backgroundColor": bg,
                                   "fontFamily": "monospace", "fontSize": "0.75rem",
                                   "whiteSpace": "pre", "padding": "0 6px",
                                   "lineHeight": "1.5"}))
    return html.Div([
        html.Div("📝 Code Diff — Vulnerable vs. Patched",
                 style={"color": CYAN, "fontSize": "0.78rem", "fontWeight": "700",
                        "marginBottom": "6px"}),
        html.Div(els, style={
            "backgroundColor": "#0d1117", "borderRadius": "6px",
            "padding": "8px 4px", "overflowX": "auto",
            "border": "1px solid #222", "maxHeight": "260px", "overflowY": "auto",
        }),
    ])


# ─────────────────────────────────────────────────────────────────────────────
# SCAN HISTORY TREND CHART BUILDER (Enhancement 4)
# ─────────────────────────────────────────────────────────────────────────────
import plotly.graph_objects as go

def _build_trend_chart(history: list):
    """Build a line chart from session scan history."""
    if len(history) < 2:
        return html.Div()
    labels = [h.get('ts', str(i)) for i, h in enumerate(history)]

    def _hex_rgba(hex_clr: str, alpha: float = 0.15) -> str:
        """Convert '#rrggbb' → 'rgba(r,g,b,a)' for Plotly fillcolor."""
        h = hex_clr.lstrip('#')
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f'rgba({r},{g},{b},{alpha})'

    def _trace(name, key, clr):
        vals = [h.get(key, 0) for h in history]
        return go.Scatter(
            x=labels, y=vals, name=name,
            mode='lines+markers',
            line=dict(color=clr, width=2),
            marker=dict(size=5, color=clr),
            fill='tozeroy',
            fillcolor=_hex_rgba(clr),
        )
    fig = go.Figure([
        _trace('Critical', 'critical', RED),
        _trace('High',     'high',     ORANGE),
        _trace('Medium',   'medium',   YELLOW),
        _trace('Low',      'low',      CYAN),
    ])
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=36, r=12, t=6, b=28),
        height=150,
        showlegend=True,
        legend=dict(orientation='h', y=1.12, font=dict(color='#aaa', size=10)),
        xaxis=dict(color='#555', showgrid=False),
        yaxis=dict(color='#555', gridcolor='#1e2230'),
    )
    return html.Div([
        html.Div([
            html.Span('📈 Scan History Trend',
                      style={'color': CYAN, 'fontWeight': '700', 'fontSize': '11px',
                             'textTransform': 'uppercase', 'letterSpacing': '0.8px'}),
            html.Span(f'{len(history)} scan(s) this session',
                      style={'color': TEXT_COL, 'fontSize': '9px', 'marginLeft': '12px'}),
        ], style={'marginBottom': '4px'}),
        dcc.Graph(figure=fig, config={'displayModeBar': False},
                  style={'height': '150px'}),
    ], style={
        'backgroundColor': '#161820', 'border': '1px solid #2a2d3a',
        'borderRadius': '10px', 'padding': '10px 16px', 'marginBottom': '14px',
    })


# ── Sample code snippets for each language ────────────────────────────────────
SAMPLE_CODE: dict = {
    "python": '''\
#!/usr/bin/env python3
"""Deliberately Vulnerable Flask App — Python Sample"""
from flask import Flask, request, render_template_string
import sqlite3, hashlib, pickle, os

app = Flask(__name__)
SECRET_KEY = "hardcoded_s3cr3t!"        # ← Hardcoded credential (CWE-798)

conn = sqlite3.connect(":memory:")

@app.route("/user")
def get_user():
    uid = request.args.get("id")
    # ← SQL Injection via string concat (CWE-89)
    query = "SELECT * FROM users WHERE id=" + uid
    conn.execute(query)
    return "ok"

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)     # ← OS Command Injection (CWE-78)
    return "ok"

@app.route("/hash")
def weak_hash():
    pw = request.args.get("pw")
    return hashlib.md5(pw.encode()).hexdigest()  # ← Weak crypto (CWE-327)

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # ← Unsafe deserialisation (CWE-502)

@app.route("/render")
def render():
    name = request.args.get("name")
    # ← SSTI — Server Side Template Injection (CWE-94)
    return render_template_string(f"<h1>Hello {name}</h1>")

if __name__ == "__main__":
    app.run(debug=True, port=5000)     # ← Debug mode in production (CWE-94)
''',

    "javascript": '''\
// Deliberately Vulnerable Express App — JavaScript Sample
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();

const DB_PASSWORD = "admin123secret";  // ← Hardcoded credential (CWE-798)

app.get("/search", (req, res) => {
  const term = req.query.q;
  // ← SQL injection via string concat (CWE-89)
  const sql = "SELECT * FROM items WHERE name LIKE '%" + term + "%'";
  db.query(sql, (err, rows) => res.json(rows));
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, out) => res.send(out)); // ← Command injection (CWE-78)
});

app.get("/file", (req, res) => {
  const name = req.query.name;
  fs.readFileSync("/var/data/" + name);  // ← Path traversal (CWE-22)
});

app.get("/search-result", (req, res) => {
  const q = req.query.q;
  // ← XSS: user input in innerHTML (CWE-79)
  res.send(`<div id="out"></div><script>document.getElementById("out").innerHTML="${q}"</script>`);
});

app.listen(3000, () => console.log("Running in debug mode"));  // debug
''',

    "java": '''\
// Deliberately Vulnerable Java Servlet — Java Sample
import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class VulnerableServlet extends HttpServlet {

    static final String DB_PASS = "Admin@1234!";  // ← Hardcoded cred (CWE-798)

    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        String userId = req.getParameter("id");
        // ← SQL Injection via concatenation (CWE-89)
        String sql = "SELECT * FROM users WHERE id='" + userId + "'";
        Connection conn = DriverManager.getConnection("jdbc:...", "root", DB_PASS);
        conn.createStatement().executeQuery(sql);

        // ← OS Command Injection (CWE-78)
        Runtime.getRuntime().exec("ping -c 1 " + req.getParameter("host"));

        // ← Unsafe deserialisation (CWE-502)
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        ois.readObject();

        // ← XSS: unescaped output (CWE-79)
        PrintWriter out = res.getWriter();
        out.println("<h1>" + req.getParameter("name") + "</h1>");

        // ← XXE: unsafe XML parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(req.getInputStream());
    }
}
''',

    "php": '''\
<?php
// Deliberately Vulnerable PHP App — PHP Sample

$DB_PASS = "SuperSecret123!";  // ← Hardcoded credential (CWE-798)

// ← SQL Injection: superglobal in query (CWE-89)
$query = "SELECT * FROM users WHERE id=" . $_GET["id"];
mysql_query($query);

// ← OS Command Injection (CWE-78)
$out = shell_exec("ping -c 1 " . $_GET["host"]);
echo $out;

// ← XSS: direct echo of superglobal (CWE-79)
echo $_GET["name"];

// ← Dynamic file inclusion — RFI/LFI (CWE-98)
include($_GET["page"] . ".php");

// ← Unsafe deserialisation (CWE-502)
$obj = unserialize($_POST["data"]);

// ← Weak hash for password (CWE-327)
$hash = md5($_POST["password"]);

?>
''',

    "go": '''\
// Deliberately Vulnerable Go App — Go Sample
package main

import (
    "crypto/md5"
    "database/sql"
    "fmt"
    "net/http"
    "os/exec"
)

const APISecret = "hardcoded-secret-key"  // ← Hardcoded credential (CWE-798)

func searchHandler(w http.ResponseWriter, r *http.Request) {
    term := r.URL.Query().Get("q")
    // ← SQL Injection via fmt.Sprintf (CWE-89)
    query := fmt.Sprintf("SELECT * FROM items WHERE name='%s'", term)
    db.Query(query)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    // ← OS Command Injection (CWE-78)
    out, _ := exec.Command("ping", "-c", "1", host).Output()
    fmt.Fprintf(w, string(out))
}

func hashPassword(pw string) string {
    // ← Weak hash MD5 (CWE-327)
    h := md5.New()
    h.Write([]byte(pw))
    return fmt.Sprintf("%x", h.Sum(nil))
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    // ← SSRF (CWE-918)
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}
''',

    "ruby": '''\
# Deliberately Vulnerable Ruby on Rails App — Ruby Sample
require "open3"

SECRET_TOKEN = "my_hardcoded_secret_123"  # ← Hardcoded credential (CWE-798)

class VulnerableController < ApplicationController

  def search
    term = params[:q]
    # ← SQL Injection via interpolation (CWE-89)
    @results = User.where("name = '#{term}'")
  end

  def ping
    host = params[:host]
    # ← OS Command Injection (CWE-78)
    output = `ping -c 1 #{host}`
    render plain: output
  end

  def load_object
    # ← Unsafe deserialisation (CWE-502)
    obj = Marshal.load(params[:data])
  end

  def update_profile
    # ← Mass Assignment (CWE-915)
    current_user.update(params)
  end

  def run_code
    # ← eval with user input (CWE-95)
    eval(params[:code])
  end
end
''',

    "typescript": '''\
// Deliberately Vulnerable TypeScript/Node App — TypeScript Sample
import express from "express";
import { exec } from "child_process";

const SECRET: string = "hardcoded-jwt-secret";  // ← Hardcoded credential (CWE-798)
const app = express();

app.get("/search", async (req: any, res: any) => {
  const term = req.query.q as any;  // ← Unsafe any cast (CWE-unknown)
  // ← SQL Injection — template literal (CWE-89)
  const sql = `SELECT * FROM items WHERE name = '${term}'`;
  const rows = await db.query(sql);
  res.json(rows);
});

app.get("/run", (req: any, res: any) => {
  const cmd = req.query.cmd as string;
  // ← Command injection (CWE-78)
  exec(cmd, (err, stdout) => res.send(stdout));
});

app.get("/unsafe", (req: any, res: any) => {
  const code = req.query.code;
  // ← eval with user input (CWE-95)
  const result = eval(code);
  res.json({ result });
});

// ← Debug mode active
app.listen(3000, () => console.log("NODE_ENV=development debug active"));
''',

    "c_cpp": '''\
/* Deliberately Vulnerable C Program — C/C++ Sample */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ← Hardcoded credential (CWE-798) */
const char *DB_PASSWORD = "SuperSecret123!";

void copy_input(char *dst, char *src) {
    /* ← Buffer overflow: strcpy without bounds (CWE-120) */
    strcpy(dst, src);
}

void echo_name(char *name) {
    /* ← Format string attack if name contains % (CWE-134) */
    printf(name);
}

int run_command(char *host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);
    /* ← OS Command Injection: system() with user input (CWE-78) */
    return system(cmd);
}

int main(int argc, char *argv[]) {
    char buf[64];
    /* ← Buffer overflow: gets() is unsafe (CWE-120) */
    gets(buf);
    echo_name(argv[1]);
    run_command(argv[2]);
    return 0;
}
''',
}


def layout_sast_dashboard():
    return html.Div([
        dcc.Store(id="sast-findings-store",   storage_type="session", data=[]),
        dcc.Store(id="sast-selected-finding", storage_type="session", data=None),
        dcc.Store(id="sast-highlight-line",   storage_type="session", data=None),
        dcc.Store(id="sast-history-store",    storage_type="session", data=[]),
        dcc.Download(id="sast-export-download"),

        # ── Animated Gradient Header ─────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div([
                    html.Span("🛡️", style={"fontSize": "2rem", "marginRight": "14px"}),
                    html.Div([
                        html.H3("Static Application Security Testing",
                                style={"color": "#fff", "margin": "0", "fontWeight": "800",
                                       "fontSize": "1.4rem", "letterSpacing": "0.5px"}),
                        html.P("22 Plugins · Regex · Bandit · Semgrep · SSA · Program Slicing · LLM",
                               style={"color": "#7a8ba8", "fontSize": "0.78rem", "margin": "2px 0 0"}),
                    ]),
                ], style={"display": "flex", "alignItems": "center"}),

                # ── Engine pill tags ─────────────────────────────────────────
                html.Div([
                    *[html.Span(e, style={
                        "backgroundColor": c + "22", "color": c,
                        "border": f"1px solid {c}55",
                        "borderRadius": "20px", "padding": "3px 10px",
                        "fontSize": "0.68rem", "fontWeight": "600",
                        "marginRight": "6px", "whiteSpace": "nowrap",
                    }) for e, c in [
                        ("⚡ Regex", CYAN), ("🐍 Bandit", GREEN),
                        ("🔬 Semgrep", ORANGE), ("🧠 SSA", PURPLE),
                        ("✂️ Slicing", YELLOW), ("🤖 LLM", "#ff6b9d"),
                        ("📦 22 Plugins", "#42f5a4"),
                    ]],
                ], style={"display": "flex", "alignItems": "center", "flexWrap": "wrap", "gap": "4px"}),
            ], style={
                "display": "flex", "justifyContent": "space-between",
                "alignItems": "center", "flexWrap": "wrap", "gap": "12px",
            }),
        ], style={
            "background": "linear-gradient(135deg, #1a1c24 0%, #1e2235 50%, #1a1c24 100%)",
            "borderBottom": f"2px solid {CYAN}44",
            "padding": "18px 28px 14px",
            "marginBottom": "0",
        }),

        dbc.Container([
            # ── Metric Summary Row ──────────────────────────────────────────
            html.Div(id="sast-summary-bar", style={"paddingTop": "16px"}),

            # ── OWASP Top 10 Panel ─────────────────────────────────────────
            html.Div(id="sast-owasp-panel"),

            # ── Trend Chart ────────────────────────────────────────────────
            html.Div(id="sast-trend-wrapper"),

            # ── Main 3-Column Layout ────────────────────────────────────────
            dbc.Row([

                # ══ LEFT: Code Input (5/12) ═══════════════════════════════
                dbc.Col([
                    html.Div([
                        # Card header
                        html.Div([
                            html.Div([
                                html.Span("</> ", style={"color": CYAN, "fontWeight": "900", "fontFamily": "monospace"}),
                                html.Span("Code Input", style={"color": "#fff", "fontWeight": "700",
                                                                "fontSize": "0.95rem"}),
                            ], style={"display": "flex", "alignItems": "center"}),
                            html.Div([
                                dbc.Button("⚡ Load Sample", id="sast-load-sample-btn",
                                           size="sm", color="outline-warning",
                                           style={"fontSize": "0.72rem", "padding": "3px 10px",
                                                  "border": f"1px solid {ORANGE}66",
                                                  "color": ORANGE, "background": "transparent"}),
                            ]),
                        ], style={"display": "flex", "justifyContent": "space-between",
                                  "alignItems": "center", "padding": "12px 16px 10px",
                                  "borderBottom": "1px solid #2a2d3a"}),

                        # Language selector + Upload
                        html.Div([
                            html.Div([
                                html.Label("Language", style={**LABEL_STYLE, "fontSize": "0.72rem"}),
                                dbc.Select(id="sast-lang",
                                    options=[
                                        {"label": "🔍  Auto-Detect",  "value": "auto"},
                                        {"label": "🐍  Python",        "value": "python"},
                                        {"label": "🟨  JavaScript",    "value": "javascript"},
                                        {"label": "☕  Java",          "value": "java"},
                                        {"label": "🐘  PHP",           "value": "php"},
                                        {"label": "🐹  Go",            "value": "go"},
                                        {"label": "💎  Ruby",          "value": "ruby"},
                                        {"label": "🔷  TypeScript",    "value": "typescript"},
                                        {"label": "⚙️  C / C++",       "value": "c_cpp"},
                                    ],
                                    value="auto",
                                    style={**INPUT_STYLE, "fontSize": "0.82rem"},
                                ),
                            ], style={"flex": "1", "marginRight": "10px"}),

                            html.Div([
                                html.Label("Upload File", style={**LABEL_STYLE, "fontSize": "0.72rem"}),
                                dcc.Upload(
                                    id="sast-upload",
                                    children=html.Div([
                                        html.I(className="bi bi-cloud-upload me-1"),
                                        "Drag & Drop or ",
                                        html.Span("Browse", style={"color": CYAN, "fontWeight": "600"}),
                                    ], style={"fontSize": "0.75rem"}),
                                    style={
                                        "border": f"1px dashed {CYAN}66",
                                        "borderRadius": "8px", "padding": "8px 12px",
                                        "textAlign": "center", "color": TEXT_COL,
                                        "cursor": "pointer", "backgroundColor": "#111",
                                        "transition": "border-color 0.2s",
                                    },
                                    multiple=False,
                                ),
                            ], style={"flex": "1"}),
                        ], style={"display": "flex", "padding": "10px 14px 8px"}),

                        # Code editor with line-number gutter aesthetic
                        html.Div([
                            # Line number strip
                            html.Div(id="sast-line-numbers",
                                     style={
                                         "position": "absolute",
                                         "top": "0", "left": "0", "bottom": "0",
                                         "width": "36px",
                                         "backgroundColor": "#161820",
                                         "borderRight": "1px solid #2a2d3a",
                                         "color": "#444", "fontSize": "0.72rem",
                                         "fontFamily": "monospace",
                                         "padding": "8px 4px", "lineHeight": "1.45",
                                         "textAlign": "right", "overflowY": "hidden",
                                         "userSelect": "none", "pointerEvents": "none",
                                         "zIndex": "1",
                                         "display": "none",   # shown via clientside JS
                                     }),
                            dcc.Textarea(
                                id="sast-code-input",
                                placeholder=(
                                    "# Paste code or click ⚡ Load Sample above\n\n"
                                    "# Quick demo:\n"
                                    "import pickle\n"
                                    "password = 'Admin123!'           # ← hardcoded cred\n"
                                    "data = pickle.loads(user_input)  # ← unsafe deserialisation\n"
                                ),
                                style={
                                    **INPUT_STYLE,
                                    "width": "100%", "height": "390px",
                                    "fontFamily": "'Fira Code', 'Courier New', monospace",
                                    "fontSize": "0.80rem", "resize": "vertical",
                                    "borderRadius": "0", "border": "none",
                                    "lineHeight": "1.45", "padding": "8px 10px",
                                    "backgroundColor": "#0d0f18",
                                    "caretColor": CYAN,
                                },
                            ),
                        ], style={"position": "relative", "borderTop": "1px solid #1e2030",
                                  "borderBottom": "1px solid #1e2030"}),

                        # Line indicator
                        html.Div(id="sast-line-indicator",
                                 style={"minHeight": "18px", "padding": "2px 14px",
                                        "fontSize": "0.7rem"}),

                        # Action bar
                        html.Div([
                            # Scan button (primary CTA)
                            dbc.Button([
                                html.I(className="bi bi-shield-exclamation me-2"),
                                "▶  Scan Code",
                            ], id="sast-scan-btn",
                               style={
                                   "background": f"linear-gradient(135deg, {RED}, #c0152a)",
                                   "border": "none", "fontWeight": "800",
                                   "fontSize": "0.85rem", "padding": "8px 22px",
                                   "borderRadius": "8px", "boxShadow": f"0 0 14px {RED}55",
                                   "color": "#fff", "marginRight": "8px",
                                   "transition": "box-shadow 0.2s",
                               }),
                            dbc.Button("🗑 Clear", id="sast-clear-btn",
                                       color="outline-secondary", size="sm",
                                       style={"marginRight": "6px", "fontSize": "0.75rem"}),
                            dbc.Button("💾 JSON", id="sast-export-json-btn",
                                       color="outline-info", size="sm",
                                       style={"marginRight": "6px", "fontSize": "0.75rem"}),
                            dbc.Button("📊 CSV", id="sast-export-csv-btn",
                                       color="outline-success", size="sm",
                                       style={"fontSize": "0.75rem"}),
                        ], style={"display": "flex", "alignItems": "center",
                                  "padding": "10px 14px 8px", "gap": "4px",
                                  "flexWrap": "wrap"}),

                        # Scan status
                        dcc.Loading(
                            html.Div(id="sast-scan-status",
                                     style={"color": TEXT_COL, "fontSize": "0.76rem",
                                            "padding": "0 14px 10px", "minHeight": "20px"}),
                            type="dot", color=CYAN,
                        ),
                    ], style={
                        **CARD_STYLE,
                        "borderTop": f"3px solid {CYAN}",
                        "overflow": "hidden",
                    }),
                ], width=5),

                # ══ MIDDLE: Findings Table (4/12) ════════════════════════
                dbc.Col([
                    html.Div([
                        # Card header with severity filter
                        html.Div([
                            html.Div([
                                html.Span("🚨 ", style={"fontSize": "1rem"}),
                                html.Span("Findings", style={"color": RED, "fontWeight": "700",
                                                             "fontSize": "0.95rem"}),
                                html.Span(id="sast-finding-count",
                                          style={"color": TEXT_COL, "fontSize": "0.72rem",
                                                 "marginLeft": "8px"}),
                            ], style={"display": "flex", "alignItems": "center"}),
                            dbc.Select(
                                id="sast-filter-sev",
                                options=[{"label": "All Severities", "value": "ALL"}] +
                                        [{"label": f"{SEV_ICON[s]}  {s}", "value": s} for s in SEV_ORDER],
                                value="ALL",
                                style={**INPUT_STYLE, "fontSize": "0.73rem",
                                       "padding": "3px 8px", "width": "130px"},
                            ),
                        ], style={"display": "flex", "justifyContent": "space-between",
                                  "alignItems": "center", "padding": "12px 14px 10px",
                                  "borderBottom": "1px solid #2a2d3a"}),

                        # Findings list
                        html.Div(id="sast-findings-table",
                                 style={"overflowY": "auto", "maxHeight": "560px",
                                        "padding": "6px 8px"}),

                    ], style={
                        **CARD_STYLE,
                        "borderTop": f"3px solid {RED}",
                    }),
                ], width=4),

                # ══ RIGHT: Finding Detail (3/12) ═════════════════════════
                dbc.Col([
                    html.Div([
                        # Card header
                        html.Div([
                            html.Span("🔎 ", style={"fontSize": "1rem"}),
                            html.Span("Finding Detail", style={"color": PURPLE, "fontWeight": "700",
                                                               "fontSize": "0.95rem"}),
                        ], style={"display": "flex", "alignItems": "center",
                                  "padding": "12px 14px 10px",
                                  "borderBottom": "1px solid #2a2d3a"}),

                        # Detail content
                        dcc.Loading(
                            html.Div(id="sast-finding-detail",
                                     children=html.Div([
                                         html.Div("⬅ Select a finding",
                                                  style={"color": TEXT_COL, "fontSize": "0.85rem",
                                                         "textAlign": "center", "marginBottom": "8px"}),
                                         html.Div("Click any row in the Findings panel to see CWE details, "
                                                  "CVSS score, and AI-generated fix.",
                                                  style={"color": "#555", "fontSize": "0.76rem",
                                                         "textAlign": "center"}),
                                     ], style={"padding": "30px 16px"})),
                            type="circle", color=PURPLE,
                        ),

                        html.Hr(style={"borderColor": "#2a2d3a", "margin": "0 14px"}),

                        # AI action bar
                        html.Div([
                            dbc.Button([
                                html.I(className="bi bi-stars me-1"),
                                "🤖 AI Fix",
                            ], id="sast-ai-btn", size="sm",
                               style={
                                   "background": f"linear-gradient(135deg, {PURPLE}, #7a3fa8)",
                                   "border": "none", "fontSize": "0.76rem",
                                   "borderRadius": "6px", "padding": "5px 12px",
                                   "color": "#fff", "marginRight": "6px",
                                   "boxShadow": f"0 0 10px {PURPLE}44",
                               }),
                            dbc.Button("📋 Copy", id="sast-copy-fix-btn",
                                       color="outline-success", size="sm",
                                       n_clicks=0,
                                       style={"fontSize": "0.74rem", "padding": "5px 10px"}),
                        ], style={"display": "flex", "padding": "10px 14px 8px", "gap": "4px"}),

                        # AI output
                        dcc.Loading(
                            html.Div(id="sast-ai-output",
                                     style={"color": TEXT_COL, "fontSize": "0.82rem",
                                            "padding": "0 14px", "whiteSpace": "pre-wrap",
                                            "lineHeight": "1.7", "minHeight": "20px"}),
                            type="dot", color=PURPLE,
                        ),
                        dcc.Loading(
                            html.Div(id="sast-ai-diff", style={"padding": "0 14px 14px"}),
                            type="dot", color=GREEN,
                        ),
                        dcc.Store(id="sast-ai-fix-text", data=""),

                    ], style={
                        **CARD_STYLE,
                        "borderTop": f"3px solid {PURPLE}",
                        "maxHeight": "660px", "overflowY": "auto",
                    }),
                ], width=3),

            ], className="g-3"),
        ], fluid=True, style={"backgroundColor": BG_DARK, "padding": "0 20px 40px"}),
    ], style={"backgroundColor": BG_DARK, "minHeight": "100vh",
              "fontFamily": "'Inter', 'Segoe UI', sans-serif"})


# ─────────────────────────────────────────────────────────────────────────────
# FINDINGS TABLE RENDERER
# ─────────────────────────────────────────────────────────────────────────────
def _render_findings_table(findings: list, severity_filter: str) -> html.Div:
    if severity_filter != "ALL":
        findings = [f for f in findings if f.get("severity") == severity_filter]
    if not findings:
        return html.Div("No findings." if findings is not None else "Run a scan to see results.",
                        style={"color": TEXT_COL, "padding": "20px", "textAlign": "center"})
    rows = []
    for i, f in enumerate(findings):
        sev   = f.get("severity", "INFO")
        color = SEV_COLOR.get(sev, TEXT_COL)
        rows.append(
            html.Div([
                html.Div([
                    html.Span(SEV_ICON.get(sev, "⚪"), style={"marginRight": "6px"}),
                    html.Span(f.get("rule", "Unknown")[:28],
                              style={"color": "#fff", "fontSize": "0.82rem", "fontWeight": "600"}),
                    html.Span(f" L{f.get('line', '?')}", style={"color": TEXT_COL, "fontSize": "0.72rem",
                                                                  "marginLeft": "auto"}),
                ], style={"display": "flex", "alignItems": "center"}),
                html.Div([
                    html.Span(sev, style={"color": color, "fontSize": "0.7rem", "fontWeight": "bold",
                                          "marginRight": "8px"}),
                    html.Span(f.get("engine", ""), style={"color": TEXT_COL, "fontSize": "0.68rem"}),
                ]),
                html.Div(f.get("code", "")[:80],
                         style={"color": "#aaa", "fontSize": "0.68rem", "fontFamily": "monospace",
                                "overflow": "hidden", "textOverflow": "ellipsis", "whiteSpace": "nowrap",
                                "marginTop": "2px"}),
            ],
            id={"type": "sast-finding-row", "index": i},
            n_clicks=0,
            style={
                "padding": "8px 10px",
                "borderLeft": f"3px solid {color}",
                "borderBottom": "1px solid #222",
                "cursor": "pointer",
                "borderRadius": "0 4px 4px 0",
                "marginBottom": "2px",
                "backgroundColor": "#0d1117",
            }),
        )
    return html.Div(rows)


# ─────────────────────────────────────────────────────────────────────────────
# FINDING DETAIL RENDERER
# ─────────────────────────────────────────────────────────────────────────────
def _render_finding_detail(finding: dict) -> html.Div:
    sev   = finding.get("severity", "INFO")
    color = SEV_COLOR.get(sev, TEXT_COL)
    return html.Div([
        # Title + severity
        html.Div([
            html.Span(SEV_ICON.get(sev, "⚪") + " ", style={"fontSize": "1.2rem"}),
            html.Span(finding.get("rule", "Unknown Rule"),
                      style={"color": "#fff", "fontWeight": "bold", "fontSize": "1rem"}),
            html.Br(),
            _sev_badge(sev),
            html.Span(f"  Line {finding.get('line', '?')}",
                      style={"color": TEXT_COL, "fontSize": "0.75rem", "marginLeft": "8px"}),
        ], style={"marginBottom": "12px"}),

        # IDs + CWE
        dbc.Row([
            dbc.Col([
                html.Div("Rule ID", style={**LABEL_STYLE}),
                html.Code(finding.get("id", "—"), style={"color": CYAN, "fontSize": "0.78rem"}),
            ], width=6),
            dbc.Col([
                html.Div("CWE", style={**LABEL_STYLE}),
                _cwe_link(finding.get("cwe", "")),
            ], width=6),
        ], className="mb-2"),

        # Engine
        html.Div([
            html.Span("Engine: ", style={"color": TEXT_COL, "fontSize": "0.75rem"}),
            html.Span(finding.get("engine", ""), style={"color": ORANGE, "fontSize": "0.75rem"}),
        ], style={"marginBottom": "10px"}),

        # Description
        html.Div("Description", style={**LABEL_STYLE, "marginBottom": "4px"}),
        html.Div(finding.get("message", ""),
                 style={"color": TEXT_COL, "fontSize": "0.82rem", "lineHeight": "1.6",
                        "marginBottom": "12px"}),

        # Vulnerable code
        html.Div("Vulnerable Code", style={**LABEL_STYLE, "marginBottom": "4px"}),
        html.Code(
            finding.get("code", "No code snippet available"),
            style={"backgroundColor": "#0d1117", "color": RED, "padding": "8px 12px",
                   "borderRadius": "6px", "display": "block", "fontSize": "0.78rem",
                   "fontFamily": "monospace", "wordBreak": "break-all",
                   "marginBottom": "12px", "border": f"1px solid {RED}44"},
        ),

        # Fix suggestion (semgrep autofix)
        (html.Div([
            html.Div("Suggested Fix", style={**LABEL_STYLE, "marginBottom": "4px"}),
            html.Code(
                finding.get("fix", ""),
                style={"backgroundColor": "#0d1a0d", "color": GREEN, "padding": "8px 12px",
                       "borderRadius": "6px", "display": "block", "fontSize": "0.78rem",
                       "fontFamily": "monospace", "wordBreak": "break-all",
                       "marginBottom": "12px", "border": f"1px solid {GREEN}44"},
            ),
        ]) if finding.get("fix") else html.Span()),
    ])


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

# ── Load Sample Code callback ────────────────────────────────────────────────
@callback(
    Output("sast-code-input", "value",    allow_duplicate=True),
    Output("sast-lang",       "value",    allow_duplicate=True),
    Input("sast-load-sample-btn", "n_clicks"),
    State("sast-lang",            "value"),
    prevent_initial_call=True,
)
def load_sample(n_clicks, lang):
    if not n_clicks:
        raise PreventUpdate
    # Use python sample if auto or unknown
    effective = lang if lang in SAMPLE_CODE else "python"
    sample_lang = effective
    return SAMPLE_CODE[effective], sample_lang


# ── File upload → populate code textarea ────────────────────────────────────
@callback(
    Output("sast-code-input", "value", allow_duplicate=True),
    Output("sast-lang",       "value"),
    Input("sast-upload",      "contents"),
    State("sast-upload",      "filename"),
    prevent_initial_call=True,
)
def handle_upload(contents, filename):
    if not contents:
        raise PreventUpdate
    import base64
    _, content_string = contents.split(",")
    code = base64.b64decode(content_string).decode("utf-8", errors="replace")
    # Detect language from extension
    ext_map = {".py": "python", ".js": "javascript", ".ts": "typescript",
               ".java": "java", ".php": "php", ".go": "go", ".rb": "ruby",
               ".c": "c_cpp", ".cpp": "c_cpp", ".h": "c_cpp"}
    ext  = os.path.splitext(filename or "")[1].lower()
    lang = ext_map.get(ext, "auto")
    return code, lang


# ── Clear button ─────────────────────────────────────────────────────────────
@callback(
    Output("sast-code-input",    "value",    allow_duplicate=True),
    Output("sast-findings-store","data",     allow_duplicate=True),
    Output("sast-summary-bar",   "children", allow_duplicate=True),
    Output("sast-findings-table","children", allow_duplicate=True),
    Output("sast-finding-detail","children", allow_duplicate=True),
    Output("sast-owasp-panel",   "children", allow_duplicate=True),
    Output("sast-trend-wrapper", "children", allow_duplicate=True),
    Output("sast-ai-diff",       "children", allow_duplicate=True),
    Output("sast-line-indicator","children", allow_duplicate=True),
    Input("sast-clear-btn",      "n_clicks"),
    prevent_initial_call=True,
)
def clear_all(n):
    if not n: raise PreventUpdate
    placeholder = html.Div("Select a finding from the table to see details.",
                            style={"color": TEXT_COL, "padding": "20px",
                                   "textAlign": "center", "fontSize": "0.85rem"})
    return "", [], html.Span(), html.Span(), placeholder, html.Span(), html.Span(), html.Span(), html.Span()


# ── Main scan ────────────────────────────────────────────────────────────────
@callback(
    Output("sast-findings-store",  "data"),
    Output("sast-scan-status",     "children"),
    Output("sast-summary-bar",     "children"),
    Output("sast-findings-table",  "children"),
    Output("sast-owasp-panel",     "children"),
    Output("sast-history-store",   "data",  allow_duplicate=True),
    Output("sast-trend-wrapper",   "children", allow_duplicate=True),
    Input("sast-scan-btn",         "n_clicks"),
    State("sast-code-input",       "value"),
    State("sast-lang",             "value"),
    State("sast-history-store",    "data"),
    prevent_initial_call=True,
)
def run_scan(n, code, lang_hint, history):
    if not n or not code or not code.strip():
        raise PreventUpdate
    try:
        language          = _detect_language(code, lang_hint)
        findings, ecounts = _full_scan(code, language)
        summary           = _summary_bar(findings)
        table             = _render_findings_table(findings, "ALL")
        count             = len(findings)
        crits             = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        eng_detail = "  |  ".join(
            f"{eng}: {n}" for eng, n in ecounts.items() if n > 0
        ) or "no engine results"
        status = (
            f"✅ {count} finding(s)  [{eng_detail}]  —  "
            f"lang: {language.upper()}"
            + (f"  🔴 {crits} CRITICAL" if crits else "")
        )
    except Exception as e:
        findings = []
        summary  = html.Span()
        table    = html.Div(f"Scan error: {e}", style={"color": RED})
        status   = f"❌ Scan failed: {e}"

    # ── Enhancement 1: OWASP breakdown ──────────────────────────────────────
    owasp_panel = _owasp_breakdown(findings)

    # ── Enhancement 4: Scan History Trend ───────────────────────────────────
    import datetime as _dt
    history = list(history or [])
    crits_n = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    highs_n = sum(1 for f in findings if f.get("severity") == "HIGH")
    meds_n  = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    lows_n  = sum(1 for f in findings if f.get("severity") == "LOW")
    try: lang_used = _detect_language(code or "", lang_hint or "auto")
    except Exception: lang_used = "unknown"
    history.append({
        "ts":       _dt.datetime.now().strftime("%H:%M:%S"),
        "lang":     lang_used,
        "total":    len(findings),
        "critical": crits_n,
        "high":     highs_n,
        "medium":   meds_n,
        "low":      lows_n,
    })
    history = history[-30:]  # keep last 30 scans
    # Also write to Neo4j (true fire-and-forget — never blocks scan response)
    _neo_rec = dict(history[-1]) if history else {}
    def _neo_write():
        try:
            import os as _os_neo
            from neo4j import GraphDatabase
            _pw_s = _os_neo.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            _drv  = GraphDatabase.driver(
                "bolt://127.0.0.1:7687", auth=("neo4j", _pw_s),
                connection_timeout=2, max_transaction_retry_time=1,
            )
            with _drv.session() as _sess:
                _sess.run(
                    "CREATE (s:SASTScan {ts:$ts,lang:$lang,total:$total,"
                    "critical:$critical,high:$high,medium:$medium,low:$low})",
                    **_neo_rec,
                )
            _drv.close()
        except Exception:
            pass
    import threading as _thr
    _thr.Thread(target=_neo_write, daemon=True).start()
    trend_chart = _build_trend_chart(history)

    return findings, status, summary, table, owasp_panel, history, trend_chart


# ── Severity filter ───────────────────────────────────────────────────────────
@callback(
    Output("sast-findings-table", "children", allow_duplicate=True),
    Input("sast-filter-sev",      "value"),
    State("sast-findings-store",  "data"),
    prevent_initial_call=True,
)
def filter_findings(sev, findings):
    findings = findings or []
    return _render_findings_table(findings, sev or "ALL")


# ── Row click → populate detail panel ────────────────────────────────────────
@callback(
    Output("sast-finding-detail",   "children"),
    Output("sast-selected-finding", "data"),
    Output("sast-highlight-line",   "data"),
    Output("sast-line-indicator",   "children"),
    Input({"type": "sast-finding-row", "index": dash.ALL}, "n_clicks"),
    State("sast-findings-store", "data"),
    State("sast-filter-sev",     "value"),
    prevent_initial_call=True,
)
def select_finding(n_clicks_list, findings, sev_filter):
    ctx = dash.callback_context
    if not ctx.triggered or not any(n_clicks_list):
        raise PreventUpdate
    triggered = ctx.triggered[0]["prop_id"]
    import json as _j
    idx_raw = _j.loads(triggered.split(".")[0]).get("index", 0)
    if sev_filter and sev_filter != "ALL":
        filtered = [f for f in (findings or []) if f.get("severity") == sev_filter]
    else:
        filtered = findings or []
    if idx_raw >= len(filtered):
        raise PreventUpdate
    finding  = filtered[idx_raw]
    line_no  = finding.get("line") or 0
    sev      = finding.get("severity", "INFO")
    sev_clr  = SEV_COLOR.get(sev, TEXT_COL)
    indicator = html.Div([
        html.Span(f"🎯 Viewing line {line_no} — {finding.get('rule','?')}",
                  style={"color": sev_clr, "fontSize": "0.75rem", "fontWeight": "600"}),
        html.Span(f"  [{sev}]",
                  style={"color": sev_clr, "fontSize": "0.68rem",
                         "background": f"{sev_clr}22", "padding": "1px 6px",
                         "borderRadius": "8px", "marginLeft": "6px"}),
    ], style={"display": "flex", "alignItems": "center", "padding": "3px 6px",
              "backgroundColor": "#161820", "borderRadius": "4px",
              "border": f"1px solid {sev_clr}44"})
    return _render_finding_detail(finding), finding, line_no, indicator


# ── AI Remediation ────────────────────────────────────────────────────────────
@callback(
    Output("sast-ai-output",    "children"),
    Output("sast-ai-diff",      "children"),
    Output("sast-ai-fix-text",  "data"),
    Input("sast-ai-btn",        "n_clicks"),
    State("sast-selected-finding", "data"),
    prevent_initial_call=True,
)
def ai_remediate(n, finding):
    if not n or not finding:
        raise PreventUpdate
    try:
        from llm_engine import call_llm
        prompt = (
            f"You are an application security expert. Analyze this vulnerability and respond "
            f"ONLY with valid JSON in this exact schema: "
            f'{{"explanation": "...", "patched_code": "...", "prevention": "..."}}\n\n'
            f"Rule: {finding.get('rule')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"CWE: {finding.get('cwe')}\n"
            f"Description: {finding.get('message')}\n"
            f"Vulnerable code:\n```\n{finding.get('code')}\n```"
        )
        raw = call_llm(prompt)
        # Try to parse structured JSON
        import json as _json, re as _re
        patched = ""
        explanation = raw
        try:
            m = _re.search(r'\{.*\}', raw, _re.DOTALL)
            if m:
                parsed = _json.loads(m.group())
                explanation = (
                    f"**Why it's vulnerable:** {parsed.get('explanation', '')}\n\n"
                    f"**Prevention:** {parsed.get('prevention', '')}"
                )
                patched = parsed.get("patched_code", "")
        except Exception:
            pass
        diff_div = _render_diff(finding.get("code", ""), patched) if patched else html.Span()
        return explanation, diff_div, patched
    except Exception as e:
        return f"⚠️ LLM unavailable: {e}", html.Span(), ""


def register_sast_callbacks(app):
    """No-op kept for backwards compatibility — validation_layout handles this now."""
    pass


# ── Export JSON ────────────────────────────────────────────────────────────────
@callback(
    Output("sast-export-download", "data", allow_duplicate=True),
    Input("sast-export-json-btn",  "n_clicks"),
    State("sast-findings-store",   "data"),
    prevent_initial_call=True,
)
def export_json(n, findings):
    if not n: raise PreventUpdate
    fname = f"sast_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.json"
    return dcc.send_string(json.dumps(findings or [], indent=2), filename=fname)


# ── Export CSV ────────────────────────────────────────────────────────────────
@callback(
    Output("sast-export-download", "data"),
    Input("sast-export-csv-btn",   "n_clicks"),
    State("sast-findings-store",   "data"),
    prevent_initial_call=True,
)
def export_csv(n, findings):
    if not n: raise PreventUpdate
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "rule", "severity", "cwe", "line", "engine", "message", "code"])
    writer.writeheader()
    for f in (findings or []):
        writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    fname = f"sast_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return dcc.send_string(buf.getvalue(), filename=fname)


# ─────────────────────────────────────────────────────────────────────────────
# Copy Fix to Clipboard — clientside callback (Enhancement 3)
# ─────────────────────────────────────────────────────────────────────────────
dash.clientside_callback(
    """
    function(n, fix_text) {
        if (!n || !fix_text) return window.dash_clientside.no_update;
        navigator.clipboard.writeText(fix_text).catch(function(e){
            console.warn('Clipboard copy failed:', e);
        });
        return window.dash_clientside.no_update;
    }
    """,
    Output("sast-copy-fix-btn", "children"),
    Input("sast-copy-fix-btn",  "n_clicks"),
    State("sast-ai-fix-text",   "data"),
    prevent_initial_call=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# Code Textarea Line Scroll & Flash — clientside (Enhancement 2)
# ─────────────────────────────────────────────────────────────────────────────
dash.clientside_callback(
    """
    function(line_no, code_val) {
        if (!line_no || !code_val) return window.dash_clientside.no_update;
        var ta = document.getElementById('sast-code-input');
        if (!ta) return window.dash_clientside.no_update;
        // Split into lines and compute character offset for target line
        var lines = code_val.split('\\n');
        var targetLine = Math.max(0, line_no - 1);
        var charOffset = 0;
        for (var i = 0; i < targetLine && i < lines.length; i++) {
            charOffset += lines[i].length + 1;  // +1 for newline
        }
        // Scroll textarea to make the line visible
        ta.focus();
        ta.setSelectionRange(charOffset, charOffset + (lines[targetLine] || '').length);
        // Estimate approximate scroll position
        var lineHeight = parseFloat(getComputedStyle(ta).lineHeight) || 18;
        var scrollTop = Math.max(0, (targetLine - 3) * lineHeight);
        ta.scrollTop = scrollTop;
        // Flash border red briefly to indicate located line
        ta.style.boxShadow = '0 0 0 2px #f54254';
        ta.style.transition = 'box-shadow 0.1s';
        setTimeout(function() {
            ta.style.boxShadow = '';
        }, 1400);
        return window.dash_clientside.no_update;
    }
    """,
    Output("sast-highlight-line", "data", allow_duplicate=True),
    Input("sast-highlight-line",  "data"),
    State("sast-code-input",      "value"),
    prevent_initial_call=True,
)
