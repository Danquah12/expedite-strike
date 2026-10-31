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
     "pattern": r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*["\'].*\+|f["\'].*SELECT|execute\s*\(\s*["\'].*%',
     "severity": "HIGH", "cwe": "CWE-89",
     "message": "Possible SQL injection via string concatenation. Use parameterized queries."},
    # Cryptography
    {"id": "CRY-001", "name": "Weak Hash: MD5",
     "pattern": r'\bmd5\s*\(',
     "severity": "MEDIUM", "cwe": "CWE-327",
     "message": "MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords."},
    {"id": "CRY-002", "name": "Weak Hash: SHA1",
     "pattern": r'\bsha1\s*\(',
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
     "pattern": r'(?i)(render_template_string|from_string)\s*\(.*request\.',
     "severity": "CRITICAL", "cwe": "CWE-94",
     "message": "User input passed to template renderer — SSTI possible."},
    # SSRF
    {"id": "SSRF-001", "name": "SSRF Risk — requests with user input",
     "pattern": r'requests\.(get|post|put|delete)\s*\(.*request\.',
     "severity": "HIGH", "cwe": "CWE-918",
     "message": "requests call with user-controlled URL — potential Server-Side Request Forgery."},
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


def _full_scan(code: str, language: str) -> tuple:
    """Run all engines in parallel threads, merge results. Returns (findings, engine_counts)."""
    results     = []
    ext         = LANG_EXTENSIONS.get(language, ".py")
    containers  = [[] for _ in range(3)]
    labels      = ["Regex", "Semgrep", "Bandit"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, prefix="/tmp/sast_") as f:
        f.write(code)
        tmpfile = f.name

    def t0(): containers[0].extend(_run_regex_scan(code))
    def t1(): containers[1].extend(_run_semgrep(code, language, tmpfile))
    def t2():
        if language == "python":
            containers[2].extend(_run_bandit(code, tmpfile))

    threads = []
    for fn in [t0, t1, t2]:
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
# LAYOUT
# ─────────────────────────────────────────────────────────────────────────────
def layout_sast_dashboard():
    return html.Div([
        dcc.Store(id="sast-findings-store", storage_type="session", data=[]),
        dcc.Store(id="sast-selected-finding", storage_type="session", data=None),
        dcc.Download(id="sast-export-download"),

        # ── Header ──────────────────────────────────────────────────────────
        html.Div([
            html.H3("🔬 Static Application Security Testing",
                    style={"color": "#fff", "marginBottom": "0"}),
            html.P("Multi-engine scanner: Semgrep · Bandit · Built-in Regex Rules",
                   style={"color": TEXT_COL, "fontSize": "0.85rem"}),
        ], style={"padding": "20px 20px 10px"}),

        dbc.Container([
            # ── Severity Summary ──────────────────────────────────────────
            html.Div(id="sast-summary-bar"),

            dbc.Row([
                # ── LEFT: Code Input ──────────────────────────────────────
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(
                            html.Span("📝 Code Input", style={"color": CYAN, "fontWeight": "bold"}),
                            style={"backgroundColor": "#1a1c24", "border": "none"}
                        ),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Language", style=LABEL_STYLE),
                                    dbc.Select(id="sast-lang", options=[
                                        {"label": "🔍 Auto-Detect",    "value": "auto"},
                                        {"label": "🐍 Python",       "value": "python"},
                                        {"label": "🟨 JavaScript",    "value": "javascript"},
                                        {"label": "☕ Java",          "value": "java"},
                                        {"label": "🐘 PHP",           "value": "php"},
                                        {"label": "🐹 Go",            "value": "go"},
                                        {"label": "💎 Ruby",          "value": "ruby"},
                                        {"label": "🔷 TypeScript",    "value": "typescript"},
                                        {"label": "⚙️ C / C++",      "value": "c_cpp"},
                                    ], value="auto", style=INPUT_STYLE),
                                ], width=6),
                                dbc.Col([
                                    html.Label("Upload File", style=LABEL_STYLE),
                                    dcc.Upload(
                                        id="sast-upload",
                                        children=html.Div([
                                            "Drag & Drop or ",
                                            html.A("Browse", style={"color": CYAN}),
                                        ]),
                                        style={
                                            "border": "1px dashed #555",
                                            "borderRadius": "6px",
                                            "padding": "6px 10px",
                                            "textAlign": "center",
                                            "color": TEXT_COL,
                                            "fontSize": "0.8rem",
                                            "cursor": "pointer",
                                            "backgroundColor": "#111",
                                        },
                                        multiple=False,
                                    ),
                                ], width=6),
                            ], className="mb-2"),

                            dcc.Textarea(
                                id="sast-code-input",
                                placeholder="Paste your code here, or upload a file above...\n\n# Example (Python):\nimport pickle\ndata = pickle.loads(user_input)  # ← vulnerability\n\npassword = 'Admin123!'           # ← hardcoded credential\n",
                                style={**INPUT_STYLE, "width": "100%", "height": "420px",
                                       "fontFamily": "monospace", "fontSize": "0.82rem",
                                       "resize": "vertical"},
                            ),

                            html.Div([
                                dbc.Button([
                                    html.I(className="bi bi-shield-exclamation me-2"),
                                    "▶ Scan Code",
                                ], id="sast-scan-btn", color="danger", size="sm",
                                   style={"fontWeight": "bold", "marginRight": "8px"}),
                                dbc.Button("🗑 Clear", id="sast-clear-btn",
                                           color="outline-secondary", size="sm",
                                           style={"marginRight": "8px"}),
                                dbc.Button("💾 Export JSON", id="sast-export-json-btn",
                                           color="outline-info", size="sm",
                                           style={"marginRight": "8px"}),
                                dbc.Button("📊 Export CSV", id="sast-export-csv-btn",
                                           color="outline-success", size="sm"),
                            ], style={"marginTop": "10px", "display": "flex", "alignItems": "center"}),

                            dcc.Loading(
                                html.Div(id="sast-scan-status",
                                         style={"color": TEXT_COL, "fontSize": "0.78rem",
                                                "marginTop": "8px", "minHeight": "20px"}),
                                type="dot", color=CYAN,
                            ),
                        ]),
                    ], style=CARD_STYLE),
                ], width=4),

                # ── MIDDLE: Findings Table ────────────────────────────────
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(
                            dbc.Row([
                                dbc.Col(html.Span("🚨 Findings", style={"color": RED, "fontWeight": "bold"}), width=6),
                                dbc.Col(dbc.Select(
                                    id="sast-filter-sev",
                                    options=[{"label": "All Severities", "value": "ALL"}] +
                                            [{"label": f"{SEV_ICON[s]} {s}", "value": s} for s in SEV_ORDER],
                                    value="ALL",
                                    size="sm",
                                    style={**INPUT_STYLE, "fontSize": "0.78rem"},
                                ), width=6),
                            ]),
                            style={"backgroundColor": "#1a1c24", "border": "none"},
                        ),
                        dbc.CardBody([
                            html.Div(id="sast-findings-table",
                                     style={"overflowY": "auto", "maxHeight": "540px"}),
                        ], style={"padding": "8px"}),
                    ], style=CARD_STYLE),
                ], width=4),

                # ── RIGHT: Finding Detail ─────────────────────────────────
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(
                            html.Span("🔎 Finding Detail", style={"color": PURPLE, "fontWeight": "bold"}),
                            style={"backgroundColor": "#1a1c24", "border": "none"}
                        ),
                        dbc.CardBody([
                            dcc.Loading(
                                html.Div(id="sast-finding-detail",
                                         children=html.Div(
                                             "Select a finding from the table to see details.",
                                             style={"color": TEXT_COL, "padding": "20px",
                                                    "textAlign": "center", "fontSize": "0.85rem"}
                                         )),
                                type="circle", color=PURPLE,
                            ),
                            html.Hr(style={"borderColor": "#333", "margin": "12px 0"}),
                            dbc.Button([
                                html.I(className="bi bi-stars me-2"),
                                "🤖 AI Remediation Advice",
                            ], id="sast-ai-btn", color="outline-light", size="sm",
                               style={"fontSize": "0.8rem", "border": "1px solid #555"}),
                            dcc.Loading(
                                html.Div(id="sast-ai-output",
                                         style={"color": TEXT_COL, "fontSize": "0.82rem",
                                                "marginTop": "10px", "whiteSpace": "pre-wrap",
                                                "lineHeight": "1.6"}),
                                type="dot", color=PURPLE,
                            ),
                        ], style={"padding": "12px", "overflowY": "auto", "maxHeight": "560px"}),
                    ], style=CARD_STYLE),
                ], width=4),
            ]),
        ], fluid=True, style={"backgroundColor": BG_DARK, "padding": "0 20px 40px"}),
    ], style={"backgroundColor": BG_DARK, "minHeight": "100vh", "fontFamily": "Inter, sans-serif"})


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
    Input("sast-clear-btn",      "n_clicks"),
    prevent_initial_call=True,
)
def clear_all(n):
    if not n: raise PreventUpdate
    placeholder = html.Div("Select a finding from the table to see details.",
                            style={"color": TEXT_COL, "padding": "20px",
                                   "textAlign": "center", "fontSize": "0.85rem"})
    return "", [], html.Span(), html.Span(), placeholder


# ── Main scan ────────────────────────────────────────────────────────────────
@callback(
    Output("sast-findings-store", "data"),
    Output("sast-scan-status",    "children"),
    Output("sast-summary-bar",    "children"),
    Output("sast-findings-table", "children"),
    Input("sast-scan-btn",        "n_clicks"),
    State("sast-code-input",      "value"),
    State("sast-lang",            "value"),
    prevent_initial_call=True,
)
def run_scan(n, code, lang_hint):
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
    return findings, status, summary, table


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
    finding = filtered[idx_raw]
    return _render_finding_detail(finding), finding


# ── AI Remediation ────────────────────────────────────────────────────────────
@callback(
    Output("sast-ai-output", "children"),
    Input("sast-ai-btn",     "n_clicks"),
    State("sast-selected-finding", "data"),
    prevent_initial_call=True,
)
def ai_remediate(n, finding):
    if not n or not finding:
        raise PreventUpdate
    try:
        from llm_engine import call_llm
        prompt = (
            f"You are an application security expert. Analyze this code vulnerability:\n\n"
            f"Rule: {finding.get('rule')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"CWE: {finding.get('cwe')}\n"
            f"Description: {finding.get('message')}\n"
            f"Vulnerable code:\n```\n{finding.get('code')}\n```\n\n"
            f"Provide:\n"
            f"1. A brief explanation of WHY this is vulnerable\n"
            f"2. A corrected, secure code snippet\n"
            f"3. One sentence on prevention best practice"
        )
        return call_llm(prompt)
    except Exception as e:
        return f"⚠️ LLM unavailable: {e}"


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
