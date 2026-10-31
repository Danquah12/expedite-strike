"""
AegisProbe — Burp Suite-Like Web Assessment Engine
====================================================
Plugin-based active/passive web vulnerability scanner.
Provides: crawling, active attack plugins (SQLi, XSS, SSRF, LFI, CMDI,
IDOR, JWT, AuthBypass, OpenRedirect, CORS, Cookies, InfoDisclosure,
Intruder) + passive posture checks.
"""
import os
import re
import sys
import time
import json
import html
import base64
import hashlib
import threading
import traceback
import concurrent.futures
import urllib.parse
from datetime import datetime, timezone

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

SESS = requests.Session()
SESS.verify = False
SESS.headers.update({"User-Agent": "AegisProbe/2.0 (Security Assessment)"})

# ─────────────────────────────────────────────────────────────────────
# BASE PLUGIN
# ─────────────────────────────────────────────────────────────────────
class BasePlugin:
    """Base class for all AegisProbe modules."""
    PLUGIN_TYPE = "passive"   # 'passive' or 'active'

    def get_name(self) -> str:
        return "BasePlugin"

    def scan(self, url: str, on_output) -> list[dict]:
        """Run the module and return a list of finding dicts."""
        return []

    def _finding(self, name, severity, url, param="", payload="",
                  evidence="", cwe="", cvss=0.0, method="GET"):
        return {
            "plugin":   self.get_name(),
            "name":     name,
            "severity": severity,
            "method":   method,
            "url":      url,
            "param":    param,
            "payload":  payload,
            "evidence": evidence[:300] if evidence else "",
            "cwe":      cwe,
            "cvss":     cvss,
        }


# ─────────────────────────────────────────────────────────────────────
# PASSIVE: Security Headers
# ─────────────────────────────────────────────────────────────────────
class SecurityHeadersPlugin(BasePlugin):
    """Check HTTP response headers for missing security controls."""
    PLUGIN_TYPE = "passive"

    def get_name(self): return "Security Headers"

    def scan(self, url, on_output):
        findings = []
        try:
            on_output(f"[SecurityHeaders] Checking headers for {url}\n")
            r = SESS.get(url, timeout=10)
            h = r.headers
            checks = [
                ("X-Frame-Options", "Content-Security-Policy",
                 "Clickjacking Protection Missing", "Low", "CWE-1021", 4.3),
                ("Strict-Transport-Security", None,
                 "HSTS Not Enforced", "Low", "CWE-319", 5.3),
                ("X-Content-Type-Options", None,
                 "MIME Sniffing Not Blocked (X-Content-Type-Options)", "Low", "CWE-693", 4.3),
                ("Content-Security-Policy", None,
                 "No Content Security Policy", "Medium", "CWE-1021", 5.4),
                ("Referrer-Policy", None,
                 "Referrer-Policy Missing", "Information", "CWE-200", 2.0),
                ("Permissions-Policy", None,
                 "Permissions-Policy Missing", "Information", "CWE-732", 2.0),
            ]
            for h1, h2, name, sev, cwe, cvss in checks:
                present = h1 in h or (h2 and h2 in h)
                if not present:
                    findings.append(self._finding(name, sev, url, cwe=cwe, cvss=cvss,
                        evidence=f"Missing header: {h1}"))
                    on_output(f"  [!] {sev}: {name}\n")
            if "Server" in h:
                findings.append(self._finding(
                    "Server Version Disclosure", "Information", url,
                    evidence=f"Server: {h['Server']}", cwe="CWE-200", cvss=2.0))
                on_output(f"  [!] Info: Server header discloses: {h['Server']}\n")
            if "X-Powered-By" in h:
                findings.append(self._finding(
                    "Technology Disclosure (X-Powered-By)", "Information", url,
                    evidence=f"X-Powered-By: {h['X-Powered-By']}", cwe="CWE-200", cvss=2.0))
        except Exception as e:
            on_output(f"  [SecurityHeaders] Error: {e}\n")
        return findings


# ─────────────────────────────────────────────────────────────────────
# PASSIVE: Cookie Security
# ─────────────────────────────────────────────────────────────────────
class CookieAnalysisPlugin(BasePlugin):
    """Analyse Set-Cookie headers for missing security flags."""
    PLUGIN_TYPE = "passive"

    def get_name(self): return "Cookie Security"

    def scan(self, url, on_output):
        findings = []
        try:
            on_output(f"[CookieSecurity] Analysing cookies for {url}\n")
            r = SESS.get(url, timeout=10)
            for k, v in r.cookies.items():
                cobj = r.cookies.get_dict()
                raw_header = r.headers.get("Set-Cookie", "")
                flags = raw_header.lower()
                if "secure" not in flags:
                    findings.append(self._finding(
                        f"Cookie '{k}' Missing Secure Flag", "Medium", url,
                        evidence=f"Cookie: {k}={v[:30]}...", cwe="CWE-614", cvss=5.3))
                    on_output(f"  [!] Medium: Cookie '{k}' missing Secure flag\n")
                if "httponly" not in flags:
                    findings.append(self._finding(
                        f"Cookie '{k}' Missing HttpOnly Flag", "Medium", url,
                        evidence=f"Cookie: {k}={v[:30]}...", cwe="CWE-1004", cvss=5.3))
                    on_output(f"  [!] Medium: Cookie '{k}' missing HttpOnly flag\n")
                if "samesite" not in flags:
                    findings.append(self._finding(
                        f"Cookie '{k}' Missing SameSite Attribute (CSRF risk)", "Low", url,
                        evidence=f"Cookie: {k}", cwe="CWE-352", cvss=4.3))
        except Exception as e:
            on_output(f"  [CookieSecurity] Error: {e}\n")
        return findings


# ─────────────────────────────────────────────────────────────────────
# PASSIVE: CORS Misconfiguration
# ─────────────────────────────────────────────────────────────────────
class CORSPlugin(BasePlugin):
    """Detect CORS misconfiguration: wildcard or reflected origin."""
    PLUGIN_TYPE = "passive"

    def get_name(self): return "CORS Misconfiguration"

    def scan(self, url, on_output):
        findings = []
        try:
            on_output(f"[CORS] Testing CORS policy for {url}\n")
            evil = "https://evil.attacker.com"
            r = SESS.get(url, timeout=10, headers={"Origin": evil})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                findings.append(self._finding(
                    "CORS: Wildcard Allow-Origin", "Medium", url,
                    evidence=f"Access-Control-Allow-Origin: *", cwe="CWE-942", cvss=6.5))
                on_output("  [!] Medium: CORS wildcard Access-Control-Allow-Origin: *\n")
            elif acao == evil:
                sev = "High" if acac.lower() == "true" else "Medium"
                findings.append(self._finding(
                    f"CORS: Reflected Origin {'+ Credentials' if acac else ''}", sev, url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}", cwe="CWE-942", cvss=8.1))
                on_output(f"  [!] {sev}: CORS reflects attacker origin\n")
        except Exception as e:
            on_output(f"  [CORS] Error: {e}\n")
        return findings


# ─────────────────────────────────────────────────────────────────────
# PASSIVE: Information Disclosure
# ─────────────────────────────────────────────────────────────────────
class InfoDisclosurePlugin(BasePlugin):
    """Probe for sensitive file exposure and version strings."""
    PLUGIN_TYPE = "passive"

    def get_name(self): return "Information Disclosure"

    PATHS = [
        ("/.env",            "Environment File Exposed",            "Critical", "CWE-538", 9.8),
        ("/.git/config",     "Git Repository Exposed",              "Critical", "CWE-538", 9.0),
        ("/robots.txt",      "Robots.txt Discloses Hidden Paths",   "Information", "CWE-200", 2.0),
        ("/sitemap.xml",     "Sitemap Exposes Full URL Structure",   "Information", "CWE-200", 2.0),
        ("/phpinfo.php",     "PHP Info Page Exposed",               "High", "CWE-200", 7.5),
        ("/server-status",   "Apache Server Status Exposed",        "High", "CWE-200", 7.5),
        ("/web.config",      "Web.config Exposed",                  "Critical", "CWE-538", 9.1),
        ("/backup.zip",      "Backup Archive Exposed",              "Critical", "CWE-538", 9.5),
        ("/api/swagger.json","Swagger/OpenAPI Spec Exposed",        "Medium", "CWE-200", 5.0),
        ("/api/docs",        "API Documentation Exposed",           "Medium", "CWE-200", 5.0),
        ("/.DS_Store",       "macOS .DS_Store Leaked",              "Low", "CWE-200", 3.5),
    ]

    def scan(self, url, on_output):
        findings = []
        base = url.rstrip("/")
        on_output(f"[InfoDisclosure] Probing {len(self.PATHS)} paths on {base}\n")
        for path, name, sev, cwe, cvss in self.PATHS:
            try:
                r = SESS.get(f"{base}{path}", timeout=8, allow_redirects=False)
                if r.status_code in (200, 206):
                    findings.append(self._finding(
                        name, sev, f"{base}{path}",
                        evidence=r.text[:200], cwe=cwe, cvss=cvss))
                    on_output(f"  [!] {sev}: {name} — {base}{path}\n")
            except Exception:
                pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: SQL Injection
# ─────────────────────────────────────────────────────────────────────
class SQLiPlugin(BasePlugin):
    """Detect error-based and time-based SQL injection in GET params."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "SQL Injection"

    ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(\):",
        r"supplied argument is not a valid mysqli",
        r"ORA-\d{5}",
        r"microsoft ole db provider for sql server",
        r"syntax error.*near",
    ]
    PAYLOADS = ["'", "''", "'--", "' OR '1'='1", "1 AND 1=2", "\" OR \"1\"=\"1"]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[SQLi] Testing SQL injection on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            params = {"id": ["1"], "q": ["test"]}
        for param in list(params.keys())[:5]:
            for payload in self.PAYLOADS:
                try:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=8)
                    body = r.text.lower()
                    for pat in self.ERROR_PATTERNS:
                        if re.search(pat, body, re.IGNORECASE):
                            findings.append(self._finding(
                                "SQL Injection (Error-Based)", "Critical", test_url,
                                param=param, payload=payload,
                                evidence=body[max(0,body.find(pat[:10])-50):][:200],
                                cwe="CWE-89", cvss=9.8))
                            on_output(f"  [!!!] CRITICAL: SQLi in param '{param}' payload={payload!r}\n")
                            break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Reflected XSS
# ─────────────────────────────────────────────────────────────────────
class XSSPlugin(BasePlugin):
    """Detect reflected XSS in URL query parameters."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Cross-Site Scripting (XSS)"

    PAYLOADS = [
        '<script>alert("AEGIS")</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[XSS] Testing reflected XSS on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            params = {"q": ["test"], "search": ["test"], "name": ["test"]}
        for param in list(params.keys())[:5]:
            for payload in self.PAYLOADS:
                try:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=8)
                    if payload in r.text or html.unescape(payload) in r.text:
                        findings.append(self._finding(
                            "Reflected Cross-Site Scripting (XSS)", "High", test_url,
                            param=param, payload=payload,
                            evidence=r.text[:200], cwe="CWE-79", cvss=7.2))
                        on_output(f"  [!] HIGH: XSS reflected in param '{param}'\n")
                        break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: SSRF
# ─────────────────────────────────────────────────────────────────────
class SSRFPlugin(BasePlugin):
    """Probe URL parameters for Server-Side Request Forgery."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Server-Side Request Forgery (SSRF)"

    SSRF_PARAMS = ["url", "path", "redirect", "next", "target", "link", "src", "img",
                   "file", "callback", "uri", "endpoint", "proxy", "load"]
    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://127.0.0.1/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/",
        "http://[::1]/",
    ]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[SSRF] Testing SSRF vectors on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        ssrf_candidates = {k for k in params if k.lower() in self.SSRF_PARAMS}
        if not ssrf_candidates:
            ssrf_candidates = {"url", "path"}
        for param in ssrf_candidates:
            for payload in self.PAYLOADS[:3]:
                try:
                    test_params = dict(params) if params else {}
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=6, allow_redirects=False)
                    if r.status_code in (200, 301, 302) and (
                        "root:" in r.text or "ami-id" in r.text or
                        r.headers.get("Location", "").startswith("http://localhost")
                    ):
                        findings.append(self._finding(
                            "Server-Side Request Forgery (SSRF)", "Critical", test_url,
                            param=param, payload=payload,
                            evidence=r.text[:200], cwe="CWE-918", cvss=9.0))
                        on_output(f"  [!!!] CRITICAL: SSRF in param '{param}' — {payload}\n")
                    elif r.status_code == 200 and len(r.text) > 100:
                        findings.append(self._finding(
                            "Potential SSRF (Unvalidated Redirect/Fetch)", "Medium", test_url,
                            param=param, payload=payload,
                            evidence=r.text[:100], cwe="CWE-918", cvss=6.5))
                        on_output(f"  [~] Medium: Potential SSRF response in '{param}'\n")
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Open Redirect
# ─────────────────────────────────────────────────────────────────────
class OpenRedirectPlugin(BasePlugin):
    """Test URL parameters for open redirect vulnerabilities."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Open Redirect"

    REDIRECT_PARAMS = ["redirect", "next", "url", "goto", "return", "returnurl",
                       "continue", "dest", "destination", "forward", "to"]
    PAYLOADS = [
        "//evil.attacker.com",
        "https://evil.attacker.com",
        "////evil.attacker.com",
        "/\\evil.attacker.com",
        "javascript:alert(1)",
    ]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[OpenRedirect] Testing redirect parameters on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        candidates = {k for k in params if k.lower() in self.REDIRECT_PARAMS}
        if not candidates:
            candidates = {"redirect", "next", "url"}
        for param in candidates:
            for payload in self.PAYLOADS:
                try:
                    test_params = dict(params) if params else {}
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=6, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if "evil.attacker.com" in loc or loc.startswith("javascript:"):
                        findings.append(self._finding(
                            "Open Redirect", "High", test_url,
                            param=param, payload=payload,
                            evidence=f"Location: {loc}", cwe="CWE-601", cvss=7.4))
                        on_output(f"  [!] HIGH: Open Redirect in '{param}' → {loc}\n")
                        break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Local File Inclusion
# ─────────────────────────────────────────────────────────────────────
class LFIPlugin(BasePlugin):
    """Test file path parameters for Local File Inclusion."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Local File Inclusion (LFI)"

    FILE_PARAMS = ["file", "page", "include", "path", "template", "lang",
                   "module", "document", "view", "load", "read"]
    PAYLOADS = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "....//....//Windows/System32/drivers/etc/hosts",
        "php://filter/convert.base64-encode/resource=index",
    ]
    SIGNATURES = ["root:x:", "[boot loader]", "root:!:", "bin:x:", "daemon:x:"]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[LFI] Testing file inclusion on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        candidates = {k for k in params if k.lower() in self.FILE_PARAMS}
        if not candidates:
            candidates = {"file", "page"}
        for param in candidates:
            for payload in self.PAYLOADS:
                try:
                    test_params = dict(params) if params else {}
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=8)
                    for sig in self.SIGNATURES:
                        if sig in r.text:
                            findings.append(self._finding(
                                "Local File Inclusion (LFI)", "Critical", test_url,
                                param=param, payload=payload,
                                evidence=r.text[:200], cwe="CWE-22", cvss=9.8))
                            on_output(f"  [!!!] CRITICAL: LFI in '{param}' — signature '{sig}' found!\n")
                            break
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Command Injection
# ─────────────────────────────────────────────────────────────────────
class CMDIPlugin(BasePlugin):
    """Test parameters for OS command injection."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Command Injection (CMDI)"

    PAYLOADS = [
        "; id", "| id", "& id", "` id`",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "$(id)", "; sleep 3 #",
    ]
    SIGNATURES = ["uid=", "gid=", "root:", "www-data"]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[CMDI] Testing command injection on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            params = {"cmd": ["test"], "exec": ["test"], "q": ["test"]}
        for param in list(params.keys())[:4]:
            for payload in self.PAYLOADS[:4]:
                try:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    t0 = time.time()
                    r = SESS.get(test_url, timeout=10)
                    elapsed = time.time() - t0
                    for sig in self.SIGNATURES:
                        if sig in r.text:
                            findings.append(self._finding(
                                "OS Command Injection", "Critical", test_url,
                                param=param, payload=payload,
                                evidence=r.text[:200], cwe="CWE-78", cvss=10.0))
                            on_output(f"  [!!!] CRITICAL: CMDI in '{param}' — output: {r.text[:80]}\n")
                            break
                    if "sleep 3" in payload and elapsed > 2.5:
                        findings.append(self._finding(
                            "Blind Command Injection (Time-Based)", "Critical", test_url,
                            param=param, payload=payload,
                            evidence=f"Response delay: {elapsed:.1f}s", cwe="CWE-78", cvss=10.0))
                        on_output(f"  [!!!] CRITICAL: Blind CMDI (delay {elapsed:.1f}s) in '{param}'\n")
                except Exception:
                    pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: IDOR
# ─────────────────────────────────────────────────────────────────────
class IDORPlugin(BasePlugin):
    """Detect Insecure Direct Object Reference via numeric ID fuzzing."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Insecure Direct Object Reference (IDOR)"

    def scan(self, url, on_output):
        findings = []
        on_output(f"[IDOR] Testing IDOR on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        id_params = {k for k in params if k.lower() in ("id","user_id","uid","account","order","doc","file_id","record")}
        if not id_params and re.search(r"/\d+", parsed.path):
            # try path-based numeric IDs
            baseline = SESS.get(url, timeout=8)
            for offset in (1, -1, 99999):
                try:
                    new_path = re.sub(r"(\d+)", lambda m: str(int(m.group()) + offset), parsed.path, count=1)
                    test_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
                    r = SESS.get(test_url, timeout=8)
                    if r.status_code == 200 and len(r.text) > 100 and r.text != baseline.text:
                        findings.append(self._finding(
                            "Potential IDOR (Path-Based ID Enumeration)", "High", test_url,
                            param="path_id", payload=str(offset),
                            evidence=f"Status 200, length {len(r.text)}", cwe="CWE-639", cvss=8.1))
                        on_output(f"  [!] HIGH: Potential IDOR — {test_url}\n")
                except Exception:
                    pass
            return findings
        for param in id_params:
            try:
                orig_val = params[param][0]
                baseline = SESS.get(url, timeout=8)
                for new_val in [str(int(orig_val)+1), str(int(orig_val)-1), "0", "99999"]:
                    test_params = dict(params)
                    test_params[param] = [new_val]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=8)
                    if r.status_code == 200 and r.text != baseline.text and len(r.text) > 50:
                        findings.append(self._finding(
                            "Potential IDOR (Param Enumeration)", "High", test_url,
                            param=param, payload=new_val,
                            evidence=f"Original ID {orig_val} → new ID {new_val} returned different data",
                            cwe="CWE-639", cvss=8.1))
                        on_output(f"  [!] HIGH: IDOR — param '{param}' value {new_val} returned different data\n")
                        break
            except (ValueError, Exception):
                pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: JWT Weakness
# ─────────────────────────────────────────────────────────────────────
class JWTPlugin(BasePlugin):
    """Detect JWT 'alg:none' bypass and weak HMAC secrets."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "JWT Weakness"

    WEAK_SECRETS = ["secret", "password", "123456", "changeme",
                    "jwt_secret", "your-256-bit-secret", "supersecret"]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[JWT] Probing for JWT tokens on {url}\n")
        try:
            r = SESS.get(url, timeout=10)
            # Check cookies and headers for JWTs
            jwt_sources = []
            auth = r.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                jwt_sources.append(auth.split(" ", 1)[1])
            for name, val in r.cookies.items():
                if val.count(".") == 2:
                    jwt_sources.append(val)
            # Also check response body
            tokens = re.findall(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', r.text)
            jwt_sources.extend(tokens)
            for token in set(jwt_sources):
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    header_json = json.loads(base64.b64decode(parts[0] + "==").decode("utf-8", errors="ignore"))
                    alg = header_json.get("alg", "").lower()
                    on_output(f"  [JWT] Token found — alg: {alg}\n")
                    if alg in ("none", "", "null"):
                        findings.append(self._finding(
                            "JWT Algorithm 'none' Bypass", "Critical", url,
                            payload=token[:40]+"...", cwe="CWE-327", cvss=9.8,
                            evidence="alg:none allows unsigned token forgery"))
                        on_output("  [!!!] CRITICAL: JWT alg=none bypass!\n")
                    if alg in ("hs256", "hs384", "hs512"):
                        findings.append(self._finding(
                            "JWT Uses Weak Symmetric Algorithm (HS256)", "Medium", url,
                            payload=token[:40]+"...", cwe="CWE-327", cvss=6.5,
                            evidence="HMAC secret may be brutable"))
                        on_output("  [~] Medium: JWT uses HS256 — recommend HMAC secret strength audit\n")
                except Exception:
                    pass
            if not jwt_sources:
                on_output("  [JWT] No JWT tokens detected at this endpoint\n")
        except Exception as e:
            on_output(f"  [JWT] Error: {e}\n")
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Authentication Bypass
# ─────────────────────────────────────────────────────────────────────
class AuthBypassPlugin(BasePlugin):
    """Test for forced browsing, HTTP verb tampering, and header bypasses."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Authentication Bypass"

    ADMIN_PATHS = [
        "/admin", "/admin/", "/dashboard", "/management",
        "/api/admin", "/api/v1/users", "/api/v1/admin",
        "/wp-admin", "/phpmyadmin", "/server-status",
        "/actuator", "/actuator/env", "/actuator/beans",
    ]
    BYPASS_HEADERS = {
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Forwarded-For": "127.0.0.1",
    }

    def scan(self, url, on_output):
        findings = []
        base = url.rstrip("/")
        on_output(f"[AuthBypass] Testing forced browsing + verb tampering on {base}\n")
        for path in self.ADMIN_PATHS:
            try:
                r = SESS.get(f"{base}{path}", timeout=6, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 200:
                    findings.append(self._finding(
                        f"Admin/Sensitive Path Accessible: {path}", "High",
                        f"{base}{path}", cwe="CWE-425", cvss=8.6,
                        evidence=r.text[:150]))
                    on_output(f"  [!] HIGH: Admin path accessible: {base}{path}\n")
            except Exception:
                pass
        # Header bypass
        for header, value in self.BYPASS_HEADERS.items():
            try:
                r = SESS.get(f"{base}/admin", timeout=6,
                             headers={header: value}, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 100:
                    findings.append(self._finding(
                        f"Auth Bypass via Header: {header}", "Critical",
                        f"{base}/admin", cwe="CWE-863", cvss=9.1,
                        evidence=f"Header {header}: {value} returned 200"))
                    on_output(f"  [!!!] CRITICAL: Auth bypass via {header}\n")
            except Exception:
                pass
        return findings


# ─────────────────────────────────────────────────────────────────────
# ACTIVE: Intruder (Fuzzer)
# ─────────────────────────────────────────────────────────────────────
class IntruderPlugin(BasePlugin):
    """Fuzz URL parameters with a built-in mixed payload wordlist."""
    PLUGIN_TYPE = "active"

    def get_name(self): return "Intruder (Parameter Fuzzer)"

    WORDLIST = [
        # Admin paths
        "admin", "administrator", "root", "superuser", "manager",
        # SQLi
        "'", "' OR 1=1--", "\" OR 1=1--", "1; DROP TABLE users--",
        # XSS
        "<script>", '<img src=x onerror="alert(1)">',
        # Path traversal
        "../", "../../etc/passwd", "....//etc/passwd",
        # Template injection
        "{{7*7}}", "${7*7}", "<%=7*7%>",
        # Null bytes / special chars
        "%00", "%0a", "%09", "\\n",
    ]

    def scan(self, url, on_output):
        findings = []
        on_output(f"[Intruder] Fuzzing parameters on {url}\n")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            on_output("  [Intruder] No query params found — skipping\n")
            return findings
        for param in list(params.keys())[:3]:
            baseline = SESS.get(url, timeout=8)
            baseline_len = len(baseline.text)
            anomalies = []
            for payload in self.WORDLIST:
                try:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    qstr = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=qstr))
                    r = SESS.get(test_url, timeout=6)
                    delta = abs(len(r.text) - baseline_len)
                    if delta > 200 or r.status_code != baseline.status_code:
                        anomalies.append((payload, r.status_code, len(r.text), delta))
                        on_output(f"  [~] Anomaly: param '{param}' payload={repr(str(payload))[:30]:30} → status={r.status_code} len_delta={delta}\n")
                except Exception:
                    pass
                time.sleep(0.05)
            if anomalies:
                findings.append(self._finding(
                    f"Parameter Fuzzing Anomalies Detected: '{param}'", "Medium", url,
                    param=param, cwe="CWE-20", cvss=5.0,
                    evidence=str(anomalies[:3])))
        return findings


# ─────────────────────────────────────────────────────────────────────
# PASSIVE: Crawler / Spider
# ─────────────────────────────────────────────────────────────────────
class CrawlerPlugin(BasePlugin):
    """BFS link and form crawler — supports multiple seed URLs and parallel fetching."""
    PLUGIN_TYPE = "passive"

    def get_name(self): return "Spider / Crawler"

    def __init__(self):
        super().__init__()
        self.extra_seeds   = []   # additional starting URLs (set by engine or UI)
        self.crawl_workers = 10   # concurrent page-fetch threads
        self.max_urls      = 200  # max pages per crawl run
        self.max_depth     = 3    # BFS depth limit

    def scan(self, url, on_output):
        # Build seed list: primary target + any extras
        all_seeds = [url] + [s.strip() for s in self.extra_seeds if s.strip()]
        # Map host → bool so we stay within each seed's domain
        allowed_hosts = {urllib.parse.urlparse(s).netloc for s in all_seeds}

        findings = []
        visited  = set()
        # Queue entries: (url, depth)
        queue = [(s, 0) for s in all_seeds]
        seen_js  = set()
        js_count = 0

        on_output(f"[Crawler] Starting BFS — {len(all_seeds)} seed(s) | "
                  f"max_depth={self.max_depth} max_urls={self.max_urls} "
                  f"workers={self.crawl_workers}\n")
        for s in all_seeds:
            on_output(f"  [Seed] {s}\n")

        _lock = threading.Lock()

        def fetch_page(item):
            """Fetch a single page and return (url, depth, hrefs, forms, scripts, ok)."""
            current, depth = item
            try:
                r = SESS.get(current, timeout=8, allow_redirects=True)
                on_output(f"  [Crawl] {r.status_code} {current}\n")
                hrefs   = re.findall(r'href=["\']([^"\']+)["\']',   r.text, re.IGNORECASE)
                forms   = re.findall(r'action=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
                scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
                return (current, depth, hrefs, forms, scripts, True)
            except Exception:
                return (current, depth, [], [], [], False)

        while queue and len(visited) < self.max_urls:
            # Build a batch from the front of the queue (skip already-visited)
            batch = []
            temp  = []
            for (u, d) in queue:
                if len(visited) + len(batch) >= self.max_urls:
                    temp.append((u, d))
                    continue
                if u in visited or d > self.max_depth:
                    continue
                visited.add(u)
                batch.append((u, d))
            queue = temp  # remaining unprocessed items

            if not batch:
                break

            # Fetch all pages in the batch concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.crawl_workers) as ex:
                results = list(ex.map(fetch_page, batch))

            # Process results and grow the queue
            for (current, depth, hrefs, forms, scripts, ok) in results:
                if not ok:
                    continue
                base_url = f"{urllib.parse.urlparse(current).scheme}://{urllib.parse.urlparse(current).netloc}"
                # Enqueue child links (same-host)
                for raw in hrefs + forms:
                    abs_url = urllib.parse.urljoin(current, raw)
                    p = urllib.parse.urlparse(abs_url)
                    if p.netloc in allowed_hosts and abs_url not in visited:
                        queue.append((abs_url, depth + 1))
                # Collect first-party JS files
                for s in scripts:
                    abs_url = urllib.parse.urljoin(current, s)
                    js_host = urllib.parse.urlparse(abs_url).netloc
                    if js_host in allowed_hosts and abs_url not in seen_js and js_count < 15:
                        seen_js.add(abs_url)
                        js_count += 1
                        findings.append(self._finding(
                            "JavaScript Source File Discovered", "Information", abs_url,
                            cwe="CWE-200", evidence=abs_url))

        total = len(visited)
        on_output(f"  [Crawl] Done — {total} URLs visited across {len(all_seeds)} seed(s)\n")
        findings.insert(0, self._finding(
            f"Crawl Complete — {total} endpoints discovered", "Information",
            url, evidence="\n".join(list(visited)[:30])))
        return findings



# ─────────────────────────────────────────────────────────────────────
# ENGINE CONTROLLER
# ─────────────────────────────────────────────────────────────────────
class AegisProbeEngine:
    """
    Burp Suite-like engine controller.
    Manages plugin lifecycle, threading, and Neo4j ingestion.
    """
    REPORT_DIR = "/mnt/scans/incoming/aegisprobe"

    PASSIVE_PLUGINS = [
        SecurityHeadersPlugin,
        CookieAnalysisPlugin,
        CORSPlugin,
        InfoDisclosurePlugin,
        CrawlerPlugin,
    ]
    ACTIVE_PLUGINS = [
        SQLiPlugin,
        XSSPlugin,
        SSRFPlugin,
        OpenRedirectPlugin,
        LFIPlugin,
        CMDIPlugin,
        IDORPlugin,
        JWTPlugin,
        AuthBypassPlugin,
        IntruderPlugin,
    ]

    def __init__(self, scan_mode="full", intensity="medium", selected_plugins=None):
        """
        scan_mode: 'passive' | 'active' | 'full'
        intensity: 'low' | 'medium' | 'aggressive'
        selected_plugins: list of plugin class names to run, or None = all
        """
        os.makedirs(self.REPORT_DIR, exist_ok=True)
        self._cancel_flag = False
        self.scan_mode = scan_mode
        self.intensity = intensity

        if scan_mode == "passive":
            plugin_classes = self.PASSIVE_PLUGINS
        elif scan_mode == "active":
            plugin_classes = self.ACTIVE_PLUGINS
        else:
            plugin_classes = self.PASSIVE_PLUGINS + self.ACTIVE_PLUGINS

        if selected_plugins:
            # Match by class name OR display name (get_name()) for flexibility
            plugin_classes = [p for p in plugin_classes
                              if p.__name__ in selected_plugins or p().get_name() in selected_plugins]

        self.plugins = [p() for p in plugin_classes]
        # Plugin-level concurrency (parallel plugins per target)
        self.max_workers = {"low": 2, "medium": 5, "aggressive": 12}.get(intensity, 5)
        # Target-level concurrency is set externally or defaults by intensity
        self._default_target_concurrency = {"low": 5, "medium": 10, "aggressive": 25}.get(intensity, 10)

    def start_scan(self, targets, on_output, on_complete, target_concurrency=None):
        """Scan targets in parallel.

        target_concurrency: max simultaneous targets (None = use intensity default).
        Plugin-level concurrency is still controlled by self.max_workers.
        """
        self._cancel_flag = False
        if not targets:
            raise ValueError("AegisProbe requires at least one target URL.")

        t_workers = target_concurrency or self._default_target_concurrency
        all_target_findings = {}
        last_meta_path = [None]
        _lock = threading.Lock()

        def scan_one_target(raw_url):
            if self._cancel_flag:
                return
            url = raw_url.strip()
            if not url.startswith(("http://", "https://")):
                url = f"http://{url}"

            timestamp   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            clean       = re.sub(r"[^\w]", "_", url)[:60]
            report_path = os.path.join(self.REPORT_DIR, f"aegis_{clean}_{timestamp}.json")
            meta_path   = os.path.join(self.REPORT_DIR, f"aegis_{clean}_{timestamp}.meta.json")

            on_output(f"\n{'='*60}\n[AegisProbe] TARGET: {url}\n{'='*60}\n")
            on_output(f"[AegisProbe] Mode: {self.scan_mode} | Intensity: {self.intensity} | Plugins: {len(self.plugins)}\n\n")

            target_findings = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {ex.submit(plugin.scan, url, on_output): plugin
                           for plugin in self.plugins}
                for future in concurrent.futures.as_completed(futures):
                    if self._cancel_flag:
                        break
                    try:
                        target_findings.extend(future.result())
                    except Exception as e:
                        on_output(f"  [!] Plugin {futures[future].get_name()} failed: {e}\n")

            if self._cancel_flag:
                return

            sev_counts = {}
            for f in target_findings:
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

            on_output(f"\n{'='*60}\n[AegisProbe] SCAN COMPLETE \u2014 {url}\n")
            on_output(f"  Total findings: {len(target_findings)}\n")
            for sev, count in sorted(sev_counts.items()):
                on_output(f"  {sev}: {count}\n")
            on_output(f"{'='*60}\n")

            with open(report_path, "w") as fp:
                json.dump({"target": url, "timestamp": timestamp,
                           "findings": target_findings}, fp, indent=2)
            on_output(f"[AegisProbe] Report saved \u2192 {report_path}\n")

            self._ingest_to_neo4j(url, target_findings, timestamp)

            metadata = {
                "scanner": "aegisprobe", "target": url, "scan_time": timestamp,
                "status": "completed", "total_findings": len(target_findings),
                "severity_breakdown": sev_counts, "scan_mode": self.scan_mode,
                "intensity": self.intensity, "ingest": {"status": "completed"}
            }
            with open(meta_path, "w") as fp:
                json.dump(metadata, fp, indent=2)

            with _lock:
                all_target_findings[url] = target_findings
                last_meta_path[0] = meta_path

        def run():
            cancelled = False
            try:
                on_output(f"[AegisProbe] Scan started \u2014 {len(targets)} target(s) | "
                          f"concurrent_targets={t_workers} | plugin_workers={self.max_workers}\n")
                with concurrent.futures.ThreadPoolExecutor(max_workers=t_workers) as pool:
                    futs = {pool.submit(scan_one_target, url): url for url in targets}
                    for fut in concurrent.futures.as_completed(futs):
                        if self._cancel_flag:
                            cancelled = True
                            break
                        try:
                            fut.result()
                        except Exception as e:
                            on_output(f"\n[!] Target error: {e}\n")
            except Exception as e:
                on_output(f"\n[!] AegisProbe engine exception: {e}\n{traceback.format_exc()}\n")
                cancelled = True
            finally:
                on_complete(cancelled or self._cancel_flag, last_meta_path[0])

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread


    def cancel_scan(self):
        self._cancel_flag = True
        return True

    def _ingest_to_neo4j(self, url, findings, timestamp):
        try:
            from neo4j import GraphDatabase
            password = os.environ.get("NEO4J_PASSWORD", "neo4j_password")
            driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", password))
            with driver.session() as session:
                host = url.split("://")[-1].split("/")[0].split(":")[0]
                for f in findings:
                    sev_map = {"Critical":9.5,"High":7.5,"Medium":5.5,"Low":3.5,"Information":1.0}
                    severity = sev_map.get(f.get("severity","Medium"), 5.0)
                    if f.get("cvss", 0): severity = max(severity, f["cvss"])
                    fid = f"aegisprobe:{host}:{f.get('url','')[:40]}:{f.get('name','')[:30]}"
                    session.run("""
                        MERGE (a:Asset {host:$host})
                        MERGE (s:Service {id:$sid})
                        SET s.name='Web', s.port='443', s.protocol='tcp', s.source='AegisProbe'
                        MERGE (a)-[:RUNS_SERVICE]->(s)
                        MERGE (f:Finding {id:$fid})
                        ON CREATE SET f.first_seen=$ts
                        SET f.name=$name, f.severity=$severity, f.severity_text=$sev_text,
                            f.path=$path, f.description=$desc, f.evidence=$evidence, f.cwe=$cwe,
                            f.scanner='AegisProbe', f.source='AegisProbe', f.last_seen=$ts
                        MERGE (s)-[:HAS_FINDING]->(f)
                    """, host=host, sid=f"{host}:443:web", fid=fid,
                             name=f["name"], severity=severity, sev_text=f.get("severity",""),
                             path=f.get("url",""),
                             desc=f.get("description", f.get("evidence","")),
                             evidence=f.get("evidence",""),
                             cwe=f.get("cwe",""), ts=timestamp)
            driver.close()
        except Exception:
            pass  # Fails safely if Neo4j offline


# Backward compat alias
class AegisProbeIngestor(AegisProbeEngine):
    def __init__(self):
        super().__init__(scan_mode="passive", intensity="low")


# Convenience: get all plugin info for UI (returns class name as value, display name as label)
def get_plugin_names():
    return {
        "passive": [{"label": p().get_name(), "value": p.__name__}
                    for p in AegisProbeEngine.PASSIVE_PLUGINS],
        "active":  [{"label": p().get_name(), "value": p.__name__}
                    for p in AegisProbeEngine.ACTIVE_PLUGINS],
    }


__all__ = ["AegisProbeEngine", "AegisProbeIngestor", "get_plugin_names"]
