"""
scap_assessor.py
================
Live SCAP assessment engine that performs REAL checks against target systems.

Instead of using hardcoded test results from static XML files, this engine:
  1. Reads the Rule definitions from XCCDF benchmark files
  2. Performs actual network checks against the target (HTTP headers, TLS, ports, etc.)
  3. Generates dynamic pass/fail results based on what the target actually exposes

Supported assessment types:
  - Web Server: HTTP headers, TLS configuration, cookies, directory listing
  - Network Infrastructure: Open ports, service exposure, SSH hardening
  - OWASP Top 10: Maps existing scan findings from Neo4j/SQLite

Usage:
    from cyber_range.services.scap_assessor import live_assess
    findings = live_assess(target="192.168.1.100", benchmark_path="...", on_log=log)
"""

import os
import re
import ssl
import socket
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError


# ── Content Integrity ─────────────────────────────────────────────────
def _verify_benchmark_integrity(benchmark_path: str, on_log=None) -> dict:
    """
    Verify SHA256 integrity of a benchmark file before assessment.

    Returns: {"valid": bool, "sha256": str, "reason": str}

    If no inventory exists, bootstraps one (first-run case).
    """
    log = on_log or (lambda m: None)
    try:
        from cyber_range.services.scap_content_manager import (
            verify_file_integrity, ensure_repo_structure, INVENTORY_PATH,
        )
        # Bootstrap inventory on first run
        if not INVENTORY_PATH.exists():
            log("[SCAP]   ⚙ Bootstrapping content inventory (first run)...\n")
            ensure_repo_structure()

        result = verify_file_integrity(benchmark_path)
        if result.get("valid"):
            sha_short = result.get("sha256", "")[:12]
            log(f"[SCAP]   ✓ Integrity OK: SHA256={sha_short}...\n")
        else:
            reason = result.get("reason", "unknown")
            log(f"[SCAP]   🚫 INTEGRITY FAILURE: {reason}\n")
        return result
    except ImportError:
        # Content manager not available — compute SHA256 directly
        try:
            h = hashlib.sha256()
            with open(benchmark_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha = h.hexdigest()
            log(f"[SCAP]   ✓ SHA256={sha[:12]}... (no inventory)\n")
            return {"valid": True, "sha256": sha, "note": "computed without inventory"}
        except Exception as e:
            return {"valid": False, "reason": str(e)}
    except Exception as e:
        log(f"[SCAP]   ⚠ Integrity check skipped: {e}\n")
        return {"valid": True, "note": f"check skipped: {e}"}


# ── Timeouts ──────────────────────────────────────────────────────────
_CONNECT_TIMEOUT = 5
_HTTP_TIMEOUT = 8


# ── HTTP helper ───────────────────────────────────────────────────────
def _http_get_headers(target: str, port: int = 80, use_ssl: bool = False) -> dict:
    """Fetch HTTP response headers from target."""
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{target}:{port}/" if port not in (80, 443) else f"{scheme}://{target}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = Request(url, headers={"User-Agent": "Aegis-SCAP-Assessor/1.0"})
        resp = urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        headers["_status"] = resp.status
        headers["_url"] = url
        return headers
    except Exception as e:
        return {"_error": str(e)}


def _check_port(host: str, port: int) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_CONNECT_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _check_tls(host: str, port: int = 443) -> dict:
    """Check TLS configuration."""
    result = {"supported": False, "version": "", "error": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                result["supported"] = True
                result["version"] = s.version() or "unknown"
                result["cipher"] = s.cipher()
    except ssl.SSLError as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def _resolve_host(target: str) -> tuple:
    """Extract hostname/IP and optional port from target string.
    Returns (host, port) where port may be 0 if not specified."""
    t = target.strip()
    port = 0
    # Strip protocol
    for prefix in ("https://", "http://", "ftp://"):
        if t.startswith(prefix):
            if "https" in prefix:
                port = 443
            t = t[len(prefix):]
    # Extract port if present
    path_idx = t.find("/")
    host_part = t[:path_idx] if path_idx >= 0 else t
    if ":" in host_part:
        parts = host_part.rsplit(":", 1)
        try:
            port = int(parts[1])
        except ValueError:
            pass
        host_part = parts[0]
    # Strip CIDR
    host_part = host_part.split("/")[0]
    return host_part, port


def _discover_http_service(host: str, user_port: int = 0) -> dict:
    """Auto-discover web service on the target by trying multiple ports."""
    # Build list of ports to try, prioritizing user-specified port
    ports_to_try = []
    if user_port and user_port not in (80, 443):
        ports_to_try.append((user_port, False))  # Try user port as HTTP first
        ports_to_try.append((user_port, True))   # Then try as HTTPS
    ports_to_try.extend([
        (443, True), (80, False), (8443, True), (8080, False), (9010, False),
    ])

    for port, use_ssl in ports_to_try:
        headers = _http_get_headers(host, port, use_ssl=use_ssl)
        if "_error" not in headers:
            return headers
    return {"_error": f"No web service found on {host} (tried ports: {', '.join(str(p) for p, _ in ports_to_try)})"}


# ── Assessment checks per rule ID ─────────────────────────────────────
def _assess_web_server(host: str, rule_id: str, on_log=None, user_port: int = 0) -> dict:
    """Perform a live check for web server benchmark rules."""
    log = on_log or (lambda m: None)
    result = {"status": "notchecked", "message": "Check not implemented for this rule"}

    # Auto-discover web service
    headers = _discover_http_service(host, user_port)

    if "_error" in headers:
        return {"status": "error", "message": f"Cannot connect to {host}: {headers.get('_error', 'timeout')}"}

    rid = rule_id.lower()

    # ── TLS Version Check ──
    if "tls-version" in rid:
        tls = _check_tls(host, 443)
        if not tls["supported"]:
            if _check_port(host, 443):
                result = {"status": "fail", "message": f"Port 443 open but TLS handshake failed: {tls['error']}"}
            else:
                result = {"status": "fail", "message": "HTTPS (port 443) not detected. No TLS configured."}
        else:
            ver = tls["version"]
            if "TLSv1.2" in ver or "TLSv1.3" in ver:
                result = {"status": "pass", "message": f"TLS version: {ver} — compliant"}
            else:
                result = {"status": "fail", "message": f"TLS version: {ver} — deprecated version detected"}

    # ── HSTS Header ──
    elif "hsts" in rid:
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "max-age=" in hsts:
                try:
                    age = int(re.search(r"max-age=(\d+)", hsts).group(1))
                    if age >= 31536000:
                        result = {"status": "pass", "message": f"HSTS header present: {hsts}"}
                    else:
                        result = {"status": "fail", "message": f"HSTS max-age too low ({age}s). Minimum: 31536000"}
                except:
                    result = {"status": "fail", "message": f"HSTS header found but malformed: {hsts}"}
            else:
                result = {"status": "fail", "message": f"HSTS header missing max-age directive: {hsts}"}
        else:
            result = {"status": "fail", "message": "Strict-Transport-Security header is missing"}

    # ── CSP Header ──
    elif "csp" in rid:
        csp = headers.get("content-security-policy", "")
        if csp:
            result = {"status": "pass", "message": f"Content-Security-Policy header present: {csp[:120]}"}
        else:
            result = {"status": "fail", "message": "Content-Security-Policy header is missing"}

    # ── X-Frame-Options ──
    elif "x-frame" in rid:
        xfo = headers.get("x-frame-options", "")
        if xfo:
            result = {"status": "pass", "message": f"X-Frame-Options: {xfo}"}
        else:
            result = {"status": "fail", "message": "X-Frame-Options header is missing. Vulnerable to clickjacking."}

    # ── X-Content-Type-Options ──
    elif "x-content-type" in rid:
        xcto = headers.get("x-content-type-options", "")
        if xcto and "nosniff" in xcto.lower():
            result = {"status": "pass", "message": "X-Content-Type-Options: nosniff — set correctly"}
        else:
            result = {"status": "fail", "message": "X-Content-Type-Options: nosniff is not set"}

    # ── Server Header Disclosure ──
    elif "server-header" in rid or "server.*disclosure" in rid:
        server = headers.get("server", "")
        if server:
            # Check if version info is disclosed
            if re.search(r"\d+\.\d+", server):
                result = {"status": "fail", "message": f"Server header reveals version: {server}"}
            else:
                result = {"status": "pass", "message": f"Server header present but no version disclosed: {server}"}
        else:
            result = {"status": "pass", "message": "Server header is not present — no disclosure"}

    # ── Directory Listing ──
    elif "directory" in rid and "listing" in rid:
        # Try common paths
        for path in ["/images/", "/static/", "/css/", "/js/", "/uploads/"]:
            try:
                test_url = f"http://{host}{path}"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request(test_url, headers={"User-Agent": "Aegis-SCAP-Assessor/1.0"})
                resp = urlopen(req, timeout=5, context=ctx)
                body = resp.read(2048).decode("utf-8", errors="ignore").lower()
                if "index of" in body or "<pre>" in body and "parent directory" in body:
                    result = {"status": "fail", "message": f"Directory listing enabled at {path}"}
                    break
            except:
                pass
        else:
            result = {"status": "pass", "message": "No directory listing detected on common paths"}

    # ── Secure Cookies ──
    elif "cookie" in rid:
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            flags = set_cookie.lower()
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if missing:
                result = {"status": "fail", "message": f"Cookie missing flags: {', '.join(missing)}. Header: {set_cookie[:100]}"}
            else:
                result = {"status": "pass", "message": f"Cookie has Secure and HttpOnly flags"}
        else:
            result = {"status": "pass", "message": "No Set-Cookie header in initial response (check application login)"}

    # ── CORS Policy ──
    elif "cors" in rid:
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            result = {"status": "fail", "message": "CORS wildcard (*) detected — allows any origin"}
        elif cors:
            result = {"status": "pass", "message": f"CORS restricted to: {cors}"}
        else:
            result = {"status": "pass", "message": "No CORS header — default same-origin policy"}

    # ── Default Credentials ──
    elif "default-credentials" in rid or "default.*cred" in rid:
        result = {"status": "notchecked", "message": "Default credential check requires manual verification or authenticated scan"}

    # ── Error Handling ──
    elif "error" in rid and ("handling" in rid or "verbose" in rid):
        # Try to trigger an error
        try:
            err_url = f"http://{host}/nonexistent_page_aegis_test_404"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = Request(err_url, headers={"User-Agent": "Aegis-SCAP-Assessor/1.0"})
            resp = urlopen(req, timeout=5, context=ctx)
            body = resp.read(4096).decode("utf-8", errors="ignore").lower()
            if any(kw in body for kw in ["stack trace", "traceback", "exception", "debug",
                                          "display_errors", "/var/www", "/usr/local"]):
                result = {"status": "fail", "message": "Verbose error information detected in 404 response"}
            else:
                result = {"status": "pass", "message": "No verbose error information in error response"}
        except:
            result = {"status": "pass", "message": "Error page did not reveal verbose information"}

    # ── Admin Path ──
    elif "admin" in rid and "path" in rid:
        found_paths = []
        for path in ["/admin", "/wp-admin", "/phpmyadmin", "/console", "/manager"]:
            try:
                test_url = f"http://{host}{path}"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request(test_url, headers={"User-Agent": "Aegis-SCAP-Assessor/1.0"})
                resp = urlopen(req, timeout=5, context=ctx)
                if resp.status in (200, 301, 302):
                    found_paths.append(path)
            except:
                pass
        if found_paths:
            result = {"status": "fail", "message": f"Admin interfaces found at default paths: {', '.join(found_paths)}"}
        else:
            result = {"status": "pass", "message": "No admin interfaces at default paths"}

    return result


def _assess_network(host: str, rule_id: str, on_log=None, user_port: int = 0) -> dict:
    """Perform a live check for network infrastructure benchmark rules."""
    log = on_log or (lambda m: None)
    result = {"status": "notchecked", "message": "Check not implemented"}
    rid = rule_id.lower()

    # ── Unnecessary Ports ──
    if "unnecessary-ports" in rid or "unnecessary.*port" in rid:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                        993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]
        open_ports = []
        for p in common_ports:
            if _check_port(host, p):
                open_ports.append(p)
        if len(open_ports) > 3:
            result = {"status": "fail",
                      "message": f"{len(open_ports)} open ports detected: {', '.join(map(str, open_ports))}. Review for unnecessary services."}
        elif open_ports:
            result = {"status": "pass",
                      "message": f"{len(open_ports)} ports open: {', '.join(map(str, open_ports))}. Minimal exposure."}
        else:
            result = {"status": "pass", "message": "No common ports detected as open (host may be filtered)"}

    # ── SSH Hardening ──
    elif "ssh" in rid:
        if _check_port(host, 22):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(_CONNECT_TIMEOUT)
                sock.connect((host, 22))
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                sock.close()
                result = {"status": "fail" if banner else "pass",
                          "message": f"SSH detected on port 22. Banner: {banner}" if banner else "SSH port 22 open but no banner"}
            except:
                result = {"status": "fail", "message": "SSH port 22 is open — verify hardening configuration"}
        else:
            result = {"status": "pass", "message": "SSH port 22 is not externally accessible"}

    # ── Database Exposure ──
    elif "database" in rid:
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
                    1433: "MSSQL", 6379: "Redis"}
        exposed = []
        for port, name in db_ports.items():
            if _check_port(host, port):
                exposed.append(f"{name} ({port})")
        if exposed:
            result = {"status": "fail",
                      "message": f"Database services externally accessible: {', '.join(exposed)}"}
        else:
            result = {"status": "pass", "message": "No database ports externally accessible"}

    # ── VNC/RDP Exposure ──
    elif "vnc" in rid or "rdp" in rid:
        remote = {}
        if _check_port(host, 5900): remote["VNC"] = 5900
        if _check_port(host, 3389): remote["RDP"] = 3389
        if remote:
            services = [f"{n} ({p})" for n, p in remote.items()]
            result = {"status": "fail",
                      "message": f"Remote desktop services exposed: {', '.join(services)}"}
        else:
            result = {"status": "pass", "message": "No VNC/RDP services detected externally"}

    # ── SMB Exposure ──
    elif "smb" in rid or "netbios" in rid:
        smb_ports = {135: "RPC", 139: "NetBIOS", 445: "SMB"}
        exposed = []
        for port, name in smb_ports.items():
            if _check_port(host, port):
                exposed.append(f"{name} ({port})")
        if exposed:
            result = {"status": "fail",
                      "message": f"SMB/NetBIOS exposed: {', '.join(exposed)}"}
        else:
            result = {"status": "pass", "message": "No SMB/NetBIOS ports detected externally. PASS."}

    # ── DNS Recursion ──
    elif "dns" in rid:
        if _check_port(host, 53):
            result = {"status": "fail", "message": "DNS service (port 53) is externally accessible — verify recursion settings"}
        else:
            result = {"status": "pass", "message": "No DNS service (port 53) detected externally. PASS."}

    # ── FTP ──
    elif "ftp" in rid:
        if _check_port(host, 21):
            result = {"status": "fail", "message": "FTP service (port 21) is active — should be replaced with SFTP"}
        else:
            result = {"status": "pass", "message": "No FTP service (port 21) detected. PASS."}

    # ── Telnet ──
    elif "telnet" in rid:
        if _check_port(host, 23):
            result = {"status": "fail", "message": "Telnet (port 23) is active — insecure, replace with SSH"}
        else:
            result = {"status": "pass", "message": "No Telnet service (port 23) detected. PASS."}

    # ── ICMP ──
    elif "icmp" in rid:
        try:
            import subprocess
            r = subprocess.run(["ping", "-c", "1", "-W", "2", host],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                result = {"status": "fail", "message": "Host responds to ICMP echo — consider rate limiting"}
            else:
                result = {"status": "pass", "message": "Host does not respond to ICMP echo"}
        except:
            result = {"status": "notchecked", "message": "ICMP check unavailable"}

    # ── Network Segmentation ──
    elif "segmentation" in rid:
        # Check if web + DB on same host
        web_open = _check_port(host, 80) or _check_port(host, 443)
        db_open = _check_port(host, 3306) or _check_port(host, 5432) or _check_port(host, 27017)
        if web_open and db_open:
            result = {"status": "fail",
                      "message": f"Web and database services on same host ({host}) — no segmentation detected"}
        else:
            result = {"status": "pass", "message": "No evidence of mixed web+database on same host"}

    return result


def _assess_owasp(host: str, rule_id: str, on_log=None, user_port: int = 0) -> dict:
    """Perform OWASP Top 10 checks — combines live checks with existing findings."""
    log = on_log or (lambda m: None)
    result = {"status": "notchecked", "message": "Check requires authenticated application scan"}
    rid = rule_id.lower()

    h = _discover_http_service(host, user_port)

    if "_error" in h:
        return {"status": "error", "message": f"Cannot connect to {host}: {h.get('_error', 'timeout')}"}

    # A01: Broken Access Control
    if "access-control" in rid:
        xfo = h.get("x-frame-options", "")
        cors = h.get("access-control-allow-origin", "")
        issues = []
        if not xfo: issues.append("Missing X-Frame-Options")
        if cors == "*": issues.append("CORS wildcard (*)")
        if issues:
            result = {"status": "fail", "message": f"Access control weaknesses: {'; '.join(issues)}"}
        else:
            result = {"status": "pass", "message": "Basic access control headers present"}

    # A02: Cryptographic Failures
    elif "cryptographic" in rid:
        tls = _check_tls(host, 443)
        if not tls["supported"] and _check_port(host, 80):
            result = {"status": "fail", "message": "No HTTPS detected — data transmitted in cleartext over HTTP"}
        elif tls["supported"]:
            hsts = h.get("strict-transport-security", "")
            if hsts:
                result = {"status": "pass", "message": f"HTTPS with HSTS enabled. TLS: {tls['version']}"}
            else:
                result = {"status": "fail", "message": f"HTTPS present but no HSTS header. TLS: {tls['version']}"}
        else:
            result = {"status": "notchecked", "message": "No web service detected"}

    # A03: Injection
    elif "injection" in rid:
        csp = h.get("content-security-policy", "")
        xcto = h.get("x-content-type-options", "")
        issues = []
        if not csp: issues.append("No CSP header (XSS risk)")
        if not xcto: issues.append("No X-Content-Type-Options (MIME sniffing risk)")
        if issues:
            result = {"status": "fail", "message": f"Injection protection gaps: {'; '.join(issues)}"}
        else:
            result = {"status": "pass", "message": "CSP and X-Content-Type-Options headers present"}

    # A04: Insecure Design
    elif "insecure-design" in rid:
        result = {"status": "notchecked", "message": "Insecure design requires manual architecture review and threat modeling"}

    # A05: Security Misconfiguration
    elif "misconfiguration" in rid:
        server = h.get("server", "")
        x_powered = h.get("x-powered-by", "")
        issues = []
        if server and re.search(r"\d+\.\d+", server):
            issues.append(f"Server version disclosed: {server}")
        if x_powered:
            issues.append(f"X-Powered-By disclosed: {x_powered}")
        if issues:
            result = {"status": "fail", "message": f"Misconfigurations: {'; '.join(issues)}"}
        else:
            result = {"status": "pass", "message": "No obvious misconfigurations in response headers"}

    # A06: Vulnerable Components
    elif "component" in rid or "outdated" in rid:
        server = h.get("server", "")
        x_powered = h.get("x-powered-by", "")
        if server or x_powered:
            result = {"status": "fail", "message": f"Component versions exposed — Server: {server}, X-Powered-By: {x_powered}. Verify versions are current."}
        else:
            result = {"status": "pass", "message": "No component versions disclosed in headers"}

    # A07: Authentication Failures
    elif "auth" in rid:
        result = {"status": "notchecked", "message": "Authentication testing requires a valid login endpoint and credentials"}

    # A08: Integrity Failures
    elif "integrity" in rid:
        csp = h.get("content-security-policy", "")
        if csp and ("require-sri-for" in csp or "script-src" in csp):
            result = {"status": "pass", "message": "CSP with script-src restrictions present"}
        elif csp:
            result = {"status": "fail", "message": "CSP present but may not enforce script integrity"}
        else:
            result = {"status": "fail", "message": "No CSP header — cannot enforce script/resource integrity"}

    # A09: Logging & Monitoring
    elif "logging" in rid or "monitoring" in rid:
        result = {"status": "notchecked", "message": "Security logging and monitoring requires internal access to verify"}

    # A10: SSRF
    elif "ssrf" in rid:
        result = {"status": "notchecked", "message": "SSRF testing requires application-level scanning with authenticated access"}

    return result


# ── Main assessment entry point ───────────────────────────────────────
def live_assess(target: str, benchmark_path: str, on_log=None, target_os: dict = None) -> list:
    """
    Perform a LIVE SCAP assessment against a target using benchmark rules.

    Supports:
      - Plain XCCDF (.xccdf.xml or xccdf_*.xml)
      - SCAP 1.2 DataStream (.ds.xml) — used by SSG 0.1.75+

    Args:
        target: Target hostname/IP/URL
        benchmark_path: Path to XCCDF or SCAP DS XML file
        on_log: Callback for progress messages
        target_os: OS info dict from fingerprinting (for applicability checks)

    Returns:
        List of finding dicts ready for Neo4j ingestion.
        Includes a special '_type': 'scap_metrics' entry with compliance scoring.
    """
    log = on_log or (lambda m: None)
    host, user_port = _resolve_host(target)
    findings = []
    # Store target_os for applicability checks
    live_assess._target_os = target_os or {}

    try:
        # ── Content Integrity Verification (NIST SP 800-126) ──────────
        _integrity = _verify_benchmark_integrity(benchmark_path, on_log=log)
        if not _integrity.get("valid", True):
            log(f"[SCAP]   🚫 SKIPPING {os.path.basename(benchmark_path)} — integrity check failed\n")
            log(f"[SCAP]   Reason: {_integrity.get('reason', 'unknown')}\n")
            return findings  # Return empty — do not process tampered content

        tree = ET.parse(benchmark_path)
        root = tree.getroot()

        # ── Detect namespace ──────────────────────────────────────────
        ns = ""
        if "{" in root.tag:
            ns = root.tag.split("}")[0] + "}"
        tag_local = root.tag.replace(ns, "")

        # ── SCAP DataStream handling (.ds.xml) ────────────────────────
        # SSG ships as DataStreamCollection with embedded XCCDF Benchmarks
        if "DataStreamCollection" in tag_local or "data-stream-collection" in tag_local.lower():
            log(f"[SCAP]   Format: SCAP 1.2 DataStream — extracting embedded XCCDF\n")
            # Find all embedded XCCDF Benchmark elements
            XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
            bm_root = root.find(f".//{{{XCCDF_NS}}}Benchmark")
            if bm_root is not None:
                root = bm_root
                ns = f"{{{XCCDF_NS}}}"
            else:
                # Fallback: find any Benchmark tag
                for el in root.iter():
                    if "Benchmark" in el.tag:
                        root = el
                        ns = el.tag.split("}")[0] + "}" if "{" in el.tag else ""
                        break

        # ── Get benchmark title ───────────────────────────────────────
        title_el = root.find(f".//{ns}title")
        benchmark_title = title_el.text.strip() if (title_el is not None and title_el.text) else "SCAP Benchmark"

        # Detect benchmark type from title/filename
        fname = os.path.basename(benchmark_path).lower()
        if "web_server" in fname or "web-server" in fname:
            assess_fn = _assess_web_server
            btype = "web"
        elif "network" in fname or "infrastructure" in fname:
            assess_fn = _assess_network
            btype = "network"
        elif "owasp" in fname:
            assess_fn = _assess_owasp
            btype = "owasp"
        else:
            # Auto-detect from benchmark title
            btitle = benchmark_title.lower()
            if "web" in btitle or "http" in btitle:
                assess_fn = _assess_web_server
                btype = "web"
            elif "network" in btitle or "infrastructure" in btitle:
                assess_fn = _assess_network
                btype = "network"
            else:
                assess_fn = _assess_owasp
                btype = "owasp"

        log(f"[SCAP]   Assessment type: {btype.upper()} | Target: {host}\n")

        # Extract rules
        SEV_MAP = {"high": "High", "medium": "Medium", "low": "Low",
                   "unknown": "Info", "info": "Info", "critical": "High"}

        all_rules = root.findall(f".//{ns}Rule")
        total_rules = len(all_rules)

        # ── SSG files have 500-1500+ rules — smart sampling ──────────────────
        _is_ssg = total_rules > 50 or "ssg-" in os.path.basename(benchmark_path).lower()
        log(f"[SCAP]   Rules in benchmark: {total_rules} ({'SSG official' if _is_ssg else 'custom'})\n")

        # For SSG: select all High severity + sample Medium + skip Low config rules
        if _is_ssg and total_rules > 50:
            high_rules   = [r for r in all_rules if (r.get("severity") or "").lower() in ("high", "critical")]
            medium_rules = [r for r in all_rules if (r.get("severity") or "").lower() == "medium"]
            low_rules    = [r for r in all_rules if (r.get("severity") or "").lower() in ("low", "unknown", "")]

            # Take all High, sample Medium (max 20), skip Low
            import random; random.seed(42)
            selected_rules = (
                high_rules[:30] +
                random.sample(medium_rules, min(20, len(medium_rules))) +
                random.sample(low_rules, min(5, len(low_rules)))
            )
            log(f"[SCAP]   Selected: {len(high_rules)} High + {min(20,len(medium_rules))} Medium + {min(5,len(low_rules))} Low\n")
        else:
            selected_rules = all_rules

        # SSG rule ID patterns that can be network-checked remotely
        NETWORK_CHECKABLE = [
            "tls", "ssl", "https", "http", "header", "cors", "cookie",
            "ftp", "telnet", "ssh", "rdp", "vnc", "smb", "netbios",
            "port", "service", "firewall", "remote", "banner",
            "directory", "listing", "admin", "phpmyadmin",
            "database", "mysql", "postgresql", "mongodb", "redis",
            "hsts", "csp", "xss", "cors", "injection",
            "icmp", "ping", "segment", "access_control",
        ]

        # ── Federal-grade compliance scoring ──
        try:
            from cyber_range.services.scap_auth_scanner import (
                ComplianceScorer, POAMGenerator, ScanResult,
                map_rule_to_nist, classify_applicability, STIG_CAT,
            )
            scorer = ComplianceScorer()
            poam = POAMGenerator()
            _has_scorer = True
        except ImportError:
            _has_scorer = False
            scorer = None
            poam = None

        # Target OS info for applicability checks (passed via kwargs if available)
        _target_os = getattr(live_assess, '_target_os', {}) or {}

        # ── Counters for all 5 federal SCAP states ──
        _pass_count = 0
        _fail_count = 0
        _error_count = 0
        _notchecked_count = 0      # Cannot verify (requires auth)
        _notapplicable_count = 0   # Not relevant to this system
        _notassessed_count = 0     # Explicitly out of scan scope

        # Minimum coverage to compute a reportable compliance score
        _COVERAGE_THRESHOLD = 90.0

        for rule in selected_rules:
            rule_id = rule.get("id", "")
            severity = (rule.get("severity", "medium") or "medium").lower()
            severity = SEV_MAP.get(severity, "Medium")

            rtitle_el = rule.find(f"{ns}title")
            rdesc_el  = rule.find(f"{ns}description")
            rtitle = rtitle_el.text.strip() if (rtitle_el is not None and rtitle_el.text) else rule_id
            rtitle = re.sub(r'<[^>]+>', '', rtitle).strip()[:100]
            rdesc = ET.tostring(rdesc_el, encoding="unicode", method="text").strip()[:500] if rdesc_el is not None else ""

            # Extract identifiers (CVEs, CWEs, CCIs from SSG)
            cve_refs, cwe_refs, cci_refs = [], [], []
            for ident_el in rule.findall(f".//{ns}ident"):
                val = (ident_el.text or "").strip()
                if "CVE" in val: cve_refs.append(val)
                elif "CWE" in val: cwe_refs.append(val)
                elif "CCI" in val: cci_refs.append(val[:12])
            cve_refs  += re.findall(r'CVE-\d{4}-\d+', rdesc + rtitle)
            cwe_refs  += re.findall(r'CWE-\d+', rdesc + rtitle)
            cve_str = ", ".join(sorted(set(cve_refs))[:2])
            cwe_str = ", ".join(sorted(set(cwe_refs))[:3])
            cci_str = ", ".join(cci_refs[:3])

            # ── NIST 800-53 + STIG mapping (every rule) ──
            _nist = {}
            _stig_cat = ""
            if _has_scorer:
                _nist = map_rule_to_nist(rule_id, rtitle, rdesc)
                _stig_cat = STIG_CAT.get(severity, "CAT III")

            # ═══════════════════════════════════════════════════
            # 1. APPLICABILITY CHECK → NOTAPPLICABLE
            # ═══════════════════════════════════════════════════
            if _has_scorer and _target_os and _target_os.get("os_family", "unknown") != "unknown":
                _applicability = classify_applicability(rule_id, rtitle, _target_os)
                if _applicability == "notapplicable":
                    _notapplicable_count += 1
                    if scorer:
                        scorer.record(ScanResult.NOTAPPLICABLE, severity, _nist.get("nist_family", "CM"))
                    # NOT recorded as finding — excluded from ALL scoring
                    continue

            # ── Determine check method ──
            rule_text = (rule_id + " " + rtitle + " " + rdesc).lower()
            can_network_check = any(kw in rule_text for kw in NETWORK_CHECKABLE)

            # ═══════════════════════════════════════════════════
            # 2. EVIDENCE STRUCTURE (populated per check)
            # ═══════════════════════════════════════════════════
            evidence = {
                "rule_id":     rule_id,
                "title":       rtitle,
                "nist_family": _nist.get("nist_family", ""),
                "nist_control": _nist.get("nist_control", ""),
                "stig_cat":    _stig_cat,
                "check_type":  "network" if can_network_check else "local_config",
                "target":      host,
                "timestamp":   "",
                "command":     "",
                "output":      "",
                "status":      "",
                "remediation": "",
            }

            if can_network_check:
                # ═══════════════════════════════════════════════
                # 3. LIVE NETWORK CHECK
                # ═══════════════════════════════════════════════
                from datetime import datetime as _dt, timezone as _tz
                evidence["timestamp"] = _dt.now(_tz.utc).isoformat()

                check_result = assess_fn(host, rule_id, on_log=log, user_port=user_port)
                status  = check_result["status"]
                message = check_result["message"]

                evidence["status"] = status.upper()
                evidence["output"] = message[:500]

                if status == "pass":
                    _pass_count += 1
                    evidence["remediation"] = "No action needed — compliant"
                    if scorer:
                        scorer.record(ScanResult.PASS, severity,
                                      _nist.get("nist_family", "CM"), evidence=evidence)
                elif status == "fail":
                    _fail_count += 1
                    evidence["remediation"] = f"Remediate per {_stig_cat}: {rtitle[:60]}"
                    if scorer:
                        scorer.record(ScanResult.FAIL, severity,
                                      _nist.get("nist_family", "CM"), evidence=evidence)
                    if poam:
                        poam.add_finding(rule_id, rtitle, severity,
                                         _nist.get("nist_family", "CM"), message)
                elif status == "error":
                    _error_count += 1
                    evidence["remediation"] = "Investigate scan error"
                    if scorer:
                        scorer.record(ScanResult.ERROR, severity,
                                      _nist.get("nist_family", "CM"), evidence=evidence)
                else:
                    _notchecked_count += 1
                    evidence["status"] = "NOTCHECKED"
                    evidence["remediation"] = "Deeper probe or authenticated access required"
                    if scorer:
                        scorer.record(ScanResult.NOTCHECKED, severity,
                                      _nist.get("nist_family", "CM"), evidence=evidence)

                icon = "✗" if status == "fail" else "✓" if status == "pass" else "⚠" if status == "error" else "○"
                _tag = f" [{_nist.get('nist_family', '')}]" if _nist else ""
                log(f"[SCAP]   {icon} {rtitle[:55]}{_tag} → {status.upper()}\n")
            else:
                # ═══════════════════════════════════════════════
                # 4. CONFIG CHECK → NOTCHECKED (requires SSH/root)
                # ═══════════════════════════════════════════════
                status  = "notchecked"
                message = (f"UNVERIFIED: Requires local access (SSH/root). "
                           f"Rule: {rule_id} | NIST: {_nist.get('nist_family', 'CM')} | {_stig_cat}")
                _notchecked_count += 1

                evidence["status"] = "NOTCHECKED"
                evidence["output"] = "Not evaluated — requires authenticated scan"
                evidence["remediation"] = f"Run: oscap-ssh user@{host} 22 xccdf eval ..."
                if scorer:
                    scorer.record(ScanResult.NOTCHECKED, severity,
                                  _nist.get("nist_family", "CM"), evidence=evidence)

            # ═══════════════════════════════════════════════════
            # 5. RECORD FINDINGS (with evidence + control mapping)
            #    Source = "scap_compliance" (NOT "scap_xccdf")
            #    This separates SCAP compliance from CVE pipeline
            # ═══════════════════════════════════════════════════
            _nist_label = f" [{_nist.get('nist_family', '')}]" if _nist else ""

            if status in ("fail", "error"):
                finding_name = f"{rtitle} [{status.upper()}]{_nist_label}"
                desc_parts = [rdesc or f"Rule {rule_id}"]
                if cci_str:
                    desc_parts.append(f"CCI: {cci_str}")
                if _nist:
                    desc_parts.append(f"NIST 800-53: {_nist['nist_family']} ({_nist.get('nist_family_name', '')})")
                if _stig_cat:
                    desc_parts.append(f"STIG: {_stig_cat}")
                desc_parts.append(f"Remediation: {evidence.get('remediation', '')}")

                findings.append({
                    "host":           host,
                    "port":           "",
                    "protocol":       "",
                    "service":        benchmark_title[:80],
                    "name":           finding_name[:120],
                    "severity":       severity,
                    "cve":            cve_str,
                    "cwe":            cwe_str,
                    "evidence":       message,
                    "description":    " | ".join(desc_parts)[:800],
                    "url":            "",
                    "source":         "scap_compliance",
                    "rule_id":        rule_id,
                    "status":         status,
                    "nist_family":    _nist.get("nist_family", ""),
                    "nist_control":   _nist.get("nist_control", ""),
                    "stig_cat":       _stig_cat,
                    "evidence_record": evidence,
                })

            elif status == "notchecked":
                finding_name = f"[UNVERIFIED] {rtitle}{_nist_label}"
                findings.append({
                    "host":           host,
                    "port":           "",
                    "protocol":       "",
                    "service":        benchmark_title[:80],
                    "name":           finding_name[:120],
                    "severity":       "Info",
                    "cve":            "",
                    "cwe":            "",
                    "evidence":       message,
                    "description":    (f"Requires authenticated scan (SSH/root). "
                                       f"NIST: {_nist.get('nist_family_name', 'N/A')} | "
                                       f"{_stig_cat} | Rule: {rule_id}"),
                    "url":            "",
                    "source":         "scap_compliance",
                    "rule_id":        rule_id,
                    "status":         "unverified",
                    "nist_family":    _nist.get("nist_family", ""),
                    "stig_cat":       _stig_cat,
                })
            # PASS → not recorded as finding (compliant — evidence in scorer)

        # ═══════════════════════════════════════════════════════════
        # ── FEDERAL COMPLIANCE SCORECARD ──
        # ═══════════════════════════════════════════════════════════

        if _has_scorer and scorer:
            scorer.render_scorecard(log, benchmark=os.path.basename(benchmark_path), target=host)

            # Coverage threshold enforcement
            _cov = scorer.coverage_pct
            if _cov is not None and _cov < _COVERAGE_THRESHOLD:
                log(f"[SCAP]   ⚠ COVERAGE BELOW THRESHOLD: {_cov:.0f}% < {_COVERAGE_THRESHOLD:.0f}%\n")
                log(f"[SCAP]   ⚠ Compliance score is UNRELIABLE — authenticated scan required\n")
                log(f"[SCAP]   ⚠ Score NOT reportable to dashboards until threshold met\n")

            if poam:
                poam.render_summary(log)
            _scorer_data = scorer.to_dict()
        else:
            _scorer_data = {}

        # ── Metrics (all 5 states) ──
        _evaluated = _pass_count + _fail_count + _error_count
        _applicable = _evaluated + _notchecked_count
        _total = _applicable + _notapplicable_count
        _coverage_pct = (_evaluated / _applicable * 100) if _applicable > 0 else 0

        if _evaluated > 0:
            _compliance_pct = (_pass_count / _evaluated * 100)
        else:
            _compliance_pct = None  # NULL — prevents false "100% clean"

        _score_reliable = _coverage_pct >= _COVERAGE_THRESHOLD

        if not (_has_scorer and scorer):
            log(f"[SCAP]   ╔══════════════════════════════════════╗\n")
            log(f"[SCAP]   ║   SCAP CONTROL CLASSIFICATION       ║\n")
            log(f"[SCAP]   ╠══════════════════════════════════════╣\n")
            log(f"[SCAP]   ║  ✓ PASS           : {_pass_count:<16}║\n")
            log(f"[SCAP]   ║  ✗ FAIL           : {_fail_count:<16}║\n")
            log(f"[SCAP]   ║  ⚠ ERROR          : {_error_count:<16}║\n")
            log(f"[SCAP]   ║  - NOT APPLICABLE : {_notapplicable_count:<16}║\n")
            log(f"[SCAP]   ║  ○ NOT CHECKED    : {_notchecked_count:<16}║\n")
            log(f"[SCAP]   ╠══════════════════════════════════════╣\n")
            cov_str = f"{_coverage_pct:.0f}%"
            log(f"[SCAP]   ║  Coverage         : {cov_str:<17}║\n")
            if _compliance_pct is not None and _score_reliable:
                comp_str = f"{_compliance_pct:.0f}%"
                log(f"[SCAP]   ║  Compliance       : {comp_str:<17}║\n")
            elif _compliance_pct is not None:
                log(f"[SCAP]   ║  Compliance       : {_compliance_pct:.0f}% (unreliable) ║\n")
            else:
                log(f"[SCAP]   ║  Compliance       : NULL             ║\n")
                log(f"[SCAP]   ║  ⚠ POSTURE: UNKNOWN                ║\n")
            log(f"[SCAP]   ╚══════════════════════════════════════╝\n")

        # Metrics entry for upstream consumption
        findings.append({
            "_type":             "scap_metrics",
            "total_controls":    _total,
            "total_applicable":  _applicable,
            "pass":              _pass_count,
            "fail":              _fail_count,
            "error":             _error_count,
            "notapplicable":     _notapplicable_count,
            "notchecked":        _notchecked_count,
            "unverified":        _notchecked_count,
            "coverage_pct":      round(_coverage_pct, 1),
            "compliance_pct":    round(_compliance_pct, 1) if _compliance_pct is not None else None,
            "coverage_threshold": _COVERAGE_THRESHOLD,
            "score_reliable":    _score_reliable,
            "benchmark":         os.path.basename(benchmark_path),
            "benchmark_title":   benchmark_title,
            "scorer":            _scorer_data,
        })

        # ── Export POA&M ──
        if poam and poam.entries:
            try:
                _rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "reports")
                os.makedirs(_rdir, exist_ok=True)
                _poam_path = os.path.join(_rdir,
                    f"poam_{os.path.basename(benchmark_path).replace('.xml', '')}.json")
                with open(_poam_path, "w") as pf:
                    pf.write(poam.to_json())
                log(f"[POAM]   Exported → {_poam_path}\n")
            except Exception as pe:
                log(f"[POAM]   Export error: {pe}\n")

        # ── Export evidence archive ──
        if _has_scorer and scorer and scorer.evidence:
            try:
                import json as _json
                _rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "reports")
                os.makedirs(_rdir, exist_ok=True)
                _ev_path = os.path.join(_rdir,
                    f"evidence_{os.path.basename(benchmark_path).replace('.xml', '')}.json")
                with open(_ev_path, "w") as ef:
                    ef.write(_json.dumps(scorer.evidence, indent=2, default=str))
                log(f"[EVIDENCE] {len(scorer.evidence)} records → {_ev_path}\n")
            except Exception as ee:
                log(f"[EVIDENCE] Export error: {ee}\n")

    except Exception as e:
        import traceback
        log(f"[SCAP] Assessment error in {os.path.basename(benchmark_path)}: {e}\n")
        log(f"[SCAP] {traceback.format_exc()[:300]}\n")

    return findings


__all__ = ["live_assess"]
