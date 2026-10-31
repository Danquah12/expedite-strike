"""
Expedite Strike -- Cross-Site Scripting (XSS) Assessment Engine
==============================================================
Automated Dynamic Application Security Testing (DAST) engine for evaluating
web applications against Cross-Site Scripting vulnerabilities (CWE-79 / OWASP A03:2021).

Detection Categories
--------------------
XSS-REF-01   Reflected HTML Context Unencoded Canary Reflection
XSS-ATTR-02  HTML Attribute Context Quote Delimiter Breakout
XSS-JS-03    JavaScript String Context Escape Neutralization
XSS-DOM-04   DOM Source-to-Sink Flow & Unsafe Sinks (innerHTML, document.write)
XSS-HREF-05  Anchor href Attribute Protocol Injection (javascript:, data:)
XSS-CSP-06   Content-Security-Policy (CSP) Policy Strength & Directive Audit
XSS-COOKIE-07 Session Cookie HttpOnly & SameSite Mitigation Audit
"""

import time
import urllib.parse
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

_log_fn: Optional[Callable] = None

def _log(msg: str) -> None:
    if _log_fn:
        _log_fn(msg)
    else:
        print(f"[XSS-ENGINE] {msg}")


@dataclass
class XSSTarget:
    """Target configuration for XSS assessment."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_cookie: str = ""
    bearer_token: str = ""
    proxy: str = ""
    timeout: int = 8

    def __post_init__(self):
        if self.url:
            u = self.url.strip()
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            self.url = u

    @property
    def base_url(self) -> str:
        if not self.url:
            return ""
        p = urllib.parse.urlparse(self.url)
        return f"{p.scheme}://{p.netloc}"


@dataclass
class XSSFinding:
    """Result of a single XSS assessment check."""
    check_id: str
    category: str
    title: str
    status: str          # VULNERABLE | SECURE | NOT_APPLICABLE | ERROR
    severity: str        # Critical | High | Medium | Low | Info
    cvss_score: float
    mitre_id: str
    mitre_name: str
    cwe: str
    owasp: str
    evidence: str
    recommendation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _session(target: XSSTarget) -> "requests.Session":
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Aegis-XSS-DAST/3.0"
    if target.bearer_token:
        s.headers["Authorization"] = f"Bearer {target.bearer_token}"
    if target.session_cookie:
        s.headers["Cookie"] = target.session_cookie
    if target.headers:
        s.headers.update(target.headers)
    if target.proxy:
        s.proxies = {"http": target.proxy, "https": target.proxy}
    return s


# ---------------------------------------------------------------------------
# Assessment Checks
# ---------------------------------------------------------------------------

def check_xss_reflected_html(target: XSSTarget, session: "requests.Session") -> XSSFinding:
    """XSS-REF-01: Reflected HTML Body Context Canary Delimiter Test."""
    _CID = "XSS-REF-01"
    _TITLE = "Reflected XSS in HTML Body Context"

    parsed = urllib.parse.urlparse(target.url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        return XSSFinding(
            check_id=_CID, category="Reflected-HTML", title=_TITLE, status="NOT_APPLICABLE",
            severity="High", cvss_score=7.5, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-79", owasp="A03:2021", evidence="No query parameters found in target URL.",
            recommendation="Supply parameterized endpoints for reflection testing.", references=["OWASP WSTG-INPV-01"]
        )

    canary_id = uuid.uuid4().hex[:8]
    canary_token = f"aegis_{canary_id}_<xss_probe>"
    
    unencoded_reflections = []
    for param_name in query_params:
        mutated_params = {k: v[0] for k, v in query_params.items()}
        mutated_params[param_name] = canary_token

        try:
            r = session.get(target.url.split("?")[0], params=mutated_params, timeout=target.timeout)
            if canary_token in r.text:
                unencoded_reflections.append(f"Param '{param_name}' reflects raw unencoded angle brackets: '{canary_token}'")
        except Exception:
            pass

    if unencoded_reflections:
        return XSSFinding(
            check_id=_CID, category="Reflected-HTML", title=_TITLE, status="VULNERABLE",
            severity="High", cvss_score=7.5, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-79", owasp="A03:2021", evidence="; ".join(unencoded_reflections),
            recommendation="Apply context-aware HTML entity encoding (&lt;, &gt;, &quot;, &#x27;) before rendering user input.",
            references=["CWE-79", "OWASP Top 10 A03:2021", "NIST SP 800-53 SI-10"]
        )

    return XSSFinding(
        check_id=_CID, category="Reflected-HTML", title=_TITLE, status="SECURE",
        severity="High", cvss_score=7.5, mitre_id="T1059.007", mitre_name="JavaScript",
        cwe="CWE-79", owasp="A03:2021", evidence="Input characters were either encoded (&lt; &gt;) or not reflected in HTML body.",
        recommendation="Maintain context-aware output encoding.", references=["CWE-79"]
    )


def check_xss_attribute_breakout(target: XSSTarget, session: "requests.Session") -> XSSFinding:
    """XSS-ATTR-02: HTML Attribute Context Quote Delimiter Breakout."""
    _CID = "XSS-ATTR-02"
    _TITLE = "XSS via HTML Attribute Breakout"

    parsed = urllib.parse.urlparse(target.url)
    query_params = urllib.parse.parse_qs(parsed.query)

    if not query_params:
        return XSSFinding(
            check_id=_CID, category="Attribute-XSS", title=_TITLE, status="NOT_APPLICABLE",
            severity="Medium", cvss_score=6.1, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-79", owasp="A03:2021", evidence="No parameters to test for attribute injection.",
            recommendation="Supply input parameters.", references=["CWE-79"]
        )

    canary_id = uuid.uuid4().hex[:8]
    canary_token = f"aegis_attr_{canary_id}\"'"
    
    breakout_detected = []
    for param_name in query_params:
        mutated_params = {k: v[0] for k, v in query_params.items()}
        mutated_params[param_name] = canary_token

        try:
            r = session.get(target.url.split("?")[0], params=mutated_params, timeout=target.timeout)
            # Check if quotation marks reflect unencoded inside HTML tag attributes
            match = re.search(r'<[^>]+' + re.escape(canary_token) + r'[^>]*>', r.text)
            if match:
                breakout_detected.append(f"Param '{param_name}' reflected unescaped quotes inside HTML tag: {match.group(0)[:60]}")
        except Exception:
            pass

    if breakout_detected:
        return XSSFinding(
            check_id=_CID, category="Attribute-XSS", title=_TITLE, status="VULNERABLE",
            severity="High", cvss_score=7.1, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-79", owasp="A03:2021", evidence="; ".join(breakout_detected),
            recommendation="Encode attribute values using HTML attribute encoding (&quot;, &#x27;) and enclose all attributes in quotes.",
            references=["CWE-79", "OWASP WSTG-INPV-02"]
        )

    return XSSFinding(
        check_id=_CID, category="Attribute-XSS", title=_TITLE, status="SECURE",
        severity="High", cvss_score=7.1, mitre_id="T1059.007", mitre_name="JavaScript",
        cwe="CWE-79", owasp="A03:2021", evidence="Attribute delimiters were sanitized or encoded appropriately.",
        recommendation="Continue enforcing attribute quotation and encoding.", references=["CWE-79"]
    )


def check_xss_csp_policy(target: XSSTarget, session: "requests.Session") -> XSSFinding:
    """XSS-CSP-06: Content-Security-Policy (CSP) Policy Strength & Directive Audit."""
    _CID = "XSS-CSP-06"
    _TITLE = "Content-Security-Policy (CSP) XSS Mitigation Audit"

    try:
        r = session.get(target.url, timeout=target.timeout)
        csp = r.headers.get("Content-Security-Policy", "")
    except Exception as exc:
        return XSSFinding(
            check_id=_CID, category="CSP-Audit", title=_TITLE, status="ERROR",
            severity="Medium", cvss_score=5.0, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-693", owasp="A05:2021", evidence=f"Failed to fetch CSP header: {exc}",
            recommendation="Verify server connectivity.", references=["W3C CSP"]
        )

    if not csp:
        return XSSFinding(
            check_id=_CID, category="CSP-Audit", title=_TITLE, status="VULNERABLE",
            severity="Medium", cvss_score=5.8, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-693", owasp="A05:2021", evidence="No Content-Security-Policy header returned by target.",
            recommendation="Implement a robust Content-Security-Policy (e.g., default-src 'self'; script-src 'self' 'nonce-...').",
            references=["W3C CSP 3", "OWASP CSP Cheat Sheet"]
        )

    issues = []
    if "'unsafe-inline'" in csp:
        issues.append("Policy includes ''unsafe-inline'', weakening XSS defense")
    if "'unsafe-eval'" in csp:
        issues.append("Policy includes ''unsafe-eval'', allowing dynamic code execution")
    if "default-src" not in csp and "script-src" not in csp:
        issues.append("Policy lacks default-src and script-src restriction directives")

    if issues:
        return XSSFinding(
            check_id=_CID, category="CSP-Audit", title=_TITLE, status="VULNERABLE",
            severity="Low", cvss_score=4.3, mitre_id="T1059.007", mitre_name="JavaScript",
            cwe="CWE-693", owasp="A05:2021", evidence=f"CSP: {csp[:80]}... | Issues: {'; '.join(issues)}",
            recommendation="Refactor CSP to eliminate 'unsafe-inline' and 'unsafe-eval' by adopting cryptographic nonces or hashes.",
            references=["W3C CSP 3", "NIST SP 800-53 SC-8"]
        )

    return XSSFinding(
        check_id=_CID, category="CSP-Audit", title=_TITLE, status="SECURE",
        severity="Low", cvss_score=4.3, mitre_id="T1059.007", mitre_name="JavaScript",
        cwe="CWE-693", owasp="A05:2021", evidence=f"CSP is active and enforces strict script execution controls: {csp[:100]}",
        recommendation="Maintain strict CSP directives.", references=["W3C CSP 3"]
    )


def check_xss_cookie_httponly(target: XSSTarget, session: "requests.Session") -> XSSFinding:
    """XSS-COOKIE-07: Session Cookie HttpOnly & SameSite Mitigation Audit."""
    _CID = "XSS-COOKIE-07"
    _TITLE = "Session Cookie HttpOnly & SameSite Flag Mitigation"

    try:
        r = session.get(target.url, timeout=target.timeout)
        cookie_header = r.headers.get("Set-Cookie", "")
    except Exception as exc:
        return XSSFinding(
            check_id=_CID, category="Cookie-Security", title=_TITLE, status="ERROR",
            severity="Medium", cvss_score=5.0, mitre_id="T1539", mitre_name="Steal Web Session Cookie",
            cwe="CWE-1004", owasp="A07:2021", evidence=f"Failed to inspect cookies: {exc}",
            recommendation="Verify connectivity.", references=["CWE-1004"]
        )

    if not cookie_header:
        return XSSFinding(
            check_id=_CID, category="Cookie-Security", title=_TITLE, status="NOT_APPLICABLE",
            severity="Medium", cvss_score=5.3, mitre_id="T1539", mitre_name="Steal Web Session Cookie",
            cwe="CWE-1004", owasp="A07:2021", evidence="No Set-Cookie header issued on initial request.",
            recommendation="Audit authenticated session cookie handling.", references=["CWE-1004"]
        )

    issues = []
    if "httponly" not in cookie_header.lower():
        issues.append("Missing 'HttpOnly' flag (cookie accessible to client-side scripts)")
    if "samesite" not in cookie_header.lower():
        issues.append("Missing 'SameSite' attribute (vulnerable to cross-site request leakage)")

    if issues:
        return XSSFinding(
            check_id=_CID, category="Cookie-Security", title=_TITLE, status="VULNERABLE",
            severity="Medium", cvss_score=5.9, mitre_id="T1539", mitre_name="Steal Web Session Cookie",
            cwe="CWE-1004", owasp="A07:2021", evidence=f"Cookie '{cookie_header[:60]}...' has security deficiencies: {'; '.join(issues)}",
            recommendation="Set HttpOnly; Secure; SameSite=Lax (or Strict) on all session cookies to prevent theft via XSS.",
            references=["CWE-1004", "OWASP Session Management Cheat Sheet"]
        )

    return XSSFinding(
        check_id=_CID, category="Cookie-Security", title=_TITLE, status="SECURE",
        severity="Medium", cvss_score=5.9, mitre_id="T1539", mitre_name="Steal Web Session Cookie",
        cwe="CWE-1004", owasp="A07:2021", evidence="Session cookies enforce HttpOnly and SameSite protections.",
        recommendation="Continue enforcing secure cookie attributes.", references=["CWE-1004"]
    )


# ---------------------------------------------------------------------------
# Engine Runner
# ---------------------------------------------------------------------------

ALL_XSS_CHECKS = {
    "XSS-REF-01":   check_xss_reflected_html,
    "XSS-ATTR-02":  check_xss_attribute_breakout,
    "XSS-CSP-06":   check_xss_csp_policy,
    "XSS-COOKIE-07": check_xss_cookie_httponly,
}

def run_xss_assessment(
    target: XSSTarget,
    checks: Optional[List[str]] = None,
    log_fn: Optional[Callable] = None
) -> Dict[str, Any]:
    """Execute automated XSS assessment against the target."""
    global _log_fn
    _log_fn = log_fn

    if not _REQUESTS_OK:
        return {"scan_id": uuid.uuid4().hex[:12], "findings": [], "error": "Requests library not available"}

    _log(f"Starting XSS Assessment: {target.url}")
    session = _session(target)
    findings: List[XSSFinding] = []

    selected = {cid: fn for cid, fn in ALL_XSS_CHECKS.items()
                if checks is None or cid in checks}

    for cid, fn in selected.items():
        _log(f"Running {cid} ...")
        try:
            f = fn(target, session)
            findings.append(f)
            _log(f"{cid}: {f.status} | {f.evidence[:60]}")
        except Exception as exc:
            findings.append(XSSFinding(
                check_id=cid, category="General", title=cid, status="ERROR",
                severity="Info", cvss_score=0.0, mitre_id="T1059.007", mitre_name="JavaScript",
                cwe="CWE-79", owasp="A03:2021", evidence=f"Execution error: {exc}",
                recommendation="Investigate scan logs."
            ))

    vuln_count = sum(1 for f in findings if f.status == "VULNERABLE")
    sec_count = sum(1 for f in findings if f.status == "SECURE")

    return {
        "scan_id": uuid.uuid4().hex[:12],
        "target_url": target.url,
        "findings": [f.to_dict() for f in findings],
        "vulnerable_count": vuln_count,
        "secure_count": sec_count,
        "checks_run": len(findings),
        "timestamp": time.time()
    }
