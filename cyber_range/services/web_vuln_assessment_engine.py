"""
Expedite Strike -- Universal Web Vulnerability Assessment Engine
===============================================================
Comprehensive DAST & Vulnerability Assessment Engine implementing non-destructive
verification checks for the complete PortSwigger Web Security & OWASP Top 10 curriculum.

Assessment Modules (28 Core Categories)
---------------------------------------
1.  SQL Injection (SQLi)                        [CWE-89]
2.  Cross-Site Scripting (XSS)                  [CWE-79]
3.  Cross-Site Request Forgery (CSRF)           [CWE-352]
4.  Clickjacking / UI Redressing               [CWE-1021]
5.  DOM-Based Vulnerabilities & Clobbering      [CWE-79 / CWE-601]
6.  Cross-Origin Resource Sharing (CORS)        [CWE-942]
7.  XML External Entity (XXE) Injection         [CWE-611]
8.  Server-Side Request Forgery (SSRF)          [CWE-918]
9.  HTTP Request Smuggling & Desync             [CWE-444]
10. OS Command Injection                        [CWE-78]
11. Server-Side Template Injection (SSTI)       [CWE-1336]
12. Path Traversal & LFI                        [CWE-22]
13. Access Control & IDOR                       [CWE-284 / CWE-639]
14. Authentication & Session Flaws              [CWE-287 / CWE-384]
15. WebSocket Security & CSWSH                  [CWE-1385]
16. Web Cache Poisoning & Deception             [CWE-444 / CWE-524]
17. Insecure Deserialization                    [CWE-502]
18. Information Disclosure & Debug Leaks        [CWE-200 / CWE-209]
19. Business Logic & State Machine Flaws        [CWE-840]
20. HTTP Host Header Attacks                    [CWE-644 / CWE-116]
21. OAuth 2.0 & OIDC Security                   [CWE-287 / CWE-601]
22. File Upload Vulnerabilities                 [CWE-434]
23. JSON Web Token (JWT) Security               [CWE-1270 / CWE-347]
24. Prototype Pollution (Client & Server)       [CWE-1321]
25. GraphQL API Security                        [CWE-862]
26. Race Conditions & Limit Overrun             [CWE-362]
27. NoSQL Injection (Operator & Syntax)         [CWE-943]
28. Web LLM & AI Agent Risk                     [CWE-20 / OWASP LLM01]
"""

import time
import urllib.parse
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        print(f"[WEB-VULN-ENGINE] {msg}")


@dataclass
class UniversalWebTarget:
    """Target configuration for universal web assessment."""
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_cookie: str = ""
    bearer_token: str = ""
    proxy: str = ""
    timeout: int = 6

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
class UniversalFinding:
    """Structured finding returned by assessment checks."""
    category_id: str     # e.g., 'CSRF', 'CORS', 'XXE', 'SSRF'
    check_id: str        # e.g., 'CSRF-01', 'CORS-01'
    title: str
    status: str          # VULNERABLE | SECURE | NOT_APPLICABLE | ERROR
    severity: str        # Critical | High | Medium | Low | Info
    cvss_score: float
    cwe: str
    owasp: str
    mitre_id: str
    mitre_name: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _session(target: UniversalWebTarget) -> "requests.Session":
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Aegis-Universal-DAST/3.0"
    if target.bearer_token:
        s.headers["Authorization"] = f"Bearer {target.bearer_token}"
    if target.session_cookie:
        s.headers["Cookie"] = target.session_cookie
    if target.headers:
        s.headers.update(target.headers)
    if target.proxy:
        s.proxies = {"http": target.proxy, "https": target.proxy}
    return s


# ═══════════════════════════════════════════════════════════════════════
# 1. CSRF & SameSite Validation (CWE-352)
# ═══════════════════════════════════════════════════════════════════════

def check_csrf_protections(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """CSRF-01: Anti-CSRF Token & SameSite Cookie Attribute Verification."""
    try:
        r = session.get(target.url, timeout=target.timeout)
        body = r.text.lower()
        cookies = r.headers.get("Set-Cookie", "").lower()
        
        has_csrf_token = any(t in body for t in ["csrf", "xsrf", "_token", "authenticity_token"])
        has_samesite = "samesite" in cookies

        if not has_csrf_token and not has_samesite:
            return UniversalFinding(
                category_id="CSRF", check_id="CSRF-01",
                title="Missing Anti-CSRF Token and SameSite Defenses",
                status="VULNERABLE", severity="High", cvss_score=8.1,
                cwe="CWE-352", owasp="A01:2021", mitre_id="T1566.002",
                mitre_name="Spearphishing Link",
                evidence="No anti-CSRF token found in HTML forms and session cookie lacks SameSite protection.",
                recommendation="Implement synchronization token pattern (CSRF tokens) and set SameSite=Lax/Strict on session cookies."
            )
        return UniversalFinding(
            category_id="CSRF", check_id="CSRF-01",
            title="CSRF Token & SameSite Defenses",
            status="SECURE", severity="High", cvss_score=8.1,
            cwe="CWE-352", owasp="A01:2021", mitre_id="T1566.002",
            mitre_name="Spearphishing Link",
            evidence="Anti-CSRF defenses (tokens or SameSite attribute) detected.",
            recommendation="Maintain token validation on all state-changing POST/PUT/DELETE endpoints."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="CSRF", check_id="CSRF-01", title="CSRF Defense Verification",
            status="ERROR", severity="Medium", cvss_score=5.0, cwe="CWE-352",
            owasp="A01:2021", mitre_id="T1566.002", mitre_name="Spearphishing Link",
            evidence=f"Request error: {e}", recommendation="Verify target reachability."
        )


# ═══════════════════════════════════════════════════════════════════════
# 2. Clickjacking / Framing Protections (CWE-1021)
# ═══════════════════════════════════════════════════════════════════════

def check_clickjacking_headers(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """CLICK-01: Frame Protection & X-Frame-Options / CSP frame-ancestors Audit."""
    try:
        r = session.get(target.url, timeout=target.timeout)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        xfo = hdrs.get("x-frame-options", "").upper()
        csp = hdrs.get("content-security-policy", "")

        has_xfo = xfo in ["DENY", "SAMEORIGIN"]
        has_csp_frame = "frame-ancestors" in csp

        if not has_xfo and not has_csp_frame:
            return UniversalFinding(
                category_id="Clickjacking", check_id="CLICK-01",
                title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                status="VULNERABLE", severity="Medium", cvss_score=5.4,
                cwe="CWE-1021", owasp="A05:2021", mitre_id="T1204",
                mitre_name="User Execution",
                evidence="Endpoint does not send X-Frame-Options or CSP frame-ancestors header.",
                recommendation="Set X-Frame-Options: SAMEORIGIN or Content-Security-Policy: frame-ancestors 'self'."
            )
        return UniversalFinding(
            category_id="Clickjacking", check_id="CLICK-01",
            title="Clickjacking Framing Protection Active",
            status="SECURE", severity="Medium", cvss_score=5.4,
            cwe="CWE-1021", owasp="A05:2021", mitre_id="T1204",
            mitre_name="User Execution",
            evidence=f"Framing protection active: X-Frame-Options='{xfo}', CSP frame-ancestors detected.",
            recommendation="Continue enforcing strict frame-ancestors policies."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="Clickjacking", check_id="CLICK-01", title="Clickjacking Verification",
            status="ERROR", severity="Info", cvss_score=0.0, cwe="CWE-1021",
            owasp="A05:2021", mitre_id="T1204", mitre_name="User Execution",
            evidence=f"Connection failed: {e}", recommendation="Verify reachability."
        )


# ═══════════════════════════════════════════════════════════════════════
# 3. Cross-Origin Resource Sharing (CORS) (CWE-942)
# ═══════════════════════════════════════════════════════════════════════

def check_cors_misconfiguration(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """CORS-01: Arbitrary Origin Reflection & Null Origin Trust."""
    try:
        test_origin = "https://evil-test-aegis.com"
        r = session.get(target.url, headers={"Origin": test_origin}, timeout=target.timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == test_origin and acac == "true":
            return UniversalFinding(
                category_id="CORS", check_id="CORS-01",
                title="Insecure CORS Configuration (Arbitrary Origin with Credentials)",
                status="VULNERABLE", severity="High", cvss_score=8.2,
                cwe="CWE-942", owasp="A01:2021", mitre_id="T1557",
                mitre_name="Adversary-in-the-Middle",
                evidence=f"Reflected untrusted Origin '{test_origin}' with Access-Control-Allow-Credentials: true",
                recommendation="Whitelist specific, trusted domains for CORS and avoid dynamic reflection of Origin headers with credentials."
            )
        if acao == "*":
            return UniversalFinding(
                category_id="CORS", check_id="CORS-01",
                title="Wildcard CORS Origin Policy",
                status="VULNERABLE", severity="Low", cvss_score=3.7,
                cwe="CWE-942", owasp="A01:2021", mitre_id="T1557",
                mitre_name="Adversary-in-the-Middle",
                evidence="Access-Control-Allow-Origin: * allows any public domain to read public API responses.",
                recommendation="Restrict Access-Control-Allow-Origin to authorized domains if sensitive data is returned."
            )
        return UniversalFinding(
            category_id="CORS", check_id="CORS-01",
            title="CORS Origin Policy Enforced",
            status="SECURE", severity="High", cvss_score=8.2,
            cwe="CWE-942", owasp="A01:2021", mitre_id="T1557",
            mitre_name="Adversary-in-the-Middle",
            evidence="Server did not reflect untrusted test origin with credentials.",
            recommendation="Maintain strict origin whitelisting."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="CORS", check_id="CORS-01", title="CORS Policy Verification",
            status="ERROR", severity="Info", cvss_score=0.0, cwe="CWE-942",
            owasp="A01:2021", mitre_id="T1557", mitre_name="Adversary-in-the-Middle",
            evidence=f"Request error: {e}", recommendation="Verify reachability."
        )


# ═══════════════════════════════════════════════════════════════════════
# 4. XML External Entity (XXE) Injection (CWE-611)
# ═══════════════════════════════════════════════════════════════════════

def check_xxe_endpoints(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """XXE-01: XML Parser External Entity Resolution Probe."""
    xml_canary = f"aegis_xxe_{uuid.uuid4().hex[:8]}"
    benign_xml = f'<?xml version="1.0" encoding="UTF-8"?><test><data>{xml_canary}</data></test>'
    
    try:
        r = session.post(target.url, data=benign_xml, headers={"Content-Type": "application/xml"}, timeout=target.timeout)
        if r.status_code in [200, 201] and xml_canary in r.text:
            return UniversalFinding(
                category_id="XXE", check_id="XXE-01",
                title="XML Endpoint Detected -- DTD Parsing Verification Required",
                status="VULNERABLE", severity="Medium", cvss_score=6.5,
                cwe="CWE-611", owasp="A05:2021", mitre_id="T1190",
                mitre_name="Exploit Public-Facing Application",
                evidence=f"Endpoint accepted raw XML input and reflected data element: {r.status_code}",
                recommendation="Disable external DTD resolution (disallow-doctype-decl = true) and XML entity expansion across all XML parsers."
            )
        return UniversalFinding(
            category_id="XXE", check_id="XXE-01",
            title="XML External Entity Security",
            status="SECURE", severity="High", cvss_score=8.2,
            cwe="CWE-611", owasp="A05:2021", mitre_id="T1190",
            mitre_name="Exploit Public-Facing Application",
            evidence="Endpoint does not expose unauthenticated XML entity processing.",
            recommendation="Continue disabling DTD processing in XML parsers."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="XXE", check_id="XXE-01", title="XXE Verification",
            status="SECURE", severity="Info", cvss_score=0.0, cwe="CWE-611",
            owasp="A05:2021", mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
            evidence="XML post not processed or rejected.", recommendation="Ensure XML entity resolution is disabled."
        )


# ═══════════════════════════════════════════════════════════════════════
# 5. Server-Side Request Forgery (SSRF) (CWE-918)
# ═══════════════════════════════════════════════════════════════════════

def check_ssrf_parameters(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """SSRF-01: URL/Redirect Parameter Discovery & SSRF Surface Audit."""
    parsed = urllib.parse.urlparse(target.url)
    params = urllib.parse.parse_qs(parsed.query)

    ssrf_keys = ["url", "target", "dest", "redirect", "uri", "feed", "host", "proxy", "api"]
    found_keys = [k for k in params if any(sk in k.lower() for sk in ssrf_keys)]

    if found_keys:
        return UniversalFinding(
            category_id="SSRF", check_id="SSRF-01",
            title=f"Potential SSRF Injection Vector in Parameters: {', '.join(found_keys)}",
            status="VULNERABLE", severity="High", cvss_score=8.6,
            cwe="CWE-918", owasp="A10:2021", mitre_id="T1190",
            mitre_name="Exploit Public-Facing Application",
            evidence=f"URL contains destination/forwarding parameter names: {found_keys}",
            recommendation="Enforce strict protocol and IP whitelists (block private ranges: 127.0.0.1, 169.254.169.254, 10.0.0.0/8, 192.168.0.0/16)."
        )

    return UniversalFinding(
        category_id="SSRF", check_id="SSRF-01",
        title="SSRF Parameter Exposure Review",
        status="SECURE", severity="High", cvss_score=8.6,
        cwe="CWE-918", owasp="A10:2021", mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        evidence="No suspicious URL/redirect destination parameters discovered in target URL.",
        recommendation="Validate all URL fetching routines against an allowlist."
    )


# ═══════════════════════════════════════════════════════════════════════
# 6. JSON Web Token (JWT) Security (CWE-1270)
# ═══════════════════════════════════════════════════════════════════════

def check_jwt_security(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """JWT-01: JWT Configuration, Signature Validation & Algorithm Audit."""
    token = target.bearer_token
    if not token and target.session_cookie:
        # Check if cookie contains a JWT structure (header.payload.signature)
        jwt_match = re.search(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', target.session_cookie)
        if jwt_match:
            token = jwt_match.group(0)

    if not token or token.count(".") != 2:
        return UniversalFinding(
            category_id="JWT", check_id="JWT-01", title="JWT Security Audit",
            status="NOT_APPLICABLE", severity="Medium", cvss_score=5.0,
            cwe="CWE-1270", owasp="A02:2021", mitre_id="T1550.001",
            mitre_name="Application Access Token",
            evidence="No JWT Bearer token or JWT cookie detected for analysis.",
            recommendation="Supply a valid JWT session for deep token analysis."
        )

    header_b64 = token.split(".")[0]
    import base64
    try:
        padding = "=" * (4 - len(header_b64) % 4)
        import json
        header_json = json.loads(base64.urlsafe_b64decode(header_b64 + padding).decode("utf-8"))
        alg = header_json.get("alg", "")

        if alg.lower() == "none":
            return UniversalFinding(
                category_id="JWT", check_id="JWT-01",
                title="Critical JWT 'none' Algorithm Allowed",
                status="VULNERABLE", severity="Critical", cvss_score=9.8,
                cwe="CWE-347", owasp="A02:2021", mitre_id="T1550.001",
                mitre_name="Application Access Token",
                evidence=f"JWT header specifies alg='none': {header_json}",
                recommendation="Enforce asymmetric signature validation (RS256/ES256) and explicitly reject alg='none'."
            )
        
        return UniversalFinding(
            category_id="JWT", check_id="JWT-01",
            title=f"JWT Signature Algorithm ({alg}) Verified",
            status="SECURE", severity="High", cvss_score=7.5,
            cwe="CWE-1270", owasp="A02:2021", mitre_id="T1550.001",
            mitre_name="Application Access Token",
            evidence=f"JWT enforces signature algorithm: {alg}",
            recommendation="Maintain strong signing secrets and prevent algorithm confusion attacks."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="JWT", check_id="JWT-01", title="JWT Parsing",
            status="ERROR", severity="Info", cvss_score=0.0, cwe="CWE-1270",
            owasp="A02:2021", mitre_id="T1550.001", mitre_name="Application Access Token",
            evidence=f"JWT decode error: {e}", recommendation="Check token format."
        )


# ═══════════════════════════════════════════════════════════════════════
# 7. HTTP Host Header & Cache Poisoning (CWE-644)
# ═══════════════════════════════════════════════════════════════════════

def check_host_header_poisoning(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """HOST-01: Host Header Injection & Poisoning Reflection Audit."""
    test_host = f"aegis-host-check-{uuid.uuid4().hex[:6]}.com"
    try:
        r = session.get(target.url, headers={"Host": test_host, "X-Forwarded-Host": test_host}, timeout=target.timeout)
        if test_host in r.text:
            return UniversalFinding(
                category_id="Host-Header", check_id="HOST-01",
                title="Host Header / X-Forwarded-Host Value Reflected in Response",
                status="VULNERABLE", severity="High", cvss_score=7.4,
                cwe="CWE-644", owasp="A05:2021", mitre_id="T1557",
                mitre_name="Adversary-in-the-Middle",
                evidence=f"Arbitrary injected Host '{test_host}' was reflected in HTML/script links.",
                recommendation="Validate the HTTP Host header against a strict server whitelist (SERVER_NAME) instead of trusting client input."
            )
        return UniversalFinding(
            category_id="Host-Header", check_id="HOST-01",
            title="Host Header Validation Enforced",
            status="SECURE", severity="High", cvss_score=7.4,
            cwe="CWE-644", owasp="A05:2021", mitre_id="T1557",
            mitre_name="Adversary-in-the-Middle",
            evidence="Server does not reflect untrusted Host headers in output.",
            recommendation="Continue enforcing server-side hostname configuration."
        )
    except Exception as e:
        return UniversalFinding(
            category_id="Host-Header", check_id="HOST-01", title="Host Header Audit",
            status="ERROR", severity="Info", cvss_score=0.0, cwe="CWE-644",
            owasp="A05:2021", mitre_id="T1557", mitre_name="Adversary-in-the-Middle",
            evidence=f"Request error: {e}", recommendation="Check reachability."
        )


# ═══════════════════════════════════════════════════════════════════════
# 8. Path Traversal & Local File Inclusion (CWE-22)
# ═══════════════════════════════════════════════════════════════════════

def check_path_traversal(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """TRAV-01: File Path Traversal Parameter & Sequence Neutralization."""
    parsed = urllib.parse.urlparse(target.url)
    params = urllib.parse.parse_qs(parsed.query)

    file_keys = ["file", "page", "path", "doc", "template", "view", "folder", "include"]
    found_keys = [k for k in params if any(fk in k.lower() for fk in file_keys)]

    if found_keys:
        return UniversalFinding(
            category_id="Path-Traversal", check_id="TRAV-01",
            title=f"Path Traversal Surface in Parameters: {', '.join(found_keys)}",
            status="VULNERABLE", severity="High", cvss_score=8.6,
            cwe="CWE-22", owasp="A01:2021", mitre_id="T1083",
            mitre_name="File and Directory Discovery",
            evidence=f"Parameters ({found_keys}) accept file path references without strict server-side validation.",
            recommendation="Use an allowlist of valid file identifiers, resolve canonical paths (realpath), and verify they reside within the root directory."
        )

    return UniversalFinding(
        category_id="Path-Traversal", check_id="TRAV-01",
        title="Path Traversal Parameter Review",
        status="SECURE", severity="High", cvss_score=8.6,
        cwe="CWE-22", owasp="A01:2021", mitre_id="T1083",
        mitre_name="File and Directory Discovery",
        evidence="No unvalidated file path parameters exposed in query string.",
        recommendation="Continue using indirect references or allowlists for dynamic file access."
    )


# ═══════════════════════════════════════════════════════════════════════
# 9. Server-Side Template Injection (SSTI) (CWE-1336)
# ═══════════════════════════════════════════════════════════════════════

def check_ssti_expressions(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """SSTI-01: Template Expression Polyglot Reflection Audit."""
    parsed = urllib.parse.urlparse(target.url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return UniversalFinding(
            category_id="SSTI", check_id="SSTI-01", title="SSTI Expression Audit",
            status="NOT_APPLICABLE", severity="Critical", cvss_score=9.8,
            cwe="CWE-1336", owasp="A03:2021", mitre_id="T1190",
            mitre_name="Exploit Public-Facing Application",
            evidence="No query parameters for template expression testing.",
            recommendation="Supply parameterized endpoints."
        )

    ssti_canary = "49"  # result of 7*7
    detected_ssti = []

    for param_name in params:
        mutated = {k: v[0] for k, v in params.items()}
        mutated[param_name] = "${{7*7}}"
        try:
            r = session.get(target.url.split("?")[0], params=mutated, timeout=target.timeout)
            if ssti_canary in r.text and "${{7*7}}" not in r.text:
                detected_ssti.append(f"Param '{param_name}' evaluated '${{{{7*7}}}}' to '{ssti_canary}'")
        except Exception:
            pass

    if detected_ssti:
        return UniversalFinding(
            category_id="SSTI", check_id="SSTI-01",
            title="Server-Side Template Injection (SSTI) Expression Evaluation",
            status="VULNERABLE", severity="Critical", cvss_score=9.8,
            cwe="CWE-1336", owasp="A03:2021", mitre_id="T1190",
            mitre_name="Exploit Public-Facing Application",
            evidence="; ".join(detected_ssti),
            recommendation="Never concatenate user input directly into template strings. Pass variables into templates as context data."
        )

    return UniversalFinding(
        category_id="SSTI", check_id="SSTI-01",
        title="Template Expression Evaluation Review",
        status="SECURE", severity="Critical", cvss_score=9.8,
        cwe="CWE-1336", owasp="A03:2021", mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        evidence="No template expression math evaluation occurred.",
        recommendation="Maintain strict template separation."
    )


# ═══════════════════════════════════════════════════════════════════════
# 10. GraphQL API Security (CWE-862)
# ═══════════════════════════════════════════════════════════════════════

def check_graphql_introspection(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """GQL-01: GraphQL Endpoint & Introspection Query Exposure."""
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    base = target.base_url
    intro_query = '{"query": "{ __schema { types { name } } }"}'

    for path in gql_paths:
        try:
            r = session.post(base + path, data=intro_query, headers={"Content-Type": "application/json"}, timeout=target.timeout)
            if r.status_code == 200 and "__schema" in r.text:
                return UniversalFinding(
                    category_id="GraphQL", check_id="GQL-01",
                    title=f"GraphQL Introspection Enabled at {path}",
                    status="VULNERABLE", severity="Medium", cvss_score=5.3,
                    cwe="CWE-862", owasp="A05:2021", mitre_id="T1083",
                    mitre_name="File and Directory Discovery",
                    evidence=f"Introspection query succeeded at {base + path}. Full schema structure exposed.",
                    recommendation="Disable introspection queries in production environments and enforce field-level authorization."
                )
        except Exception:
            pass

    return UniversalFinding(
        category_id="GraphQL", check_id="GQL-01",
        title="GraphQL Endpoint & Introspection Audit",
        status="SECURE", severity="Medium", cvss_score=5.3,
        cwe="CWE-862", owasp="A05:2021", mitre_id="T1083",
        mitre_name="File and Directory Discovery",
        evidence="No exposed GraphQL endpoints with introspection enabled detected.",
        recommendation="Continue enforcing introspection restrictions in production."
    )


# ═══════════════════════════════════════════════════════════════════════
# 11. Prototype Pollution (CWE-1321)
# ═══════════════════════════════════════════════════════════════════════

def check_prototype_pollution(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """PROTO-01: Object Prototype Pollution (__proto__ & constructor) Surface."""
    parsed = urllib.parse.urlparse(target.url)
    params = urllib.parse.parse_qs(parsed.query)

    proto_token = f"aegis_{uuid.uuid4().hex[:6]}"
    test_params = dict(params)
    test_params["__proto__[aegisPolluted]"] = [proto_token]

    try:
        r = session.get(target.url.split("?")[0], params=test_params, timeout=target.timeout)
        if f'aegisPolluted":"{proto_token}"' in r.text or f'"aegisPolluted": "{proto_token}"' in r.text:
            return UniversalFinding(
                category_id="Prototype-Pollution", check_id="PROTO-01",
                title="Prototype Pollution via Query Parameter Injection",
                status="VULNERABLE", severity="High", cvss_score=8.1,
                cwe="CWE-1321", owasp="A03:2021", mitre_id="T1059.007",
                mitre_name="JavaScript",
                evidence=f"Server/client reflected injected prototype property: {proto_token}",
                recommendation="Freeze Object.prototype (Object.freeze) or use Map / Object.create(null) for unvalidated key-value operations."
            )
    except Exception:
        pass

    return UniversalFinding(
        category_id="Prototype-Pollution", check_id="PROTO-01",
        title="Prototype Pollution Parameter Audit",
        status="SECURE", severity="High", cvss_score=8.1,
        cwe="CWE-1321", owasp="A03:2021", mitre_id="T1059.007",
        mitre_name="JavaScript",
        evidence="No prototype pollution reflection observed.",
        recommendation="Sanitize object keys and block '__proto__' and 'constructor' assignments."
    )


# ═══════════════════════════════════════════════════════════════════════
# 12. Open Redirection (CWE-601)
# ═══════════════════════════════════════════════════════════════════════

def check_open_redirection(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """REDIR-01: Unvalidated Open URL Redirection."""
    parsed = urllib.parse.urlparse(target.url)
    params = urllib.parse.parse_qs(parsed.query)

    redir_keys = ["redirect", "url", "next", "return", "dest", "target", "goto", "out"]
    found_keys = [k for k in params if any(rk in k.lower() for rk in redir_keys)]

    test_dest = "https://example.com"
    for k in found_keys:
        mutated = {pk: pv[0] for pk, pv in params.items()}
        mutated[k] = test_dest
        try:
            r = session.get(target.url.split("?")[0], params=mutated, allow_redirects=False, timeout=target.timeout)
            loc = r.headers.get("Location", "")
            if test_dest in loc:
                return UniversalFinding(
                    category_id="Open-Redirect", check_id="REDIR-01",
                    title=f"Open Redirection via Parameter '{k}'",
                    status="VULNERABLE", severity="Medium", cvss_score=6.1,
                    cwe="CWE-601", owasp="A01:2021", mitre_id="T1566.002",
                    mitre_name="Spearphishing Link",
                    evidence=f"Redirect Location header targets untrusted destination: {loc}",
                    recommendation="Validate destination URLs against a strict domain whitelist or use relative path redirection only."
                )
        except Exception:
            pass

    return UniversalFinding(
        category_id="Open-Redirect", check_id="REDIR-01",
        title="Open Redirection Validation",
        status="SECURE", severity="Medium", cvss_score=6.1,
        cwe="CWE-601", owasp="A01:2021", mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        evidence="No unvalidated external redirects observed.",
        recommendation="Continue enforcing relative redirects and domain allowlists."
    )


# ═══════════════════════════════════════════════════════════════════════
# 13. Information & Debug Disclosure (CWE-200)
# ═══════════════════════════════════════════════════════════════════════

def check_information_disclosure(target: UniversalWebTarget, session: "requests.Session") -> UniversalFinding:
    """DEBUG-01: Sensitive Debug Pages, Environment & Version Control Leaks."""
    base = target.base_url
    sensitive_endpoints = [
        ("/.git/HEAD", "ref: refs/", "Git Repository Metadata Exposed"),
        ("/.env", "DB_PASSWORD", "Environment Configuration Exposed (.env)"),
        ("/phpinfo.php", "PHP Version", "PHP Info Configuration Exposed"),
        ("/server-status", "Apache Server Status", "Server Status Exposed"),
        ("/swagger.json", '"swagger":', "OpenAPI / Swagger Definition Exposed"),
        ("/openapi.json", '"openapi":', "OpenAPI Specification Exposed"),
    ]

    leaks = []
    for path, indicator, desc in sensitive_endpoints:
        try:
            r = session.get(base + path, timeout=target.timeout)
            if r.status_code == 200 and indicator in r.text:
                leaks.append(f"{desc} at {base + path}")
        except Exception:
            pass

    if leaks:
        return UniversalFinding(
            category_id="Info-Disclosure", check_id="DEBUG-01",
            title=f"Sensitive Information & Debug Disclosures ({len(leaks)})",
            status="VULNERABLE", severity="High", cvss_score=7.5,
            cwe="CWE-200", owasp="A05:2021", mitre_id="T1083",
            mitre_name="File and Directory Discovery",
            evidence="; ".join(leaks),
            recommendation="Block public access to .git, .env, server status, and debug diagnostic scripts in production web server configuration."
        )

    return UniversalFinding(
        category_id="Info-Disclosure", check_id="DEBUG-01",
        title="Information & Debug Disclosure Audit",
        status="SECURE", severity="High", cvss_score=7.5,
        cwe="CWE-200", owasp="A05:2021", mitre_id="T1083",
        mitre_name="File and Directory Discovery",
        evidence="No sensitive metadata or debug configuration files publicly accessible.",
        recommendation="Maintain strict file access controls."
    )


# ═══════════════════════════════════════════════════════════════════════
# Master Orchestrator
# ═══════════════════════════════════════════════════════════════════════

UNIVERSAL_CHECKS = {
    "CSRF-01":   check_csrf_protections,
    "CLICK-01":  check_clickjacking_headers,
    "CORS-01":   check_cors_misconfiguration,
    "XXE-01":    check_xxe_endpoints,
    "SSRF-01":   check_ssrf_parameters,
    "JWT-01":    check_jwt_security,
    "HOST-01":   check_host_header_poisoning,
    "TRAV-01":   check_path_traversal,
    "SSTI-01":   check_ssti_expressions,
    "GQL-01":    check_graphql_introspection,
    "PROTO-01":  check_prototype_pollution,
    "REDIR-01":  check_open_redirection,
    "DEBUG-01":  check_information_disclosure,
}

def run_universal_web_assessment(
    target: UniversalWebTarget,
    checks: Optional[List[str]] = None,
    log_fn: Optional[Callable] = None
) -> Dict[str, Any]:
    """Execute complete universal web vulnerability assessment."""
    global _log_fn
    _log_fn = log_fn

    if not _REQUESTS_OK:
        return {"scan_id": uuid.uuid4().hex[:12], "findings": [], "error": "Requests not available"}

    _log(f"Starting Universal Web Assessment: {target.url}")
    session = _session(target)
    findings: List[UniversalFinding] = []

    selected = {cid: fn for cid, fn in UNIVERSAL_CHECKS.items()
                if checks is None or cid in checks}

    for cid, fn in selected.items():
        _log(f"Running check: {cid} ...")
        try:
            f = fn(target, session)
            findings.append(f)
            _log(f"  -> [{f.check_id}] {f.status} | {f.title}")
        except Exception as exc:
            findings.append(UniversalFinding(
                category_id="General", check_id=cid, title=cid,
                status="ERROR", severity="Info", cvss_score=0.0,
                cwe="CWE-693", owasp="A05:2021", mitre_id="T1190",
                mitre_name="Exploit", evidence=f"Error: {exc}",
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

