"""
Admin Portal — Flask Blueprint (Redesigned)
============================================
Routes:
    GET  /admin          → Modern card-style login page
    POST /admin/auth     → Validate → redirect to /admin/panel
    GET  /admin/panel    → Ops-center style admin portal
    POST /admin/save     → Save permissions (JSON API)
    POST /admin/adduser  → Create user
    POST /admin/deluser  → Delete user
    GET  /admin/logout   → Logout → back to /admin
"""

import os, json, functools, base64, io
from flask import Blueprint, request, redirect, session, Response

PERM_FILE = os.path.join(os.path.dirname(__file__), "user_permissions.json")
bp        = Blueprint("admin_portal", __name__, url_prefix="/admin")
MAIN_APP  = "/admin/panel"   # Redirect here after login (admin portal)

def _load():
    try:    return json.load(open(PERM_FILE))
    except: return {"users": {}, "all_tabs": []}

def _save(data):
    json.dump(data, open(PERM_FILE, "w"), indent=2)

def _require_admin(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin_logged_in"):
            return redirect("/admin")
        return f(*a, **kw)
    return wrapper


# ── Canonical navigation catalog ─────────────────────────────────────────────
# Single source of truth: every menu group + every sub-menu item (nav ID → label).
NAV_CATALOG = [
    {"menu": "⚙️ Platform", "icon": "fa-gear", "items": [
        {"id": "nav-home",           "label": "🏠 Home"},
        {"id": "nav-admin",          "label": "⚙️ Admin Panel [RBAC]"},
        {"id": "nav-burp-engine",    "label": "🕷 XStrikeProbe"},
        {"id": "nav-system",         "label": "System Health"},
        {"id": "nav-assessment",     "label": "Assessment"},
        {"id": "nav-import",         "label": "Import Feeds"},
        {"id": "nav-llm",            "label": "LLM Engine"},
        {"id": "nav-phd-comparison", "label": "🎓 PhD AI Comparison"},
        {"id": "nav-phd-advanced",   "label": "🔬 PhD Research Tools"},
        {"id": "nav-enhancements",   "label": "🚀 Platform Enhancements"},
        {"id": "nav-chatbot",        "label": "Chatbot"},
        {"id": "nav-voice",          "label": "🎙️ Voice Simulator"},
    ]},
    {"menu": "🔎 External Assessment", "icon": "fa-magnifying-glass", "items": [

        {"id": "menu-osint-0",   "label": "OSINT Intelligence"},
        {"id": "menu-ti-0",      "label": "Threat Intelligence"},
        {"id": "menu-darkweb-0", "label": "Dark Web Monitor"},
        {"id": "menu-neo4j-1",   "label": "Neo4j Graph Explorer"},
        {"id": "menu-neo4j-2",   "label": "Neo4j Graph Presets"},
    ]},
    {"menu": "🎯 Attack Surface", "icon": "fa-crosshairs", "items": [
        {"id": "nav-vulns",               "label": "Vulnerabilities"},
        {"id": "menu-vuln-mgmt-0",        "label": "Vulnerability Management"},
        {"id": "menu-mitre-0",            "label": "MITRE ATT&CK Intelligence"},
        {"id": "menu-mitre-1",            "label": "Threat Actor Profiling"},
        {"id": "menu-mitre-2",            "label": "TTP Correlation Analysis"},
        {"id": "menu-mitre-3",            "label": "Campaign Attribution Modeling"},
        {"id": "menu-mitre-4",            "label": "Detection Gap Mapping"},
        {"id": "menu-mitre-5",            "label": "Control Effectiveness Mapping"},
        {"id": "menu-mitre-6",            "label": "D3FEND Mapping"},
        {"id": "menu-identity-posture-0", "label": "Identity Posture (Entra/SaaS)"},
        {"id": "menu-shadow-ai-0",        "label": "Shadow AI Discovery"},
    ]},
    {"menu": "🔴 Red Team", "icon": "fa-circle", "items": [
        {"id": "menu-sim-0",         "label": "Attack Chain Simulator"},
        {"id": "menu-sim-1",         "label": "Kill Chain"},
        {"id": "menu-sim-2",         "label": "Digital Twin"},
        {"id": "menu-sim-3",         "label": "Honeypots"},
        {"id": "menu-sim-4",         "label": "Exploit AI"},
        {"id": "menu-sim-5",         "label": "Wargame AI"},
        {"id": "menu-apt-0",         "label": "Automated Pen Testing"},
        {"id": "menu-apt-1",         "label": "Exploitation"},
        {"id": "menu-apt-2",         "label": "Post Exploitation"},
        {"id": "menu-ad-0",          "label": "AD RedOps Scanner"},
        {"id": "menu-redteam-0",     "label": "Red Team Infrastructure"},
        {"id": "menu-pingcastle-0",  "label": "🏰 PingCastle AD Assessment"},
        {"id": "menu-iam-redteam-0", "label": "IAM / MFA Bypass"},
        {"id": "menu-llm-redteam-0", "label": "LLM Red Teaming"},
    ]},
    {"menu": "🛡️ Defence", "icon": "fa-shield-halved", "items": [
        {"id": "menu-sast-0",         "label": "SAST Scanner"},
        {"id": "menu-api-0",          "label": "API Assessment"},
        {"id": "menu-container-0",    "label": "Container & K8s Security"},
        {"id": "menu-supply-0",       "label": "Supply Chain Security"},
        {"id": "menu-phishing-0",     "label": "Phishing & Email Security"},
        {"id": "menu-hunting-0",      "label": "Threat Hunting"},
        {"id": "menu-oauth-0",        "label": "OAuth / OIDC Security"},
        {"id": "menu-ai-hardening-0", "label": "AI Model Hardening"},
        {"id": "menu-edr-gaps-0",     "label": "EDR Gap Analysis"},
        {"id": "menu-waa-0",          "label": "Web App — Recon/Scan"},
        {"id": "menu-waa-1",          "label": "Web App — Exploitation"},
        {"id": "menu-waa-2",          "label": "Web App — Priv Escalation"},
        {"id": "menu-waa-3",          "label": "Web App — Lateral Movement"},
        {"id": "menu-waa-4",          "label": "Web App — Post Exploitation"},
        {"id": "menu-waa-5",          "label": "Web App — Reporting"},
    ]},
    {"menu": "🏭 Specialised", "icon": "fa-industry", "items": [
        {"id": "menu-cloud-0",    "label": "Cloud Assessment"},
        {"id": "menu-iot-0",      "label": "IoT / OT Security"},
        {"id": "menu-forensics-0","label": "Digital Forensics"},
        {"id": "menu-mobile-0",   "label": "Mobile Security"},
        {"id": "menu-ir-0",       "label": "IR Playbooks"},
        {"id": "nav-plugins",     "label": "🔌 Security Plugins"},
    ]},
    {"menu": "📋 GRC & Reports", "icon": "fa-clipboard-list", "items": [
        {"id": "menu-compliance-0","label": "Compliance & GRC"},
        {"id": "menu-dfir-case-0", "label": "DFIR Case Management"},
        {"id": "menu-rep-0",       "label": "1. Executive Summary"},
        {"id": "menu-rep-1",       "label": "2. Attack Timeline Analysis"},
        {"id": "menu-rep-2",       "label": "3. Impacted Assets"},
        {"id": "menu-rep-3",       "label": "4. User & Identity Impact"},
        {"id": "menu-rep-4",       "label": "5. Vulnerability Exploitation"},
        {"id": "menu-rep-5",       "label": "6. Malware / Tooling Used"},
        {"id": "menu-rep-6",       "label": "7. Detection & Monitoring"},
        {"id": "menu-rep-7",       "label": "8. Data Exposure & Exfiltration"},
        {"id": "menu-rep-8",       "label": "9. Lateral Movement Analysis"},
        {"id": "menu-rep-9",       "label": "10. Control Failures & Gaps"},
        {"id": "menu-rep-10",      "label": "11. Remediation & Recovery"},
        {"id": "menu-rep-11",      "label": "12. Compliance Reporting"},
        {"id": "menu-rep-12",      "label": "13. Neo4j Graph Report"},
        {"id": "menu-rep-13",      "label": "14. Shared Drive Analysis"},
    ]},
]
# Flat list of all nav IDs for quick membership tests
ALL_NAV_IDS = [item["id"] for group in NAV_CATALOG for item in group["items"]]


# ─── LOGIN PAGE ───────────────────────────────────────────────────────────────
@bp.route("/", methods=["GET"])
def login_page():
    err = request.args.get("err", "")
    info = request.args.get("info", "")
    err_html = f'<div class="err-msg">❌ {err}</div>' if err else ""
    info_html = f'<div style="background:#d4edda;border:1px solid #c3e6cb;color:#155724;font-size:12px;padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600">✅ {info}</div>' if info else ""
    body = f"""
<div class="login-wrap">
  <div class="login-card">
    <div class="avatar-ring">
      <svg viewBox="0 0 120 120" width="90" height="90">
        <circle cx="60" cy="60" r="58" fill="#a0a6af"/>
        <circle cx="60" cy="44" r="20" fill="#7a8290"/>
        <ellipse cx="60" cy="95" rx="32" ry="22" fill="#7a8290"/>
      </svg>
    </div>
    <div class="card-title">LOGIN</div>
    {err_html}{info_html}
    <form method="POST" action="/admin/auth">
      <div class="input-row">
        <span class="input-icon"><i class="fas fa-user"></i></span>
        <input type="text" name="username" placeholder="Username" autofocus autocomplete="off">
      </div>
      <div class="input-row">
        <span class="input-icon"><i class="fas fa-lock"></i></span>
        <input type="password" name="password" placeholder="Password">
      </div>
      <label class="remember-row">
        <input type="checkbox" name="remember" value="1"> Remember me
      </label>
      <button type="submit" class="login-btn">LOGIN</button>
    </form>
    <a href="/admin/forgot" class="forgot-link">Forgot Username / Password?</a>
  </div>
</div>
"""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter','Segoe UI',sans-serif;
      background:linear-gradient(160deg,#b8bcc4 0%,#a8adb6 100%);min-height:100vh}}
.login-wrap{{min-height:100vh;display:flex;align-items:center;justify-content:center}}
.login-card{{background:#bec3cb;padding:44px 36px 32px;border-radius:10px;width:360px;
             box-shadow:0 8px 32px rgba(0,0,0,0.18);position:relative;text-align:center}}
.avatar-ring{{margin-top:-50px;margin-bottom:10px;text-align:center}}
.card-title{{font-size:18px;font-weight:700;color:#5a6069;letter-spacing:3px;margin-bottom:22px}}
.input-row{{display:flex;align-items:stretch;margin-bottom:12px;background:#e8ecf0;
            border-bottom:2px solid #cdd1d6}}
.input-icon{{display:flex;align-items:center;justify-content:center;width:42px;
             color:#8a929c;font-size:14px;background:#e8ecf0}}
.input-row input[type="text"],.input-row input[type="password"]{{
  flex:1;padding:10px 12px;background:#e8ecf0;border:none;color:#444;font-size:14px;
  font-family:inherit;outline:none}}
.input-row input::placeholder{{color:#999}}
.remember-row{{display:flex;align-items:center;gap:6px;font-size:12px;color:#7a8290;
               margin-bottom:18px;cursor:pointer;text-align:left}}
.remember-row input{{width:auto;margin:0;accent-color:#5ea7d8}}
.err-msg{{background:#f8d7da;border:1px solid #f5c2c7;color:#842029;font-size:12px;
          padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600}}
.login-btn{{width:100%;padding:11px;background:linear-gradient(135deg,#5ea7d8,#4a90c4);
            border:none;border-radius:20px;color:#fff;font-size:14px;font-weight:700;
            letter-spacing:3px;cursor:pointer;box-shadow:0 4px 14px rgba(74,144,196,0.35);
            transition:all .25s ease;font-family:inherit}}
.login-btn:hover{{box-shadow:0 6px 20px rgba(74,144,196,0.5);transform:translateY(-1px)}}
.forgot-link{{font-size:11px;color:#98a0aa;margin-top:16px;cursor:pointer}}
.forgot-link:hover{{color:#5ea7d8}}
</style>
</head><body>{body}</body></html>"""


# ─── AUTH ─────────────────────────────────────────────────────────────────────
@bp.route("/auth", methods=["POST"])
def auth():
    username  = request.form.get("username","").strip().lower()
    password  = request.form.get("password","")
    next_url  = request.form.get("next_url","").strip()   # e.g. "/app/" from landing page
    data      = _load()
    users     = data.get("users",{})

    # ── Pre-authorized first-time login: password not set yet ──
    # Match by username OR by the local part of an email in the DB
    matched_key = None
    if username in users:
        matched_key = username
    else:
        local = username.split("@")[0] if "@" in username else username
        if local in users:
            matched_key = local

    if matched_key and users[matched_key].get("pending_approval") and not users[matched_key].get("password"):
        # User is whitelisted but has never set a password — send to first-login setup
        session["first_login_user"]    = matched_key
        session["first_login_next_url"] = next_url
        if next_url:                        # came from landing page
            from flask import jsonify
            return jsonify({"ok": False, "first_login": True,
                            "redirect": "/admin/first-login"}), 200
        return redirect("/admin/first-login")

    if matched_key is None or users[matched_key].get("password","") != password:
        if next_url:
            from flask import jsonify
            return jsonify({"ok": False, "error": "Invalid credentials"}), 401
        return redirect("/admin?err=Invalid+username+or+password")

    username = matched_key
    role = users[username].get("role","viewer")

    # Stage 1a: First-login — force password change before MFA (applies to all login paths)
    if users[username].get("must_change_password"):
        session["admin_logged_in"] = True
        session["admin_user"]      = username
        session["admin_role"]      = role
        if next_url:
            from flask import jsonify
            return jsonify({"ok": False, "redirect": "/admin/change-password"}), 200
        return redirect("/admin/change-password")

    # ── 2FA disabled — complete login immediately after credentials ──
    udata = users[username]
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role
    session["username"]        = username
    session["logged_in"]       = True

    # Landing-page login (next_url set) — return JSON so JS navigates
    if next_url:
        from flask import jsonify
        display = udata.get("display_name", username)

        # ── Role-aware redirect: send user to their module, not admin panel ──
        tabs    = udata.get("tabs", [])
        nav     = udata.get("nav_items", [])
        has_all = tabs == ["all"] or nav == "all"

        _TAB_MAP = {
            "assessment": "/app/assessment", "api-assessment": "/app/assessment",
            "automated_pt": "/app/redteam",  "red-team": "/app/redteam",
            "privesc": "/app/redteam",       "exploitation": "/app/redteam",
            "osint": "/app/attack",          "mitre": "/app/attack",
            "attack_chain": "/app/attack",   "killchain": "/app/attack",
            "forensics": "/app/defence",     "threat-hunting": "/app/defence",
            "dfir-case": "/app/defence",     "edr-gaps": "/app/defence",
            "threat-intel": "/app/intel",    "darkweb": "/app/intel",
            "supply-chain": "/app/intel",    "phishing": "/app/intel",
            "compliance": "/app/grc",        "grc-executive": "/app/grc",
            "vuln-mgmt": "/app/grc",         "pingcastle": "/app/grc",
            "sast": "/app/specialised",      "cloud-security": "/app/specialised",
            "iot-sec": "/app/specialised",   "container-sec": "/app/specialised",
            "phd-comparison": "/app/ai",     "phd-advanced": "/app/ai",
            "voice": "/app/ai",              "ai-hardening": "/app/ai",
            "admin": "/app/admin-panel",     "plugins": "/app/admin-panel",
        }
        _ROLE_DEFAULT = {
            "admin":   "/app/",
            "manager": "/app/grc",
            "analyst": "/app/assessment",
            "viewer":  "/app/assessment",
        }

        # Priority 1: explicit default_page set by admin
        if udata.get("default_page"):
            redirect_url = udata["default_page"]
        elif has_all:
            # Priority 2: role default for full-access users
            redirect_url = _ROLE_DEFAULT.get(role, "/app/assessment")
        else:
            # Priority 3: first assigned tab
            redirect_url = "/app/assessment"
            for t in (tabs if isinstance(tabs, list) else []):
                if t in _TAB_MAP:
                    redirect_url = _TAB_MAP[t]
                    break

        return jsonify({"ok": True, "display": display, "role": role,
                        "redirect": redirect_url})


    # Admin portal login — redirect directly to panel
    return redirect(MAIN_APP)


# ─── USER MFA CHECK (landing-page login: existing MFA users) ─────────────────
@bp.route("/user-mfa-check", methods=["POST"])
def user_mfa_check():
    """Verify the TOTP code for a user who is mid-login from the landing page."""
    from flask import jsonify
    username = session.get("mfa_pending_user", "")
    if not username:
        return jsonify({"ok": False, "error": "Session expired. Please log in again."}), 401

    code     = request.form.get("code", "").strip()
    next_url = session.get("mfa_pending_next_url", "/app/")
    data     = _load()
    udata    = data.get("users", {}).get(username, {})
    secret   = udata.get("mfa_secret", "")

    if not secret:
        return jsonify({"ok": False, "error": "MFA not set up. Please contact your administrator."}), 400

    totp = __import__("pyotp").TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "error": "Invalid code — please try again."}), 401

    # ✅ MFA passed — complete the login
    role = session.get("mfa_pending_role", "viewer")
    session.pop("mfa_pending_user",     None)
    session.pop("mfa_pending_role",     None)
    session.pop("mfa_pending_next_url", None)
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role
    session["username"]        = username
    session["logged_in"]       = True
    display = udata.get("display_name", username)
    return jsonify({"ok": True, "display": display, "role": role,
                    "redirect": next_url or "/app/"})


# ─── USER MFA ENROLL (landing-page login: new users scanning QR) ─────────────
@bp.route("/user-mfa-enroll", methods=["POST"])
def user_mfa_enroll():
    """Confirm the TOTP code during MFA enrollment for a new user (landing page)."""
    from flask import jsonify
    username = session.get("mfa_pending_user", "")
    secret   = session.get("mfa_setup_secret", "")
    if not username or not secret:
        return jsonify({"ok": False, "error": "Session expired. Please log in again."}), 401

    code     = request.form.get("code", "").strip()
    next_url = session.get("mfa_pending_next_url", "/app/")

    totp = __import__("pyotp").TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "error": "Invalid code — please try again."}), 401

    # Save MFA secret to user record
    data = _load()
    if username in data.get("users", {}):
        data["users"][username]["mfa_secret"] = secret
        _save(data)
        udata = data["users"][username]
    else:
        return jsonify({"ok": False, "error": "User not found."}), 404

    # ✅ MFA enrolled & verified — complete the login
    role = session.get("mfa_pending_role", "viewer")
    session.pop("mfa_pending_user",     None)
    session.pop("mfa_pending_role",     None)
    session.pop("mfa_pending_next_url", None)
    session.pop("mfa_setup_secret",     None)
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role
    session["username"]        = username
    session["logged_in"]       = True
    display = udata.get("display_name", username)
    return jsonify({"ok": True, "display": display, "role": role,
                    "redirect": next_url or "/app/"})


# ─── FIRST-TIME PASSWORD SETUP (pre-authorized users) ────────────────────────
@bp.route("/first-login", methods=["GET"])
def first_login_page():
    username = session.get("first_login_user","")
    if not username:
        return redirect("/admin")
    err = request.args.get("err","")
    err_html = f'<div class="err-msg">❌ {err}</div>' if err else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set Password — VulnIntel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:linear-gradient(160deg,#b8bcc4 0%,#a8adb6 100%);min-height:100vh}}
.wrap{{min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#bec3cb;padding:44px 36px 32px;border-radius:10px;width:400px;
       box-shadow:0 8px 32px rgba(0,0,0,0.18);text-align:center}}
.avatar{{margin-top:-50px;margin-bottom:10px}}
.title{{font-size:16px;font-weight:700;color:#5a6069;letter-spacing:2px;margin-bottom:6px}}
.subtitle{{font-size:12px;color:#7a8290;margin-bottom:20px;line-height:1.6}}
.input-row{{display:flex;align-items:stretch;margin-bottom:12px;background:#e8ecf0;border-bottom:2px solid #cdd1d6}}
.input-icon{{display:flex;align-items:center;justify-content:center;width:42px;color:#8a929c;font-size:14px;background:#e8ecf0}}
.input-row input{{flex:1;padding:10px 12px;background:#e8ecf0;border:none;color:#444;font-size:14px;font-family:inherit;outline:none}}
.input-row input::placeholder{{color:#999}}
.err-msg{{background:#f8d7da;border:1px solid #f5c2c7;color:#842029;font-size:12px;
          padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600}}
.submit-btn{{width:100%;padding:11px;background:linear-gradient(135deg,#44bb88,#339966);
             border:none;border-radius:20px;color:#fff;font-size:14px;font-weight:700;
             letter-spacing:2px;cursor:pointer;transition:all .25s ease;font-family:inherit}}
.submit-btn:hover{{box-shadow:0 6px 20px rgba(51,153,102,0.5);transform:translateY(-1px)}}
.badge{{display:inline-block;background:#2a1a00;color:#ffd080;border:1px solid #ff990066;
        font-size:11px;padding:4px 12px;border-radius:4px;margin-bottom:16px;font-weight:600}}
</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="avatar">
    <svg viewBox="0 0 120 120" width="80" height="80">
      <circle cx="60" cy="60" r="58" fill="#a0a6af"/>
      <circle cx="60" cy="44" r="20" fill="#7a8290"/>
      <ellipse cx="60" cy="95" rx="32" ry="22" fill="#7a8290"/>
    </svg>
  </div>
  <div class="badge">⚡ Pre-Authorized Account</div>
  <div class="title">SET YOUR PASSWORD</div>
  <div class="subtitle">Welcome, <strong>{username}</strong>!<br>Your account has been pre-authorized.<br>Please set a secure password to activate it.</div>
  {err_html}
  <form method="POST" action="/admin/first-login-save">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-lock"></i></span>
      <input type="password" name="new_password" placeholder="New password (min 8 chars)" required autofocus>
    </div>
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-check-double"></i></span>
      <input type="password" name="confirm_password" placeholder="Confirm password" required>
    </div>
    <button type="submit" class="submit-btn">ACTIVATE ACCOUNT</button>
  </form>
</div></div>
</body></html>"""


@bp.route("/first-login-save", methods=["POST"])
def first_login_save():
    username = session.get("first_login_user","")
    next_url = session.get("first_login_next_url","")
    if not username:
        return redirect("/admin")
    new_pw  = request.form.get("new_password","")
    conf_pw = request.form.get("confirm_password","")
    if len(new_pw) < 8:
        return redirect("/admin/first-login?err=Password+must+be+at+least+8+characters")
    if new_pw != conf_pw:
        return redirect("/admin/first-login?err=Passwords+do+not+match")

    data = _load()
    if username in data.get("users",{}):
        data["users"][username]["password"] = new_pw
        data["users"][username].pop("pending_approval", None)
        data["users"][username].pop("must_change_password", None)
        _save(data)

    # Log the user in immediately
    role = data["users"].get(username,{}).get("role","viewer")
    session.pop("first_login_user", None)
    session.pop("first_login_next_url", None)
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role
    session["logged_in"]       = True

    return redirect(next_url if next_url else "/")


# ─── PANEL PAGE — OPS-CENTER STYLE ───────────────────────────────────────────
@bp.route("/panel", methods=["GET"])
@_require_admin
def panel():
    import pyotp as _pyotp, base64 as _b64, io as _io
    try: import qrcode as _qr
    except ImportError: _qr = None

    data     = _load()
    users    = data.get("users",{})
    all_tabs = data.get("all_tabs",[])
    admin    = session.get("admin_user","admin")

    # Exempt users — never generate or display QR codes for these
    MFA_EXEMPT = {"admin", "yasiedu"}

    # Build users_js: safe version (no plaintext passwords), with qr_b64 for non-exempt
    users_js = {}
    for uname, udata in users.items():
        safe = {
            "role":         udata.get("role","viewer"),
            "display_name": udata.get("display_name", uname),
            "tabs":         udata.get("tabs",[]),
            "nav_items":    udata.get("nav_items", None),
            "has_mfa":      bool(udata.get("mfa_secret","")),
            "exempt":       uname in MFA_EXEMPT,
            "qr_b64":       None,
            "mfa_secret":   None,
        }
        if uname not in MFA_EXEMPT and _qr:
            secret = udata.get("mfa_secret") or _pyotp.random_base32()
            try:
                totp = _pyotp.TOTP(secret)
                uri  = totp.provisioning_uri(name=uname, issuer_name="VulnIntel")
                img  = _qr.make(uri, box_size=5, border=2)
                buf  = _io.BytesIO()
                img.save(buf, format="PNG")
                safe["qr_b64"]     = _b64.b64encode(buf.getvalue()).decode()
                safe["mfa_secret"] = secret
            except Exception:
                pass
        users_js[uname] = safe

    # Build user list cards
    user_cards = ""
    for uname, udata in users.items():
        role  = udata.get("role","viewer")
        dname = udata.get("display_name", uname)
        email = udata.get("email", "")
        utabs = udata.get("tabs",[])
        ntabs = "ALL" if "all" in utabs else str(len(utabs))
        is_pending = udata.get("pending_approval", False) or role == "pending"
        role_colors = {"admin":"#ff4444","manager":"#ff8800","analyst":"#44aaff","viewer":"#666","pending":"#ff9900"}
        rc = role_colors.get(role,"#666")
        pending_badge = '<span style="background:#2a1a00;color:#ff9900;border:1px solid #ff990044;font-size:8px;font-weight:800;letter-spacing:1px;padding:2px 6px;border-radius:2px;margin-left:6px;">⏳ PENDING</span>' if is_pending else ""
        email_row = f'<div style="font-size:9px;color:#ff9900;margin-top:2px">{email}</div>' if is_pending and email else ""
        border_clr = "#ff990033" if is_pending else "#1a1a28"
        left_clr   = "#ff9900"   if is_pending else "#1a1a28"
        user_cards += f"""
        <div class="user-card" onclick="selectUser('{uname}')" id="u-{uname}" style="border-left-color:{left_clr};border-color:{border_clr}">
          <div class="user-card-inner">
            <div class="user-avatar"><i class="fas fa-user-circle"></i></div>
            <div class="user-info">
              <div class="user-name">{dname}{pending_badge}</div>
              <div class="user-handle">@{uname}</div>
              {email_row}
            </div>
            <div class="user-meta">
              <span class="role-tag" style="color:{rc};border-color:{rc}44">{role.upper()}</span>
              <div class="user-tabs">{ntabs} tabs</div>
            </div>
          </div>
        </div>"""


    # Count roles for stats
    role_counts = {"admin":0,"manager":0,"analyst":0,"viewer":0}
    for u in users.values():
        r = u.get("role","viewer")
        if r in role_counts: role_counts[r] += 1

    body = f"""
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!--  TOP NAVIGATION BAR                                                     -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="topbar">
  <div class="topbar-left">
    <div class="brand-box">
      <i class="fas fa-shield-halved brand-icon"></i>
      <span class="brand-text">VULNINTEL</span>
    </div>
    <span class="topbar-title">Admin Operations Center</span>
    <span class="topbar-badge live-badge">● LIVE</span>
  </div>
  <div class="topbar-right">
    <div class="topbar-stat">
      <i class="fas fa-users"></i> <strong>{len(users)}</strong> Users
    </div>
    <div class="topbar-stat">
      <i class="fas fa-layer-group"></i> <strong>{len(all_tabs)}</strong> Modules
    </div>
    <div class="topbar-user">
      <i class="fas fa-user-shield"></i> {admin}
    </div>
    <a href="/" class="topbar-btn launch-btn">
      <i class="fas fa-rocket"></i> Launch Dashboard
    </a>
    <a href="/admin/logout" class="topbar-btn logout-btn">
      <i class="fas fa-right-from-bracket"></i> Logout
    </a>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!--  STATS ROW                                                              -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-icon" style="color:#ff4444"><i class="fas fa-users-cog"></i></div>
    <div><div class="stat-val">{len(users)}</div><div class="stat-label">Total Users</div></div>
  </div>
  <div class="stat-card">
    <div class="stat-icon" style="color:#ff4444"><i class="fas fa-crown"></i></div>
    <div><div class="stat-val">{role_counts['admin']}</div><div class="stat-label">Admins</div></div>
  </div>
  <div class="stat-card">
    <div class="stat-icon" style="color:#ff8800"><i class="fas fa-clipboard-list"></i></div>
    <div><div class="stat-val">{role_counts['manager']}</div><div class="stat-label">Managers</div></div>
  </div>
  <div class="stat-card">
    <div class="stat-icon" style="color:#44aaff"><i class="fas fa-magnifying-glass"></i></div>
    <div><div class="stat-val">{role_counts['analyst']}</div><div class="stat-label">Analysts</div></div>
  </div>
  <div class="stat-card">
    <div class="stat-icon" style="color:#888"><i class="fas fa-eye"></i></div>
    <div><div class="stat-val">{role_counts['viewer']}</div><div class="stat-label">Viewers</div></div>
  </div>
  <div class="stat-card">
    <div class="stat-icon" style="color:#44ff88"><i class="fas fa-puzzle-piece"></i></div>
    <div><div class="stat-val">{len(all_tabs)}</div><div class="stat-label">Modules</div></div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!--  MAIN BODY: 3 PANEL LAYOUT                                             -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div class="body-wrap">

  <!-- LEFT PANEL: Users List -->
  <div class="panel-left">
    <div class="panel-header">
      <i class="fas fa-address-book"></i> Registered Users
    </div>
    <div class="user-list" id="user-list">{user_cards}</div>
  </div>

  <!-- CENTER PANEL: Pre-Authorize + Register + Permissions -->
  <div class="panel-center">

    <!-- ① Pre-Authorize (whitelist — user sets own password on registration) -->
    <div class="register-section" style="border-bottom:1px solid #ff990022;background:#0d0d18">
      <div class="section-header" style="color:#ff9900">
        <i class="fas fa-shield-check"></i> Pre-Authorize User
        <span style="color:#444;font-size:9px;font-weight:400;margin-left:8px">Whitelist only — user sets their own password when they register</span>
      </div>
      <form method="POST" action="/admin/preauth" class="register-form">
        <div class="form-grid">
          <div class="form-field">
            <label><i class="fas fa-envelope"></i> Email / Username</label>
            <input name="username" placeholder="user@company.com" required>
          </div>
          <div class="form-field">
            <label><i class="fas fa-id-card"></i> Display Name</label>
            <input name="displayname" placeholder="Full name">
          </div>
          <div class="form-field">
            <label><i class="fas fa-shield-halved"></i> Role (after activation)</label>
            <select name="role">
              <option value="viewer">👁️ Viewer</option>
              <option value="analyst">🔍 Analyst</option>
              <option value="manager">📋 Manager</option>
              <option value="admin">👑 Admin</option>
            </select>
          </div>
        </div>
        <button type="submit" style="background:linear-gradient(135deg,#995500,#663300);color:#ffd080;border:none;border-radius:3px;padding:10px 20px;font-weight:700;font-size:11px;letter-spacing:2px;cursor:pointer;display:inline-flex;align-items:center;gap:8px;font-family:inherit">
          <i class="fas fa-shield-check"></i> WHITELIST USER
        </button>
      </form>
    </div>

    <!-- ② Register New User (admin sets password — immediate access) -->
    <div class="register-section">
      <div class="section-header">
        <i class="fas fa-user-plus"></i> Create User Directly
        <span style="color:#444;font-size:9px;font-weight:400;margin-left:8px">Admin sets password — immediate access</span>
      </div>
      <form method="POST" action="/admin/adduser" class="register-form">
        <div class="form-grid">
          <div class="form-field">
            <label><i class="fas fa-user"></i> Username</label>
            <input name="username" placeholder="Enter username" required>
          </div>
          <div class="form-field">
            <label><i class="fas fa-id-card"></i> Display Name</label>
            <input name="displayname" placeholder="Full name">
          </div>
          <div class="form-field">
            <label><i class="fas fa-lock"></i> Password</label>
            <input name="password" type="password" placeholder="Set password" required>
          </div>
          <div class="form-field">
            <label><i class="fas fa-shield-halved"></i> Role</label>
            <select name="role">
              <option value="viewer">👁️ Viewer</option>
              <option value="analyst">🔍 Analyst</option>
              <option value="manager">📋 Manager</option>
              <option value="admin">👑 Admin</option>
            </select>
          </div>
        </div>
        <button type="submit" class="register-btn">
          <i class="fas fa-user-plus"></i> CREATE USER
        </button>
      </form>
    </div>

    <!-- User Permissions (shown when user selected) -->
    <div id="placeholder" class="placeholder-area">
      <i class="fas fa-arrow-left placeholder-icon"></i>
      <div>Select a user from the list to manage permissions</div>
    </div>
    <div id="perm-panel" style="display:none" class="perm-panel"></div>
  </div>

  <!-- RIGHT PANEL: Role Info & Quick Actions -->
  <div class="panel-right">
    <div class="panel-header"><i class="fas fa-info-circle"></i> Role Hierarchy</div>
    <div class="role-item">
      <div class="role-bar" style="background:#ff4444"></div>
      <div><div class="role-name" style="color:#ff4444">👑 Admin</div>
           <div class="role-desc">Full access — All modules + user management</div></div>
    </div>
    <div class="role-item">
      <div class="role-bar" style="background:#ff8800"></div>
      <div><div class="role-name" style="color:#ff8800">📋 Manager</div>
           <div class="role-desc">Most modules — No admin settings</div></div>
    </div>
    <div class="role-item">
      <div class="role-bar" style="background:#44aaff"></div>
      <div><div class="role-name" style="color:#44aaff">🔍 Analyst</div>
           <div class="role-desc">Recon, Attack Surface, Red Team</div></div>
    </div>
    <div class="role-item">
      <div class="role-bar" style="background:#666"></div>
      <div><div class="role-name" style="color:#888">👁️ Viewer</div>
           <div class="role-desc">Read-only — System tab only</div></div>
    </div>

    <!-- QR CODE SECTION -->
    <div class="panel-header" style="margin-top:16px"><i class="fas fa-qrcode"></i> Authenticator QR</div>
    <div id="qr-placeholder" style="padding:10px 14px;font-size:9px;color:#333;text-align:center;letter-spacing:1px">
      Select a user to view<br>their authenticator code
    </div>
    <div id="qr-display" style="display:none;padding:8px 14px">
      <div id="qr-img-wrap" style="text-align:center;margin-bottom:8px"></div>
      <div id="qr-secret-label" style="font-size:8px;color:#444;text-align:center;letter-spacing:1px;margin-bottom:4px">MANUAL KEY</div>
      <div id="qr-secret-val" style="font-family:monospace;font-size:9px;color:#cc4444;text-align:center;letter-spacing:2px;word-break:break-all;background:#0d0d16;padding:5px 8px;border-radius:3px;border:1px solid #1a1a28"></div>
      <div id="qr-mfa-status" style="text-align:center;font-size:9px;margin-top:8px"></div>
    </div>
    <div id="qr-exempt" style="display:none;padding:10px 14px;font-size:9px;color:#444;text-align:center;letter-spacing:1px">
      🔒 MFA exempt account
    </div>

    <div class="panel-header" style="margin-top:12px"><i class="fas fa-bolt"></i> Quick Actions</div>
    <a href="/" class="quick-action">
      <i class="fas fa-chart-line"></i> Vulnerability Dashboard
    </a>
    <a href="/admin/logout" class="quick-action danger">
      <i class="fas fa-power-off"></i> End Session
    </a>
  </div>
</div>

<!-- Toast notification -->
<div id="toast" class="toast">✅ SAVED</div>

<script>
const USERS={json.dumps(users_js)};
const NAV_CATALOG={json.dumps(NAV_CATALOG)};
let cur=null;

function selectUser(u){{
  cur=u;
  document.querySelectorAll('.user-card').forEach(el=>{{ el.classList.remove('active'); }});
  const el=document.getElementById('u-'+u);
  if(el) el.classList.add('active');

  const user=USERS[u];
  const utabs=user.tabs||[];
  const uItems=user.nav_items||null;   // null = not yet set (fall back to tabs logic)

  // ── Update QR panel on the right side ────────────────────────────────────
  const qrPlaceholder=document.getElementById('qr-placeholder');
  const qrDisplay=document.getElementById('qr-display');
  const qrExempt=document.getElementById('qr-exempt');
  if(user.exempt){{
    qrPlaceholder.style.display='none'; qrDisplay.style.display='none'; qrExempt.style.display='block';
  }} else {{
    qrPlaceholder.style.display='none'; qrExempt.style.display='none'; qrDisplay.style.display='block';
    const wrap=document.getElementById('qr-img-wrap');
    const secVal=document.getElementById('qr-secret-val');
    const status=document.getElementById('qr-mfa-status');
    if(user.qr_b64){{
      wrap.innerHTML=`<img src="data:image/png;base64,${{user.qr_b64}}" alt="QR" style="width:140px;height:140px;border:2px solid #330000;background:#fff;display:inline-block">`;
      secVal.textContent=user.mfa_secret||'';
    }} else {{
      wrap.innerHTML='<div style="font-size:9px;color:#555">QR unavailable</div>';
      secVal.textContent='';
    }}
    if(user.has_mfa){{
      status.innerHTML='<span style="color:#44ff88;font-size:9px;font-weight:700">✅ MFA ACTIVE</span><br><span style="color:#444;font-size:8px">User has authenticator enrolled</span>';
    }} else {{
      status.innerHTML='<span style="color:#ff8800;font-size:9px;font-weight:700">⚠ MFA NOT SET UP</span><br><span style="color:#444;font-size:8px">Share QR above for first-time setup</span>';
    }}
  }}
  const hasAll=utabs.includes('all');
  const role=user.role||'viewer';
  const dname=user.display_name||u;

  // determine which items are "on"
  function isOn(navId){{
    if(hasAll) return true;
    if(uItems!==null) return uItems.includes(navId);
    return false;  // old users without nav_items start clean
  }}

  let html=`<div class="perm-header">
    <div>
      <div class="perm-user-name">${{dname}}</div>
      <div class="perm-user-handle">@${{u}}</div>
    </div>
    <div class="perm-controls">
      <label class="grant-all-label">
        <input type="checkbox" id="grant-all" ${{hasAll?'checked':''}} onchange="toggleAll(this)"> Grant All
      </label>
      <select id="role-sel" class="role-select">
        <option value="admin"   ${{role=='admin'   ?'selected':''}}>👑 Admin</option>
        <option value="manager" ${{role=='manager' ?'selected':''}}>📋 Manager</option>
        <option value="analyst" ${{role=='analyst' ?'selected':''}}>🔍 Analyst</option>
        <option value="viewer"  ${{role=='viewer'  ?'selected':''}}>👁️ Viewer</option>
      </select>
      <button class="save-btn" onclick="save()"><i class="fas fa-save"></i> SAVE</button>
      <button class="del-btn" onclick="delUser('${{u}}')"><i class="fas fa-trash"></i></button>
    </div>
  </div>
  <div style="font-size:9px;color:#555;letter-spacing:1px;margin-bottom:12px;padding:0 2px">
    GRANULAR ACCESS — toggle individual items below or use <strong style="color:#888">Grant All</strong> for full access
  </div>`;

  NAV_CATALOG.forEach((group, gi)=>{{
    const groupId='grp-'+gi;
    const allForGroup=group.items.every(it=>isOn(it.id));
    html+=`
    <div class="nav-group" id="${{groupId}}">
      <div class="nav-group-header" onclick="toggleGroupAccordion('${{groupId}}')">
        <div class="nav-group-title">
          <i class="fas fa-chevron-down nav-group-chevron" id="chev-${{groupId}}"></i>
          ${{group.menu}}
          <span class="nav-group-count" id="cnt-${{groupId}}">${{group.items.filter(it=>isOn(it.id)).length}}/${{group.items.length}}</span>
        </div>
        <label class="group-select-all" onclick="event.stopPropagation()">
          <input type="checkbox" id="grp-all-${{gi}}" ${{allForGroup?'checked':''}}
                 onchange="toggleGroup(${{gi}},this.checked)"> All
        </label>
      </div>
      <div class="nav-group-body" id="body-${{groupId}}">
        <div class="nav-item-grid">`;
    group.items.forEach(item=>{{
      const on=isOn(item.id);
      html+=`
          <div class="nav-item-card ${{on?'on':''}}" id="nic-${{item.id}}" onclick="toggleNavItem('${{item.id}}','${{gi}}')">
            <label class="switch" onclick="event.stopPropagation()">
              <input type="checkbox" id="sw-${{item.id}}" ${{on?'checked':''}}
                     onchange="syncNavItem('${{item.id}}','${{gi}}')">
              <span class="slider"></span>
            </label>
            <div class="nav-item-label" id="nil-${{item.id}}">${{item.label}}</div>
          </div>`;
    }});
    html+=`
        </div>
      </div>
    </div>`;
  }});

  document.getElementById('perm-panel').innerHTML=html;
  document.getElementById('perm-panel').style.display='block';
  document.getElementById('placeholder').style.display='none';
}}

function toggleGroupAccordion(groupId){{
  const body=document.getElementById('body-'+groupId);
  const chev=document.getElementById('chev-'+groupId);
  const open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  chev.style.transform=open?'rotate(-90deg)':'rotate(0deg)';
}}

function toggleGroup(gi, checked){{
  const group=NAV_CATALOG[gi];
  group.items.forEach(item=>{{
    const sw=document.getElementById('sw-'+item.id);
    if(sw){{ sw.checked=checked; syncNavItem(item.id, gi); }}
  }});
}}

function toggleNavItem(id, gi){{
  const sw=document.getElementById('sw-'+id);
  if(sw){{ sw.checked=!sw.checked; syncNavItem(id, gi); }}
}}

function syncNavItem(id, gi){{
  const sw=document.getElementById('sw-'+id);
  const card=document.getElementById('nic-'+id);
  const lbl=document.getElementById('nil-'+id);
  if(!sw) return;
  const on=sw.checked;
  card.classList[on?'add':'remove']('on');
  if(lbl) lbl.style.color=on?'#ff8888':'#555';
  // Update group count badge
  const group=NAV_CATALOG[gi];
  const groupId='grp-'+gi;
  const cnt=group.items.filter(it=>{{const s=document.getElementById('sw-'+it.id); return s&&s.checked;}}).length;
  const cntEl=document.getElementById('cnt-'+groupId);
  if(cntEl) cntEl.textContent=cnt+'/'+group.items.length;
  // sync group select-all checkbox
  const grpAll=document.getElementById('grp-all-'+gi);
  if(grpAll) grpAll.checked=(cnt===group.items.length);
}}

function toggleAll(cb){{
  NAV_CATALOG.forEach((group,gi)=>{{
    group.items.forEach(item=>{{
      const sw=document.getElementById('sw-'+item.id);
      if(sw){{ sw.checked=cb.checked; syncNavItem(item.id,gi); }}
    }});
    const ga=document.getElementById('grp-all-'+gi);
    if(ga) ga.checked=cb.checked;
  }});
}}

function save(){{
  if(!cur)return;
  const grantAll=document.getElementById('grant-all').checked;
  const role=document.getElementById('role-sel').value;
  let nav_items;
  if(grantAll){{
    nav_items='all';
  }} else {{
    nav_items=[...document.querySelectorAll('[id^=sw-]')]
                .filter(s=>s.checked).map(s=>s.id.replace('sw-',''));
  }}
  fetch('/admin/save',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{username:cur,nav_items,role}})}})
    .then(r=>r.json()).then(d=>{{
      const t=document.getElementById('toast');
      t.textContent=d.ok?'✅ SAVED':'❌ Error saving';
      t.style.display='flex';
      setTimeout(()=>t.style.display='none',2200);
      if(d.ok){{
        // Update user card count
        const uc=document.getElementById('u-'+cur);
        if(uc){{
          const metaEl=uc.querySelector('.user-tabs');
          if(metaEl) metaEl.textContent=(nav_items==='all'?'ALL':nav_items.length)+' items';
        }}
      }}
    }});
}}

function delUser(u){{
  if(!confirm('Delete user '+u+'?'))return;
  fetch('/admin/deluser',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{username:u}})}}).then(()=>location.reload());
}}
</script>
"""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Portal — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
/* ── RESET & BASE ────────────────────────────────────────────── */
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:#0a0a0f;color:#ccc;min-height:100vh;overflow-x:hidden;
     background-image:radial-gradient(ellipse at 20% 50%,rgba(180,0,0,0.05) 0%,transparent 60%),
                      radial-gradient(ellipse at 80% 20%,rgba(255,100,0,0.03) 0%,transparent 50%)}}

/* ── TOP BAR ─────────────────────────────────────────────────── */
.topbar{{display:flex;align-items:center;justify-content:space-between;
         background:#06060d;border-bottom:1px solid #1a1a25;padding:0 20px;height:52px}}
.topbar-left,.topbar-right{{display:flex;align-items:center;gap:16px}}
.brand-box{{background:linear-gradient(135deg,#cc0000,#8b0000);padding:6px 16px;
            display:flex;align-items:center;gap:8px;border-radius:3px}}
.brand-icon{{color:#fff;font-size:16px}}
.brand-text{{color:#fff;font-weight:900;font-size:13px;letter-spacing:3px}}
.topbar-title{{color:#cc000099;font-size:12px;font-weight:600;letter-spacing:1px}}
.live-badge{{color:#44ff88;font-size:10px;font-weight:700;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}
.topbar-stat{{color:#555;font-size:11px}}
.topbar-stat strong{{color:#ccc}}
.topbar-user{{color:#fff;font-size:11px;font-weight:600}}
.topbar-btn{{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:3px;
             font-size:10px;font-weight:700;letter-spacing:1px;text-decoration:none;text-transform:uppercase;
             transition:all .2s;cursor:pointer;border:none;font-family:inherit}}
.launch-btn{{background:#0d200d;color:#44ff88;border:1px solid #44ff8833}}
.launch-btn:hover{{background:#0f2f0f;box-shadow:0 0 12px rgba(68,255,136,.2)}}
.logout-btn{{background:#200d0d;color:#ff4444;border:1px solid #ff444433}}
.logout-btn:hover{{background:#2f0d0d}}

/* ── STATS ROW ───────────────────────────────────────────────── */
.stats-row{{display:flex;gap:12px;padding:16px 20px;background:#08080e;border-bottom:1px solid #111}}
.stat-card{{flex:1;background:#0d0d16;border:1px solid #1a1a28;border-radius:6px;padding:14px 16px;
            display:flex;align-items:center;gap:12px;transition:border-color .2s}}
.stat-card:hover{{border-color:#333}}
.stat-icon{{font-size:20px;opacity:.9}}
.stat-val{{font-size:22px;font-weight:900;color:#fff;line-height:1}}
.stat-label{{font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;margin-top:2px}}

/* ── BODY 3-PANEL ────────────────────────────────────────────── */
.body-wrap{{display:flex;height:calc(100vh - 52px - 76px)}}

/* LEFT PANEL */
.panel-left{{width:260px;background:#06060d;border-right:1px solid #151520;display:flex;flex-direction:column;overflow-y:auto}}
.panel-header{{padding:12px 16px;color:#555;font-size:10px;letter-spacing:2px;text-transform:uppercase;
               border-bottom:1px solid #111;display:flex;align-items:center;gap:8px}}
.user-list{{flex:1;padding:6px 8px;overflow-y:auto}}
.user-card{{cursor:pointer;margin-bottom:6px;padding:10px 12px;background:#0d0d16;border:1px solid #1a1a28;
            border-left:3px solid #1a1a28;border-radius:4px;transition:all .2s}}
.user-card:hover{{border-color:#333;background:#10101a}}
.user-card.active{{border-left-color:#cc0000;background:#1a0008;border-color:#cc000033}}
.user-card-inner{{display:flex;align-items:center;gap:10px}}
.user-avatar{{font-size:24px;color:#333;width:32px;text-align:center}}
.user-card.active .user-avatar{{color:#cc0000}}
.user-info{{flex:1;min-width:0}}
.user-name{{font-size:12px;font-weight:600;color:#ccc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.user-handle{{font-size:9px;color:#444;margin-top:1px}}
.user-meta{{text-align:right}}
.role-tag{{font-size:8px;font-weight:800;letter-spacing:1px;padding:2px 6px;border-radius:2px;
           border:1px solid;background:transparent}}
.user-tabs{{font-size:9px;color:#444;margin-top:3px}}

/* CENTER PANEL */
.panel-center{{flex:1;overflow-y:auto;background:#0a0a12}}

/* Register Section */
.register-section{{background:#0d0d18;border-bottom:1px solid #1a1a28;padding:20px 24px}}
.section-header{{color:#cc0000;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
                 margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.register-form label{{display:block;color:#555;font-size:9px;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px}}
.register-form label i{{margin-right:4px;font-size:10px}}
.form-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}}
.form-field input,.form-field select{{width:100%;padding:9px 12px;background:#0a0a14;border:1px solid #1e1e30;
                  border-radius:3px;color:#fff;font-family:inherit;font-size:13px;transition:border-color .2s}}
.form-field input:focus,.form-field select:focus{{outline:none;border-color:#cc0000;box-shadow:0 0 0 2px rgba(204,0,0,0.12)}}
.form-field input::placeholder{{color:#333}}
.register-btn{{background:linear-gradient(135deg,#cc0000,#990000);color:#fff;border:none;border-radius:3px;
               padding:10px 24px;font-weight:700;font-size:11px;letter-spacing:2px;cursor:pointer;
               transition:all .2s;display:inline-flex;align-items:center;gap:8px;text-transform:uppercase;font-family:inherit}}
.register-btn:hover{{box-shadow:0 0 16px rgba(204,0,0,.3);transform:translateY(-1px)}}

/* Placeholder */
.placeholder-area{{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#1a1a2a;gap:10px}}
.placeholder-icon{{font-size:36px;opacity:.5}}

/* Permission Panel */
.perm-panel{{padding:20px 24px}}
.perm-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;
              padding-bottom:14px;border-bottom:1px solid #1a1a25}}
.perm-user-name{{font-size:16px;font-weight:700;color:#fff}}
.perm-user-handle{{color:#444;font-size:10px;margin-top:3px}}
.perm-controls{{display:flex;align-items:center;gap:8px}}
.grant-all-label{{display:flex;align-items:center;gap:5px;color:#888;font-size:10px;cursor:pointer}}
.grant-all-label input{{width:auto;accent-color:#cc0000}}
.role-select{{background:#0d0d16;border:1px solid #1e1e30;color:#fff;padding:5px 10px;font-size:10px;
              border-radius:3px;font-family:inherit}}
.save-btn{{background:#cc0000;color:#fff;border:none;border-radius:3px;padding:6px 16px;
           font-weight:700;font-size:10px;letter-spacing:1px;cursor:pointer;display:flex;align-items:center;gap:5px;
           font-family:inherit}}
.save-btn:hover{{background:#ff0000;box-shadow:0 0 10px rgba(255,0,0,.2)}}
.del-btn{{background:#200d0d;color:#ff4444;border:1px solid #ff444433;border-radius:3px;padding:6px 10px;
          font-size:10px;cursor:pointer;font-family:inherit}}
.del-btn:hover{{background:#2f0d0d}}
/* ── NAV ACCORDION GROUPS ─────────────────────────────── */
.nav-group{{background:#0d0d16;border:1px solid #1a1a28;border-radius:5px;margin-bottom:8px;overflow:hidden}}
.nav-group-header{{display:flex;align-items:center;justify-content:space-between;
                    padding:10px 14px;cursor:pointer;user-select:none;transition:background .15s}}
.nav-group-header:hover{{background:#12121e}}
.nav-group-title{{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;color:#ccc;letter-spacing:.5px}}
.nav-group-chevron{{color:#444;font-size:9px;transition:transform .2s}}
.nav-group-count{{background:#1a1a28;color:#cc0000;font-size:9px;font-weight:800;
                   padding:2px 7px;border-radius:10px;letter-spacing:.5px;font-family:monospace}}
.group-select-all{{display:flex;align-items:center;gap:5px;color:#555;font-size:10px;cursor:pointer;white-space:nowrap}}
.group-select-all input{{width:auto;accent-color:#cc0000;cursor:pointer}}
.nav-group-body{{padding:10px 12px 12px}}
.nav-item-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:5px}}
@media(max-width:1200px){{.nav-item-grid{{grid-template-columns:repeat(2,1fr)}}}}
.nav-item-card{{background:#101018;border:1px solid #1a1a28;border-radius:4px;padding:8px 10px;
                display:flex;align-items:center;gap:8px;cursor:pointer;transition:all .15s}}
.nav-item-card:hover{{border-color:#333;background:#14141f}}
.nav-item-card.on{{background:#190008;border-color:#cc000044}}
.nav-item-label{{font-size:10px;font-weight:600;color:#555;transition:color .15s;line-height:1.3}}
.nav-item-card.on .nav-item-label{{color:#ff8888}}

/* Toggle Switch */
.switch{{position:relative;display:inline-block;width:36px;height:18px}}
.switch input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;inset:0;background:#1a1a20;border-radius:18px;transition:.3s}}
.slider:before{{content:"";position:absolute;width:12px;height:12px;left:3px;bottom:3px;
               background:#333;border-radius:50%;transition:.3s}}
input:checked+.slider{{background:#1a0000}}
input:checked+.slider:before{{transform:translateX(18px);background:#cc0000}}

/* RIGHT PANEL */
.panel-right{{width:200px;background:#06060d;border-left:1px solid #151520;padding:0;overflow-y:auto;display:flex;flex-direction:column}}
.role-item{{display:flex;align-items:flex-start;gap:10px;padding:10px 14px}}
.role-bar{{width:3px;border-radius:2px;min-height:32px;flex-shrink:0}}
.role-name{{font-size:11px;font-weight:700}}
.role-desc{{font-size:9px;color:#444;margin-top:2px;line-height:1.4}}
.quick-action{{display:flex;align-items:center;gap:8px;padding:10px 14px;color:#888;font-size:11px;
               text-decoration:none;transition:all .2s;border-top:1px solid #111}}
.quick-action:hover{{background:#0d0d16;color:#fff}}
.quick-action.danger{{color:#ff4444}}
.quick-action.danger:hover{{background:#1a0000}}

/* TOAST */
.toast{{position:fixed;bottom:20px;right:20px;background:#0d1a0d;border:1px solid #44ff8844;
        color:#44ff88;padding:12px 24px;border-radius:4px;font-size:12px;font-weight:700;
        display:none;z-index:9999;letter-spacing:1px;align-items:center;gap:6px;
        box-shadow:0 4px 16px rgba(0,0,0,.3)}}

/* SCROLLBAR */
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-track{{background:#0a0a0f}}
::-webkit-scrollbar-thumb{{background:#1e1e30;border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#333}}
</style>
</head><body>{body}</body></html>"""


# ─── API ROUTES ───────────────────────────────────────────────────────────────
@bp.route("/save", methods=["POST"])
@_require_admin
def save_perms():
    body = request.get_json() or {}
    data = _load()
    u    = body.get("username","")
    if u in data.get("users",{}):
        new_role   = body.get("role","viewer")
        nav_items  = body.get("nav_items", None)  # new granular field

        # --- Handle nav_items ---
        if nav_items == "all" or nav_items is None:
            # Grant all: use legacy 'all' tab token
            data["users"][u]["tabs"]      = ["all"]
            data["users"][u]["nav_items"] = "all"
        else:
            # Specific items granted
            data["users"][u]["nav_items"] = nav_items
            # Derive coarse tabs from granted nav IDs for backward-compat
            # (kept for any old code that checks tabs)
            data["users"][u]["tabs"] = ["system"]  # minimum baseline

        data["users"][u]["role"] = new_role
        # Promote: clear pending flags when admin assigns a real role
        if new_role != "pending":
            data["users"][u].pop("pending_approval", None)
            data["users"][u].pop("must_change_password", None)
        _save(data)
        return {"ok": True}
    return {"ok": False}

@bp.route("/preauth", methods=["POST"])
@_require_admin
def preauth_user():
    """Pre-authorize a user: add them to the list with no password.
    They will set their own password when they register on the landing page."""
    uname = request.form.get("username","").strip().lower()
    if not uname: return redirect("/admin/panel")
    data  = _load()
    users = data.setdefault("users",{})
    if uname not in users:   # Don't overwrite existing users
        users[uname] = {
            "password":         "",
            "role":             request.form.get("role","viewer"),
            "tabs":             request.form.get("tabs","system").split(","),
            "display_name":     request.form.get("displayname", uname),
            "pending_approval": True,
        }
        _save(data)
    return redirect("/admin/panel")

@bp.route("/adduser", methods=["POST"])
@_require_admin
def add_user():
    uname = request.form.get("username","").strip().lower()
    if not uname: return redirect("/admin/panel")
    data  = _load()
    data.setdefault("users",{})[uname] = {
        "password":    request.form.get("password","changeme"),
        "role":        request.form.get("role","viewer"),
        "tabs":        ["system"],
        "display_name": request.form.get("displayname", uname),
        "must_change_password": True,
    }
    _save(data)
    return redirect("/admin/panel")

@bp.route("/deluser", methods=["POST"])
@_require_admin
def del_user():
    u = (request.get_json() or {}).get("username","")
    if u == "admin": return {"ok": False}
    data = _load()
    data.get("users",{}).pop(u, None)
    _save(data)
    return {"ok": True}

@bp.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─── CHANGE PASSWORD PAGE ─────────────────────────────────────────────────────
@bp.route("/change-password", methods=["GET"])
def change_password_page():
    if not session.get("admin_logged_in"):
        return redirect("/admin")
    user = session.get("admin_user", "")
    err = request.args.get("err", "")
    err_html = f'<div class="err-msg">❌ {err}</div>' if err else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Password — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:linear-gradient(160deg,#b8bcc4 0%,#a8adb6 100%);min-height:100vh}}
.wrap{{min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#bec3cb;padding:44px 36px 32px;border-radius:10px;width:400px;
       box-shadow:0 8px 32px rgba(0,0,0,0.18);text-align:center}}
.avatar{{margin-top:-50px;margin-bottom:10px}}
.title{{font-size:16px;font-weight:700;color:#5a6069;letter-spacing:2px;margin-bottom:6px}}
.subtitle{{font-size:12px;color:#7a8290;margin-bottom:20px}}
.input-row{{display:flex;align-items:stretch;margin-bottom:12px;background:#e8ecf0;border-bottom:2px solid #cdd1d6}}
.input-icon{{display:flex;align-items:center;justify-content:center;width:42px;color:#8a929c;font-size:14px;background:#e8ecf0}}
.input-row input{{flex:1;padding:10px 12px;background:#e8ecf0;border:none;color:#444;font-size:14px;font-family:inherit;outline:none}}
.input-row input::placeholder{{color:#999}}
.err-msg{{background:#f8d7da;border:1px solid #f5c2c7;color:#842029;font-size:12px;
          padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600}}
.submit-btn{{width:100%;padding:11px;background:linear-gradient(135deg,#44bb88,#339966);border:none;border-radius:20px;
             color:#fff;font-size:14px;font-weight:700;letter-spacing:2px;cursor:pointer;
             box-shadow:0 4px 14px rgba(51,153,102,0.35);transition:all .25s ease;font-family:inherit}}
.submit-btn:hover{{box-shadow:0 6px 20px rgba(51,153,102,0.5);transform:translateY(-1px)}}
</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="avatar">
    <svg viewBox="0 0 120 120" width="80" height="80">
      <circle cx="60" cy="60" r="58" fill="#a0a6af"/>
      <circle cx="60" cy="44" r="20" fill="#7a8290"/>
      <ellipse cx="60" cy="95" rx="32" ry="22" fill="#7a8290"/>
    </svg>
  </div>
  <div class="title">CHANGE PASSWORD</div>
  <div class="subtitle">Welcome <strong>{user}</strong> — please set a new password</div>
  {err_html}
  <form method="POST" action="/admin/update-password">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-lock"></i></span>
      <input type="password" name="new_password" placeholder="New password" required autofocus>
    </div>
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-check-double"></i></span>
      <input type="password" name="confirm_password" placeholder="Confirm new password" required>
    </div>
    <button type="submit" class="submit-btn">SET NEW PASSWORD</button>
  </form>
</div></div>
</body></html>"""


@bp.route("/update-password", methods=["POST"])
def update_password():
    if not session.get("admin_logged_in"):
        return redirect("/admin")
    new_pw   = request.form.get("new_password", "")
    conf_pw  = request.form.get("confirm_password", "")
    username = session.get("admin_user", "")

    if len(new_pw) < 4:
        return redirect("/admin/change-password?err=Password+must+be+at+least+4+characters")
    if new_pw != conf_pw:
        return redirect("/admin/change-password?err=Passwords+do+not+match")

    data = _load()
    if username in data.get("users", {}):
        data["users"][username]["password"] = new_pw
        data["users"][username].pop("must_change_password", None)
        _save(data)

    role = session.get("admin_role", "viewer")
    if role == "admin":
        return redirect("/admin/panel")
    return redirect("/")


# ══════════════════════════════════════════════════════════════════════
#  MULTI-FACTOR AUTHENTICATION (TOTP)
# ══════════════════════════════════════════════════════════════════════
import pyotp
import qrcode

_MFA_CARD_STYLE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:linear-gradient(160deg,#b8bcc4 0%,#a8adb6 100%);min-height:100vh}
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#bec3cb;padding:40px 36px 32px;border-radius:10px;width:420px;
      box-shadow:0 8px 32px rgba(0,0,0,0.18);text-align:center}
.title{font-size:16px;font-weight:700;color:#5a6069;letter-spacing:2px;margin-bottom:6px}
.subtitle{font-size:12px;color:#7a8290;margin-bottom:18px;line-height:1.5}
.qr-wrap{background:#fff;display:inline-block;padding:12px;border-radius:8px;margin-bottom:16px}
.secret-code{font-family:'Courier New',monospace;font-size:14px;font-weight:700;color:#333;
              background:#e8ecf0;padding:8px 14px;border-radius:6px;display:inline-block;
              letter-spacing:3px;margin-bottom:18px;word-break:break-all}
.input-row{display:flex;align-items:stretch;margin-bottom:14px;background:#e8ecf0;border-bottom:2px solid #cdd1d6}
.input-icon{display:flex;align-items:center;justify-content:center;width:42px;color:#8a929c;font-size:14px;background:#e8ecf0}
.input-row input{flex:1;padding:12px 12px;background:#e8ecf0;border:none;color:#333;font-size:18px;
                  font-family:'Courier New',monospace;outline:none;text-align:center;letter-spacing:8px}
.input-row input::placeholder{color:#aaa;letter-spacing:2px;font-size:13px}
.err-msg{background:#f8d7da;border:1px solid #f5c2c7;color:#842029;font-size:12px;
          padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600}
.submit-btn{width:100%;padding:11px;border:none;border-radius:20px;color:#fff;
             font-size:14px;font-weight:700;letter-spacing:2px;cursor:pointer;
             transition:all .25s ease;font-family:inherit}
.btn-blue{background:linear-gradient(135deg,#5ea7d8,#4a90c4);box-shadow:0 4px 14px rgba(74,144,196,0.35)}
.btn-blue:hover{box-shadow:0 6px 20px rgba(74,144,196,0.5);transform:translateY(-1px)}
.btn-green{background:linear-gradient(135deg,#44bb88,#339966);box-shadow:0 4px 14px rgba(51,153,102,0.35)}
.btn-green:hover{box-shadow:0 6px 20px rgba(51,153,102,0.5);transform:translateY(-1px)}
.shield{font-size:48px;margin-bottom:10px}
"""

def _qr_base64(uri):
    """Generate a QR code PNG as a base64-encoded data URI."""
    img = qrcode.make(uri, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ─── MFA SETUP (Enrollment) ───────────────────────────────────────────────
@bp.route("/mfa-setup", methods=["GET"])
def mfa_setup():
    username = session.get("mfa_pending_user")
    if not username:
        return redirect("/admin")

    # Reuse existing secret (don't regenerate on error redirects)
    secret = session.get("mfa_setup_secret") or pyotp.random_base32()
    session["mfa_setup_secret"] = secret

    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=username, issuer_name="VulnIntel")
    qr_b64 = _qr_base64(uri)

    err = request.args.get("err", "")
    err_html = f'<div class="err-msg">❌ {err}</div>' if err else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MFA Setup — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>{_MFA_CARD_STYLE}</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="shield">🛡️</div>
  <div class="title">SET UP TWO-FACTOR AUTH</div>
  <div class="subtitle">
    Scan this QR code with <strong>Google Authenticator</strong><br>
    or <strong>Microsoft Authenticator</strong>
  </div>
  <div class="qr-wrap">
    <img src="data:image/png;base64,{qr_b64}" alt="QR Code" width="200" height="200">
  </div>
  <div style="font-size:11px;color:#7a8290;margin-bottom:6px">Or enter this key manually:</div>
  <div class="secret-code">{secret}</div>
  {err_html}
  <form method="POST" action="/admin/mfa-confirm">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-key"></i></span>
      <input type="text" name="code" maxlength="6" pattern="[0-9]{{6}}" placeholder="000000"
             autocomplete="off" required autofocus inputmode="numeric">
    </div>
    <button type="submit" class="submit-btn btn-green">VERIFY & ACTIVATE MFA</button>
  </form>
</div></div>
</body></html>"""


# ─── MFA CONFIRM (Finish enrollment) ─────────────────────────────────────
@bp.route("/mfa-confirm", methods=["POST"])
def mfa_confirm():
    username = session.get("mfa_pending_user")
    secret   = session.get("mfa_setup_secret")
    if not username or not secret:
        return redirect("/admin")

    code = request.form.get("code", "").strip()
    totp = pyotp.TOTP(secret)

    if not totp.verify(code, valid_window=1):
        return redirect("/admin/mfa-setup?err=Invalid+code+—+please+try+again")

    # Save the secret to the user's profile
    data = _load()
    if username in data.get("users", {}):
        data["users"][username]["mfa_secret"] = secret
        _save(data)

    # Complete login
    role = session.get("mfa_pending_role", "viewer")
    session.pop("mfa_pending_user", None)
    session.pop("mfa_pending_role", None)
    session.pop("mfa_setup_secret", None)
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role

    if role == "admin":
        return redirect("/admin/panel")
    return redirect("/")


# ─── MFA VERIFY (Returning user) ─────────────────────────────────────────
@bp.route("/mfa-verify", methods=["GET"])
def mfa_verify():
    username = session.get("mfa_pending_user")
    if not username:
        return redirect("/admin")

    err = request.args.get("err", "")
    err_html = f'<div class="err-msg">❌ {err}</div>' if err else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MFA Verification — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>{_MFA_CARD_STYLE}</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="shield">🔐</div>
  <div class="title">TWO-FACTOR VERIFICATION</div>
  <div class="subtitle">
    Enter the 6-digit code from your<br><strong>Authenticator app</strong>
  </div>
  {err_html}
  <form method="POST" action="/admin/mfa-check">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-key"></i></span>
      <input type="text" name="code" maxlength="6" pattern="[0-9]{{6}}" placeholder="000000"
             autocomplete="off" required autofocus inputmode="numeric">
    </div>
    <button type="submit" class="submit-btn btn-blue">VERIFY</button>
  </form>
  <div style="margin-top:14px;font-size:11px;color:#98a0aa">
    <a href="/admin" style="color:#5ea7d8;text-decoration:none">Cancel and return to login</a>
  </div>
</div></div>
</body></html>"""


# ─── MFA CHECK (Validate code for returning user) ───────────────────────
@bp.route("/mfa-check", methods=["POST"])
def mfa_check():
    username = session.get("mfa_pending_user")
    if not username:
        return redirect("/admin")

    data  = _load()
    udata = data.get("users", {}).get(username, {})
    secret = udata.get("mfa_secret", "")

    if not secret:
        return redirect("/admin/mfa-setup")

    code = request.form.get("code", "").strip()
    totp = pyotp.TOTP(secret)

    if not totp.verify(code, valid_window=1):
        return redirect("/admin/mfa-verify?err=Invalid+code+—+please+try+again")

    # Complete login
    role = session.get("mfa_pending_role", "viewer")
    session.pop("mfa_pending_user", None)
    session.pop("mfa_pending_role", None)
    session["admin_logged_in"] = True
    session["admin_user"]      = username
    session["admin_role"]      = role

    if role == "admin":
        return redirect("/admin/panel")
    return redirect("/")


# ══════════════════════════════════════════════════════════════════════
#  FORGOT PASSWORD
# ══════════════════════════════════════════════════════════════════════

_FORGOT_STYLE = _MFA_CARD_STYLE   # Reuse same card styling

@bp.route("/forgot", methods=["GET"])
def forgot_page():
    err  = request.args.get("err", "")
    info = request.args.get("info", "")
    err_html  = f'<div class="err-msg">\u274c {err}</div>' if err else ""
    info_html = f'<div style="background:#d1ecf1;border:1px solid #bee5eb;color:#0c5460;font-size:12px;padding:8px 14px;border-radius:6px;margin-bottom:14px;text-align:center;font-weight:600">{info}</div>' if info else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forgot Password — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>{_FORGOT_STYLE}</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="shield">🔑</div>
  <div class="title">RESET PASSWORD</div>
  <div class="subtitle">Enter your username and verify your identity<br>using your <strong>Authenticator app</strong></div>
  {err_html}{info_html}
  <form method="POST" action="/admin/forgot-verify">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-user"></i></span>
      <input type="text" name="username" placeholder="Your username" required autofocus autocomplete="off">
    </div>
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-key"></i></span>
      <input type="text" name="code" maxlength="6" pattern="[0-9]{{6}}" placeholder="6-digit MFA code"
             autocomplete="off" required inputmode="numeric">
    </div>
    <button type="submit" class="submit-btn btn-blue">VERIFY IDENTITY</button>
  </form>
  <div style="margin-top:14px;font-size:11px;color:#98a0aa">
    <a href="/admin" style="color:#5ea7d8;text-decoration:none">← Back to login</a>
  </div>
</div></div>
</body></html>"""


@bp.route("/forgot-verify", methods=["POST"])
def forgot_verify():
    username = request.form.get("username", "").strip().lower()
    code     = request.form.get("code", "").strip()
    data     = _load()
    users    = data.get("users", {})

    if username not in users:
        return redirect("/admin/forgot?err=Username+not+found")

    secret = users[username].get("mfa_secret", "")
    if not secret:
        return redirect("/admin/forgot?err=MFA+not+set+up+for+this+account.+Contact+your+administrator.")

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return redirect("/admin/forgot?err=Invalid+MFA+code")

    # Identity verified — allow password reset
    session["forgot_user"] = username
    return redirect("/admin/forgot-reset")


@bp.route("/forgot-reset", methods=["GET"])
def forgot_reset_page():
    username = session.get("forgot_user")
    if not username:
        return redirect("/admin/forgot")

    err = request.args.get("err", "")
    err_html = f'<div class="err-msg">\u274c {err}</div>' if err else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reset Password — VulnIntel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>{_FORGOT_STYLE}</style>
</head><body>
<div class="wrap"><div class="card">
  <div class="shield">✅</div>
  <div class="title">SET NEW PASSWORD</div>
  <div class="subtitle">Identity verified for <strong>{username}</strong></div>
  {err_html}
  <form method="POST" action="/admin/forgot-save">
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-lock"></i></span>
      <input type="password" name="new_password" placeholder="New password" required autofocus>
    </div>
    <div class="input-row">
      <span class="input-icon"><i class="fas fa-check-double"></i></span>
      <input type="password" name="confirm_password" placeholder="Confirm new password" required>
    </div>
    <button type="submit" class="submit-btn btn-green">SAVE NEW PASSWORD</button>
  </form>
</div></div>
</body></html>"""


@bp.route("/forgot-save", methods=["POST"])
def forgot_save():
    username = session.get("forgot_user")
    if not username:
        return redirect("/admin/forgot")

    new_pw  = request.form.get("new_password", "")
    conf_pw = request.form.get("confirm_password", "")

    if len(new_pw) < 4:
        return redirect("/admin/forgot-reset?err=Password+must+be+at+least+4+characters")
    if new_pw != conf_pw:
        return redirect("/admin/forgot-reset?err=Passwords+do+not+match")

    data = _load()
    if username in data.get("users", {}):
        data["users"][username]["password"] = new_pw
        data["users"][username].pop("must_change_password", None)
        _save(data)

    session.pop("forgot_user", None)
    return redirect("/admin?info=Password+reset+successful")

