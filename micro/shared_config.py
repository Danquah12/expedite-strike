# -*- coding: utf-8 -*-
"""
Aegis Microservices — Shared Configuration
All 10 independent apps import from here to stay invisibly linked.
"""
import os, sys
from pathlib import Path
from functools import wraps
from flask import session, redirect

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT         = Path(__file__).resolve().parent.parent   # /opt/vuln_intel/app
ASSETS_DIR   = str(ROOT / "assets")
UPLOADS_DIR  = str(ROOT / "uploads" / "assessments")
DB_PATH      = "/opt/vuln_intel/vuln_intel.db"
ENV_FILE     = str(ROOT / ".env")

# Ensure cyber_range package is importable from every micro app
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Shared secret key — single login works across ALL apps ───────────────────
SECRET_KEY = os.environ.get("FLASK_SECRET", "vuln_intel_secret_2025_!@#")

# ── Common Dash external stylesheets ─────────────────────────────────────────
import dash_bootstrap_components as dbc
EXTERNAL_STYLESHEETS = [dbc.themes.DARKLY]

# ── Shared nav links (used in every app's minimal header) ────────────────────
NAV_LINKS = [
    {"label": "📋 Assessment",  "href": "/app/assessment"},
    {"label": "🔴 Red Team",    "href": "/app/redteam"},
    {"label": "🎯 Attack",      "href": "/app/attack"},
    {"label": "🛡️ Defence",    "href": "/app/defence"},
    {"label": "📡 Intel",       "href": "/app/intel"},
    {"label": "📊 GRC",         "href": "/app/grc"},
    {"label": "🔬 Specialised", "href": "/app/specialised"},
    {"label": "🤖 AI",          "href": "/app/ai"},
    {"label": "⚙️ Admin",       "href": "/app/admin-panel"},
]

# ── Auth gate decorator ───────────────────────────────────────────────────────
def current_user():
    return session.get("admin_user") or session.get("username")

def auth_required(f):
    """Flask route decorator — redirects to landing if not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

# ── Dash layout auth gate (returns Div or None) ───────────────────────────────
from dash import html
def dash_auth_gate(module_name="this module"):
    if not current_user():
        return html.Div(html.Div([
            html.I(className="fas fa-lock",
                   style={"fontSize":"48px","color":"#cc0000","marginBottom":"16px"}),
            html.H4("Login Required", style={"color":"#ff4444","fontWeight":"700"}),
            html.P(f"You must be logged in to access {module_name}.",
                   style={"color":"#888","fontSize":"13px"}),
            html.Br(),
            html.A("← Back to Login", href="/",
                   style={"color":"#00aadd","fontWeight":"700","display":"inline-block"}),
        ], style={
            "textAlign":"center","padding":"80px 40px","background":"#0a0a12",
            "border":"1px solid #1a1a28","borderRadius":"12px",
            "maxWidth":"420px","margin":"80px auto",
        }))
    return None

# ── Shared minimal top nav bar (renders in every micro app) ──────────────────
def micro_navbar(active_label=""):
    import dash_bootstrap_components as dbc
    links = []
    for item in NAV_LINKS:
        is_active = item["label"] == active_label
        links.append(
            html.A(item["label"], href=item["href"],
                   style={
                       "padding":"6px 12px","borderRadius":"4px","fontSize":"11px",
                       "fontWeight":"700","textDecoration":"none","letterSpacing":"0.5px",
                       "color":"#00d4ff" if is_active else "#aaa",
                       "background":"rgba(0,212,255,0.08)" if is_active else "transparent",
                       "border":"1px solid #00d4ff44" if is_active else "1px solid transparent",
                   })
        )
    return html.Div([
        # Logo
        html.A("⬡ ÆGIS", href="/app/",
               style={"color":"#00d4ff","fontWeight":"900","fontSize":"18px",
                      "textDecoration":"none","letterSpacing":"2px","marginRight":"24px"}),
        # Nav links
        html.Div(links, style={"display":"flex","gap":"4px","flexWrap":"wrap","flex":"1"}),
        # Logout
        html.A("🔓 Logout", href="/admin/logout",
               style={"color":"#ff4444","fontSize":"11px","fontWeight":"700",
                      "textDecoration":"none","padding":"6px 12px",
                      "border":"1px solid #ff444466","borderRadius":"4px"}),
    ], style={
        "display":"flex","alignItems":"center","padding":"10px 20px",
        "background":"#0d1117","borderBottom":"1px solid #1a1a28",
        "position":"sticky","top":"0","zIndex":"1000",
    })

# ── Helper: error card ────────────────────────────────────────────────────────
def error_card(module, err):
    return html.Div([
        html.H5(f"⚠ {module} failed to load", style={"color":"#ffaa00"}),
        html.Pre(str(err), style={"color":"#888","fontSize":"11px","whiteSpace":"pre-wrap"}),
        html.A("Reload", href="javascript:location.reload()",
               style={"color":"#00aadd","marginTop":"8px","display":"inline-block"}),
    ], style={"padding":"20px","background":"#120a00","border":"1px solid #ffaa0033",
              "borderRadius":"8px","margin":"20px"})
