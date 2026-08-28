"""
ui_killchain.py — Cyber Kill Chain Board (Premium Tactical Edition)
===================================================================
Dual-mode display:
  1. Standalone MITRE ATT&CK Kill Chain visualization pulled from Neo4j
  2. Live simulation state abstract when Attack Chain engine is active
"""

import json
from dash import html, dcc, Input, Output, State, callback, no_update, ALL
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

from cyber_range.services.simulation_engine import engine


# ── Design tokens ──────────────────────────────────────────────────────────────
_DARK   = "#0a0d14"
_CARD   = "#0f1420"
_BORDER = "#1e2a3a"
_GOLD   = "#ffd700"
_DIM    = "#4a5568"
_GREEN  = "#00ff88"
_RED    = "#ff3355"
_ORANGE = "#ff8c00"
_CYAN   = "#00c8ff"
_PURPLE = "#cc44ff"


# ── Lockheed Martin Kill Chain phases ──────────────────────────────────────────
_KILL_CHAIN: list[dict] = [
    {
        "phase":   "Reconnaissance",
        "icon":    "🔍",
        "tactics": ["Reconnaissance", "Resource Development"],
        "color":   "#00bcd4",
        "desc":    "Target selection, OSINT gathering, network mapping",
        "mitre":   "TA0043 · TA0042",
    },
    {
        "phase":   "Weaponisation",
        "icon":    "🔧",
        "tactics": ["Initial Access"],
        "color":   "#ff9800",
        "desc":    "Coupling exploit with backdoor into deliverable payload",
        "mitre":   "TA0001",
    },
    {
        "phase":   "Delivery",
        "icon":    "📨",
        "tactics": ["Execution"],
        "color":   "#ff5722",
        "desc":    "Transmission of weapon to target environment",
        "mitre":   "TA0002",
    },
    {
        "phase":   "Exploitation",
        "icon":    "💥",
        "tactics": ["Persistence", "Privilege Escalation", "Defense Evasion"],
        "color":   "#f44336",
        "desc":    "Triggering the attacker's code on victim system",
        "mitre":   "TA0003 · TA0004 · TA0005",
    },
    {
        "phase":   "Installation",
        "icon":    "📦",
        "tactics": ["Credential Access", "Discovery"],
        "color":   "#e91e63",
        "desc":    "Installing persistent backdoor or RAT on victim system",
        "mitre":   "TA0006 · TA0007",
    },
    {
        "phase":   "C2",
        "icon":    "📡",
        "tactics": ["Lateral Movement", "Command and Control"],
        "color":   "#9c27b0",
        "desc":    "Two-way communication between attacker and compromised host",
        "mitre":   "TA0008 · TA0011",
    },
    {
        "phase":   "Actions on Objectives",
        "icon":    "🎯",
        "tactics": ["Collection", "Exfiltration", "Impact"],
        "color":   "#ff1744",
        "desc":    "Data exfiltration, encryption, destruction, or persistence",
        "mitre":   "TA0009 · TA0010 · TA0040",
    },
]

# Status colour mapping
_STATUS_COLORS = {
    "Compromised":       "#ff3355",
    "Active Combat":     "#ff8c00",
    "Defended/Blocked":  "#00ff88",
    "Pending":           "#2a3a50",
    "Not in scope":      "#1a2030",
}

_STATUS_ICONS = {
    "Compromised":       "🔴",
    "Active Combat":     "🟡",
    "Defended/Blocked":  "🟢",
    "Pending":           "⬜",
    "Not in scope":      "—",
}


# ── Kill chain mapping from engine state ───────────────────────────────────────
def _map_engine_to_killchain() -> dict | None:
    """Read SimulationEngine nodes → map to 7 Kill Chain phases."""
    if not engine.nodes:
        return None

    chain = {p["phase"]: {"status": "Pending", "nodes": [], "color": p["color"],
                           "icon": p["icon"], "desc": p["desc"], "mitre": p["mitre"],
                           "tactics": p["tactics"]}
             for p in _KILL_CHAIN}

    tactic_to_phase = {}
    for p in _KILL_CHAIN:
        for t in p["tactics"]:
            tactic_to_phase[t] = p["phase"]

    for node in engine.nodes:
        tactic = node.get("tactic", "Lateral Movement")
        phase  = tactic_to_phase.get(tactic, "Actions on Objectives")
        chain[phase]["nodes"].append(node)
        state = node.get("state", "PENDING")
        if state == "SUCCESS":
            chain[phase]["status"] = "Compromised"
        elif state in ("FAILED", "BLOCKED"):
            if chain[phase]["status"] != "Compromised":
                chain[phase]["status"] = "Defended/Blocked"
        elif state == "IN_PROGRESS":
            if chain[phase]["status"] not in ("Compromised",):
                chain[phase]["status"] = "Active Combat"

    return chain


# ── Static standalone kill chain (with Live Graph correlation) ──────────────
def _render_standalone_killchain(selected_phase=None) -> html.Div:
    """Render the 7-phase strip with live finding counts and detailed phase inspector."""
    vuln_count = host_count = crit_count = 0
    phase_findings_map = {p["phase"]: [] for p in _KILL_CHAIN}
    phase_counts = {p["phase"]: 0 for p in _KILL_CHAIN}

    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        drv = Neo4jEngine().driver
        with drv.session() as s:
            h_res = s.run("MATCH (h:Host) RETURN count(h) AS c").single()
            host_count = h_res["c"] if h_res else 0

            v_res = s.run("MATCH (f:Finding) RETURN count(f) AS c").single()
            vuln_count = v_res["c"] if v_res else 0

            c_res = s.run("MATCH (f:Finding) WHERE f.cvss >= 9 OR toLower(toString(f.severity)) = 'critical' RETURN count(f) AS c").single()
            crit_count = c_res["c"] if c_res else 0

            # Pull findings mapped to MITRE tactics / kill chain
            q_findings = """
            MATCH (h:Host)-[:HAS_FINDING|HAS_VULN|HAS_VULNERABILITY|RUNS_SERVICE*1..2]->(f:Finding)
            OPTIONAL MATCH (f)-[:MAPS_TO_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
            RETURN coalesce(h.host, h.ip, '192.168.195.139') AS host,
                   coalesce(f.title, f.name, f.cve, 'Vulnerability') AS title,
                   coalesce(f.severity, 'High') AS severity,
                   coalesce(f.cvss, 7.5) AS cvss,
                   coalesce(t.id, f.mitre_id, 'T1000') AS tech_id,
                   coalesce(t.name, t.label, 'Exploitation') AS tech_name
            LIMIT 200
            """
            findings_data = s.run(q_findings).data()

            # Categorize findings into 7 phases
            for f in findings_data:
                tid = str(f.get("tech_id", "")).upper()
                if tid.startswith("T1046") or tid.startswith("T1595") or tid.startswith("T1592") or tid.startswith("T1590") or tid.startswith("T1589"):
                    phase_findings_map["Reconnaissance"].append(f)
                elif tid.startswith("T1190") or tid.startswith("T1078") or tid.startswith("T1133") or tid.startswith("T1200"):
                    phase_findings_map["Weaponisation"].append(f)
                elif tid.startswith("T1059") or tid.startswith("T1204") or tid.startswith("T1566") or tid.startswith("T1203"):
                    phase_findings_map["Delivery"].append(f)
                elif tid.startswith("T1068") or tid.startswith("T1210") or tid.startswith("T1548") or tid.startswith("T1055"):
                    phase_findings_map["Exploitation"].append(f)
                elif tid.startswith("T1003") or tid.startswith("T1110") or tid.startswith("T1552") or tid.startswith("T1083") or tid.startswith("T1557"):
                    phase_findings_map["Installation"].append(f)
                elif tid.startswith("T1021") or tid.startswith("T1071") or tid.startswith("T1570") or tid.startswith("T1571"):
                    phase_findings_map["C2"].append(f)
                else:
                    phase_findings_map["Actions on Objectives"].append(f)

            for p_name in phase_findings_map:
                phase_counts[p_name] = len(phase_findings_map[p_name])
    except Exception as e:
        print("[KillChain Error]", e)

    if not selected_phase:
        selected_phase = "Reconnaissance"

    phase_cards = []
    for i, p in enumerate(_KILL_CHAIN):
        color = p["color"]
        p_name = p["phase"]
        cnt = phase_counts.get(p_name, 0)
        is_sel = (p_name == selected_phase)

        arrow = html.Div("▶", style={
            "color": f"{color}66", "fontSize": "18px",
            "display": "flex", "alignItems": "center",
            "padding": "0 2px",
        }) if i < len(_KILL_CHAIN) - 1 else html.Span()

        card = html.Button([
            html.Div([
                html.Span(p["icon"], style={"fontSize": "22px"}),
                html.Div(p_name, style={
                    "color": color, "fontWeight": "900", "fontSize": "11px",
                    "letterSpacing": "0.5px", "marginTop": "4px",
                    "fontFamily": "monospace", "textTransform": "uppercase",
                }),
                html.Span(f"{cnt} findings", className="badge mt-1", style={
                    "backgroundColor": f"{color}33", "color": color, "fontSize": "9px",
                    "border": f"1px solid {color}66"
                }),
            ], style={"textAlign": "center", "marginBottom": "8px"}),

            html.Div(p["mitre"], style={
                "color": f"{color}aa", "fontSize": "8px", "fontWeight": "700",
                "letterSpacing": "1px", "fontFamily": "monospace",
                "textAlign": "center", "marginBottom": "6px",
            }),

            html.Div(p["desc"], style={
                "color": "#94a3b8", "fontSize": "9px", "lineHeight": "1.4",
                "textAlign": "center", "marginBottom": "8px",
            }),

            html.Div([
                html.Div(t, style={
                    "background": f"{color}15", "border": f"1px solid {color}44",
                    "color": color, "fontSize": "8px", "fontWeight": "700",
                    "padding": "2px 4px", "borderRadius": "3px",
                    "marginBottom": "2px", "textAlign": "center",
                    "fontFamily": "monospace",
                })
                for t in p["tactics"]
            ]),

        ], id={"type": "kc-phase-btn", "index": p_name}, style={
            "background":    f"linear-gradient(160deg, {color}15 0%, {_CARD} 100%)" if is_sel else f"linear-gradient(160deg, {color}08 0%, {_CARD} 100%)",
            "border":        f"2px solid {color}" if is_sel else f"1px solid {color}33",
            "boxShadow":     f"0 0 12px {color}44" if is_sel else "none",
            "borderTop":     f"4px solid {color}",
            "borderRadius":  "10px",
            "padding":       "12px 10px",
            "flex":          "1",
            "minWidth":      "120px",
            "cursor":        "pointer",
            "textAlign":     "left",
        })

        phase_cards.append(card)
        phase_cards.append(arrow)

    # ── Render Selected Phase Detail Inspector & Recommendations ─────────────
    sel_data = next((p for p in _KILL_CHAIN if p["phase"] == selected_phase), _KILL_CHAIN[0])
    sel_color = sel_data["color"]
    sel_findings = phase_findings_map.get(selected_phase, [])

    # Recommendations dictionary per phase
    recommendations_map = {
        "Reconnaissance": [
            "🛡️ Implement egress/ingress port filtering and disable ICMP/port broadcast responses on DMZ subnets.",
            "🔒 Disable unnecessary legacy discovery services (SNMP v1/v2, NetBIOS, LLMNR).",
            "🔍 Deploy Network Intrusion Detection (Snort/Suricata) alert rules for rapid TCP SYN sweeps."
        ],
        "Weaponisation": [
            "⚡ Apply vendor security patches to exposed web perimeter servers and public-facing APIs.",
            "🛡️ Deploy Web Application Firewall (WAF) rules with virtual patching for identified CVEs.",
            "🔐 Enforce Multi-Factor Authentication (MFA) on all internet-facing admin endpoints."
        ],
        "Delivery": [
            "📧 Enable strict email gateway attachment sandboxing and macro execution blocks in MS Office.",
            "🚫 Implement Application Whitelisting / AppLocker policies to restrict untrusted binary execution.",
            "👁️ Monitor script execution telemetry via PowerShell Script Block Logging (Event ID 4104)."
        ],
        "Exploitation": [
            "🔒 Isolate vulnerable hosts from internal subnets until exploit patches are deployed.",
            "🛡️ Enable Windows Credential Guard and Kernel DMA Protection to stop memory corruption vectors.",
            "🚨 Configure EDR behavioral prevention against LSASS memory access and process injection."
        ],
        "Installation": [
            "🔑 Rotate local Administrator passwords via LAPS to prevent pass-the-hash persistence.",
            "🚫 Audit and remove unquoted service paths and world-writable directories from PATH.",
            "📜 Monitor scheduled tasks and registry Run key additions via Sysmon (Event ID 1 & 13)."
        ],
        "C2": [
            "🌐 Enforce DNS sinkholing and inspect outbound TLS traffic using SSL Decryption proxies.",
            "🔒 Block inter-VLAN SMB/RPC communication across user workstations to choke lateral spread.",
            "📡 Alert on anomalous beaconing intervals and newly registered domain queries."
        ],
        "Actions on Objectives": [
            "💾 Implement immutable offline backups to prevent ransomware encryption impact.",
            "🛡️ Enforce strict Data Loss Prevention (DLP) controls on large outbound data streams.",
            "📊 Apply Least Privilege Access to sensitive file shares and domain databases."
        ]
    }

    recs = recommendations_map.get(selected_phase, recommendations_map["Reconnaissance"])

    inspector = html.Div([
        html.Div([
            html.H4([
                html.Span(sel_data["icon"], style={"marginRight": "10px"}),
                f"Phase Intelligence: {selected_phase}",
                html.Span(f"{len(sel_findings)} Active Findings", className="badge ms-3", style={"backgroundColor": f"{sel_color}33", "color": sel_color, "fontSize": "11px", "border": f"1px solid {sel_color}"})
            ], style={"color": sel_color, "fontWeight": "bold"}),
            html.P(sel_data["desc"], className="text-light small mb-3"),
        ], style={"borderBottom": f"1px solid {sel_color}44", "paddingBottom": "10px", "marginBottom": "16px"}),

        dbc.Row([
            dbc.Col([
                html.H6("⚠️ Target Findings Mapped to this Phase", className="text-warning fw-bold"),
                html.Div([
                    html.Div([
                        html.Div([
                            html.Strong(f["title"], style={"color": "#fff", "fontSize": "12px"}),
                            html.Span(f"CVSS {f['cvss']}", className="badge float-end", style={"backgroundColor": "#7f1d1d", "color": "#fca5a5" if float(f['cvss'])>=9 else "#fef08a"}),
                        ]),
                        html.Div([
                            html.Span(f"Host: {f['host']}", className="text-info me-3", style={"fontSize": "11px"}),
                            html.Span(f"Technique: {f['tech_id']} ({f['tech_name']})", className="text-muted", style={"fontSize": "11px"}),
                        ], style={"marginTop": "3px"})
                    ], style={"backgroundColor": "#111827", "border": "1px solid #1f2937", "borderRadius": "6px", "padding": "8px 12px", "marginBottom": "8px"})
                    for f in sel_findings[:8]
                ] if sel_findings else [html.P("No critical vulnerabilities currently mapped to this phase.", className="text-muted small")])
            ], width=7),

            dbc.Col([
                html.H6("🛡️ Prioritized Defensive Hardening Recommendations", className="text-success fw-bold"),
                html.Div([
                    html.Div(r, style={"backgroundColor": "#064e3b22", "border": "1px solid #065f46", "borderRadius": "6px", "padding": "10px 12px", "marginBottom": "8px", "color": "#a7f3d0", "fontSize": "12px", "lineHeight": "1.5"})
                    for r in recs
                ])
            ], width=5),
        ])
    ], style={"backgroundColor": "#0b0f19", "border": f"1px solid {sel_color}44", "borderRadius": "10px", "padding": "20px", "marginTop": "24px"})

    return html.Div([
        # Stats bar
        html.Div([
            html.Div([
                html.Div(str(host_count), style={
                    "color": _CYAN, "fontSize": "28px", "fontWeight": "900",
                    "fontFamily": "monospace",
                }),
                html.Div("HOSTS IN GRAPH", style={
                    "color": _DIM, "fontSize": "8px", "fontWeight": "700",
                    "letterSpacing": "1px",
                }),
            ], style={"textAlign": "center"}),
            html.Div([
                html.Div(str(vuln_count), style={
                    "color": _ORANGE, "fontSize": "28px", "fontWeight": "900",
                    "fontFamily": "monospace",
                }),
                html.Div("VULNERABILITIES", style={
                    "color": _DIM, "fontSize": "8px", "fontWeight": "700",
                    "letterSpacing": "1px",
                }),
            ], style={"textAlign": "center"}),
            html.Div([
                html.Div(str(crit_count), style={
                    "color": _RED, "fontSize": "28px", "fontWeight": "900",
                    "fontFamily": "monospace",
                }),
                html.Div("CRITICAL (CVSS≥9)", style={
                    "color": _DIM, "fontSize": "8px", "fontWeight": "700",
                    "letterSpacing": "1px",
                }),
            ], style={"textAlign": "center"}),
            html.Div([
                html.Div(engine.status, style={
                    "color": _DIM, "fontSize": "16px", "fontWeight": "900",
                    "fontFamily": "monospace",
                }),
                html.Div("SIM ENGINE", style={
                    "color": _DIM, "fontSize": "8px", "fontWeight": "700",
                    "letterSpacing": "1px",
                }),
            ], style={"textAlign": "center"}),
        ], style={
            "display": "flex", "gap": "40px", "justifyContent": "center",
            "padding": "20px", "marginBottom": "24px",
            "background": _DARK, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px",
        }),

        # Phase strip
        html.Div([
            html.Div("LOCKHEED MARTIN CYBER KILL CHAIN  ·  MITRE ATT&CK OVERLAY  ·  CLICK ANY PHASE TO INSPECT",
                     style={
                         "color": _GOLD, "fontSize": "10px", "fontWeight": "700",
                         "letterSpacing": "2px", "textAlign": "center", "marginBottom": "16px",
                     }),
            html.Div(phase_cards, style={
                "display": "flex", "alignItems": "stretch", "gap": "4px",
                "overflowX": "auto",
            }),
        ]),

        inspector
    ])


# ── Simulation-active render ───────────────────────────────────────────────────
def _render_sim_killchain(chain: dict) -> html.Div:
    """Show the 7 phases with live node state overlaid."""
    cards = []
    for p in _KILL_CHAIN:
        phase = p["phase"]
        data  = chain[phase]
        color = p["color"]
        st    = data["status"]
        st_color = _STATUS_COLORS.get(st, _BORDER)
        nodes    = data["nodes"]

        node_pills = [
            html.Div([
                html.Span(
                    {"SUCCESS": "🟢", "FAILED": "🔴", "BLOCKED": "🟣",
                     "IN_PROGRESS": "🟡", "PENDING": "⬜"}.get(n.get("state",""),  "⬜"),
                    style={"marginRight": "4px"}
                ),
                html.Span(n.get("label","")[:20], style={
                    "color": "#ccc", "fontSize": "9px", "fontFamily": "monospace",
                }),
            ], style={"marginBottom": "3px"})
            for n in nodes
        ] if nodes else [html.Div("— not in scope", style={"color": _DIM, "fontSize": "9px"})]

        cards.append(html.Div([
            html.Div([
                html.Span(p["icon"], style={"fontSize": "18px", "marginRight": "8px"}),
                html.Div([
                    html.Div(phase, style={
                        "color": color, "fontWeight": "900", "fontSize": "11px",
                        "textTransform": "uppercase", "fontFamily": "monospace",
                    }),
                    html.Div(f"{_STATUS_ICONS.get(st,'')} {st}", style={
                        "color": st_color, "fontSize": "10px", "fontWeight": "700",
                    }),
                ]),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "10px",
                      "borderBottom": f"1px solid {_BORDER}", "paddingBottom": "8px"}),
            *node_pills,
            html.Div(p["mitre"], style={
                "color": _DIM, "fontSize": "8px", "fontFamily": "monospace",
                "marginTop": "8px",
            }),
        ], style={
            "background":   f"linear-gradient(160deg,{color}0d,{_CARD})",
            "border":       f"1px solid {color}33",
            "borderLeft":   f"3px solid {st_color}",
            "borderRadius": "10px",
            "padding":      "14px",
            "marginBottom": "12px",
        }))

    return html.Div(cards)


# ── Main layout ────────────────────────────────────────────────────────────────
def killchain_tab() -> html.Div:
    return html.Div([

        dcc.Interval(id="kc-auto-refresh", interval=5000, n_intervals=0),

        # ── Header ───────────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div("⚔  CYBER KILL CHAIN BOARD", style={
                    "color": _GOLD, "fontSize": "11px", "fontWeight": "900",
                    "letterSpacing": "3px", "fontFamily": "monospace",
                }),
                html.Div(
                    "Lockheed Martin Kill Chain · MITRE ATT&CK Overlay · Live Engine Integration",
                    style={"color": _DIM, "fontSize": "12px", "marginTop": "2px"},
                ),
            ]),
            html.Div([
                dbc.Button("🔄 Refresh State", id="killchain-run", color="primary",
                           size="sm", style={"fontSize": "11px", "marginRight": "8px"}),
                html.Div(id="kc-sim-badge", style={"display": "inline-block"}),
            ]),
        ], style={
            "display": "flex", "justifyContent": "space-between", "alignItems": "center",
            "marginBottom": "24px",
            "borderBottom": f"2px solid {_GOLD}33", "paddingBottom": "16px",
        }),

        # ── Engine state info bar ─────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Span("ℹ️ ", style={"marginRight": "6px"}),
                html.Span(
                    "This board reads the live SimulationEngine. "
                    "Below is the static Kill Chain anatomy from your Neo4j graph. "
                    "Load a scenario in Attack Chain Modeler to overlay simulation state.",
                    style={"color": _DIM, "fontSize": "11px"},
                ),
            ]),
        ], style={
            "background": f"{_CYAN}0a", "border": f"1px solid {_CYAN}33",
            "borderRadius": "8px", "padding": "10px 14px", "marginBottom": "24px",
        }),

        # ── Main output ───────────────────────────────────────────────────────
        html.Div(id="killchain-output"),

    ], style={
        "background": _CARD, "minHeight": "100vh",
        "padding": "24px", "fontFamily": "'Inter', monospace",
    })


# ── Callbacks ──────────────────────────────────────────────────────────────────
def register_callbacks(app):

    @app.callback(
        Output("killchain-output", "children"),
        Output("kc-sim-badge",     "children"),
        Input("killchain-run",     "n_clicks"),
        Input("kc-auto-refresh",   "n_intervals"),
        Input({"type": "kc-phase-btn", "index": ALL}, "n_clicks"),
        prevent_initial_call=False,
    )
    def update_killchain(refresh_clicks, interval_ticks, phase_btn_clicks):
        from dash import ctx
        try:
            selected_phase = "Reconnaissance"
            if ctx.triggered_id and isinstance(ctx.triggered_id, dict):
                selected_phase = ctx.triggered_id.get("index", "Reconnaissance")

            chain = _map_engine_to_killchain()

            if chain:
                # ── Simulation active ────────────────────────────────────────
                badge = html.Span([
                    html.Span("⬤ SIM ACTIVE", style={
                        "color": _GREEN, "fontSize": "10px", "fontWeight": "900",
                        "fontFamily": "monospace",
                        "background": f"{_GREEN}15",
                        "border": f"1px solid {_GREEN}44",
                        "borderRadius": "12px", "padding": "4px 10px",
                    }),
                ])
                header = html.Div([
                    html.Div([
                        html.Span("SIMULATION ABSTRACT", style={
                            "color": _GOLD, "fontSize": "10px", "fontWeight": "900",
                            "letterSpacing": "2px", "fontFamily": "monospace",
                        }),
                        html.Span(f"  ·  Step {engine.current_step}/{len(engine.nodes)}"
                                  f"  ·  {engine.status}", style={
                            "color": _ORANGE, "fontSize": "10px",
                            "fontFamily": "monospace",
                        }),
                    ], style={"marginBottom": "16px"}),
                    _render_sim_killchain(chain),
                    html.Hr(style={"border": f"1px solid {_BORDER}", "margin": "24px 0"}),
                    html.Div("LIVE GRAPH ANATOMY", style={
                        "color": _DIM, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "2px", "marginBottom": "16px",
                    }),
                    _render_standalone_killchain(selected_phase),
                ])
                return header, badge
            else:
                # ── No simulation — show standalone view ─────────────────────
                badge = html.Span("⬤ SIM IDLE", style={
                    "color": _DIM, "fontSize": "10px", "fontWeight": "900",
                    "fontFamily": "monospace",
                    "background": f"{_DIM}22",
                    "border": f"1px solid {_DIM}44",
                    "borderRadius": "12px", "padding": "4px 10px",
                })
                return _render_standalone_killchain(selected_phase), badge

        except Exception as e:
            return html.Div(f"[Kill Chain Error] {e}",
                            style={"color": _RED, "fontFamily": "monospace"}), ""

    print("[ui_killchain] Loaded — Premium Kill Chain Board active.")
