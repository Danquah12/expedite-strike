"""
ui_killchain.py — Cyber Kill Chain Board (Premium Tactical Edition)
===================================================================
Dual-mode display:
  1. Standalone MITRE ATT&CK Kill Chain visualization pulled from Neo4j
  2. Live simulation state abstract when Attack Chain engine is active
"""

import json
from dash import html, dcc, Input, Output, State, callback, no_update
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


# ── Static standalone kill chain (no simulation) ──────────────────────────────
def _render_standalone_killchain() -> html.Div:
    """Render the 7-phase strip with Neo4j stats context — no active sim needed."""
    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        drv = Neo4jEngine().driver
        with drv.session() as s:
            vuln_count  = s.run("MATCH (v:Vulnerability) RETURN count(v) AS c").single()["c"]
            host_count  = s.run("MATCH (h:Host) RETURN count(h) AS c").single()["c"]
            crit_count  = s.run("MATCH (v:Vulnerability) WHERE v.cvss >= 9 RETURN count(v) AS c").single()["c"]
    except Exception:
        vuln_count = host_count = crit_count = "?"

    phase_cards = []
    for i, p in enumerate(_KILL_CHAIN):
        color = p["color"]
        arrow = html.Div("▶", style={
            "color": f"{color}66", "fontSize": "20px",
            "display": "flex", "alignItems": "center",
            "padding": "0 4px",
        }) if i < len(_KILL_CHAIN) - 1 else html.Span()

        card = html.Div([
            html.Div([
                html.Span(p["icon"], style={"fontSize": "22px"}),
                html.Div(p["phase"], style={
                    "color": color, "fontWeight": "900", "fontSize": "11px",
                    "letterSpacing": "0.5px", "marginTop": "4px",
                    "fontFamily": "monospace", "textTransform": "uppercase",
                }),
            ], style={"textAlign": "center", "marginBottom": "8px"}),

            html.Div(p["mitre"], style={
                "color": f"{color}88", "fontSize": "8px", "fontWeight": "700",
                "letterSpacing": "1px", "fontFamily": "monospace",
                "textAlign": "center", "marginBottom": "8px",
            }),

            html.Div(p["desc"], style={
                "color": _DIM, "fontSize": "9px", "lineHeight": "1.5",
                "textAlign": "center", "marginBottom": "10px",
            }),

            html.Div([
                html.Div(t, style={
                    "background": f"{color}15", "border": f"1px solid {color}44",
                    "color": color, "fontSize": "8px", "fontWeight": "700",
                    "padding": "2px 6px", "borderRadius": "3px",
                    "marginBottom": "3px", "textAlign": "center",
                    "fontFamily": "monospace",
                })
                for t in p["tactics"]
            ]),

        ], style={
            "background":    f"linear-gradient(160deg, {color}0a 0%, {_CARD} 100%)",
            "border":        f"1px solid {color}33",
            "borderTop":     f"3px solid {color}",
            "borderRadius":  "10px",
            "padding":       "14px 12px",
            "flex":          "1",
            "minWidth":      "120px",
        })

        phase_cards.append(card)
        phase_cards.append(arrow)

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
            "padding": "20px", "marginBottom": "28px",
            "background": _DARK, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px",
        }),

        # Phase strip
        html.Div([
            html.Div("LOCKHEED MARTIN CYBER KILL CHAIN  ·  MITRE ATT&CK OVERLAY",
                     style={
                         "color": _DIM, "fontSize": "9px", "fontWeight": "700",
                         "letterSpacing": "2px", "textAlign": "center", "marginBottom": "16px",
                     }),
            html.Div(phase_cards, style={
                "display": "flex", "alignItems": "stretch", "gap": "4px",
                "overflowX": "auto",
            }),
        ]),
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
        prevent_initial_call=False,
    )
    def update_killchain(_, __):
        try:
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
                    html.Div("STATIC ANATOMY", style={
                        "color": _DIM, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "2px", "marginBottom": "16px",
                    }),
                    _render_standalone_killchain(),
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
                return _render_standalone_killchain(), badge

        except Exception as e:
            return html.Div(f"[Kill Chain Error] {e}",
                            style={"color": _RED, "fontFamily": "monospace"}), ""

    print("[ui_killchain] Loaded — Premium Kill Chain Board active.")
