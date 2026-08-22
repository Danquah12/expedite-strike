"""
ui_attack_chain.py — Attack Chain Simulator (Premium Tactical Edition)
=====================================================================
Full MITRE ATT&CK-mapped simulation engine with:
  - Premium dark tactical UI
  - Real-time node state graph (Cytoscape)
  - Live execution log with color-coded events
  - MITRE ATT&CK tactic phase mapping on every node
  - Traffic-light status indicators
  - Auto-populate dropdowns from Neo4j
"""

from dash import html, dcc, Input, Output, State, callback, no_update, ctx
from dash.exceptions import PreventUpdate
import dash_cytoscape as cyto
import dash_bootstrap_components as dbc
import json

# Attack path module
from cyber_range.services.attack_paths import (
    get_all_assets,
    safe_attack_path,
    get_exploit_chain_for_asset,
    get_edge_exploits,
    get_vulns_for_asset,
    get_cves_for_vuln
)

# Core Simulation Engine
from cyber_range.services.simulation_engine import engine


# ── Design tokens ─────────────────────────────────────────────────────────────
_DARK    = "#0a0d14"
_CARD    = "#0f1420"
_BORDER  = "#1e2a3a"
_GOLD    = "#ffd700"
_CYAN    = "#00c8ff"
_GREEN   = "#00ff88"
_RED     = "#ff3355"
_ORANGE  = "#ff8c00"
_PURPLE  = "#cc44ff"
_DIM     = "#4a5568"

# MITRE tactic colour palette
_TACTIC_COLORS = {
    "Reconnaissance":       "#00bcd4",
    "Resource Development": "#00bcd4",
    "Initial Access":       "#ff9800",
    "Execution":            "#ff5722",
    "Persistence":          "#f44336",
    "Privilege Escalation": "#e91e63",
    "Defense Evasion":      "#9c27b0",
    "Credential Access":    "#673ab7",
    "Discovery":            "#3f51b5",
    "Lateral Movement":     "#2196f3",
    "Collection":           "#009688",
    "Command and Control":  "#4caf50",
    "Exfiltration":         "#8bc34a",
    "Impact":               "#ff1744",
}


def _tactic_badge(tactic: str) -> html.Span:
    color = _TACTIC_COLORS.get(tactic, "#555")
    return html.Span(tactic, style={
        "background": f"{color}22",
        "border":     f"1px solid {color}66",
        "color":      color,
        "fontSize":   "9px",
        "fontWeight": "700",
        "letterSpacing": "0.5px",
        "padding":    "2px 7px",
        "borderRadius": "4px",
        "fontFamily": "monospace",
        "textTransform": "uppercase",
    })


def _stat_box(label, value, color=_CYAN):
    return html.Div([
        html.Div(str(value), style={
            "color": color, "fontSize": "24px", "fontWeight": "900",
            "fontFamily": "monospace", "lineHeight": "1",
        }),
        html.Div(label, style={
            "color": _DIM, "fontSize": "9px", "fontWeight": "700",
            "letterSpacing": "1px", "textTransform": "uppercase", "marginTop": "2px",
        }),
    ], style={
        "background": _CARD, "border": f"1px solid {_BORDER}",
        "borderTop":  f"2px solid {color}",
        "borderRadius": "8px", "padding": "12px 16px", "textAlign": "center",
        "flex": "1",
    })


# ── Cytoscape stylesheet ───────────────────────────────────────────────────────
_CYTO_STYLE = [
    {"selector": "node", "style": {
        "label":            "data(short_label)",
        "color":            "#ccc",
        "background-color": "#1a2030",
        "border-color":     "#2a3a50",
        "border-width":     2,
        "font-size":        "10px",
        "font-family":      "monospace",
        "width":            "70px",
        "height":           "70px",
        "shape":            "hexagon",
        "text-valign":      "center",
        "text-halign":      "center",
        "text-wrap":        "wrap",
        "text-max-width":   "60px",
    }},
    {"selector": "node[state = 'PENDING']", "style": {
        "background-color": "#1a2030",
        "border-color":     "#2a3a50",
        "color":            "#4a5568",
    }},
    {"selector": "node[state = 'IN_PROGRESS']", "style": {
        "background-color": "#ff8c0022",
        "border-color":     "#ff8c00",
        "border-width":     4,
        "color":            "#ff8c00",
        "font-weight":      "bold",
    }},
    {"selector": "node[state = 'SUCCESS']", "style": {
        "background-color": "#00ff8822",
        "border-color":     "#00ff88",
        "border-width":     3,
        "color":            "#00ff88",
        "font-weight":      "bold",
    }},
    {"selector": "node[state = 'FAILED']", "style": {
        "background-color": "#ff335522",
        "border-color":     "#ff3355",
        "border-width":     3,
        "color":            "#ff3355",
    }},
    {"selector": "node[state = 'BLOCKED']", "style": {
        "background-color": "#cc44ff22",
        "border-color":     "#cc44ff",
        "border-width":     4,
        "shape":            "octagon",
        "color":            "#cc44ff",
    }},
    {"selector": "edge", "style": {
        "line-color":           "#1e2a3a",
        "target-arrow-color":   "#1e2a3a",
        "target-arrow-shape":   "triangle",
        "curve-style":          "bezier",
        "width":                2,
    }},
    {"selector": "edge[active = 'true']", "style": {
        "line-color":           "#00ff88",
        "target-arrow-color":   "#00ff88",
        "width":                3,
    }},
    {"selector": "edge[active = 'blocked']", "style": {
        "line-color":           "#ff3355",
        "target-arrow-color":   "#ff3355",
        "width":                2,
        "line-style":           "dashed",
    }},
]


# ── Helper: build graph elements from engine ───────────────────────────────────
def build_graph_elements_from_engine():
    elements = []
    for node in engine.nodes:
        label = node.get("label", node["id"])
        short = label[:12] + "…" if len(label) > 12 else label
        tactic_color = _TACTIC_COLORS.get(node.get("tactic", ""), "#555")
        elements.append({"data": {
            "id":          node["id"],
            "label":       label,
            "short_label": short,
            "state":       node["state"],
            "tactic":      node.get("tactic", "Lateral Movement"),
            "tactic_color": tactic_color,
            "base_success": node.get("base_success", 70),
        }})
    for i in range(len(engine.nodes) - 1):
        n1, n2 = engine.nodes[i], engine.nodes[i + 1]
        active = "true"   if n1["state"] == "SUCCESS"             else \
                 "blocked" if n1["state"] in ("FAILED", "BLOCKED") else \
                 "false"
        elements.append({"data": {
            "source": n1["id"], "target": n2["id"], "active": active
        }})
    return elements


def build_log_html():
    lines = []
    for log in engine.logs[-50:]:   # last 50 entries
        msg   = log if isinstance(log, str) else log.get("message", str(log))
        ts    = log.get("timestamp", "") if isinstance(log, dict) else ""
        color = (_GREEN  if "SUCCESS" in msg or "Loaded" in msg else
                 _RED    if "FAILED" in msg or "ALERT" in msg or "BROKEN" in msg else
                 _ORANGE if "BLOCKED" in msg or "DEFENDED" in msg else
                 _PURPLE if "HONEYPOT" in msg else
                 _CYAN)
        lines.append(html.Div([
            html.Span(f"[{ts}] " if ts else "", style={"color": _DIM, "fontSize": "9px"}),
            html.Span(msg, style={"color": color}),
        ], style={"padding": "2px 0", "borderBottom": f"1px solid {_BORDER}22"}))
    return lines or [html.Div("— Awaiting simulation —", style={"color": _DIM, "fontStyle": "italic"})]


# ── Aggressive mode layout ─────────────────────────────────────────────────────
def aggressive_attack_layout():
    return html.Div([
        html.Div([
            html.Span("⚡", style={"fontSize": "20px", "marginRight": "10px"}),
            html.Div([
                html.Div("AGGRESSIVE MODE", style={
                    "color": _RED, "fontSize": "10px", "fontWeight": "900",
                    "letterSpacing": "2px", "textTransform": "uppercase",
                }),
                html.Div("Automated Exploitation Engine", style={
                    "color": "#ccc", "fontSize": "14px", "fontWeight": "700",
                }),
            ]),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "20px"}),

        html.Div(
            "This module evaluates vulnerabilities, searches for PoCs, runs exploitation "
            "attempts, and updates Neo4j with findings.",
            style={"color": _DIM, "fontSize": "12px", "marginBottom": "20px",
                   "padding": "10px 14px", "background": f"{_RED}11",
                   "border": f"1px solid {_RED}33", "borderRadius": "8px"}
        ),

        dbc.Row([
            dbc.Col([
                html.Div("TARGET ASSET", style={"color": _DIM, "fontSize": "9px",
                          "fontWeight": "700", "letterSpacing": "1px", "marginBottom": "6px"}),
                dcc.Dropdown(id="aggr-target-ip", options=[], placeholder="Select target host…",
                             style={"background": "#0f1420", "color": "#eee"}),
            ], width=8),
            dbc.Col([
                dbc.Button("🔃 Refresh", id="aggr-refresh-btn", color="secondary",
                           size="sm", className="mt-4",
                           style={"width": "100%", "fontSize": "11px"}),
                html.Div(id="aggr-refresh-status",
                         style={"color": _GREEN, "fontSize": "10px", "marginTop": "4px"}),
            ], width=4),
        ], className="mb-3"),

        html.Div("VULNERABILITY", style={"color": _DIM, "fontSize": "9px",
                  "fontWeight": "700", "letterSpacing": "1px", "marginBottom": "6px"}),
        dcc.Dropdown(id="aggr-vuln-name", options=[], placeholder="Select vulnerability…",
                     disabled=True, className="mb-3",
                     style={"background": "#0f1420", "color": "#eee"}),

        html.Div("CVE ID", style={"color": _DIM, "fontSize": "9px",
                  "fontWeight": "700", "letterSpacing": "1px", "marginBottom": "6px"}),
        dcc.Dropdown(id="aggr-cve", options=[], placeholder="Select CVE…",
                     disabled=True, className="mb-3",
                     style={"background": "#0f1420", "color": "#eee"}),

        dcc.Interval(id="aggr-init-interval", interval=1500, max_intervals=1),

        dbc.Button("💥 Run Full Exploitation", id="aggr-run-btn", color="danger",
                   style={"width": "100%", "fontWeight": "800", "marginBottom": "20px",
                          "letterSpacing": "1px", "fontSize": "13px"}),

        html.Div([
            html.Div("EXECUTION LOG", style={
                "color": _DIM, "fontSize": "9px", "fontWeight": "700",
                "letterSpacing": "1px", "marginBottom": "8px",
            }),
            html.Div(id="aggr-log-output", style={
                "background": _DARK, "border": f"1px solid {_BORDER}",
                "borderRadius": "8px", "padding": "12px", "minHeight": "300px",
                "fontFamily": "monospace", "fontSize": "11px",
                "overflow": "auto", "maxHeight": "500px",
            }),
        ]),
    ], style={"background": _CARD, "border": f"1px solid {_BORDER}",
              "borderRadius": "12px", "padding": "24px"})


# ── Main Attack Chain Simulator layout ────────────────────────────────────────
def attack_chain_simulator_layout():
    return html.Div([

        # ── Header ───────────────────────────────────────────────────────────
        html.Div([
            html.Div([
                html.Div("⚔ ATTACK CHAIN SIMULATOR", style={
                    "color": _GOLD, "fontSize": "11px", "fontWeight": "900",
                    "letterSpacing": "3px", "textTransform": "uppercase",
                    "fontFamily": "monospace",
                }),
                html.Div("MITRE ATT&CK · Neo4j Graph · Live Step-Through Engine", style={
                    "color": _DIM, "fontSize": "12px", "marginTop": "2px",
                }),
            ]),
            # Status pill
            html.Div(id="acs-status-pill", children=[
                html.Span("⬤", style={"color": _DIM, "marginRight": "6px"}),
                html.Span("IDLE", style={"color": _DIM, "fontSize": "11px",
                                          "fontWeight": "700", "fontFamily": "monospace"}),
            ], style={"display": "flex", "alignItems": "center",
                      "background": _DARK, "border": f"1px solid {_BORDER}",
                      "borderRadius": "20px", "padding": "6px 14px"}),
        ], style={
            "display": "flex", "justifyContent": "space-between", "alignItems": "center",
            "marginBottom": "24px",
            "borderBottom": f"2px solid {_GOLD}33", "paddingBottom": "16px",
        }),

        # ── Stat row ─────────────────────────────────────────────────────────
        html.Div(id="acs-stat-row", children=[
            _stat_box("Hosts in Neo4j", "…", _CYAN),
            _stat_box("Nodes Loaded",   "0",  _GOLD),
            _stat_box("Current Step",   "0",  _ORANGE),
            _stat_box("Status",         "IDLE", _DIM),
        ], style={"display": "flex", "gap": "12px", "marginBottom": "20px"}),

        # ── Config panel ──────────────────────────────────────────────────────
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div("🎯 ATTACKER STARTING ASSET", style={
                        "color": _CYAN, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "1px", "marginBottom": "6px",
                    }),
                    dcc.Dropdown(
                        id="attack-start-asset",
                        options=[{"label": a, "value": a} for a in get_all_assets()],
                        placeholder="Select starting node…",
                        style={"fontSize": "12px"},
                    ),
                ], width=4),
                dbc.Col([
                    html.Div("💎 TARGET ASSET (CROWN JEWEL)", style={
                        "color": _RED, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "1px", "marginBottom": "6px",
                    }),
                    dcc.Dropdown(
                        id="attack-target-asset",
                        options=[{"label": a, "value": a} for a in get_all_assets()],
                        placeholder="Select target…",
                        style={"fontSize": "12px"},
                    ),
                ], width=4),
                dbc.Col([
                    html.Div("⚡ EXPLOIT MODE", style={
                        "color": _ORANGE, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "1px", "marginBottom": "6px",
                    }),
                    dcc.Dropdown(
                        id="attack-exploit-mode",
                        options=[
                            {"label": "🛡 Mode 1 — Defensive (Resume Only)",   "value": "resume"},
                            {"label": "🔍 Mode 2 — Enumerate PoCs Only",        "value": "enum"},
                            {"label": "💥 Mode 3 — Full Aggressive",           "value": "aggressive"},
                        ],
                        placeholder="Select mode…",
                        style={"fontSize": "12px"},
                    ),
                ], width=4),
            ], className="mb-3"),

            dbc.Row([
                dbc.Col([
                    html.Div("LHOST (Optional)", style={"color": _DIM, "fontSize": "9px",
                              "fontWeight": "700", "letterSpacing": "1px", "marginBottom": "4px"}),
                    dcc.Input(id="attack-lhost", placeholder="192.168.1.111", type="text",
                              style={"background": _DARK, "border": f"1px solid {_BORDER}",
                                     "color": "#ccc", "borderRadius": "6px", "padding": "8px 12px",
                                     "width": "100%", "fontSize": "12px", "fontFamily": "monospace"}),
                ], width=3),
                dbc.Col([
                    html.Div("LPORT (Optional)", style={"color": _DIM, "fontSize": "9px",
                              "fontWeight": "700", "letterSpacing": "1px", "marginBottom": "4px"}),
                    dcc.Input(id="attack-lport", placeholder="4444", type="number",
                              style={"background": _DARK, "border": f"1px solid {_BORDER}",
                                     "color": "#ccc", "borderRadius": "6px", "padding": "8px 12px",
                                     "width": "100%", "fontSize": "12px", "fontFamily": "monospace"}),
                ], width=2),
                dbc.Col([
                    html.Div(" ", style={"marginBottom": "4px", "fontSize": "9px"}),
                    html.Div([
                        dbc.Button("📥 Load Scenario",  id="run-attack-sim",        color="primary",
                                   size="sm", className="me-1",
                                   style={"fontSize": "11px", "fontWeight": "700"}),
                        dbc.Button("▶ Step",            id="attack-step-btn",        color="success",
                                   size="sm", className="me-1",
                                   style={"fontSize": "11px"}),
                        dbc.Button("⏩ Auto-Run",        id="attack-auto-btn",        color="warning",
                                   size="sm", className="me-1",
                                   style={"fontSize": "11px"}),
                        dbc.Button("🔄 Reset",           id="attack-reset-btn",       color="danger",
                                   size="sm", className="me-1",
                                   style={"fontSize": "11px"}),
                        dbc.Button("🔃 Refresh Assets",  id="attack-refresh-assets-btn", color="secondary",
                                   size="sm",
                                   style={"fontSize": "11px"}),
                    ]),
                ], width=7),
            ]),

            html.Div(id="attack-asset-load-status", style={"marginTop": "8px", "fontSize": "11px"}),
        ], style={
            "background": _DARK, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px", "padding": "18px", "marginBottom": "20px",
        }),

        dcc.Interval(id="attack-auto-timer", interval=1500, n_intervals=0, disabled=True),

        # ── Tactical graph ────────────────────────────────────────────────────
        html.Div([
            html.Div("⬡  TACTICAL EXECUTION BOARD", style={
                "color": _GOLD, "fontSize": "9px", "fontWeight": "900",
                "letterSpacing": "2px", "fontFamily": "monospace",
                "marginBottom": "12px",
            }),
            cyto.Cytoscape(
                id="attack-path-graph",
                layout={"name": "dagre", "rankDir": "LR", "nodeSep": 60, "rankSep": 160},
                style={"width": "100%", "height": "420px",
                       "background": _DARK, "borderRadius": "8px",
                       "border": f"1px solid {_BORDER}"},
                stylesheet=_CYTO_STYLE,
                elements=[],
            ),
        ], style={
            "background": _CARD, "border": f"1px solid {_BORDER}",
            "borderRadius": "10px", "padding": "16px", "marginBottom": "20px",
        }),

        # ── Status + Log row ──────────────────────────────────────────────────
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div("SIMULATION STATUS", style={
                        "color": _DIM, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "1px", "marginBottom": "10px",
                    }),
                    html.Div(id="attack-chain-summary", style={
                        "fontSize": "12px", "fontFamily": "monospace",
                        "minHeight": "180px", "overflowY": "auto",
                    }, children=[
                        html.Div("Select assets and click Load Scenario to begin.",
                                 style={"color": _DIM, "fontStyle": "italic"}),
                    ]),
                ], style={
                    "background": _DARK, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "16px", "height": "100%",
                }),
            ], width=4),
            dbc.Col([
                html.Div([
                    html.Div("DETECTION & EVENT LOG", style={
                        "color": _RED, "fontSize": "9px", "fontWeight": "700",
                        "letterSpacing": "1px", "marginBottom": "10px",
                    }),
                    html.Div(id="attack-path-narration", style={
                        "fontFamily": "monospace", "fontSize": "10px",
                        "height": "180px", "overflowY": "auto",
                        "lineHeight": "1.7",
                    }, children=[
                        html.Div("— Awaiting simulation —",
                                 style={"color": _DIM, "fontStyle": "italic"}),
                    ]),
                ], style={
                    "background": _DARK, "border": f"1px solid {_BORDER}",
                    "borderRadius": "10px", "padding": "16px", "height": "100%",
                }),
            ], width=8),
        ]),

    ], style={
        "background": _CARD, "minHeight": "100vh",
        "padding": "24px", "fontFamily": "'Inter', monospace",
    })


# ── Callbacks ─────────────────────────────────────────────────────────────────
@callback(
    Output("attack-start-asset",       "options"),
    Output("attack-target-asset",      "options"),
    Output("attack-asset-load-status", "children"),
    Output("acs-stat-row",             "children"),
    Input("run-attack-sim",            "n_clicks"),
    Input("attack-refresh-assets-btn", "n_clicks"),
    Input("attack-reset-btn",          "n_clicks"),
    prevent_initial_call=False,
)
def refresh_asset_dropdowns(_, __, ___):
    assets = get_all_assets()
    opts   = [{"label": a, "value": a} for a in assets]
    n      = len(assets)

    stat_row = [
        _stat_box("Hosts in Neo4j", n,    _CYAN),
        _stat_box("Nodes Loaded",   len(engine.nodes), _GOLD),
        _stat_box("Current Step",   engine.current_step, _ORANGE),
        _stat_box("Status",         engine.status, _GREEN if engine.status == "COMPLETED" else _DIM),
    ]

    if not assets:
        msg = html.Div("⚠ No hosts in Neo4j — run a scan first, then Refresh Assets.",
                       style={"color": _ORANGE, "fontSize": "11px"})
        return [], [], msg, stat_row

    msg = html.Div([
        html.Span("✅ ", style={"color": _GREEN}),
        html.Span(f"{n} host(s) available — select Attacker Start and Target, then Load Scenario.",
                  style={"color": _DIM, "fontSize": "11px"}),
    ])
    return opts, opts, msg, stat_row


@callback(
    Output("attack-path-graph",    "elements"),
    Output("attack-chain-summary", "children"),
    Output("attack-path-narration","children"),
    Output("attack-auto-timer",    "disabled"),
    Output("acs-status-pill",      "children"),

    Input("run-attack-sim",        "n_clicks"),
    Input("attack-step-btn",       "n_clicks"),
    Input("attack-auto-btn",       "n_clicks"),
    Input("attack-reset-btn",      "n_clicks"),
    Input("attack-auto-timer",     "n_intervals"),

    State("attack-start-asset",    "value"),
    State("attack-target-asset",   "value"),
    State("attack-auto-timer",     "disabled"),

    prevent_initial_call=True,
)
def handle_simulation_controls(btn_load, btn_step, btn_auto, btn_reset,
                                n_ticks, src, dst, timer_disabled):
    trigger = ctx.triggered_id

    def _status_pill(label, color):
        return [
            html.Span("⬤", style={"color": color, "marginRight": "6px"}),
            html.Span(label, style={"color": color, "fontSize": "11px",
                                     "fontWeight": "700", "fontFamily": "monospace"}),
        ]

    def _summary(lines):
        return [html.Div(l, style={"padding": "3px 0", "borderBottom": f"1px solid {_BORDER}22"})
                for l in lines]

    # ── Reset ──────────────────────────────────────────────────────────────
    if trigger == "attack-reset-btn":
        engine.reset()
        return ([], _summary([
            html.Span("🔄 Engine Reset — IDLE", style={"color": _GREEN, "fontWeight": "700"}),
            html.Span("1. Select Attacker Starting Asset", style={"color": _DIM}),
            html.Span("2. Select Target (Crown Jewel)",    style={"color": _DIM}),
            html.Span("3. Choose Exploit Mode",            style={"color": _DIM}),
            html.Span("4. Click Load Scenario ▶",          style={"color": _GOLD}),
        ]), build_log_html(), True, _status_pill("IDLE", _DIM))

    # ── Load Scenario ──────────────────────────────────────────────────────
    if trigger == "run-attack-sim":
        if not src or not dst:
            missing = "Attacker Starting Asset" if not src else "Target Asset"
            return (no_update, _summary([
                html.Span(f"⚠ {missing} not selected!", style={"color": _RED, "fontWeight": "700"}),
                html.Span("Both fields required before loading a scenario.", style={"color": _ORANGE}),
            ]), no_update, True, _status_pill("CONFIG ERROR", _RED))
        if src == dst:
            return (no_update, _summary([
                html.Span("⚠ Start and Target must be different hosts!", style={"color": _RED}),
            ]), no_update, True, _status_pill("CONFIG ERROR", _RED))

        result = safe_attack_path(src, dst)
        if not result:
            return (no_update, _summary([
                html.Span(f"⚠ No path found: {src} → {dst}", style={"color": _ORANGE, "fontWeight": "700"}),
                html.Span("Hosts must be connected in Neo4j (CONNECTED relationships).", style={"color": _DIM}),
            ]), no_update, True, _status_pill("NO PATH", _ORANGE))

        # Map MITRE tactics based on position in chain
        tactic_sequence = [
            "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
        ]
        raw_nodes = []
        for i, n in enumerate(result["nodes"]):
            tactic = tactic_sequence[min(i, len(tactic_sequence) - 1)]
            raw_nodes.append({
                "id":     n["data"]["id"],
                "label":  n["data"].get("label", n["data"]["id"]),
                "tactic": tactic,
            })

        engine.load_scenario(raw_nodes)

        summary = _summary([
            html.Span([
                html.Span("🔥 Loaded: ", style={"color": _GOLD, "fontWeight": "900"}),
                html.Span(f"{src} → {dst}", style={"color": "#fff", "fontFamily": "monospace"}),
            ]),
            html.Span(f"Total Steps: {len(raw_nodes)}", style={"color": _CYAN}),
            html.Span(f"Status: {engine.status}", style={"color": _GREEN}),
            html.Span("▶ Click Step or ⏩ Auto-Run to execute.", style={"color": _DIM}),
        ])
        return (build_graph_elements_from_engine(), summary,
                build_log_html(), True, _status_pill("READY", _CYAN))

    # ── Step / Auto-Timer ──────────────────────────────────────────────────
    if trigger in ("attack-step-btn", "attack-auto-timer"):
        if engine.status in ("IDLE", "COMPLETED", "FAILED", "DEFENDED"):
            return (no_update,
                    _summary([html.Span(f"Engine halted: {engine.status} — Reset to restart.",
                                        style={"color": _RED})]),
                    no_update, True, _status_pill(engine.status, _RED))

        engine.step_forward()

        status_color = (_GREEN  if engine.status == "COMPLETED" else
                        _RED    if engine.status in ("FAILED", "DEFENDED") else
                        _ORANGE)
        summary = _summary([
            html.Span(f"Step: {engine.current_step} / {len(engine.nodes)}",
                      style={"color": "#fff", "fontWeight": "700"}),
            html.Span(f"Status: {engine.status}", style={"color": status_color}),
        ])
        new_timer = True if engine.status in ("COMPLETED", "FAILED", "DEFENDED") else timer_disabled
        return (build_graph_elements_from_engine(), summary,
                build_log_html(), new_timer, _status_pill(engine.status, status_color))

    # ── Auto-Run Toggle ────────────────────────────────────────────────────
    if trigger == "attack-auto-btn":
        if engine.status in ("IDLE", "COMPLETED", "FAILED", "DEFENDED"):
            return no_update, no_update, no_update, True, no_update
        return no_update, no_update, no_update, not timer_disabled, no_update

    raise PreventUpdate


# ── Aggressive mode callbacks ──────────────────────────────────────────────────
@callback(
    Output("aggr-target-ip",      "options"),
    Output("aggr-refresh-status", "children"),
    Input("aggr-init-interval",   "n_intervals"),
    Input("aggr-refresh-btn",     "n_clicks"),
    prevent_initial_call=False,
)
def refresh_aggr_targets(_intervals, _clicks):
    try:
        assets = get_all_assets()
        opts   = [{"label": a, "value": a} for a in assets]
        if not assets:
            return [], html.Span("⚠ No hosts in Neo4j — run a scan first.",
                                  style={"color": _ORANGE})
        return opts, html.Span(f"✅ {len(assets)} host(s) loaded", style={"color": _GREEN})
    except Exception as e:
        return [], html.Span(f"❌ Neo4j error: {e}", style={"color": _RED})


@callback(
    Output("aggr-vuln-name", "options"),
    Output("aggr-vuln-name", "disabled"),
    Output("aggr-vuln-name", "value"),
    Input("aggr-target-ip",  "value"),
    prevent_initial_call=False,
)
def update_aggr_vulns(host):
    if not host:
        return [], True, None
    try:
        pairs = get_vulns_for_asset(host)
        if not pairs:
            return [{"label": "No vulnerabilities found for this host", "value": ""}], False, ""
        opts = [{"label": (lbl[:80] + "…" if len(lbl) > 80 else lbl), "value": val}
                for lbl, val in pairs]
        return opts, False, None
    except Exception as e:
        return [{"label": f"Error: {e}", "value": ""}], True, None


@callback(
    Output("aggr-cve", "options"),
    Output("aggr-cve", "disabled"),
    Output("aggr-cve", "value"),
    Input("aggr-target-ip",  "value"),
    Input("aggr-vuln-name",  "value"),
    prevent_initial_call=False,
)
def update_aggr_cves(host, vuln):
    if not host or not vuln:
        return [], True, None
    try:
        cves = get_cves_for_vuln(host, vuln)
        if not cves:
            return [{"label": "No associated CVEs", "value": ""}], False, ""
        return ([{"label": c, "value": c} for c in cves],
                False, cves[0] if len(cves) == 1 else None)
    except Exception as e:
        return [{"label": f"Error: {e}", "value": ""}], True, None


@callback(
    Output("aggr-log-output", "children"),
    Input("aggr-run-btn",     "n_clicks"),
    State("aggr-target-ip",   "value"),
    State("aggr-vuln-name",   "value"),
    State("aggr-cve",         "value"),
    prevent_initial_call=True,
)
def run_aggressive_attack(_, ip, vuln, cve):
    from cyber_range.services.exploit_engine import execute_attack
    if not ip or not vuln:
        return html.Div("❌ Missing fields — provide IP and Vulnerability.",
                        style={"color": _RED, "fontFamily": "monospace"})

    result = execute_attack(ip, vuln, cve)

    def _section(title, color, content):
        return html.Div([
            html.Div(title, style={"color": color, "fontWeight": "700",
                                    "fontSize": "11px", "marginBottom": "8px",
                                    "borderBottom": f"1px solid {color}44",
                                    "paddingBottom": "4px"}),
            *content,
        ], style={"marginBottom": "16px"})

    enum_items = []
    if result.get("searchsploit"):
        enum_items += [html.Div(f"[{i['path']}] {i['title']}",
                                style={"color": _CYAN, "fontSize": "10px",
                                       "fontFamily": "monospace"})
                       for i in result["searchsploit"]]
    else:
        enum_items.append(html.Div("No local exploits found.", style={"color": _DIM}))
    if result.get("github"):
        enum_items += [html.A(i.get("name"), href=i.get("url"), target="_blank",
                               style={"color": _GREEN, "display": "block", "fontSize": "10px"})
                       for i in result["github"]]
    else:
        enum_items.append(html.Div("No GitHub PoCs found.", style={"color": _DIM}))

    exploit_items = []
    exec_res = result.get("execution", {})
    if exec_res:
        ok = exec_res.get("success")
        exploit_items.append(html.Div(
            f"{'✅ SUCCESS' if ok else '❌ FAILED'} — Script Execution",
            style={"color": _GREEN if ok else _RED, "fontWeight": "700"}
        ))
        exploit_items.append(html.Pre(exec_res.get("output", ""),
            style={"color": "#0f0", "background": _DARK, "padding": "10px",
                   "borderRadius": "6px", "maxHeight": "200px", "overflowY": "auto",
                   "fontSize": "10px", "border": f"1px solid {_BORDER}"}))

    post_items = [
        html.Div("Log file:", style={"color": _DIM, "fontSize": "10px"}),
        html.Code(result.get("log_file", "None"),
                  style={"color": _PURPLE, "fontSize": "10px"}),
    ]

    return dbc.Tabs([
        dbc.Tab(html.Div([
            _section("SearchSploit & GitHub", _CYAN, enum_items),
        ], style={"padding": "12px", "background": _DARK, "borderRadius": "6px"}),
            label="1. Enumeration"),
        dbc.Tab(html.Div([
            _section("Exploitation Results", _RED, exploit_items),
        ], style={"padding": "12px", "background": _DARK, "borderRadius": "6px"}),
            label="2. Exploitation"),
        dbc.Tab(html.Div([
            _section("Post-Exploitation", _PURPLE, post_items),
        ], style={"padding": "12px", "background": _DARK, "borderRadius": "6px"}),
            label="3. Post-Exploitation"),
    ])
