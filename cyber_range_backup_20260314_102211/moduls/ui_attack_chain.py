# ======================================================================
# ui_attack_chain.py — Attack Chain Simulator (Final Reconciled Version)
# ======================================================================


from dash import html, dcc, Input, Output, State, callback, no_update, ctx
from dash.exceptions import PreventUpdate
import dash_cytoscape as cyto
import json
import dash_bootstrap_components as dbc

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


# ======================================================================
# Layout
# ======================================================================

def aggressive_attack_layout():
    return html.Div(
        [
            html.H3("Aggressive Mode — Automated Exploitation Engine", className="text-danger mb-3"),

            html.P(
                "This module automatically evaluates vulnerabilities, searches for PoCs, "
                "runs exploitation attempts, and updates Neo4j.",
                className="text-info"
            ),

            dbc.Row([
                dbc.Col([
                    html.Label("Target Asset (IP/Hostname)", className="text-warning"),
                    dcc.Dropdown(
                        id="aggr-target-ip",
                        options=[],           # populated by callback
                        placeholder="Select an active target...",
                    ),
                ], width=6),
                dbc.Col([
                    dbc.Button("🔃 Refresh Targets", id="aggr-refresh-btn", color="secondary",
                               size="sm", className="mt-4"),
                    html.Div(id="aggr-refresh-status", className="text-success small mt-1"),
                ], width=3),
            ], className="mb-3"),

            html.Label("Vulnerability Name", className="text-warning"),
            dcc.Dropdown(
                id="aggr-vuln-name",
                options=[],
                placeholder="Select a discovered vulnerability...",
                disabled=True,
                className="mb-3",
            ),

            html.Label("CVE ID", className="text-warning"),
            dcc.Dropdown(
                id="aggr-cve",
                options=[],
                placeholder="Select associated CVE...",
                disabled=True,
                className="mb-3",
            ),

            # Auto-fires once on page load to populate targets
            dcc.Interval(id="aggr-init-interval", interval=1500, max_intervals=1),

            html.Br(), html.Br(),

            html.Button(
                "Run Full Exploitation",
                id="aggr-run-btn",
                className="btn btn-danger"
            ),

            html.Br(), html.Br(),

            html.H4("Execution Log", className="text-warning"),
            html.Div(
                id="aggr-log-output",
                style={
                    "minHeight": "300px",
                    "padding": "10px",
                    "border": "1px solid #444",
                    "borderRadius": "5px",
                    "backgroundColor": "#1a1a1a"
                }
            ),
        ],
        className="p-3"
    )



def attack_chain_simulator_layout():

    return html.Div(
        [
            html.H3("Attack Chain Simulator", className="text-warning mb-4"),

            # ---------------------------------------------------------------
            # Starting Asset
            # ---------------------------------------------------------------
            html.Div(
                [
                    html.Label("Attacker Starting Asset", className="text-info"),
                    dcc.Dropdown(
                        id="attack-start-asset",
                        options=[{"label": a, "value": a} for a in get_all_assets()],
                        placeholder="Select starting asset",
                    ),
                ],
                className="mb-3"
            ),

            # ---------------------------------------------------------------
            # Target Asset
            # ---------------------------------------------------------------
            html.Div(
                [
                    html.Label("Target Asset (Crown Jewel)", className="text-danger"),
                    dcc.Dropdown(
                        id="attack-target-asset",
                        options=[{"label": a, "value": a} for a in get_all_assets()],
                        placeholder="Select target asset",
                    ),
                ],
                className="mb-3"
            ),

            # ---------------------------------------------------------------
            # Exploit Mode
            # ---------------------------------------------------------------
            html.Div(
                [
                    html.Label("Exploit Mode", className="text-warning"),
                    dcc.Dropdown(
                        id="attack-exploit-mode",
                        options=[
                            {"label": "Mode 1 — Resume Only (Defensive)", "value": "resume"},
                            {"label": "Mode 2 — Enumerate PoCs Only", "value": "enum"},
                            {"label": "Mode 3 — Full Aggressive Exploitation", "value": "aggressive"},
                        ],
                        placeholder="Select exploitation mode",
                    ),
                ],
                className="mb-3"
            ),

            # ---------------------------------------------------------------
            # Reverse Shell (optional)
            # ---------------------------------------------------------------
            html.Div(
                [
                    html.Label("Reverse Shell Listener IP (Optional)", className="text-info"),
                    dcc.Input(
                        id="attack-lhost",
                        placeholder="192.168.1.111",
                        type="text",
                        className="form-control"
                    ),

                    html.Label("Reverse Shell Listener Port (Optional)", className="text-info mt-2"),
                    dcc.Input(
                        id="attack-lport",
                        placeholder="4444",
                        type="number",
                        className="form-control"
                    ),
                ],
                className="mb-3"
            ),

            # ---------------------------------------------------------------
            # Controls
            # ---------------------------------------------------------------
            html.Div([
                html.Button("📥 Load Scenario", id="run-attack-sim", className="btn btn-primary me-2"),
                html.Button("▶ Step Forward", id="attack-step-btn", className="btn btn-success me-2"),
                html.Button("⏩ Auto-Run", id="attack-auto-btn", className="btn btn-warning me-2"),
                html.Button("🔄 Reset", id="attack-reset-btn", className="btn btn-danger me-2"),
                html.Button("🔃 Refresh Assets", id="attack-refresh-assets-btn", className="btn btn-secondary me-2"),
            ], className="mb-2"),

            # Asset load status banner (hidden by default)
            html.Div(id="attack-asset-load-status", className="mb-3"),


            # Hidden Interval for Auto-Run
            dcc.Interval(id="attack-auto-timer", interval=1500, n_intervals=0, disabled=True),

            # ---------------------------------------------------------------
            # Attack Graph
            # ---------------------------------------------------------------
            html.H4("Tactical Execution Board", className="text-warning"),
            cyto.Cytoscape(
                id="attack-path-graph",
                layout={
                    "name": "dagre",
                    "rankDir": "LR",  # Left to Right tactical columns
                    "nodeSep": 50,
                    "rankSep": 150
                },
                style={"width": "100%", "height": "500px", "background-color": "#0a0a0a", "border": "1px solid #33ccff", "borderRadius": "8px"},
                stylesheet=[
                    {
                        "selector": "node",
                        "style": {
                            "label": "data(label)",
                            "color": "white",
                            "background-color": "#444",
                            "font-size": "14px",
                            "width": "60px",
                            "height": "60px",
                            "shape": "hexagon"
                        }
                    },
                    {
                        "selector": "node[state = 'PENDING']",
                        "style": {
                            "background-color": "#555",
                            "border-color": "#888",
                            "border-width": 2
                        }
                    },
                    {
                        "selector": "node[state = 'IN_PROGRESS']",
                        "style": {
                            "background-color": "#ff8c00",
                            "color": "black",
                            "border-color": "#ffaa00",
                            "border-width": 4
                        }
                    },
                    {
                        "selector": "node[state = 'SUCCESS']",
                        "style": {
                            "background-color": "#00ff00",
                            "color": "black",
                            "border-color": "#00cc00",
                            "border-width": 3
                        }
                    },
                    {
                        "selector": "node[state = 'FAILED']",
                        "style": {
                            "background-color": "#ff0000",
                            "border-color": "#cc0000",
                            "border-width": 3
                        }
                    },
                    {
                        "selector": "node[state = 'BLOCKED']",
                        "style": {
                            "background-color": "#ff00ff", # Wargame countermeasure
                            "shape": "octagon",
                            "border-color": "#cc00cc",
                            "border-width": 4
                        }
                    },
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#334455",
                            "target-arrow-color": "#334455",
                            "target-arrow-shape": "triangle",
                            "curve-style": "bezier",
                            "width": 2
                        }
                    },
                    {
                        "selector": "edge[active = 'true']",
                        "style": {
                            "line-color": "#00ff00",
                            "target-arrow-color": "#00ff00",
                            "width": 4
                        }
                    }
                ],
                elements=[]
            ),

            # Status and Logs
            html.Div([
                html.Div([
                    html.H4("Simulation Status", className="text-warning mt-4"),
                    html.Div(id="attack-chain-summary", className="text-light", style={"height": "150px", "overflowY": "auto"}),
                ], style={"width": "30%", "float": "left", "paddingRight": "20px"}),

                html.Div([
                    html.H4("Detection & Event Log", className="text-danger mt-4"),
                    html.Div(id="attack-path-narration", className="text-info", style={
                        "height": "200px", "overflowY": "scroll", "backgroundColor": "#111", 
                        "padding": "10px", "border": "1px solid #444", "fontFamily": "monospace"
                    }),
                ], style={"width": "70%", "float": "left"})
            ], style={"width": "100%", "display": "inline-block"}),
        ],
        className="p-4"
    )


def build_graph_elements_from_engine():
    """Converts the linear/DAG SimulationEngine internal nodes back to active Cytoscape elements."""
    elements = []
    
    # Render Nodes
    for i, node in enumerate(engine.nodes):
        elements.append({
            "data": {
                "id": node["id"],
                "label": f"{node['label']}\n({node['state']})",
                "state": node["state"],  # drives CSS coloring
                "tactic": node["tactic"]
            }
        })
        
    # Render Edges based on linearity (for phase 1, assume linear progression)
    for i in range(len(engine.nodes) - 1):
        n1 = engine.nodes[i]
        n2 = engine.nodes[i+1]
        
        # Edge is green/active if n1 is SUCCESS
        edge_active = "true" if n1["state"] == "SUCCESS" else "false"
        
        elements.append({
            "data": {
                "source": n1["id"],
                "target": n2["id"],
                "active": edge_active
            }
        })
        
    return elements

def build_log_html():
    """Converts engine event logs into colored HTML blocks."""
    lines = []
    for log in engine.logs:
        color = "#00ff00" if "SUCCESS" in log else "#ff0000" if "FAILED" in log or "ALERT" in log else "#33ccff"
        lines.append(html.Div(log, style={"color": color}))
    return lines


# ======================================================================
# Dropdown Refresh
# ======================================================================
@callback(
    Output("attack-start-asset",       "options"),
    Output("attack-target-asset",      "options"),
    Output("attack-asset-load-status", "children"),
    Input("run-attack-sim",            "n_clicks"),
    Input("attack-refresh-assets-btn", "n_clicks"),
    Input("attack-reset-btn",          "n_clicks"),
    prevent_initial_call=False
)
def refresh_asset_dropdowns(_, __, ___):
    """Refresh dropdown options from Neo4j. Does NOT set values — user must pick."""
    assets = get_all_assets()
    opts = [{"label": a, "value": a} for a in assets]
    if not assets:
        warn = html.Div(
            "⚠ No host assets found in Neo4j. Run a scan first, then click 🔃 Refresh Assets.",
            className="text-warning small"
        )
        return [], [], warn
    status = html.Div(
        f"✅ {len(assets)} host(s) available — select Attacker Starting Asset and Target to load a scenario.",
        className="text-success small"
    )
    return opts, opts, status


# ======================================================================
# MAIN Simulation Execution Callback
# ======================================================================
from dash import ctx

@callback(
    Output("attack-path-graph", "elements"),
    Output("attack-chain-summary", "children"),
    Output("attack-path-narration", "children"),
    Output("attack-auto-timer", "disabled"),

    Input("run-attack-sim", "n_clicks"),
    Input("attack-step-btn", "n_clicks"),
    Input("attack-auto-btn", "n_clicks"),
    Input("attack-reset-btn", "n_clicks"),
    Input("attack-auto-timer", "n_intervals"),

    State("attack-start-asset", "value"),
    State("attack-target-asset", "value"),
    State("attack-auto-timer", "disabled"),

    prevent_initial_call=True
)
def handle_simulation_controls(btn_load, btn_step, btn_auto, btn_reset, n_ticks, src, dst, timer_disabled):
    trigger = ctx.triggered_id
    
    # 1. Reset
    if trigger == "attack-reset-btn":
        engine.reset()
        reset_msg = html.Div([
            html.P("🔄 Engine Reset — Ready for new scenario.", className="text-success fw-bold mb-1"),
            html.P("1. Select Attacker Starting Asset above", className="text-info mb-0 small"),
            html.P("2. Select Target Asset (Crown Jewel)", className="text-info mb-0 small"),
            html.P("3. Choose Exploit Mode", className="text-info mb-0 small"),
            html.P("4. Click Load Scenario", className="text-warning mb-0 small"),
        ])
        return [], reset_msg, build_log_html(), True
        
    # 2. Load Scenario
    if trigger == "run-attack-sim":
        if not src and not dst:
            err = html.Div([
                html.P("⚠ Both fields are empty!", className="text-danger fw-bold mb-1"),
                html.P("Select an Attacker Starting Asset AND a Target Asset from the dropdowns above.",
                       className="text-warning small"),
            ])
            return no_update, err, no_update, True
        if not src:
            err = html.Div([
                html.P("⚠ Attacker Starting Asset is not selected!", className="text-danger fw-bold mb-1"),
                html.P("Pick a starting host from the first dropdown above, then click Load Scenario again.",
                       className="text-warning small"),
            ])
            return no_update, err, no_update, True
        if not dst:
            err = html.Div([
                html.P("⚠ Target Asset is not selected!", className="text-danger fw-bold mb-1"),
                html.P("Pick a target host from the second dropdown above, then click Load Scenario again.",
                       className="text-warning small"),
            ])
            return no_update, err, no_update, True
        if src == dst:
            err = html.Div([
                html.P("⚠ Start and Target must be different hosts!", className="text-danger fw-bold mb-1"),
                html.P(f"Currently both are set to: {src}", className="text-warning small"),
            ])
            return no_update, err, no_update, True
        
        result = safe_attack_path(src, dst)
        if not result:
            return no_update, html.Div([
                html.P(f"⚠ No attack path found: {src} → {dst}", className="text-warning fw-bold mb-1"),
                html.P("Ensure these hosts are connected in Neo4j (CONNECTED relationships).",
                       className="text-muted small"),
            ]), no_update, True
            
        # We parse the existing structure to inject into our new SimulationEngine
        raw_nodes = []
        for n in result["nodes"]:
            raw_nodes.append({
                "id": n["data"]["id"],
                "label": n["data"].get("label", n["data"]["id"]),
                "tactic": "Lateral Movement"  # stub for now pending MITRE enrichment
            })
            
        engine.load_scenario(raw_nodes)
        
        summary = html.Div([
            html.P(f"🔥 Scenario Loaded: {src} → {dst}", className="text-success fw-bold mb-1"),
            html.P(f"Total Steps: {len(raw_nodes)}", className="text-info mb-0"),
            html.P(f"Engine Status: {engine.status}", className="text-warning mb-0"),
            html.P("▶ Click Step Forward to begin, or ⏩ Auto-Run to execute automatically.",
                   className="text-light small mt-1"),
        ])
        return build_graph_elements_from_engine(), summary, build_log_html(), True

    # 3. Step Forward (Manual or Auto-Timer)
    if trigger == "attack-step-btn" or trigger == "attack-auto-timer":
        if engine.status in ["IDLE", "COMPLETED", "FAILED", "DEFENDED"]:
            return no_update, html.P(f"Engine halted: {engine.status} — Reset to start over.", className="text-danger"), no_update, True
            
        engine.step_forward()
        
        status_color = "red" if engine.status in ["FAILED", "DEFENDED"] else "green"
        summary = html.Div([
            html.P(f"Step: {engine.current_step} / {len(engine.nodes)}"),
            html.P(f"Engine Status: {engine.status}", style={"color": status_color})
        ])
        
        # Disable timer if finished, else keep current state
        new_timer_state = True if engine.status in ["COMPLETED", "FAILED", "DEFENDED"] else timer_disabled
        
        return build_graph_elements_from_engine(), summary, build_log_html(), new_timer_state
        
    # 4. Auto-Run Toggle
    if trigger == "attack-auto-btn":
        if engine.status in ["IDLE", "COMPLETED", "FAILED", "DEFENDED"]:
            return no_update, no_update, no_update, True # Can't start
        # Toggle disabled state
        return no_update, no_update, no_update, not timer_disabled

    raise PreventUpdate


# ======================================================================
# Aggressive Attack Dropdown Cascading
# ======================================================================

@callback(
    Output("aggr-target-ip",      "options"),
    Output("aggr-refresh-status", "children"),
    Input("aggr-init-interval",   "n_intervals"),
    Input("aggr-refresh-btn",     "n_clicks"),
    prevent_initial_call=False,
)
def refresh_aggr_targets(_intervals, _clicks):
    """Populate target-IP dropdown from Neo4j on page load and Refresh."""
    try:
        assets = get_all_assets()
        opts = [{"label": a, "value": a} for a in assets]
        if not assets:
            return [], "⚠ No hosts in Neo4j yet — run a scan first."
        return opts, f"✅ {len(assets)} host(s) loaded"
    except Exception as e:
        return [], f"❌ Neo4j error: {e}"


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
        pairs = get_vulns_for_asset(host)   # list of (label, internal_id)
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
        return [{"label": c, "value": c} for c in cves], False, cves[0] if len(cves) == 1 else None
    except Exception as e:
        return [{"label": f"Error: {e}", "value": ""}], True, None


@callback(
    Output("aggr-log-output", "children"),
    Input("aggr-run-btn", "n_clicks"),
    State("aggr-target-ip", "value"),
    State("aggr-vuln-name", "value"),
    State("aggr-cve", "value"),
    prevent_initial_call=True
)
def run_aggressive_attack(_, ip, vuln, cve):
    from cyber_range.services.exploit_engine import execute_attack

    if not ip or not vuln:
        return html.Div("❌ Missing fields. Provide an IP and Vulnerability name.", className="text-danger")

    result = execute_attack(ip, vuln, cve)

    # 1. ENUMERATION TAB
    enum_content = []
    enum_content.append(html.H5("SearchSploit Discoveries", className="text-info mt-3"))
    if result.get("searchsploit"):
        enum_content.append(html.Ul([html.Li(f"[{item['path']}] {item['title']}") for item in result["searchsploit"]]))
    else:
        enum_content.append(html.P("No local exploits discovered.", className="text-muted"))

    enum_content.append(html.H5("GitHub PoCs", className="text-info mt-3"))
    if result.get("github"):
        enum_content.append(html.Ul([html.Li(html.A(item.get("name"), href=item.get("url"), target="_blank", className="text-success")) for item in result["github"]]))
    else:
        enum_content.append(html.P("No GitHub PoCs found.", className="text-muted"))

    # 2. EXPLOITATION TAB
    exploit_content = []
    exec_res = result.get("execution", {})
    if exec_res:
        status = "✅ SUCCESS" if exec_res.get("success") else "❌ FAILED"
        exploit_content.append(html.H5(f"Script Execution: {status}", className="mt-3 text-warning"))
        exploit_content.append(html.Pre(exec_res.get("output", ""), style={"color": "#00ff00", "backgroundColor": "#000", "padding": "10px", "borderRadius": "5px", "maxHeight": "200px", "overflowY": "auto"}))

    msf_res = result.get("metasploit", {})
    if msf_res:
        status = "✅ SUCCESS" if msf_res.get("success") else "❌ FAILED"
        exploit_content.append(html.H5(f"Metasploit Execution: {status}", className="mt-3 text-warning"))
        exploit_content.append(html.Pre(msf_res.get("output", ""), style={"color": "#00ff00", "backgroundColor": "#000", "padding": "10px", "borderRadius": "5px", "maxHeight": "200px", "overflowY": "auto"}))

    # 3. POST-EXPLOITATION
    post_content = []
    post_content.append(html.H5("Artifact & Log Generation", className="text-warning mt-3"))
    post_content.append(html.P(f"Execution Log Written to Tracking File:", className="text-light"))
    post_content.append(html.Code(result.get("log_file", "None"), style={"color": "#ff33cc"}))
    
    tabs = dbc.Tabs([
        dbc.Tab(html.Div(enum_content, className="p-3"), label="1. Enumeration"),
        dbc.Tab(html.Div(exploit_content, className="p-3"), label="2. Exploitation"),
        dbc.Tab(html.Div(post_content, className="p-3"), label="3. Post-Exploitation"),
    ])

    return tabs
