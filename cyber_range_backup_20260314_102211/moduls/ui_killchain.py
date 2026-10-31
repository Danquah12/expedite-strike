# ==============================================================
# ui_killchain.py — FIXED VERSION (Asset-based dropdowns)
# ==============================================================

import json
from dash import html, dcc, Input, Output, State, callback
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

# Core Simulation Engine
from cyber_range.services.simulation_engine import engine


# ==============================================================
# KILL CHAIN MAPPER
# ==============================================================
# Maps generic MITRE tactics (or node states) to the higher-level
# Lockheed Martin Cyber Kill Chain phases.
TARGET_PHASES = {
    "Recon": ["Reconnaissance", "Resource Development"],
    "Weaponization": ["Initial Access"],
    "Delivery": ["Execution"],
    "Exploitation": ["Persistence", "Privilege Escalation", "Defense Evasion"],
    "Installation": ["Credential Access", "Discovery", "Lateral Movement"],
    "C2": ["Command and Control"],
    "Actions on Objectives": ["Collection", "Exfiltration", "Impact"]
}

def map_engine_to_killchain():
    """Reads the live SimulationEngine and categorizes progress into the 7 phases."""
    if not engine.nodes:
        return None
        
    mapped_chain = {phase: {"status": "Pending", "nodes": []} for phase in TARGET_PHASES.keys()}
    
    for node in engine.nodes:
        tactic = node.get("tactic", "Lateral Movement") # Fallback
        matched_phase = "Installation" # Default fallback
        
        for phase, tactics in TARGET_PHASES.items():
            if tactic in tactics:
                matched_phase = phase
                break
                
        mapped_chain[matched_phase]["nodes"].append(node)
        
        # Determine aggregate status for the phase
        state = node.get("state")
        if state == "SUCCESS":
            mapped_chain[matched_phase]["status"] = "Compromised"
        elif state == "FAILED" or state == "BLOCKED":
            mapped_chain[matched_phase]["status"] = "Defended / Blocked"
        elif state == "IN_PROGRESS":
            mapped_chain[matched_phase]["status"] = "Active Combat"
            
    return mapped_chain


# ==============================================================
# FRONTEND: Render Kill Chain Output Panel
# ==============================================================
def render_kill_chain(mapped_chain):
    if not mapped_chain:
        return html.Div("No active simulation. Go to the Attack Chain tab to load a scenario.", className="text-warning p-4")

    # Build the 7-phase vertical abstraction
    phase_cards = []
    
    for phase_name, data in mapped_chain.items():
        status = data["status"]
        nodes = data["nodes"]
        
        if not nodes:
            continue # Skip phases that aren't part of this simulation
            
        # Color coding
        color = "secondary"
        text_theme = "text-muted"
        if status == "Compromised":
            color = "danger"
            text_theme = "text-light"
        elif status == "Active Combat":
            color = "warning"
            text_theme = "text-dark"
        elif status == "Defended / Blocked":
            color = "success"
            text_theme = "text-light"
            
        node_details = html.Ul([
            html.Li(f"{n['label']} ({n['state']}) - Base Success: {n.get('base_success')}%") 
            for n in nodes
        ])
            
        card = dbc.Card(
            [
                dbc.CardHeader(html.H4(phase_name, className="mb-0")),
                dbc.CardBody(
                    [
                        html.H6(f"Status: {status}", className=f"{text_theme} fw-bold"),
                        html.Hr(),
                        html.P("Techniques tracked in this phase:"),
                        node_details
                    ]
                )
            ],
            color=color,
            inverse=(color in ["danger", "success", "secondary"]),
            className="mb-3"
        )
        phase_cards.append(card)

    return dbc.Container([
        html.H3("Strategic Kill Chain Abstraction", className="text-info"),
        html.P("This view aggregates the granular, step-by-step Attack Chain data into the 7 high-level phases of the Lockheed Martin Cyber Kill Chain.", className="text-muted"),
        html.Hr(),
        dbc.Row([
            dbc.Col(phase_cards, width=8),
            dbc.Col([
                html.H4("Simulation Overview", className="text-warning"),
                html.Div([
                    html.P(f"Engine Status: {engine.status}", className="text-light fw-bold"),
                    html.P(f"Total Nodes: {len(engine.nodes)}"),
                    html.P(f"Current Step: {engine.current_step}"),
                    html.P("Wargame AI: " + ("Enabled" if engine.wargame_active else "Disabled")),
                    html.P("Honeypots: " + ("Enabled" if engine.honeypots_active else "Disabled"))
                ], className="p-3 border rounded border-warning")
            ], width=4)
        ])
    ])

# ==============================================================
# TAB LAYOUT
# ==============================================================
def killchain_tab():
    return dbc.Container([

        html.H2("⚔ Cyber Kill Chain Board", className="text-warning mb-4"),
        
        html.Div(
            "This module reads the live engine state from the Attack Chain module and does not require re-simulation. Click 'Refresh State' to update the abstraction.",
            className="alert alert-info"
        ),

        dbc.Button("🔄 Refresh State", id="killchain-run", color="primary", className="mb-4"),

        html.Div(
            id="killchain-output",
            children="Click Refresh to aggregate the active simulation.",
            className="p-3",
        ),

    ], fluid=True)


# ==============================================================
# CALLBACK REGISTRATION
# ==============================================================
def register_callbacks(app):

    @app.callback(
        Output("killchain-output", "children"),
        Input("killchain-run", "n_clicks"),
        prevent_initial_call=False
    )
    def update_killchain(_):
        try:
            mapped_chain = map_engine_to_killchain()
            return render_kill_chain(mapped_chain)
        except Exception as e:
            return html.Div(f"[Kill Chain Error] {e}", className="text-danger")

    print("[ui_killchain] Loaded — Hooked into unified SimulationEngine.")
