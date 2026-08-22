# ui_wargame_ai.py
"""
Dash UI module for the Autonomous Cyber Wargame Engine.
Includes:
  - Wargame text output (colour-coded per round)
  - Cytoscape graph visualising every round with
    Attacker → Red moves → Blue defences → Outcomes → MITRE techniques → Target
"""

import re
from dash import html, dcc, Input, Output, State, callback
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

from cyber_range.services.wargame_ai import WargameAI
from cyber_range.services.simulation_engine import engine

war_ai = WargameAI()

# ──────────────────────────────────────────────────────────────────────────────
# Cytoscape stylesheet for the wargame graph
# ──────────────────────────────────────────────────────────────────────────────
WARGAME_STYLESHEET = [
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "color": "white",
            "font-size": "10px",
            "text-valign": "center",
            "text-halign": "center",
            "text-wrap": "wrap",
            "text-max-width": "130px",
            "width": "130px",
            "height": "55px",
            "shape": "round-rectangle",
            "background-color": "#2a2a2a",
            "border-width": 2,
            "border-color": "#555",
        },
    },
    # Attacker
    {
        "selector": "node[type='attacker']",
        "style": {
            "background-color": "#6b0000",
            "border-color": "#ff4444",
            "border-width": 4,
            "width": "150px",
            "height": "65px",
            "font-size": "12px",
            "font-weight": "bold",
            "shape": "pentagon",
        },
    },
    # Target (crown jewel)
    {
        "selector": "node[type='target']",
        "style": {
            "background-color": "#00285a",
            "border-color": "#33aaff",
            "border-width": 4,
            "width": "150px",
            "height": "65px",
            "font-size": "12px",
            "font-weight": "bold",
            "shape": "star",
        },
    },
    # Round marker
    {
        "selector": "node[type='round']",
        "style": {
            "background-color": "#1a1a1a",
            "border-color": "#aaa",
            "shape": "diamond",
            "width": "70px",
            "height": "70px",
            "font-size": "11px",
            "font-weight": "bold",
        },
    },
    # Red Team action
    {
        "selector": "node[type='red']",
        "style": {
            "background-color": "#7a1500",
            "border-color": "#ff6633",
            "border-width": 2,
        },
    },
    # Blue Team defence
    {
        "selector": "node[type='blue']",
        "style": {
            "background-color": "#003366",
            "border-color": "#3399ff",
            "border-width": 2,
        },
    },
    # Outcome — Red Team gained ground
    {
        "selector": "node[type='outcome_red']",
        "style": {
            "background-color": "#550000",
            "border-color": "#ff0000",
            "border-width": 3,
            "shape": "octagon",
        },
    },
    # Outcome — Blue Team defended
    {
        "selector": "node[type='outcome_blue']",
        "style": {
            "background-color": "#003300",
            "border-color": "#00ff66",
            "border-width": 3,
            "shape": "octagon",
        },
    },
    # MITRE ATT&CK technique
    {
        "selector": "node[type='mitre']",
        "style": {
            "background-color": "#4a3000",
            "border-color": "#ffaa00",
            "border-width": 2,
            "shape": "hexagon",
            "width": "100px",
            "height": "50px",
            "font-size": "9px",
        },
    },
    # Edges
    {
        "selector": "edge",
        "style": {
            "line-color": "#444",
            "target-arrow-color": "#666",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "width": 1.5,
        },
    },
    {
        "selector": "edge[etype='attack']",
        "style": {"line-color": "#ff5533", "target-arrow-color": "#ff5533", "width": 2.5},
    },
    {
        "selector": "edge[etype='defend']",
        "style": {"line-color": "#3399ff", "target-arrow-color": "#3399ff", "width": 2},
    },
    {
        "selector": "edge[etype='chain']",
        "style": {
            "line-color": "#888",
            "target-arrow-color": "#888",
            "line-style": "dashed",
            "width": 1.5,
        },
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Text → graph parser
# ──────────────────────────────────────────────────────────────────────────────
def _first_sentence(text: str, max_chars: int = 90) -> str:
    if not text:
        return ""
    # Take first sentence or clip
    s = re.split(r'(?<=[.!?])\s', text.strip())[0]
    return s[:max_chars] + ("…" if len(s) > max_chars else "")


def _extract_section(round_text: str, headers: list) -> str:
    """Extract the text under a bold section header."""
    for h in headers:
        pat = rf'\*\*{re.escape(h)}[:\*]*\*\*\s*(.*?)(?=\n\*\*|\Z)'
        m = re.search(pat, round_text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _parse_wargame_to_elements(full_text: str, source: str, target: str) -> list:
    """Convert wargame text output to Cytoscape elements."""
    elements = []

    # Attacker + Target
    elements.append({
        "data": {"id": "attacker", "label": f"🔴 ATTACKER\n{source}", "type": "attacker"}
    })
    elements.append({
        "data": {"id": "target_node", "label": f"💎 CROWN JEWEL\n{target}", "type": "target"}
    })

    # Split by round
    parts = re.split(r'###\s*Round\s*(\d+)', full_text)
    # parts = ['preamble', '1', 'text1', '2', 'text2', ...]

    prev_id = "attacker"

    for i in range(1, len(parts), 2):
        round_num = parts[i].strip()
        rtxt = parts[i + 1] if i + 1 < len(parts) else ""

        red_txt  = _extract_section(rtxt, ["Red Team Action", "Red Team Move"])
        blue_txt = _extract_section(rtxt, ["Blue Team Response", "Blue Team Move"])
        out_txt  = _extract_section(rtxt, ["Outcome of the Interaction", "Outcome", "Result"])
        mitre_txt = _extract_section(rtxt, ["Relevant MITRE ATT&CK Techniques", "MITRE ATT&CK"])

        # Determine who won this round
        red_won = any(kw in out_txt.lower() for kw in
                      ["successful", "success", "compromised", "gained", "achieved",
                       "breach", "accessed", "established", "exfil"])

        rnd_id  = f"rnd_{round_num}"
        red_id  = f"red_{round_num}"
        blue_id = f"blue_{round_num}"
        out_id  = f"out_{round_num}"

        # Nodes
        elements.append({
            "data": {
                "id":    rnd_id,
                "label": f"⚔️ Round {round_num}",
                "type":  "round",
            }
        })
        elements.append({
            "data": {
                "id":    red_id,
                "label": f"🔴 Red: {_first_sentence(red_txt) or 'Recon / Attack'}",
                "type":  "red",
            }
        })
        elements.append({
            "data": {
                "id":    blue_id,
                "label": f"🔵 Blue: {_first_sentence(blue_txt) or 'Monitor / Defend'}",
                "type":  "blue",
            }
        })
        elements.append({
            "data": {
                "id":    out_id,
                "label": ("⚡ BREACH — " if red_won else "🛡 DEFENDED — ") + _first_sentence(out_txt, 70),
                "type":  "outcome_red" if red_won else "outcome_blue",
            }
        })

        # MITRE technique nodes (extract T#### IDs)
        mitre_ids = list(dict.fromkeys(re.findall(r'T\d{4}(?:\.\d{3})?', mitre_txt)))[:4]
        for j, tid in enumerate(mitre_ids):
            mid = f"mitre_{round_num}_{j}"
            elements.append({
                "data": {"id": mid, "label": f"🎯 {tid}", "type": "mitre"}
            })
            elements.append({"data": {"source": out_id, "target": mid, "etype": "chain"}})

        # Edges
        elements.append({"data": {"source": prev_id,  "target": rnd_id,  "etype": "chain"}})
        elements.append({"data": {"source": rnd_id,   "target": red_id,  "etype": "attack"}})
        elements.append({"data": {"source": rnd_id,   "target": blue_id, "etype": "defend"}})
        elements.append({"data": {"source": red_id,   "target": out_id,  "etype": "attack"}})
        elements.append({"data": {"source": blue_id,  "target": out_id,  "etype": "defend"}})

        prev_id = out_id

    elements.append({"data": {"source": prev_id, "target": "target_node", "etype": "chain"}})
    return elements


# ──────────────────────────────────────────────────────────────────────────────
# Colour-coded text renderer
# ──────────────────────────────────────────────────────────────────────────────
def _render_coloured_text(full_text: str) -> list:
    """Return a list of Dash children with colour highlights per section."""
    blocks = []
    parts = re.split(r'(###\s*Round\s*\d+)', full_text)

    SECTION_COLORS = {
        "red team":  "#ff6633",
        "blue team": "#3399ff",
        "outcome":   "#ffdd00",
        "next-step": "#aaffaa",
        "mitre":     "#ffaa44",
        "detection": "#cc99ff",
    }

    for part in parts:
        if re.match(r'###\s*Round\s*\d+', part):
            blocks.append(html.H5(part.strip(),
                                  style={"color": "#ff9900", "marginTop": "16px",
                                         "borderBottom": "1px solid #444", "paddingBottom": "4px"}))
        else:
            lines = part.split("\n")
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                color = "#ccc"
                lower = stripped.lower()
                for kw, c in SECTION_COLORS.items():
                    if kw in lower:
                        color = c
                        break
                # Bold **markers**
                if stripped.startswith("**") and stripped.endswith("**"):
                    blocks.append(html.P(stripped.replace("**", ""),
                                         style={"color": color, "fontWeight": "bold",
                                                "marginBottom": "2px", "fontSize": "13px"}))
                else:
                    blocks.append(html.P(stripped.lstrip("- "),
                                         style={"color": color, "marginBottom": "2px",
                                                "fontSize": "12px", "paddingLeft": "8px"}))
    return blocks


# ──────────────────────────────────────────────────────────────────────────────
# Layout
# ──────────────────────────────────────────────────────────────────────────────
def wargame_tab():
    host_options = []
    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        neo = Neo4jEngine()
        results = neo.query("MATCH (h:Host) RETURN coalesce(h.host, h.ip, h.name) AS ip LIMIT 200")
        if results:
            host_options = [{"label": str(r["ip"]), "value": str(r["ip"])}
                            for r in results if r.get("ip")]
            host_options.sort(key=lambda x: x["label"])
    except Exception:
        pass

    legend = dbc.Row([
        dbc.Col(dbc.Badge("🔴 Red Team Attack",       color="danger",   className="me-1")),
        dbc.Col(dbc.Badge("🔵 Blue Team Defence",     color="primary",  className="me-1")),
        dbc.Col(dbc.Badge("⚡ Breach (Red wins)",      color="danger",   className="me-1")),
        dbc.Col(dbc.Badge("🛡 Defended (Blue wins)",   color="success",  className="me-1")),
        dbc.Col(dbc.Badge("🎯 MITRE ATT&CK",          color="warning",  text_color="dark", className="me-1")),
        dbc.Col(dbc.Badge("💎 Crown Jewel Target",    color="info",     className="me-1")),
    ], className="mb-3 flex-wrap")

    return dbc.Container([
        html.H3("⚔️ AI Wargame Simulator", className="text-warning mb-2"),
        html.P(
            "Challenge the AI to evaluate an attack path between two hosts against "
            "simulated defensive responses based on environment data.",
            className="text-light mb-3"
        ),

        dbc.Row([
            dbc.Col([
                html.Label("Source Host (Attacker)"),
                dcc.Dropdown(id="wg-source", options=host_options, placeholder="Select source IP…"),
            ], width=4),
            dbc.Col([
                html.Label("Target Host (Crown Jewel)"),
                dcc.Dropdown(id="wg-target", options=host_options, placeholder="Select target IP…"),
            ], width=4),
            dbc.Col([
                html.Label("Number of Rounds"),
                dcc.Input(id="wg-rounds", type="number", value=3, min=1, max=20,
                          step=1, className="form-control"),
            ], width=2),
            dbc.Col([
                html.Label(" "),
                html.Div(
                    dbc.Button("▶ Run Wargame Simulation", id="wg-run", color="danger",
                               className="w-100"),
                    style={"marginTop": "8px"}
                ),
            ], width=2),
        ], className="mb-3"),

        html.Hr(),

        # Graph section (hidden until simulation runs)
        html.Div(id="wg-graph-section", style={"display": "none"}, children=[
            html.H4("🗺 Wargame Battle Graph", className="text-warning mb-2"),
            legend,
            dcc.Loading(
                type="circle",
                children=cyto.Cytoscape(
                    id="wg-graph",
                    layout={"name": "dagre", "rankDir": "LR", "nodeSep": 40, "rankSep": 120},
                    style={
                        "width": "100%",
                        "height": "520px",
                        "background-color": "#0a0a0a",
                        "border": "1px solid #ff4444",
                        "borderRadius": "8px",
                        "marginBottom": "20px",
                    },
                    stylesheet=WARGAME_STYLESHEET,
                    elements=[],
                ),
            ),
            # Node tooltip when clicked
            html.Div(id="wg-node-tooltip", className="text-light small mb-3",
                     style={"backgroundColor": "#111", "padding": "8px",
                            "borderRadius": "4px", "minHeight": "30px"}),
            html.Hr(),
        ]),

        # Coloured text output
        html.H4("📋 Round-by-Round Analysis", className="text-warning mb-2",
                id="wg-text-heading", style={"display": "none"}),
        dcc.Loading(
            type="default",
            children=html.Div(id="wg-output", className="mt-2"),
        ),
    ], fluid=True)


# ──────────────────────────────────────────────────────────────────────────────
# Callbacks
# ──────────────────────────────────────────────────────────────────────────────
def register_callbacks(app):

    @app.callback(
        Output("wg-output",        "children"),
        Output("wg-graph",         "elements"),
        Output("wg-graph-section", "style"),
        Output("wg-text-heading",  "style"),
        Input("wg-run",            "n_clicks"),
        State("wg-source",         "value"),
        State("wg-target",         "value"),
        State("wg-rounds",         "value"),
        prevent_initial_call=True,
    )
    def run_simulation(n_clicks, source, target, rounds):
        if not n_clicks:
            raise PreventUpdate

        if not source or not target:
            return ("⚠️ Please select both a Source Host and a Target Host.",
                    [], {"display": "none"}, {"display": "none"})

        rounds = max(1, int(rounds or 3))

        try:
            war_ai.active_chain_override = None
            war_ai.active_env_override   = None

            raw = war_ai.run_match(start=source, target=target, rounds=rounds)

            # Build graph elements
            elements  = _parse_wargame_to_elements(raw, source, target)

            # Render colour-coded text
            text_div  = html.Div(
                _render_coloured_text(raw),
                style={"maxHeight": "600px", "overflowY": "auto",
                       "backgroundColor": "#0d0d0d", "borderRadius": "6px",
                       "padding": "12px", "border": "1px solid #333"}
            )

            show = {"display": "block"}
            return text_div, elements, show, show

        except Exception as e:
            msg = f"❌ Error running wargame simulation:\n{e}"
            return html.Pre(msg, style={"color": "#ff6666"}), [], {"display": "none"}, {"display": "none"}

    # Node click tooltip
    @app.callback(
        Output("wg-node-tooltip", "children"),
        Input("wg-graph",         "tapNodeData"),
        prevent_initial_call=True,
    )
    def node_tooltip(data):
        if not data:
            return ""
        ntype = data.get("type", "")
        label = data.get("label", "")
        color_map = {
            "attacker":     "#ff6633",
            "target":       "#33aaff",
            "red":          "#ff5522",
            "blue":         "#2288ff",
            "round":        "#aaaaaa",
            "outcome_red":  "#ff2222",
            "outcome_blue": "#22ff66",
            "mitre":        "#ffaa22",
        }
        color = color_map.get(ntype, "#ccc")
        return html.Span(label, style={"color": color, "fontWeight": "bold"})
