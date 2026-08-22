# ui_honeypot.py

from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
from cyber_range.services.honeypot import HoneypotEngine
from cyber_range.services.simulation_engine import engine

honeypot = HoneypotEngine()

# -------------------------------------------------------------
# Layout
# -------------------------------------------------------------
def honeypot_tab():
    # Fetch hosts dynamically from Neo4j
    host_options = []
    try:
        from cyber_range.services.neo4j_engine import Neo4jEngine
        neo = Neo4jEngine()
        results = neo.query("MATCH (h:Host) RETURN h.ip AS ip LIMIT 200")
        if results:
            host_options = [{"label": str(r["ip"]), "value": str(r["ip"])} for r in results if r.get("ip")]
            host_options.sort(key=lambda x: x["label"])
    except Exception:
        pass

    return dbc.Container(
        [
            html.H3("🕵️ Honeypot & Deception Engine", className="text-warning mb-3"),
            dbc.Switch(id="hp-global-toggle", label="Enable Global Active Deception", value=engine.honeypots_active, className="mb-4 text-light"),
            
            dbc.Row([
                dbc.Col([
                    html.Label("Honeypot Name"),
                    dbc.Input(id="hp-name", placeholder="decoy-db", className="mb-2"),
                ], width=4),

                dbc.Col([
                    html.Label("Segment (Optional)"),
                    dbc.Input(id="hp-segment", placeholder="DeceptionNet", className="mb-2"),
                ], width=4),
                
                dbc.Col([
                    html.Label("Attach to Host (Optional)"),
                    dcc.Dropdown(id="hp-asset", options=host_options, placeholder="Select an Asset to link..."),
                ], width=4),
            ]),

            dbc.Button("Deploy Honeypot", id="hp-deploy", color="danger", className="mt-3 mb-4"),

            html.Hr(),

            dbc.Button("List Active Honeypots", id="hp-list", color="primary", className="mb-3"),

            html.Div(id="hp-output", className="text-light mt-3")
        ],
        fluid=True
    )

# -------------------------------------------------------------
# Callbacks
# -------------------------------------------------------------
def register_callbacks(app):

    # Global Toggle
    @app.callback(
        Output("hp-output", "children", allow_duplicate=True),
        Input("hp-global-toggle", "value"),
        prevent_initial_call=True
    )
    def toggle_honeypots(is_active):
        engine.honeypots_active = is_active
        engine.log_event("DEFENSE", f"Global Honeypot Deception Native: {'ENABLED' if is_active else 'DISABLED'}")
        return html.Div(f"Global honeypot active state set to {is_active}.", className="text-warning")

    # Deploy honeypot
    @app.callback(
        Output("hp-output", "children"),
        Input("hp-deploy", "n_clicks"),
        State("hp-name", "value"),
        State("hp-segment", "value"),
        State("hp-asset", "value"),
        prevent_initial_call=True
    )
    def deploy_hp(_, name, segment, asset):
        if not name:
            return html.Div("⚠ Please provide a honeypot name.", className="text-danger")

        hp = honeypot.deploy_honeypot(name, segment or "DeceptionNet")
        msg = f"✔ Honeypot deployed: {hp['name']}"
        
        if asset:
            honeypot.link_to_asset(f"honeypot-{name.lower()}", asset)
            msg += f" (Linked safely to host {asset})"
            
        return html.Div(msg, className="text-success")

    # List honeypots
    @app.callback(
        Output("hp-output", "children", allow_duplicate=True),
        Input("hp-list", "n_clicks"),
        prevent_initial_call=True
    )
    def list_hp(_):
        hps = honeypot.list_honeypots()
        if not hps:
            return html.Div("No honeypots deployed.", className="text-warning")

        items = []
        for h in hps:
            name = h.get("name", "Unknown")
            seg = h.get("segment", "Unknown")
            items.append(html.Li(f"{name} (Segment: {seg})"))
            
        return html.Ul(items)


