# ui_ti_feed.py
from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
from cyber_range.services.ti_feed import ThreatIntelFeed
from cyber_range.services.neo4j_engine import Neo4jEngine

ti = ThreatIntelFeed()
neo = Neo4jEngine()

# -------------------------------------------------------------
# Layout
# -------------------------------------------------------------
def ti_feed_tab():
    return dbc.Container(
        [
            html.H3("🌐 Threat Intelligence Feeds", className="text-warning mb-4"),

            dbc.Button("Update All Threat Feeds (KEV + EPSS)", 
                       id="ti-update", 
                       color="danger", 
                       className="mb-3"),

            html.Div(id="ti-update-output", className="text-light mb-4"),

            html.Hr(),

            html.H4("AI CVE Enrichment", className="text-warning"),

            dbc.Row([
                dbc.Col([
                    html.Label("CVE ID"),
                    dcc.Input(id="ti-cve-input", placeholder="CVE-2023-12345", className="mb-2")
                ], width=6),

                dbc.Col([
                    dbc.Button("Enrich CVE with AI", 
                               id="ti-cve-btn", 
                               color="primary", 
                               className="mt-4")
                ], width=6)
            ], className="mb-3"),

            html.Div(id="ti-cve-output", className="text-light mt-3")
        ],
        fluid=True
    )

# -------------------------------------------------------------
# Callbacks
# -------------------------------------------------------------
def register_callbacks(app):

    # ---------------------------------------------------------
    # Update all TI feeds
    # ---------------------------------------------------------
    @app.callback(
        Output("ti-update-output", "children"),
        Input("ti-update", "n_clicks"),
        prevent_initial_call=True
    )
    def update_feeds(_):
        updated = ti.update_all()

        if not updated:
            return "❌ No TI data updated."

        return html.Div([
            html.P(f"✔ Updated {len(updated)} vulnerabilities from KEV/EPSS."),
            html.P("Neo4j graph now contains fresh threat intel.")
        ], style={"color": "#99ffcc"})

    # ---------------------------------------------------------
    # AI CVE enrichment
    # ---------------------------------------------------------
    @app.callback(
        Output("ti-cve-output", "children"),
        Input("ti-cve-btn", "n_clicks"),
        State("ti-cve-input", "value"),
        prevent_initial_call=True
    )
    def enrich_cve(_, cve_id):
        if not cve_id:
            return "⚠ Please enter a CVE ID."

        result = ti.enrich_cve_ai(cve_id)

        return html.Pre(result, style={
            "whiteSpace": "pre-wrap",
            "color": "#99ccff",
            "fontSize": "14px"
        })

