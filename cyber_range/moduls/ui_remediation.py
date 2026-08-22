# ui_remediation.py

from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
from cyber_range.services.remediation_ai import RemediationAI
from cyber_range.services.neo4j_engine import Neo4jEngine

rem = RemediationAI()
neo = Neo4jEngine()

# -------------------------------------------------------------
# Layout
# -------------------------------------------------------------
def remediation_tab():
    return dbc.Container(
        [
            html.H3("🛠️ Automated Remediation & Hardening AI", className="text-warning mb-4"),

            # --- Blast Radius + Fix Recommendation ---
            html.H4("Fix Single Vulnerability", className="text-warning"),
            dbc.Row([
                dbc.Col([
                    html.Label("Select Vulnerability Node"),
                    dcc.Dropdown(id="rm-vuln", placeholder="Choose vulnerability…")
                ], width=8),

                dbc.Col([
                    dbc.Button("Generate Remediation Plan",
                               id="rm-fix-btn",
                               color="primary",
                               className="mt-4")
                ], width=4),
            ], className="mb-4"),

            html.Div(id="rm-fix-output",
                     className="text-light mt-3"),

            html.Hr(),

            # --- Prioritization ---
            html.H4("Prioritize Multiple CVEs", className="text-warning mt-3"),
            dcc.Textarea(
                id="rm-priority-list",
                placeholder="Enter CVEs separated by commas (e.g., CVE-2023-1234, CVE-2024-5678)",
                style={"width": "100%", "height": "100px"},
                className="mb-3"
            ),

            dbc.Button("Prioritize Vulnerabilities",
                       id="rm-priority-btn",
                       color="danger"),

            html.Div(id="rm-priority-output",
                     className="text-light mt-3"),

            html.Hr(),

            # --- System hardening ---
            html.H4("Hardening Checklist (per Asset)", className="text-warning mt-3"),

            dbc.Row([
                dbc.Col([
                    html.Label("Asset Node ID"),
                    dcc.Input(id="rm-asset", placeholder="asset-001", className="mb-2")
                ], width=6),

                dbc.Col([
                    dbc.Button("Generate Hardening Plan",
                               id="rm-harden-btn",
                               color="secondary",
                               className="mt-4")
                ], width=6),
            ]),

            html.Div(id="rm-harden-output",
                     className="text-light mt-3")
        ],
        fluid=True
    )

# -------------------------------------------------------------
# Callbacks
# -------------------------------------------------------------
def register_callbacks(app):

    # -----------------------------------------------------------------
    # Populate vulnerability dropdown dynamically from Neo4j graph
    # -----------------------------------------------------------------
    @app.callback(
        Output("rm-vuln", "options"),
        Input("neo4j-graph", "elements"),
        prevent_initial_call=False
    )
    def populate_vulns(elements):
        if not elements:
            return []

        vulns = []
        seen = set()

        for el in elements:
            if "data" not in el:
                continue
            d = el["data"]

            lbl = d.get("type", "").lower()

            # Only vulnerability nodes
            if "vuln" in lbl or "vulnerability" in lbl:
                nid = d["id"]
                name = d.get("label", nid)
                if nid not in seen:
                    seen.add(nid)
                    vulns.append({"label": name, "value": nid})

        return vulns

    # -----------------------------------------------------------------
    # Fix Single Vulnerability (AI Plan)
    # -----------------------------------------------------------------
    @app.callback(
        Output("rm-fix-output", "children"),
        Input("rm-fix-btn", "n_clicks"),
        State("rm-vuln", "value"),
        prevent_initial_call=True
    )
    def fix_single(_, vuln_id):
        if not vuln_id:
            return "⚠ Please select a vulnerability."

        plan = rem.fix_vulnerability(vuln_id)

        return html.Pre(
            plan,
            style={"whiteSpace": "pre-wrap", "color": "#ffddaa", "fontSize": "14px"}
        )

    # -----------------------------------------------------------------
    # Prioritization of Multiple CVEs
    # -----------------------------------------------------------------
    @app.callback(
        Output("rm-priority-output", "children"),
        Input("rm-priority-btn", "n_clicks"),
        State("rm-priority-list", "value"),
        prevent_initial_call=True
    )
    def prioritize(_, text):
        if not text:
            return "⚠ Enter at least one CVE."

        cves = [c.strip() for c in text.split(",") if c.strip()]
        result = rem.prioritize_vulns(cves)

        return html.Pre(
            result,
            style={"whiteSpace": "pre-wrap", "color": "#ffcccc", "fontSize": "14px"}
        )

    # -----------------------------------------------------------------
    # Hardening Recommendations
    # -----------------------------------------------------------------
    @app.callback(
        Output("rm-harden-output", "children"),
        Input("rm-harden-btn", "n_clicks"),
        State("rm-asset", "value"),
        prevent_initial_call=True
    )
    def harden(_, asset_id):
        if not asset_id:
            return "⚠ Enter an asset ID."

        checklist = rem.harden_system(asset_id)

        return html.Pre(
            checklist,
            style={"whiteSpace": "pre-wrap", "color": "#ccffcc", "fontSize": "14px"}
        )
