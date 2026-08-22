# ==============================================================
# ui_digital_twin.py — FINAL DASH-SAFE DIGITAL TWIN UI
# ==============================================================

from dash import html, dcc, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

from cyber_range.services.digital_twin import DigitalTwin
from cyber_range.services.simulation_engine import engine

dt = DigitalTwin()
cyto.load_extra_layouts()


# ==============================================================
# DIGITAL TWIN TAB
# ==============================================================
def digital_twin_tab():
    return dbc.Container(
        [
            html.H3("🌐 Digital Twin — Network Intelligence", className="text-warning mb-3"),

            dbc.Button("Refresh Model", id="dt-refresh", color="primary", className="mb-3"),

            html.Div(id="dt-summary", className="text-light mb-4"),

            html.Hr(),
            html.H4("Environment Modifiers", className="text-info"),
            dbc.Row([
                dbc.Col([
                    html.Label("Defense Strength", className="text-light"),
                    dcc.Slider(id="dt-defense", min=0.0, max=2.0, step=0.1, value=engine.environment["defense_strength"], marks={0: '0x', 1: '1x', 2: '2x'}),
                ], width=4),
                dbc.Col([
                    html.Label("Visibility", className="text-light"),
                    dcc.Slider(id="dt-visibility", min=0.0, max=2.0, step=0.1, value=engine.environment["visibility"], marks={0: '0x', 1: '1x', 2: '2x'}),
                ], width=4),
                dbc.Col([
                    html.Label("Network Segmentation", className="text-light"),
                    dcc.Slider(id="dt-segmentation", min=0.0, max=2.0, step=0.1, value=engine.environment["segmentation"], marks={0: '0x', 1: '1x', 2: '2x'}),
                ], width=4),
            ]),
            html.Div(id="dt-env-output", className="text-success mt-2 mb-3"),

            html.Hr(),

            cyto.Cytoscape(
                id="dt-graph",
                layout={"name": "cose"},
                style={"width": "100%", "height": "600px"},
                elements=[],
                stylesheet=[
                    {
                        "selector": "node",
                        "style": {
                            "content": "data(label)",
                            "background-color": "#2ECC71",
                            "color": "white",
                            "font-size": "12px",
                            "text-outline-width": 2,
                            "text-outline-color": "#000",
                        },
                    },
                    {
                        "selector": "edge",
                        "style": {
                            "line-color": "#999",
                        },
                    },
                ],
            ),

            html.Hr(),

            html.H4("Asset Intelligence Panel", className="text-info"),
            html.Div(id="dt-asset-details", className="p-3 text-light"),

            html.Hr(),

            html.H4("Propagation Simulation", className="text-warning"),

            dcc.Input(
                id="dt-start",
                placeholder="Start Asset (ex: 192.168.1.10)",
                style={"width": "300px"},
            ),

            html.Label("Hop Depth", className="text-light mt-2"),

            dcc.Slider(
                id="dt-depth",
                min=1,
                max=10,
                value=3,
                marks={i: str(i) for i in range(1, 11)},
            ),

            dbc.Button("Simulate Propagation", id="dt-propagate", color="secondary", className="mt-2"),

            dcc.Store(id="dt-propagation-state"),
            dcc.Interval(id="dt-timer", interval=1200, disabled=True),

            html.Div(id="dt-propagation-output", className="text-light mt-3"),
            html.Div(id="dt-narrative", className="text-info mt-3"),
        ],
        fluid=True,
    )


# ==============================================================
# CALLBACKS
# ==============================================================
def register_callbacks(app):

    # ----- SUMMARY -----
    @app.callback(Output("dt-summary", "children"), Input("dt-refresh", "n_clicks"))
    def refresh_summary(_):
        s = dt.summary()
        return html.Div([
            html.P(f"Assets: {s['assets']}"),
            html.P(f"Services: {s['services']}"),
            html.P(f"Vulnerabilities: {s['vulns']}"),
        ])

    # ----- ENVIRONMENT MODIFIERS -----
    @app.callback(
        Output("dt-env-output", "children"),
        Input("dt-defense", "value"),
        Input("dt-visibility", "value"),
        Input("dt-segmentation", "value"),
        prevent_initial_call=False
    )
    def update_env(defense, visibility, segmentation):
        engine.update_environment(defense, visibility, segmentation)
        return f"Global target environment updated: DEF={defense:.1f}x, VIS={visibility:.1f}x, SEG={segmentation:.1f}x"

    # ----- ASSET PANEL -----
    @app.callback(Output("dt-asset-details", "children"), Input("dt-graph", "tapNodeData"))
    def asset_panel(node):
        if not node:
            return "Click a node to load intelligence."

        host = node.get("label")
        epss_data, kev_cves, mitre = dt.asset_risk(host)

        # ── EPSS section ─────────────────────────────────────────────────
        if epss_data:
            max_epss = max(s for _, s in epss_data)
            epss_header = html.Div([
                html.Span("Max EPSS: ", className="text-muted"),
                html.Span(
                    f"{max_epss:.4f}",
                    style={"color": "#ff4444" if max_epss >= 0.5
                                    else "#ffa500" if max_epss >= 0.1
                                    else "#aaa",
                           "fontWeight": "bold"}
                ),
                html.Span(f"  ({max_epss*100:.1f}th percentile risk)", className="text-muted small"),
            ], className="mb-1")
            top5 = epss_data[:5]
            epss_badges = html.Div([
                dbc.Badge(
                    f"{cve}  {score:.4f}",
                    color="danger" if score >= 0.5 else "warning" if score >= 0.1 else "secondary",
                    className="me-1 mb-1",
                    style={"fontSize": "0.75rem"}
                )
                for cve, score in top5 if score > 0
            ] or [html.Span("No EPSS scores (CVEs may be unpublished)", className="text-muted small")],
                className="mb-2"
            )
        else:
            epss_header = html.P("EPSS: No CVE data found for this host.", className="text-muted")
            epss_badges = html.Div()

        # ── KEV section ──────────────────────────────────────────────────
        if kev_cves:
            kev_section = html.Div([
                html.Span("⚠ CISA KEV: ", className="text-danger fw-bold"),
                *[dbc.Badge(c, color="danger", className="me-1", style={"fontSize": "0.75rem"})
                  for c in kev_cves],
            ], className="mb-2")
        else:
            kev_section = html.P("✅ Not in CISA Known Exploited Vulnerabilities", className="text-success mb-2 small")

        # ── MITRE section ────────────────────────────────────────────────
        if mitre:
            mitre_section = html.Div([
                html.P("🎯 MITRE ATT&CK Techniques:", className="text-warning mb-1 small fw-bold"),
                html.Div([
                    dbc.Badge(t, color="warning", text_color="dark", className="me-1 mb-1",
                              style={"fontSize": "0.72rem"})
                    for t in mitre
                ])
            ], className="mb-2")
        else:
            mitre_section = html.P("No MITRE data matched (check vuln names in Neo4j)", className="text-muted small mb-2")

        return html.Div([
            html.H5(host, className="text-warning mb-2"),
            html.Hr(className="my-2"),
            epss_header,
            epss_badges,
            kev_section,
            mitre_section,
        ])


    # ----- START PROPAGATION (STATE ONLY) -----
    @app.callback(
        Output("dt-propagation-state", "data"),
        Output("dt-timer", "disabled", allow_duplicate=True),
        Input("dt-propagate", "n_clicks"),
        State("dt-start", "value"),
        State("dt-depth", "value"),
        prevent_initial_call=True,
    )
    def start_propagation(_, start, depth):
        if not start:
            return None, True
        return dt.propagate(start, depth), False

    # ----- SINGLE GRAPH OWNER CALLBACK -----
    @app.callback(
        Output("dt-graph", "elements"),
        Output("dt-propagation-output", "children"),
        Output("dt-narrative", "children"),
        Output("dt-timer", "disabled"),
        Input("dt-refresh", "n_clicks"),
        Input("dt-timer", "n_intervals"),
        Input("dt-propagation-state", "data"),
        State("dt-graph", "elements"),
        State("dt-start", "value"),
        prevent_initial_call=True,
    )
    def graph_controller(_, step, state, elements, start):
        trigger = callback_context.triggered[0]["prop_id"].split(".")[0]

        # ---- Refresh graph ----
        if trigger == "dt-refresh":
            return dt.build_graph_elements(), "", "", True

        # ---- No propagation ----
        if not state:
            return elements, "", "", True

        # ---- Normalize step (FIXES NoneType >= int ERROR) ----
        current_step = step if isinstance(step, int) else 0
        max_step = max(state.values()) if state else 0

        predicted = dt.predict_next(start)

        for el in elements:
            label = el.get("data", {}).get("label")

            if label in state and state[label] == current_step:
                el["style"] = {"background-color": "#FF4500"}

            if label == predicted:
                el.setdefault("style", {})
                el["style"]["border-color"] = "#00FFFF"
                el["style"]["border-width"] = "4px"

        done = current_step >= max_step
        narrative = dt.narrative(start, state, [], predicted)

        return (
            elements,
            html.Ul([html.Li(f"{h} (hop {d})") for h, d in state.items()]),
            narrative,
            done,
        )


print("[ui_digital_twin] Loaded — FINAL error-free Digital Twin UI.")
