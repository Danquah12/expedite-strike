from dash import html, dcc
from exploit_llm_engine.reasoning.risk_indicators import verdict_to_traffic_light


def main_tab_layout():
    """
    Main dashboard tab combining executive and analyst views.
    """

    return html.Div(
        [
            html.H2("Vulnerability Intelligence Dashboard"),

            # --- CVE selector (can be asset-based later) ---
            dcc.Input(
                id="cve-input",
                type="text",
                placeholder="Enter CVE ID (e.g., CVE-2021-41773)",
                style={"width": "300px"}
            ),

            html.Button(
                "Analyze",
                id="analyze-button",
                n_clicks=0,
                style={"marginLeft": "10px"}
            ),

            html.Hr(),

            # --- Traffic light ---
            html.Div(id="risk-indicator"),

            html.Hr(),

            # --- Executive Summary ---
            html.H3("Executive Summary"),
            html.Pre(id="executive-summary"),

            html.Hr(),

            # --- Affected Hosts ---
            html.H3("Affected Lab Systems"),
            html.Ul(id="affected-hosts"),

            html.Hr(),

            # --- Change Detection ---
            html.H3("Change Since Last Assessment"),
            html.Div(id="change-detection"),

            html.Hr(),

            # --- Technical Appendix ---
            html.Details(
                [
                    html.Summary("Technical Appendix (Click to Expand)"),
                    html.Pre(id="technical-appendix")
                ]
            ),
        ],
        style={"padding": "20px"}
    )
