# cyber_range/ui/ui_mitre_matrix.py
# UI FOR LM ↔ MITRE CORRELATION MATRIX (ULTRA MODE)

from dash import html, dcc
import dash_bootstrap_components as dbc

from cyber_range.ui.matrix_view import (
    map_lm_to_mitre,
    render_matrix,
    LM_STAGES
)

# =====================================================================
# MAIN LAYOUT FOR TAB
# =====================================================================

def ui_mitre_matrix_layout(chain):
    """
    Build the MITRE correlation matrix tab UI.

    Parameters:
        chain (dict): Full kill chain dict containing LM_KillChain and MITRE_Chain.

    Returns:
        dbc.Container: The correlation matrix UI.
    """

    if not chain:
        return html.Div("No kill chain data available.", className="text-danger mt-4")

    lm_chain = chain.get("LM_KillChain", {})
    mitre_chain = chain.get("MITRE_Chain", [])

    matrix = map_lm_to_mitre(lm_chain, mitre_chain)

    return dbc.Container([
        html.H2("LM Kill Chain ↔ MITRE ATT&CK Correlation Matrix", className="text-warning mt-4"),

        html.P(
            """
            This matrix shows a research-grade correlation between Lockheed Martin Kill Chain 
            stages and MITRE ATT&CK tactics. It provides a cross-framework understanding of 
            adversary behavior by mapping high-level intrusion stages to specific ATT&CK tactics 
            and techniques used by real-world threat actors.
            """,
            className="text-light"
        ),

        html.P(
            """
            Each colored dot represents a MITRE ATT&CK technique discovered in the target 
            environment. Colors correspond to severity based on CVSS, EPSS, KEV status, and 
            exploitability. Hover over any dot to view the technique name.
            """,
            className="text-light"
        ),

        html.Hr(),

        # -----------------------
        # LEGEND
        # -----------------------
        build_matrix_legend(),

        html.Br(),

        # -----------------------
        # MATRIX RENDER
        # -----------------------
        render_matrix(matrix),

        html.Br(), html.Hr(),

        html.H4("Methodology", className="text-warning"),
        html.P(
            """
            Technique-to-stage assignments use a hybrid mapping approach:
              1) ATT&CK tactic semantics (e.g., 'Discovery' → Reconnaissance)
              2) Exploit chain context (e.g., Privilege Escalation used during Exploitation)
              3) Empirical correlations from ATT&CK Enterprise documentation
              4) Analytical heuristic mapping for unknown or new techniques

            This approach provides strong academic justification for cross-model mapping 
            used in adversary simulation, incident response analysis, and cyber threat 
            intelligence research.
            """,
            className="text-light"
        ),

        html.Br()
    ], fluid=True)


# =====================================================================
# MATRIX LEGEND
# =====================================================================

def build_matrix_legend():
    """
    Build a color legend for matrix severity dots.
    """

    dot_style = lambda color: html.Div(
        style={
            "width": "18px",
            "height": "18px",
            "backgroundColor": color,
            "borderRadius": "50%",
            "display": "inline-block",
            "marginRight": "10px"
        }
    )

    return dbc.Row([
        dbc.Col([
            html.Div([
                html.H5("Severity Legend", className="text-warning"),
                html.Div([dot_style("#ff4d4d"), html.Span("Critical (KEV)", className="text-light")]),
                html.Div([dot_style("#ff944d"), html.Span("High", className="text-light")]),
                html.Div([dot_style("#ffd24d"), html.Span("Medium", className="text-light")]),
                html.Div([dot_style("#6c9cff"), html.Span("Low", className="text-light")]),
                html.Div([dot_style("#aaaaaa"), html.Span("Unknown", className="text-light")]),
            ])
        ], width=4)
    ])
