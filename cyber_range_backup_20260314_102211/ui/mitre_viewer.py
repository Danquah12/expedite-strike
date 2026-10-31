# cyber_range/ui/mitre_viewer.py
# MITRE ATT&CK INTELLIGENCE VIEWER (ULTRA MODE)

import json
from dash import html, dcc, Input, Output, State
import dash_bootstrap_components as dbc

# Colors for risk levels (used across the entire Option-8 upgrade)
COLOR_MAP = {
    "critical": "#ff4d4d",
    "high": "#ff944d",
    "medium": "#ffd24d",
    "low": "#6c9cff",
    "unknown": "#aaaaaa"
}

# =====================================================================
# LAYOUT: MITRE ATT&CK VIEWER TAB
# =====================================================================

def mitre_viewer_layout():
    return dbc.Container([
        html.H2("MITRE ATT&CK Intelligence Viewer", className="text-warning mt-4"),

        # --------------------
        # SEARCH / FILTER BAR
        # --------------------
        dbc.Row([
            dbc.Col([
                dcc.Input(
                    id="mitre-search",
                    placeholder="Search techniques (e.g., T1059, PowerShell)...",
                    type="text",
                    className="form-control",
                )
            ], width=4),

            dbc.Col([
                dcc.Dropdown(
                    id="mitre-tactic-filter",
                    placeholder="Filter by Tactic",
                    multi=False,
                    className="text-dark"
                )
            ], width=3),

            dbc.Col([
                dcc.Dropdown(
                    id="mitre-platform-filter",
                    placeholder="Filter by Platform",
                    multi=True,
                    className="text-dark"
                )
            ], width=3),

            dbc.Col([
                dbc.Button(
                    "Export JSON",
                    id="mitre-export-json",
                    color="primary",
                    className="w-100"
                )
            ], width=2)
        ], className="mt-3 mb-4"),

        # --------------------
        # RESULTS TABLE
        # --------------------
        html.Div(id="mitre-table-container"),

        # --------------------
        # DETAIL PANEL
        # --------------------
        html.Hr(className="mt-4"),
        html.H3("Technique Details"),
        html.Div(id="mitre-detail-panel", className="p-3 border rounded bg-dark text-light")

    ], fluid=True)


# =====================================================================
# BUILD TABLE OF TECHNIQUES
# =====================================================================

def build_mitre_table(mitre_chain):
    """
    Takes the enriched MITRE technique list, returns table UI.
    """

    if not mitre_chain:
        return html.Div("No MITRE techniques available.", className="text-muted")

    rows = []

    for entry in mitre_chain:
        tech_id = entry.get("technique")
        tech_name = entry.get("technique_name", tech_id)
        tactic = entry.get("tactic_name", entry.get("tactic"))
        platforms = ", ".join(entry.get("platforms", []))

        severity = get_mitre_severity(entry)
        color = COLOR_MAP.get(severity, "#999")

        row = dbc.Row([
            dbc.Col(html.Button(
                f"{tech_id} — {tech_name}",
                id={"type": "mitre-row", "tech": tech_id},
                n_clicks=0,
                className="btn btn-link text-light"
            ), width=4),

            dbc.Col(tactic, width=3),
            dbc.Col(platforms, width=3),
            dbc.Col(html.Div(style={
                "width": "15px",
                "height": "15px",
                "backgroundColor": color,
                "borderRadius": "50%"
            }), width=2)

        ], className="border-bottom py-2")

        rows.append(row)

    return html.Div(rows, className="bg-secondary p-2 rounded")


# =====================================================================
# SEVERITY HELPER
# =====================================================================

def get_mitre_severity(entry):
    """
    Determine severity for color coding.
    Criteria:
      - KEV present (critical)
      - EPSS > 0.5 or CVSS > 8 (high)
      - EPSS > 0.2 or CVSS > 6 (medium)
    """
    kev = entry.get("kev", False)
    cvss = entry.get("cvss", 0)
    epss = entry.get("epss", 0)

    if kev:
        return "critical"
    if cvss >= 8 or epss >= 0.5:
        return "high"
    if cvss >= 6 or epss >= 0.2:
        return "medium"
    return "low"


# =====================================================================
# DETAILS PANEL
# =====================================================================

def build_detail_panel(entry):
    if not entry:
        return html.Div("Select a technique to view details.", className="text-muted")

    return html.Div([
        html.H4(f"{entry.get('technique')} — {entry.get('technique_name')}"),

        html.P(entry.get("description", ""), className="mb-3"),

        html.H5("Platforms"),
        html.P(", ".join(entry.get("platforms", [])) or "None"),

        html.H5("Data Sources"),
        html.P(", ".join(entry.get("data_sources", [])) or "None"),

        html.H5("Mitigations"),
        html.Ul([html.Li(m) for m in entry.get("mitigations", [])] or "None"),

        html.H5("Detection Guidance"),
        html.Ul([html.Li(d) for d in entry.get("detection", [])] or "None"),

        html.H5("APT Groups"),
        html.P(", ".join(entry.get("groups", [])) or "None"),

        html.H5("External References"),
        html.Ul([
            html.Li(html.A(ref.get("url"), href=ref.get("url"), target="_blank"))
            for ref in entry.get("external_refs", [])
        ] or "None")

    ])


# =====================================================================
# EXPORTER
# =====================================================================

def export_mitre_json(mitre_chain):
    """
    Returns a JSON string the user can download.
    """
    return json.dumps(mitre_chain, indent=2)
