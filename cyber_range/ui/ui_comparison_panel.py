# cyber_range/ui/ui_comparison_panel.py
# LM ↔ MITRE SIDE-BY-SIDE COMPARISON PANEL (ULTRA MODE)

from dash import html
import dash_bootstrap_components as dbc

from cyber_range.services.color_severity import severity_color, compute_severity

LM_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objective"
]


# =====================================================================
# MAPPING LOGIC (USES SAME HEURISTIC AS MATRIX)
# =====================================================================

def guess_lm_stage_from_tactic(tactic):
    t = tactic.lower()

    if "initial" in t:
        return "Reconnaissance"
    if "execution" in t:
        return "Exploitation"
    if "persistence" in t:
        return "Installation"
    if "privilege" in t:
        return "Exploitation"
    if "defense evasion" in t:
        return "Weaponization"
    if "credential" in t:
        return "Weaponization"
    if "discovery" in t:
        return "Reconnaissance"
    if "lateral" in t:
        return "Delivery"
    if "collection" in t:
        return "Actions on Objective"
    if "exfiltration" in t:
        return "Actions on Objective"
    if "command and control" in t:
        return "Command & Control"

    return "Reconnaissance"


# =====================================================================
# MAP LM → MITRE (DETAIL LEVEL)
# =====================================================================

def build_comparison_map(lm_chain, mitre_chain):
    """
    Produce output format:
    {
        "Reconnaissance": [ enriched MITRE entries ],
        "Exploitation": [...],
        ...
    }
    """
    comp = {stage: [] for stage in LM_STAGES}

    for entry in mitre_chain:
        tactic = entry.get("tactic_name", entry.get("tactic"))
        if not tactic:
            continue

        stage = guess_lm_stage_from_tactic(tactic)
        comp[stage].append(entry)

    return comp


# =====================================================================
# BUILD THE EXPANDABLE CARDS
# =====================================================================

def build_stage_card(stage, entries):
    """
    Renders one LM stage card containing all MITRE techniques mapped to it.
    """

    if not entries:
        body = html.P("No mapped MITRE techniques for this stage.", className="text-muted")
    else:
        body = html.Div([
            build_technique_card(entry) for entry in entries
        ])

    return dbc.Card([
        dbc.CardHeader(html.H4(stage, className="text-warning")),
        dbc.CardBody(body, className="bg-dark text-light")
    ], className="mb-3 border border-warning rounded")


# =====================================================================
# TECHNIQUE CARD (DETAILS)
# =====================================================================

def build_technique_card(entry):
    """
    Provides a detailed breakdown of a single MITRE technique.
    """

    tech_id = entry.get("technique")
    tech_name = entry.get("technique_name", tech_id)

    sev_color = severity_color(entry)
    sev_label = compute_severity(entry).capitalize()

    platforms = ", ".join(entry.get("platforms", [])) or "None"
    data_sources = ", ".join(entry.get("data_sources", [])) or "None"
    groups = ", ".join(entry.get("groups", [])) or "None"

    return dbc.Card([
        dbc.CardHeader([
            html.Span(
                style={
                    "backgroundColor": sev_color,
                    "width": "14px",
                    "height": "14px",
                    "display": "inline-block",
                    "borderRadius": "50%",
                    "marginRight": "10px"
                }
            ),
            html.B(f"{tech_id} — {tech_name}"),
            html.Span(f" ({sev_label})", className="ms-2 text-muted")
        ]),

        dbc.CardBody([
            html.P(entry.get("description", ""), className="fst-italic text-light"),

            html.P(html.B("Platforms: "), className="d-inline"),
            html.Span(platforms),

            html.Br(), html.Br(),

            html.P(html.B("Data Sources: "), className="d-inline"),
            html.Span(data_sources),

            html.Br(), html.Br(),

            html.P(html.B("APT Groups: "), className="d-inline"),
            html.Span(groups),

            html.Br(), html.Br(),

            html.P(html.B("Mitigations:"), className="mt-2"),
            html.Ul([html.Li(m) for m in entry.get("mitigations", [])] or html.Li("None")),

            html.P(html.B("Detection Guidance:"), className="mt-2"),
            html.Ul([html.Li(d) for d in entry.get("detection", [])] or html.Li("None")),

            html.P(html.B("External References:"), className="mt-2"),
            html.Ul([
                html.Li(html.A(ref.get("url"), href=ref.get("url"), target="_blank"))
                for ref in entry.get("external_refs", [])
            ] or [html.Li("None")])
        ], className="bg-dark text-light")
    ], className="mb-3 bg-secondary rounded")


# =====================================================================
# MAIN COMPARISON PANEL LAYOUT
# =====================================================================

def comparison_panel_layout(chain):
    """
    Renders the LM ↔ MITRE comparison tab.
    """

    if not chain:
        return html.Div("No kill chain data available.", className="text-danger mt-4")

    lm_chain = chain.get("LM_KillChain", {})
    mitre_chain = chain.get("MITRE_Chain", [])

    comparison = build_comparison_map(lm_chain, mitre_chain)

    return html.Div([
        html.H2("LM Kill Chain ↔ MITRE ATT&CK Comparison Panel", className="text-warning mt-4"),

        html.P(
            """
            This panel provides a side-by-side analytical comparison of Lockheed Martin Kill Chain 
            stages and the specific MITRE ATT&CK techniques associated with each stage in this 
            intrusion. Each stage is shown with the corresponding techniques, their descriptions, 
            platforms, data sources, APT associations, detection guidance, and mitigations.
            """,
            className="text-light"
        ),

        html.Hr(),

        # Build each stage card
        html.Div([
            build_stage_card(stage, comparison.get(stage, []))
            for stage in LM_STAGES
        ])
    ])
