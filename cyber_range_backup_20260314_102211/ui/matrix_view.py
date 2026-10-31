# cyber_range/ui/matrix_view.py
# LM KILL CHAIN ↔ MITRE ATT&CK CORRELATION MATRIX (ULTRA MODE)

from dash import html, dcc
import dash_bootstrap_components as dbc

# Shared severity colors (matches mitre_viewer + heatmap)
COLOR_MAP = {
    "critical": "#ff4d4d",
    "high": "#ff944d",
    "medium": "#ffd24d",
    "low": "#6c9cff",
    "unknown": "#aaaaaa"
}

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
# DETERMINE SEVERITY FOR MATRIX CELL COLORING
# =====================================================================

def compute_severity(entry):
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
# BUILD THE MATRIX MAP
# =====================================================================

def map_lm_to_mitre(lm_chain, mitre_chain):
    """
    Produces a dict:
    {
        "Reconnaissance": {
             "Discovery": [technique objects...],
             "Execution": [technique objects...]
        },
        ...
    }
    """
    matrix = {stage: {} for stage in LM_STAGES}

    # Flatten LM chain nodes into a searchable set of node IDs
    lm_nodes = set()
    for stage, items in lm_chain.items():
        if isinstance(items, list):
            for node in items:
                if isinstance(node, dict):
                    nid = node.get("id")
                    if nid is not None:
                        lm_nodes.add(nid)

    # Map MITRE techniques to LM stages based on relevance
    for entry in mitre_chain:
        tactic = entry.get("tactic_name", entry.get("tactic", "Unknown"))
        technique = entry.get("technique_name", entry.get("technique"))

        # Default stage mapping (approximate)
        stage_map = guess_lm_stage_from_tactic(tactic)

        if stage_map:
            matrix.setdefault(stage_map, {})
            matrix[stage_map].setdefault(tactic, [])
            matrix[stage_map][tactic].append(entry)

    return matrix


# =====================================================================
# SIMPLE LM ↔ MITRE HEURISTIC
# =====================================================================

def guess_lm_stage_from_tactic(tactic):
    """
    Maps MITRE Tactics to LM Kill Chain stages.
    Used academically in correlation research.
    """
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
# MATRIX UI COMPONENT
# =====================================================================

def render_matrix(matrix):
    """
    Renders the LM↔MITRE correlation matrix as a grid of cards.
    """

    rows = []

    # Header Row
    header = dbc.Row(
        [
            dbc.Col(html.B("Kill Chain Stage"), width=2)
        ] +
        [
            dbc.Col(html.B(tactic), width=2)
            for tactic in sorted(get_all_tactics(matrix))
        ],
        className="border-bottom py-2 bg-dark text-white"
    )
    rows.append(header)

    # Body Rows
    for stage in LM_STAGES:
        row_cells = [dbc.Col(html.B(stage), width=2, className="bg-secondary text-light")]

        for tactic in sorted(get_all_tactics(matrix)):
            tech_list = matrix.get(stage, {}).get(tactic, [])
            cell = build_matrix_cell(tech_list)
            row_cells.append(dbc.Col(cell, width=2))

        row = dbc.Row(row_cells, className="border-bottom py-2")
        rows.append(row)

    return html.Div(rows, className="p-3 bg-dark text-light rounded mt-4")


# =====================================================================
# EXTRACT UNIQUE TACTICS
# =====================================================================

def get_all_tactics(matrix):
    tactics = set()
    for stage in matrix.values():
        for tactic in stage.keys():
            tactics.add(tactic)
    return tactics


# =====================================================================
# BUILD EACH CELL
# =====================================================================

def build_matrix_cell(tech_list):
    """
    A cell can contain several techniques.
    We cluster them into colored dots with tooltips.
    """

    if not tech_list:
        return html.Div("-", className="text-muted text-center")

    dots = []

    for entry in tech_list:
        sev = compute_severity(entry)
        color = COLOR_MAP.get(sev, "#999")

        dot = html.Div(
            style={
                "width": "14px",
                "height": "14px",
                "backgroundColor": color,
                "borderRadius": "50%",
                "display": "inline-block",
                "margin": "3px",
                "cursor": "pointer"
            },
            title=f"{entry.get('technique_name', entry.get('technique'))}"
        )
        dots.append(dot)

    return html.Div(dots)


# =====================================================================
# MAIN LAYOUT FOR NEW TAB
# =====================================================================

def matrix_view_layout(chain):
    if not chain:
        return html.Div("No chain data available.", className="text-danger")

    lm_chain = chain.get("LM_KillChain", {})
    mitre_chain = chain.get("MITRE_Chain", [])

    matrix = map_lm_to_mitre(lm_chain, mitre_chain)

    return dbc.Container([
        html.H2("LM Kill Chain ↔ MITRE ATT&CK Correlation Matrix", className="text-warning mt-4"),
        html.P(
            "This matrix visualizes the relationship between Lockheed Martin Kill Chain "
            "stages and MITRE ATT&CK Tactics, providing a cross-framework analytical map."
        ),
        render_matrix(matrix)
    ], fluid=True)
