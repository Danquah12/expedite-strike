# cyber_range/services/navigator_export.py
# ATT&CK NAVIGATOR JSON LAYER EXPORT (ULTRA MODE)

import json
from datetime import datetime

# Color mapping for Navigator layer
COLOR_MAP = {
    "critical": "#ff4d4d",
    "high": "#ff944d",
    "medium": "#ffd24d",
    "low": "#6c9cff",
    "unknown": "#aaaaaa"
}

# ===============================================================
# DETERMINE SEVERITY (matches other modules)
# ===============================================================

def determine_severity(entry):
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


# ===============================================================
# BUILD TECHNIQUE OBJECT FOR NAVIGATOR
# ===============================================================

def build_navigator_technique(entry):
    tech_id = entry.get("technique")
    tech_name = entry.get("technique_name", tech_id)

    severity = determine_severity(entry)
    color = COLOR_MAP.get(severity, "#AAAAAA")

    # Navigator technique entry
    return {
        "techniqueID": tech_id,
        "tactic": entry.get("tactic_name"),
        "color": color,
        "comment": entry.get("description", "")[:500],  # avoid massive comments
        "enabled": True,
        "metadata": [
            {"name": "Technique Name", "value": tech_name},
            {"name": "Severity", "value": severity},
            {"name": "Platforms", "value": ", ".join(entry.get("platforms", []))},
            {"name": "Data Sources", "value": ", ".join(entry.get("data_sources", []))},
            {"name": "Groups", "value": ", ".join(entry.get("groups", []))}
        ]
    }


# ===============================================================
# EXPORT FULL LAYER
# ===============================================================

def export_navigator_layer(mitre_chain, title="Kill Chain MITRE Layer"):
    """
    Converts enriched MITRE entries into a Navigator layer JSON.
    """

    techniques = [build_navigator_technique(entry) for entry in mitre_chain]

    layer = {
        "version": "4.3",
        "name": title,
        "domain": "enterprise-attack",
        "description": "Layer generated from ULTRA TI Kill Chain System",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff0000"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "Critical (KEV)", "color": COLOR_MAP["critical"]},
            {"label": "High", "color": COLOR_MAP["high"]},
            {"label": "Medium", "color": COLOR_MAP["medium"]},
            {"label": "Low", "color": COLOR_MAP["low"]},
            {"label": "Unknown", "color": COLOR_MAP["unknown"]}
        ],
        "metadata": [
            {"name": "Generated", "value": datetime.now().isoformat()},
            {"name": "Author", "value": "ULTRA Kill Chain System"},
            {"name": "Techniques Count", "value": str(len(techniques))}
        ]
    }

    return json.dumps(layer, indent=2)

