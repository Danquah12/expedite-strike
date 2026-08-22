# cyber_range/services/color_severity.py
# GLOBAL SEVERITY CALCULATION ENGINE (ULTRA MODE)

"""
This module provides unified threat severity scoring for:
- MITRE ATT&CK techniques
- LM Kill Chain correlations
- Matrix heatmaps
- MITRE Viewer severity dots
- Navigator JSON export
- Technique cards
- PDF visualization

Using a global severity engine ensures:
• academic reproducibility
• consistent scoring across modules
• transparent methodology for PhD-level work
• unified risk metrics for dashboards + exports
"""

# ======================================================================
# WEIGHT PARAMETERS (ADJUSTABLE FOR RESEARCH)
# ======================================================================

WEIGHTS = {
    "cvss_high": 8.0,
    "cvss_medium": 6.0,
    "epss_high": 0.5,
    "epss_medium": 0.2,
    "kev_weight": 5,          # KEV overrides nearly everything
    "exploit_true_weight": 2, # Exploitable flag
}

# ======================================================================
# COLOR MAP (GLOBAL)
# ======================================================================

COLOR_MAP = {
    "critical": "#ff4d4d",
    "high": "#ff944d",
    "medium": "#ffd24d",
    "low": "#6c9cff",
    "unknown": "#aaaaaa"
}

# ======================================================================
# MAIN SEVERITY ENGINE
# ======================================================================

def compute_severity(entry):
    """
    Returns ("critical" | "high" | "medium" | "low" | "unknown")
    Based on CVSS, EPSS, KEV, and exploitability.
    """

    if not entry:
        return "unknown"

    kev = entry.get("kev", False)
    cvss = float(entry.get("cvss", 0))
    epss = float(entry.get("epss", 0))
    exploitable = entry.get("exploitable", False)

    # KEV entries are ALWAYS critical
    if kev:
        return "critical"

    # Exploitable flag makes it at least high
    if exploitable and cvss >= WEIGHTS["cvss_medium"]:
        return "high"

    # High severity thresholds
    if cvss >= WEIGHTS["cvss_high"] or epss >= WEIGHTS["epss_high"]:
        return "high"

    # Medium severity thresholds
    if cvss >= WEIGHTS["cvss_medium"] or epss >= WEIGHTS["epss_medium"]:
        return "medium"

    # Low severity baseline
    if cvss > 0:
        return "low"

    return "unknown"


# ======================================================================
# COLOR LOOKUP
# ======================================================================

def severity_color(entry):
    """
    Returns color hex code for severity.
    """
    sev = compute_severity(entry)
    return COLOR_MAP.get(sev, COLOR_MAP["unknown"])


# ======================================================================
# SCORE (0–100)
# ======================================================================

def severity_score(entry):
    """
    Returns a 0–100 normalized numerical severity score
    for export, PDF, academic analysis, or Navigator gradient.
    """

    if not entry:
        return 0

    cvss = float(entry.get("cvss", 0))
    epss = float(entry.get("epss", 0))
    kev = entry.get("kev", False)

    score = 0

    # CVSS contributes up to 50 points
    score += (cvss / 10) * 50

    # EPSS contributes up to 30 points
    score += epss * 30

    # KEV contributes up to 20 points
    if kev:
        score += 20

    return min(100, max(0, round(score)))


# ======================================================================
# EXPORT UTILS
# ======================================================================

def enrich_entry_with_severity(entry):
    """
    Adds global severity fields to an entry:
       severity: "high"
       severity_color: "#FF..."
       severity_score: 82
    """
    if not entry:
        return entry

    sev = compute_severity(entry)
    entry["severity"] = sev
    entry["severity_color"] = COLOR_MAP.get(sev)
    entry["severity_score"] = severity_score(entry)
    return entry
