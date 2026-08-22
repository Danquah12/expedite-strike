"""
MITRE ATT&CK Navigator — Mapping & Export Engine
==================================================
Maps AD security findings to MITRE ATT&CK Tactics + Techniques.
Generates ATT&CK Navigator v4.x compatible JSON layers.
"""

import json
import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ── Comprehensive Technique Map ──────────────────────────────────────
TECHNIQUE_MAP = {
    "T1558.003": {"name": "Kerberoasting", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1558.004": {"name": "AS-REP Roasting", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1550.003": {"name": "Pass-the-Ticket / Delegation", "tactic": "lateral-movement", "tactic_id": "TA0008"},
    "T1087.002": {"name": "Account Discovery: Domain", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1069.002": {"name": "Group Discovery: Domain", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1018": {"name": "Remote System Discovery", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1016": {"name": "System Network Config Discovery", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1557.001": {"name": "LLMNR/NBT-NS Poisoning (SMB Relay)", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1110": {"name": "Brute Force / Password Spraying", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1003.006": {"name": "DCSync", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1484.001": {"name": "Group Policy Modification", "tactic": "defense-evasion", "tactic_id": "TA0005"},
    "T1078.002": {"name": "Valid Accounts: Domain", "tactic": "initial-access", "tactic_id": "TA0001"},
    "T1136.002": {"name": "Create Account: Domain", "tactic": "persistence", "tactic_id": "TA0003"},
    "T1222.001": {"name": "File/Dir Permissions Modification", "tactic": "defense-evasion", "tactic_id": "TA0005"},
    "T1649": {"name": "Steal/Forge Auth Certificates (ADCS)", "tactic": "credential-access", "tactic_id": "TA0006"},
    # Network-level techniques
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery", "tactic_id": "TA0007"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access", "tactic_id": "TA0001"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "lateral-movement", "tactic_id": "TA0008"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral-movement", "tactic_id": "TA0008"},
    "T1021.004": {"name": "SSH", "tactic": "lateral-movement", "tactic_id": "TA0008"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution", "tactic_id": "TA0002"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "persistence", "tactic_id": "TA0003"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence", "tactic_id": "TA0003"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1003.002": {"name": "Security Account Manager", "tactic": "credential-access", "tactic_id": "TA0006"},
    "T1003.003": {"name": "NTDS", "tactic": "credential-access", "tactic_id": "TA0006"},
}

SEVERITY_COLORS = {
    "Critical": "#ff0022", "High": "#ff8800",
    "Medium": "#ffc300", "Low": "#22c55e", "Info": "#4287f5",
}

SEVERITY_SCORES = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0,
}


def map_findings_to_attack(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Map findings to MITRE ATT&CK Tactics + Techniques."""
    tactics_covered = set()
    techniques_covered = set()
    technique_details = {}

    for finding in findings:
        mitre_id = finding.get("mitre_id", "")
        if not mitre_id or mitre_id not in TECHNIQUE_MAP:
            continue
        mapping = TECHNIQUE_MAP[mitre_id]
        tactics_covered.add(mapping["tactic"])
        techniques_covered.add(mitre_id)

        if mitre_id not in technique_details:
            technique_details[mitre_id] = {
                "id": mitre_id, "name": mapping["name"],
                "tactic": mapping["tactic"], "tactic_id": mapping["tactic_id"],
                "findings": [],
            }
        technique_details[mitre_id]["findings"].append(finding)

    total_known = len(TECHNIQUE_MAP)
    coverage = (len(techniques_covered) / total_known) * 100 if total_known else 0

    return {
        "tactics_covered": sorted(tactics_covered),
        "techniques_covered": sorted(techniques_covered),
        "technique_details": technique_details,
        "coverage_percentage": round(coverage, 2),
    }


def generate_navigator_json(findings: List[Dict[str, Any]],
                            name: str = "AEGIS Assessment") -> str:
    """Generate ATT&CK Navigator v4.x compatible JSON layer."""
    layer = {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "AEGIS AD Security Assessment — Auto-generated ATT&CK layer",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {
            "layout": "side", "aggregateFunction": "average",
            "showID": False, "showName": True,
            "showAggregateScores": False, "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ffffff", "#22c55e", "#ffc300", "#ff8800", "#ff0022"],
            "minValue": 0, "maxValue": 4,
        },
        "legendItems": [
            {"label": "Critical", "color": "#ff0022"},
            {"label": "High", "color": "#ff8800"},
            {"label": "Medium", "color": "#ffc300"},
            {"label": "Low", "color": "#22c55e"},
        ],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    mapped = map_findings_to_attack(findings)
    for tech_id, details in mapped["technique_details"].items():
        highest_severity = "Low"
        highest_score = 0
        titles = []
        for f in details["findings"]:
            sev = f.get("severity", "Low")
            score = SEVERITY_SCORES.get(sev, 1)
            titles.append(f.get("title", "Unknown"))
            if score > highest_score:
                highest_score = score
                highest_severity = sev

        layer["techniques"].append({
            "techniqueID": tech_id,
            "tactic": details["tactic"],
            "color": SEVERITY_COLORS.get(highest_severity, "#ffffff"),
            "score": highest_score,
            "comment": "\n".join(titles),
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": True,
        })

    return json.dumps(layer, indent=2)


def save_navigator_layer(findings: List[Dict[str, Any]],
                         output_path: Optional[str] = None) -> str:
    """Save ATT&CK Navigator JSON layer to disk."""
    if not output_path:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "aegis_navigator_layer.json")

    data = generate_navigator_json(findings)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(data)
    logger.info(f"[MITRE] Navigator layer saved: {output_path}")
    return output_path


def get_attack_coverage_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Get ATT&CK coverage summary with tactic breakdown."""
    mapped = map_findings_to_attack(findings)

    tactic_coverage = {}
    for tech_id, mapping in TECHNIQUE_MAP.items():
        tactic = mapping["tactic"]
        if tactic not in tactic_coverage:
            tactic_coverage[tactic] = {"total": 0, "covered": 0}
        tactic_coverage[tactic]["total"] += 1
        if tech_id in mapped["techniques_covered"]:
            tactic_coverage[tactic]["covered"] += 1

    matrix = {}
    for tactic, counts in tactic_coverage.items():
        matrix[tactic] = f"{counts['covered']}/{counts['total']}"

    uncovered = [t for t in TECHNIQUE_MAP if t not in mapped["techniques_covered"]]

    return {
        "total_techniques": len(mapped["techniques_covered"]),
        "total_tactics": len(mapped["tactics_covered"]),
        "coverage_matrix": matrix,
        "uncovered_critical_techniques": uncovered,
        "overall_percentage": mapped["coverage_percentage"],
    }
