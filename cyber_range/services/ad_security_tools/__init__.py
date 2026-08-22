"""
AD Security Tools — Tool Registry & Main Package
=================================================
Enterprise AD Security Assessment Platform.

Architecture:
    ┌─────────────────────────────────┐
    │     AD Security Orchestrator    │
    │  (Plan → Execute → Validate)   │
    └──────────────┬──────────────────┘
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
    Discovery  Analysis  Correlation
     8 tools   7 tools    3 engines
        │          │          │
        └──────────┼──────────┘
                   ▼
            Evidence Store
            (SQLite + Audit)
"""

from .discovery.discovery_tools import ALL_DISCOVERY_TOOLS
from .analysis.analysis_tools import ALL_ANALYSIS_TOOLS
from .agents.ad_orchestrator import run_ad_security_assessment


# ── Tool Registry ────────────────────────────────────────────────────

TOOL_REGISTRY = {
    **ALL_DISCOVERY_TOOLS,
    **ALL_ANALYSIS_TOOLS,
}

TOOL_METADATA = {
    "discover_domain":     {"category": "discovery", "risk": "passive", "desc": "Domain/forest enumeration via RootDSE"},
    "enumerate_users":     {"category": "discovery", "risk": "passive", "desc": "User account analysis with UAC flags"},
    "enumerate_groups":    {"category": "discovery", "risk": "passive", "desc": "Group membership and privilege mapping"},
    "enumerate_computers": {"category": "discovery", "risk": "passive", "desc": "Computer inventory and OS detection"},
    "enumerate_dcs":       {"category": "discovery", "risk": "passive", "desc": "Domain controller identification"},
    "enumerate_gpos":      {"category": "discovery", "risk": "passive", "desc": "Group Policy Object enumeration"},
    "enumerate_trusts":    {"category": "discovery", "risk": "passive", "desc": "Trust relationship mapping"},
    "enumerate_spns":      {"category": "discovery", "risk": "passive", "desc": "Service Principal Name enumeration"},
    "analyze_kerberos":    {"category": "analysis",  "risk": "passive", "desc": "Kerberos delegation and encryption analysis"},
    "analyze_ldap":        {"category": "analysis",  "risk": "passive", "desc": "LDAP binding and signing analysis"},
    "analyze_smb":         {"category": "analysis",  "risk": "passive", "desc": "SMB signing and version analysis"},
    "analyze_ntlm":        {"category": "analysis",  "risk": "passive", "desc": "NTLM authentication surface analysis"},
    "analyze_adcs":        {"category": "analysis",  "risk": "passive", "desc": "AD Certificate Services ESC1-ESC8"},
    "analyze_acls":        {"category": "analysis",  "risk": "passive", "desc": "ACL/DACL permission analysis"},
    "analyze_passwords":   {"category": "analysis",  "risk": "passive", "desc": "Password policy assessment"},
}


def get_tool(name: str):
    """Get a tool function by name."""
    return TOOL_REGISTRY.get(name)


def list_tools(category: str = None) -> list:
    """List available tools, optionally filtered by category."""
    tools = []
    for name, meta in TOOL_METADATA.items():
        if category is None or meta["category"] == category:
            tools.append({"name": name, **meta})
    return tools


def invoke_tool(name: str, params: dict, assessment_id: str = "") -> dict:
    """Invoke a tool by name with parameters. Auto-logs evidence."""
    fn = TOOL_REGISTRY.get(name)
    if not fn:
        return {"tool": name, "status": "error", "error": f"Unknown tool: {name}"}

    result = fn(**params)

    # Auto-log evidence
    if assessment_id:
        try:
            from .evidence.evidence_store import log_evidence
            eid = log_evidence(assessment_id, name,
                               params.get("target_ip", ""),
                               result.get("raw_output", "")[:5000])
            result["evidence_ids"] = [eid]
        except Exception:
            pass

    return result
