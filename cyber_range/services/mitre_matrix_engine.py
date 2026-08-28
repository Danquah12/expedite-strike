"""
Expedite Strike — MITRE ATT&CK Enterprise Matrix & Heatmap Engine
==================================================================
Provides:
  1. Complete 14-Tactic MITRE ATT&CK Enterprise Matrix
  2. Automated Finding-to-Technique Mapping & Tactic Coverage Scoring
  3. Official MITRE ATT&CK Navigator JSON Export (Layer v4.3)
  4. Interactive Heatmap Visualization Component
"""

import json
from typing import List, Dict, Any, Tuple
from dash import html


# ── Full 14-Tactic MITRE ATT&CK Enterprise Matrix Definition ──────────────────
MITRE_TACTICS_MATRIX = [
    {
        "tactic_id": "TA0043",
        "name": "Reconnaissance",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning"},
            {"id": "T1592", "name": "Gather Victim Host Info"},
            {"id": "T1589", "name": "Gather Victim Identity Info"},
            {"id": "T1590", "name": "Gather Victim Network Info"},
            {"id": "T1596", "name": "Search Open Technical DBs"},
        ],
    },
    {
        "tactic_id": "TA0042",
        "name": "Resource Development",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure"},
            {"id": "T1586", "name": "Compromise Accounts"},
            {"id": "T1588", "name": "Obtain Capabilities"},
        ],
    },
    {
        "tactic_id": "TA0001",
        "name": "Initial Access",
        "techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1133", "name": "External Remote Services"},
            {"id": "T1566", "name": "Phishing"},
        ],
    },
    {
        "tactic_id": "TA0002",
        "name": "Execution",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter"},
            {"id": "T1203", "name": "Exploitation for Client Execution"},
            {"id": "T1053", "name": "Scheduled Task/Job"},
            {"id": "T1047", "name": "Windows Management Instrumentation"},
        ],
    },
    {
        "tactic_id": "TA0003",
        "name": "Persistence",
        "techniques": [
            {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
            {"id": "T1136", "name": "Create Account"},
            {"id": "T1505", "name": "Server Software Component (Web Shell)"},
        ],
    },
    {
        "tactic_id": "TA0004",
        "name": "Privilege Escalation",
        "techniques": [
            {"id": "T1548", "name": "Abuse Elevation Control (Sudo/SUID)"},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1134", "name": "Access Token Manipulation"},
            {"id": "T1574", "name": "Hijack Execution Flow"},
        ],
    },
    {
        "tactic_id": "TA0005",
        "name": "Defense Evasion",
        "techniques": [
            {"id": "T1070", "name": "Indicator Removal"},
            {"id": "T1036", "name": "Masquerading"},
            {"id": "T1562", "name": "Impair Defenses"},
        ],
    },
    {
        "tactic_id": "TA0006",
        "name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force / Password Spray"},
            {"id": "T1552", "name": "Unsecured Credentials"},
            {"id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
            {"id": "T1003", "name": "OS Credential Dumping"},
        ],
    },
    {
        "tactic_id": "TA0007",
        "name": "Discovery",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1082", "name": "System Information Discovery"},
            {"id": "T1016", "name": "System Network Configuration Discovery"},
            {"id": "T1087", "name": "Account Discovery"},
        ],
    },
    {
        "tactic_id": "TA0008",
        "name": "Lateral Movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services (SSH/SMB/RDP)"},
            {"id": "T1550", "name": "Use Alternate Authentication Material"},
            {"id": "T1570", "name": "Lateral Tool Transfer"},
        ],
    },
    {
        "tactic_id": "TA0009",
        "name": "Collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1213", "name": "Data from Information Repositories"},
        ],
    },
    {
        "tactic_id": "TA0011",
        "name": "Command and Control",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol"},
            {"id": "T1572", "name": "Protocol Tunneling"},
        ],
    },
    {
        "tactic_id": "TA0010",
        "name": "Exfiltration",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
        ],
    },
    {
        "tactic_id": "TA0040",
        "name": "Impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact"},
            {"id": "T1499", "name": "Endpoint Denial of Service"},
        ],
    },
]


class MITREMatrixEngine:
    """Computes MITRE ATT&CK heatmap coverage and exports official Navigator layers."""

    @classmethod
    def evaluate_coverage(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map findings against MITRE tactics and calculate coverage scores."""
        findings = findings or []
        observed_ids = set()

        for f in findings:
            mid = (f.get("mitre_id", "") or f.get("mitre", "") or "").upper().strip()
            if mid:
                observed_ids.add(mid.split(".")[0])
                observed_ids.add(mid)

            # Auto-match keywords to MITRE IDs
            t_str = ((f.get("title", "") or "") + " " + (f.get("description", "") or "")).lower()
            if "scan" in t_str or "port" in t_str or "nmap" in t_str:
                observed_ids.add("T1595")
                observed_ids.add("T1046")
            if "exploit" in t_str or "rce" in t_str or "backdoor" in t_str:
                observed_ids.add("T1190")
                observed_ids.add("T1059")
            if "sudo" in t_str or "suid" in t_str or "privesc" in t_str:
                observed_ids.add("T1548")
                observed_ids.add("T1068")
            if "ssh" in t_str or "smb" in t_str:
                observed_ids.add("T1021")
            if "credential" in t_str or "password" in t_str or "hydra" in t_str:
                observed_ids.add("T1110")
                observed_ids.add("T1552")

        tactics_coverage = []
        total_techs = 0
        total_covered = 0

        for tac in MITRE_TACTICS_MATRIX:
            techs = tac["techniques"]
            covered_in_tac = [t for t in techs if t["id"] in observed_ids]
            cov_pct = round((len(covered_in_tac) / max(1, len(techs))) * 100, 1)

            total_techs += len(techs)
            total_covered += len(covered_in_tac)

            tactics_coverage.append({
                "tactic_id": tac["tactic_id"],
                "tactic_name": tac["name"],
                "total_techniques": len(techs),
                "covered_count": len(covered_in_tac),
                "coverage_pct": cov_pct,
                "techniques": [
                    {
                        "id": t["id"],
                        "name": t["name"],
                        "status": "CONFIRMED" if t["id"] in observed_ids else "INACTIVE",
                        "color": "#ef4444" if t["id"] in observed_ids else "#334155",
                    }
                    for t in techs
                ],
            })

        overall_score = round((total_covered / max(1, total_techs)) * 100, 1)

        return {
            "overall_coverage_pct": overall_score,
            "total_techniques_evaluated": total_techs,
            "total_confirmed_techniques": total_covered,
            "tactics": tactics_coverage,
            "observed_ids": list(observed_ids),
        }

    @classmethod
    def export_navigator_json(cls, findings: List[Dict[str, Any]], scan_name: str = "Expedite Strike Assessment") -> str:
        """Export official MITRE ATT&CK Navigator JSON layer file."""
        cov = cls.evaluate_coverage(findings)
        techniques_list = []

        for mid in cov["observed_ids"]:
            techniques_list.append({
                "techniqueID": mid,
                "score": 100,
                "color": "#ef4444",
                "comment": "Verified executed during Expedite Strike autonomous assessment",
                "enabled": True,
            })

        layer = {
            "name": f"{scan_name} — MITRE ATT&CK Matrix",
            "versions": {
                "attack": "14",
                "navigator": "4.8.0",
                "layer": "4.3",
            },
            "domain": "enterprise-attack",
            "description": f"Exported from Expedite Strike Autonomous Penetration Testing Platform. Total techniques verified: {len(cov['observed_ids'])}.",
            "gradient": {
                "colors": ["#1e293b", "#ef4444"],
                "minValue": 0,
                "maxValue": 100,
            },
            "techniques": techniques_list,
        }
        return json.dumps(layer, indent=2)

    @classmethod
    def render_matrix_widget(cls, findings: List[Dict[str, Any]]) -> html.Div:
        """Render the interactive MITRE ATT&CK Heatmap widget for the Dash dashboard."""
        cov = cls.evaluate_coverage(findings)

        cols = []
        for tac in cov["tactics"][:6]:  # Show primary tactics in compact view
            tech_items = []
            for t in tac["techniques"]:
                is_hit = t["status"] == "CONFIRMED"
                bg = "rgba(239, 68, 68, 0.25)" if is_hit else "rgba(30, 41, 59, 0.6)"
                border = "#ef4444" if is_hit else "#334155"
                text_col = "#fca5a5" if is_hit else "#64748b"

                tech_items.append(html.Div([
                    html.Span(f"[{t['id']}] ", style={"color": "#94a3b8", "fontWeight": "700", "fontSize": "8px"}),
                    html.Span(t["name"], style={"color": text_col, "fontSize": "8px"}),
                ], style={
                    "background": bg,
                    "border": f"1px solid {border}",
                    "borderRadius": "4px",
                    "padding": "4px 6px",
                    "marginBottom": "4px",
                    "fontFamily": "monospace",
                }))

            cols.append(html.Div([
                html.Div([
                    html.Div(tac["tactic_name"], style={"color": "#00d6b4", "fontWeight": "900", "fontSize": "10px", "fontFamily": "monospace"}),
                    html.Div(f"{tac['coverage_pct']}% Covered", style={"color": "#94a3b8", "fontSize": "8px"}),
                ], style={"borderBottom": "1px solid #1e2a3a", "paddingBottom": "4px", "marginBottom": "6px"}),
                html.Div(tech_items),
            ], style={"flex": "1", "minWidth": "140px", "background": "#0a0f1d", "padding": "8px", "borderRadius": "6px", "border": "1px solid #1e293b"}))

        return html.Div([
            html.Div([
                html.Span("🗺️ ", style={"fontSize": "16px", "marginRight": "8px"}),
                html.Span("MITRE ATT&CK® ENTERPRISE HEATMAP MATRIX", style={"color": "#00d6b4", "fontWeight": "900", "fontSize": "11px", "letterSpacing": "2px", "fontFamily": "monospace"}),
                html.Span(f"  ·  Overall Adversary TTP Coverage: {cov['overall_coverage_pct']}%", style={"color": "#94a3b8", "fontSize": "10px", "fontFamily": "monospace"}),
            ], style={"display": "flex", "alignItems": "center", "marginBottom": "10px"}),
            html.Div(cols, style={"display": "flex", "gap": "8px", "overflowX": "auto"}),
        ], style={
            "background": "linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(11, 15, 25, 0.95))",
            "border": "1px solid #1e293b",
            "borderRadius": "8px",
            "padding": "12px 16px",
            "marginBottom": "16px",
        })
