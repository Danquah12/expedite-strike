# ==========================================================
# ADVANCED SECURITY CHATBOT ENGINE
# ==========================================================
import json
from neo4j import GraphDatabase
from datetime import datetime
import requests
import sqlite3
import pandas as pd
from pathlib import Path
import subprocess
import os

DB_PATH = "/root/vuln_intel/vuln_intel.db"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


# ==========================================================
#  LOADER FUNCTIONS
# ==========================================================
def load_local_cves():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM findings", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()


def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ==========================================================
#  WORKFLOW 1 — HIGH-LEVEL THREAT SUMMARY
# ==========================================================
def workflow_summary():
    df = load_local_cves()

    if df.empty:
        return "No vulnerability data loaded."

    critical = df[df["cvss"] >= 9]
    high = df[df["cvss"].between(7, 9)]
    medium = df[df["cvss"].between(4, 7)]

    summary = f"""
🛡 SECURITY SUMMARY — {datetime.now().strftime('%Y-%m-%d %H:%M')}

Total Findings: {len(df)}
Critical: {len(critical)}
High: {len(high)}
Medium: {len(medium)}

Top Critical Vulnerabilities:
{critical['id'].head(5).to_string(index=False)}

Use workflows:
- 'attack_path asset=<asset>'
- 'explain cve=CVE-XXXX-YYYY'
- 'mitre_map'
- 'remediate'
"""

    return summary


# ==========================================================
# WORKFLOW 2 — ATTACK PATH GENERATION
# ==========================================================
def workflow_attack_path(asset):
    """
    Returns shortest attack path to the specified asset.
    """
    try:
        driver = get_driver()
        with driver.session() as session:
            q = f"""
            MATCH p=shortestPath(
                (u:User)-[*..6]->(a:Asset {{host: '{asset}'}})
            )
            RETURN p
            """
            result = session.run(q)
            record = result.single()

            if not record:
                return f"No attack paths found to asset {asset}."

            path = record["p"]
            nodes = [n.get("host") or n.get("name") or list(n.labels)[0] for n in path.nodes]

            attack_chain = " → ".join(nodes)

            return f"""
⚔ ATTACK PATH TO {asset}

{attack_chain}

Interpretation:
- User compromise leads to lateral movement.
- Service exploitation connects attacker to {asset}.
- Patch vulnerabilities and isolate high-risk services.
"""
    except Exception as e:
        return f"Neo4j error: {e}"


# ==========================================================
# WORKFLOW 3 — EXPLAIN A CVE
# ==========================================================
def workflow_explain_cve(cve):
    """
    Fetch CVE details + map to MITRE + find affected assets.
    """

    df = load_local_cves()
    affected = df[df["id"] == cve]

    # Vulners API
    vulners_key = os.getenv("VULNERS_API_KEY")
    if vulners_key:
        try:
            resp = requests.get(
                "https://vulners.com/api/v3/search/lucene/",
                params={"query": cve, "size": 3},
                headers={"X-Api-Key": vulners_key},
                timeout=10,
            )
            vulners_data = resp.json()
        except:
            vulners_data = {}
    else:
        vulners_data = {}

    msg = f"""
📝 CVE ANALYSIS: {cve}

Affected Assets:
{affected['host'].to_string(index=False) if not affected.empty else "None found"}

CVSS:
{affected['cvss'].iloc[0] if not affected.empty else "N/A"}

Raw Vulners Extract:
{json.dumps(vulners_data, indent=2)[:2000]}...
"""

    return msg


# ==========================================================
# WORKFLOW 4 — MITRE MAPPING
# ==========================================================
def workflow_mitre_map():
    try:
        driver = get_driver()
        with driver.session() as session:
            q = """
            MATCH (v:Vulnerability)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
            RETURN v.id AS cve, t.id AS tech, t.label AS name
            LIMIT 30
            """
            rows = session.run(q)
            data = list(rows)

            if not data:
                return "No MITRE mappings found."

            text = "🔥 MITRE TECHNIQUE MAPPINGS:\n\n"
            for row in data:
                text += f"CVE {row['cve']} → {row['tech']} ({row['name']})\n"

            return text
    except Exception as e:
        return f"MITRE MAP ERROR: {e}"


# ==========================================================
# WORKFLOW 5 — REMEDIATION PLAN
# ==========================================================
def workflow_remediation():
    df = load_local_cves()

    if df.empty:
        return "Unable to build remediation plan — no findings found."

    critical = df[df["cvss"] >= 9]
    high = df[df["cvss"].between(7, 9)]

    return f"""
🛠 REMEDIATION PLAN (30 DAYS)

🚨 IMMEDIATE (24–72 HRS)
{critical['id'].to_string(index=False)}

🔥 HIGH PRIORITY (7 DAYS)
{high['id'].to_string(index=False)}

📅 30-DAY TASKS
- Patch all medium vulnerabilities
- Harden network segmentation
- Enforce MFA
- Implement continuous scanning
"""


# ==========================================================
# MASTER ROUTING FUNCTION
# ==========================================================
def process_chat_query(prompt):
    """
    Main router that interprets chat commands.
    """

    prompt = prompt.lower().strip()

    # ROUTERS
    if prompt.startswith("summary"):
        return workflow_summary()

    if prompt.startswith("attack_path"):
        try:
            asset = prompt.split("=")[1]
            return workflow_attack_path(asset)
        except:
            return "Usage: attack_path asset=<host>"

    if prompt.startswith("explain") or "cve" in prompt:
        try:
            cve = prompt.split("=")[1].upper()
            return workflow_explain_cve(cve)
        except:
            return "Usage: explain cve=CVE-XXXX-YYYY"

    if prompt.startswith("mitre_map"):
        return workflow_mitre_map()

    if prompt.startswith("remediate"):
        return workflow_remediation()

    # DEFAULT — Use LLM fallback
    return f"""
🤖 Default LLM Mode:
No workflow triggered. You said:

{prompt}

Try:
- summary
- explain cve=CVE-2021-44228
- attack_path asset=192.168.1.10
- mitre_map
- remediate
"""
