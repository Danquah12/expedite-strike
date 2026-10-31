#!/usr/bin/env python3
# ==========================================
# zap_import.py — CVE-Enabled ZAP Importer
# Attack-Path Compatible (creates EXPLOITS edges)
# ==========================================

import os
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# Correct relative import for utils_cve
from app.importers.utils_cve import extract_cves, extract_cwe

# Corrected ZAP feed directory path
ZAP_DIR = "/opt/vuln_intel/feeds/zap"

# Neo4j driver
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "Adomaa12@")
)

# --------------------------------------------------------
# Derive Asset (Host, URL, or Target)
# --------------------------------------------------------
def derive_asset(alert):
    """
    Extracts the asset (URL/URI/endpoint) affected by each ZAP finding.
    Compatible with <uri>, <url>, <attack>, <param>.
    """
    candidates = [
        alert.findtext("uri"),
        alert.findtext("url"),
        alert.findtext("attack"),
        alert.findtext("param"),
    ]

    for c in candidates:
        if c and c.strip():
            return c.strip()

    return "Web-Application"  # fallback


# --------------------------------------------------------
# Main ZAP Importer
# --------------------------------------------------------
def import_zap_file(path):
    print(f"[+] Importing ZAP XML: {path}")

    try:
        tree = ET.parse(path)
    except Exception as e:
        print(f"[!] Failed to parse {path}: {e}")
        return

    root = tree.getroot()

    with driver.session() as session:

        for alert in root.findall(".//alertitem"):

            name = alert.findtext("alert", "Unknown Issue")
            desc = alert.findtext("desc", "")
            riskdesc = alert.findtext("riskdesc", "Unknown Risk")
            refs = alert.findtext("reference", "")
            sol = alert.findtext("solution", "")
            cwe = alert.findtext("cweid", "")

            # Extract affected asset
            asset = derive_asset(alert)

            # Build text blob for CVE detection
            text_blob = " ".join([desc, refs, sol, cwe])
            cves = list(set(extract_cves(text_blob)))

            # ---------------------------------------------------------------
            # Merge Asset + Web Vulnerability
            # ---------------------------------------------------------------
            session.run("""
                MERGE (a:Asset {name:$asset})
                MERGE (v:WebVulnerability {
                    name:$name,
                    description:$desc,
                    severity:$severity
                })
                MERGE (a)-[:HAS_VULN]->(v)
            """, asset=asset, name=name, desc=desc, severity=riskdesc)

            # ---------------------------------------------------------------
            # Create EXPLOITS relationship (attack path)
            # ---------------------------------------------------------------
            session.run("""
                MATCH (a:Asset {name:$asset})
                MATCH (v:WebVulnerability {name:$name})
                MERGE (v)-[:EXPLOITS]->(a)
            """, asset=asset, name=name)

            # ---------------------------------------------------------------
            # Link CVEs
            # ---------------------------------------------------------------
            for cve in cves:
                session.run("""
                    MERGE (c:CVE {id:$cve})
                    WITH c
                    MATCH (v:WebVulnerability {name:$name})
                    MERGE (v)-[:IS_CVE]->(c)
                """, cve=cve, name=name)

    print("[✓] ZAP import completed.")


# --------------------------------------------------------
# Directory Import
# --------------------------------------------------------
def import_zap_directory():
    if not os.path.isdir(ZAP_DIR):
        print(f"[!] ZAP directory not found: {ZAP_DIR}")
        return

    files = [f for f in os.listdir(ZAP_DIR) if f.endswith(".xml")]

    if not files:
        print("[!] No ZAP XML files found.")
        return

    for file in files:
        import_zap_file(os.path.join(ZAP_DIR, file))


# --------------------------------------------------------
if __name__ == "__main__":
    import_zap_directory()
