#!/usr/bin/env python3
import os
import glob
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# ----------------------------------------------
# Neo4j Connection
# ----------------------------------------------
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "Adomaa12@")


driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ----------------------------------------------
# Insert or merge a WebPath node
# ----------------------------------------------
def create_webpath(tx, asset, uri):
    tx.run(
        """
        MERGE (a:Asset {host: $asset})
        MERGE (p:WebPath {uri: $uri})
        MERGE (a)-[:HOSTS]->(p)
        """,
        asset=asset,
        uri=uri
    )


# ----------------------------------------------
# Insert a WebVulnerability and link it
# ----------------------------------------------
def create_webvuln(tx, alert, risk, description, uri, method, param, attack):
    tx.run(
        """
        MERGE (v:WebVulnerability {
            name: $alert,
            risk: $risk,
            description: $description
        })
        MERGE (p:WebPath {uri: $uri})
        MERGE (p)-[:HAS_VULN]->(v)
        """,
        alert=alert,
        risk=risk,
        description=description,
        uri=uri
    )


# ----------------------------------------------
# Parse one XML file
# ----------------------------------------------
def parse_zap_file(path):
    print(f"[+] Parsing ZAP file: {path}")

    tree = ET.parse(path)
    root = tree.getroot()

    site = root.find(".//site")
    if site is None:
        print("[-] No <site> found, skipping...")
        return

    asset_host = site.get("host")

    for alert in site.findall(".//alertitem"):
        alert_name = alert.findtext("alert", "").strip()
        riskcode = alert.findtext("riskcode", "").strip()
        desc = alert.findtext("desc", "").strip()

        # Convert riskcode to readable risk
        risk_map = {
            "0": "Informational",
            "1": "Low",
            "2": "Medium",
            "3": "High"
        }
        risk = risk_map.get(riskcode, "Unknown")

        # Process all instances (each affected URL)
        for inst in alert.findall(".//instance"):
            uri = inst.findtext("uri", "").strip()
            method = inst.findtext("method", "").strip()
            param = inst.findtext("param", "").strip()
            attack = inst.findtext("attack", "").strip()

            with driver.session() as session:
                session.execute_write(create_webpath, asset_host, uri)
                session.execute_write(
                    create_webvuln,
                    alert_name,
                    risk,
                    desc,
                    uri,
                    method,
                    param,
                    attack
                )

    print(f"[+] Done: {path}")


# ----------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------
def run_import():
    zap_dir = "/opt/vuln_intel/imports/zap/*.xml"
    files = glob.glob(zap_dir)

    if not files:
        print("[-] No ZAP XML files found.")
        return

    print(f"[+] Found {len(files)} ZAP scan files.")

    for f in files:
        parse_zap_file(f)

    print("\n🔥 ZAP import completed successfully!")
    print("Open Neo4j Browser and run: MATCH (n) RETURN n LIMIT 50;")

if __name__ == "__main__":
    run_import()
