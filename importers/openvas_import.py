#!/usr/bin/env python3
import os
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# Import local CVE extraction helper
from app.importers.utils_cve import extract_cves, extract_cwe

# Correct path for new installation
OPENVAS_DIR = "/opt/vuln_intel/feeds/openvas"

# Neo4j connection
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "Adomaa12@")
)

# ---------------------------------------------------------
# Safe asset extraction
# ---------------------------------------------------------
def derive_asset_identifier(result):
    host = result.findtext("host")
    if host and host.strip():
        return host.strip()

    ip = result.findtext("ip")
    if ip and ip.strip():
        return ip.strip()

    port = result.findtext("port")
    if port and port.strip():
        return f"UNKNOWN-ASSET-{port.strip()}"

    return None

# ---------------------------------------------------------
# Import a single OpenVAS XML file
# ---------------------------------------------------------
def import_openvas_file(path):
    print(f"[+] Importing OpenVAS XML: {path}")
    tree = ET.parse(path)
    root = tree.getroot()

    with driver.session() as session:
        for result in root.findall(".//result"):

            host = derive_asset_identifier(result)
            if host is None:
                print(f"[!] Skipping result with NULL host in {path}")
                continue

            name = result.findtext("name", "")
            desc = result.findtext("description", "")
            threat = result.findtext("threat", "Unknown")

            # Extract CVEs
            cves = extract_cves(desc)

            nvt = result.find("nvt")
            if nvt is not None:
                cves.extend(extract_cves(nvt.findtext("cve", "")))
                cves.extend(extract_cves(nvt.findtext("tags", "")))

            cves = list(set(cves))

            # Merge asset + vulnerability
            session.run("""
                MERGE (a:Asset {host:$host})
                MERGE (v:Vulnerability {
                    name:$name,
                    description:$desc,
                    severity:$threat
                })
                MERGE (a)-[:HAS_VULN]->(v)
            """, host=host, name=name, desc=desc, threat=threat)

            # Link CVEs
            for cve in cves:
                session.run("""
                    MERGE (c:CVE {id:$cve})
                    WITH c
                    MATCH (v:Vulnerability {name:$vname})
                    MERGE (v)-[:IS_CVE]->(c)
                """, cve=cve, vname=name)

# ---------------------------------------------------------
# Process all XML files in directory
# ---------------------------------------------------------
def import_openvas_directory():
    if not os.path.isdir(OPENVAS_DIR):
        print(f"[!] Directory not found: {OPENVAS_DIR}")
        return

    files = [f for f in os.listdir(OPENVAS_DIR) if f.endswith(".xml")]

    if not files:
        print("[!] No OpenVAS XML files found.")
        return

    for file in files:
        import_openvas_file(os.path.join(OPENVAS_DIR, file))

# ---------------------------------------------------------
if __name__ == "__main__":
    import_openvas_directory()
