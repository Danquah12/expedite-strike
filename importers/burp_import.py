#!/usr/bin/env python3
import os
import re
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

import re

def extract_cwe(text):
    """
    Extract first CWE identifier from text (e.g., 'CWE-79', 'CWE-89').
    Returns 'CWE-XX' or None.
    """
    if not text:
        return None
    m = re.search(r"CWE-\d+", text, re.IGNORECASE)
    return m.group(0) if m else None


# Corrected Burp directory
BURP_DIR = "/opt/vuln_intel/feeds/burp"

# Proper relative import for shared CVE/CWE extractors
from app.importers.utils_cve import extract_cves, extract_cwe

# Neo4j driver
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "Adomaa12@")
)

# ----------------------------------------------------
# Helper Functions
# ----------------------------------------------------
def get_text(elem):
    return elem.text.strip() if elem is not None and elem.text else ""

def derive_asset(issue):
    """
    Attempts to derive the host/asset from:
    <host>, <path>, <location>
    """
    host = get_text(issue.find("host"))
    path = get_text(issue.find("path"))
    location = get_text(issue.find("location"))

    if host:
        return host
    if path:
        return path
    if location:
        return location

    return "Unknown-Web-Asset"


# ----------------------------------------------------
# Import a Single Burp XML File
# ----------------------------------------------------
def import_burp_file(file_path):
    print(f"[+] Importing Burp XML: {file_path}")

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Failed to parse {file_path}: {e}")
        return

    with driver.session() as session:

        for issue in root.findall(".//issue"):

            # Raw Burp fields
            name = get_text(issue.find("name"))
            host = derive_asset(issue)
            path = get_text(issue.find("path"))
            severity = get_text(issue.find("severity"))
            confidence = get_text(issue.find("confidence"))
            background = get_text(issue.find("issueBackground"))
            details = get_text(issue.find("issueDetail"))

            description = f"{background}\n\n{details}".strip()

            # Analytical fields
            cwe = extract_cwe(description)
            cves = extract_cves(description)

            # -------------------------------------------------
            # 1. Asset node
            # -------------------------------------------------
            session.run("""
                MERGE (a:Asset {name:$host})
            """, host=host)

            # -------------------------------------------------
            # 2. WebPath node (safe)
            # -------------------------------------------------
            if path:
                session.run("""
                    MERGE (p:WebPath {url:$path})
                """, path=path)

            # -------------------------------------------------
            # 3. Burp Vulnerability node
            # -------------------------------------------------
            session.run("""
                MERGE (b:BurpVulnerability {name:$name, host:$host, path:$path})
                SET b.severity=$severity,
                    b.confidence=$confidence,
                    b.description=$description
            """,
                name=name, host=host, path=path,
                severity=severity, confidence=confidence,
                description=description
            )

            # -------------------------------------------------
            # 4. Asset → Vulnerability
            # -------------------------------------------------
            session.run("""
                MATCH (a:Asset {name:$host})
                MATCH (b:BurpVulnerability {name:$name, host:$host, path:$path})
                MERGE (a)-[:HAS_VULN]->(b)
            """, host=host, name=name, path=path)

            # -------------------------------------------------
            # 5. Vulnerability → WebPath
            # -------------------------------------------------
            if path:
                session.run("""
                    MATCH (b:BurpVulnerability {name:$name, host:$host, path:$path})
                    MATCH (p:WebPath {url:$path})
                    MERGE (b)-[:AT_PATH]->(p)
                """, name=name, host=host, path=path)

            # -------------------------------------------------
            # 6. CWE Node
            # -------------------------------------------------
            if cwe:
                session.run("""
                    MERGE (c:CWE {id:$cwe})
                """, cwe=cwe)

                session.run("""
                    MATCH (b:BurpVulnerability {name:$name, host:$host, path:$path})
                    MATCH (c:CWE {id:$cwe})
                    MERGE (b)-[:HAS_CWE]->(c)
                """, name=name, host=host, path=path, cwe=cwe)

            # -------------------------------------------------
            # 7. CVEs
            # -------------------------------------------------
            for cve in cves:
                session.run("""
                    MERGE (c:CVE {id:$cve})
                """, cve=cve)

                session.run("""
                    MATCH (b:BurpVulnerability {name:$name, host:$host, path:$path})
                    MATCH (c:CVE {id:$cve})
                    MERGE (b)-[:IS_CVE]->(c)
                """, name=name, host=host, path=path, cve=cve)

            # -------------------------------------------------
            # 8. Attack Path (EXPLOITS)
            # -------------------------------------------------
            session.run("""
                MATCH (a:Asset {name:$host})
                MATCH (b:BurpVulnerability {name:$name, host:$host, path:$path})
                MERGE (b)-[:EXPLOITS]->(a)
            """, host=host, name=name, path=path)

    print("[✓] Burp import complete.")


# ----------------------------------------------------
# Directory Import
# ----------------------------------------------------
def import_burp_directory():
    if not os.path.isdir(BURP_DIR):
        print(f"[!] Burp directory not found: {BURP_DIR}")
        return

    files = sorted(f for f in os.listdir(BURP_DIR) if f.endswith(".xml"))
    if not files:
        print("[!] No Burp XML files found.")
        return

    for f in files:
        import_burp_file(os.path.join(BURP_DIR, f))


if __name__ == "__main__":
    import_burp_directory()
