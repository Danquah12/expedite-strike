import os
import json
import datetime
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase

# =========================
# Neo4j Ingestor
# =========================

class Neo4jIngestor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_nmap(self, finding):
        query = """
        MERGE (h:Host {ip:$host})
        MERGE (s:Service {name:$service, port:$port, protocol:$protocol})
        MERGE (h)-[:EXPOSES]->(s)
        """
        with self.driver.session() as session:
            session.run(query, finding)

    def ingest_zap(self, finding):
        query = """
        MERGE (a:Application {url:$application})
        MERGE (v:Vulnerability {name:$name})
        SET v.severity=$severity,
            v.description=$description,
            v.source='zap',
            v.import_date=$import_date
        MERGE (a)-[:HAS_VULN]->(v)
        """
        with self.driver.session() as session:
            session.run(query, finding)

# =========================
# Nmap Parser (Tolerant XML)
# =========================

def parse_nmap(path):
    findings = []

    try:
        with open(path, "rb") as f:
            data = f.read().decode("utf-8", errors="ignore")
        root = ET.fromstring(data)

    except Exception as e:
        print(f"[NMAP] Skipping malformed XML file {path}: {e}")
        return findings  # safely skip bad file

    for host in root.findall("host"):
        addr_elem = host.find("address")
        addr = addr_elem.get("addr") if addr_elem is not None else "unknown"

        for port in host.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port.find("service")
            service = service_elem.get("name") if service_elem is not None else "unknown"

            findings.append({
                "host": addr,
                "service": service,
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
            })

    return findings

# =========================
# ZAP Parser (JSON)
# =========================

def parse_zap(path):
    findings = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ZAP] Skipping invalid JSON file {path}: {e}")
        return findings

    for site in data.get("site", []):
        application = site.get("@name", "unknown")

        for alert in site.get("alerts", []):
            findings.append({
                "application": application,
                "name": alert.get("alert", "unknown"),
                "severity": alert.get("riskdesc", "info").split(" ")[0].lower(),
                "description": alert.get("desc", ""),
                "import_date": datetime.datetime.now(datetime.UTC).isoformat()
            })

    return findings

# =========================
# Main Ingestion Logic
# =========================

NMAP_DIR = "/mnt/scans/incoming/nmap"
ZAP_DIR = "/mnt/scans/incoming/zap"

def main():
    neo = Neo4jIngestor(
        uri="bolt://localhost:7687",
        user="neo4j",
        password="Adomaa12@"   # confirmed working
    )

    # ---- Nmap ingestion ----
    for file in os.listdir(NMAP_DIR):
        if not file.endswith(".xml"):
            continue

        path = os.path.join(NMAP_DIR, file)
        print(f"[NMAP] Ingesting {file}")

        for finding in parse_nmap(path):
            neo.ingest_nmap(finding)

    # ---- ZAP ingestion ----
    for file in os.listdir(ZAP_DIR):
        if not file.endswith(".json"):
            continue

        path = os.path.join(ZAP_DIR, file)
        print(f"[ZAP] Ingesting {file}")

        for finding in parse_zap(path):
            neo.ingest_zap(finding)

    neo.close()
    print("[DONE] Ingestion complete")

if __name__ == "__main__":
    main()
