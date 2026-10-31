import os
from cyber_range.parsers.zap_parser import ZapParser
from cyber_range.parsers.nmap_parser import NmapParser
from neo4j_ingestor import Neo4jIngestor

ZAP_DIR = "/mnt/scans/incoming/zap"
NMAP_DIR = "/mnt/scans/incoming/nmap"

neo = Neo4jIngestor(
    uri="bolt://localhost:7687",
    user="neo4j",
    password="password"  # <-- change if needed
)

def ingest_zap_reports():
    parser = ZapParser()
    for file in os.listdir(ZAP_DIR):
        if not file.endswith((".xml", ".json")):
            continue
        path = os.path.join(ZAP_DIR, file)
        findings = parser.parse(path)
        for finding in findings:
            neo.ingest_zap(finding)

def ingest_nmap_reports():
    parser = NmapParser()
    for file in os.listdir(NMAP_DIR):
        if not file.endswith(".xml"):
            continue
        path = os.path.join(NMAP_DIR, file)
        findings = parser.parse(path)
        for finding in findings:
            neo.ingest_nmap(finding)

if __name__ == "__main__":
    ingest_zap_reports()
    ingest_nmap_reports()
    neo.close()
