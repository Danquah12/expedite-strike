# ingest_zap_to_neo4j.py
# STEP 6 (FIXED): ZAP → Neo4j ingestion
# Deterministic, scan-faithful, Neo4j-safe

import sys

# --------------------------------------------------
# Ensure shared-drive ZAP parsers are importable
# --------------------------------------------------
ZAP_SHARED_DIR = "/mnt/scans/incoming/zap"
if ZAP_SHARED_DIR not in sys.path:
    sys.path.insert(0, ZAP_SHARED_DIR)

from neo4j_engine import neo4j
from batch_parse_zap_shared import PARSED_RESULTS


# ======================================================
# ASSETS (unique by host)
# ======================================================
def ingest_assets():
    print("[*] Ingesting ZAP Assets")

    for asset in PARSED_RESULTS["assets"]:
        host = asset.get("host")
        if not host:
            continue

        neo4j.run_query(
            """
            MERGE (a:Asset {host:$host})
            SET a.source = 'zap'
            """,
            host=host
        )


# ======================================================
# SERVICES (unique per host + port)
# ======================================================
def ingest_services():
    print("[*] Ingesting ZAP Services")

    for svc in PARSED_RESULTS["services"]:
        if not all(k in svc for k in ("host", "port", "protocol")):
            continue

        neo4j.run_query(
            """
            MATCH (a:Asset)
            WHERE a.host = $host

            MERGE (s:Service {
                host:$host,
                port:$port,
                protocol:$protocol
            })
            SET s.name = $name,
                s.source = 'zap'

            MERGE (a)-[:EXPOSES]->(s)
            """,
            host=svc["host"],
            port=svc["port"],
            protocol=svc["protocol"],
            name=svc.get("name")
        )


# ======================================================
# FINDINGS + VULNERABILITIES (CRITICAL FIX APPLIED)
# ======================================================
def ingest_findings():
    print("[*] Ingesting ZAP Findings & Vulnerabilities")

    for f in PARSED_RESULTS["findings"]:
        required = ("host", "port", "pluginid", "name")
        if not all(k in f for k in required):
            continue

        neo4j.run_query(
            """
            MATCH (s:Service)
            WHERE s.host = $host AND s.port = $port

            MERGE (v:Vulnerability {external_id:$external_id})
            SET v.source = 'cwe',
                v.cwe = $cwe,
                v.wasc = $wasc,
                v.name = $name

            CREATE (f:Finding {
                host:$host,
                port:$port,
                pluginid:$external_id,
                name:$name,
                riskcode:$riskcode,
                confidence:$confidence,
                description:$description,
                solution:$solution,
                source:'zap'
            })

            MERGE (s)-[:HAS_FINDING]->(f)
            MERGE (f)-[:INSTANCE_OF]->(v)
            """,
            host=f["host"],
            port=f["port"],
            external_id=f["pluginid"],
            name=f["name"],
            riskcode=f.get("riskcode"),
            confidence=f.get("confidence"),
            description=f.get("description"),
            solution=f.get("solution"),
            cwe=f.get("cweid"),
            wasc=f.get("wascid"),
        )


# ======================================================
# MAIN
# ======================================================
def main():
    print("[+] Ingesting ZAP data into Neo4j")

    ingest_assets()
    ingest_services()
    ingest_findings()

    print("[+] ZAP ingestion complete")


if __name__ == "__main__":
    main()
