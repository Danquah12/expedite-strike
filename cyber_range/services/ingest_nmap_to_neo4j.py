# ingest_nmap_to_neo4j.py
# STEP 4 (FIXED): Correct Nmap → Neo4j ingestion with scan-level fidelity

from neo4j_engine import neo4j
from batch_parse_nmap_shared import PARSED_RESULTS


# ======================================================
# ASSETS (unique by IP)
# ======================================================
def ingest_assets():
    print("[*] Ingesting Assets")

    for asset in PARSED_RESULTS["assets"]:
        ip = asset.get("ip")
        if not ip:
            continue

        neo4j.run_query(
            """
            MERGE (a:Asset {host: $host})
            SET a.source = 'nmap'
            """,
            host=ip
        )


# ======================================================
# SERVICES (unique per host + port + protocol)
# ======================================================
def ingest_services():
    print("[*] Ingesting Services")

    for svc in PARSED_RESULTS["services"]:
        if not all(k in svc for k in ("ip", "port", "protocol")):
            continue

        neo4j.run_query(
            """
            MATCH (a:Asset {host: $host})
            MERGE (s:Service {
                host: $host,
                port: $port,
                protocol: $protocol
            })
            SET
                s.name   = $name,
                s.source = 'nmap'
            MERGE (a)-[:EXPOSES]->(s)
            """,
            host=svc["ip"],
            port=svc["port"],
            protocol=svc["protocol"],
            name=svc.get("service")
        )


# ======================================================
# FINDINGS + VULNERABILITIES
# ======================================================
def ingest_vulnerabilities():
    print("[*] Ingesting Findings & Vulnerabilities")

    for v in PARSED_RESULTS["vulnerabilities"]:
        if not all(k in v for k in ("ip", "port", "cve")):
            continue

        neo4j.run_query(
            """
            MATCH (s:Service {
                host: $host,
                port: $port
            })

            MERGE (vuln:Vulnerability {cve: $cve})
            SET vuln.source = 'nvd'

            CREATE (f:Finding {
                host:        $host,
                port:        $port,
                cve:         $cve,
                cvss:        $cvss,
                exploitable: $exploitable,
                source:      'nmap'
            })

            MERGE (s)-[:HAS_FINDING]->(f)
            MERGE (f)-[:INSTANCE_OF]->(vuln)
            """,
            host=v["ip"],
            port=v["port"],
            cve=v["cve"],
            cvss=v.get("cvss"),
            exploitable=v.get("exploitable", False),
        )


# ======================================================
# MAIN
# ======================================================
def main():
    print("[+] Re-ingesting Nmap data (correct model)")
    ingest_assets()
    ingest_services()
    ingest_vulnerabilities()
    print("[+] Done")


if __name__ == "__main__":
    main()
