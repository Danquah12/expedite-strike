import os
import xml.etree.ElementTree as ET
import requests
from datetime import datetime
from neo4j import GraphDatabase
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)

# ==========================================================
#  CONNECTION
# ==========================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def get_driver():
    """Connect to Neo4j."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ==========================================================
#  IMPORT NMAP XML INTO NEO4J
# ==========================================================
def import_nmap_hosts_to_neo4j(xml_path: str):
    """
    Parse Nmap XML and import into Neo4j as Assets and Services.
    Creates (:Asset)-[:RUNS_SERVICE]->(:Service) relationships.
    """
    logger.info(f"📡 Importing Nmap data from {xml_path}")

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        driver = get_driver()
        with driver.session() as session:
            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    continue
                ip_addr = addr_el.get("addr")

                session.run(
                    "MERGE (a:Asset {host: $host}) SET a.last_seen=$time",
                    {"host": ip_addr, "time": datetime.now().isoformat()},
                )

                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    portid = port.get("portid")
                    service = port.find("service")
                    if service is None:
                        continue

                    s_name = service.get("name", "unknown")
                    s_prod = service.get("product", "unknown")
                    s_ver = service.get("version", "")
                    cpe_el = service.find("cpe")
                    cpe = cpe_el.text if cpe_el is not None else None

                    session.run(
                        """
                        MERGE (s:Service {name: $name, port: $port})
                        SET s.product=$prod, s.version=$ver, s.cpe=$cpe
                        WITH s
                        MATCH (a:Asset {host: $host})
                        MERGE (a)-[:RUNS_SERVICE]->(s)
                        """,
                        {
                            "host": ip_addr,
                            "name": s_name,
                            "prod": s_prod,
                            "ver": s_ver,
                            "cpe": cpe,
                            "port": portid,
                        },
                    )

        driver.close()
        logger.info("✅ Nmap import completed successfully.")

    except Exception as e:
        logger.error(f"❌ Error importing Nmap XML: {e}")


# ==========================================================
#  ENRICH VULNERABILITIES FROM NVD API
# ==========================================================
def enrich_cves_from_nvd(limit=50):
    """
    Enrich vulnerabilities from NVD (mock or live query).
    Creates (:Vulnerability) nodes with minimal properties if missing.
    """
    logger.info("🧠 Starting NVD enrichment process...")

    try:
        driver = get_driver()
        with driver.session() as session:
            # Example enrichment
            mock_vulns = [
                {"id": "CVE-2011-3192", "cvss": 7.5, "cpe": "cpe:/a:apache:http_server:2.2.8", "last_updated": "2025-11-13"},
                {"id": "CVE-2010-0926", "cvss": 8.0, "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4", "last_updated": "2025-11-13"},
            ]

            for vuln in mock_vulns:
                session.run(
                    """
                    MERGE (v:Vulnerability {id: $id})
                    SET v.cvss=$cvss, v.cpe=$cpe, v.last_updated=$updated
                    """,
                    {
                        "id": vuln["id"],
                        "cvss": vuln["cvss"],
                        "cpe": vuln["cpe"],
                        "updated": vuln["last_updated"],
                    },
                )

        driver.close()
        logger.info("✅ NVD enrichment complete.")

    except Exception as e:
        logger.error(f"❌ NVD enrichment failed: {e}")


# ==========================================================
#  AUTO-LINK SERVICES TO VULNERABILITIES
# ==========================================================
def auto_link_services_to_vulns():
    """
    Automatically link (:Service) nodes to (:Vulnerability) nodes
    based on shared CPE or product name similarity.
    """
    logger.info("🔗 Starting auto-linking of Services to Vulnerabilities...")

    try:
        driver = get_driver()
        with driver.session() as session:
            # Match via CPE (most accurate)
            session.run(
                """
                MATCH (s:Service), (v:Vulnerability)
                WHERE s.cpe IS NOT NULL AND v.cpe IS NOT NULL AND s.cpe = v.cpe
                MERGE (s)-[:HAS_VULNERABILITY]->(v)
                """
            )

            # Fallback: Match by product/vendor name similarity
            session.run(
                """
                MATCH (s:Service), (v:Vulnerability)
                WHERE toLower(s.product) CONTAINS toLower(split(v.cpe, ':')[3])
                   OR toLower(s.name) CONTAINS toLower(split(v.cpe, ':')[3])
                MERGE (s)-[:HAS_VULNERABILITY]->(v)
                """
            )

        driver.close()
        logger.info("✅ Auto-linking completed successfully.")

    except Exception as e:
        logger.error(f"❌ Error during auto-linking: {e}")


# ==========================================================
#  COMBINED PIPELINE: IMPORT → ENRICH → LINK
# ==========================================================
def run_full_pipeline(nmap_xml_path: str):
    """
    Runs full Neo4j enrichment workflow:
    1. Import Nmap scan data
    2. Enrich vulnerabilities
    3. Auto-link services to vulnerabilities
    """
    logger.info("🚀 Starting full Neo4j data pipeline...")
    import_nmap_hosts_to_neo4j(nmap_xml_path)
    enrich_cves_from_nvd(limit=50)
    auto_link_services_to_vulns()
    logger.info("✅ Full pipeline completed successfully.")
