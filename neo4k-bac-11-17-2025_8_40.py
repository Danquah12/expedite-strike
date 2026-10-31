import os
import xml.etree.ElementTree as ET
from datetime import datetime
from neo4j import GraphDatabase
import logging
import requests

# ==========================================================
#  LOGGING SETUP
# ==========================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("neo4j_integration")

# ==========================================================
#  NEO4J CONNECTION
# ==========================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def get_driver():
    """Initialize Neo4j driver connection"""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ==========================================================
#  CONSTRAINTS
# ==========================================================
def init_constraints():
    """Create unique constraints for node types"""
    driver = get_driver()
    with driver.session() as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.host IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.port) IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (scan:Scan) REQUIRE scan.id IS UNIQUE")
    driver.close()


# ==========================================================
#  IMPORT NMAP XML (with Historical Scans)
# ==========================================================
def import_nmap_hosts_to_neo4j(xml_path: str):
    """
    Parse Nmap XML and import into Neo4j as Assets, Services, and Scan records.
    Creates (:Scan)-[:DISCOVERED]->(:Asset)-[:RUNS_SERVICE]->(:Service).
    """
    logger.info(f"📡 Importing Nmap data from {xml_path}")
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = os.path.basename(xml_path).replace(".xml", "")

        driver = get_driver()
        with driver.session() as session:
            # Create Scan node
            session.run("""
                MERGE (scan:Scan {id:$id})
                SET scan.date=$date, scan.source_file=$file
            """, {"id": scan_id, "date": scan_time, "file": xml_path})

            count = 0
            for host in root.findall("host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    continue
                ip_addr = addr_el.get("addr")

                session.run("""
                    MERGE (a:Asset {host:$host})
                    SET a.last_seen=$time
                    MERGE (scan:Scan {id:$scan_id})
                    MERGE (scan)-[:DISCOVERED]->(a)
                """, {"host": ip_addr, "time": scan_time, "scan_id": scan_id})

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

                    session.run("""
                        MERGE (s:Service {name:$name, port:$port})
                        SET s.product=$prod, s.version=$ver, s.cpe=$cpe
                        WITH s
                        MATCH (a:Asset {host:$host})
                        MERGE (a)-[:RUNS_SERVICE]->(s)
                    """, {
                        "host": ip_addr, "name": s_name, "prod": s_prod,
                        "ver": s_ver, "cpe": cpe, "port": portid
                    })
                    count += 1

        driver.close()
        logger.info(f"✅ Imported {count} Nmap entries for scan '{scan_id}'")
        return count

    except Exception as e:
        logger.error(f"❌ Error importing Nmap XML: {e}")
        return 0


# ==========================================================
#  ENRICH CVES FROM NVD
# ==========================================================
def enrich_cves_from_nvd(limit=50):
    """
    Fetch CVE details from NVD API and enrich vulnerabilities in Neo4j.
    """
    logger.info("🧠 Starting NVD enrichment process...")
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    driver = get_driver()
    with driver.session() as session:
        q = """
        MATCH (v:Vulnerability)
        WHERE v.id STARTS WITH 'CVE-' AND 
              (v.cvss IS NULL OR v.last_updated IS NULL OR v.last_updated < date() - duration('P30D'))
        RETURN v.id AS cve
        LIMIT $limit
        """
        vulns = [r["cve"] for r in session.run(q, {"limit": limit})]

        if not vulns:
            logger.info("✅ No CVEs needing enrichment.")
            driver.close()
            return

        for cve_id in vulns:
            try:
                resp = requests.get(f"{NVD_API}?cveId={cve_id}", timeout=15)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                items = data.get("vulnerabilities", [])
                if not items:
                    continue
                cve_info = items[0]["cve"]
                desc = cve_info["descriptions"][0]["value"]
                metrics = cve_info.get("metrics", {})
                cvss = None

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                session.run("""
                    MATCH (v:Vulnerability {id:$cve})
                    SET v.description=$desc,
                        v.cvss=$cvss,
                        v.last_updated=date()
                """, {"cve": cve_id, "desc": desc, "cvss": cvss})
                logger.info(f"✅ Updated {cve_id} (CVSS: {cvss})")

            except Exception as e:
                logger.warning(f"⚠️ Error updating {cve_id}: {e}")

    driver.close()
    logger.info("✅ NVD enrichment complete.")


# ==========================================================
#  AUTO-LINK SERVICES TO VULNERABILITIES (Regex Safe)
# ==========================================================
def auto_link_vulnerabilities():
    """
    Auto-link services to vulnerabilities using regex-based CPE pattern matching.
    Avoids illegal STRING_CONTAINS predicate errors and logs summary.
    """
    logger.info("🔗 Starting auto-linking of Services to Vulnerabilities...")

    driver = get_driver()
    with driver.session() as session:
        q = """
        MATCH (s:Service)
        WHERE s.cpe IS NOT NULL
        WITH s
        MATCH (v:Vulnerability)
        WHERE toLower(v.id) =~ '.*' + toLower(replace(replace(s.cpe, 'cpe:/a:', ''), ':', '.*')) + '.*'
        MERGE (s)-[:HAS_VULNERABILITY]->(v)
        RETURN s.name AS service, count(v) AS vulns
        """
        results = session.run(q)
        linked_summary = [(r["service"], r["vulns"]) for r in results]
    driver.close()

    if linked_summary:
        logger.info("✅ Auto-linking completed. Summary:")
        for svc, count in linked_summary:
            logger.info(f"  • {svc}: {count} vulnerabilities linked")
    else:
        logger.warning("⚠️ No services linked to vulnerabilities.")


# ==========================================================
#  FULL PIPELINE: IMPORT → ENRICH → LINK
# ==========================================================
def run_full_pipeline(nmap_path: str):
    """Run full data ingestion & enrichment workflow."""
    init_constraints()
    count = import_nmap_hosts_to_neo4j(nmap_path)
    if count > 0:
        enrich_cves_from_nvd(limit=50)
        auto_link_vulnerabilities()
    else:
        logger.warning("⚠️ No data imported from Nmap scan.")
