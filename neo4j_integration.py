import os
import xml.etree.ElementTree as ET
from datetime import datetime
from neo4j import GraphDatabase
import logging
import requests

# ==========================================================
#  LOGGING SETUP
# ==========================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("neo4j_integration")

# ==========================================================
#  NEO4J CONNECTION CONFIG
# ==========================================================
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def get_driver():
    """Initialize and return Neo4j driver connection"""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# ==========================================================
#  CREATE CONSTRAINTS
# ==========================================================
def init_constraints():
    """Ensure all Neo4j constraints exist to prevent duplicates"""
    driver = get_driver()
    with driver.session() as session:
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.host IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.port) IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE")
        session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (scan:Scan) REQUIRE scan.id IS UNIQUE")
    driver.close()
    logger.info("✅ Constraints verified.")


# ==========================================================
#  IMPORT NMAP XML → ASSETS & SERVICES
# ==========================================================
def import_nmap_hosts_to_neo4j(xml_path: str):
    """Parse Nmap XML file and insert Assets, Services, and Scan nodes"""
    logger.info(f"📡 Importing Nmap data from {xml_path}")
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = os.path.basename(xml_path).replace(".xml", "")

        driver = get_driver()
        with driver.session() as session:
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
        logger.info(f"✅ Imported {count} open ports from Nmap scan.")
        return count

    except Exception as e:
        logger.error(f"❌ Error importing Nmap XML: {e}")
        return 0


# ==========================================================
#  CREATE VULNERABILITIES FROM CPEs (NVD LOOKUPS)
# ==========================================================
def create_vulns_from_cpe(limit=10):
    """Query NVD for each unique CPE and create Vulnerability nodes"""
    logger.info("🧩 Generating Vulnerability nodes from CPEs...")
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    driver = get_driver()

    with driver.session() as session:
        cpe_results = session.run("""
            MATCH (s:Service)
            WHERE s.cpe IS NOT NULL
            RETURN DISTINCT s.cpe AS cpe
            LIMIT $limit
        """, {"limit": limit})
        cpes = [r["cpe"] for r in cpe_results]

        if not cpes:
            logger.warning("⚠️ No CPEs found to map to vulnerabilities.")
            driver.close()
            return

        for cpe in cpes:
            try:
                logger.info(f"🔎 Querying NVD for {cpe}")
                resp = requests.get(f"{NVD_API}?cpeName={cpe}", timeout=25)
                if resp.status_code != 200:
                    continue

                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                for item in vulns:
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"]
                    metrics = item["cve"].get("metrics", {})
                    cvss = None
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                    session.run("""
                        MERGE (v:Vulnerability {id:$id})
                        SET v.description=$desc,
                            v.cvss=$cvss,
                            v.source='NVD',
                            v.created=date()
                    """, {"id": cve_id, "desc": desc, "cvss": cvss})
                    logger.info(f"  ➕ Created/updated {cve_id} (CVSS: {cvss})")

            except Exception as e:
                logger.warning(f"⚠️ Error creating vulns for {cpe}: {e}")

    driver.close()
    logger.info("✅ Finished generating vulnerabilities from CPEs.")


# ==========================================================
#  ENRICH CVES FROM NVD (Adds severity classification + CVSS)
# ==========================================================
def enrich_cves_from_nvd(limit=50):
    """
    Fetch CVE details from NVD and enrich Vulnerability nodes
    with description, CVSS score, and severity classification.
    """
    logger.info("🧠 Starting NVD enrichment process...")
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    driver = get_driver()

    with driver.session() as session:
        q = """
        MATCH (v:Vulnerability)
        WHERE v.id STARTS WITH 'CVE-'
        AND (v.cvss IS NULL OR v.last_updated IS NULL OR v.last_updated < date() - duration('P30D'))
        RETURN v.id AS cve
        LIMIT $limit
        """
        vulns = [r["cve"] for r in session.run(q, {"limit": limit})]

        # If no CVEs need enrichment, create new ones from CPEs
        if not vulns:
            logger.info("✅ No existing CVEs needing enrichment — creating new ones from CPEs.")
            driver.close()
            create_vulns_from_cpe(limit=20)
            return

        for cve_id in vulns:
            try:
                resp = requests.get(f"{NVD_API}?cveId={cve_id}", timeout=20)
                if resp.status_code != 200:
                    logger.warning(f"⚠️ NVD API error {resp.status_code} for {cve_id}")
                    continue

                data = resp.json()
                items = data.get("vulnerabilities", [])
                if not items:
                    continue

                # Extract details
                cve_info = items[0]["cve"]
                desc = cve_info["descriptions"][0]["value"]
                metrics = cve_info.get("metrics", {})
                cvss = None

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                # --- Derive severity label ---
                if cvss is None:
                    severity = "Unknown"
                elif cvss >= 9.0:
                    severity = "Critical"
                elif cvss >= 7.0:
                    severity = "High"
                elif cvss >= 4.0:
                    severity = "Medium"
                elif cvss > 0.0:
                    severity = "Low"
                else:
                    severity = "Informational"

                # --- Update vulnerability node in Neo4j ---
                session.run("""
                    MATCH (v:Vulnerability {id:$cve})
                    SET v.description=$desc,
                        v.cvss=$cvss,
                        v.type=$severity,
                        v.last_updated=date(),
                        v.source='NVD'
                """, {"cve": cve_id, "desc": desc, "cvss": cvss, "severity": severity})

                logger.info(f"✅ Updated {cve_id}: {severity} (CVSS {cvss})")

            except Exception as e:
                logger.warning(f"⚠️ Error enriching {cve_id}: {e}")

    driver.close()
    logger.info("✅ NVD enrichment complete — severity and CVSS updated.")


# ==========================================================
#  AUTO-LINK SERVICES → VULNERABILITIES
# ==========================================================
def auto_link_vulnerabilities():
    """Auto-link Service → Vulnerability based on product/vendor text match"""
    logger.info("🔗 Starting enhanced auto-linking of Services to Vulnerabilities...")
    driver = get_driver()
    with driver.session() as session:
        q = """
        MATCH (s:Service)
        WHERE s.cpe IS NOT NULL
        WITH s, split(replace(s.cpe, 'cpe:/a:', ''), ':') AS parts
        WITH s, parts[0] AS vendor, parts[1] AS product
        MATCH (v:Vulnerability)
        WHERE toLower(v.description) CONTAINS toLower(product)
           OR toLower(v.id) CONTAINS toLower(product)
           OR toLower(v.description) CONTAINS toLower(vendor)
        MERGE (s)-[r:HAS_VULNERABILITY]->(v)
        SET r.linked_at=datetime(), r.cvss=v.cvss
        RETURN s.name AS service, count(v) AS vulns
        """
        results = session.run(q)
        linked = [(r["service"], r["vulns"]) for r in results]
    driver.close()

    if linked:
        for svc, count in linked:
            logger.info(f"  • {svc}: {count} vulnerabilities linked")
    else:
        logger.warning("⚠️ No services linked to vulnerabilities.")


# ==========================================================
#  FETCH ATTACK PATHS OR ANY GRAPH QUERY
# ==========================================================
def fetch_graph(query: str):
    """Run Cypher query and return list of records"""
    driver = get_driver()
    with driver.session() as session:
        results = [dict(r) for r in session.run(query)]
    driver.close()
    return results


# ==========================================================
#  HEALTH CHECK
# ==========================================================
def check_neo4j_health():
    """Check if Neo4j is online and reachable"""
    try:
        driver = get_driver()
        with driver.session() as session:
            session.run("RETURN 1")
        driver.close()
        return True
    except Exception:
        return False


# ==========================================================
#  FULL PIPELINE
# ==========================================================
def run_full_pipeline(nmap_path: str):
    """Run entire ingestion and enrichment workflow"""
    init_constraints()
    count = import_nmap_hosts_to_neo4j(nmap_path)
    if count > 0:
        create_vulns_from_cpe(limit=20)
        enrich_cves_from_nvd(limit=50)
        auto_link_vulnerabilities()
        logger.info("✅ Full Neo4j ingestion & enrichment pipeline complete.")
    else:
        logger.warning("⚠️ No hosts imported — check Nmap XML path.")



# ==========================================================
#  BUILD GRAPH FOR CYTOSCAPE (Nodes + Edges)
# ==========================================================
def get_full_graph():
    """
    Pull all nodes + relationships from Neo4j in a format compatible
    with Dash Cytoscape.
    """
    driver = get_driver()
    elements = []

    with driver.session() as session:
        # ---- Fetch nodes ----
        nodes = session.run("""
            MATCH (n)
            RETURN id(n) AS id, labels(n) AS labels, properties(n) AS props
        """)

        for record in nodes:
            node_id = record["id"]
            labels = record["labels"]
            props = record["props"]

            label = props.get("name") or props.get("id") or list(labels)[0]

            elements.append({
                "data": {
                    "id": str(node_id),
                    "label": label,
                    **props
                }
            })

        # ---- Fetch relationships ----
        rels = session.run("""
            MATCH (a)-[r]->(b)
            RETURN id(a) AS src, id(b) AS dst, type(r) AS type
        """)

        for r in rels:
            elements.append({
                "data": {
                    "source": str(r["src"]),
                    "target": str(r["dst"]),
                    "label": r["type"]
                }
            })

    driver.close()
    return elements
