#!/usr/bin/env python3
# ==========================================================
#  EXPORT TO NEO4J (SQLite → Neo4j)
#  Aligns schema with neo4j_integration.py (uses cve_id)
# ==========================================================

import os
import sqlite3
import logging
from neo4j import GraphDatabase

# --- Setup logging ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("export_to_neo4j")

# --- Paths ---
SQLITE_PATH = "/root/vuln_intel/app/data/findings.db"

# --- Neo4j connection info ---
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "admin"  # 🔒 Change if needed

# ==========================================================
#  Function: connect_to_sqlite
# ==========================================================
def connect_to_sqlite():
    """Connect to the local SQLite database."""
    if not os.path.exists(SQLITE_PATH):
        raise FileNotFoundError(f"SQLite database not found at {SQLITE_PATH}")
    conn = sqlite3.connect(SQLITE_PATH)
    logger.info(f"📦 Connected to SQLite: {SQLITE_PATH}")
    return conn

# ==========================================================
#  Function: get_driver
# ==========================================================
def get_driver():
    """Establish connection to Neo4j."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# ==========================================================
#  Function: export_findings_to_neo4j
# ==========================================================
def export_findings_to_neo4j():
    """Export vulnerabilities and assets from SQLite to Neo4j."""
    conn = connect_to_sqlite()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, host, port, service, severity, cvss, cve_id, description, source, import_date
        FROM findings
        WHERE cve_id IS NOT NULL OR description IS NOT NULL
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        logger.warning("⚠️ No findings to export from SQLite.")
        return

    logger.info(f"🚀 Exporting {len(rows)} findings to Neo4j...")
    driver = get_driver()

    query = """
        MERGE (a:Asset {host: $host})
        ON CREATE SET a.first_seen = datetime()
        SET a.last_seen = datetime()

        MERGE (v:Vulnerability {cve_id: $cve_id})
        ON CREATE SET v.created = datetime()
        SET v.service = $service,
            v.port = $port,
            v.cvss = $cvss,
            v.severity = $severity,
            v.description = $description,
            v.source = $source,
            v.last_updated = date()

        MERGE (a)-[:HAS_VULNERABILITY]->(v)
    """

    with driver.session() as session:
        for row in rows:
            (
                _id, host, port, service, severity, cvss,
                cve_id, description, source, import_date
            ) = row

            # Skip if no host or CVE
            if not host or (not cve_id and not description):
                continue

            # Handle nulls safely
            port = port or "unknown"
            service = service or "unknown"
            severity = severity or "info"
            source = source or "unknown"
            cvss = float(cvss) if cvss not in (None, "", "NULL") else 0.0
            cve_id = cve_id or f"GEN-{_id}"  # fallback unique ID

            try:
                session.run(
                    query,
                    host=host,
                    port=str(port),
                    service=service,
                    severity=severity,
                    cvss=cvss,
                    cve_id=cve_id,
                    description=description,
                    source=source
                )
                logger.info(f"✅ Exported: {host} | {cve_id} | {severity}")
            except Exception as e:
                logger.error(f"❌ Error exporting record ({host}, {cve_id}): {e}")

    driver.close()
    logger.info("🏁 Export to Neo4j complete.")

# ==========================================================
#  MAIN EXECUTION
# ==========================================================
if __name__ == "__main__":
    try:
        export_findings_to_neo4j()
    except Exception as e:
        logger.error(f"💥 Export failed: {e}")
