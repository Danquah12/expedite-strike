import logging
from .driver import get_driver

logger = logging.getLogger("ingest_vulns")

def ingest_vulnerability(host, port, service, vuln_id, cvss=None):
    try:
        with get_driver().session() as session:
            session.run(
                "MATCH (s:Service {name: $service, port: $port}) "
                "MERGE (v:Vulnerability {id: $vuln}) "
                "SET v.cvss = $cvss "
                "MERGE (s)-[:HAS_VULNERABILITY]->(v)",
                service=service, port=port, vuln=vuln_id, cvss=cvss)
            logger.info(f"Inserted vulnerability {vuln_id} on {service}:{port}")
    except Exception as e:
        logger.error(f"Failed to ingest vulnerability {vuln_id}: {e}")
