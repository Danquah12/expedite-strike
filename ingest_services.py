import logging
from .driver import get_driver

logger = logging.getLogger("ingest_services")

def ingest_service(host, port, service_name):
    try:
        with get_driver().session() as session:
            session.run(
                "MATCH (a:Asset {host: $host}) "
                "MERGE (s:Service {name: $service, port: $port}) "
                "MERGE (a)-[:RUNS_SERVICE]->(s)",
                host=host, service=service_name, port=port)
            logger.info(f"Service {service_name}:{port} added to asset {host}")
    except Exception as e:
        logger.error(f"Failed to ingest service for {host}: {e}")
