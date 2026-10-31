import logging
from .driver import get_driver

logger = logging.getLogger("ingest_assets")

def ingest_asset(host):
    try:
        with get_driver().session() as session:
            session.run("MERGE (a:Asset {host: $host})", host=host)
            logger.info(f"Inserted asset: {host}")
    except Exception as e:
        logger.error(f"Failed to ingest asset {host}: {e}")
