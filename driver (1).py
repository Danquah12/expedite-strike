import logging
from neo4j import GraphDatabase, basic_auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("neo4j_driver")

URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "Adomaa12@"

def get_driver():
    try:
        driver = GraphDatabase.driver(URI, auth=basic_auth(USER, PASSWORD))
        logger.info("Neo4j driver initialized.")
        return driver
    except Exception as e:
        logger.error(f"Neo4j driver initialization failed: {e}")
        raise
