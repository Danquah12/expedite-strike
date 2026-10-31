
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_range.services.openvas_ingest import OpenVASIngestor
from neo4j import GraphDatabase
import os

# Neo4j connection
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("Adomaa12@")

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD),
)

def main():
    print("[*] OpenVAS import starting (connectivity test)")

    # Just test Neo4j connection for now
    with driver.session() as session:
        result = session.run("RETURN 'Neo4j OK' AS status").single()
        print("[+] Neo4j:", result["status"])

    print("[✓] Import skeleton working")

if __name__ == "__main__":
    main()
