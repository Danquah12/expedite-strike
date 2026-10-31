import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    result = session.run("""
        MATCH (a:Host)
        WITH coalesce(a.host, a.ip, a.name) AS host_id
        WHERE host_id IS NOT NULL AND host_id <> ''
        RETURN DISTINCT host_id AS host
        ORDER BY host
    """)
    assets = [row["host"] for row in result]
    print(f"Count: {len(assets)}")
    print(f"Assets: {assets}")
driver.close()
