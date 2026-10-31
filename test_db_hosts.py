import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    records = session.run("MATCH (h:Host) RETURN count(h) AS c")
    for r in records:
        print("Total Hosts:", r["c"])
driver.close()
