import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    records = session.run("MATCH (n:Computer) RETURN n.name, labels(n) LIMIT 10")
    for r in records:
        print("Computer:", r["n.name"], r["labels(n)"])
driver.close()
