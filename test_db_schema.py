import sys
from neo4j import GraphDatabase

with GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@")) as driver:
    with driver.session() as session:
        result = session.run("MATCH (h:Host)-[r1]-(s:Service)-[r2]-(f) RETURN labels(h), type(r1), labels(s), type(r2), labels(f) LIMIT 5")
        for r in result:
            print(r)
