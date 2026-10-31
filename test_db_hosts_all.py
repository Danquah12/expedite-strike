import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    result = session.run("MATCH (a:Host) RETURN id(a) as id, a.host as host, a.ip as ip, a.name as name")
    for r in result:
        print(f"ID: {r['id']}, Host: {r['host']}, IP: {r['ip']}, Name: {r['name']}")
driver.close()
