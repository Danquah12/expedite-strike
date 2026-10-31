import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- Top Labels ---")
    records = session.run("MATCH (n) RETURN labels(n) AS labels, count(*) AS count ORDER BY count DESC LIMIT 10")
    for r in records:
        print(r["labels"], r["count"])
    
    print("\n--- Sample Asset/Host Nodes ---")
    records = session.run("MATCH (n:Host) RETURN n.host, n.ip, n.name LIMIT 5")
    for r in records:
        print("Host:", r["n.host"], "| IP:", r["n.ip"], "| Name:", r["n.name"])
        
    records = session.run("MATCH (n:Asset) RETURN n.name, n.ip LIMIT 5")
    if records.peek():
        for r in records:
            print("Asset:", r["n.name"], "| IP:", r["n.ip"])

driver.close()
