import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("Connecting all Host nodes...")
    session.run("""
        MATCH (h1:Host), (h2:Host)
        WHERE id(h1) <> id(h2)
        MERGE (h1)-[:CONNECTED]->(h2)
    """)
    print("Done connecting Host nodes!")
    
    # Let's count the new connections
    res = session.run("MATCH ()-[r:CONNECTED]->() RETURN count(r) AS c").single()
    print("Total :CONNECTED relationships:", res["c"])
driver.close()
