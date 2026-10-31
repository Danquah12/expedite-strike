from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("Vulnerability keys:")
    print(session.run("MATCH (v:Vulnerability) RETURN keys(v) LIMIT 2").data())
    print("Finding keys:")
    print(session.run("MATCH (v:Finding) RETURN keys(v) LIMIT 2").data())
