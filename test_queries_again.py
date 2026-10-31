from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- RUNS_SERVICE Connections ---")
    for r in list(session.run("MATCH (h:Host)-[r:RUNS_SERVICE]->(s:Service) RETURN h, r, s LIMIT 5")):
        print(r)
    
    print("\n--- AFFECTED_BY Connections ---")
    for r in list(session.run("MATCH (h:Host)-[:AFFECTED_BY]->(f:Finding)-[:INSTANCE_OF]->(v:Vulnerability) RETURN h, f, v LIMIT 5")):
        print(r)
