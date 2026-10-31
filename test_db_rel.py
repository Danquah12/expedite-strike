from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- HAS_VULNERABILITY Connections ---")
    for r in session.run("MATCH (src)-[:HAS_VULNERABILITY]->(dst) RETURN labels(src) as sl, labels(dst) as dl LIMIT 5"):
        print(f"{r['sl']} -> {r['dl']}")
    
    print("--- HasVulnerability Connections ---")
    for r in session.run("MATCH (src)-[:HasVulnerability]->(dst) RETURN labels(src) as sl, labels(dst) as dl LIMIT 5"):
        print(f"{r['sl']} -> {r['dl']}")
