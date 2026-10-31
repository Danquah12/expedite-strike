from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- ENABLES_EXPLOIT Connections ---")
    for r in session.run("MATCH (src)-[:ENABLES_EXPLOIT]->(dst) RETURN labels(src) as sl, labels(dst) as dl LIMIT 1"):
        print(f"{r['sl']} -> {r['dl']}")
    print("--- MAPS_TO Connections ---")
    for r in session.run("MATCH (src)-[:MAPS_TO]->(dst) RETURN labels(src) as sl, labels(dst) as dl LIMIT 1"):
        print(f"{r['sl']} -> {r['dl']}")
    print("--- INSTANCE_OF Connections ---")
    for r in session.run("MATCH (src)-[:INSTANCE_OF]->(dst) RETURN labels(src) as sl, labels(dst) as dl LIMIT 1"):
        print(f"{r['sl']} -> {r['dl']}")
