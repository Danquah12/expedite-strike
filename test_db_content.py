from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- NODE LABELS ---")
    for r in session.run("CALL db.labels() YIELD label RETURN label"):
        count = session.run("MATCH (n:`" + r['label'] + "`) RETURN count(n) as c").single()['c']
        print(f"{r['label']}: {count}")

    print("\n--- RELATIONSHIP TYPES ---")
    for r in session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"):
        count = session.run("MATCH ()-[r:`" + r['relationshipType'] + "`]->() RETURN count(r) as c").single()['c']
        print(f"{r['relationshipType']}: {count}")
    
    print("\n--- SAMPLE ASSET ---")
    for r in session.run("MATCH (a:Asset) RETURN a LIMIT 1"):
        print(r)
        
    print("\n--- SAMPLE VULN ---")
    for r in session.run("MATCH (v:Vulnerability) RETURN v LIMIT 1"):
        print(r)
