from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))

with driver.session() as session:
    res = session.run("MATCH (t:Tactic) RETURN t.id, t.name")
    tactics = res.data()
    print("Tactics:")
    for t in tactics:
        print(t)
        
    res2 = session.run("MATCH (tech:Technique)-[:PART_OF]->(t:Tactic) RETURN t.id, count(tech) as count")
    counts = res2.data()
    print("\nTechniques per tactic:")
    for c in counts:
        print(c)
