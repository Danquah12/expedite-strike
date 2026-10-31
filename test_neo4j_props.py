from neo4j import GraphDatabase

def test_neo4j():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
    with driver.session() as session:
        records = session.run("MATCH (t:Technique) RETURN t LIMIT 1")
        for record in records:
            print("Technique:", dict(record["t"]))
        records = session.run("MATCH (ta:Tactic) RETURN ta LIMIT 1")
        for record in records:
            print("Tactic:", dict(record["ta"]))

test_neo4j()
