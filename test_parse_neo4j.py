from neo4j import GraphDatabase

def test_parse():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
    with driver.session() as session:
        cypher = "MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN a, v"
        print("RUNNING:", cypher)
        records = list(session.run(cypher))
        print("RECORD COUNT:", len(records))

        for record in records:
            for value in record.values():
                print("TYPE:", type(value))
                if hasattr(value, "labels") and hasattr(value, "id"):
                    nid = str(value.element_id if hasattr(value, "element_id") else value.id)
                    print("  - NODE ID:", nid, "LABELS:", value.labels)

test_parse()
