from neo4j import GraphDatabase

def test_neo4j():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
    with driver.session() as session:
        records = session.run("MATCH p=(nt:Technique)-[r:PART_OF]->(ta:Tactic) RETURN p LIMIT 10")
        for record in records:
            value = record["p"]
            node_ids = [getattr(n, "element_id", getattr(n, "id")) for n in value.nodes]
            for rel in value.relationships:
                start_id = getattr(rel.start_node, "element_id", getattr(rel.start_node, "id"))
                if start_id not in node_ids:
                    print(f"MISSING start_id! {start_id} not in {node_ids}")
            print(node_ids)

test_neo4j()
