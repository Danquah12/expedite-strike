from neo4j import GraphDatabase

def test_neo4j():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
    with driver.session() as session:
        records = session.run("MATCH p=(nt:Technique)-[r:PART_OF]->(ta:Tactic) RETURN p LIMIT 1")
        for record in records:
            value = record["p"]
            node1 = value.nodes[0]
            rel = value.relationships[0]
            print(f"Node element_id: {getattr(node1, 'element_id', 'MISSING')}, Node id: {getattr(node1, 'id', 'MISSING')}")
            print(f"Rel start_node element_id: {getattr(rel.start_node, 'element_id', 'MISSING')}, id: {getattr(rel.start_node, 'id', 'MISSING')}")
            print(f"Rel element_id: {getattr(rel, 'element_id', 'MISSING')}, id: {getattr(rel, 'id', 'MISSING')}")

test_neo4j()
