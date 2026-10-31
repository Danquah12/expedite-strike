import sys
from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    records = session.run("MATCH p=(a:Host)-[r:RUNS_SERVICE]->(s:Service) RETURN p LIMIT 1")
    for record in records:
        for value in record.values():
            print("Path:")
            for n in value.nodes:
                nid = str(n.element_id if hasattr(n, "element_id") else getattr(n, "id", None))
                print(f"Node: {nid}, exact object: {n}")
            for r in value.relationships:
                start_id = str(r.start_node.element_id if hasattr(r.start_node, "element_id") else getattr(r.start_node, "id", None))
                end_id = str(r.end_node.element_id if hasattr(r.end_node, "element_id") else getattr(r.end_node, "id", None))
                print(f"Rel: {start_id} -> {end_id}, exact object: {r}")
driver.close()
