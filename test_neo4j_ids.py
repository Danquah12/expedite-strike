from cyber_range.services.neo4j_engine import Neo4jEngine
e = Neo4jEngine()
with e.driver.session() as s:
    records = s.run("MATCH p=(a:Host)-[r:RUNS_SERVICE]->(s:Service) RETURN p LIMIT 1")
    for rec in records:
        for val in rec.values():
            if hasattr(val, "nodes"):
                for node in val.nodes:
                    print("NODE:", type(node), getattr(node, "element_id", None), getattr(node, "id", None))
                for rel in val.relationships:
                    print("EDGE:", type(rel), getattr(rel, "element_id", None))
                    print("  START:", getattr(rel.start_node, "element_id", None), getattr(rel.start_node, "id", None))
                    print("  END:", getattr(rel.end_node, "element_id", None), getattr(rel.end_node, "id", None))
