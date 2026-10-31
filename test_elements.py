from cyber_range.moduls.ui_neo4j_presets import build_cytoscape_node, build_cytoscape_edge
from cyber_range.services.neo4j_engine import Neo4jEngine

driver = Neo4jEngine().driver
cypher = "MATCH p=(a:Host)-[r:RUNS_SERVICE]->(s:Service) RETURN p LIMIT 10"
node_map = {}
edge_list = []

with driver.session() as session:
    records = session.run(cypher)
    for record in records:
        for value in record.values():
            if hasattr(value, "nodes") and hasattr(value, "relationships"):
                for node in value.nodes:
                    nid = str(node.element_id if hasattr(node, "element_id") else getattr(node, "id", None))
                    if nid not in node_map: node_map[nid] = build_cytoscape_node(node)
                for rel in value.relationships:
                    edge_list.append(build_cytoscape_edge(rel))

print("NODES:")
for k, v in node_map.items():
    print(v)

print("EDGES:")
for e in edge_list:
    print(e)
