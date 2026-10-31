import sys

GRAPH_QUERIES = {
    "Core Relationship Graphs": {
        "core_asset_service": "MATCH (a:Asset)-[r:HAS_SERVICE]->(s:Service) RETURN a, r, s",
        "core_asset_vuln": "MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN a, v",
    }
}

graph_type = "core_asset_vuln"
cypher = None
for category in GRAPH_QUERIES.values():
    if graph_type in category:
        cypher = category[graph_type]
        break

print(f"CYPHER: {cypher}")
