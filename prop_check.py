from neo4j import GraphDatabase
uri = "bolt://localhost:7687"
auth = ("neo4j", "Adomaa12@")
driver = GraphDatabase.driver(uri, auth=auth)
with driver.session() as session:
    res = session.run("MATCH (v:Vulnerability) RETURN DISTINCT labels(v), keys(v) LIMIT 1")
    for r in res: print("Vulnerability:", r)
            
    # Host/Asset to Finding mapping
    q = """
    MATCH (h)-[*1..2]-(f:Finding)
    WHERE any(l IN labels(h) WHERE l IN ['Host', 'Asset']) AND f.cve IS NOT NULL
    RETURN h.host AS host, f.cve AS cve, f.severity AS severity, f.name AS name LIMIT 5
    """
    res = session.run(q)
    print("\nHost to Finding:")
    for r in res: print(r)
driver.close()
