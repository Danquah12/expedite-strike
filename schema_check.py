from neo4j import GraphDatabase
uri = "bolt://localhost:7687"
auth = ("neo4j", "Adomaa12@")
driver = GraphDatabase.driver(uri, auth=auth)
with driver.session() as session:
    res = session.run("""
    MATCH (a)-[r]->(b)
    WHERE any(l in labels(a) WHERE l IN ['Host', 'Service', 'Finding', 'AttackTechnique', 'KEV'])
       OR any(l in labels(b) WHERE l IN ['Host', 'Service', 'Finding', 'AttackTechnique', 'KEV'])
    RETURN DISTINCT labels(a) AS start_labels, type(r) AS rel_type, labels(b) AS end_labels
    """)
    for record in res:
        print(f"{record['start_labels']}-[{record['rel_type']}]->{record['end_labels']}")
driver.close()
