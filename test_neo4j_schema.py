from cyber_range.services.neo4j_engine import Neo4jEngine

engine = Neo4jEngine()
with engine.driver.session() as session:
    labels = session.run("MATCH (n) RETURN labels(n) as l, count(n) as c")
    print("--- LABELS ---")
    for rec in labels: print(rec)
    
    rels = session.run("MATCH ()-[r]->() RETURN type(r) as t, count(r) as c")
    print("--- RELATIONS ---")
    for rec in rels: print(rec)

    findings = session.run("MATCH (f:Finding) RETURN f.source as s, count(f) as c")
    print("--- FINDING SOURCES ---")
    for rec in findings: print(rec)
