from neo4j import GraphDatabase
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))
with driver.session() as session:
    print("--- RELATIONSHIP DETAILS ---")
    q = """
    MATCH (a)-[r]->(b)
    RETURN head(labels(a)) AS src, type(r) AS rel, head(labels(b)) AS dst, count(*) AS count
    ORDER BY count DESC
    """
    for rec in session.run(q):
        print(f"{rec['src']} -[{rec['rel']}]-> {rec['dst']} : {rec['count']}")

