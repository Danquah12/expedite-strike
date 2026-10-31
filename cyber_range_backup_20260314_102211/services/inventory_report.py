from neo4j import GraphDatabase
import os


def list_assets_services_vulns():
    password = os.getenv("NEO4J_PASSWORD")
    if not password:
        raise RuntimeError("NEO4J_PASSWORD not set")

    driver = GraphDatabase.driver(
        "bolt://127.0.0.1:7687",
        auth=("neo4j", password)
    )

    query = """
    MATCH (a:Asset)
    OPTIONAL MATCH (a)-[:RUNS_SERVICE]->(s:Service)
    OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(sv:Vulnerability)
    RETURN
        a.host AS ip,
        collect(DISTINCT {
            name: s.name,
            port: s.port,
            protocol: s.protocol,
            product: s.product,
            version: s.version,
            source: s.source
        }) AS services,
        collect(DISTINCT {
            id: v.id,
            name: v.name,
            severity: v.severity,
            source: v.scanner
        }) +
        collect(DISTINCT {
            id: sv.id,
            name: sv.name,
            severity: sv.severity,
            source: sv.scanner
        }) AS vulnerabilities
    ORDER BY ip
    """

    results = []

    with driver.session() as session:
        for record in session.run(query):
            results.append({
                "ip": record["ip"],
                "services": [s for s in record["services"] if s["name"] is not None],
                "vulnerabilities": [v for v in record["vulnerabilities"] if v["id"] is not None]
            })

    driver.close()
    return results
