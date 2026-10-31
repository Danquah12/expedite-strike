from neo4j import GraphDatabase

uri = "bolt://localhost:7687"
auth = ("neo4j", "Adomaa12@")
driver = GraphDatabase.driver(uri, auth=auth)

with driver.session() as session:
    vulns = session.run("MATCH (f:Finding) WHERE f.cve IS NOT NULL RETURN f.cve AS cve, f.name AS name, f.severity AS severity LIMIT 5").data()
    hosts = session.run("MATCH (a:Asset) WHERE a.host IS NOT NULL RETURN a.host AS host LIMIT 5").data()
    services = session.run("MATCH (s:Service) RETURN s.name AS name, s.port AS port LIMIT 5").data()

print("VULNS:", vulns)
print("HOSTS:", hosts)
print("SERVICES:", services)
driver.close()
