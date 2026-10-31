from neo4j import GraphDatabase
import os

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "Adomaa12@"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def test_queries():
    with driver.session() as session:
        print("--- THREAT ACTORS ---")
        res = session.run("MATCH (a:IntrusionSet) RETURN count(a) as cnt").single()
        print(f"Total Intrusion Sets: {res['cnt']}")
        
        res = session.run("MATCH (a:IntrusionSet) RETURN a.name LIMIT 5").data()
        print(f"Sample Actors: {[r['a.name'] for r in res]}")
        
        print("\n--- ACTOR -> TECHNIQUE LINKS ---")
        res = session.run("MATCH (a:IntrusionSet)-[:USES]->(t:Technique) RETURN count(*) as cnt").single()
        print(f"Total Uses relationships (Actor -> Tech): {res['cnt']}")
        
        print("\n--- VULNERABILITY -> TECHNIQUE LINKS ---")
        res = session.run("MATCH (c:Vulnerability)-[:TARGETS|MAPPED_TO]-(t:Technique) RETURN count(*) as cnt").single()
        print(f"Total CVE -> Tech relationships: {res['cnt']}")

test_queries()
