import sys
from cyber_range.services.digital_twin import DigitalTwin

dt = DigitalTwin()

assets = dt.db.run_query("""
    MATCH (a:Host)
    RETURN id(a) AS id, coalesce(a.host, a.ip, a.name, toString(id(a))) AS host LIMIT 5
""")
print("Assets:", assets)

edges = dt.db.run_query("""
    MATCH (a:Host)-[:CONNECTED]-(b:Host)
    RETURN id(a) AS src, id(b) AS dst LIMIT 5
""")
print("Edges:", edges)

print("Summary counts:", dt.db.run_query_simple("MATCH (a:Host) RETURN count(a)")[0])

try:
    risk = dt.db.run_query("""
        MATCH (a:Host) WHERE a.host='192.168.1.101' OR a.ip='192.168.1.101' OR a.name='192.168.1.101'
        OPTIONAL MATCH (a)-[*1..2]->(v) WHERE labels(v)[0] IN ['Finding', 'Vulnerability']
        OPTIONAL MATCH (v)-[:HAS_CVE]->(c:CVE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(t:Technique)
        RETURN
            max(c.epss) AS epss,
            max(c.kev) AS kev,
            collect(DISTINCT t.id) AS techniques
    """)
    print("Risk:", risk)
except Exception as e:
    print("Error:", e)
