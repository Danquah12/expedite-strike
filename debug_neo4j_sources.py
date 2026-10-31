#!/usr/bin/env python3
"""Quick Neo4j diagnostic — see what f.source values exist for Findings."""
import sys
sys.path.insert(0, "/opt/vuln_intel/app")

from cyber_range.services.neo4j_engine import Neo4jEngine

engine = Neo4jEngine()
with engine.driver.session() as s:
    print("=== All distinct f.source values in Finding nodes ===")
    rows = s.run("""
        MATCH (f:Finding)
        RETURN coalesce(f.source, '__NULL__') AS src, count(f) AS n
        ORDER BY n DESC
    """).data()
    for r in rows:
        print(f"  source={r['src']!r:40s}  count={r['n']}")

    print()
    print("=== f.url, f.host, f.port sample for source='zap' ===")
    rows2 = s.run("""
        MATCH (f:Finding)
        WHERE f.source = 'zap'
        RETURN f.url AS url, f.host AS host, f.port AS port
        LIMIT 5
    """).data()
    if rows2:
        for r in rows2:
            print(f"  url={r['url']!r}  host={r['host']!r}  port={r['port']!r}")
    else:
        print("  (no findings with source='zap')")

    print()
    print("=== f.url, f.host, f.port for ANY Finding LIMIT 5 ===")
    rows3 = s.run("""
        MATCH (f:Finding)
        RETURN f.source AS src, f.url AS url, f.host AS host, f.port AS port
        LIMIT 5
    """).data()
    for r in rows3:
        print(f"  src={r['src']!r:20s} url={r['url']!r:30s} host={r['host']!r}  port={r['port']!r}")

engine.driver.close()
print("\nDone.")
