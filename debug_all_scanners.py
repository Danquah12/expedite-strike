#!/usr/bin/env python3
"""
Comprehensive pipeline diagnostic — checks ALL scanners against Neo4j
and simulates the exact pipeline query for each one.
"""
import sys
sys.path.insert(0, "/opt/vuln_intel/app")

try:
    from neo4j_engine import get_driver
    drv = get_driver()
except Exception:
    from neo4j import GraphDatabase
    drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Adomaa12@"))

WEB_SCANNERS = ["zap", "nuclei", "AegisProbe"]
NET_SCANNERS = ["nmap", "pentest-engine"]
ALL_SCANNERS = WEB_SCANNERS + NET_SCANNERS

with drv.session() as s:

    print("\n" + "="*70)
    print("=== STEP 1: Finding counts per scanner ===")
    rows = s.run("""
        MATCH (f:Finding)
        RETURN coalesce(f.source, '__NULL__') AS src, count(*) AS n
        ORDER BY n DESC
    """).data()
    for r in rows:
        print(f"  {r['src']:<25} {r['n']}")

    print("\n" + "="*70)
    print("=== STEP 2: Web-mode pipeline query per scanner ===")
    print("    (simulates: MATCH (f:Finding) WHERE f.source IN ['X'])")
    for sc in WEB_SCANNERS:
        recs = s.run(f"""
            MATCH (f:Finding)
            WHERE f.source = $src
            RETURN DISTINCT
                coalesce(f.url, f.uri, f.path, f.host, '') AS raw_target,
                coalesce(f.host, '')                        AS raw_host,
                coalesce(f.port, '')                        AS raw_port
            LIMIT 5
        """, src=sc).data()
        print(f"\n  [{sc}] → {len(recs)} sample records (LIMIT 5)")
        for r in recs:
            print(f"    raw_target={r['raw_target']!r:45}  host={r['raw_host']!r:25}  port={r['raw_port']!r}")
        if not recs:
            # Try case-insensitive fallback
            recs2 = s.run(f"""
                MATCH (f:Finding)
                WHERE toLower(f.source) = toLower($src)
                RETURN DISTINCT f.source AS actual_src LIMIT 3
            """, src=sc).data()
            if recs2:
                print(f"    ⚠ Case mismatch! Actual sources: {[r['actual_src'] for r in recs2]}")
            else:
                print(f"    ✗ No findings for source='{sc}' in Neo4j at all")

    print("\n" + "="*70)
    print("=== STEP 3: Network-mode pipeline query per scanner ===")
    print("    (simulates: MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service))")
    for sc in NET_SCANNERS:
        # First check: do findings exist with this source?
        f_count = s.run("MATCH (f:Finding) WHERE f.source=$s RETURN count(*) AS n", s=sc).single()["n"]
        print(f"\n  [{sc}] → {f_count} findings in neo4j")

        # Check if Service nodes have .host property
        svc_host_sample = s.run("""
            MATCH (srv:Service)
            WHERE srv.source = $s
            RETURN srv.host AS h, srv.port AS p LIMIT 3
        """, s=sc).data()
        print(f"    Service.source='{sc}' sample: {svc_host_sample}")

        # Standard network mode query
        recs = s.run("""
            MATCH (h:Host)-[:RUNS_SERVICE]->(srv:Service)
            WHERE h.ip IS NOT NULL
            RETURN DISTINCT h.ip AS ip, srv.port AS port,
                   coalesce(srv.name, srv.product, '') AS service
            LIMIT 5
        """).data()
        print(f"    Host→Service MATCH: {len(recs)} sample records")
        for r in recs:
            print(f"      ip={r['ip']!r:20}  port={r['port']!r:8}  svc={r['service']!r}")

    print("\n" + "="*70)
    print("=== STEP 4: Check f.path for AegisProbe (full URL stored there) ===")
    ap_recs = s.run("""
        MATCH (f:Finding) WHERE f.source = 'AegisProbe'
        RETURN f.path AS path, f.url AS url, f.host AS host
        LIMIT 5
    """).data()
    for r in ap_recs:
        print(f"  path={r['path']!r:50}  url={r['url']!r:20}  host={r['host']!r}")

    print("\n" + "="*70)
    print("=== STEP 5: Check nuclei fields ===")
    nuc_recs = s.run("""
        MATCH (f:Finding) WHERE f.source = 'nuclei'
        RETURN f.url AS url, f.path AS path, f.host AS host, f.port AS port
        LIMIT 5
    """).data()
    for r in nuc_recs:
        print(f"  url={r['url']!r:40}  path={r['path']!r:30}  host={r['host']!r:20}  port={r['port']!r}")

    print("\n" + "="*70)
    print("=== STEP 6: Check pentest-engine fields ===")
    pe_recs = s.run("""
        MATCH (f:Finding) WHERE f.source = 'pentest-engine'
        RETURN f.url AS url, f.path AS path, f.host AS host, f.port AS port,
               f.ip AS ip LIMIT 5
    """).data()
    for r in pe_recs:
        print(f"  url={r['url']!r:30}  host={r['host']!r:20}  ip={r['ip']!r:20}  port={r['port']!r}")

print("\n✅ Diagnostic complete.\n")
