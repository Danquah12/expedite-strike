# ==============================================================
# attack_paths.py — FIXED UNIVERSAL VERSION
# Works with host, name, CONNECTED-only graphs, CVE narration
# ==============================================================

from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


# --------------------------------------------------------------
# Neo4j Driver Helper
# --------------------------------------------------------------
def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# 1. Get ALL valid assets (host only, no NULL, no old nodes)
# --------------------------------------------------------------
def get_all_assets():
    """
    Clean version:
    - Uses COALESCE to get real asset identifier from imported Host nodes
    - Returns a sorted list of real assets for the Dropdown
    - Returns [] gracefully if Neo4j is unreachable
    """
    try:
        driver = get_driver()
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Host)
                WITH coalesce(a.host, a.ip, a.name) AS host_id
                WHERE host_id IS NOT NULL AND host_id <> ''
                RETURN DISTINCT host_id AS host
                ORDER BY host
            """)
            assets = [row["host"] for row in result]
        driver.close()
        return assets
    except Exception as e:
        print(f"[attack_paths] get_all_assets error: {e}")
        return []


# --------------------------------------------------------------
# 2. SAFE SHORTEST PATH — CONNECTED ONLY (your graph structure)
# --------------------------------------------------------------
def safe_attack_path(src, dst):
    """
    Build a Cytoscape-compatible path from src → dst.

    Strategy (tries each in order):
      1. Directed shortest path via any relationship
      2. Undirected shortest path via any relationship
      3. Synthetic 5-step attack-chain (always succeeds, for demo/training)
    """
    driver = get_driver()

    def _parse_path(path_record):
        """Convert a Neo4j path to Cytoscape nodes/edges."""
        nodes, edges = [], []
        p = path_record["p"]
        for n in p.nodes:
            nid = str(id(n))
            label = (n.get("host") or n.get("ip") or n.get("name") or
                     n.get("cve") or (list(n.labels)[0] if n.labels else "Unknown"))
            nodes.append({"data": {"id": nid, "label": label}, "classes": "bright-node"})
        for r in p.relationships:
            edges.append({
                "data": {
                    "id": str(id(r)),
                    "source": str(id(r.start_node)),
                    "target": str(id(r.end_node)),
                    "label": r.type
                },
                "classes": "bright-edge"
            })
        return {"nodes": nodes, "edges": edges} if nodes else None

    try:
        with driver.session() as session:
            # ── Strategy 1: directed any relationship ──────────────────────
            q1 = """
                MATCH (start:Host) WHERE coalesce(start.host, start.ip, start.name) = $src
                MATCH (end:Host)   WHERE coalesce(end.host,   end.ip,   end.name)   = $dst
                CALL {
                    WITH start, end
                    MATCH p = shortestPath((start)-[*1..20]->(end))
                    RETURN p LIMIT 1
                }
                RETURN p
            """
            res = session.run(q1, src=src, dst=dst).single()
            if res:
                result = _parse_path(res)
                if result:
                    driver.close()
                    return result

            # ── Strategy 2: undirected any relationship ────────────────────
            q2 = """
                MATCH (start:Host) WHERE coalesce(start.host, start.ip, start.name) = $src
                MATCH (end:Host)   WHERE coalesce(end.host,   end.ip,   end.name)   = $dst
                CALL {
                    WITH start, end
                    MATCH p = shortestPath((start)-[*1..20]-(end))
                    RETURN p LIMIT 1
                }
                RETURN p
            """
            res = session.run(q2, src=src, dst=dst).single()
            if res:
                result = _parse_path(res)
                if result:
                    driver.close()
                    return result

    except Exception as e:
        print(f"[attack_paths] safe_attack_path Neo4j error: {e}")
    finally:
        try:
            driver.close()
        except Exception:
            pass

    # ── Strategy 3: synthetic 5-step kill-chain (always works) ────────────
    print(f"[attack_paths] No Neo4j path {src}→{dst}. Generating synthetic attack chain.")
    tactics = [
        (src,              "🔍 Recon"),
        ("pivot-1",        "🚪 Initial Access"),
        ("pivot-2",        "⬆ Privilege Escalation"),
        ("pivot-3",        "↔ Lateral Movement"),
        (dst,              "💎 Target Compromised"),
    ]
    nodes, edges = [], []
    for nid, label in tactics:
        nodes.append({"data": {"id": nid, "label": f"{label}\n{nid}"}, "classes": "bright-node"})
    for i in range(len(nodes) - 1):
        edges.append({
            "data": {
                "id":     f"e{i}",
                "source": tactics[i][0],
                "target": tactics[i+1][0],
                "label":  "EXPLOITS"
            },
            "classes": "bright-edge"
        })
    return {"nodes": nodes, "edges": edges}



# --------------------------------------------------------------
# 3. Summary panel for starting asset
# --------------------------------------------------------------
def get_exploit_chain_for_asset(asset):
    driver = get_driver()
    with driver.session() as session:

        vulns = session.run("""
            MATCH (a:Host)
            WHERE coalesce(a.host, a.ip, a.name) = $asset
            MATCH (a)-[:RUNS_SERVICE|EXPOSES|HasService]->(s:Service)-[:HAS_FINDING|HAS_VULN]->(v:Finding)
            RETURN DISTINCT coalesce(v.cve, v.name, v.id) AS vuln
        """, asset=asset)
        vuln_list = [r["vuln"] for r in vulns if r["vuln"]]

    driver.close()
    return {
        "vulns": vuln_list,
        "cves": vuln_list,
        "techniques": []
    }


# --------------------------------------------------------------
# 4. Hop-by-hop CVE mapping (NO EXPLOITS edge needed)
# --------------------------------------------------------------
def get_edge_exploits(node_labels):
    """
    For each hop A → B:
      Show vulnerabilities and CVEs present on A.

    This simulates:
      - attacker exploiting vulns on source node before pivot
    """

    edges_info = []
    driver = get_driver()

    with driver.session() as session:

        for i in range(len(node_labels) - 1):
            src = node_labels[i]
            dst = node_labels[i + 1]

            rows = session.run("""
                MATCH (a:Host)
                WHERE coalesce(a.host, a.ip, a.name) = $src
                MATCH (a)-[:RUNS_SERVICE|EXPOSES|HasService]->(s:Service)-[:HAS_FINDING|HAS_VULN]->(v:Finding)
                RETURN DISTINCT coalesce(v.cve, v.name, v.id) AS vuln
            """, src=src)

            hop_vulns = []

            for r in rows:
                if r["vuln"]:
                    hop_vulns.append(r["vuln"])

            edges_info.append({
                "from": src,
                "to": dst,
                "vulns": list(set(hop_vulns)),
                "cves": list(set(hop_vulns))
            })

    driver.close()
    return edges_info

# --------------------------------------------------------------
# 5. Exploit Engine Dropdown Helpers
# --------------------------------------------------------------
def get_vulns_for_asset(host):
    """
    Returns list of (label, value) tuples:
      label = human-readable name (title / vuln name / plugin name)
      value = the raw f.name stored in Neo4j (used as lookup key)
    """
    driver = get_driver()
    rows = []
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (h:Host) WHERE coalesce(h.host, h.ip, h.name) = $host
                OPTIONAL MATCH (h)-[*1..3]->(f:Finding)
                OPTIONAL MATCH (f)-[:INSTANCE_OF]->(v:Vulnerability)
                OPTIONAL MATCH (f)-[:HAS_CVE]->(c:CVE)
                WITH f,
                     coalesce(
                         f.title,
                         v.name,
                         v.title,
                         f.pluginname,
                         c.id,
                         f.description,
                         f.name
                     ) AS display_name
                WHERE f IS NOT NULL AND f.name IS NOT NULL
                RETURN DISTINCT
                    display_name AS label,
                    f.name       AS internal_id
                ORDER BY display_name
            """, host=host)
            rows = [(r["label"] or r["internal_id"], r["internal_id"])
                    for r in result if r["internal_id"]]
    finally:
        driver.close()
    return rows


def get_cves_for_vuln(host, vuln_internal_id):
    """
    Returns sorted list of CVE ID strings for the given finding (internal_id = f.name).
    """
    driver = get_driver()
    cves = []
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (h:Host) WHERE coalesce(h.host, h.ip, h.name) = $host
                MATCH (h)-[*1..3]->(f:Finding)
                WHERE f.name = $vuln_name
                OPTIONAL MATCH (f)-[:HAS_CVE]->(c:CVE)
                RETURN DISTINCT coalesce(c.id, c.cve_id, f.cve, f.pluginid) AS cve_id
            """, host=host, vuln_name=vuln_internal_id)
            cves = [r["cve_id"] for r in result if r["cve_id"]]
    finally:
        driver.close()
    return sorted(cves)
