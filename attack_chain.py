# attack_chain.py
# Standard Attack Chain Simulator (Option A)

from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "Adomaa12@"


def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


# --------------------------------------------------------
# Load Assets, Services, Vulnerabilities, Techniques
# --------------------------------------------------------
def load_attack_graph():
    driver = get_driver()
    session = driver.session()

    query = """
    MATCH (a:Asset)-[:RUNS_SERVICE]->(s:Service)
    OPTIONAL MATCH (s)-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(t:Technique)
    RETURN a, s, v, t
    """

    data = list(session.run(query))
    session.close()
    driver.close()

    assets = {}
    vulns = {}
    techniques = {}

    for r in data:
        a = r["a"]
        s = r["s"]
        v = r["v"]
        t = r["t"]

        host = a["host"]
        service_id = s["name"] + ":" + str(s["port"])

        if host not in assets:
            assets[host] = {"services": set(), "vulns": set()}

        assets[host]["services"].add(service_id)

        if v:
            vid = v["id"]
            vulns[vid] = {
                "id": vid,
                "asset": host,
                "service": service_id,
                "cvss": v.get("cvss", 0),
            }
            assets[host]["vulns"].add(vid)

            if t:
                techniques[vid] = t["id"]

    return assets, vulns, techniques


# --------------------------------------------------------
# Step 2: Compute Attack Chain (Shortest Path Style)
# --------------------------------------------------------
def compute_attack_chain(start_asset, crown_jewel, assets, vulns, techniques):
    """
    Basic attack chain:
    1. Start at attacker asset (external or compromised host)
    2. Move through reachable assets
    3. Use vulnerabilities mapped to techniques
    4. End at crown jewel
    """

    chain = []
    risk_score = 0
    visited = set()

    # Very basic BFS exploration
    queue = [(start_asset, [])]

    while queue:
        node, path = queue.pop(0)

        if node in visited:
            continue
        visited.add(node)

        # If we reached the crown jewel, done
        if node == crown_jewel:
            return path + [{
                "asset": node,
                "technique": "GOAL",
                "vuln": None,
                "cvss": None
            }], risk_score

        # Explore vulnerabilities on this node
        if node in assets:
            for vid in assets[node]["vulns"]:
                vuln = vulns[vid]
                step = {
                    "asset": node,
                    "technique": techniques.get(vid, "UNKNOWN"),
                    "vuln": vid,
                    "cvss": vuln["cvss"]
                }
                risk_score += vuln["cvss"]
                chain.append(step)

        # Simulate adjacency: services imply reachability (simplified)
        for other in assets:
            if other != node:
                queue.append((other, chain.copy()))

    return chain, risk_score
