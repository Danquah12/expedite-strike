# nmap_graph_builder.py
"""
Builds Neo4j CONNECTED relationships from Nmap scan results.
This enables Digital Twin propagation to function.
"""

from cyber_range.services.neo4j_engine import Neo4jEngine

neo = Neo4jEngine()


class NmapGraphBuilder:

    # ---------------------------------------------------------
    # Build CONNECTED relationships between discovered hosts
    # ---------------------------------------------------------
    def connect_discovered_hosts(self, discovered_ips):
        """
        Create a fully-connected graph for all IPs in the scan.

        discovered_ips = ["127.0.0.2", "192.168.174.2", ...]
        """

        if not discovered_ips or len(discovered_ips) < 2:
            return

        for a in discovered_ips:
            for b in discovered_ips:
                if a != b:
                    neo.query("""
                        MATCH (x:Asset {ip:$a}), (y:Asset {ip:$b})
                        MERGE (x)-[:CONNECTED]->(y)
                    """, {"a": a, "b": b})

    # ---------------------------------------------------------
    # Connect based on same /24 subnet
    # ---------------------------------------------------------
    def connect_by_subnet(self, discovered_ips):
        """
        Automatically group hosts in same /24 subnet and connect them.
        Example: 192.168.174.2 -> subnet key "192.168.174"
        """

        subnets = {}
        for ip in discovered_ips:
            parts = ip.split(".")
            if len(parts) != 4:
                continue

            subnet = ".".join(parts[:3])  # /24
            subnets.setdefault(subnet, []).append(ip)

        for subnet, hosts in subnets.items():
            if len(hosts) < 2:
                continue

            for a in hosts:
                for b in hosts:
                    if a != b:
                        neo.query("""
                            MATCH (x:Asset {ip:$a}), (y:Asset {ip:$b})
                            MERGE (x)-[:CONNECTED]->(y)
                        """, {"a": a, "b": b})

    # ---------------------------------------------------------
    # Connect based on open ports (reachable)
    # ---------------------------------------------------------
    def connect_by_services(self, scan_results):
        """
        scan_results = [
            {"ip": "192.168.174.2", "ports": [80, 443]},
            {"ip": "192.168.174.129", "ports": [22]},
            ...
        ]

        If two hosts have any open port, assume reachable.
        """

        for a in scan_results:
            for b in scan_results:
                if a["ip"] != b["ip"]:
                    if a["ports"] and b["ports"]:
                        neo.query("""
                            MATCH (x:Asset {ip:$a}), (y:Asset {ip:$b})
                            MERGE (x)-[:CONNECTED]->(y)
                        """, {"a": a["ip"], "b": b["ip"]})
