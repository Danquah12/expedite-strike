# honeypot.py
"""
Real-Time Honeypot & Deception Engine
-------------------------------------
Creates deception assets, monitors attacker interaction,
and provides tripwire logic for:
 - Red team exercises
 - Wargaming
 - Detection engineering
 - Lateral movement traps
"""

from cyber_range.services.neo4j_engine import Neo4jEngine
from datetime import datetime


class HoneypotEngine:

    def __init__(self):
        self.neo4j = Neo4jEngine()

    # ---------------------------------------------------------
    # Deploy a fake honeypot asset in the graph
    # ---------------------------------------------------------
    def deploy_honeypot(self, name, segment="DeceptionNet"):
        cypher = """
        CREATE (h:Honeypot {
            id:$id,
            name:$name,
            deployed:$timestamp,
            segment:$segment,
            active:true
        })
        RETURN h
        """
        result = self.neo4j.query(
            cypher,
            {
                "id": f"honeypot-{name.lower()}",
                "name": name,
                "timestamp": str(datetime.utcnow()),
                "segment": segment
            }
        )
        return result[0]["h"] if result else None

    # ---------------------------------------------------------
    # Connect honeypot to an asset to lure attackers
    # ---------------------------------------------------------
    def link_to_asset(self, honeypot_id, host_ip):
        cypher = """
        MATCH (h:Honeypot {id:$h}), (a:Host {ip:$a})
        MERGE (a)-[:DECOY_EDGE]->(h)
        RETURN h, a
        """
        return self.neo4j.query(cypher, {"h": honeypot_id, "a": host_ip})

    # ---------------------------------------------------------
    # Check if attacker touched honeypot node (tripwire detection)
    # ---------------------------------------------------------
    def detect_interaction(self, attacker_node_id):
        cypher = """
        MATCH (attacker {id:$id})-[:REL*1..3]->(h:Honeypot)
        RETURN h
        """
        result = self.neo4j.query(cypher, {"id": attacker_node_id})
        if result:
            return [r["h"] for r in result]
        return []

    # ---------------------------------------------------------
    # Pull all active honeypots
    # ---------------------------------------------------------
    def list_honeypots(self):
        cypher = """
        MATCH (h:Honeypot)
        RETURN h
        """
        return [r["h"] for r in self.neo4j.query(cypher)]

    # ---------------------------------------------------------
    # Automatically redirect attackers to honeypots (graph deception)
    # ---------------------------------------------------------
    def auto_redirect(self, attacker_id):
        """
        Dynamically change the graph so attackers get pulled
        toward honeypots instead of real assets.
        """
        cypher = """
        MATCH (h:Honeypot), (a:Asset), (att {id:$id})
        MERGE (att)-[:REL]->(h)
        RETURN h
        """
        result = self.neo4j.query(cypher, {"id": attacker_id})
        return [r["h"] for r in result]

