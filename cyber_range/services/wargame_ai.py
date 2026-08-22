# wargame_ai.py
"""
Autonomous Cyber Wargame Engine
-------------------------------
Simulates Red-Team vs Blue-Team AI-driven engagements
using a Neo4j attack graph.

SAFE MODE:
 - No exploit code
 - Conceptual actions only
 - Defensive and analytical focus
"""

import os
from datetime import datetime
import openai

from cyber_range.services.neo4j_engine import Neo4jEngine
from cyber_range.services.honeypot import HoneypotEngine


# ---------------------------------------------------------
# OpenAI configuration (safe)
# ---------------------------------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY


class WargameAI:
    """
    Core cyber wargame simulation engine.
    This class does NOT auto-run and must be invoked explicitly
    (e.g., from a Dash callback or controller).
    """

    def __init__(self):
        self.neo4j = Neo4jEngine()
        self.honey = HoneypotEngine()
        self.active_chain_override = None
        self.active_env_override = None
        self.client = openai.OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

    # ---------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------
    @staticmethod
    def _node_label(node):
        """
        Safely extract a meaningful identifier from a Neo4j node.
        """
        for key in (
            "name",
            "id",
            "cve",
            "cve_id",
            "hostname",
            "asset_id",
            "title",
            "label"
        ):
            if key in node:
                return str(node[key])

        # Fallback: stringify full property set
        return str(dict(node))

    def _serialize_path(self, path):
        """
        Convert Neo4j Path → ordered list of node labels.
        """
        if not path or not hasattr(path, "nodes"):
            return []

        return [self._node_label(n) for n in path.nodes]

    # ---------------------------------------------------------
    # Core function: run one full wargame round
    # ---------------------------------------------------------
    def run_round(self, start, target):
        """
        Produces:
        - Red Team move
        - Blue Team move
        - Outcome
        """

        # 1) Pull environment context
        # Use SimulationEngine overrides if provided to evaluate current tactical state
        if self.active_env_override and self.active_chain_override:
            nodes = [f"Attack node: {n}" for n in self.active_chain_override]
            edges = "Linear sequence representing attack execution."
            attack_chain = self.active_chain_override
            env_state = f"Defense={self.active_env_override['defense_strength']}x, Visibility={self.active_env_override['visibility']}x, Seg={self.active_env_override['segmentation']}x"
        else:
            try:
                full_graph = self.neo4j.get_full_graph()
                nodes = [self._node_label(record["n"]) for record in full_graph if "n" in record]
                edges = [str(record["r"]) for record in full_graph if "r" in record]
            except Exception as e:
                return f"ERROR: Unable to retrieve graph context: {e}"

            try:
                path = self.neo4j.get_shortest_path(start, target)
                attack_chain = self._serialize_path(path)
            except Exception:
                path = None
                attack_chain = ["NO VALID ATTACK PATH FOUND"]
            env_state = "Defense=1.0x, Visibility=1.0x, Seg=1.0x"
        prompt = f"""
You are simulating a cyber wargame in SAFE MODE.

Environment Graph:
Current Network Modifiers: {env_state}
Nodes: {nodes}
Edges: {edges}

Attack Chain (Start → Target):
{attack_chain}

Start Node: {start}
Target Node: {target}

Simulate ONE ROUND with:
1. Red Team action (conceptual, no exploits)
2. Blue Team response (defensive controls & detection)
3. Outcome of the interaction
4. Next-step recommendations for BOTH teams
5. Relevant MITRE ATT&CK techniques
6. Detection, evasion, or deception effects

STRICT RULES:
- No exploit code
- No commands
- No payloads
- High-level reasoning only
"""

        if not self.client:
            return "ERROR: OPENAI_API_KEY is not set."

        decision = self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        return decision.choices[0].message.content

    # ---------------------------------------------------------
    # Run a multi-round match
    # ---------------------------------------------------------
    def run_match(self, start, target, rounds=3):
        """
        Runs multiple sequential wargame rounds.
        """
        results = []

        for r in range(1, rounds + 1):
            result = self.run_round(start, target)
            results.append(f"### Round {r}\n{result}\n")

        return "\n".join(results)

    # ---------------------------------------------------------
    # Automatically deploy honeypots
    # ---------------------------------------------------------
    def deploy_dynamic_honeypots(self, quantity=3):
        """
        Deploys decoy honeypots dynamically.
        """
        created = []

        for i in range(quantity):
            name = f"decoy-{datetime.utcnow().isoformat()}-{i}"
            try:
                created.append(self.honey.deploy_honeypot(name))
            except Exception as e:
                created.append(f"ERROR deploying {name}: {e}")

        return created
