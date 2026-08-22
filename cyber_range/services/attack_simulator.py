"""
attack_simulator.py
────────────────────
Generates attacker scenario narratives from Neo4j attack paths.
"""
from __future__ import annotations
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict

log = logging.getLogger("attack_simulator")

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "Adomaa12@")


@dataclass
class AttackScenario:
    title:    str
    steps:    List[str] = field(default_factory=list)
    impact:   str = "Domain Compromise"
    risk:     str = "Critical"
    score:    int = 0
    mitre:    List[str] = field(default_factory=list)


# MITRE technique mapping by relationship type
_REL_MITRE = {
    "MemberOf":           ("T1069", "Permission Groups Discovery"),
    "AdminTo":            ("T1021", "Remote Services"),
    "HasSession":         ("T1078", "Valid Accounts"),
    "GenericAll":         ("T1484", "Domain Policy Modification"),
    "WriteDACL":          ("T1484.002", "Domain Trust Modification"),
    "DCSync":             ("T1003.006", "DCSync"),
    "Kerberoastable":     ("T1558.003", "Kerberoasting"),
    "AllExtendedRights":  ("T1098", "Account Manipulation"),
    "ForceChangePassword":("T1098.001", "Additional Cloud Credentials"),
    "GenericWrite":       ("T1484", "Domain Policy Modification"),
    "WriteOwner":         ("T1222", "File and Directory Permissions Modification"),
    "Owns":               ("T1484", "Domain Policy Modification"),
}

_ACTION_TEMPLATES = {
    "User":     "Compromise user account: {name}",
    "Group":    "Exploit group membership: {name}",
    "Computer": "Lateral move to computer: {name}",
    "Domain":   "Reach domain: {name}",
    "GPO":      "Abuse GPO: {name}",
}

_TECHNIQUE_INTROS = {
    "Kerberoastable":  "Request TGS ticket → offline crack password",
    "WriteDACL":       "Modify DACL → grant self GenericAll",
    "GenericAll":      "Abuse GenericAll → reset password / add to group",
    "DCSync":          "Execute DCSync → dump all NTLM hashes",
    "AdminTo":         "Use admin rights → remote execution",
    "HasSession":      "Steal session token → impersonate user",
    "AllExtendedRights": "Abuse extended rights → force password reset",
}


class AttackSimulator:

    def __init__(self, uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS):
        self._uri  = uri
        self._user = user
        self._pass = password

    def _driver(self):
        from neo4j import GraphDatabase
        return GraphDatabase.driver(self._uri, auth=(self._user, self._pass))

    def simulate(self, max_paths: int = 5) -> List[AttackScenario]:
        """Generate attacker scenarios from AD attack paths in Neo4j."""
        scenarios: List[AttackScenario] = []

        try:
            driver = self._driver()
        except Exception as e:
            log.error(f"Neo4j connection failed: {e}")
            return [_demo_scenario()]

        with driver.session() as s:
            # Fetch paths with relationship types
            result = s.run("""
                MATCH p=shortestPath(
                    (u:User)-[*1..8]->(g:Group)
                )
                WHERE toLower(g.name) CONTAINS 'domain admin'
                RETURN
                    [n IN nodes(p)         | coalesce(n.name, n.id, 'node')] AS node_names,
                    [n IN nodes(p)         | labels(n)[0]]                    AS node_types,
                    [r IN relationships(p) | type(r)]                         AS rel_types,
                    length(p) AS hops
                ORDER BY hops ASC
                LIMIT $limit
            """, limit=max_paths)
            paths = [dict(r) for r in result]

        driver.close()

        if not paths:
            return [_demo_scenario()]

        for i, p in enumerate(paths):
            names     = p.get("node_names", [])
            types     = p.get("node_types",  [])
            rels      = p.get("rel_types",   [])
            hops      = p.get("hops", len(rels))
            score     = max(100 - hops * 10, 30)

            steps: List[str] = []
            mitre_set: List[str] = []

            for j, name in enumerate(names):
                # Movement step
                ntype  = types[j] if j < len(types) else "Node"
                action = _ACTION_TEMPLATES.get(ntype, "Move to {name}")
                steps.append(action.format(name=name))

                # Edge technique
                if j < len(rels):
                    rel = rels[j]
                    intro = _TECHNIQUE_INTROS.get(rel, "")
                    if intro:
                        steps.append(f"  ↳ {intro}")
                    m = _REL_MITRE.get(rel)
                    if m:
                        mitre_set.append(f"{m[0]} — {m[1]}")

            steps.append("🏁  Domain Admins — full domain compromise achieved")

            scenarios.append(AttackScenario(
                title  = f"Attack Path {i+1}: {names[0]} → {names[-1]} ({hops} hops)",
                steps  = steps,
                impact = "Domain Compromise",
                risk   = "Critical" if score >= 70 else "High",
                score  = score,
                mitre  = list(dict.fromkeys(mitre_set)),  # dedupe, keep order
            ))

        return scenarios


def _demo_scenario() -> AttackScenario:
    """Fallback demo scenario when Neo4j has no DA paths yet."""
    return AttackScenario(
        title  = "Demo Path: john.doe → Domain Admins (3 hops)",
        steps  = [
            "Compromise user account: john.doe",
            "  ↳ Request TGS ticket → offline crack password",
            "Exploit group membership: IT-Admins",
            "  ↳ Abuse GenericAll → reset password",
            "Lateral move to computer: EXPEDITE-DC",
            "  ↳ Execute DCSync → dump all NTLM hashes",
            "🏁  Domain Admins — full domain compromise achieved",
        ],
        impact = "Domain Compromise",
        risk   = "Critical",
        score  = 87,
        mitre  = [
            "T1558.003 — Kerberoasting",
            "T1484 — Domain Policy Modification",
            "T1003.006 — DCSync",
        ],
    )


def simulate_from_paths(paths: list) -> List[AttackScenario]:
    """Lightweight version — generate scenarios from pre-fetched path dicts."""
    if not paths:
        return [_demo_scenario()]
    scenarios = []
    for i, p in enumerate(paths):
        path_list = p.get("path", [])
        hops      = p.get("hops", len(path_list) - 1)
        score     = max(100 - hops * 10, 30)
        steps     = [f"Move to {n}" for n in path_list]
        steps.append("🏁  Domain Admins — full domain compromise achieved")
        scenarios.append(AttackScenario(
            title  = f"Path {i+1}: {path_list[0] if path_list else '?'} → DA ({hops} hops)",
            steps  = steps,
            score  = score,
            risk   = "Critical" if score >= 70 else "High",
        ))
    return scenarios
