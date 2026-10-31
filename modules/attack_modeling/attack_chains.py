class AttackChainBuilder:
    """
    Builds host-centric attack chains from exploit intelligence and risk results.
    """

    def execute(self, context):
        if not context.exploits or not context.risk_results:
            raise RuntimeError("Exploit intelligence and risk results required")

        context.attack_chains = []

        for risk in context.risk_results:
            chain = {
                "host": risk["host"],
                "entry_point": {
                    "port": risk["port"],
                    "service": risk["service"]
                },
                "exploit_class": risk["exploit_class"],
                "severity": risk["severity"],
                "outcome": risk["post_exploitation"],
                "next_steps": self._infer_next_steps(risk["exploit_class"])
            }

            context.attack_chains.append(chain)

    def _infer_next_steps(self, exploit_class):
        """
        Deterministic mapping — no guessing.
        """
        if exploit_class == "Remote Code Execution":
            return [
                "Privilege escalation",
                "Credential harvesting",
                "Persistence"
            ]
        if exploit_class == "Authentication Weakness":
            return [
                "Privilege abuse",
                "Data access"
            ]
        if exploit_class == "User Enumeration":
            return [
                "Password spraying",
                "Brute-force authentication"
            ]
        return ["Manual investigation"]
