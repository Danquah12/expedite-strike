from core.risk_model import RiskModel


class RiskScoringModule:
    """
    Applies deterministic risk scoring to host-aware exploit intelligence.
    """

    def execute(self, context):
        if not context.exploits:
            raise RuntimeError("Exploit intelligence must exist before risk scoring")

        context.risk_results = []

        # context.exploits is now: { host: [exploit, exploit, ...] }
        for host, exploits in context.exploits.items():
            for exploit in exploits:
                exploit_class = exploit.get("exploit_class")

                # Explicit, deterministic mapping
                if exploit_class == "Remote Code Execution":
                    score = RiskModel.calculate(
                        attack_vector="network",
                        complexity="low",
                        impact="high",
                        chained=True
                    )

                elif exploit_class == "Authentication Weakness":
                    score = RiskModel.calculate(
                        attack_vector="network",
                        complexity="medium",
                        impact="medium",
                        chained=True
                    )

                elif exploit_class == "User Enumeration":
                    score = RiskModel.calculate(
                        attack_vector="network",
                        complexity="low",
                        impact="low",
                        chained=False
                    )

                else:
                    score = RiskModel.calculate(
                        attack_vector="local",
                        complexity="high",
                        impact="low",
                        chained=False
                    )

                context.risk_results.append({
                    "host": host,
                    "port": exploit.get("port"),
                    "service": exploit.get("service"),
                    "exploit_class": exploit_class,
                    "risk_score": score,
                    "severity": RiskModel.severity(score),
                    "post_exploitation": exploit.get("post_exploitation")
                })
