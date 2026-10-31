class RiskModel:
    """
    Deterministic, CVSS-inspired risk scoring model.
    """

    ATTACK_VECTOR = {
        "network": 1.0,
        "local": 0.5
    }

    ATTACK_COMPLEXITY = {
        "low": 1.0,
        "medium": 0.7,
        "high": 0.4
    }

    IMPACT = {
        "low": 0.4,
        "medium": 0.7,
        "high": 1.0
    }

    @staticmethod
    def calculate(attack_vector, complexity, impact, chained=False):
        base_score = (
            RiskModel.ATTACK_VECTOR[attack_vector] *
            RiskModel.ATTACK_COMPLEXITY[complexity] *
            RiskModel.IMPACT[impact]
        )

        if chained:
            base_score *= 1.2

        score = min(round(base_score * 10, 1), 10.0)
        return score

    @staticmethod
    def severity(score):
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"
