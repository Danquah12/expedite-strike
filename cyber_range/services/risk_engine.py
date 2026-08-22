# cyber_range/services/risk_engine.py

class RiskEngine:

    @staticmethod
    def calculate_score(severity, epss, criticality=1.0):
        sev_map = {
            "Critical": 9,
            "High": 7,
            "Medium": 5,
            "Low": 2,
            "Info": 1
        }
        base = sev_map.get(severity, 3)
        return round(base * (1 + epss) * criticality, 2)
