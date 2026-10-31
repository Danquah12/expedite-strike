class AssessmentContext:
    def __init__(self):
        self.scope = {}
        self.open_ports = {}
        self.services = {}
        self.exploits = {}
        self.risk_results = []

        self.hosts = {}
        self.attack_chains = []

        # ✅ ADD THIS
        self.attack_graph = {
            "nodes": set(),
            "edges": []
        }
