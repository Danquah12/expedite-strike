class AttackGraphBuilder:
    """
    Builds directed attack graphs from attack chains.
    """

    def execute(self, context):
        if not context.attack_chains:
            raise RuntimeError("Attack chains must exist before graph construction")

        context.attack_graph = {
            "nodes": set(),
            "edges": []
        }

        for chain in context.attack_chains:
            host = f"host:{chain['host']}"
            service = f"service:{chain['entry_point']['service']}:{chain['entry_point']['port']}"
            exploit = f"exploit:{chain['exploit_class']}"
            outcome = f"outcome:{chain['outcome']}"

            # Register nodes
            context.attack_graph["nodes"].update([
                host, service, exploit, outcome
            ])

            # Register edges (directed)
            context.attack_graph["edges"].extend([
                (host, service),
                (service, exploit),
                (exploit, outcome)
            ])
