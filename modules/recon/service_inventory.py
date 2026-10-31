class ServiceInventoryModule:
    """
    Maps ports to known services using explicit input.
    """

    def __init__(self, services):
        self.services = services

    def execute(self, context):
        if not context.open_ports:
            raise RuntimeError("Ports must be defined before services")

        for port, svc in self.services.items():
            if port not in context.open_ports:
                raise ValueError(f"Service defined for unopened port {port}")

            if "service" not in svc or "version" not in svc:
                raise ValueError(f"Invalid service definition on port {port}")

        context.services = self.services.copy()
