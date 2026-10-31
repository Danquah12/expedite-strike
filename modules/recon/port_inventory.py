class PortInventoryModule:
    """
    Ingests a predefined list of open ports.
    No scanning is performed.
    """

    def __init__(self, open_ports):
        self.open_ports = open_ports

    def execute(self, context):
        if context.scope is None:
            raise RuntimeError("Scope must be defined first")

        for port, proto in self.open_ports.items():
            if not isinstance(port, int):
                raise ValueError("Port must be an integer")
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            if proto not in ("tcp", "udp"):
                raise ValueError(f"Invalid protocol for port {port}")

        context.open_ports = self.open_ports.copy()
