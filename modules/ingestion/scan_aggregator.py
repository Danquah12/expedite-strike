class ScanAggregator:
    """
    Aggregates normalized scan records into the assessment context
    while preserving host attribution.
    """

    def __init__(self, normalized_records):
        self.records = normalized_records

    def aggregate(self, context):
        seen = set()

        for record in self.records:
            target = record.get("target")
            port = record.get("port")

            if not target or not port:
                continue

            key = (
                target,
                port,
                record.get("protocol"),
                record.get("service"),
                record.get("version")
            )

            if key in seen:
                continue

            seen.add(key)

            # Initialize host entry
            if target not in context.hosts:
                context.hosts[target] = {
                    "ports": {},
                    "services": {},
                    "web_findings": []
                }

            host = context.hosts[target]

            # Ports
            if record.get("protocol"):
                host["ports"][port] = record.get("protocol")

            # Services
            if record.get("service"):
                host["services"][port] = {
                    "service": record.get("service"),
                    "version": record.get("version")
                }

            # Web findings
            if record.get("tool") == "zap":
                host["web_findings"].append(record)
