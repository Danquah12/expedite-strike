import xml.etree.ElementTree as ET
import datetime

class NmapParser:
    def parse(self, path):
        findings = []
        tree = ET.parse(path)
        root = tree.getroot()

        for host in root.findall("host"):
            addr = host.find("address").get("addr", "unknown")

            for port in host.findall(".//port"):
                service_elem = port.find("service")
                service = service_elem.get("name") if service_elem is not None else "unknown"

                findings.append({
                    "host": addr,
                    "port": port.get("portid"),
                    "service": service,
                    "protocol": port.get("protocol"),
                    "state": port.find("state").get("state"),
                    "severity": "info",
                    "description": f"{service} service exposed",
                    "source": "nmap",
                    "import_date": datetime.datetime.utcnow().isoformat()
                })

        return findings
