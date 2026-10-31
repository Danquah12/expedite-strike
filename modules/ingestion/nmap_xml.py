import xml.etree.ElementTree as ET


def parse_nmap_xml(file_path):
    """
    Parses Nmap XML output.
    Returns:
      ports: dict[int, str]
      services: dict[int, dict]
    """
    ports = {}
    services = {}

    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = int(port.get("portid"))
            protocol = port.get("protocol")

            ports[port_id] = protocol

            service = port.find("service")
            if service is not None:
                services[port_id] = {
                    "service": service.get("name", "unknown"),
                    "version": service.get("version", "unknown")
                }

    return ports, services
