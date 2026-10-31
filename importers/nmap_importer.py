import xml.etree.ElementTree as ET
from shared_utils import merge_asset, merge_service, merge_vulnerability, merge_cve, debug

def import_nmap(path):
    debug(f"Importing Nmap XML: {path}")
    tree = ET.parse(path)
    root = tree.getroot()

    # Loop over each host block
    for host in root.findall("host"):

        # -----------------------------------------
        # EXTRACT IP ADDRESS SAFELY
        # -----------------------------------------
        ip = None
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr")
                break

        if not ip:
            continue

        merge_asset(ip)

        # -----------------------------------------
        # PROCESS PORTS
        # -----------------------------------------
        for port in host.findall(".//port"):
            portid = port.attrib.get("portid")
            protocol = port.attrib.get("protocol")

            service_el = port.find("service")
            service_name = service_el.attrib.get("name") if service_el is not None else "unknown"

            merge_service(ip, portid, protocol, service_name)

            # Nmap does NOT provide vulnerabilities natively
            # So nothing else here

    debug("Nmap import completed.")
