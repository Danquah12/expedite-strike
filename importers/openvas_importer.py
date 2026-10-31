import xml.etree.ElementTree as ET
from shared_utils import (
    merge_asset,
    merge_service,
    merge_vulnerability,
    merge_cve,
    link_asset_vuln,
    extract_cves,
    debug
)

def import_openvas(path):
    debug(f"Importing OpenVAS XML: {path}")
    tree = ET.parse(path)
    root = tree.getroot()

    for result in root.findall(".//result"):
        ip = result.findtext("host")
        if not ip:
            continue

        merge_asset(ip)

        port = result.findtext("port") or "0"
        service_port = port.split("/")[0]

        plugin_id = result.findtext("nvt/oid") or "OVAS-" + ip
        vuln_name = result.findtext("nvt/name") or "OpenVAS Finding"
        severity = result.findtext("severity") or "0"
        description = result.findtext("description") or ""

        merge_service(ip, service_port, "tcp", "openvas")

        merge_vulnerability(ip, service_port, plugin_id, vuln_name, severity, description)

        for cve in extract_cves(description):
            merge_cve(cve, plugin_id)

    debug("OpenVAS import finished.")
