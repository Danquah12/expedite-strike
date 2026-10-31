import xml.etree.ElementTree as ET
from shared_utils import merge_asset, merge_service, merge_vulnerability, merge_cve, extract_cves, debug

def import_zap(path):
    debug(f"Importing ZAP XML: {path}")
    tree = ET.parse(path)
    root = tree.getroot()

    for site in root.findall(".//site"):
        host = site.attrib.get("host")
        port = site.attrib.get("port")

        merge_asset(host)
        merge_service(host, port, "http", "zap")

        for alert in site.findall(".//alertitem"):
            plugin_id = alert.findtext("pluginid") or "ZAPGEN"
            name = alert.findtext("name")
            severity = alert.findtext("riskcode")
            desc = alert.findtext("desc") or ""

            merge_vulnerability(host, port, plugin_id, name, severity, desc)

            for cve in extract_cves(desc):
                merge_cve(cve, plugin_id)

    debug("ZAP import completed.")
