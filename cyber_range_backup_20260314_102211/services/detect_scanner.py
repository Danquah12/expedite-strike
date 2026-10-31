from lxml import etree

def detect_scanner_type(xml_bytes: bytes) -> str:
    tree = etree.fromstring(xml_bytes)
    root_tag = tree.tag.lower()

    if "nmaprun" in root_tag:
        return "nmap"

    if "owaspzapreport" in root_tag:
        return "zap"

    if tree.xpath("//report") and tree.xpath("//result") and tree.xpath("//nvt"):
        return "openvas"

    if tree.xpath("//issues/issue"):
        return "burp"

    return "unknown"
