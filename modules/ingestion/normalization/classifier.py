import os


def classify_scan_files(scan_dir):
    nmap_xml = []
    zap_json = []
    metadata = []

    for fname in os.listdir(scan_dir):
        if fname.endswith(".meta.json"):
            metadata.append(fname)
        elif fname.endswith(".xml") and fname.startswith("nmap_"):
            nmap_xml.append(fname)
        elif fname.endswith(".json") and fname.startswith("zap_"):
            zap_json.append(fname)

    return {
        "nmap": nmap_xml,
        "zap": zap_json,
        "meta": metadata
    }
