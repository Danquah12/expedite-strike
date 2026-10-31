from modules.ingestion.nmap_xml import parse_nmap_xml
from modules.ingestion.normalization.filename_parser import parse_scan_filename


def normalize_nmap(file_path, filename):
    meta = parse_scan_filename(filename)
    if not meta:
        return None

    ports, services = parse_nmap_xml(file_path)

    if not ports:
        return None

    normalized_records = []

    for port, proto in ports.items():
        svc = services.get(port, {})

        normalized_records.append({
            "tool": "nmap",
            "target": meta["target"],
            "timestamp": meta["timestamp"],
            "port": port,
            "protocol": proto,
            "service": svc.get("service", "unknown"),
            "version": svc.get("version", "unknown")
        })

    return normalized_records
