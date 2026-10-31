from modules.ingestion.zap_json import parse_zap_json
from modules.ingestion.normalization.filename_parser import parse_scan_filename


def normalize_zap(file_path, filename):
    meta = parse_scan_filename(filename)
    if not meta:
        return None

    findings = parse_zap_json(file_path)

    if not findings:
        return None

    normalized_records = []

    for finding in findings:
        normalized_records.append({
            "tool": "zap",
            "target": meta["target"],
            "timestamp": meta["timestamp"],
            "port": finding.get("port"),
            "service": "http",
            "alert": finding.get("alert"),
            "risk": finding.get("risk")
        })

    return normalized_records
