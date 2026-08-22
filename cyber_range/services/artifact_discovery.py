# cyber_range/services/artifact_discovery.py

from pathlib import Path
import json
from cyber_range.models.scan_artifact import ScanArtifact

# Incoming scan directories
NMAP_DIR = Path("/mnt/scans/incoming/nmap")
ZAP_DIR  = Path("/mnt/scans/incoming/zap")


def discover_scan_artifacts():
    """
    Discovers scan artifacts by pairing scan output files
    with their corresponding .meta.json files.
    """
    artifacts = []

    # ==================== NMAP ====================
    for meta_file in NMAP_DIR.glob("*.meta.json"):
        try:
            with open(meta_file, "r") as f:
                meta = json.load(f)

            # nmap_xxx.xml + nmap_xxx.meta.json
            base_name = meta_file.name.replace(".meta.json", "")
            scan_file = meta_file.parent / f"{base_name}.xml"

            if not scan_file.exists():
                continue

            artifacts.append(
                ScanArtifact(
                    tool="nmap",
                    scan_file=scan_file,
                    meta_file=meta_file,
                    timestamp=meta.get("timestamp"),
                    target=meta.get("target")
                )
            )
        except Exception:
            continue

    # ==================== ZAP ====================
    for meta_file in ZAP_DIR.glob("*.meta.json"):
        try:
            with open(meta_file, "r") as f:
                meta = json.load(f)

            # zap_xxx.json + zap_xxx.meta.json
            base_name = meta_file.name.replace(".meta.json", "")
            scan_file = meta_file.parent / f"{base_name}.json"

            if not scan_file.exists():
                continue

            artifacts.append(
                ScanArtifact(
                    tool="zap",
                    scan_file=scan_file,
                    meta_file=meta_file,
                    timestamp=meta.get("timestamp"),
                    target=meta.get("target")
                )
            )
        except Exception:
            continue

    return artifacts
