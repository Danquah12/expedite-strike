import os

from modules.ingestion.normalization.classifier import classify_scan_files
from modules.ingestion.normalization.nmap_normalizer import normalize_nmap
from modules.ingestion.normalization.zap_normalizer import normalize_zap


def normalize_scan_repository(scan_dir):
    normalized = []

    classified = classify_scan_files(scan_dir)

    for fname in classified["nmap"]:
        records = normalize_nmap(
            os.path.join(scan_dir, fname),
            fname
        )
        if records:
            normalized.extend(records)

    for fname in classified["zap"]:
        records = normalize_zap(
            os.path.join(scan_dir, fname),
            fname
        )
        if records:
            normalized.extend(records)

    return normalized
