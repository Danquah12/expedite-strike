from modules.ingestion.normalization.normalizer import normalize_scan_repository
from modules.ingestion.scan_aggregator import ScanAggregator


class ScanIngestionModule:
    """
    Loads centralized scan results (read-only).
    """

    def __init__(self, nmap_dir=None, zap_dir=None):
        self.nmap_dir = nmap_dir
        self.zap_dir = zap_dir

    def execute(self, context):
        normalized_records = []

        if self.nmap_dir:
            normalized_records.extend(
                normalize_scan_repository(self.nmap_dir)
            )

        if self.zap_dir:
            normalized_records.extend(
                normalize_scan_repository(self.zap_dir)
            )

        aggregator = ScanAggregator(normalized_records)
        aggregator.aggregate(context)
