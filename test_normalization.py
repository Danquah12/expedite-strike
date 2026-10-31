from modules.ingestion.normalization.normalizer import normalize_scan_repository

NMAP_DIR = "/mnt/scans/incoming/nmap"
ZAP_DIR = "/mnt/scans/incoming/zap"

print("\n=== NORMALIZED NMAP RECORDS ===")
nmap_results = normalize_scan_repository(NMAP_DIR)

for record in nmap_results:
    print(record)

print("\nTotal Nmap Records:", len(nmap_results))


print("\n=== NORMALIZED ZAP RECORDS ===")
zap_results = normalize_scan_repository(ZAP_DIR)

for record in zap_results:
    print(record)

print("\nTotal ZAP Records:", len(zap_results))
