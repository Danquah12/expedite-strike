import sys
import traceback
from pathlib import Path

# Add the app directory to the python path
sys.path.append("/Backup/vuln_intel/app")

try:
    from cyber_range.ingest.neo4j_ingestor import Neo4jIngestor
    ingestor = Neo4jIngestor()
    base_dir = Path("/mnt/scans/incoming/aegisprobe")
    files = list(base_dir.glob("*.json"))
    if not files:
        print("No files found!")
    else:
        path = files[-1]
        print(f"Testing {path}")
        ingestor.process_meta(path)
        print("Success")
except Exception as e:
    traceback.print_exc()
