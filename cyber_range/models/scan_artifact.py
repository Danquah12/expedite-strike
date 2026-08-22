# cyber_range/models/scan_artifact.py

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class ScanArtifact:
    tool: str                # nmap | zap
    scan_file: Path
    meta_file: Path
    timestamp: Optional[str]
    target: Optional[str]
