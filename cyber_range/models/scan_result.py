"""
models/scan_result.py
─────────────────────
Python analogue of Models/ScanResult.cs

Canonical data model shared across all services and the UI.
All services return objects that compose into a ScanSession (scan_orchestrator.py),
which in turn produces a ScanResult for persistence and display.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


# ── Atomic finding ─────────────────────────────────────────────────────────────
@dataclass
class Finding:
    """Single security finding from any scanner."""
    tool:        str   = ""           # "PingCastle" | "Nmap" | "BloodHound"
    rule:        str   = ""
    category:   str   = ""
    severity:   str   = "Info"        # Critical | High | Medium | Low | Info
    description: str   = ""
    mitre_id:   str   = ""           # e.g. T1558.003


# ── Port entry ─────────────────────────────────────────────────────────────────
@dataclass
class PortEntry:
    port:     int  = 0
    protocol: str  = "tcp"
    state:    str  = "open"
    service:  str  = ""
    version:  str  = ""


# ── Attack path ────────────────────────────────────────────────────────────────
@dataclass
class AttackPath:
    source:       str = ""
    target:       str = ""
    relationship: str = ""
    risk:         str = "High"


# ── Composite scan result (mirrors ScanResult.cs) ─────────────────────────────
@dataclass
class ScanResult:
    """
    Canonical result object — analogue of ScanResult.cs.

    .NET:                         Python:
    ScanResult.PingCastle   (str) → pc_summary  (str)
    ScanResult.Nmap         (str) → nmap_summary (str)
    ScanResult.RiskScore    (int) → risk_score   (int)
    Extended with:
      findings, ports, attack_paths, ai_recommendation, scan_id, timestamp
    """
    scan_id:           str              = ""
    timestamp:         Optional[datetime] = None

    # ── Tool outputs ──────────────────────────────────────────────────────────
    pc_summary:        str              = ""    # ScanResult.PingCastle
    pc_global_score:   int              = 0
    pc_risk_level:     str              = "Unknown"
    pc_report_path:    Optional[str]    = None

    nmap_summary:      str              = ""    # ScanResult.Nmap
    nmap_open_count:   int              = 0

    blood_summary:     str              = ""
    blood_da_paths:    int              = 0

    # ── Composite score ───────────────────────────────────────────────────────
    risk_score:        int              = 0     # ScanResult.RiskScore (0-100)
    risk_level:        str              = "Unknown"

    # ── Structured findings ───────────────────────────────────────────────────
    findings:          List[Finding]    = field(default_factory=list)
    ports:             List[PortEntry]  = field(default_factory=list)
    attack_paths:      List[AttackPath] = field(default_factory=list)

    # ── AI narrative ──────────────────────────────────────────────────────────
    ai_recommendation: str              = ""

    # ── Target info ───────────────────────────────────────────────────────────
    dc_ip:             str              = ""
    domain:            str              = ""
    domains_scanned:   List[str]        = field(default_factory=list)

    def to_neo4j_props(self) -> dict:
        """Serialize to a flat dict suitable for Neo4j CREATE."""
        return {
            "scan_id":         self.scan_id,
            "timestamp":       self.timestamp.isoformat() if self.timestamp else "",
            "dc_ip":           self.dc_ip,
            "domain":          self.domain,
            "risk_score":      self.risk_score,
            "risk_level":      self.risk_level,
            "pc_score":        self.pc_global_score,
            "pc_risk":         self.pc_risk_level,
            "nmap_open_ports": self.nmap_open_count,
            "da_paths":        self.blood_da_paths,
            "critical_count":  sum(1 for f in self.findings if f.severity == "Critical"),
            "high_count":      sum(1 for f in self.findings if f.severity == "High"),
            "ai_summary":      self.ai_recommendation[:500] if self.ai_recommendation else "",
        }
