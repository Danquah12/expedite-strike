"""
scoring_service.py
──────────────────
Python analogue of ScoringService.cs

  ScoringService.calculate(ping, nmap, bloodhound) → ScoreResult

Scoring weights (matches .NET ScoringService.Calculate logic, extended):
  Ægis AD Scanner  global_score  60 %  (already 0-100)
  Nmap        open critical ports 25 %  (per-port penalty)
  BloodHound  DA paths            15 %  (per-path penalty)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyber_range.services.pingcastle_service  import PingResult
    from cyber_range.services.nmap_service        import NmapResult
    from cyber_range.services.bloodhound_service  import BloodHoundResult


# Ports considered high-exposure in an AD environment
_HIGH_RISK_PORTS = {3389, 5985, 5986, 23, 21, 2049, 111}
_MEDIUM_RISK_PORTS = {445, 139, 135}


@dataclass
class ScoreResult:
    total:       int  = 0    # 0 = safe, 100 = critical
    level:       str  = "A+"
    pc_contrib:  int  = 0
    nmap_contrib: int = 0
    bh_contrib:  int  = 0
    breakdown:   dict = None  # type: ignore

    def __post_init__(self):
        if self.breakdown is None:
            self.breakdown = {}


class ScoringService:
    """
    Python equivalent of:
        public int Calculate(string ping, string nmap) {
            int score = 0;
            if (ping.Contains("80")) score += 50;
            if (nmap.Contains("open")) score += 20;
            return Math.Min(score, 100);
        }
    Extended with BloodHound and weighted scoring.
    """

    @staticmethod
    def calculate(ping=None, nmap=None, bloodhound=None) -> ScoreResult:
        """Calculate composite risk score 0-100."""

        # ── 1. Ægis AD Scanner contribution (60%) ────────────────────────────
        pc_raw = 0
        if ping and ping.success:
            pc_raw = ping.global_score          # already 0-100
            # Boost for critical findings
            crits = sum(1 for f in ping.findings if f.severity == "Critical")
            pc_raw = min(100, pc_raw + crits * 5)
        pc_contrib = int(pc_raw * 0.60)

        # ── 2. Nmap contribution (25%) ────────────────────────────────────────
        nmap_raw = 0
        if nmap and nmap.success:
            for p in nmap.open_ports:
                if p.port in _HIGH_RISK_PORTS:
                    nmap_raw += 12
                elif p.port in _MEDIUM_RISK_PORTS:
                    nmap_raw += 5
                else:
                    nmap_raw += 2
            nmap_raw = min(100, nmap_raw)
        nmap_contrib = int(nmap_raw * 0.25)

        # ── 3. BloodHound contribution (15%) ──────────────────────────────────
        bh_raw = 0
        if bloodhound and bloodhound.success:
            bh_raw += bloodhound.da_paths * 25
            crits  = sum(1 for p in bloodhound.attack_paths if p.risk == "Critical")
            bh_raw += crits * 10
            bh_raw = min(100, bh_raw)
        bh_contrib = int(bh_raw * 0.15)

        total = min(100, pc_contrib + nmap_contrib + bh_contrib)

        # Risk level (mirrors Ægis AD Scanner convention)
        if total <= 10:   level = "A+"
        elif total <= 25: level = "A"
        elif total <= 50: level = "B"
        elif total <= 75: level = "C"
        else:             level = "D"

        return ScoreResult(
            total=total,
            level=level,
            pc_contrib=pc_contrib,
            nmap_contrib=nmap_contrib,
            bh_contrib=bh_contrib,
            breakdown={
                "Ægis AD Scanner (60%)":  f"{pc_contrib} pts  (raw: {pc_raw})",
                "Nmap (25%)":        f"{nmap_contrib} pts  (raw: {nmap_raw})",
                "BloodHound (15%)":  f"{bh_contrib} pts  (raw: {bh_raw})",
            }
        )
