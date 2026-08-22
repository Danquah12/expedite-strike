"""
scan_orchestrator.py  (v2)
──────────────────────────
Python analogue of ScanController.RunAll() — extended with:

  • ScanResult model     (models/scan_result.py)
  • Scan history         (services/scan_history.py  → Neo4j)
  • AI recommendations   (services/ai_recommendation.py → GPT-4o-mini)
  • Multi-domain support (optional extra targets)
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from cyber_range.models.scan_result       import (ScanResult, Finding,
                                                    PortEntry, AttackPath)
from cyber_range.services.pingcastle_service  import PingCastleService
from cyber_range.services.nmap_service        import NmapService
from cyber_range.services.bloodhound_service  import BloodHoundService
from cyber_range.services.scoring_service     import ScoringService
from cyber_range.services.scan_history        import ScanHistory


# ── Scan parameters ────────────────────────────────────────────────────────────
@dataclass
class ScanParams:
    dc_ip:         str         = "192.168.1.10"
    domain:        str         = "corp.local"
    username:      str         = "Administrator"
    password:      str         = ""
    pc_exe:        str         = "/home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe"
    bh_exe:        str         = "/home/kali/Downloads/SharpHound.exe"
    extra_domains: List[str]   = field(default_factory=list)  # multi-domain
    run_ping:      bool        = True
    run_nmap:      bool        = True
    run_blood:     bool        = True
    run_ai:        bool        = True    # AI recommendations


# ── Session (live state while scanning) ───────────────────────────────────────
@dataclass
class ScanSession:
    params:        ScanParams             = field(default_factory=ScanParams)
    running:       bool                   = False
    done:          bool                   = False
    started:       Optional[datetime]     = None
    finished:      Optional[datetime]     = None
    log:           deque                  = field(default_factory=lambda: deque(maxlen=800))

    # Raw service results
    ping:          object                 = None
    nmap:          object                 = None
    blood:         object                 = None
    score:         object                 = None

    # Final composite
    result:        Optional[ScanResult]   = None
    error:         str                    = ""

    @property
    def elapsed(self) -> str:
        if not self.started:
            return ""
        end  = self.finished or datetime.now()
        secs = int((end - self.started).total_seconds())
        return f"{secs // 60:02d}:{secs % 60:02d}"

    @property
    def status_label(self) -> str:
        if self.running:             return "🔴 RUNNING"
        if self.done and not self.error: return "✅ COMPLETE"
        if self.done and self.error: return "❌ ERROR"
        return "IDLE"


# ── Singleton session ──────────────────────────────────────────────────────────
_SESSION_LOCK = threading.Lock()
_current: ScanSession = ScanSession()


class ScanOrchestrator:
    """
    Python equivalent of ScanController.RunAll()

    Extended with:
      - ScanResult composite model
      - Neo4j history persistence
      - AI narrative generation
      - Multi-domain scanning
    """

    # ── Public API ─────────────────────────────────────────────────────────────
    @classmethod
    def start(cls, params: ScanParams) -> bool:
        global _current
        with _SESSION_LOCK:
            if _current.running:
                return False
            _current = ScanSession(params=params, running=True, started=datetime.now())
        threading.Thread(target=cls._orchestrate, args=(_current,), daemon=True).start()
        return True

    @classmethod
    def get_session(cls) -> ScanSession:
        return _current

    @classmethod
    def reset(cls):
        global _current
        with _SESSION_LOCK:
            _current = ScanSession()

    @classmethod
    def get_history(cls, limit: int = 10) -> list:
        """Return past scan records from Neo4j."""
        return ScanHistory.get_all(limit=limit)

    # ── Internal orchestration ─────────────────────────────────────────────────
    @classmethod
    def _orchestrate(cls, session: ScanSession):
        q = session.log
        p = session.params

        def _log(msg: str):
            q.append(f"[{datetime.now():%H:%M:%S}] {msg}")
        def _banner(title: str):
            _log("═" * 52)
            _log(f"▶  {title}")
            _log("═" * 52)

        try:
            scan_id = str(uuid.uuid4())[:8].upper()
            _banner(f"AD SECURITY SCAN  [{scan_id}]  started")
            _log(f"    Primary target  : {p.dc_ip}  ({p.domain})")
            if p.extra_domains:
                _log(f"    Extra domains   : {', '.join(p.extra_domains)}")
            _log(f"    Tools active    : "
                 f"{'Ægis AD Scanner ' if p.run_ping else ''}"
                 f"{'Nmap ' if p.run_nmap else ''}"
                 f"{'BloodHound ' if p.run_blood else ''}"
                 f"{'AI' if p.run_ai else ''}")

            ping_res  = [None]
            nmap_res  = [None]
            blood_res = [None]
            errors: list[str] = []

            # Parallel thread workers
            def _run_ping():
                try:
                    ping_res[0] = PingCastleService(log_queue=q).run(
                        p.dc_ip, p.domain, p.username, p.password, p.pc_exe)
                    # Also run PingCastle on extra IPs
                    for extra_ip in p.extra_domains:
                        _log(f"🛡️  Ægis AD Scanner extra target: {extra_ip}")
                        extra_pr = PingCastleService(log_queue=q).run(
                            extra_ip, p.domain, p.username, p.password, p.pc_exe)
                        if extra_pr.success and ping_res[0]:
                            ping_res[0].findings.extend(extra_pr.findings)
                            # Keep highest score
                            if extra_pr.global_score > ping_res[0].global_score:
                                ping_res[0].global_score = extra_pr.global_score
                                ping_res[0].risk_level   = extra_pr.risk_level
                        elif extra_pr.success and not ping_res[0]:
                            ping_res[0] = extra_pr
                except Exception as e:
                    errors.append(f"Ægis AD Scanner: {e}")

            def _run_nmap():
                try:
                    nmap_res[0] = NmapService(log_queue=q).run(p.dc_ip)
                    # Also scan extra targets with Nmap
                    for extra in p.extra_domains:
                        _log(f"🗺️  Nmap extra target: {extra}")
                        extra_r = NmapService(log_queue=q).run(extra)
                        if extra_r.success and nmap_res[0]:
                            nmap_res[0].open_ports.extend(extra_r.open_ports)
                        elif extra_r.success and not nmap_res[0]:
                            nmap_res[0] = extra_r
                except Exception as e:
                    errors.append(f"Nmap: {e}")

            def _run_blood():
                try:
                    blood_res[0] = BloodHoundService(log_queue=q).run(
                        p.dc_ip, p.domain, p.username, p.password, p.bh_exe)
                except Exception as e:
                    errors.append(f"BloodHound: {e}")

            # Launch in parallel
            threads = []
            if p.run_ping:  threads.append(threading.Thread(target=_run_ping,  daemon=True))
            if p.run_nmap:  threads.append(threading.Thread(target=_run_nmap,  daemon=True))
            if p.run_blood: threads.append(threading.Thread(target=_run_blood, daemon=True))
            for t in threads: t.start()
            for t in threads: t.join()

            # ── Score ──────────────────────────────────────────────────────────
            score = ScoringService.calculate(ping_res[0], nmap_res[0], blood_res[0])
            _banner("COMPOSITE RISK SCORING")
            _log(f"    Risk Score : {score.total}/100   Level: {score.level}")
            for k, v in score.breakdown.items():
                _log(f"    {k:<20}  {v}")

            # ── Build ScanResult ──────────────────────────────────────────────
            pr, nr, br = ping_res[0], nmap_res[0], blood_res[0]
            findings = []
            if pr:
                for f in pr.findings:
                    findings.append(Finding(
                        tool=f.severity, rule=f.rule, category=f.category,
                        severity=f.severity, description=f.description))
            ports = []
            if nr:
                for p2 in nr.open_ports:
                    ports.append(PortEntry(port=p2.port, protocol=p2.protocol,
                                           state=p2.state, service=p2.service,
                                           version=p2.version))
            atk_paths = []
            if br:
                for ap in br.attack_paths:
                    atk_paths.append(AttackPath(source=ap.source, target=ap.target,
                                                relationship=ap.relationship, risk=ap.risk))

            result = ScanResult(
                scan_id         = scan_id,
                timestamp       = session.started,
                dc_ip           = p.dc_ip,
                domain          = p.domain,
                domains_scanned = [p.dc_ip] + p.extra_domains,
                pc_summary      = pr.raw_output[:500] if pr else "",
                pc_global_score = pr.global_score    if pr else 0,
                pc_risk_level   = pr.risk_level       if pr else "Unknown",
                pc_report_path  = pr.report_path      if pr else None,
                nmap_summary    = nr.raw_output[:500] if nr else "",
                nmap_open_count = nr.open_count       if nr else 0,
                blood_summary   = "BloodHound collection completed" if br else "",
                blood_da_paths  = br.da_paths         if br else 0,
                risk_score      = score.total,
                risk_level      = score.level,
                findings        = findings,
                ports           = ports,
                attack_paths    = atk_paths,
            )

            # ── AI Recommendations ────────────────────────────────────────────
            if p.run_ai:
                _banner("AI RECOMMENDATIONS  —  generating narrative")
                try:
                    from cyber_range.services.ai_recommendation import generate_ai_recommendation
                    narrative = generate_ai_recommendation(result)
                    result.ai_recommendation = narrative
                    _log("✅  AI narrative generated")
                except Exception as e:
                    _log(f"⚠️  AI narrative unavailable: {e}")

            # ── Persist to Neo4j ──────────────────────────────────────────────
            _banner("HISTORY  —  persisting to Neo4j")
            try:
                saved_id = ScanHistory.save(result)
                _log(f"✅  Saved as scan #{saved_id}")
            except Exception as e:
                _log(f"⚠️  History save skipped: {e}")

            # ── Finalise session ──────────────────────────────────────────────
            with _SESSION_LOCK:
                session.ping     = pr
                session.nmap     = nr
                session.blood    = br
                session.score    = score
                session.result   = result
                session.done     = True
                session.running  = False
                session.finished = datetime.now()
                if errors:
                    session.error = "; ".join(errors)

            _banner(f"✅  COMPLETE in {session.elapsed}  —  "
                    f"Score: {score.total}/100  (Level {score.level})")

        except Exception as e:
            with _SESSION_LOCK:
                session.error    = str(e)
                session.done     = True
                session.running  = False
                session.finished = datetime.now()
            q.append(f"[{datetime.now():%H:%M:%S}] ❌  Orchestrator error: {e}")
