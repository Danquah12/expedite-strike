# ================================================================
# cert_tracker.py — Security Certification Tracker
#
# Tracks: SOC 2, ISO 27001, FedRAMP, StateRAMP, CMMC, NIST 800-53
#
# Features:
#   1. Certification lifecycle (plan → assess → remediate → certify → maintain)
#   2. Evidence collection tracking
#   3. Audit readiness scoring
#   4. Control mapping across certifications
#   5. Timeline/milestone management
# ================================================================

import os
import json
import logging
from datetime import datetime, date, timedelta
from typing import Optional

log = logging.getLogger(__name__)


# ── Certification Frameworks ─────────────────────────────────────
CERTIFICATIONS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "authority": "AICPA",
        "categories": ["Security", "Availability", "Processing Integrity",
                       "Confidentiality", "Privacy"],
        "duration_months": 12,
        "renewal": "Annual",
        "typical_controls": 80,
        "phases": [
            {"name": "Readiness Assessment", "duration_weeks": 4},
            {"name": "Gap Remediation", "duration_weeks": 8},
            {"name": "Control Implementation", "duration_weeks": 6},
            {"name": "Type I Audit", "duration_weeks": 4},
            {"name": "Observation Period", "duration_weeks": 26},
            {"name": "Type II Audit", "duration_weeks": 6},
        ],
    },
    "iso27001": {
        "name": "ISO 27001",
        "authority": "ISO/IEC",
        "categories": ["A.5 Policies", "A.6 Organization", "A.7 HR",
                       "A.8 Asset Mgmt", "A.9 Access Control", "A.10 Crypto",
                       "A.11 Physical", "A.12 Operations", "A.13 Communications",
                       "A.14 System Acq", "A.15 Supplier", "A.16 Incident",
                       "A.17 BCM", "A.18 Compliance"],
        "duration_months": 36,
        "renewal": "3-year cycle (annual surveillance)",
        "typical_controls": 114,
        "phases": [
            {"name": "Scope & Gap Analysis", "duration_weeks": 4},
            {"name": "Risk Assessment", "duration_weeks": 4},
            {"name": "ISMS Implementation", "duration_weeks": 12},
            {"name": "Internal Audit", "duration_weeks": 3},
            {"name": "Stage 1 Audit", "duration_weeks": 2},
            {"name": "Stage 2 Audit", "duration_weeks": 3},
        ],
    },
    "fedramp": {
        "name": "FedRAMP",
        "authority": "GSA / PMO",
        "categories": ["AC", "AT", "AU", "CA", "CM", "CP", "IA",
                       "IR", "MA", "MP", "PE", "PL", "PM", "PS",
                       "PT", "RA", "SA", "SC", "SI", "SR"],
        "duration_months": 36,
        "renewal": "3-year ATO (continuous monitoring)",
        "typical_controls": 325,
        "phases": [
            {"name": "Preparation", "duration_weeks": 8},
            {"name": "SSP Development", "duration_weeks": 8},
            {"name": "3PAO Assessment", "duration_weeks": 12},
            {"name": "SAR & POA&M", "duration_weeks": 4},
            {"name": "Agency Review", "duration_weeks": 8},
            {"name": "ATO Decision", "duration_weeks": 4},
        ],
    },
    "cmmc": {
        "name": "CMMC 2.0",
        "authority": "DoD",
        "categories": ["Access Control", "Awareness & Training", "Audit",
                       "Config Management", "Identification & Auth",
                       "Incident Response", "Maintenance", "Media Protection",
                       "Personnel Security", "Physical Protection",
                       "Risk Assessment", "Security Assessment",
                       "System & Comms", "System & Info Integrity"],
        "duration_months": 36,
        "renewal": "3-year",
        "typical_controls": 110,
        "phases": [
            {"name": "Self-Assessment", "duration_weeks": 4},
            {"name": "Gap Analysis", "duration_weeks": 4},
            {"name": "Remediation", "duration_weeks": 12},
            {"name": "C3PAO Assessment", "duration_weeks": 6},
            {"name": "Certification", "duration_weeks": 4},
        ],
    },
    "stateramp": {
        "name": "StateRAMP",
        "authority": "StateRAMP PMO",
        "categories": ["FedRAMP-aligned controls for state/local"],
        "duration_months": 36,
        "renewal": "3-year (continuous monitoring)",
        "typical_controls": 230,
        "phases": [
            {"name": "Preparation", "duration_weeks": 6},
            {"name": "SSP & Assessment", "duration_weeks": 10},
            {"name": "Review & Authorization", "duration_weeks": 6},
        ],
    },
}


class CertTracker:
    """Track certification lifecycle and audit readiness."""

    def __init__(self):
        self._certs: dict[str, dict] = {}
        self._evidence: dict[str, list] = {}  # cert_id -> evidence items
        self._milestones: dict[str, list] = {}
        self._init_defaults()

    def _init_defaults(self):
        """Initialize default certification entries."""
        for key, info in CERTIFICATIONS.items():
            self._certs[key] = {
                "id": key,
                "name": info["name"],
                "authority": info["authority"],
                "status": "Not Started",
                "phase": "",
                "phase_progress": 0,
                "target_date": None,
                "start_date": None,
                "last_audit": None,
                "next_audit": None,
                "readiness_score": 0,
                "controls_total": info["typical_controls"],
                "controls_met": 0,
                "evidence_count": 0,
                "findings_open": 0,
            }
            self._evidence[key] = []
            self._milestones[key] = []

    def start_certification(self, cert_id: str, target_date: str = None) -> dict:
        """Begin a certification process."""
        if cert_id not in self._certs:
            return {"error": f"Unknown certification: {cert_id}"}

        cert = self._certs[cert_id]
        cert["status"] = "In Progress"
        cert["start_date"] = date.today().isoformat()
        cert["phase"] = CERTIFICATIONS[cert_id]["phases"][0]["name"]
        cert["phase_progress"] = 0

        if target_date:
            cert["target_date"] = target_date
        else:
            total_weeks = sum(p["duration_weeks"] for p in CERTIFICATIONS[cert_id]["phases"])
            cert["target_date"] = (date.today() + timedelta(weeks=total_weeks)).isoformat()

        # Create milestones
        current_date = date.today()
        for phase in CERTIFICATIONS[cert_id]["phases"]:
            end = current_date + timedelta(weeks=phase["duration_weeks"])
            self._milestones[cert_id].append({
                "phase": phase["name"],
                "start": current_date.isoformat(),
                "end": end.isoformat(),
                "status": "Pending",
                "duration_weeks": phase["duration_weeks"],
            })
            current_date = end

        log.info(f"[CertTracker] Started {cert['name']}, target: {cert['target_date']}")
        return cert

    def update_phase(self, cert_id: str, phase_name: str, progress: int = 100) -> dict:
        """Update phase progress."""
        if cert_id not in self._certs:
            return {"error": "Unknown cert"}
        cert = self._certs[cert_id]
        cert["phase"] = phase_name
        cert["phase_progress"] = min(progress, 100)

        for m in self._milestones.get(cert_id, []):
            if m["phase"] == phase_name:
                m["status"] = "Complete" if progress >= 100 else "In Progress"
        return cert

    def add_evidence(self, cert_id: str, evidence: dict) -> dict:
        """Add evidence artifact for a certification."""
        if cert_id not in self._evidence:
            return {"error": "Unknown cert"}
        item = {
            "id": f"EV-{len(self._evidence[cert_id])+1:04d}",
            "title": evidence.get("title", ""),
            "type": evidence.get("type", "document"),  # document, screenshot, log, config
            "control": evidence.get("control", ""),
            "description": evidence.get("description", ""),
            "file_path": evidence.get("file_path", ""),
            "collected_date": date.today().isoformat(),
            "status": evidence.get("status", "Collected"),
        }
        self._evidence[cert_id].append(item)
        self._certs[cert_id]["evidence_count"] = len(self._evidence[cert_id])
        return item

    def get_readiness_score(self, cert_id: str) -> dict:
        """Calculate audit readiness score."""
        if cert_id not in self._certs:
            return {"error": "Unknown cert"}

        cert = self._certs[cert_id]
        info = CERTIFICATIONS.get(cert_id, {})
        total_controls = info.get("typical_controls", 100)

        # Try to get actual control status from PostgreSQL
        controls_met = 0
        try:
            from cyber_range.services.pg_engine import pg_execute, _PG_AVAILABLE
            if _PG_AVAILABLE:
                r = pg_execute("""
                    SELECT count(*) FILTER (WHERE status='Implemented') AS met,
                           count(*) AS total
                    FROM system_controls WHERE system_id = 1
                """)
                if r and r[0]["total"]:
                    controls_met = r[0]["met"] or 0
                    total_controls = r[0]["total"]
        except Exception:
            pass

        evidence_count = len(self._evidence.get(cert_id, []))
        phases_complete = sum(
            1 for m in self._milestones.get(cert_id, [])
            if m["status"] == "Complete"
        )
        total_phases = len(self._milestones.get(cert_id, [])) or 1

        score = round(
            (controls_met / max(total_controls, 1)) * 40 +
            (evidence_count / max(total_controls * 0.5, 1)) * 30 +
            (phases_complete / total_phases) * 30,
            1
        )
        score = min(score, 100)

        cert["readiness_score"] = score
        cert["controls_met"] = controls_met
        cert["controls_total"] = total_controls

        return {
            "cert": cert_id,
            "readiness_score": score,
            "controls_met": controls_met,
            "controls_total": total_controls,
            "evidence_count": evidence_count,
            "phases_complete": phases_complete,
            "total_phases": total_phases,
        }

    def get_certification(self, cert_id: str) -> dict:
        """Get full certification status."""
        if cert_id not in self._certs:
            return {"error": "Unknown cert"}
        return {
            **self._certs[cert_id],
            "milestones": self._milestones.get(cert_id, []),
            "evidence": self._evidence.get(cert_id, []),
            "framework": CERTIFICATIONS.get(cert_id, {}),
        }

    def get_all_certifications(self) -> list[dict]:
        """Get status of all certifications."""
        results = []
        for cert_id in self._certs:
            self.get_readiness_score(cert_id)
            results.append(self._certs[cert_id])
        return results

    def get_cross_mapping(self) -> dict:
        """Show control mapping across certification frameworks."""
        mapping = {
            "AC (Access Control)":        {"soc2": "CC6.1-6.3", "iso27001": "A.9",   "fedramp": "AC-*",  "cmmc": "AC"},
            "AT (Awareness & Training)":  {"soc2": "CC1.4",     "iso27001": "A.7.2", "fedramp": "AT-*",  "cmmc": "AT"},
            "AU (Audit & Accountability)":{"soc2": "CC7.2",     "iso27001": "A.12.4","fedramp": "AU-*",  "cmmc": "AU"},
            "CA (Security Assessment)":   {"soc2": "CC4.1",     "iso27001": "A.18.2","fedramp": "CA-*",  "cmmc": "CA"},
            "CM (Config Management)":     {"soc2": "CC7.1",     "iso27001": "A.14.2","fedramp": "CM-*",  "cmmc": "CM"},
            "CP (Contingency Planning)":  {"soc2": "A1.2",      "iso27001": "A.17",  "fedramp": "CP-*",  "cmmc": "—"},
            "IA (ID & Authentication)":   {"soc2": "CC6.1",     "iso27001": "A.9.2", "fedramp": "IA-*",  "cmmc": "IA"},
            "IR (Incident Response)":     {"soc2": "CC7.3-7.5", "iso27001": "A.16",  "fedramp": "IR-*",  "cmmc": "IR"},
            "SC (System & Comms)":        {"soc2": "CC6.7",     "iso27001": "A.13",  "fedramp": "SC-*",  "cmmc": "SC"},
            "SI (System & Info Integrity)":{"soc2":"CC7.1-7.2", "iso27001": "A.12.2","fedramp": "SI-*",  "cmmc": "SI"},
        }
        return mapping


# Global tracker
_cert_tracker = CertTracker()


def get_tracker() -> CertTracker:
    return _cert_tracker
