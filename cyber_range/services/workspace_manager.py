"""
Expedite Strike — Multi-Tenant MSSP & White-Label Workspace Manager
===================================================================
Manages client workspaces, organization profiles, custom branding,
and role-based assessment scoping for Managed Security Service Providers (MSSPs).
"""

import os
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

_WS_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scan_cache")
os.makedirs(_WS_CACHE_DIR, exist_ok=True)
_WS_CACHE_FILE = os.path.join(_WS_CACHE_DIR, "mssp_workspaces.json")


DEFAULT_WORKSPACES = [
    {
        "id": "org_default",
        "name": "Acme Financial Services",
        "industry": "Financial Services & Banking",
        "lead_tester": "Expedite Strike Autonomous Engine",
        "agency_name": "Expedite Consults Ltd",
        "classification": "CONFIDENTIAL",
        "targets": ["192.168.195.139", "192.168.195.140", "api.acmefinance.local"],
        "compliance_frameworks": ["PCI-DSS", "NIST 800-53", "ISO 27001", "SOC2"],
        "notes": "Primary external perimeter & core banking API endpoints.",
        "created_at": "2026-08-01 09:00:00",
    },
    {
        "id": "org_apex_health",
        "name": "Apex Healthcare Systems",
        "industry": "Healthcare & Life Sciences",
        "lead_tester": "Cyber Assurance Team",
        "agency_name": "Expedite Consults Ltd",
        "classification": "RESTRICTED / HIPAA",
        "targets": ["portal.apexhealth.org", "192.168.195.155", "ehr-api.apexhealth.internal"],
        "compliance_frameworks": ["HIPAA", "NIST CSF", "HITRUST"],
        "notes": "Electronic Health Record (EHR) perimeter & patient portal.",
        "created_at": "2026-08-10 14:30:00",
    },
    {
        "id": "org_global_logistics",
        "name": "Global Freight & Logistics",
        "industry": "Supply Chain & Logistics",
        "lead_tester": "Senior Security Consultant",
        "agency_name": "Expedite Consults Ltd",
        "classification": "CONFIDENTIAL",
        "targets": ["tracking.globallog.com", "fleet-gw.globallog.com"],
        "compliance_frameworks": ["ISO 27001", "CIS Controls", "GDPR"],
        "notes": "Supply chain telematics gateway and web fleet portal.",
        "created_at": "2026-08-15 11:00:00",
    },
]


class WorkspaceManager:
    """Manages multi-tenant client workspaces and white-label branding configurations."""

    _workspaces: Dict[str, Dict[str, Any]] = {}
    _active_ws_id: str = "org_default"

    @classmethod
    def initialize(cls):
        """Load workspaces from disk cache or initialize defaults."""
        if os.path.exists(_WS_CACHE_FILE):
            try:
                with open(_WS_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cls._workspaces = {w["id"]: w for w in data.get("workspaces", [])}
                    cls._active_ws_id = data.get("active_id", "org_default")
            except Exception:
                pass

        if not cls._workspaces:
            cls._workspaces = {w["id"]: w for w in DEFAULT_WORKSPACES}
            cls.save()

    @classmethod
    def save(cls):
        """Persist workspaces to disk."""
        try:
            with open(_WS_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "active_id": cls._active_ws_id,
                    "workspaces": list(cls._workspaces.values()),
                    "saved_at": time.time(),
                }, f, indent=2)
        except Exception:
            pass

    @classmethod
    def list_workspaces(cls) -> List[Dict[str, Any]]:
        """Return all available client organization workspaces."""
        if not cls._workspaces:
            cls.initialize()
        return list(cls._workspaces.values())

    @classmethod
    def get_active_workspace(cls) -> Dict[str, Any]:
        """Return the currently active client organization profile."""
        if not cls._workspaces:
            cls.initialize()
        return cls._workspaces.get(cls._active_ws_id, DEFAULT_WORKSPACES[0])

    @classmethod
    def set_active_workspace(cls, ws_id: str) -> Dict[str, Any]:
        """Switch the active client workspace."""
        if not cls._workspaces:
            cls.initialize()
        if ws_id in cls._workspaces:
            cls._active_ws_id = ws_id
            cls.save()
        return cls.get_active_workspace()

    @classmethod
    def create_or_update_workspace(cls, ws_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a client organization workspace."""
        if not cls._workspaces:
            cls.initialize()
        ws_id = ws_data.get("id") or f"org_{int(time.time())}"
        ws_data["id"] = ws_id
        ws_data.setdefault("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        cls._workspaces[ws_id] = ws_data
        cls.save()
        return ws_data

    @classmethod
    def get_report_config(cls, scan_target: str = "") -> Dict[str, Any]:
        """Generate ReportLab metadata config matching the active workspace."""
        ws = cls.get_active_workspace()
        return {
            "client_name": ws.get("name", "Client Organization"),
            "system_name": f"{ws.get('name', 'Target Environment')} — External Surface ({scan_target or 'Perimeter'})",
            "lead_tester": ws.get("lead_tester", "Autonomous Assessment Engine"),
            "team_name": ws.get("agency_name", "Expedite Consults Ltd"),
            "classification": ws.get("classification", "CONFIDENTIAL"),
            "industry": ws.get("industry", "General Enterprise"),
            "compliance_frameworks": ws.get("compliance_frameworks", ["PCI-DSS", "NIST", "ISO 27001"]),
        }


# Auto-initialize on module load
WorkspaceManager.initialize()
