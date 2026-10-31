"""
Expedite Strike — Multi-Tenant MSSP & White-Label Workspace Manager
===================================================================
Manages client workspaces, organization profiles, custom branding,
and role-based assessment scoping for Managed Security Service Providers (MSSPs).
"""

import os
import json
import time
import uuid
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

    # ── PROJECT ISOLATION ─────────────────────────────────────────────────────

    @classmethod
    def create_project_workspace(
        cls,
        name: str,
        industry: str = "General Enterprise",
        targets: Optional[List[str]] = None,
        lead_tester: str = "Autonomous Assessment Engine",
        agency_name: str = "Expedite Consults Ltd",
        classification: str = "CONFIDENTIAL",
        compliance_frameworks: Optional[List[str]] = None,
        rules_of_engagement: str = "",
        scope_notes: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Create a new fully-isolated client project workspace.

        Each workspace gets:
          * A unique org_<id> workspace_id
          * Its own scan history SQLite DB at scan_cache/<ws_id>/scan_history.db
          * Its own findings directory at scan_cache/<ws_id>/findings/
          * Engagement metadata (RoE, scope, compliance)

        Returns the created workspace dict.
        """
        if not cls._workspaces:
            cls.initialize()

        ws_id = f"org_{uuid.uuid4().hex[:10]}"
        ws = {
            "id": ws_id,
            "name": name,
            "industry": industry,
            "targets": targets or [],
            "lead_tester": lead_tester,
            "agency_name": agency_name,
            "classification": classification,
            "compliance_frameworks": compliance_frameworks or ["ISO 27001"],
            "rules_of_engagement": rules_of_engagement,
            "scope_notes": scope_notes,
            "notes": notes,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Create isolated directories for this workspace
        ws_dir = os.path.join(_WS_CACHE_DIR, ws_id)
        findings_dir = os.path.join(ws_dir, "findings")
        os.makedirs(findings_dir, exist_ok=True)

        # Write engagement metadata file inside isolated dir
        meta_path = os.path.join(ws_dir, "engagement_meta.json")
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(ws, f, indent=2)
        except Exception:
            pass

        cls._workspaces[ws_id] = ws
        cls.save()
        return ws

    @classmethod
    def get_scan_db_path(cls, workspace_id: Optional[str] = None) -> str:
        """
        Return the per-workspace SQLite scan history DB path.
        Falls back to the shared scan_history.db if workspace not found.
        """
        ws_id = workspace_id or cls._active_ws_id
        ws_dir = os.path.join(_WS_CACHE_DIR, ws_id)
        if os.path.isdir(ws_dir):
            return os.path.join(ws_dir, "scan_history.db")
        # Fall back to shared DB
        return os.path.join(_WS_CACHE_DIR, "..", "scan_history.db")

    @classmethod
    def get_findings_dir(cls, workspace_id: Optional[str] = None) -> str:
        """Return the per-workspace findings storage directory, creating it if needed."""
        ws_id = workspace_id or cls._active_ws_id
        findings_dir = os.path.join(_WS_CACHE_DIR, ws_id, "findings")
        os.makedirs(findings_dir, exist_ok=True)
        return findings_dir

    @classmethod
    def save_findings_snapshot(
        cls,
        scan_id: str,
        findings: List[Dict[str, Any]],
        workspace_id: Optional[str] = None,
    ) -> str:
        """
        Persist a findings snapshot to the workspace-isolated findings directory.
        Returns the file path written.
        """
        findings_dir = cls.get_findings_dir(workspace_id)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"findings_{scan_id[:12]}_{ts}.json"
        fpath = os.path.join(findings_dir, filename)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_id": scan_id,
                    "workspace_id": workspace_id or cls._active_ws_id,
                    "exported_at": ts,
                    "total": len(findings),
                    "findings": findings,
                }, f, indent=2, default=str)
        except Exception:
            pass
        return fpath

    @classmethod
    def list_findings_snapshots(cls, workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all findings snapshot files for a workspace."""
        findings_dir = cls.get_findings_dir(workspace_id)
        snapshots = []
        for fname in sorted(os.listdir(findings_dir), reverse=True):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(findings_dir, fname)
            try:
                stat = os.stat(fpath)
                with open(fpath, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                snapshots.append({
                    "filename": fname,
                    "path": fpath,
                    "scan_id": meta.get("scan_id", ""),
                    "exported_at": meta.get("exported_at", ""),
                    "total_findings": meta.get("total", 0),
                    "size_kb": round(stat.st_size / 1024, 1),
                })
            except Exception:
                pass
        return snapshots

    @classmethod
    def archive_engagement(cls, workspace_id: str) -> Optional[str]:
        """
        Archive a completed engagement: zip the entire workspace directory
        (findings, DB, metadata) and return the archive path.
        """
        import zipfile
        ws = cls._workspaces.get(workspace_id)
        if not ws:
            return None
        ws_dir = os.path.join(_WS_CACHE_DIR, workspace_id)
        if not os.path.isdir(ws_dir):
            return None
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"engagement_{workspace_id}_{ts}.zip"
        archive_path = os.path.join(_WS_CACHE_DIR, archive_name)
        try:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _dirs, files in os.walk(ws_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, _WS_CACHE_DIR)
                        zf.write(fpath, arcname)
            return archive_path
        except Exception:
            return None

    @classmethod
    def delete_workspace(cls, workspace_id: str, archive_first: bool = True) -> bool:
        """
        Delete a workspace. Optionally archive it before deletion.
        Returns True on success.
        """
        import shutil
        if workspace_id == "org_default":
            return False  # Never delete the default workspace
        if archive_first:
            cls.archive_engagement(workspace_id)
        ws_dir = os.path.join(_WS_CACHE_DIR, workspace_id)
        try:
            if os.path.isdir(ws_dir):
                shutil.rmtree(ws_dir, ignore_errors=True)
        except Exception:
            pass
        cls._workspaces.pop(workspace_id, None)
        if cls._active_ws_id == workspace_id:
            cls._active_ws_id = "org_default"
        cls.save()
        return True


# Auto-initialize on module load
WorkspaceManager.initialize()
