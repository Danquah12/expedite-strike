"""
Expedite Strike -- Scan History & Persistence Service
=====================================================
Thread-safe SQLite storage for authentication bypass and external penetration
testing assessments, enabling historical tracking, delta comparisons, and re-reporting.
"""

import os
import json
import sqlite3
import threading
from typing import Dict, List, Optional, Any

_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_DB_PATH = os.path.join(_DB_DIR, "auth_bypass_history.db")
_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    os.makedirs(_DB_DIR, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the SQLite tables for scan history."""
    with _lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS auth_scans (
                        scan_id TEXT PRIMARY KEY,
                        created_at REAL,
                        target_url TEXT,
                        protocol TEXT,
                        vulnerable_count INTEGER,
                        secure_count INTEGER,
                        na_count INTEGER,
                        error_count INTEGER,
                        checks_run INTEGER,
                        summary TEXT,
                        mitre_ids TEXT,
                        severity_counts_json TEXT,
                        findings_json TEXT,
                        status TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_scans_created ON auth_scans(created_at DESC)")
        finally:
            conn.close()


init_db()


def save_scan(scan_dict: Dict[str, Any]) -> bool:
    """Save or update an authentication scan record."""
    if not scan_dict or not scan_dict.get("scan_id"):
        return False

    import time
    scan_id = scan_dict["scan_id"]
    created_at = scan_dict.get("start_time", time.time())
    target_url = scan_dict.get("target_url", "")
    protocol = scan_dict.get("protocol_detected", scan_dict.get("protocol", "auto"))
    vulnerable_count = scan_dict.get("vulnerable_count", 0)
    secure_count = scan_dict.get("secure_count", 0)
    na_count = scan_dict.get("na_count", 0)
    error_count = scan_dict.get("error_count", 0)
    checks_run = scan_dict.get("checks_run", len(scan_dict.get("findings", [])))
    summary = scan_dict.get("summary", "")
    mitre_ids = ",".join(scan_dict.get("mitre_ids", []))
    severity_counts_json = json.dumps(scan_dict.get("severity_counts", {}))
    findings_json = json.dumps(scan_dict.get("findings", []))
    status = scan_dict.get("status", "done")

    with _lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO auth_scans (
                        scan_id, created_at, target_url, protocol,
                        vulnerable_count, secure_count, na_count, error_count,
                        checks_run, summary, mitre_ids, severity_counts_json,
                        findings_json, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        vulnerable_count=excluded.vulnerable_count,
                        secure_count=excluded.secure_count,
                        na_count=excluded.na_count,
                        error_count=excluded.error_count,
                        checks_run=excluded.checks_run,
                        summary=excluded.summary,
                        mitre_ids=excluded.mitre_ids,
                        severity_counts_json=excluded.severity_counts_json,
                        findings_json=excluded.findings_json,
                        status=excluded.status
                """, (
                    scan_id, created_at, target_url, protocol,
                    vulnerable_count, secure_count, na_count, error_count,
                    checks_run, summary, mitre_ids, severity_counts_json,
                    findings_json, status
                ))
            return True
        except Exception as exc:
            print(f"[SCAN-HISTORY] Error saving scan {scan_id}: {exc}")
            return False
        finally:
            conn.close()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a scan by its scan_id."""
    with _lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM auth_scans WHERE scan_id = ?", (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "scan_id": row["scan_id"],
                "created_at": row["created_at"],
                "target_url": row["target_url"],
                "protocol": row["protocol"],
                "protocol_detected": row["protocol"],
                "vulnerable_count": row["vulnerable_count"],
                "secure_count": row["secure_count"],
                "na_count": row["na_count"],
                "error_count": row["error_count"],
                "checks_run": row["checks_run"],
                "summary": row["summary"],
                "mitre_ids": [m for m in row["mitre_ids"].split(",") if m] if row["mitre_ids"] else [],
                "severity_counts": json.loads(row["severity_counts_json"] or "{}"),
                "findings": json.loads(row["findings_json"] or "[]"),
                "status": row["status"],
            }
        finally:
            conn.close()


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """List recent scans ordered by creation time descending."""
    with _lock:
        conn = _get_connection()
        try:
            cur = conn.execute("""
                SELECT scan_id, created_at, target_url, protocol,
                       vulnerable_count, secure_count, na_count, error_count,
                       checks_run, summary, mitre_ids, severity_counts_json, status
                FROM auth_scans
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            results = []
            for r in rows:
                results.append({
                    "scan_id": r["scan_id"],
                    "created_at": r["created_at"],
                    "target_url": r["target_url"],
                    "protocol": r["protocol"],
                    "vulnerable_count": r["vulnerable_count"],
                    "secure_count": r["secure_count"],
                    "na_count": r["na_count"],
                    "error_count": r["error_count"],
                    "checks_run": r["checks_run"],
                    "summary": r["summary"],
                    "mitre_ids": [m for m in r["mitre_ids"].split(",") if m] if r["mitre_ids"] else [],
                    "severity_counts": json.loads(r["severity_counts_json"] or "{}"),
                    "status": r["status"],
                })
            return results
        finally:
            conn.close()


def delete_scan(scan_id: str) -> bool:
    """Delete a scan record from history."""
    with _lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM auth_scans WHERE scan_id = ?", (scan_id,))
            return True
        finally:
            conn.close()
