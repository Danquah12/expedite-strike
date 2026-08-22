"""
AD Security Tools — Evidence Store (Postgres + SQLite)
======================================================
Production: Postgres (via pg_engine.py) for concurrency, RBAC, scalability.
Development: SQLite fallback for local/offline usage.
"""

import os
import sqlite3
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Backend detection ────────────────────────────────────────────────
_USE_PG = False
_pg_execute = None

try:
    from cyber_range.services.pg_engine import pg_execute as _pg_exec, get_pg, _PG_AVAILABLE
    if _PG_AVAILABLE:
        _USE_PG = True
        _pg_execute = _pg_exec
        logger.info("[EvidenceStore] Using PostgreSQL backend")
except ImportError:
    pass

if not _USE_PG:
    logger.info("[EvidenceStore] Using SQLite backend (fallback)")

# ── SQLite fallback path ─────────────────────────────────────────────
_SQLITE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ad_evidence.db")
_SQLITE_PATH = os.path.normpath(_SQLITE_PATH)

# ── Postgres schema ──────────────────────────────────────────────────
_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS ad_assessments (
    id TEXT PRIMARY KEY,
    organization TEXT,
    target_domain TEXT,
    scope TEXT,
    mode TEXT DEFAULT 'passive',
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    status TEXT DEFAULT 'running',
    score INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ad_evidence (
    id TEXT PRIMARY KEY,
    assessment_id TEXT REFERENCES ad_assessments(id),
    tool TEXT NOT NULL,
    target TEXT,
    raw_output TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'success'
);

CREATE TABLE IF NOT EXISTS ad_findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT REFERENCES ad_assessments(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    affected_object TEXT,
    evidence_ids TEXT,
    mitre_id TEXT,
    nist_csf TEXT DEFAULT '',
    cis_control TEXT DEFAULT '',
    cvss REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.8,
    category TEXT,
    remediation TEXT DEFAULT '',
    attack_path TEXT DEFAULT '',
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ad_evidence_assessment ON ad_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ad_findings_assessment ON ad_findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ad_findings_severity ON ad_findings(severity);
"""

# ── SQLite schema ────────────────────────────────────────────────────
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ad_assessments (
    id TEXT PRIMARY KEY,
    organization TEXT,
    target_domain TEXT,
    scope TEXT,
    mode TEXT DEFAULT 'passive',
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'running',
    score INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ad_evidence (
    id TEXT PRIMARY KEY,
    assessment_id TEXT,
    tool TEXT,
    target TEXT,
    raw_output TEXT,
    timestamp TEXT,
    status TEXT DEFAULT 'success'
);

CREATE TABLE IF NOT EXISTS ad_findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT,
    title TEXT,
    severity TEXT,
    description TEXT,
    affected_object TEXT,
    evidence_ids TEXT,
    mitre_id TEXT,
    nist_csf TEXT DEFAULT '',
    cis_control TEXT DEFAULT '',
    cvss REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.8,
    category TEXT,
    remediation TEXT DEFAULT '',
    attack_path TEXT DEFAULT '',
    timestamp TEXT
);
"""

# ── Counters ─────────────────────────────────────────────────────────
_ev_counter = 0
_fnd_counter = 0


# ── SQLite connection ────────────────────────────────────────────────
def _sqlite_conn():
    conn = sqlite3.connect(_SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _sqlite_exec(sql, params=None, fetch=True):
    """Execute SQL against SQLite."""
    try:
        conn = _sqlite_conn()
        cur = conn.execute(sql, params or ())
        if fetch:
            rows = [dict(r) for r in cur.fetchall()]
        else:
            rows = cur.rowcount
        conn.commit()
        conn.close()
        return rows
    except Exception as e:
        logger.error(f"[EvidenceStore] SQLite error: {e}")
        return [] if fetch else 0


def _exec(sql_pg, sql_sqlite=None, params=None, fetch=True):
    """Execute against Postgres (primary) or SQLite (fallback)."""
    if _USE_PG:
        try:
            return _pg_execute(sql_pg, params, fetch=fetch)
        except Exception as e:
            logger.warning(f"[EvidenceStore] PG failed, falling back to SQLite: {e}")
    return _sqlite_exec(sql_sqlite or sql_pg, params, fetch)


# ── Initialize ───────────────────────────────────────────────────────
def init_db():
    """Initialize evidence database schema."""
    if _USE_PG:
        try:
            with get_pg() as conn:
                if conn:
                    with conn.cursor() as cur:
                        cur.execute(_PG_SCHEMA)
            logger.info("[EvidenceStore] Postgres schema initialized")
        except Exception as e:
            logger.warning(f"[EvidenceStore] PG schema init failed: {e}")

    # Always init SQLite too (fallback)
    try:
        conn = _sqlite_conn()
        conn.executescript(_SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        logger.info(f"[EvidenceStore] SQLite initialized at {_SQLITE_PATH}")
    except Exception as e:
        logger.error(f"[EvidenceStore] SQLite init error: {e}")


# ── Assessment CRUD ──────────────────────────────────────────────────
def create_assessment(org: str, domain: str, scope: str = "",
                      mode: str = "passive") -> str:
    """Create a new assessment. Returns assessment ID."""
    global _ev_counter, _fnd_counter
    _ev_counter = 0
    _fnd_counter = 0
    aid = f"AD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    now = datetime.now(timezone.utc).isoformat()

    _exec(
        "INSERT INTO ad_assessments (id, organization, target_domain, scope, mode, start_time, status) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        "INSERT INTO ad_assessments (id, organization, target_domain, scope, mode, start_time, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (aid, org, domain, scope, mode, now, "running"),
        fetch=False
    )
    return aid


def complete_assessment(assessment_id: str, score: int = 0):
    """Mark assessment as complete."""
    now = datetime.now(timezone.utc).isoformat()
    _exec(
        "UPDATE ad_assessments SET status = %s, end_time = %s, score = %s WHERE id = %s",
        "UPDATE ad_assessments SET status = ?, end_time = ?, score = ? WHERE id = ?",
        ("complete", now, score, assessment_id),
        fetch=False
    )


# ── Evidence CRUD ────────────────────────────────────────────────────
def log_evidence(assessment_id: str, tool: str, target: str,
                 raw_output: str, status: str = "success") -> str:
    """Log tool invocation as evidence. Returns EV-xxxx ID."""
    global _ev_counter
    _ev_counter += 1
    eid = f"EV-{_ev_counter:04d}"
    now = datetime.now(timezone.utc).isoformat()
    raw = (raw_output or "")[:10000]

    _exec(
        "INSERT INTO ad_evidence (id, assessment_id, tool, target, raw_output, timestamp, status) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        "INSERT INTO ad_evidence (id, assessment_id, tool, target, raw_output, timestamp, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (eid, assessment_id, tool, target, raw, now, status),
        fetch=False
    )
    return eid


# ── Finding CRUD ─────────────────────────────────────────────────────
def save_finding(assessment_id: str, title: str, severity: str,
                 description: str, affected_object: str = "",
                 evidence_ids: list = None, mitre_id: str = "",
                 nist_csf: str = "", cis_control: str = "",
                 cvss: float = 0.0, confidence: float = 0.8,
                 category: str = "AD", remediation: str = "",
                 attack_path: str = "") -> str:
    """Save a finding with evidence chain. Returns FND-xxxx ID."""
    global _fnd_counter
    _fnd_counter += 1
    fid = f"FND-{_fnd_counter:04d}"
    ev_str = ",".join(evidence_ids) if evidence_ids else ""
    now = datetime.now(timezone.utc).isoformat()

    _exec(
        "INSERT INTO ad_findings (id, assessment_id, title, severity, description, "
        "affected_object, evidence_ids, mitre_id, nist_csf, cis_control, "
        "cvss, confidence, category, remediation, attack_path, timestamp) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        "INSERT INTO ad_findings (id, assessment_id, title, severity, description, "
        "affected_object, evidence_ids, mitre_id, nist_csf, cis_control, "
        "cvss, confidence, category, remediation, attack_path, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (fid, assessment_id, title, severity, description, affected_object,
         ev_str, mitre_id, nist_csf, cis_control, cvss, confidence,
         category, remediation, attack_path, now),
        fetch=False
    )
    return fid


# ── Queries ──────────────────────────────────────────────────────────
def get_findings(assessment_id: str) -> list:
    """Retrieve all findings for an assessment, ordered by severity."""
    return _exec(
        "SELECT * FROM ad_findings WHERE assessment_id = %s "
        "ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        "WHEN 'Medium' THEN 2 ELSE 3 END",
        "SELECT * FROM ad_findings WHERE assessment_id = ? "
        "ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        "WHEN 'Medium' THEN 2 ELSE 3 END",
        (assessment_id,)
    )


def get_evidence_chain(finding_id: str) -> list:
    """Get all evidence records linked to a finding."""
    rows = _exec(
        "SELECT evidence_ids FROM ad_findings WHERE id = %s",
        "SELECT evidence_ids FROM ad_findings WHERE id = ?",
        (finding_id,)
    )
    if not rows or not rows[0].get("evidence_ids"):
        return []
    ev_ids = rows[0]["evidence_ids"].split(",")
    # Build query for both backends
    if _USE_PG:
        placeholders = ",".join(["%s"] * len(ev_ids))
    else:
        placeholders = ",".join(["?"] * len(ev_ids))
    return _exec(
        f"SELECT * FROM ad_evidence WHERE id IN ({','.join(['%s']*len(ev_ids))})",
        f"SELECT * FROM ad_evidence WHERE id IN ({','.join(['?']*len(ev_ids))})",
        tuple(ev_ids)
    )


def get_assessment_summary(assessment_id: str) -> dict:
    """Get assessment summary with finding counts."""
    rows = _exec(
        "SELECT * FROM ad_assessments WHERE id = %s",
        "SELECT * FROM ad_assessments WHERE id = ?",
        (assessment_id,)
    )
    if not rows:
        return {}
    assessment = rows[0]

    findings = _exec(
        "SELECT severity, COUNT(*) as cnt FROM ad_findings "
        "WHERE assessment_id = %s GROUP BY severity",
        "SELECT severity, COUNT(*) as cnt FROM ad_findings "
        "WHERE assessment_id = ? GROUP BY severity",
        (assessment_id,)
    )
    sev = {r["severity"]: r["cnt"] for r in findings}

    ev_count = _exec(
        "SELECT COUNT(*) as n FROM ad_evidence WHERE assessment_id = %s",
        "SELECT COUNT(*) as n FROM ad_evidence WHERE assessment_id = ?",
        (assessment_id,)
    )
    return {
        **assessment,
        "finding_counts": sev,
        "total_findings": sum(sev.values()),
        "total_evidence": ev_count[0]["n"] if ev_count else 0,
        "backend": "postgres" if _USE_PG else "sqlite",
    }


# Initialize on import
init_db()
