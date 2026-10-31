"""
Findings Persistence Service
============================
Shared SQLite persistence layer for all platform modules.
Provides save/query/stats functions for the platform_findings
and platform_metrics tables in /opt/vuln_intel/vuln_intel.db
"""
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = "/opt/vuln_intel/vuln_intel.db"

# ── Schema ────────────────────────────────────────────────────────────
_INIT_SQL = """
CREATE TABLE IF NOT EXISTS platform_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'Medium',
    status      TEXT    NOT NULL DEFAULT 'Open',
    host        TEXT,
    description TEXT,
    mitre_id    TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    closed_at   TEXT
);

CREATE TABLE IF NOT EXISTS platform_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    date            TEXT    NOT NULL DEFAULT (date('now')),
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    mttd_hours      REAL    DEFAULT 0,
    mttr_hours      REAL    DEFAULT 0,
    modules_active  INTEGER DEFAULT 0
);
"""

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def _ensure_schema():
    with _conn() as c:
        c.executescript(_INIT_SQL)

# Initialise on import
_ensure_schema()


# ── Write ──────────────────────────────────────────────────────────────
def save_finding(module: str, title: str, severity: str = "Medium",
                 host: str = "", description: str = "", mitre_id: str = "") -> int:
    """Insert a new finding. Returns the new row id."""
    sql = """
        INSERT INTO platform_findings
               (module, title, severity, host, description, mitre_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    with _conn() as c:
        cur = c.execute(sql, (module, title, severity, host or "", description or "", mitre_id or ""))
        return cur.lastrowid


def close_finding(finding_id: int):
    """Mark a finding as Closed."""
    with _conn() as c:
        c.execute(
            "UPDATE platform_findings SET status='Closed', closed_at=datetime('now') WHERE id=?",
            (finding_id,)
        )


def update_finding_status(finding_id: int, status: str):
    """Update finding status (Open / In Progress / Closed / Accepted)."""
    with _conn() as c:
        c.execute("UPDATE platform_findings SET status=? WHERE id=?", (status, finding_id))


def snapshot_metrics():
    """Write today's aggregate counts to platform_metrics."""
    stats = get_summary_stats()
    with _conn() as c:
        c.execute("""
            INSERT INTO platform_metrics
                   (date, critical_count, high_count, medium_count, low_count)
            VALUES (date('now'), ?, ?, ?, ?)
        """, (
            stats.get("Critical", 0), stats.get("High", 0),
            stats.get("Medium", 0),  stats.get("Low", 0),
        ))


# ── Read ───────────────────────────────────────────────────────────────
def get_findings(module: str = None, status: str = None,
                 severity: str = None, limit: int = 200) -> list[dict]:
    """Return findings as a list of dicts."""
    clauses, params = [], []
    if module:
        clauses.append("module = ?"); params.append(module)
    if status:
        clauses.append("status = ?"); params.append(status)
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM platform_findings {where} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn() as c:
        rows = c.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_summary_stats() -> dict:
    """Return open finding counts by severity."""
    sql = """
        SELECT severity, COUNT(*) as cnt
        FROM platform_findings
        WHERE status = 'Open'
        GROUP BY severity
    """
    with _conn() as c:
        rows = c.execute(sql).fetchall()
    result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in rows:
        if row["severity"] in result:
            result[row["severity"]] = row["cnt"]
    result["total"] = sum(result.values())
    return result


def get_module_stats() -> dict:
    """Return finding counts grouped by module."""
    sql = """
        SELECT module, severity, COUNT(*) as cnt
        FROM platform_findings
        WHERE status='Open'
        GROUP BY module, severity
    """
    with _conn() as c:
        rows = c.execute(sql).fetchall()
    data: dict[str, dict] = {}
    for row in rows:
        m = row["module"]
        if m not in data:
            data[m] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        if row["severity"] in data[m]:
            data[m][row["severity"]] = row["cnt"]
    return data


def get_trend_data(days: int = 30) -> list[dict]:
    """
    Return daily finding counts for the last N days.
    One row per day with severity breakdown.
    """
    sql = """
        SELECT date(created_at) as day,
               SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical,
               SUM(CASE WHEN severity='High'     THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN severity='Medium'   THEN 1 ELSE 0 END) as medium,
               SUM(CASE WHEN severity='Low'      THEN 1 ELSE 0 END) as low
        FROM platform_findings
        WHERE created_at >= datetime('now', ?)
        GROUP BY day
        ORDER BY day
    """
    cutoff = f"-{days} days"
    with _conn() as c:
        rows = c.execute(sql, (cutoff,)).fetchall()
    return [dict(r) for r in rows]


def get_risk_score() -> int:
    """
    Compute a 0-100 aggregate risk score.
    Weighted: Critical=10, High=5, Medium=2, Low=1. Cap at 100.
    """
    stats = get_summary_stats()
    raw = (stats["Critical"] * 10 +
           stats["High"]     * 5  +
           stats["Medium"]   * 2  +
           stats["Low"]      * 1)
    return min(100, raw)


def get_recent_findings(limit: int = 20) -> list[dict]:
    """Return the most recent findings across all modules."""
    return get_findings(limit=limit)


def get_mttd_mttr() -> tuple[float, float]:
    """
    Calculate mean time to detect (hours from created_at to closed_at).
    MTTD is estimated as hours open before closure.
    Returns (mttd, mttr) in hours. Returns (0, 0) if insufficient data.
    """
    sql = """
        SELECT created_at, closed_at
        FROM platform_findings
        WHERE status = 'Closed' AND closed_at IS NOT NULL
        LIMIT 100
    """
    with _conn() as c:
        rows = c.execute(sql).fetchall()
    if not rows:
        return 0.0, 0.0
    durations = []
    for row in rows:
        try:
            t1 = datetime.fromisoformat(row["created_at"])
            t2 = datetime.fromisoformat(row["closed_at"])
            durations.append((t2 - t1).total_seconds() / 3600)
        except Exception:
            pass
    if not durations:
        return 0.0, 0.0
    avg = sum(durations) / len(durations)
    return round(avg * 0.6, 1), round(avg, 1)   # MTTD ~60% of MTTR


def seed_demo_data():
    """Seed a handful of demo findings so the dashboard is not empty on first run."""
    demo = [
        # ── IAM / Identity ────────────────────────────────────────────────
        ("IAM Red Team",       "MFA Fatigue successful on 3 accounts",           "Critical", "10.0.0.5", "T1621"),
        ("IAM Red Team",       "Legacy SMTP auth not blocked — MFA bypass",      "High",     "10.0.0.6", "T1078"),
        # ── LLM / AI Attacks — MITRE ATLAS (AML.T prefix) ────────────────
        ("LLM Red Team",       "System prompt extracted via jailbreak",           "Critical", "ai-api",   "AML.T0051.000"),
        ("LLM Red Team",       "Indirect RAG injection triggered SSRF",           "Critical", "ai-api",   "AML.T0054"),
        # ── Identity Posture ──────────────────────────────────────────────
        ("Identity Posture",   "MFA not enforced for all users",                  "Critical", "Entra ID", "T1556.006"),
        ("Identity Posture",   "14 stale guest accounts inactive > 90 days",     "High",     "Entra ID", "T1078"),
        # ── OAuth / Web ───────────────────────────────────────────────────
        ("OAuth Security",     "redirect_uri accepts wildcard — token theft",     "Critical", "auth-srv",  "T1528"),
        ("OAuth Security",     "Implicit flow enabled — token in URL fragment",   "High",     "auth-srv",  "T1528"),
        # ── EDR Coverage ─────────────────────────────────────────────────
        ("EDR Gaps",           "WMI remote execution not detected (T1047)",       "Critical", "WRK*",     "T1047"),
        ("EDR Gaps",           "DLL sideloading undetected in 3/3 tests",        "Critical", "WRK*",     "T1574.002"),
        # ── Mobile — OWASP MASVS ─────────────────────────────────────────
        ("Mobile Security",    "API key hardcoded in APK strings",               "Critical", "mobile",   "MASVS-STORAGE-2"),
        ("Mobile Security",    "Certificate pinning bypassed via Frida",         "Critical", "mobile",   "MASVS-RESILIENCE-4"),
        # ── Operational ──────────────────────────────────────────────────
        ("IR Playbooks",       "No IR playbook for cloud-native incident",       "High",     "Platform", ""),
        ("DFIR Case",          "CASE-001: Ransomware Finance Dept — Active",     "Critical", "Internal", ""),
        ("Shadow AI",          "GitHub Copilot personal accounts detected",       "Critical", "Endpoints",""),
        ("AI Model Hardening", "Inference API exposed without authentication",   "Critical", "ai-svc",   ""),
    ]
    existing = get_findings(limit=1)
    if existing:
        return  # Already seeded
    for module, title, sev, host, mitre in demo:
        save_finding(module, title, sev, host, "", mitre)
