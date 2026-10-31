# ================================================================
# pg_engine.py  —  PostgreSQL connection factory
#
# Usage:
#   from cyber_range.services.pg_engine import pg_execute, audit, get_pg
#
#   # Simple query
#   rows = pg_execute("SELECT * FROM audit_log LIMIT 10")
#
#   # Write an audit event
#   audit("admin", "run_scan", module="Pentest", target="192.168.1.1")
#
#   # Context-managed connection
#   with get_pg() as conn:
#       with conn.cursor() as cur:
#           cur.execute("SELECT count(*) FROM exploit_log")
# ================================================================

import os
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ── Optional psycopg2 import ─────────────────────────────────────
try:
    import psycopg2
    import psycopg2.extras
    _PG_AVAILABLE = True
except ImportError:
    _PG_AVAILABLE = False
    log.warning("[PG] psycopg2 not installed — PostgreSQL features disabled. "
                "Install with: pip install psycopg2-binary")


def _get_dsn() -> str:
    """Resolve DSN: Vault → env var → hardcoded default."""
    try:
        from cyber_range.services.vault_client import get_postgres_dsn
        dsn = get_postgres_dsn()
        if dsn:
            return dsn
    except Exception:
        pass
    return os.getenv(
        "POSTGRES_DSN",
        "postgresql://vuln_admin:VuIntelPg2026!@localhost:5432/vuln_intel"
    )


@contextmanager
def get_pg():
    """
    Context manager that yields a psycopg2 connection.
    Auto-commits on success, rolls back on exception.
    Returns None if psycopg2 is unavailable.
    """
    if not _PG_AVAILABLE:
        yield None
        return

    conn = None
    try:
        conn = psycopg2.connect(_get_dsn())
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("[PG] Error: %s", e)
        raise
    finally:
        if conn:
            conn.close()


def pg_execute(sql: str, params=None, fetch: bool = True):
    """
    Run a single SQL statement.
    Returns list of dicts on SELECT, row count on INSERT/UPDATE/DELETE.
    Returns [] / 0 if PG unavailable.
    """
    if not _PG_AVAILABLE:
        return [] if fetch else 0

    try:
        with get_pg() as conn:
            if conn is None:
                return [] if fetch else 0
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                if fetch:
                    return [dict(r) for r in cur.fetchall()]
                return cur.rowcount
    except Exception as e:
        log.error("[PG] pg_execute error: %s", e)
        return [] if fetch else 0


def audit(
    username: str,
    action: str,
    module: str = None,
    target: str = None,
    detail: dict = None,
    ip_address: str = None,
    success: bool = True,
):
    """
    Write one row to the audit_log table.
    Silently no-ops if PostgreSQL is unavailable.
    """
    if not _PG_AVAILABLE:
        return
    try:
        pg_execute(
            """
            INSERT INTO audit_log
                (username, action, module, target, detail, ip_address, success)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                username or "anonymous",
                action,
                module,
                target,
                json.dumps(detail or {}),
                ip_address,
                success,
            ),
            fetch=False,
        )
    except Exception as e:
        log.warning("[PG] audit() failed silently: %s", e)


def log_exploit(result: dict):
    """
    Persist an Aggressive Mode result dict into exploit_log.
    Called from exploit_engine.execute_attack().
    """
    if not _PG_AVAILABLE:
        return
    try:
        pg_execute(
            """
            INSERT INTO exploit_log
                (asset_ip, vuln_name, cve_id,
                 searchsploit, github_pocs, execution, metasploit,
                 success, log_file)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                result.get("asset"),
                result.get("vulnerability"),
                result.get("cve") or "",
                json.dumps(result.get("searchsploit", [])),
                json.dumps(result.get("github", [])),
                json.dumps(result.get("execution", {})),
                json.dumps(result.get("metasploit", {})),
                bool(
                    result.get("execution", {}).get("success")
                    or result.get("metasploit", {}).get("success")
                ),
                result.get("log_file"),
            ),
            fetch=False,
        )
    except Exception as e:
        log.warning("[PG] log_exploit() failed silently: %s", e)


def store_cve(
    cve_id: str,
    epss_score: float = None,
    epss_pct: float = None,
    in_kev: bool = False,
    kev_date=None,
    cvss_score: float = None,
    cvss_vector: str = None,
    description: str = None,
):
    """
    Upsert one CVE record into cve_cache.
    """
    if not _PG_AVAILABLE:
        return
    try:
        pg_execute(
            """
            INSERT INTO cve_cache
                (cve_id, epss_score, epss_pct, in_kev, kev_date,
                 cvss_score, cvss_vector, description, fetched_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (cve_id) DO UPDATE SET
                epss_score  = EXCLUDED.epss_score,
                epss_pct    = EXCLUDED.epss_pct,
                in_kev      = EXCLUDED.in_kev,
                kev_date    = EXCLUDED.kev_date,
                cvss_score  = EXCLUDED.cvss_score,
                cvss_vector = EXCLUDED.cvss_vector,
                description = EXCLUDED.description,
                fetched_at  = NOW()
            """,
            (cve_id, epss_score, epss_pct, in_kev, kev_date,
             cvss_score, cvss_vector, description),
            fetch=False,
        )
    except Exception as e:
        log.warning("[PG] store_cve() failed silently: %s", e)


def get_cve_cache(cve_id: str) -> dict | None:
    """
    Retrieve a cached CVE record. Returns None if not cached or PG unavailable.
    """
    if not _PG_AVAILABLE:
        return None
    rows = pg_execute(
        "SELECT * FROM cve_cache WHERE cve_id = %s", (cve_id,)
    )
    return rows[0] if rows else None


def get_recent_audit(limit: int = 100) -> list[dict]:
    """Fetch the most recent audit log rows."""
    return pg_execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s", (limit,)
    )


# ── Sanity check ─────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("PG available:", _PG_AVAILABLE)
    if _PG_AVAILABLE:
        for tbl in ("audit_log", "scan_reports", "exploit_log", "cve_cache"):
            rows = pg_execute(f"SELECT count(*) AS n FROM {tbl}")
            print(f"  {tbl}: {rows[0]['n'] if rows else '?'} rows")
