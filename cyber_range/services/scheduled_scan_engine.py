"""
scheduled_scan_engine.py
========================
Expedite Strike - Recurring Scan Scheduler with Delta Comparison.

Features:
  * SQLite-backed schedule store (scan_schedules.db)
  * cron-style expressions (daily, weekly, interval-based)
  * Per-workspace / per-client scan queues
  * Delta comparison: NEW / RESOLVED / UNCHANGED / REGRESSED findings
  * Background daemon thread - starts automatically on import
  * Callbacks for on_scan_complete and on_delta_alert
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "scan_schedules.db"
)

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


def _conn():
    c = sqlite3.connect(_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id     TEXT PRIMARY KEY,
                workspace_id    TEXT NOT NULL,
                label           TEXT,
                targets         TEXT NOT NULL,
                phases          TEXT,
                auth_username   TEXT DEFAULT '',
                auth_password   TEXT DEFAULT '',
                auth_header     TEXT DEFAULT '',
                auth_cookie     TEXT DEFAULT '',
                recurrence      TEXT NOT NULL,
                interval_hours  REAL DEFAULT 24,
                day_of_week     INTEGER DEFAULT 1,
                hour_of_day     INTEGER DEFAULT 2,
                minute_of_hour  INTEGER DEFAULT 0,
                enabled         INTEGER DEFAULT 1,
                next_run_ts     REAL,
                last_scan_id    TEXT,
                last_run_ts     REAL,
                run_count       INTEGER DEFAULT 0,
                created_at      TEXT DEFAULT (datetime('now'))
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_deltas (
                delta_id          TEXT PRIMARY KEY,
                schedule_id       TEXT NOT NULL,
                scan_id           TEXT NOT NULL,
                prev_scan_id      TEXT,
                computed_at       TEXT,
                new_count         INTEGER DEFAULT 0,
                resolved_count    INTEGER DEFAULT 0,
                regressed_count   INTEGER DEFAULT 0,
                unchanged_count   INTEGER DEFAULT 0,
                new_findings      TEXT,
                resolved_findings TEXT,
                regressed_findings TEXT,
                unchanged_findings TEXT,
                summary_text      TEXT,
                FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_sched_ws   ON schedules(workspace_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sched_next ON schedules(next_run_ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_delta_scan ON scan_deltas(scan_id)")


_init_db()


def _finding_key(f):
    return "|".join([
        str(f.get("mitre_id") or ""),
        str(f.get("title") or f.get("name") or ""),
        str(f.get("host") or f.get("target") or ""),
        str(f.get("port") or ""),
        str(f.get("cls") or ""),
    ]).strip("|").lower()


def compute_delta(new_findings, old_findings):
    """
    Compare two finding lists, return dict with:
      new, resolved, regressed, unchanged, sev_delta, summary_text
    """
    old_map = {_finding_key(f): f for f in old_findings}
    new_map = {_finding_key(f): f for f in new_findings}

    new_only, resolved, regressed, unchanged = [], [], [], []

    for key, f in new_map.items():
        if key not in old_map:
            new_only.append(f)
        else:
            os_ = _SEV_RANK.get((old_map[key].get("severity") or "info").lower(), 0)
            ns_ = _SEV_RANK.get((f.get("severity") or "info").lower(), 0)
            if ns_ > os_:
                f2 = dict(f)
                f2["_prev_severity"] = old_map[key].get("severity", "info")
                regressed.append(f2)
            else:
                unchanged.append(f)

    for key, f in old_map.items():
        if key not in new_map:
            resolved.append(f)

    sev_delta = {
        sev: (sum(1 for f in new_findings if (f.get("severity") or "info").lower() == sev)
            - sum(1 for f in old_findings if (f.get("severity") or "info").lower() == sev))
        for sev in ["critical", "high", "medium", "low", "info"]
    }

    lines = [f"Delta vs previous scan ({len(old_findings)} -> {len(new_findings)} findings):"]
    if new_only:   lines.append(f"  NEW:       {len(new_only)}")
    if resolved:   lines.append(f"  RESOLVED:  {len(resolved)}")
    if regressed:  lines.append(f"  REGRESSED: {len(regressed)} (severity increased)")
    if unchanged:  lines.append(f"  UNCHANGED: {len(unchanged)}")
    for sev in ["critical", "high", "medium", "low"]:
        d = sev_delta.get(sev, 0)
        if d != 0:
            lines.append(f"  {sev.capitalize()} delta: {'+' if d>0 else ''}{d}")

    return {
        "new":          new_only,
        "resolved":     resolved,
        "regressed":    regressed,
        "unchanged":    unchanged,
        "sev_delta":    sev_delta,
        "total_new":    len(new_findings),
        "total_old":    len(old_findings),
        "summary_text": "\n".join(lines),
    }


class ScheduledScanEngine:
    """Manages recurring scan schedules and delta comparison between runs."""

    _on_complete_callbacks = []
    _on_delta_alert_callbacks = []
    _daemon_started = False
    _daemon_lock = threading.Lock()
    _scan_semaphore: threading.Semaphore = threading.Semaphore(2)  # max 2 concurrent scheduled scans

    @classmethod
    def create_schedule(
        cls, workspace_id, targets, phases=None,
        recurrence="daily", interval_hours=24, day_of_week=0,
        hour_of_day=2, minute_of_hour=0, label="",
        auth_username="", auth_password="", auth_header="", auth_cookie="",
        enabled=True,
    ):
        """Create a recurring scan schedule. Returns schedule_id."""
        sid = f"sched_{uuid.uuid4().hex[:12]}"
        next_run = cls._calc_next_run(recurrence, interval_hours, day_of_week, hour_of_day, minute_of_hour)
        with _conn() as c:
            c.execute("""
                INSERT INTO schedules (
                    schedule_id, workspace_id, label, targets, phases,
                    auth_username, auth_password, auth_header, auth_cookie,
                    recurrence, interval_hours, day_of_week, hour_of_day, minute_of_hour,
                    enabled, next_run_ts
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                sid, workspace_id,
                label or f"{recurrence.capitalize()} scan — {', '.join(targets[:2])}",
                json.dumps(targets),
                json.dumps(phases) if phases else None,
                auth_username, auth_password, auth_header, auth_cookie,
                recurrence, interval_hours, day_of_week, hour_of_day, minute_of_hour,
                1 if enabled else 0, next_run,
            ))
        cls._ensure_daemon()
        return sid

    @classmethod
    def update_schedule(cls, schedule_id, **kwargs):
        allowed = {"label","targets","phases","recurrence","interval_hours",
                   "day_of_week","hour_of_day","minute_of_hour","enabled",
                   "auth_username","auth_password","auth_header","auth_cookie"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        for f_ in ("targets","phases"):
            if f_ in updates and isinstance(updates[f_], list):
                updates[f_] = json.dumps(updates[f_])
        sched = cls.get_schedule(schedule_id)
        if sched and any(k in updates for k in ("recurrence","interval_hours","day_of_week","hour_of_day","minute_of_hour")):
            updates["next_run_ts"] = cls._calc_next_run(
                updates.get("recurrence", sched["recurrence"]),
                updates.get("interval_hours", sched["interval_hours"]),
                updates.get("day_of_week",    sched["day_of_week"]),
                updates.get("hour_of_day",    sched["hour_of_day"]),
                updates.get("minute_of_hour", sched["minute_of_hour"]),
            )
        set_clause = ", ".join(f"{k}=?" for k in updates)
        with _conn() as c:
            c.execute(f"UPDATE schedules SET {set_clause} WHERE schedule_id=?",
                      list(updates.values()) + [schedule_id])
        return True

    @classmethod
    def delete_schedule(cls, schedule_id):
        with _conn() as c:
            c.execute("DELETE FROM schedules WHERE schedule_id=?", (schedule_id,))
        return True

    @classmethod
    def get_schedule(cls, schedule_id):
        with _conn() as c:
            row = c.execute("SELECT * FROM schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
        return dict(row) if row else None

    @classmethod
    def list_schedules(cls, workspace_id=None):
        with _conn() as c:
            if workspace_id:
                rows = c.execute("SELECT * FROM schedules WHERE workspace_id=? ORDER BY next_run_ts", (workspace_id,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM schedules ORDER BY next_run_ts").fetchall()
        return [dict(r) for r in rows]

    @classmethod
    def save_delta(cls, schedule_id, scan_id, prev_scan_id, delta):
        did = f"delta_{uuid.uuid4().hex[:12]}"
        with _conn() as c:
            c.execute("""
                INSERT INTO scan_deltas (
                    delta_id, schedule_id, scan_id, prev_scan_id, computed_at,
                    new_count, resolved_count, regressed_count, unchanged_count,
                    new_findings, resolved_findings, regressed_findings, unchanged_findings,
                    summary_text
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                did, schedule_id, scan_id, prev_scan_id, datetime.now().isoformat(),
                len(delta["new"]), len(delta["resolved"]),
                len(delta["regressed"]), len(delta["unchanged"]),
                json.dumps(delta["new"],       default=str),
                json.dumps(delta["resolved"],  default=str),
                json.dumps(delta["regressed"], default=str),
                json.dumps(delta["unchanged"], default=str),
                delta["summary_text"],
            ))
        return did

    @classmethod
    def get_delta(cls, scan_id):
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM scan_deltas WHERE scan_id=? ORDER BY rowid DESC LIMIT 1",
                (scan_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        for field in ("new_findings","resolved_findings","regressed_findings","unchanged_findings"):
            try: d[field] = json.loads(d[field] or "[]")
            except: d[field] = []
        return d

    @classmethod
    def list_deltas(cls, schedule_id, limit=10):
        with _conn() as c:
            rows = c.execute("""
                SELECT delta_id, schedule_id, scan_id, prev_scan_id, computed_at,
                       new_count, resolved_count, regressed_count, unchanged_count, summary_text
                FROM scan_deltas WHERE schedule_id=? ORDER BY rowid DESC LIMIT ?
            """, (schedule_id, limit)).fetchall()
        return [dict(r) for r in rows]

    @classmethod
    def on_scan_complete(cls, fn):
        cls._on_complete_callbacks.append(fn)
        return fn

    @classmethod
    def on_delta_alert(cls, fn):
        cls._on_delta_alert_callbacks.append(fn)
        return fn

    @classmethod
    def _calc_next_run(cls, recurrence, interval_hours, day_of_week, hour_of_day, minute_of_hour):
        now = datetime.now()
        if recurrence == "hourly":
            return (now + timedelta(hours=1)).timestamp()
        elif recurrence == "interval":
            return (now + timedelta(hours=max(0.5, interval_hours))).timestamp()
        elif recurrence == "daily":
            cand = now.replace(hour=hour_of_day, minute=minute_of_hour, second=0, microsecond=0)
            if cand <= now:
                cand += timedelta(days=1)
            return cand.timestamp()
        elif recurrence == "weekly":
            days_ahead = (day_of_week - now.weekday()) % 7 or 7
            cand = (now + timedelta(days=days_ahead)).replace(
                hour=hour_of_day, minute=minute_of_hour, second=0, microsecond=0)
            return cand.timestamp()
        return (now + timedelta(hours=24)).timestamp()

    @classmethod
    def _ensure_daemon(cls):
        with cls._daemon_lock:
            if not cls._daemon_started:
                t = threading.Thread(target=cls._daemon_loop, daemon=True, name="sched-scan-daemon")
                t.start()
                cls._daemon_started = True

    @classmethod
    def _daemon_loop(cls):
        while True:
            try:
                cls._tick()
            except Exception:
                pass
            time.sleep(60)

    @classmethod
    def _tick(cls):
        now_ts = time.time()
        with _conn() as c:
            due = c.execute(
                "SELECT * FROM schedules WHERE enabled=1 AND next_run_ts<=? ORDER BY next_run_ts",
                (now_ts,)
            ).fetchall()
        for row in due:
            cls._run_scheduled_scan(dict(row))

    @classmethod
    def _run_scheduled_scan(cls, sched):
        sid = sched["schedule_id"]

        # ── Concurrency guard: max 2 simultaneous scheduled scans ─────────────
        if not cls._scan_semaphore.acquire(blocking=False):
            # Too many scans running — defer this one by 10 minutes
            with _conn() as c:
                c.execute(
                    "UPDATE schedules SET next_run_ts=next_run_ts+600 WHERE schedule_id=?",
                    (sid,),
                )
            return

        try:
            from cyber_range.services.ext_pentest_engine import start_scan, build_report_state, get_scan_status
            targets = json.loads(sched.get("targets") or "[]")
            phases  = json.loads(sched.get("phases") or "null") if sched.get("phases") else None

            scan_id = start_scan(
                targets=targets, phases=phases,
                auth_username=sched.get("auth_username",""),
                auth_password=sched.get("auth_password",""),
                auth_header=sched.get("auth_header",""),
                auth_cookie=sched.get("auth_cookie",""),
            )

            deadline = time.time() + 90 * 60
            while time.time() < deadline:
                if get_scan_status(scan_id) in ("done","stopped","error","interrupted"):
                    break
                time.sleep(15)

            state = build_report_state(scan_id)
            new_findings = state.get("findings", [])

            old_findings = []
            prev_scan_id = sched.get("last_scan_id")
            if prev_scan_id:
                try:
                    old_findings = build_report_state(prev_scan_id).get("findings", [])
                except Exception:
                    pass

            delta = compute_delta(new_findings, old_findings)
            cls.save_delta(sid, scan_id, prev_scan_id, delta)

            next_run = cls._calc_next_run(
                sched["recurrence"], sched["interval_hours"],
                sched["day_of_week"], sched["hour_of_day"], sched["minute_of_hour"],
            )
            with _conn() as c:
                c.execute("""
                    UPDATE schedules SET last_scan_id=?, last_run_ts=?, next_run_ts=?,
                    run_count=run_count+1 WHERE schedule_id=?
                """, (scan_id, time.time(), next_run, sid))

            for cb in cls._on_complete_callbacks:
                try: cb(sid, scan_id, new_findings, delta)
                except Exception: pass

            if delta["new"] or delta["regressed"]:
                for cb in cls._on_delta_alert_callbacks:
                    try: cb(sid, delta)
                    except Exception: pass

        except Exception:
            with _conn() as c:
                c.execute("UPDATE schedules SET next_run_ts=next_run_ts+3600, run_count=run_count+1 WHERE schedule_id=?", (sid,))

        finally:
            cls._scan_semaphore.release()


ScheduledScanEngine._ensure_daemon()
