"""
Scan Scheduler Engine
=====================
Schedule one-time or recurring security scans.
Uses threading-based scheduler for reliability.
"""
import os
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Callable, Optional

logger = logging.getLogger(__name__)

SCHEDULED_SCANS = {}
_SCHEDULER_THREAD = None
_STOP_EVENT = threading.Event()
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scan_cache")
_SCHEDULES_FILE = os.path.join(_DATA_DIR, "schedules.json")


def load_schedules():
    """Load scheduled scans from disk."""
    global SCHEDULED_SCANS
    try:
        if os.path.exists(_SCHEDULES_FILE):
            with open(_SCHEDULES_FILE, 'r') as f:
                SCHEDULED_SCANS = json.load(f)
            logger.info(f"[Scheduler] Loaded {len(SCHEDULED_SCANS)} scheduled scans.")
        else:
            SCHEDULED_SCANS = {}
    except Exception as e:
        logger.error(f"[Scheduler] Error loading schedules: {e}")
        SCHEDULED_SCANS = {}


def save_schedules():
    """Save scheduled scans to disk."""
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(_SCHEDULES_FILE, 'w') as f:
            json.dump(SCHEDULED_SCANS, f, indent=4, default=str)
    except Exception as e:
        logger.error(f"[Scheduler] Error saving schedules: {e}")


def schedule_scan(name: str, targets: list, schedule_type: str,
                  interval_hours: int = None, cron_expr: str = None,
                  intensity: str = 'standard', log_fn: Callable = None) -> str:
    """Creates a scheduled scan. Returns scan ID."""
    scan_id = str(uuid.uuid4())[:12]
    now = datetime.now()

    next_run = None
    if schedule_type == 'recurring' and interval_hours:
        next_run = (now + timedelta(hours=interval_hours)).isoformat()
    elif schedule_type == 'one_time':
        next_run = (now + timedelta(minutes=1)).isoformat()

    SCHEDULED_SCANS[scan_id] = {
        'id': scan_id,
        'name': name,
        'targets': targets,
        'schedule_type': schedule_type,
        'interval_hours': interval_hours,
        'cron_expression': cron_expr,
        'intensity': intensity,
        'next_run': next_run,
        'last_run': None,
        'status': 'active',
        'run_count': 0,
        'results_history': [],
        'created_at': now.isoformat(),
        'created_by': 'admin',
    }
    save_schedules()
    if log_fn:
        log_fn(f"  [Scheduler] Created scan '{name}' → {scan_id} (next: {next_run})")
    logger.info(f"[Scheduler] Scan {scan_id} created: {name}")
    return scan_id


def cancel_scan(scan_id: str) -> bool:
    """Cancels a scheduled scan."""
    if scan_id in SCHEDULED_SCANS:
        del SCHEDULED_SCANS[scan_id]
        save_schedules()
        logger.info(f"[Scheduler] Scan {scan_id} cancelled.")
        return True
    return False


def pause_scan(scan_id: str) -> bool:
    """Pauses a scheduled scan."""
    if scan_id in SCHEDULED_SCANS:
        SCHEDULED_SCANS[scan_id]['status'] = 'paused'
        save_schedules()
        return True
    return False


def resume_scan(scan_id: str) -> bool:
    """Resumes a paused scan."""
    if scan_id in SCHEDULED_SCANS:
        SCHEDULED_SCANS[scan_id]['status'] = 'active'
        save_schedules()
        return True
    return False


def list_scheduled_scans() -> list:
    """Returns all scheduled scans."""
    return list(SCHEDULED_SCANS.values())


def get_scan_status(scan_id: str) -> dict:
    """Returns current status of a scan."""
    return SCHEDULED_SCANS.get(scan_id, {})


def _execute_scheduled_scan(scan_id: str):
    """Internal: runs the scan by calling start_autopentest."""
    scan = SCHEDULED_SCANS.get(scan_id)
    if not scan:
        return

    logger.info(f"[Scheduler] Executing: {scan['name']} ({scan_id})")
    try:
        from cyber_range.services.auto_pentest_orchestrator import start_autopentest
        run_id = f"sched-{uuid.uuid4()}"
        start_autopentest(scan['targets'], scan['intensity'])

        now = datetime.now()
        scan['last_run'] = now.isoformat()
        scan['run_count'] += 1
        scan['results_history'].append(run_id)

        if scan['schedule_type'] == 'recurring' and scan['interval_hours']:
            scan['next_run'] = (now + timedelta(hours=scan['interval_hours'])).isoformat()
        else:
            scan['status'] = 'completed'

        save_schedules()
    except Exception as e:
        logger.error(f"[Scheduler] Failed to execute {scan_id}: {e}")


def _scheduler_loop():
    """Background thread that checks every 60 seconds for due scans."""
    logger.info("[Scheduler] Background thread started.")
    while not _STOP_EVENT.is_set():
        now = datetime.now()
        for scan_id, scan in list(SCHEDULED_SCANS.items()):
            if scan['status'] != 'active' or not scan.get('next_run'):
                continue
            try:
                next_run_time = datetime.fromisoformat(scan['next_run'])
                if now >= next_run_time:
                    threading.Thread(
                        target=_execute_scheduled_scan,
                        args=(scan_id,), daemon=True
                    ).start()
            except (ValueError, TypeError):
                continue

        _STOP_EVENT.wait(60)
    logger.info("[Scheduler] Background thread stopped.")


def start_scheduler():
    """Start the background scheduler thread."""
    global _SCHEDULER_THREAD
    load_schedules()
    if _SCHEDULER_THREAD is None or not _SCHEDULER_THREAD.is_alive():
        _STOP_EVENT.clear()
        _SCHEDULER_THREAD = threading.Thread(target=_scheduler_loop, daemon=True)
        _SCHEDULER_THREAD.start()
        logger.info("[Scheduler] Started.")


def stop_scheduler():
    """Stop the background scheduler thread."""
    _STOP_EVENT.set()
    if _SCHEDULER_THREAD:
        _SCHEDULER_THREAD.join(timeout=5)
    logger.info("[Scheduler] Stopped.")
