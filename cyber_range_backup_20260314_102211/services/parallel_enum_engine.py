"""
parallel_enum_engine.py
=======================
CPU/RAM-aware parallel nmap enumeration engine.

Design principles:
• Each target gets its own nmap subprocess — true parallelism
• Worker count = min(targets, cpu_count()-2, MAX_PARALLEL) — never starves the machine
• RAM guard: refuses to spawn a new process if system RAM > 85%
• Per-target semaphore prevents thundering-herd when targets > workers
• All output is streamed back to Dash via a thread-safe queue
• NmapXmlParser auto-ingests each scan on completion → Neo4j → reports update
"""

import os
import re
import json
import signal
import queue
import threading
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


from cyber_range.services.nmap_xml_parser import NmapXmlParser
from cyber_range.services.nmap_ingest import SCAN_ROOT, SCAN_PROFILES, DEFAULT_PROFILE

# ── Tuning constants ──────────────────────────────────────────────────
MAX_PARALLEL   = 8        # Hard cap on concurrent nmap processes
RAM_THRESHOLD  = 85.0     # % — refuse new process above this
NMAP_MAX_RATE  = 300      # packets/sec per target — keeps NIC sane
NMAP_TIMING    = "T3"     # Conservative timing in parallel mode


class TargetResult:
    """Captures per-target outcome."""
    def __init__(self, target: str):
        self.target   = target
        self.status   = "pending"   # pending | scanning | done | failed
        self.findings = 0
        self.xml_path = ""
        self.error    = ""


class ParallelEnumerationEngine:
    """
    Parallel nmap scanner with auto Neo4j ingest.

    Usage:
        engine = ParallelEnumerationEngine(profile="quick")
        engine.start(targets, on_output=..., on_complete=...)
    """

    def __init__(self, profile: str = DEFAULT_PROFILE):
        os.makedirs(SCAN_ROOT, exist_ok=True)
        self.profile      = profile if profile in SCAN_PROFILES else DEFAULT_PROFILE
        self._cancel_flag = threading.Event()
        self._processes   : dict[str, subprocess.Popen] = {}
        self._proc_lock   = threading.Lock()
        self._results     : dict[str, TargetResult] = {}
        self._parser      = NmapXmlParser()

        # Worker count: leave at least 2 CPU cores for the OS/Dash
        cpu = os.cpu_count() or 2
        self._max_workers = max(1, min(cpu - 2, MAX_PARALLEL))

    # ── Public API ───────────────────────────────────────────────────

    def start(self, targets: list[str], on_output, on_complete) -> threading.Thread:
        """
        Start parallel enumeration (non-blocking).
        on_output(str)  — called from multiple threads; implementation must be thread-safe
        on_complete(cancelled: bool, results: dict[str, TargetResult])  — called once
        """
        if not targets:
            raise ValueError("ParallelEnumerationEngine requires at least one target.")

        self._cancel_flag.clear()
        self._results = {t: TargetResult(t) for t in targets}

        thread = threading.Thread(target=self._run, args=(targets, on_output, on_complete), daemon=True)
        thread.start()
        return thread

    def cancel(self):
        """Signal cancellation and SIGTERM all running nmap processes."""
        self._cancel_flag.set()
        with self._proc_lock:
            for target, proc in list(self._processes.items()):
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        pass
        return True

    def get_results(self) -> dict:
        """Return current results snapshot (safe to call from UI callback)."""
        return {t: {"status": r.status, "findings": r.findings, "error": r.error}
                for t, r in self._results.items()}

    # ── Internal ─────────────────────────────────────────────────────

    def _ram_ok(self) -> bool:
        """Return True if RAM usage is below threshold."""
        if not _PSUTIL:
            return True
        return psutil.virtual_memory().percent < RAM_THRESHOLD

    def _scan_target(self, target: str, on_output) -> TargetResult:
        """Scan a single target (runs inside a ThreadPoolExecutor worker)."""
        result = self._results[target]
        result.status = "scanning"

        if self._cancel_flag.is_set():
            result.status = "cancelled"
            return result

        # RAM guard — wait up to 30 s for memory to free
        waited = 0
        while not self._ram_ok() and waited < 30:
            on_output(f"[ParallelEnum] ⚠ RAM >{RAM_THRESHOLD}% — waiting for free memory (target: {target})\n")
            threading.Event().wait(5)
            waited += 5
        if not self._ram_ok():
            result.status = "failed"
            result.error  = "RAM threshold exceeded — scan skipped"
            on_output(f"[ParallelEnum] ✗ Skipped {target}: {result.error}\n")
            return result

        # Build nmap command
        timestamp  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name  = re.sub(r"[^\w]", "_", target)[:50]
        base       = f"nmap_{safe_name}_{timestamp}"
        xml_path   = os.path.join(SCAN_ROOT, f"{base}.xml")
        meta_path  = os.path.join(SCAN_ROOT, f"{base}.meta.json")
        result.xml_path = xml_path

        prof  = SCAN_PROFILES[self.profile]
        cmd   = ["nmap"] + prof["flags"]
        cmd  += ["--max-rate", str(NMAP_MAX_RATE), f"-{NMAP_TIMING}"]
        cmd  += ["--stats-every", "5s", "-v"]
        if prof["script"]:
            cmd += ["--script", prof["script"]]
        if prof["script_args"]:
            cmd += ["--script-args", prof["script_args"]]
        cmd += ["-oX", xml_path, target]

        on_output(f"\n[ParallelEnum] ▶ {target}  cmd: {' '.join(cmd)}\n")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid,
            )
            with self._proc_lock:
                self._processes[target] = proc

            for line in proc.stdout:
                if self._cancel_flag.is_set():
                    break
                on_output(f"  [{target}] {line}")

            proc.wait()

        except FileNotFoundError:
            result.status = "failed"
            result.error  = "nmap binary not found — install: sudo apt install -y nmap"
            on_output(f"[ParallelEnum] ✗ {target}: {result.error}\n")
            return result
        except Exception as e:
            result.status = "failed"
            result.error  = str(e)
            on_output(f"[ParallelEnum] ✗ {target}: {e}\n")
            return result
        finally:
            with self._proc_lock:
                self._processes.pop(target, None)

        if self._cancel_flag.is_set():
            result.status = "cancelled"
            return result

        # ── Auto-ingest XML → Neo4j ──────────────────────────────────
        on_output(f"[ParallelEnum] ✓ Scan done — {target}  → ingesting to Neo4j...\n")
        count = self._parser.parse_and_ingest(xml_path, on_output)
        result.findings = count
        result.status   = "done"

        # Write metadata sidecar
        meta = {
            "scanner":   "nmap",
            "profile":   self.profile,
            "target":    target,
            "scan_time": timestamp,
            "format":    "nmap-xml",
            "source":    "nmap",
            "ingest":    {"status": "completed", "findings": count},
        }
        try:
            with open(meta_path, "w") as fh:
                json.dump(meta, fh, indent=2)
        except Exception:
            pass

        on_output(f"[ParallelEnum] ✓ {target} → {count} findings in Neo4j\n")
        return result

    def _run(self, targets: list[str], on_output, on_complete):
        """Main orchestration — runs inside a daemon thread."""
        cancelled   = False
        cpu         = os.cpu_count() or 2
        max_workers = max(1, min(len(targets), cpu - 2, MAX_PARALLEL))

        on_output(
            f"\n{'='*60}\n"
            f"[ParallelEnum] Starting parallel enumeration\n"
            f"  Targets  : {len(targets)}\n"
            f"  Workers  : {max_workers}  (CPU={cpu}, cap={MAX_PARALLEL})\n"
            f"  Profile  : {SCAN_PROFILES[self.profile]['label']}\n"
            f"  RAM guard: {RAM_THRESHOLD}%\n"
            f"{'='*60}\n\n"
        )

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                future_to_target = {
                    pool.submit(self._scan_target, t, on_output): t
                    for t in targets
                }
                for future in as_completed(future_to_target):
                    if self._cancel_flag.is_set():
                        cancelled = True
                        break
                    try:
                        future.result()
                    except Exception as e:
                        t = future_to_target[future]
                        on_output(f"[ParallelEnum] ✗ Unhandled error for {t}: {e}\n")

        except Exception as e:
            on_output(f"[ParallelEnum] ✗ Engine error: {e}\n")
            cancelled = True

        # Summary
        done    = sum(1 for r in self._results.values() if r.status == "done")
        failed  = sum(1 for r in self._results.values() if r.status == "failed")
        total_f = sum(r.findings for r in self._results.values())
        on_output(
            f"\n{'='*60}\n"
            f"[ParallelEnum] Enumeration complete\n"
            f"  Done   : {done}/{len(targets)}\n"
            f"  Failed : {failed}\n"
            f"  Total findings ingested: {total_f}\n"
            f"{'='*60}\n"
        )

        on_complete(cancelled or self._cancel_flag.is_set(), self._results)


__all__ = ["ParallelEnumerationEngine", "TargetResult"]
