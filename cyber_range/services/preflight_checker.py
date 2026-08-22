"""
Pre-Flight Exploit Checker
===========================
Runs 6 gate checks BEFORE ExploitRunner fires any exploit.
If ANY gate fails the exploit is blocked and the reason is logged
to the live activity feed.

Gates (in order):
  1. Host/IP is not null and in Neo4j
  2. Port is confirmed open (TCP connect, 3 s timeout)
  3. Finding severity meets minimum threshold (Critical/High/Medium)
  4. Exploit module/command is not empty
  5. MSF module .rb file exists on disk (if msf_path given)
  6. Not already compromised (unless force=True)
  7. Per-host concurrency limit (max 3 concurrent exploits)

Usage:
    from cyber_range.services.preflight_checker import PreflightChecker
    ok, reason = PreflightChecker().check(exploit_entry)
    if not ok:
        # skip / log reason
"""

import os
import socket
import threading
import datetime
import sys

_MSF_MODULES_DIR = "/usr/share/metasploit-framework/modules"

# Minimum severity to attempt exploitation
_MIN_SEVERITY = {"critical", "high", "medium"}

# Max concurrent exploits running against the same host
_MAX_CONCURRENT_PER_HOST = 3

# Active exploit counter: {ip → count}
_active_per_host: dict = {}
_active_lock = threading.Lock()


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def _log(msg: str):
    now = _ts()
    mod = sys.modules.get("cyber_range.moduls.ui_pentest")
    hist = getattr(mod, "_enum_history", []) if mod else []
    hist.append(f"[{now}] [PREFLIGHT] {msg}\n")
    hist[:] = hist[-300:]


def _neo4j():
    from cyber_range.services.neo4j_engine import Neo4jEngine
    return Neo4jEngine()


# ── Context manager for per-host concurrency tracking ────────────────────────
class _HostSlot:
    """Increment on enter, decrement on exit (use as context manager)."""
    def __init__(self, ip: str):
        self.ip = ip

    def __enter__(self):
        with _active_lock:
            _active_per_host[self.ip] = _active_per_host.get(self.ip, 0) + 1
        return self

    def __exit__(self, *_):
        with _active_lock:
            count = _active_per_host.get(self.ip, 1) - 1
            _active_per_host[self.ip] = max(0, count)


def acquire_slot(ip: str) -> "_HostSlot":
    """Return a context manager that tracks one exploit slot for ip."""
    return _HostSlot(ip)


# ══════════════════════════════════════════════════════════════════════════════
class PreflightChecker:
    """
    Run all preflight gates. Returns (True, "PASS") or (False, "<reason>").
    """

    GATE_ICONS = {
        "PASS":      "✅",
        "WARN":      "⚠️",
        "FAIL":      "⛔",
    }

    def check(
        self,
        exploit_entry: dict,
        min_severity: str = "medium",
        force_recheck: bool = False,
    ) -> tuple:
        """
        Run all 7 gates sequentially.
        Returns (passed: bool, reason: str).
        """
        target_raw = exploit_entry.get("target", "")
        ip, port   = (target_raw.split(":", 1) + ["0"])[:2]
        port_i     = int(port) if port.isdigit() else 0

        severity   = (exploit_entry.get("severity") or "medium").lower()
        msf_path   = exploit_entry.get("msf_path", "")
        exec_cmd   = exploit_entry.get("exec_cmd", "")
        expl_id    = exploit_entry.get("id", "?")

        _log(f"STARTING preflight for {ip}:{port_i} [{exploit_entry.get('msf_title','?')[:40]}]")

        # Gate 1 — valid IP
        passed, reason = self._gate_valid_ip(ip)
        if not passed:
            return self._fail(expl_id, ip, port_i, reason)

        # Gate 2 — TCP reachability
        passed, reason = self._gate_reachable(ip, port_i)
        if not passed:
            return self._fail(expl_id, ip, port_i, reason)

        # Gate 3 — severity threshold
        passed, reason = self._gate_severity(severity, min_severity)
        if not passed:
            return self._fail(expl_id, ip, port_i, reason)

        # Gate 4 — module/command not empty
        passed, reason = self._gate_module_defined(msf_path, exec_cmd)
        if not passed:
            return self._fail(expl_id, ip, port_i, reason)

        # Gate 5 — MSF module exists on disk (if applicable)
        passed, reason = self._gate_msf_exists(msf_path)
        if not passed:
            # Only WARN — don't block (module may be custom / tool-based)
            _log(f"  ⚠️  Gate 5 WARN: {reason} — continuing with exec_cmd fallback")

        # Gate 6 — not already compromised
        if not force_recheck:
            passed, reason = self._gate_not_compromised(ip)
            if not passed:
                return self._fail(expl_id, ip, port_i, reason)

        # Gate 7 — per-host concurrency limit
        passed, reason = self._gate_concurrency(ip)
        if not passed:
            return self._fail(expl_id, ip, port_i, reason)

        _log(f"  ✅ ALL GATES PASSED → launching exploit on {ip}:{port_i}")
        return True, "PASS"

    # ── Individual gate implementations ───────────────────────────────────────

    def _gate_valid_ip(self, ip: str) -> tuple:
        """Gate 1: IP must be non-null and parseable."""
        if not ip or ip in ("?", "None", "null", ""):
            return False, "Gate 1 FAIL: no valid IP address"
        # Basic format check
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    _log(f"  ✅ Gate 1 PASS: IP {ip} valid")
                    return True, "ok"
            except ValueError:
                pass
        # Allow hostnames too
        if len(ip) > 0 and len(ip) < 255:
            _log(f"  ✅ Gate 1 PASS: hostname {ip}")
            return True, "ok"
        return False, f"Gate 1 FAIL: malformed IP/host '{ip}'"

    def _gate_reachable(self, ip: str, port: int) -> tuple:
        """Gate 2: TCP connect to ip:port within 3 seconds."""
        if port == 0:
            _log(f"  ⚠️  Gate 2 SKIP: port=0, skipping reachability check")
            return True, "ok"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                _log(f"  ✅ Gate 2 PASS: {ip}:{port} is reachable")
                return True, "ok"
            else:
                return False, f"Gate 2 FAIL: {ip}:{port} refused/unreachable (code {result})"
        except socket.timeout:
            return False, f"Gate 2 FAIL: {ip}:{port} timed out"
        except OSError as e:
            return False, f"Gate 2 FAIL: {ip}:{port} error — {e}"

    def _gate_severity(self, severity: str, min_sev: str) -> tuple:
        """Gate 3: Severity must meet minimum threshold."""
        _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev_rank = _RANK.get(severity.lower(), 0)
        min_rank = _RANK.get(min_sev.lower(), 2)
        if sev_rank >= min_rank:
            _log(f"  ✅ Gate 3 PASS: severity={severity} meets threshold={min_sev}")
            return True, "ok"
        return False, f"Gate 3 FAIL: severity '{severity}' below threshold '{min_sev}'"

    def _gate_module_defined(self, msf_path: str, exec_cmd: str) -> tuple:
        """Gate 4: At least msf_path or exec_cmd must be defined."""
        if msf_path or exec_cmd:
            _log(f"  ✅ Gate 4 PASS: module/command defined")
            return True, "ok"
        return False, "Gate 4 FAIL: no exploit module or command defined"

    def _gate_msf_exists(self, msf_path: str) -> tuple:
        """Gate 5: If msf_path looks like an MSF module, verify .rb file exists."""
        if not msf_path or "/" not in msf_path:
            return True, "ok"   # not an MSF-style path, skip

        # Convert "exploit/windows/smb/ms17_010_eternalblue" → file path
        rb_path = os.path.join(_MSF_MODULES_DIR, msf_path + ".rb")
        if os.path.isfile(rb_path):
            _log(f"  ✅ Gate 5 PASS: MSF module verified on disk")
            return True, "ok"

        # Also check without the prefix segment (some paths differ)
        parts = msf_path.split("/", 1)
        if len(parts) == 2:
            alt = os.path.join(_MSF_MODULES_DIR, parts[0] + "s", parts[1] + ".rb")
            if os.path.isfile(alt):
                _log(f"  ✅ Gate 5 PASS: MSF module found at alt path")
                return True, "ok"

        return False, f"Gate 5 WARN: {msf_path}.rb not found on disk (will use exec_cmd)"

    def _gate_not_compromised(self, ip: str) -> tuple:
        """Gate 6: Skip if host is already marked compromised in Neo4j."""
        try:
            ng = _neo4j()
            with ng.driver.session() as s:
                r = s.run(
                    "MATCH (h:Host {ip: $ip}) RETURN h.compromised AS c",
                    ip=ip
                ).single()
                ng.driver.close()
            if r and r["c"] is True:
                return False, f"Gate 6 FAIL: {ip} already marked compromised — skipping (use force_recheck=True to override)"
            _log(f"  ✅ Gate 6 PASS: {ip} not yet compromised")
            return True, "ok"
        except Exception as e:
            # Neo4j error → don't block
            _log(f"  ⚠️  Gate 6 WARN: Neo4j check failed ({e}), proceeding")
            return True, "ok"

    def _gate_concurrency(self, ip: str) -> tuple:
        """Gate 7: Max _MAX_CONCURRENT_PER_HOST exploits per host."""
        with _active_lock:
            count = _active_per_host.get(ip, 0)
        if count >= _MAX_CONCURRENT_PER_HOST:
            return False, (
                f"Gate 7 FAIL: {ip} already has {count} active exploits "
                f"(limit={_MAX_CONCURRENT_PER_HOST})"
            )
        _log(f"  ✅ Gate 7 PASS: {ip} concurrency {count}/{_MAX_CONCURRENT_PER_HOST}")
        return True, "ok"

    # ── Helpers ────────────────────────────────────────────────────────────────
    @staticmethod
    def _fail(expl_id: str, ip: str, port: int, reason: str) -> tuple:
        _log(f"  ⛔ BLOCKED [{ip}:{port}] → {reason}")
        return False, reason
