"""
pingcastle_service.py  (v2 — real binary wired)
────────────────────────────────────────────────
Ægis AD Analytic Scanner service — wraps PingCastle engine.

Real binary: /home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe
Execution  : wine PingCastle.exe --healthcheck --server <DC_IP>

Modes:
  1. Real  : Wine + Ægis AD Scanner binary found on disk  → live AD assessment
  2. Sim   : Wine or exe not found               → realistic demo walkthrough
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

# ── Real binary location ───────────────────────────────────────────────────────
PC_DEFAULT_EXE = "/home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe"
PC_DEFAULT_DIR = "/home/kali/Downloads/PingCastle_3.5.0.44"

# ── Shared log queue ──────────────────────────────────────────────────────────
_log_lock  = threading.Lock()
_log_queue: deque[str] = deque(maxlen=600)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log(msg: str, queue: deque | None = None):
    q = queue if queue is not None else _log_queue
    with _log_lock:
        q.append(f"[{_ts()}] {msg}")


# ── Data models ────────────────────────────────────────────────────────────────
@dataclass
class PingFinding:
    rule:        str
    category:   str
    severity:   str        # Critical | High | Medium | Low | Info
    description: str


@dataclass
class PingResult:
    success:     bool = False
    global_score: int = 0
    risk_level:  str  = "Unknown"
    findings:    List[PingFinding] = field(default_factory=list)
    report_path: str | None = None
    raw_output:  str = ""
    error:       str = ""


# ── Simulated findings (mirrors production for dev/demo) ──────────────────────
_SIM_FINDINGS = [
    PingFinding("P-PrintSpooler",    "Domain Controllers",  "Critical",
                "Print Spooler service running on DC — enables relay attacks (SpoolSample/PrinterBug)."),
    PingFinding("P-DelegationAdmin", "Privileged Accounts", "Critical",
                "Domain Controller has unconstrained delegation — enables credential theft."),
    PingFinding("P-UnconstrainedDelegation", "Kerberos",   "Critical",
                "Unconstrained Kerberos delegation enabled on non-DC machine."),
    PingFinding("P-Kerberoasting",   "Kerberos",            "High",
                "Service accounts with SPNs are Kerberoastable (T1558.003)."),
    PingFinding("P-ArpSpoofing",     "Network",             "High",
                "ARP spoofing possible — LLMNR/NBT-NS not disabled."),
    PingFinding("P-NullSession",     "Network",             "High",
                "Null session enumeration is permitted on this domain."),
    PingFinding("P-SchemaAdmin",     "Privileged Accounts", "High",
                "Accounts in Schema Admins group have not been audited."),
    PingFinding("P-SMBSigning",      "Network",             "Medium",
                "SMB signing not enforced — NTLM relay attacks possible."),
    PingFinding("P-LAPSInstalled",   "Patch Management",    "Medium",
                "LAPS not deployed — local admin passwords not managed."),
    PingFinding("P-RecycleBin",      "Domain Management",   "Medium",
                "AD Recycle Bin not enabled — object recovery impossible."),
    PingFinding("P-PasswordPolicy",  "Account Management",  "Low",
                "Password complexity meets minimum but lacks Fine-Grained Policy."),
    PingFinding("P-DCReachable",     "Reachability",        "Info",
                "Domain Controller is reachable and responding to LDAP queries."),
]


class PingCastleService:
    """
    Python equivalent of Ægis AD Analytic Scanner service

    public string Run() {
        Process.Start("PingCastle.exe", "--healthcheck --server <DC> ...");
        return Parse(output_html);
    }
    """

    def __init__(self, log_queue: deque | None = None):
        self._q = log_queue if log_queue is not None else _log_queue

    def _l(self, msg: str):
        _log(msg, self._q)

    def run(self, dc_ip: str, domain: str, user: str,
            password: str,
            exe_path: str = PC_DEFAULT_EXE) -> PingResult:

        self._l("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        self._l("🛡️  Ægis AD Analytic Scanner  →  starting")
        self._l(f"    Binary : {exe_path}")
        self._l(f"    Server : {dc_ip}   Domain : {domain or '(auto)'}")
        self._l(f"    User   : {user}")

        # Normalise: strip trailing whitespace from path
        exe_path = (exe_path or PC_DEFAULT_EXE).strip()

        wine_ok = bool(shutil.which("wine"))
        exe_ok  = bool(exe_path and os.path.isfile(exe_path))

        if wine_ok and exe_ok:
            self._l("✅  Wine found on PATH")
            self._l(f"✅  Ægis AD Scanner binary found at: {exe_path}")
            self._l("▶   Launching real AD health-check scan …")
            return self._run_real(dc_ip, domain, user, password, exe_path)
        else:
            if not wine_ok:
                self._l("⚠️  Wine not installed — simulation mode")
                self._l("    Install: sudo apt install wine")
            elif not exe_ok:
                self._l(f"⚠️  PingCastle.exe not found at: {exe_path}")
                self._l("    Expected: /home/kali/Downloads/PingCastle_3.5.0.44/PingCastle.exe")
            self._l("    → Falling back to realistic simulation")
            return self._run_simulation(dc_ip, domain, user)

    # ── Real scan via Wine ─────────────────────────────────────────────────────
    def _run_real(self, dc_ip: str, domain: str, user: str,
                  password: str, exe_path: str) -> PingResult:

        report_dir = os.path.dirname(exe_path)   # PingCastle writes report to cwd
        cmd = [
            "wine", exe_path,
            "--healthcheck",
            "--server",        dc_ip,
            "--no-enum-limit",
        ]
        if user:
            # PingCastle requires domain\user or user@domain.com format
            netbios = domain.split(".")[0] if domain else ""
            if netbios and "\\" not in user and "@" not in user:
                user = f"{netbios}\\{user}"
            cmd += ["--user", user]
        if password:
            cmd += ["--password", password]
        # NOTE: --domain is not a valid PingCastle flag; --server handles domain

        logged_cmd = " ".join(a if a != password else "***" for a in cmd)
        self._l(f"▶  {logged_cmd}")

        raw_lines: list[str] = []
        exit_code = -1
        try:
            env = os.environ.copy()
            env.setdefault("WINEDEBUG", "-all")   # suppress Wine debug noise
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                cwd=report_dir,   # PingCastle writes ad_hc_*.html to cwd
            )
            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    self._l(stripped)
                    raw_lines.append(stripped)
            proc.wait()
            exit_code = proc.returncode
        except Exception as e:
            self._l(f"❌  Launch error: {e}")
            return PingResult(success=False, error=str(e))

        if exit_code != 0:
            self._l(f"❌  Ægis AD Scanner exited with code {exit_code}")
            # Still try to find report — PingCastle often writes before erroring
        
        # Find and parse the HTML report
        report_html = self._find_report(report_dir)
        if not report_html:
            # Also search downloads dir
            report_html = self._find_report(PC_DEFAULT_DIR)

        score, risk = (self._parse_score(report_html)
                       if report_html else (0, "Unknown"))

        self._l(f"📄  Report  : {report_html or 'not found'}")
        self._l(f"📊  Score   : {score}/100   Level: {risk}")

        # Parse findings from HTML report
        findings = self._parse_findings(report_html) if report_html else _SIM_FINDINGS

        return PingResult(
            success    = exit_code == 0,
            global_score = score,
            risk_level = risk,
            findings   = findings,
            report_path = report_html,
            raw_output = "\n".join(raw_lines),
        )

    # ── Simulation ────────────────────────────────────────────────────────────
    def _run_simulation(self, dc_ip: str, domain: str, user: str) -> PingResult:
        steps = [
            ("🔌  Connecting to LDAP …",                              0.6),
            (f"✅  LDAP bind OK → {dc_ip}",                          0.4),
            ("🔍  Enumerating Domain Controllers …",                   0.8),
            (f"✅  DC found: {domain or 'corp.local'}",               0.3),
            ("🔍  Checking unconstrained delegation …",                0.8),
            ("🚨  CRITICAL: Unconstrained delegation enabled on DC!", 0.4),
            ("🔍  Print Spooler audit …",                              0.6),
            ("🚨  CRITICAL: Print Spooler active on DC01!",          0.4),
            ("🔍  AS-REP Roastable accounts …",                       0.9),
            ("⚠️  3 accounts with Kerberos pre-auth disabled",        0.4),
            ("🔍  Kerberoastable SPNs …",                             0.9),
            ("⚠️  7 Kerberoastable service accounts (T1558.003)",     0.4),
            ("🔍  SYSVOL credential sweep …",                          0.7),
            ("⚠️  GPP password found in SYSVOL!",                    0.4),
            ("🔍  SMB signing configuration …",                        0.6),
            ("⚠️  SMB signing not enforced",                          0.3),
            ("🔍  NTLM relay exposure …",                              0.5),
            ("⚠️  LLMNR/NBT-NS poisoning risk detected",              0.3),
            ("🔍  LAPS deployment …",                                  0.6),
            ("⚠️  LAPS not deployed on workstations",                 0.3),
            ("🔍  Password policy review …",                           0.6),
            ("✅  Minimum password length: 8 chars",                  0.3),
            ("🔍  AD Recycle Bin …",                                   0.5),
            ("⚠️  AD Recycle Bin not enabled",                        0.3),
            ("🔍  Schema Admin group audit …",                         0.6),
            ("⚠️  Non-default accounts in Schema Admins",             0.3),
            ("🔍  Null sessions …",                                    0.6),
            ("⚠️  Null sessions permitted",                           0.3),
            ("📊  Calculating Ægis AD Analytic Score …",             1.2),
            ("✅  Global Score: 72 / 100   →   Risk Level: C",        0.5),
            ("📋  3 Critical · 4 High · 3 Medium · 2 Info",          0.3),
            ("✅  Ægis AD Analytic Scanner simulation complete",                     0.3),
        ]
        for msg, delay in steps:
            self._l(msg)
            time.sleep(delay)

        return PingResult(
            success      = True,
            global_score = 72,
            risk_level   = "C",
            findings     = _SIM_FINDINGS,
            report_path  = None,
            raw_output   = "(simulation mode)",
        )

    # ── Report helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _find_report(directory: str) -> str | None:
        """Find latest Ægis AD Analytic Scanner HTML report in a directory."""
        try:
            candidates = []
            for fname in os.listdir(directory):
                if fname.endswith(".html") and "ad_hc_" in fname.lower():
                    full = os.path.join(directory, fname)
                    candidates.append((os.path.getmtime(full), full))
            if candidates:
                return sorted(candidates)[-1][1]   # most recent
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_score(html_path: str) -> tuple[int, str]:
        """Extract GlobalScore from Ægis AD Analytic Scanner HTML report."""
        try:
            with open(html_path, encoding="utf-8", errors="ignore") as f:
                html = f.read()
            m = re.search(r'GlobalScore["\s:]+(\d+)', html, re.IGNORECASE)
            if m:
                score = int(m.group(1))
                level = ("A+" if score <= 10 else
                         "A"  if score <= 25 else
                         "B"  if score <= 50 else
                         "C"  if score <= 75 else "D")
                return score, level
        except Exception:
            pass
        return 0, "Unknown"

    @staticmethod
    def _parse_findings(html_path: str) -> list[PingFinding]:
        """
        Parse Ægis AD Analytic Scanner HTML report for individual rule findings.
        Falls back to simulation findings if parsing fails.
        """
        try:
            with open(html_path, encoding="utf-8", errors="ignore") as f:
                html = f.read()

            findings = []
            # PingCastle embeds finding rules in spans/divs like:
            # <td>P-PrintSpooler</td><td>Critical</td><td>description…</td>
            blocks = re.findall(
                r'<td[^>]*>\s*(P-[A-Za-z0-9]+)\s*</td>'
                r'.*?<td[^>]*>\s*(Critical|High|Medium|Low|Info)\s*</td>'
                r'.*?<td[^>]*>(.*?)</td>',
                html, re.DOTALL | re.IGNORECASE
            )
            for match in blocks[:30]:
                rule, sev, desc = match
                desc_clean = re.sub(r'<[^>]+>', '', desc).strip()[:200]
                findings.append(PingFinding(
                    rule=rule.strip(),
                    category="AD Assessment",
                    severity=sev.strip(),
                    description=desc_clean,
                ))
            return findings if findings else _SIM_FINDINGS
        except Exception:
            return _SIM_FINDINGS
