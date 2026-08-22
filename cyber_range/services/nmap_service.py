"""
nmap_service.py
───────────────
Python analogue of the .NET NmapService.

  NmapService.run(target, log_queue) → NmapResult

Wraps nmap -sV -oX, parses XML output, returns discovered open ports.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import List

_lock = Lock()

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def _log(msg: str, q: deque):
    with _lock:
        q.append(f"[{_ts()}] {msg}")


@dataclass
class PortInfo:
    port:     int
    protocol: str
    state:    str
    service:  str
    version:  str


@dataclass
class NmapResult:
    success:    bool = False
    target:     str  = ""
    open_ports: List[PortInfo] = field(default_factory=list)
    raw_output: str  = ""
    error:      str  = ""

    @property
    def open_count(self) -> int:
        return len([p for p in self.open_ports if p.state == "open"])


class NmapService:
    """
    Python equivalent of:
        public string Run(string target) {
            var psi = new ProcessStartInfo { FileName="nmap", Arguments=$"-sV -oX nmap.xml {target}" };
            ...
        }
    """

    def __init__(self, log_queue: deque | None = None):
        self._q: deque = log_queue if log_queue is not None else deque(maxlen=600)

    def run(self, target: str, ports: str = "22,80,135,139,389,443,445,3389,5985") -> NmapResult:
        self._log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        self._log("🗺️  NmapService  →  starting")
        self._log(f"    Target : {target}")

        if not shutil.which("nmap"):
            self._log("⚠️  nmap not found on PATH — simulation mode")
            return self._simulate(target)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_path = tf.name

        cmd = ["nmap", "-Pn", "-sV", "--open", "-p", ports, "-oX", xml_path, "--version-intensity", "5", target]
        self._log(f"▶  {' '.join(cmd)}")

        raw_lines: list[str] = []
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    self._log(stripped)
                    raw_lines.append(stripped)
            proc.wait()
        except Exception as e:
            self._log(f"❌  nmap error: {e}")
            return NmapResult(success=False, target=target, error=str(e))

        # Parse XML
        ports_found = self._parse_xml(xml_path)
        try:
            os.unlink(xml_path)
        except Exception:
            pass

        self._log(f"✅  Nmap complete — {len(ports_found)} open port(s)")
        for p in ports_found:
            self._log(f"    🔓 {p.port}/{p.protocol}  {p.service}  {p.version}")

        return NmapResult(
            success=True,
            target=target,
            open_ports=ports_found,
            raw_output="\n".join(raw_lines),
        )

    # ── Simulation ────────────────────────────────────────────────────────────
    def _simulate(self, target: str) -> NmapResult:
        steps = [
            (f"🗺️  Starting port scan against {target} …",           0.7),
            ("   Scanning common AD ports: 53,88,135,139,389,445,3389…", 0.6),
            ("   PORT    STATE  SERVICE      VERSION",                0.4),
            ("   53/tcp  open   domain       Windows DNS",            0.3),
            ("   88/tcp  open   kerberos-sec Microsoft Kerberos",     0.3),
            ("   135/tcp open   msrpc        Microsoft RPC",          0.3),
            ("   139/tcp open   netbios-ssn  Microsoft SMB",          0.3),
            ("   389/tcp open   ldap         Active Directory LDAP",  0.3),
            ("   445/tcp open   microsoft-ds Windows SMB",            0.3),
            ("   3268/tcp open  ldap         Global Catalog",         0.3),
            ("   3389/tcp open  ms-wbt-server RDP",                   0.3),
            ("   5985/tcp open  http         WinRM HTTP",             0.3),
            ("✅  Nmap scan complete — 9 open ports discovered",      0.5),
        ]
        for msg, delay in steps:
            self._log(msg)
            time.sleep(delay)

        sim_ports = [
            PortInfo(53,   "tcp", "open", "domain",        "Windows DNS"),
            PortInfo(88,   "tcp", "open", "kerberos-sec",  "Microsoft Kerberos"),
            PortInfo(135,  "tcp", "open", "msrpc",         "Microsoft RPC"),
            PortInfo(139,  "tcp", "open", "netbios-ssn",   "Microsoft SMB"),
            PortInfo(389,  "tcp", "open", "ldap",          "Active Directory LDAP"),
            PortInfo(445,  "tcp", "open", "microsoft-ds",  "Windows SMB"),
            PortInfo(3268, "tcp", "open", "ldap",          "Global Catalog"),
            PortInfo(3389, "tcp", "open", "ms-wbt-server", "RDP"),
            PortInfo(5985, "tcp", "open", "http",          "WinRM HTTP"),
        ]
        return NmapResult(success=True, target=target, open_ports=sim_ports,
                          raw_output="(simulation)")

    # ── XML parser ────────────────────────────────────────────────────────────
    @staticmethod
    def _parse_xml(path: str) -> list[PortInfo]:
        result = []
        try:
            tree = ET.parse(path)
            for host in tree.findall(".//host"):
                for port_el in host.findall(".//port"):
                    state_el   = port_el.find("state")
                    service_el = port_el.find("service")
                    state = state_el.get("state", "") if state_el is not None else ""
                    if state != "open":
                        continue
                    result.append(PortInfo(
                        port     = int(port_el.get("portid", 0)),
                        protocol = port_el.get("protocol", "tcp"),
                        state    = state,
                        service  = (service_el.get("name", "") if service_el is not None else ""),
                        version  = (service_el.get("version", "") if service_el is not None else ""),
                    ))
        except Exception:
            pass
        return result

    def _log(self, msg: str):
        _log(msg, self._q)
