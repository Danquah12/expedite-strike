"""
HTTPS Alternate Port — Port 8443
"""
from cyber_range.modules.port_443_https import EXPLOITS as _BASE

MODULE_INFO = {
    "port": 8443, "service": "https-alt",
    "name": "HTTPS Alt Port Module",
    "description": "Web apps on alternate HTTPS port — same attacks as 443 plus admin panel discovery",
    "author": "Custom", "mitre": ["T1190", "T1505.003"],
}

EXPLOITS = list(_BASE) + [
    {"name": "Admin Panel Discovery (8443)", "source": "custom", "type": "auxiliary",
     "msf_module": "",
     "description": "Port 8443 commonly hosts admin panels (VMware, Cisco, Fortinet)",
     "exec_command": "gobuster dir -u https://{target}:8443 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -k -q",
     "risk": "High — admin panels on alternate ports often have weaker security controls"},
]

def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)

def exploit(target_ip, port=8443, exploit_info=None):
    ei = exploit_info or EXPLOITS[0]
    return {"command": ei["exec_command"].format(target=target_ip),
            "module": ei.get("msf_module", ""), "status": "ready",
            "target": f"{target_ip}:{port}"}
