"""Add ALL VMware lab VMs to the findings database."""
import sqlite3
from datetime import datetime

db_path = r'D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app\data\vuln_intel.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# ALL VMware Workstation VMs from user's library
all_vms = [
    # (module, title, severity, host, description, mitre)
    ("Network Recon", "Windows Server 2012 — Domain Controller", "Critical", "192.168.195.138",
     "Windows Server 2012 R2 on VMnet8 NAT. SMB (445), RPC (135), NetBIOS (139) exposed. Legacy OS — end of support. High-value target for Active Directory attacks.", "T1046"),
    
    ("Network Recon", "Windows 2019 Server — Enterprise Services", "High", "Windows-2019-Server",
     "Windows Server 2019 detected in VMware lab. Potential Active Directory, DNS, DHCP services. Target for Kerberoasting, pass-the-hash, and lateral movement.", "T1046"),
    
    ("Network Recon", "Windows 10 x64 — Workstation", "Medium", "Windows-10-x64",
     "Windows 10 workstation in VMware lab. Target for privilege escalation, credential harvesting, and endpoint security testing.", "T1046"),
    
    ("Network Recon", "Metasploitable2-Linux — Intentionally Vulnerable", "Critical", "Metasploitable2",
     "Metasploitable 2 Linux VM detected. Contains multiple intentionally vulnerable services: vsftpd 2.3.4 (backdoor), Samba, distcc, Tomcat, PostgreSQL, MySQL, IRC, VNC. High-priority scan target.", "T1190"),
    
    ("Network Recon", "Kali Linux 2025.3 — Attack Platform", "Low", "Kali-2025.3",
     "Kali Linux 2025.3 attack platform in VMware lab. Contains Metasploit, Nmap, Burp Suite, and full offensive security toolkit. Used as attack source, not a scan target.", "T1588"),
    
    ("Network Recon", "pfSense/FreeBSD — Network Firewall", "Medium", "192.168.195.128",
     "pfSense firewall/router (FreeBSD-based) detected on VMnet8. Network perimeter device. Target for firewall rule analysis, VPN misconfiguration, and web UI vulnerabilities.", "T1046"),
    
    ("Web App Scan", "OWASP Broken Web Apps VM v1.2 — Web Vulns", "Critical", "OWASP-BWA",
     "OWASP BWA VM contains 30+ intentionally vulnerable web apps: DVWA, WebGoat, Mutillidae, phpMyAdmin, WordPress, Joomla. Critical target for SQL injection, XSS, CSRF, file inclusion testing.", "T1190"),
    
    ("Network Recon", "Onion-Security — Security Monitoring", "Medium", "Onion-Security",
     "Security Onion network security monitoring platform. Contains Suricata IDS, Zeek, Elasticsearch, Kibana. Used for blue team monitoring and detection validation.", "T1046"),
    
    ("Network Recon", "Kali Linux App-Install — Secondary Attack Node", "Low", "Kali-App-Install",
     "Secondary Kali Linux installation in VMware lab. Configured with additional application-layer attack tools.", "T1588"),
]

now = datetime.now().isoformat()
added = 0
for module, title, severity, host, desc, mitre in all_vms:
    cur.execute("SELECT COUNT(*) FROM platform_findings WHERE title=? AND host=?", (title, host))
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO platform_findings (module, title, severity, status, host, description, mitre_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (module, title, severity, "Open", host, desc, mitre, now)
        )
        print(f"  + [{severity:8s}] {title[:55]}")
        added += 1
    else:
        print(f"  = (exists) {title[:55]}")

conn.commit()

# Summary
print(f"\nAdded {added} new findings")
cur.execute("SELECT COUNT(*) FROM platform_findings")
total = cur.fetchone()[0]
print(f"Total findings: {total}")

cur.execute("SELECT severity, COUNT(*) FROM platform_findings WHERE status='Open' GROUP BY severity ORDER BY COUNT(*) DESC")
for row in cur.fetchall():
    print(f"  {row[0]:10s}: {row[1]}")

# Unique hosts
cur.execute("SELECT DISTINCT host FROM platform_findings ORDER BY host")
hosts = [r[0] for r in cur.fetchall()]
print(f"\nAll targets ({len(hosts)}):")
for h in hosts:
    print(f"  {h}")

conn.close()
