# privesc_tools.py
# A structured repository of standard post-exploitation tools for automated modules

PRIVESC_TOOLS = {
    "Linux Privilege Escalation Tools": {
        "Enumeration Tools": [
            "LinPEAS", "Linux Exploit Suggester", "Linux Exploit Suggester 2", 
            "LinEnum", "lse (Linux Smart Enumeration)", "BeRoot (Linux)", 
            "Unix-Privesc-Check", "linuxprivchecker", "PEASS-ng", "pspy (process monitoring)"
        ],
        "Kernel Exploit Frameworks": [
            "DirtyCow (CVE-2016-5195)", "DirtyPipe (CVE-2022-0847)", 
            "OverlayFS exploit", "PwnKit (CVE-2021-4034)", "Baron Samedit (CVE-2021-3156)"
        ],
        "Credential Harvesting": [
            "LaZagne", "Mimikatz (Linux version)", "KeeFarce"
        ],
        "SUID / Capability Abuse": [
            "GTFOBins automation scripts", "SUID3NUM"
        ]
    },
    
    "Windows Privilege Escalation Tools": {
        "Enumeration": [
            "WinPEAS", "Seatbelt", "PowerUp", "PrivescCheck", "SharpUp", 
            "BeRoot (Windows)", "Windows Exploit Suggester", "Watson", 
            "JAWS (Just Another Windows Script)"
        ],
        "Token / Impersonation": [
            "Incognito", "RottenPotato", "JuicyPotato", "SweetPotato", 
            "PrintSpoofer", "RoguePotato", "GodPotato"
        ],
        "Credential Extraction": [
            "Mimikatz", "SafetyKatz", "SharpKatz", "LSASS Dumper", "Nanodump"
        ],
        "UAC Bypass": [
            "UACMe", "SilentCleanup", "fodhelper UAC bypass", "eventvwr bypass"
        ],
        "Service / DLL Hijacking": [
            "PowerUp (service abuse)", "SharpSploit", "DLL hijack automation tools"
        ],
        "Kernel Exploit Suggesters": [
            "Sherlock", "Windows Kernel Exploit Suggester"
        ]
    },
    
    "Active Directory Privilege Escalation": {
        "Domain Traversal & Exploitation": [
            "BloodHound", "SharpHound", "PingCastle", "ADExplorer", 
            "PowerView", "Rubeus", "Kekeo", "Certify", "ForgeCert", "Whisker"
        ],
        "Credential & Hash Abuse": [
            "Impacket", "CrackMapExec / NetExec", "Responder", "Hashcat", 
            "John the Ripper", "Pass-the-Hash tools", "Pass-the-Ticket tools"
        ]
    },
    
    "Container / Cloud Privilege Escalation": {
        "Kubernetes": [
            "kube-hunter", "kube-bench", "kubectl-exec abuse", "Peirates"
        ],
        "Docker": [
            "CDK (Container Development Kit)", "deepce", "amicontained"
        ],
        "Cloud Providers": [
            "Pacu (AWS escalation)", "Cloudsploit", "ScoutSuite"
        ]
    },
    
    "C2 & Exploit Frameworks": {
        "Post-Exploitation Platforms": [
            "Metasploit", "Empire", "Covenant", "Sliver", "Mythic", 
            "Cobalt Strike", "Havoc C2"
        ],
        "Exploit Databases & Suggesters": [
            "searchsploit (ExploitDB)", "Trickest Privesc Database", 
            "GTFOBins", "LOLBAS"
        ]
    },
    
    "Windows Lateral Movement": {
        "SMB / Admin Shares": [
            "PsExec", "Impacket psexec.py", "wmiexec.py", "smbexec.py", "CrackMapExec"
        ],
        "Service & Task Creation": [
            "sc.exe remote creation", "Scheduled tasks via SMB (schtasks)", "atexec.py"
        ],
        "Remote Execution & COM": [
            "WMI (wmic /node)", "WinRM / PowerShell Remoting", "DCOM (dcomexec.py)", "Invoke-Command"
        ],
        "Interaction & Tokens": [
            "RDP (mstsc /xfrdp)", "Token Impersonation", "Remote Registry"
        ]
    },
    
    "Linux Lateral Movement": {
        "SSH Pivoting & Tunneling": [
            "SSH Key Reuse", "SSH Agent Hijacking", "Chisel", "Ligolo-ng"
        ],
        "Execution & Trusts": [
            "Cron Job Abuse", "Sudo Credential Reuse", "NFS Mount Exploitation"
        ]
    }
}
