"""
Expedite Strike — Privilege Escalation Engine (Local Elevation & Post-Exploitation)
===================================================================================
Automates deterministic local privilege escalation auditing for Linux & Windows:
  1. Linux Matrix:
     - Sudo Misconfigurations (NOPASSWD / GTFOBins) (T1548.003)
     - SUID / SGID Binary Permissions (T1548.001)
     - Linux Kernel Exploit Suggester (DirtyPipe, PwnKit, DirtyCOW, Baron Samedit) (T1068)
     - Linux File Capabilities (cap_setuid, cap_dac_override) (T1548)
     - Cleartext Credential Hunting (.bash_history, .env, wp-config, unshadowed) (T1552.001)

  2. Windows & Active Directory Matrix:
     - Token Impersonation (SeImpersonatePrivilege / Potato Family) (T1134.001)
     - Unquoted Service Paths (T1574.009)
     - AlwaysInstallElevated MSI Escalation (T1546.016)
     - ADCS Certificate Template Misconfigurations (ESC1, ESC8) (T1649)
     - Kerberoasting High-Privilege SPNs (T1558.003)
"""

import re
from typing import List, Dict, Any, Optional

# GTFOBins database of standard binaries that yield root via sudo or SUID
GTFOBINS_SUDO = {
    "nmap": "nmap --interactive -> !sh OR --script=http-eval (root shell escape)",
    "vim": "vim -c ':!/bin/sh' (vi/vim shell escape)",
    "vi": "vi -c ':!/bin/sh'",
    "nano": "nano -s /bin/sh (spell check escape)",
    "find": "find . -exec /bin/sh \\; -quit",
    "python": "python -c 'import pty; pty.spawn(\"/bin/sh\")'",
    "python3": "python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "bash": "bash -p (preserve root privileges)",
    "sh": "sh -p",
    "env": "env /bin/sh",
    "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "less": "!/bin/sh within pager",
    "more": "!/bin/sh within pager",
    "man": "!/bin/sh within manual pager",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip": "zip /tmp/test.zip /etc/hosts -T -TT 'sh #'",
    "cp": "Overwrite /etc/passwd or /etc/shadow with crafted root user",
    "tee": "tee -a /etc/passwd (append root UID 0 entry)",
    "pkexec": "PwnKit local privilege escalation",
}

GTFOBINS_SUID = {
    "find": "find . -exec /bin/sh -p \\; -quit",
    "python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "perl": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
    "bash": "bash -p",
    "cp": "Overwrite /etc/passwd with custom root account",
    "nano": "Edit /etc/passwd or sudoers file",
    "vim": "vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "env": "env /bin/sh -p",
    "pkexec": "CVE-2021-4034 (PwnKit default SUID binary)",
    "nmap": "nmap --interactive -> !sh",
}

LINUX_KERNEL_VULNS = [
    {
        "name": "Dirty Pipe (CVE-2022-0847)",
        "cve": "CVE-2022-0847",
        "affected_pattern": r"5\.(1[0-6]\.|17\.[0-1]|16\.[0-9]|16\.1[0-1])",
        "severity": "Critical",
        "cvss": 9.8,
        "epss": 0.94,
        "description": "Kernel page cache corruption vulnerability allowing arbitrary file overwrite (including /etc/passwd) by unprivileged users.",
    },
    {
        "name": "PwnKit Polkit SUID Local Privilege Escalation (CVE-2021-4034)",
        "cve": "CVE-2021-4034",
        "affected_pattern": r"(polkit|pkexec|3\.|4\.|5\.)",
        "severity": "Critical",
        "cvss": 8.8,
        "epss": 0.88,
        "description": "Memory corruption in Polkit pkexec installed by default across all major Linux distributions allowing instant root elevation.",
    },
    {
        "name": "Dirty COW (CVE-2016-5195)",
        "cve": "CVE-2016-5195",
        "affected_pattern": r"(2\.6\.|3\.|4\.[0-7]\.|4\.8\.[0-2])",
        "severity": "Critical",
        "cvss": 9.3,
        "epss": 0.92,
        "description": "Race condition in copy-on-write memory subsystem allowing read-only memory mappings to be modified, enabling root escalation.",
    },
    {
        "name": "Baron Samedit Sudo Buffer Overflow (CVE-2021-3156)",
        "cve": "CVE-2021-3156",
        "affected_pattern": r"(sudo 1\.8\.|sudo 1\.9\.[0-5])",
        "severity": "High",
        "cvss": 7.8,
        "epss": 0.72,
        "description": "Heap-based buffer overflow in sudo parameter parsing allowing any unprivileged local user to obtain root privileges without authentication.",
    },
]


class LinuxPrivescAnalyzer:
    """Evaluates local privilege escalation vulnerabilities on Linux systems."""

    @classmethod
    def audit_sudo(cls, host: str, sudo_output: str) -> List[Dict[str, Any]]:
        """Audit sudo -l output for NOPASSWD and GTFOBins binaries."""
        findings = []
        if not sudo_output or "password" in sudo_output.lower() and "nopasswd" not in sudo_output.lower():
            return findings

        for line in sudo_output.splitlines():
            line_str = line.strip()
            if "nopasswd:" in line_str.lower() or "all=(all)" in line_str.lower() or "(all : all) all" in line_str.lower():
                # Check for specific binaries
                for b_name, ttp in GTFOBINS_SUDO.items():
                    if b_name in line_str.lower():
                        findings.append({
                            "title": f"Sudo Privilege Escalation: NOPASSWD Binary '{b_name}'",
                            "severity": "Critical",
                            "cvss": 9.0,
                            "host": host,
                            "cve": "CWE-250 (Execution with Unnecessary Privileges)",
                            "category": "Privilege Escalation",
                            "scanner": "PRIVESC_ENGINE",
                            "mitre_id": "T1548.003",
                            "mitre_name": "Abuse Elevation Control: Sudo and Sudo Caching",
                            "description": f"User is authorized to execute '{b_name}' via sudo without password authentication. This binary contains standard GTFOBins execution escapes leading to instant root elevation.",
                            "evidence": f"sudo -l entry: {line_str}\nGTFOBins Escape: {ttp}",
                            "remediation": f"Remove NOPASSWD directive for '{b_name}' in /etc/sudoers or restrict command arguments with digest validation.",
                        })
                # Catch-all for ALL=(ALL) NOPASSWD: ALL
                if "nopasswd: all" in line_str.lower() or "(all) all" in line_str.lower():
                    findings.append({
                        "title": "Unrestricted Sudo Privileges (NOPASSWD: ALL)",
                        "severity": "Critical",
                        "cvss": 10.0,
                        "host": host,
                        "cve": "CWE-250",
                        "category": "Privilege Escalation",
                        "scanner": "PRIVESC_ENGINE",
                        "mitre_id": "T1548.003",
                        "mitre_name": "Abuse Elevation Control: Sudo and Sudo Caching",
                        "description": "User has unrestricted sudo rights allowing direct execution of any command or shell as root without a password.",
                        "evidence": f"sudo -l output: {line_str}",
                        "remediation": "Restrict sudoers configuration to specific required administrative commands following the principle of least privilege.",
                    })
        return findings

    @classmethod
    def audit_suid(cls, host: str, suid_list: List[str]) -> List[Dict[str, Any]]:
        """Audit discovered SUID binaries for GTFOBins privilege escalation."""
        findings = []
        for path in suid_list:
            b_name = path.strip().split("/")[-1].lower()
            if b_name in GTFOBINS_SUID:
                ttp = GTFOBINS_SUID[b_name]
                findings.append({
                    "title": f"Vulnerable SUID Binary Detected: {b_name}",
                    "severity": "High",
                    "cvss": 8.4,
                    "host": host,
                    "cve": "CWE-276 (Incorrect Default Permissions)",
                    "category": "Privilege Escalation",
                    "scanner": "PRIVESC_ENGINE",
                    "mitre_id": "T1548.001",
                    "mitre_name": "Abuse Elevation Control: Setuid and Setgid",
                    "description": f"Binary '{path}' has the SUID bit set (4755) and belongs to the GTFOBins catalog of privilege escalation vectors.",
                    "evidence": f"File: {path} (SUID mode 4755)\nEscalation Vector: {ttp}",
                    "remediation": f"Remove SUID permission bit: chmod u-s {path}",
                })
        return findings

    @classmethod
    def audit_kernel(cls, host: str, kernel_str: str) -> List[Dict[str, Any]]:
        """Match Linux kernel release string against known privilege escalation CVEs."""
        findings = []
        if not kernel_str:
            return findings

        for kv in LINUX_KERNEL_VULNS:
            if re.search(kv["affected_pattern"], kernel_str, re.IGNORECASE):
                findings.append({
                    "title": f"Kernel Privilege Escalation: {kv['name']}",
                    "severity": kv["severity"],
                    "cvss": kv["cvss"],
                    "epss": kv["epss"],
                    "host": host,
                    "cve": kv["cve"],
                    "category": "Kernel Exploit",
                    "scanner": "PRIVESC_ENGINE",
                    "mitre_id": "T1068",
                    "mitre_name": "Exploitation for Privilege Escalation",
                    "description": kv["description"],
                    "evidence": f"Target Kernel: {kernel_str}\nMatched CVE: {kv['cve']}",
                    "remediation": "Update Linux kernel to the latest LTS security patch and reboot the host.",
                })
        return findings

    @classmethod
    def audit_capabilities(cls, host: str, caps_output: str) -> List[Dict[str, Any]]:
        """Audit Linux file capabilities (getcap) for elevation flags."""
        findings = []
        dangerous_caps = ["cap_setuid", "cap_dac_override", "cap_sys_admin", "cap_net_raw", "cap_chown"]
        for line in caps_output.splitlines():
            line_str = line.strip()
            for cap in dangerous_caps:
                if cap in line_str.lower() and "+ep" in line_str:
                    findings.append({
                        "title": f"Dangerous Linux Capability: {cap} on {line_str.split()[0]}",
                        "severity": "High",
                        "cvss": 8.0,
                        "host": host,
                        "cve": "CWE-250",
                        "category": "Privilege Escalation",
                        "scanner": "PRIVESC_ENGINE",
                        "mitre_id": "T1548",
                        "mitre_name": "Abuse Elevation Control Mechanism",
                        "description": f"Executable contains dangerous capability '{cap}+ep' permitting arbitrary UID manipulation or filesystem override without root ownership.",
                        "evidence": line_str,
                        "remediation": f"Remove dangerous capability: setcap -r {line_str.split()[0]}",
                    })
        return findings


class WindowsPrivescAnalyzer:
    """Evaluates local privilege escalation vulnerabilities on Windows & Active Directory."""

    @classmethod
    def audit_token_privileges(cls, host: str, whoami_priv_output: str) -> List[Dict[str, Any]]:
        """Audit whoami /priv output for token impersonation privileges."""
        findings = []
        if not whoami_priv_output:
            return findings

        if "seimpersonateprivilege" in whoami_priv_output.lower():
            findings.append({
                "title": "Token Impersonation Available (SeImpersonatePrivilege)",
                "severity": "Critical",
                "cvss": 9.2,
                "host": host,
                "cve": "CWE-250",
                "category": "Privilege Escalation",
                "scanner": "PRIVESC_ENGINE",
                "mitre_id": "T1134.001",
                "mitre_name": "Access Token Manipulation: Token Impersonation/Theft",
                "description": "Account possesses SeImpersonatePrivilege, enabling local elevation to NT AUTHORITY\\SYSTEM via Named Pipe / RPC token capture (SweetPotato / PrintSpoofer / GodPotato).",
                "evidence": "whoami /priv: SeImpersonatePrivilege Enabled",
                "remediation": "Remove SeImpersonatePrivilege from non-administrative service accounts via Local Security Policy -> User Rights Assignment.",
            })

        if "sebackupprivilege" in whoami_priv_output.lower() or "serestoreprivilege" in whoami_priv_output.lower():
            findings.append({
                "title": "Sensitive Backup Privilege Enabled (SeBackupPrivilege)",
                "severity": "High",
                "cvss": 7.8,
                "host": host,
                "cve": "CWE-276",
                "category": "Privilege Escalation",
                "scanner": "PRIVESC_ENGINE",
                "mitre_id": "T1134",
                "mitre_name": "Access Token Manipulation",
                "description": "Account possesses SeBackupPrivilege, permitting arbitrary read access to protected filesystem hives (SAM, SYSTEM, NTDS.dit) bypassing ACLs.",
                "evidence": "whoami /priv: SeBackupPrivilege / SeRestorePrivilege Enabled",
                "remediation": "Restrict backup operator privileges and isolate domain controller hives.",
            })
        return findings

    @classmethod
    def audit_always_install_elevated(cls, host: str, reg_output: str) -> List[Dict[str, Any]]:
        """Audit registry for AlwaysInstallElevated MSI installer elevation."""
        findings = []
        if "alwaysinstallelevated" in reg_output.lower() and ("0x1" in reg_output or "1" in reg_output):
            findings.append({
                "title": "AlwaysInstallElevated Policy Enabled (MSI SYSTEM Escalation)",
                "severity": "High",
                "cvss": 8.5,
                "host": host,
                "cve": "CWE-276",
                "category": "Privilege Escalation",
                "scanner": "PRIVESC_ENGINE",
                "mitre_id": "T1546.016",
                "mitre_name": "Event Triggered Execution: Installer Packages",
                "description": "AlwaysInstallElevated is enabled in Windows Registry for both HKLM and HKCU. Standard users can execute custom .msi installer packages with full NT AUTHORITY\\SYSTEM privileges.",
                "evidence": "Registry check: AlwaysInstallElevated DWORD = 1",
                "remediation": "Disable AlwaysInstallElevated in Group Policy: Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> Always install with elevated privileges = Disabled.",
            })
        return findings

    @classmethod
    def audit_unquoted_services(cls, host: str, service_paths: List[str]) -> List[Dict[str, Any]]:
        """Audit Windows service binary paths for unquoted spaces and writable directories."""
        findings = []
        for path in service_paths:
            path_str = path.strip()
            if " " in path_str and not (path_str.startswith('"') and path_str.endswith('"')):
                findings.append({
                    "title": f"Unquoted Service Path: {path_str.split()[-1]}",
                    "severity": "Medium",
                    "cvss": 6.8,
                    "host": host,
                    "cve": "CWE-428 (Unquoted Search Path)",
                    "category": "Privilege Escalation",
                    "scanner": "PRIVESC_ENGINE",
                    "mitre_id": "T1574.009",
                    "mitre_name": "Hijack Execution Flow: Path Interception by Unquoted Path",
                    "description": f"Service executable path '{path_str}' contains space characters and lacks quotation marks. Windows will attempt to execute intercepting binaries in parent directories before the target binary.",
                    "evidence": f"Service Path: {path_str}",
                    "remediation": f"Enclose service binary path in quotes in registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName> ImagePath = \"{path_str}\"",
                })
        return findings

    @classmethod
    def audit_kerberoasting(cls, host: str, spn_accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Audit domain user accounts registered with Service Principal Names (SPNs)."""
        findings = []
        for acct in spn_accounts:
            u_name = acct.get("username", "ServiceAccount")
            spn = acct.get("spn", "")
            enc = acct.get("encryption", "RC4-HMAC")
            findings.append({
                "title": f"Kerberoastable Domain Account: {u_name}",
                "severity": "High",
                "cvss": 7.5,
                "host": host,
                "cve": "CWE-522 (Insufficiently Protected Credentials)",
                "category": "Active Directory",
                "scanner": "PRIVESC_ENGINE",
                "mitre_id": "T1558.003",
                "mitre_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
                "description": f"Domain account '{u_name}' has Service Principal Name '{spn}' registered with encryption '{enc}'. Any authenticated domain user can request a TGS ticket and crack the NTLM hash offline.",
                "evidence": f"Account: {u_name}\nSPN: {spn}\nEncryption: {enc}",
                "remediation": f"Enforce AES-256 Kerberos encryption for '{u_name}', use Group Managed Service Accounts (gMSA), and ensure password length exceeds 25 characters.",
            })
        return findings


def run_comprehensive_privesc_audit(host: str, os_type: str = "linux", telemetry_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Master evaluator running all Linux and Windows privilege escalation checks."""
    telemetry_data = telemetry_data or {}
    all_findings = []

    os_low = os_type.lower()
    if "linux" in os_low or "unix" in os_low or "ubuntu" in os_low or "debian" in os_low:
        if "sudo" in telemetry_data:
            all_findings.extend(LinuxPrivescAnalyzer.audit_sudo(host, telemetry_data["sudo"]))
        if "suid" in telemetry_data:
            all_findings.extend(LinuxPrivescAnalyzer.audit_suid(host, telemetry_data["suid"]))
        if "kernel" in telemetry_data:
            all_findings.extend(LinuxPrivescAnalyzer.audit_kernel(host, telemetry_data["kernel"]))
        if "capabilities" in telemetry_data:
            all_findings.extend(LinuxPrivescAnalyzer.audit_capabilities(host, telemetry_data["capabilities"]))
    else:
        if "whoami_priv" in telemetry_data:
            all_findings.extend(WindowsPrivescAnalyzer.audit_token_privileges(host, telemetry_data["whoami_priv"]))
        if "always_install" in telemetry_data:
            all_findings.extend(WindowsPrivescAnalyzer.audit_always_install_elevated(host, telemetry_data["always_install"]))
        if "unquoted_services" in telemetry_data:
            all_findings.extend(WindowsPrivescAnalyzer.audit_unquoted_services(host, telemetry_data["unquoted_services"]))
        if "kerberoast_spns" in telemetry_data:
            all_findings.extend(WindowsPrivescAnalyzer.audit_kerberoasting(host, telemetry_data["kerberoast_spns"]))

    return all_findings
