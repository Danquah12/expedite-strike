"""
EDR/AV Evasion Assessment Engine
=================================
Assesses an environment's resilience against common EDR evasion
techniques. Tests detection capabilities, NOT actual exploitation.

All checks are read-only and non-destructive.
"""
import os, json, logging, subprocess, time
from datetime import datetime
from typing import Callable, Optional, List, Dict

logger = logging.getLogger(__name__)

EVASION_TECHNIQUES = [
    {
        "id": "EVA-001", "name": "AMSI Bypass Detection",
        "category": "Antimalware", "mitre_id": "T1562.001",
        "description": "Checks if AMSI (Antimalware Scan Interface) can be bypassed via PowerShell reflection.",
        "detection_test": "Test if Set-MpPreference or AMSI initialization can be tampered.",
        "risk_if_vulnerable": "Attackers can run malicious PowerShell undetected.",
        "remediation": "Enable AMSI integrity monitoring. Deploy script-block logging. Use Constrained Language Mode.",
    },
    {
        "id": "EVA-002", "name": "PowerShell Constrained Language Mode",
        "category": "Script Control", "mitre_id": "T1059.001",
        "description": "Checks if PowerShell runs in Full Language Mode (allows .NET calls, reflection, etc.).",
        "detection_test": "Check $ExecutionContext.SessionState.LanguageMode",
        "risk_if_vulnerable": "Full Language Mode allows arbitrary .NET execution.",
        "remediation": "Enable Constrained Language Mode via AppLocker or WDAC.",
    },
    {
        "id": "EVA-003", "name": "Script Block Logging",
        "category": "Logging", "mitre_id": "T1059.001",
        "description": "Checks if PowerShell Script Block Logging is enabled.",
        "detection_test": "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        "risk_if_vulnerable": "Malicious scripts execute without logging.",
        "remediation": "Enable Script Block Logging via GPO.",
    },
    {
        "id": "EVA-004", "name": "Windows Defender Real-Time Protection",
        "category": "Antivirus", "mitre_id": "T1562.001",
        "description": "Checks if Windows Defender real-time protection is active.",
        "detection_test": "Get-MpComputerStatus | Select RealTimeProtectionEnabled",
        "risk_if_vulnerable": "Malware can execute without real-time scanning.",
        "remediation": "Enable real-time protection. Prevent tamper protection bypass.",
    },
    {
        "id": "EVA-005", "name": "Windows Event Log Service",
        "category": "Logging", "mitre_id": "T1562.002",
        "description": "Checks if Windows Event Log service is running and not tampered.",
        "detection_test": "sc query EventLog",
        "risk_if_vulnerable": "Attackers can clear or stop event logging.",
        "remediation": "Monitor EventLog service status. Forward logs to SIEM.",
    },
    {
        "id": "EVA-006", "name": "Sysmon Installation",
        "category": "EDR", "mitre_id": "T1562.001",
        "description": "Checks if Sysmon is installed for enhanced process/network logging.",
        "detection_test": "sc query Sysmon64 or Sysmon",
        "risk_if_vulnerable": "No detailed process creation, network, or file change logging.",
        "remediation": "Install Sysmon with SwiftOnSecurity or Olaf Hartong config.",
    },
    {
        "id": "EVA-007", "name": "LOLBins Availability",
        "category": "Living Off The Land", "mitre_id": "T1218",
        "description": "Checks availability of common LOLBins (certutil, mshta, rundll32, regsvr32, etc.) that can be abused.",
        "detection_test": "Check if LOLBins are present and unrestricted.",
        "risk_if_vulnerable": "Attackers use built-in tools to download/execute payloads.",
        "remediation": "Restrict LOLBins via AppLocker/WDAC. Monitor execution via Sysmon.",
    },
    {
        "id": "EVA-008", "name": "AppLocker / WDAC Policy",
        "category": "Application Control", "mitre_id": "T1553",
        "description": "Checks if AppLocker or Windows Defender Application Control is enforced.",
        "detection_test": "Get-AppLockerPolicy -Effective or WDAC status",
        "risk_if_vulnerable": "Any executable can run without application whitelisting.",
        "remediation": "Deploy AppLocker in Enforce mode or WDAC policies.",
    },
    {
        "id": "EVA-009", "name": "Credential Guard",
        "category": "Credential Protection", "mitre_id": "T1003.001",
        "description": "Checks if Credential Guard (VBS) is enabled to protect LSASS.",
        "detection_test": "Get-ComputerInfo | Select DeviceGuardSecurityServicesRunning",
        "risk_if_vulnerable": "LSASS memory can be dumped for credential theft.",
        "remediation": "Enable Credential Guard via GPO (requires UEFI Secure Boot).",
    },
    {
        "id": "EVA-010", "name": "LSA Protection (RunAsPPL)",
        "category": "Credential Protection", "mitre_id": "T1003.001",
        "description": "Checks if LSA runs as Protected Process Light.",
        "detection_test": "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL",
        "risk_if_vulnerable": "LSASS can be injected into for credential harvesting.",
        "remediation": "Set RunAsPPL=1 in registry and reboot.",
    },
    {
        "id": "EVA-011", "name": "Process Hollowing Detection",
        "category": "In-Memory", "mitre_id": "T1055.012",
        "description": "Assesses if EDR can detect process hollowing (unmapping + remapping PE).",
        "detection_test": "Check if EDR monitors NtUnmapViewOfSection + NtWriteVirtualMemory.",
        "risk_if_vulnerable": "Malware can hide inside legitimate process memory.",
        "remediation": "Deploy EDR with API hooking and memory scanning.",
    },
    {
        "id": "EVA-012", "name": "ETW Patching Detection",
        "category": "Telemetry", "mitre_id": "T1562.006",
        "description": "Checks if Event Tracing for Windows (ETW) can be disabled by patching ntdll.",
        "detection_test": "Verify ETW provider integrity.",
        "risk_if_vulnerable": "Attackers can blind EDR by patching ETW.",
        "remediation": "Use kernel-level ETW monitoring. Deploy tamper-resistant EDR.",
    },
]

def run_powershell(cmd: str) -> str:
    try:
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"PowerShell command failed: {e}")
        return ""

def check_local_defenses(log_fn=None) -> dict:
    findings = []
    
    if log_fn: log_fn("Starting local EDR/AV evasion posture assessment...")
    
    for tech in EVASION_TECHNIQUES:
        status = "UNABLE_TO_VERIFY"
        details = ""
        
        try:
            if tech["id"] == "EVA-002":
                out = run_powershell("$ExecutionContext.SessionState.LanguageMode")
                if "ConstrainedLanguage" in out:
                    status = "SECURE"
                    details = "PowerShell is in Constrained Language Mode."
                elif out:
                    status = "VULNERABLE"
                    details = f"PowerShell mode: {out}"
            elif tech["id"] == "EVA-003":
                out = run_powershell("(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging")
                if out == "1":
                    status = "SECURE"
                elif out:
                    status = "VULNERABLE"
            elif tech["id"] == "EVA-004":
                out = run_powershell("(Get-MpComputerStatus).RealTimeProtectionEnabled")
                if "True" in out:
                    status = "SECURE"
                elif out:
                    status = "VULNERABLE"
            elif tech["id"] == "EVA-005":
                out = run_powershell("(Get-Service EventLog).Status")
                if "Running" in out:
                    status = "SECURE"
                elif out:
                    status = "VULNERABLE"
            elif tech["id"] == "EVA-006":
                out = run_powershell("(Get-Service sysmon64 -ErrorAction SilentlyContinue).Status")
                if "Running" in out:
                    status = "SECURE"
                else:
                    status = "VULNERABLE"
                    details = "Sysmon is not running or installed."
            
        except Exception as e:
            logger.error(f"Error checking {tech['id']}: {e}")
            details = str(e)
            
        findings.append({
            "technique": tech,
            "status": status,
            "details": details
        })
        
        if log_fn: log_fn(f"Checked {tech['name']} -> {status}")
        
    return {"timestamp": datetime.now().isoformat(), "target": "localhost", "findings": findings}

def check_remote_defenses(target_ip: str, username: str = None, password: str = None, log_fn=None) -> dict:
    if log_fn: log_fn(f"Remote check not fully implemented. Falling back to UNABLE_TO_VERIFY for {target_ip}")
    findings = []
    for tech in EVASION_TECHNIQUES:
        findings.append({
            "technique": tech,
            "status": "UNABLE_TO_VERIFY",
            "details": "Remote execution not fully configured."
        })
    return {"timestamp": datetime.now().isoformat(), "target": target_ip, "findings": findings}

def assess_edr_posture(target_ip: str = 'localhost', log_fn=None) -> dict:
    if target_ip in ['localhost', '127.0.0.1']:
        return check_local_defenses(log_fn)
    else:
        return check_remote_defenses(target_ip, log_fn=log_fn)

def get_edr_score(findings: list) -> dict:
    total = len(findings)
    secure = sum(1 for f in findings if f["status"] == "SECURE")
    vuln = sum(1 for f in findings if f["status"] == "VULNERABLE")
    unable = sum(1 for f in findings if f["status"] == "UNABLE_TO_VERIFY")
    
    score = 0
    if total > 0:
        score = int((secure / (total - unable if total > unable else 1)) * 100)
        
    return {
        "score": score,
        "total_checks": total,
        "secure_count": secure,
        "vulnerable_count": vuln,
        "unable_to_verify_count": unable
    }

def generate_edr_report(findings: list) -> str:
    report = ["EDR/AV Evasion Posture Report", "="*30, ""]
    
    score_data = get_edr_score(findings)
    report.append(f"Overall Score: {score_data['score']}/100")
    report.append(f"Checks: {score_data['secure_count']} Secure, {score_data['vulnerable_count']} Vulnerable, {score_data['unable_to_verify_count']} Unable to Verify")
    report.append("")
    
    for f in findings:
        tech = f["technique"]
        report.append(f"[{f['status']}] {tech['id']} - {tech['name']} ({tech['category']})")
        report.append(f"  Risk: {tech['risk_if_vulnerable']}")
        report.append(f"  Remediation: {tech['remediation']}")
        if f['details']:
            report.append(f"  Details: {f['details']}")
        report.append("")
        
    return "\n".join(report)
