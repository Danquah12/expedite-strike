"""
AD Security Tools — Correlation Engine
=======================================
Attack path construction, multi-finding risk correlation, and exposure scoring.
"""

import logging
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)


def _ts():
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════
# ATTACK PATH BUILDER
# ═══════════════════════════════════════════════════════════════════════

def build_attack_paths(findings: list, discovery_data: dict = None,
                       log_fn: Callable = None) -> dict:
    """Build attack paths from correlated findings."""
    result = {"paths": [], "total_paths": 0, "critical_paths": 0, "timestamp": _ts()}
    if not findings:
        return result

    # Extract relevant data
    has_kerberoast = any("Kerberoast" in f.get("title", "") for f in findings)
    has_asrep = any("AS-REP" in f.get("title", "") for f in findings)
    has_unconstrained = any("Unconstrained" in f.get("title", "") for f in findings)
    has_esc1 = any("ESC1" in f.get("title", "") for f in findings)
    has_anon_ldap = any("Anonymous LDAP" in f.get("title", "") for f in findings)
    has_smb_signing = any("SMB Signing" in f.get("title", "") for f in findings)
    has_spooler = any("Spooler" in f.get("title", "") for f in findings)
    has_no_laps = any("LAPS" in f.get("title", "") for f in findings)
    has_pwd_desc = any("Password in Description" in f.get("title", "") for f in findings)
    has_priv_spn = any("Privileged Kerberoastable" in f.get("title", "") for f in findings)
    has_weak_pwd = any("Weak Password" in f.get("title", "") for f in findings)

    # Path 1: Kerberoasting → DA
    if has_kerberoast or has_priv_spn:
        path = {
            "name": "Kerberoasting → Domain Admin",
            "source": "Domain User",
            "target": "Domain Admin",
            "steps": [
                {"node": "Domain User", "relationship": "requests TGS", "technique": "T1558.003"},
                {"node": "Service Account (SPN)", "relationship": "offline crack", "technique": "T1110.002"},
                {"node": "Service Account Credentials", "relationship": "member of", "technique": "T1078.002"},
                {"node": "Privileged Group", "relationship": "admin access", "technique": "T1078.002"},
                {"node": "Domain Controller", "relationship": "DCSync", "technique": "T1003.006"},
            ],
            "risk_score": 95 if has_priv_spn else 80,
            "confidence": 0.95 if has_priv_spn else 0.7,
            "mitre_chain": ["T1558.003", "T1110.002", "T1078.002", "T1003.006"],
        }
        result["paths"].append(path)

    # Path 2: Unconstrained Delegation → DA
    if has_unconstrained:
        path = {
            "name": "Unconstrained Delegation → Domain Admin",
            "source": "Domain User",
            "target": "Domain Admin",
            "steps": [
                {"node": "Domain User", "relationship": "compromises", "technique": "T1078"},
                {"node": "Delegation Host", "relationship": "captures TGT", "technique": "T1550.003"},
                {"node": "Admin TGT", "relationship": "impersonates", "technique": "T1550.003"},
                {"node": "Domain Controller", "relationship": "full access", "technique": "T1003.006"},
            ],
            "risk_score": 95, "confidence": 0.9,
            "mitre_chain": ["T1078", "T1550.003", "T1003.006"],
        }
        result["paths"].append(path)
        if has_spooler:
            path2 = {
                "name": "PrinterBug + Unconstrained Delegation → DA",
                "source": "Domain User",
                "target": "Domain Admin",
                "steps": [
                    {"node": "Domain User", "relationship": "coerces auth", "technique": "T1187"},
                    {"node": "DC (Print Spooler)", "relationship": "sends TGT to", "technique": "T1187"},
                    {"node": "Delegation Host", "relationship": "captures DC TGT", "technique": "T1550.003"},
                    {"node": "Domain Controller", "relationship": "DCSync", "technique": "T1003.006"},
                ],
                "risk_score": 100, "confidence": 0.95,
                "mitre_chain": ["T1187", "T1550.003", "T1003.006"],
            }
            result["paths"].append(path2)

    # Path 3: ESC1 → DA
    if has_esc1:
        path = {
            "name": "ADCS ESC1 → Domain Admin",
            "source": "Domain User",
            "target": "Domain Admin",
            "steps": [
                {"node": "Domain User", "relationship": "enrolls in template", "technique": "T1649"},
                {"node": "Vulnerable Template", "relationship": "specifies SAN=DA", "technique": "T1649"},
                {"node": "Certificate as DA", "relationship": "authenticates", "technique": "T1552.004"},
                {"node": "Domain Admin", "relationship": "full control", "technique": "T1078.002"},
            ],
            "risk_score": 100, "confidence": 0.95,
            "mitre_chain": ["T1649", "T1552.004", "T1078.002"],
        }
        result["paths"].append(path)

    # Path 4: NTLM Relay Chain
    if has_anon_ldap and has_smb_signing:
        path = {
            "name": "NTLM Relay → Domain Compromise",
            "source": "Network Access",
            "target": "Domain Admin",
            "steps": [
                {"node": "Network Access", "relationship": "captures NTLM", "technique": "T1557"},
                {"node": "NTLM Hash", "relationship": "relays to LDAP", "technique": "T1557.001"},
                {"node": "LDAP (no signing)", "relationship": "modifies AD", "technique": "T1484.001"},
                {"node": "RBCD/ACL Abuse", "relationship": "escalates", "technique": "T1550.003"},
            ],
            "risk_score": 90, "confidence": 0.85,
            "mitre_chain": ["T1557", "T1557.001", "T1484.001"],
        }
        result["paths"].append(path)

    # Path 5: Password in Description → Lateral
    if has_pwd_desc:
        path = {
            "name": "Credential Leak → Lateral Movement",
            "source": "Domain User",
            "target": "Compromised Account",
            "steps": [
                {"node": "Domain User", "relationship": "reads LDAP", "technique": "T1087.002"},
                {"node": "Description Field", "relationship": "extracts password", "technique": "T1552.001"},
                {"node": "Target Account", "relationship": "authenticates", "technique": "T1078.002"},
            ],
            "risk_score": 85, "confidence": 0.95,
            "mitre_chain": ["T1087.002", "T1552.001", "T1078.002"],
        }
        result["paths"].append(path)

    # Path 6: No LAPS → Mass Lateral
    if has_no_laps:
        path = {
            "name": "Shared Local Admin → Mass Lateral Movement",
            "source": "Compromised Workstation",
            "target": "All Workstations",
            "steps": [
                {"node": "Workstation 1", "relationship": "dumps local admin", "technique": "T1003.001"},
                {"node": "Local Admin Hash", "relationship": "same on all WS", "technique": "T1078.003"},
                {"node": "All Workstations", "relationship": "mass PTH", "technique": "T1550.002"},
            ],
            "risk_score": 75, "confidence": 0.85,
            "mitre_chain": ["T1003.001", "T1078.003", "T1550.002"],
        }
        result["paths"].append(path)

    result["total_paths"] = len(result["paths"])
    result["critical_paths"] = sum(1 for p in result["paths"] if p["risk_score"] >= 90)

    if log_fn:
        log_fn(f"    [attack_paths] {result['total_paths']} paths, "
               f"{result['critical_paths']} critical")
    return result


# ═══════════════════════════════════════════════════════════════════════
# RISK CORRELATION ENGINE
# ═══════════════════════════════════════════════════════════════════════

def correlate_risks(findings: list, log_fn: Callable = None) -> dict:
    """Correlate multiple findings into compound risk assessments."""
    result = {"correlations": [], "risk_multiplier": 1.0, "timestamp": _ts()}
    if not findings:
        return result

    titles = {f.get("title", ""): f for f in findings}
    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories.setdefault(cat, []).append(f)

    # Rule 1: Kerberoast + Privilege + Weak Password = CRITICAL
    has_kerb = any("Kerberoast" in t for t in titles)
    has_weak = any("Weak Password" in t or "No Account Lockout" in t for t in titles)
    if has_kerb and has_weak:
        result["correlations"].append({
            "rule": "Kerberoast + Weak Password Policy",
            "combined_severity": "Critical",
            "attack_narrative": "Kerberoastable accounts combined with weak password policy "
                                "makes offline cracking trivial. Domain compromise likely.",
            "remediation_priority": 1,
            "constituent_findings": ["Kerberoastable Accounts", "Weak Password Policy"],
        })

    # Rule 2: Anonymous LDAP + No SMB Signing = CRITICAL (relay)
    has_anon = any("Anonymous LDAP" in t for t in titles)
    has_smb = any("SMB Signing" in t for t in titles)
    if has_anon and has_smb:
        result["correlations"].append({
            "rule": "Anonymous LDAP + SMB Signing Not Enforced",
            "combined_severity": "Critical",
            "attack_narrative": "Anonymous LDAP access enables reconnaissance. "
                                "Lack of SMB signing enables NTLM relay to LDAP for object modification.",
            "remediation_priority": 1,
            "constituent_findings": ["Anonymous LDAP Bind", "SMB Signing"],
        })

    # Rule 3: Unconstrained Delegation + Print Spooler = CRITICAL
    has_unc = any("Unconstrained" in t for t in titles)
    has_spool = any("Spooler" in t for t in titles)
    if has_unc and has_spool:
        result["correlations"].append({
            "rule": "Unconstrained Delegation + Print Spooler",
            "combined_severity": "Critical",
            "attack_narrative": "PrinterBug can coerce DC authentication to delegation host. "
                                "DC TGT captured → immediate domain compromise.",
            "remediation_priority": 1,
            "constituent_findings": ["Unconstrained Delegation", "Print Spooler"],
        })

    # Rule 4: ESC1 = Instant DA
    if any("ESC1" in t for t in titles):
        result["correlations"].append({
            "rule": "ADCS ESC1 — Instant Domain Admin",
            "combined_severity": "Critical",
            "attack_narrative": "Vulnerable certificate template allows any domain user "
                                "to request a certificate as Domain Admin.",
            "remediation_priority": 1,
            "constituent_findings": ["ESC1 Vulnerable Template"],
        })

    # Rule 5: No LAPS + Admin sprawl = HIGH
    has_laps = any("LAPS" in t for t in titles)
    has_admin = any("Admin Sprawl" in t or "Admin" in t for t in titles)
    if has_laps and has_admin:
        result["correlations"].append({
            "rule": "No LAPS + Admin Sprawl",
            "combined_severity": "High",
            "attack_narrative": "Shared local admin passwords across workstations "
                                "combined with excessive admin accounts enables mass lateral movement.",
            "remediation_priority": 2,
            "constituent_findings": ["LAPS Not Deployed", "Admin Account Sprawl"],
        })

    # Calculate risk multiplier
    critical_corrs = sum(1 for c in result["correlations"] if c["combined_severity"] == "Critical")
    result["risk_multiplier"] = 1.0 + (critical_corrs * 0.15)

    if log_fn:
        log_fn(f"    [correlate] {len(result['correlations'])} compound risks, "
               f"multiplier: {result['risk_multiplier']:.2f}x")
    return result


# ═══════════════════════════════════════════════════════════════════════
# EXPOSURE SCORE CALCULATOR
# ═══════════════════════════════════════════════════════════════════════

def calculate_exposure(findings: list, correlations: list = None,
                       attack_paths: list = None,
                       log_fn: Callable = None) -> dict:
    """PingCastle-style exposure scoring across 4 categories (0-100)."""
    cats = {
        "Privileged Accounts": 0,   # 0-25
        "Trust & Delegation": 0,     # 0-25
        "Configuration": 0,          # 0-25
        "Anomalies": 0,              # 0-25
    }

    cat_map = {
        "User Security": "Privileged Accounts",
        "Kerberos Security": "Trust & Delegation",
        "Trust Analysis": "Trust & Delegation",
        "Configuration": "Configuration",
        "Password Policy": "Configuration",
        "LDAP Analysis": "Configuration",
        "SMB Security": "Configuration",
        "NTLM Security": "Configuration",
        "Certificate Services": "Anomalies",
        "ACL Analysis": "Anomalies",
        "Reconnaissance": "Configuration",
    }

    sev_weight = {"Critical": 8, "High": 4, "Medium": 2, "Low": 1}

    for f in findings:
        fc = f.get("category", "Configuration")
        target_cat = cat_map.get(fc, "Configuration")
        weight = sev_weight.get(f.get("severity", "Low"), 1)
        cats[target_cat] = min(25, cats[target_cat] + weight)

    # Correlation bonus
    if correlations:
        for c in correlations:
            if c.get("combined_severity") == "Critical":
                cats["Anomalies"] = min(25, cats["Anomalies"] + 5)

    # Attack path bonus
    if attack_paths:
        critical_paths = sum(1 for p in attack_paths if p.get("risk_score", 0) >= 90)
        cats["Anomalies"] = min(25, cats["Anomalies"] + critical_paths * 3)

    total = sum(cats.values())
    risk_label = "LOW" if total < 25 else "MODERATE" if total < 50 else "HIGH" if total < 75 else "CRITICAL"

    recommendations = []
    if cats["Privileged Accounts"] >= 15:
        recommendations.append("Implement tiered admin model. Reduce admin count.")
    if cats["Trust & Delegation"] >= 15:
        recommendations.append("Remove unconstrained delegation. Audit trusts.")
    if cats["Configuration"] >= 15:
        recommendations.append("Enforce SMB/LDAP signing. Deploy LAPS. Strengthen password policy.")
    if cats["Anomalies"] >= 15:
        recommendations.append("Audit certificate templates. Review ACLs on privileged objects.")

    result = {
        "total_score": total,
        "risk_label": risk_label,
        "categories": cats,
        "recommendations": recommendations,
        "timestamp": _ts(),
    }

    if log_fn:
        log_fn(f"    [exposure] Score: {total}/100 ({risk_label})")
        for cat, score in cats.items():
            log_fn(f"      {cat}: {score}/25")

    return result
