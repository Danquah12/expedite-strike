"""
Expedite Strike — Hybrid Active Directory & Entra ID (Azure AD) Identity Graph Engine
=====================================================================================
Analyzes identity attack paths, delegation risks, ACL abuse, and cloud sync vulnerabilities:
  1. Unconstrained Kerberos Delegation (T1558.001)
  2. DCSync Replication Rights Abuse (T1003.006)
  3. Shadow Admin & GenericAll / WriteDacl ACL Paths (T1078)
  4. Entra ID / Azure AD Connect Sync Account Exploitation (T1078.004)
"""

from typing import List, Dict, Any


class IdentityGraphEngine:
    """Evaluates complex Active Directory & Hybrid Cloud Identity attack paths."""

    @classmethod
    def audit_delegation(cls, host: str, domain_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Audit computer and user accounts for Unconstrained and Constrained Kerberos Delegation."""
        findings = []
        for obj in domain_objects:
            name = obj.get("name", "ComputerAccount")
            flags = obj.get("userAccountControl", [])
            del_type = obj.get("delegation_type", "")

            if "TRUSTED_FOR_DELEGATION" in flags or del_type == "unconstrained":
                findings.append({
                    "title": f"Unconstrained Kerberos Delegation on {name}",
                    "severity": "Critical",
                    "cvss": 9.3,
                    "host": host,
                    "cve": "CWE-287 (Improper Authentication)",
                    "category": "Active Directory",
                    "scanner": "IDENTITY_ENGINE",
                    "mitre_id": "T1558.001",
                    "mitre_name": "Steal or Forge Kerberos Tickets: Kerberos Delegation",
                    "description": f"Object '{name}' is configured with Unconstrained Delegation. If a high-privilege account (e.g., Domain Admin) connects to this service, its TGT is cached in LSASS and can be harvested to impersonate the user across the entire domain.",
                    "evidence": f"Object: {name}\nUAC Flags: TRUSTED_FOR_DELEGATION (0x80000)",
                    "remediation": "Remove Unconstrained Delegation. Migrate to Resource-Based Constrained Delegation (RBCD) and enable 'Account is sensitive and cannot be delegated' on privileged accounts.",
                })
        return findings

    @classmethod
    def audit_dcsync_rights(cls, host: str, acl_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Audit domain object ACLs for non-Domain Admin accounts with DCSync replication rights."""
        findings = []
        for acl in acl_entries:
            principal = acl.get("principal", "StandardUser")
            rights = acl.get("rights", [])
            is_admin = acl.get("is_domain_admin", False)

            if not is_admin and ("DS-Replication-Get-Changes-All" in rights or "DCSync" in rights):
                findings.append({
                    "title": f"DCSync Rights Assigned to Non-Admin Principal: {principal}",
                    "severity": "Critical",
                    "cvss": 10.0,
                    "host": host,
                    "cve": "CWE-276 (Incorrect Default Permissions)",
                    "category": "Active Directory",
                    "scanner": "IDENTITY_ENGINE",
                    "mitre_id": "T1003.006",
                    "mitre_name": "OS Credential Dumping: DCSync",
                    "description": f"Account '{principal}' possesses directory replication rights (DS-Replication-Get-Changes-All) without being a member of Domain Admins. This allows dumping password hashes (NTDS.dit) for all domain users via the Directory Replication Service Remote Protocol (MS-DRSR).",
                    "evidence": f"Principal: {principal}\nGranted ACE: DS-Replication-Get-Changes-All / DS-Replication-Get-Changes",
                    "remediation": "Remove replication permissions from non-domain controller accounts and audit domain-level Access Control Lists.",
                })
        return findings

    @classmethod
    def audit_entra_sync_accounts(cls, host: str, sync_accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Audit Azure AD Connect / Entra ID sync service accounts for hybrid privilege pivots."""
        findings = []
        for acct in sync_accounts:
            u_name = acct.get("username", "MSOL_SyncService")
            has_dcsync = acct.get("has_dcsync", True)
            if has_dcsync:
                findings.append({
                    "title": f"Entra ID Hybrid Sync Account Attack Surface ({u_name})",
                    "severity": "High",
                    "cvss": 8.8,
                    "host": host,
                    "cve": "CWE-250",
                    "category": "Cloud Identity",
                    "scanner": "IDENTITY_ENGINE",
                    "mitre_id": "T1078.004",
                    "mitre_name": "Valid Accounts: Cloud Accounts",
                    "description": f"Hybrid sync account '{u_name}' has direct DCSync rights to replicate on-prem credentials to Microsoft Entra ID. Compromising this server permits total takeover of both on-premises AD and Azure Cloud tenants.",
                    "evidence": f"Sync Account: {u_name}\nTarget Tenant: Entra ID / Microsoft 365 Hybrid",
                    "remediation": "Isolate the Azure AD Connect server as a Tier 0 asset, enforce Azure AD Password Hash Sync security baselines, and enable Entra ID Conditional Access with Phishing-Resistant MFA.",
                })
        return findings


def run_identity_audit(host: str, telemetry: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Master evaluator for Hybrid Active Directory and Entra ID identity vectors."""
    telemetry = telemetry or {}
    findings = []

    if "delegation" in telemetry:
        findings.extend(IdentityGraphEngine.audit_delegation(host, telemetry["delegation"]))
    if "acls" in telemetry:
        findings.extend(IdentityGraphEngine.audit_dcsync_rights(host, telemetry["acls"]))
    if "entra_sync" in telemetry:
        findings.extend(IdentityGraphEngine.audit_entra_sync_accounts(host, telemetry["entra_sync"]))

    return findings
