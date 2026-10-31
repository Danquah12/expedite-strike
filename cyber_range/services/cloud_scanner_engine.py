"""
Cloud Security Scanner Engine
=============================
Assesses AWS / Azure / GCP misconfigurations.
Falls back gracefully when cloud SDKs are unavailable.
"""

import os
import json
import logging
import subprocess
import time
import uuid
from datetime import datetime
from typing import Callable, Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ── Cloud Check Registry ─────────────────────────────────────────────
CLOUD_CHECKS = {
    "aws": [
        {"id": "AWS-IAM-001", "title": "Root Account MFA Not Enabled", "severity": "Critical",
         "description": "AWS root account lacks MFA, enabling full account takeover.",
         "remediation": "Enable hardware MFA on root account immediately.",
         "mitre_id": "T1078.004", "check_type": "iam"},
        {"id": "AWS-S3-001", "title": "S3 Bucket Public Access", "severity": "Critical",
         "description": "S3 bucket allows public read/write, exposing sensitive data.",
         "remediation": "Enable S3 Block Public Access at account level.",
         "mitre_id": "T1530", "check_type": "s3"},
        {"id": "AWS-S3-002", "title": "S3 Bucket No Encryption", "severity": "High",
         "description": "S3 bucket lacks default server-side encryption.",
         "remediation": "Enable SSE-S3 or SSE-KMS default encryption.",
         "mitre_id": "T1530", "check_type": "s3"},
        {"id": "AWS-IAM-002", "title": "IAM User with Inline Policy", "severity": "Medium",
         "description": "IAM users have inline policies instead of managed policies.",
         "remediation": "Convert inline policies to managed policies.",
         "mitre_id": "T1078.004", "check_type": "iam"},
        {"id": "AWS-IAM-003", "title": "Access Keys Older Than 90 Days", "severity": "High",
         "description": "IAM access keys not rotated in 90+ days.",
         "remediation": "Rotate access keys every 90 days.",
         "mitre_id": "T1078.004", "check_type": "iam"},
        {"id": "AWS-EC2-001", "title": "Security Group Allows 0.0.0.0/0 SSH", "severity": "Critical",
         "description": "Security group allows SSH (port 22) from any IP address.",
         "remediation": "Restrict SSH to specific IP ranges or use SSM Session Manager.",
         "mitre_id": "T1190", "check_type": "ec2"},
        {"id": "AWS-EC2-002", "title": "Security Group Allows 0.0.0.0/0 RDP", "severity": "Critical",
         "description": "Security group allows RDP (port 3389) from any IP address.",
         "remediation": "Restrict RDP to VPN/bastion host IPs only.",
         "mitre_id": "T1190", "check_type": "ec2"},
        {"id": "AWS-CT-001", "title": "CloudTrail Not Enabled", "severity": "High",
         "description": "CloudTrail logging disabled — no audit trail for API calls.",
         "remediation": "Enable CloudTrail in all regions with S3 logging.",
         "mitre_id": "T1562.008", "check_type": "cloudtrail"},
        {"id": "AWS-RDS-001", "title": "RDS Instance Publicly Accessible", "severity": "Critical",
         "description": "RDS database instance is publicly accessible from the internet.",
         "remediation": "Set PubliclyAccessible=false and use VPC endpoints.",
         "mitre_id": "T1190", "check_type": "rds"},
        {"id": "AWS-KMS-001", "title": "KMS Key Rotation Disabled", "severity": "Medium",
         "description": "KMS customer-managed key lacks automatic rotation.",
         "remediation": "Enable automatic key rotation for all CMKs.",
         "mitre_id": "T1588.004", "check_type": "kms"},
    ],
    "azure": [
        {"id": "AZ-IAM-001", "title": "Azure AD Global Admin Without MFA", "severity": "Critical",
         "description": "Global Administrator role lacks MFA enforcement.",
         "remediation": "Enforce MFA via Conditional Access Policy for all admins.",
         "mitre_id": "T1078.004", "check_type": "identity"},
        {"id": "AZ-STOR-001", "title": "Storage Account Public Blob Access", "severity": "Critical",
         "description": "Azure Storage allows anonymous public blob access.",
         "remediation": "Disable public access on all storage accounts.",
         "mitre_id": "T1530", "check_type": "storage"},
        {"id": "AZ-NSG-001", "title": "NSG Allows Inbound SSH from Any", "severity": "Critical",
         "description": "Network Security Group allows SSH from 0.0.0.0/0.",
         "remediation": "Restrict SSH to bastion/VPN IP ranges.",
         "mitre_id": "T1190", "check_type": "network"},
        {"id": "AZ-SQL-001", "title": "Azure SQL Firewall Allows All IPs", "severity": "High",
         "description": "SQL Server firewall rule allows 0.0.0.0-255.255.255.255.",
         "remediation": "Remove open firewall rule. Use Private Endpoints.",
         "mitre_id": "T1190", "check_type": "sql"},
        {"id": "AZ-LOG-001", "title": "Activity Log Alerts Not Configured", "severity": "Medium",
         "description": "No activity log alerts configured for security events.",
         "remediation": "Configure alerts for critical administrative operations.",
         "mitre_id": "T1562.008", "check_type": "monitor"},
    ],
    "gcp": [
        {"id": "GCP-IAM-001", "title": "Service Account Key Older Than 90 Days", "severity": "High",
         "description": "GCP service account key not rotated in 90+ days.",
         "remediation": "Rotate service account keys every 90 days.",
         "mitre_id": "T1078.004", "check_type": "iam"},
        {"id": "GCP-GCS-001", "title": "GCS Bucket Publicly Accessible", "severity": "Critical",
         "description": "GCS bucket grants allUsers or allAuthenticatedUsers access.",
         "remediation": "Remove public ACL and use uniform bucket-level access.",
         "mitre_id": "T1530", "check_type": "storage"},
        {"id": "GCP-FW-001", "title": "Firewall Rule Allows 0.0.0.0/0 SSH", "severity": "Critical",
         "description": "VPC firewall allows SSH from any source IP.",
         "remediation": "Restrict to IAP tunnel or specific IP ranges.",
         "mitre_id": "T1190", "check_type": "network"},
        {"id": "GCP-LOG-001", "title": "Audit Logging Not Enabled", "severity": "High",
         "description": "Cloud Audit Logs not enabled for all services.",
         "remediation": "Enable Data Access audit logs for all services.",
         "mitre_id": "T1562.008", "check_type": "logging"},
    ],
}


def _run_cli(cmd: list, timeout: int = 30) -> tuple:
    """Run a CLI command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        return result.returncode == 0, result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, ""


def _make_finding(check: dict, provider: str, status: str = "VULNERABLE",
                  confidence: float = 0.9, resource: str = "") -> dict:
    """Create a unified finding dict from a check definition."""
    return {
        "id": check["id"],
        "title": check["title"],
        "severity": check["severity"],
        "description": check["description"],
        "remediation": check["remediation"],
        "mitre_id": check.get("mitre_id", ""),
        "provider": provider,
        "check_type": check["check_type"],
        "confidence": confidence,
        "affected_resource": resource,
        "status": status,
    }


# ═══════════════════════════════════════════════════════════════════
# AWS Scanner
# ═══════════════════════════════════════════════════════════════════

def scan_aws(profile: str = None, region: str = "us-east-1",
             log_fn: Callable = None) -> dict:
    """Scan AWS for security misconfigurations."""
    findings = []
    checks_run = 0
    _log = log_fn or (lambda m: None)
    _log("  ☁️  [AWS] Starting cloud security assessment...")

    # Check if boto3 is available
    boto3_available = False
    try:
        import boto3
        session = boto3.Session(profile_name=profile, region_name=region)
        boto3_available = True
        _log("  ☁️  [AWS] boto3 connected.")
    except Exception:
        _log("  ☁️  [AWS] boto3 not available, trying AWS CLI...")

    # Check if AWS CLI is available
    cli_available = False
    if not boto3_available:
        ok, out = _run_cli(["aws", "sts", "get-caller-identity"])
        cli_available = ok
        if ok:
            _log(f"  ☁️  [AWS] CLI identity: {out[:80]}")

    if boto3_available:
        # S3 public access check
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            checks_run += 1
            for b in buckets:
                try:
                    acl = s3.get_bucket_acl(Bucket=b["Name"])
                    for grant in acl.get("Grants", []):
                        uri = grant.get("Grantee", {}).get("URI", "")
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            findings.append(_make_finding(
                                CLOUD_CHECKS["aws"][1], "aws",
                                resource=b["Name"], confidence=1.0
                            ))
                except Exception:
                    pass
        except Exception as e:
            _log(f"  ☁️  [AWS] S3 check error: {e}")

        # Security Groups check
        try:
            ec2 = session.client("ec2")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            checks_run += 1
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = perm.get("FromPort", 0)
                            if port == 22:
                                findings.append(_make_finding(
                                    CLOUD_CHECKS["aws"][5], "aws",
                                    resource=f"{sg['GroupId']}:{sg.get('GroupName', '')}",
                                    confidence=1.0
                                ))
                            elif port == 3389:
                                findings.append(_make_finding(
                                    CLOUD_CHECKS["aws"][6], "aws",
                                    resource=f"{sg['GroupId']}:{sg.get('GroupName', '')}",
                                    confidence=1.0
                                ))
        except Exception as e:
            _log(f"  ☁️  [AWS] EC2 check error: {e}")

        # CloudTrail check
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            checks_run += 1
            if not trails:
                findings.append(_make_finding(
                    CLOUD_CHECKS["aws"][7], "aws",
                    resource="No CloudTrail", confidence=1.0
                ))
        except Exception as e:
            _log(f"  ☁️  [AWS] CloudTrail check error: {e}")

    elif cli_available:
        # CLI-based checks
        checks_run += 1
        ok, out = _run_cli(["aws", "s3api", "list-buckets", "--query", "Buckets[].Name"])
        if ok and out:
            _log(f"  ☁️  [AWS] CLI found buckets: {out[:60]}")

    else:
        # No AWS access — return checks as UNABLE_TO_VERIFY
        _log("  ☁️  [AWS] No AWS credentials. Returning check registry.")
        for check in CLOUD_CHECKS["aws"]:
            findings.append(_make_finding(
                check, "aws", status="CHECK_UNAVAILABLE", confidence=0.0
            ))
        checks_run = len(CLOUD_CHECKS["aws"])

    _log(f"  ☁️  [AWS] Complete: {checks_run} checks, {len(findings)} findings")
    return {"provider": "aws", "findings": findings, "checks_run": checks_run}


# ═══════════════════════════════════════════════════════════════════
# Azure Scanner
# ═══════════════════════════════════════════════════════════════════

def scan_azure(subscription_id: str = None,
               log_fn: Callable = None) -> dict:
    """Scan Azure for security misconfigurations."""
    findings = []
    checks_run = 0
    _log = log_fn or (lambda m: None)
    _log("  ☁️  [Azure] Starting cloud security assessment...")

    # Check Azure CLI
    cli_available = False
    ok, out = _run_cli(["az", "account", "show"])
    if ok:
        cli_available = True
        _log(f"  ☁️  [Azure] CLI connected: {out[:60]}")

    if cli_available:
        # Storage account check
        checks_run += 1
        ok, out = _run_cli(["az", "storage", "account", "list",
                            "--query", "[].{name:name,publicAccess:allowBlobPublicAccess}",
                            "-o", "json"])
        if ok and out:
            try:
                accounts = json.loads(out)
                for acct in accounts:
                    if acct.get("publicAccess"):
                        findings.append(_make_finding(
                            CLOUD_CHECKS["azure"][1], "azure",
                            resource=acct.get("name", ""), confidence=1.0
                        ))
            except json.JSONDecodeError:
                pass

        # NSG check
        checks_run += 1
        ok, out = _run_cli(["az", "network", "nsg", "list", "-o", "json"])
        if ok and out:
            try:
                nsgs = json.loads(out)
                for nsg in nsgs:
                    for rule in nsg.get("securityRules", []):
                        if (rule.get("sourceAddressPrefix") == "*" and
                                rule.get("destinationPortRange") == "22" and
                                rule.get("access") == "Allow"):
                            findings.append(_make_finding(
                                CLOUD_CHECKS["azure"][2], "azure",
                                resource=nsg.get("name", ""), confidence=1.0
                            ))
            except json.JSONDecodeError:
                pass
    else:
        _log("  ☁️  [Azure] No Azure credentials. Returning check registry.")
        for check in CLOUD_CHECKS["azure"]:
            findings.append(_make_finding(
                check, "azure", status="CHECK_UNAVAILABLE", confidence=0.0
            ))
        checks_run = len(CLOUD_CHECKS["azure"])

    _log(f"  ☁️  [Azure] Complete: {checks_run} checks, {len(findings)} findings")
    return {"provider": "azure", "findings": findings, "checks_run": checks_run}


# ═══════════════════════════════════════════════════════════════════
# GCP Scanner
# ═══════════════════════════════════════════════════════════════════

def scan_gcp(project_id: str = None,
             log_fn: Callable = None) -> dict:
    """Scan GCP for security misconfigurations."""
    findings = []
    checks_run = 0
    _log = log_fn or (lambda m: None)
    _log("  ☁️  [GCP] Starting cloud security assessment...")

    # Check gcloud CLI
    cli_available = False
    ok, out = _run_cli(["gcloud", "config", "get-value", "project"])
    if ok and out:
        cli_available = True
        project = project_id or out.strip()
        _log(f"  ☁️  [GCP] CLI connected. Project: {project}")

    if cli_available:
        # Firewall rules check
        checks_run += 1
        ok, out = _run_cli(["gcloud", "compute", "firewall-rules", "list",
                            "--format", "json", "--project", project])
        if ok and out:
            try:
                rules = json.loads(out)
                for rule in rules:
                    sources = rule.get("sourceRanges", [])
                    if "0.0.0.0/0" in sources:
                        allowed = rule.get("allowed", [])
                        for a in allowed:
                            ports = a.get("ports", [])
                            if "22" in ports:
                                findings.append(_make_finding(
                                    CLOUD_CHECKS["gcp"][2], "gcp",
                                    resource=rule.get("name", ""), confidence=1.0
                                ))
            except json.JSONDecodeError:
                pass
    else:
        _log("  ☁️  [GCP] No GCP credentials. Returning check registry.")
        for check in CLOUD_CHECKS["gcp"]:
            findings.append(_make_finding(
                check, "gcp", status="CHECK_UNAVAILABLE", confidence=0.0
            ))
        checks_run = len(CLOUD_CHECKS["gcp"])

    _log(f"  ☁️  [GCP] Complete: {checks_run} checks, {len(findings)} findings")
    return {"provider": "gcp", "findings": findings, "checks_run": checks_run}


# ═══════════════════════════════════════════════════════════════════
# Orchestrator
# ═══════════════════════════════════════════════════════════════════

def run_cloud_assessment(providers: list = None, config: dict = None,
                         log_fn: Callable = None) -> dict:
    """
    Run cloud security assessment across AWS/Azure/GCP.

    Args:
        providers: List of providers to scan. Default: all.
        config: Provider-specific config (profiles, regions, etc.)
        log_fn: Logging callback.

    Returns:
        Unified assessment result dict.
    """
    providers = providers or ["aws", "azure", "gcp"]
    config = config or {}
    _log = log_fn or (lambda m: None)
    start = time.time()
    assessment_id = f"CLOUD-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    _log(f"\n{'═'*60}")
    _log(f"  ☁️  CLOUD SECURITY ASSESSMENT: {assessment_id}")
    _log(f"  Providers: {', '.join(providers)}")
    _log(f"{'═'*60}")

    all_findings = []
    stats = {}

    scanner_map = {
        "aws": lambda: scan_aws(
            profile=config.get("aws_profile"),
            region=config.get("aws_region", "us-east-1"),
            log_fn=log_fn
        ),
        "azure": lambda: scan_azure(
            subscription_id=config.get("azure_subscription"),
            log_fn=log_fn
        ),
        "gcp": lambda: scan_gcp(
            project_id=config.get("gcp_project"),
            log_fn=log_fn
        ),
    }

    for provider in providers:
        if provider in scanner_map:
            try:
                result = scanner_map[provider]()
                all_findings.extend(result.get("findings", []))
                stats[provider] = {
                    "checks": result.get("checks_run", 0),
                    "findings": len(result.get("findings", [])),
                }
            except Exception as e:
                _log(f"  ☁️  [{provider.upper()}] Error: {e}")
                stats[provider] = {"checks": 0, "findings": 0, "error": str(e)}

    duration = round(time.time() - start, 1)
    total_findings = len(all_findings)
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        s = f.get("severity", "Low")
        if s in sev:
            sev[s] += 1

    _log(f"\n{'━'*60}")
    _log(f"  ☁️  CLOUD ASSESSMENT COMPLETE")
    _log(f"  ID:        {assessment_id}")
    _log(f"  Duration:  {duration}s")
    _log(f"  Findings:  {total_findings}")
    _log(f"    Critical: {sev['Critical']}")
    _log(f"    High:     {sev['High']}")
    _log(f"    Medium:   {sev['Medium']}")
    _log(f"    Low:      {sev['Low']}")
    _log(f"{'━'*60}")

    return {
        "assessment_id": assessment_id,
        "providers_scanned": providers,
        "findings": all_findings,
        "stats": stats,
        "severity_summary": sev,
        "duration_seconds": duration,
        "timestamp": datetime.now().isoformat(),
    }
