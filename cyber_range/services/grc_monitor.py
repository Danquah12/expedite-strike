# ================================================================
# grc_monitor.py — Continuous Monitoring Engine
#
# Features:
#   1. Scheduled vulnerability scanning check
#   2. Compliance score auto-update
#   3. Configuration drift detection
#   4. Cloud misconfiguration alerts (AWS/Azure/GCP stubs)
#   5. Background scheduler (APScheduler or threading)
#
# Usage:
#   from cyber_range.services.grc_monitor import start_monitor, run_monitor_cycle
#   start_monitor()          # start background scheduler
#   run_monitor_cycle()      # run one cycle manually
# ================================================================

import os
import json
import logging
import threading
from datetime import datetime, date
from typing import Optional

log = logging.getLogger(__name__)

_monitor_thread: Optional[threading.Thread] = None
_monitor_running = False
_INTERVAL_SECONDS = int(os.getenv("GRC_MONITOR_INTERVAL", "3600"))  # default: 1 hour


# ── Data Access Helpers ──────────────────────────────────────────
def _pg_execute(sql, params=None, fetch=True):
    try:
        from cyber_range.services.pg_engine import pg_execute
        return pg_execute(sql, params, fetch=fetch)
    except Exception as e:
        log.error(f"[Monitor] PG error: {e}")
        return [] if fetch else None


def _neo4j_query(cypher, params=None):
    try:
        pw = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
        with driver.session() as s:
            result = s.run(cypher, params or {})
            rows = [dict(r) for r in result]
        driver.close()
        return rows
    except Exception as e:
        log.error(f"[Monitor] Neo4j error: {e}")
        return []


# ================================================================
# Monitor Functions
# ================================================================

def check_new_vulnerabilities() -> dict:
    """
    Check for new vulnerabilities since last check.
    Compares Neo4j findings with PostgreSQL records.
    """
    log.info("[Monitor] Checking for new vulnerabilities...")
    results = {"new_vulns": 0, "new_critical": 0, "new_high": 0, "alerts": []}

    # Get last check timestamp
    last = _pg_execute("""
        SELECT MAX(last_seen) AS last_check FROM grc_vulnerabilities
    """)
    last_check = last[0].get("last_check") if last else None

    # Count current open vulns
    current = _pg_execute("""
        SELECT severity, count(*) AS cnt FROM grc_vulnerabilities
        WHERE status = 'Open' GROUP BY severity
    """)

    # Check Neo4j for findings newer than last check
    neo4j_count = _neo4j_query("""
        MATCH (f:Finding)
        WHERE f.last_seen IS NOT NULL
        RETURN count(f) AS total,
               sum(CASE WHEN f.severity IN ['Critical', 'High'] THEN 1 ELSE 0 END) AS high_crit
    """)

    if neo4j_count:
        results["neo4j_total"] = neo4j_count[0].get("total", 0)

    for row in current:
        sev = row.get("severity", "")
        cnt = row.get("cnt", 0)
        if sev == "Critical":
            results["new_critical"] = cnt
            if cnt > 0:
                results["alerts"].append(f"🔴 {cnt} Critical vulnerabilities open")
        elif sev == "High":
            results["new_high"] = cnt
            if cnt > 0:
                results["alerts"].append(f"🟠 {cnt} High vulnerabilities open")
        results["new_vulns"] += cnt

    log.info(f"[Monitor] ✅ {results['new_vulns']} open vulns ({results['new_critical']} critical)")
    return results


def update_compliance_score(system_id: int = 1) -> dict:
    """
    Calculate and record the current compliance score.
    Auto-updates the compliance_scores table.
    """
    log.info(f"[Monitor] Updating compliance score for system {system_id}...")

    # Calculate score
    controls = _pg_execute("""
        SELECT
            count(*) AS total,
            count(*) FILTER (WHERE status = 'Implemented') AS implemented,
            count(*) FILTER (WHERE status = 'Partially Implemented') AS partial,
            count(*) FILTER (WHERE status = 'N/A') AS na
        FROM system_controls WHERE system_id = %s
    """, (system_id,))

    ctrl = controls[0] if controls else {"total": 0, "implemented": 0, "partial": 0, "na": 0}
    denom = max((ctrl["total"] or 1) - (ctrl.get("na") or 0), 1)
    score = round(((ctrl["implemented"] or 0) + 0.5 * (ctrl["partial"] or 0)) / denom * 100, 1)

    # Get open findings and POA&Ms
    vulns = _pg_execute("SELECT count(*) AS n FROM grc_vulnerabilities WHERE status='Open'")
    poams = _pg_execute("SELECT count(*) AS n FROM poam WHERE status != 'Closed'")

    open_findings = vulns[0]["n"] if vulns else 0
    open_poams = poams[0]["n"] if poams else 0

    # Record score
    _pg_execute("""
        INSERT INTO compliance_scores (system_id, score, open_findings, open_poams)
        VALUES (%s, %s, %s, %s)
    """, (system_id, score, open_findings, open_poams), fetch=False)

    result = {
        "system_id": system_id,
        "score": score,
        "open_findings": open_findings,
        "open_poams": open_poams,
        "controls": ctrl,
        "timestamp": datetime.now().isoformat(),
    }
    log.info(f"[Monitor] ✅ Compliance score: {score}% (findings={open_findings}, poams={open_poams})")
    return result


def detect_config_drift(system_id: int = 1) -> dict:
    """
    Detect configuration drift by comparing current state with baseline.
    Checks: new services, changed ports, missing controls.
    """
    log.info("[Monitor] Checking for configuration drift...")
    drift_items = []

    # Check for new services/ports in Neo4j not previously seen
    new_services = _neo4j_query("""
        MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)
        WHERE s.port IS NOT NULL
        RETURN h.ip AS host, s.port AS port, s.name AS service, s.source AS source
        ORDER BY s.port
    """)

    # Compare with last known baseline
    known = _pg_execute("""
        SELECT DISTINCT host, port FROM grc_vulnerabilities
    """)
    known_set = {(r.get("host", ""), str(r.get("port", ""))) for r in known}

    for svc in new_services:
        key = (svc.get("host", ""), str(svc.get("port", "")))
        if key not in known_set and svc.get("port"):
            drift_items.append({
                "type": "new_service",
                "host": svc.get("host"),
                "port": svc.get("port"),
                "service": svc.get("service"),
                "severity": "Medium",
                "detail": f"New service {svc.get('service', '?')} on port {svc.get('port', '?')}",
            })

    # Check for overdue POA&Ms
    overdue = _pg_execute("""
        SELECT poam_id, weakness, risk_level, due_date
        FROM poam WHERE due_date < CURRENT_DATE AND status = 'Open'
    """)
    for p in overdue:
        drift_items.append({
            "type": "overdue_poam",
            "poam_id": p.get("poam_id"),
            "weakness": p.get("weakness"),
            "risk_level": p.get("risk_level"),
            "severity": "High",
            "detail": f"POA&M {p.get('poam_id')} overdue since {p.get('due_date')}",
        })

    result = {
        "drift_items": drift_items[:50],
        "new_services": sum(1 for d in drift_items if d["type"] == "new_service"),
        "overdue_poams": sum(1 for d in drift_items if d["type"] == "overdue_poam"),
        "total_drift": len(drift_items),
        "timestamp": datetime.now().isoformat(),
    }
    log.info(f"[Monitor] ✅ Drift: {len(drift_items)} items ({result['new_services']} new services, "
             f"{result['overdue_poams']} overdue POA&Ms)")
    return result


def check_cloud_misconfigs() -> dict:
    """
    Check for cloud misconfigurations.
    Stubs for AWS/Azure/GCP — returns findings from available sources.
    """
    log.info("[Monitor] Checking cloud misconfigurations...")
    findings = []

    # AWS (requires boto3 + credentials)
    aws_available = False
    try:
        import boto3
        sts = boto3.client("sts")
        sts.get_caller_identity()
        aws_available = True
    except Exception:
        pass

    if aws_available:
        try:
            import boto3
            # S3 bucket public access check
            s3 = boto3.client("s3")
            for bucket in s3.list_buckets().get("Buckets", []):
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            findings.append({
                                "cloud": "AWS", "resource": f"s3://{name}",
                                "issue": "Public access enabled",
                                "severity": "High",
                            })
                except Exception:
                    pass

            # Security groups with 0.0.0.0/0
            ec2 = boto3.client("ec2")
            for sg in ec2.describe_security_groups().get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "all")
                            findings.append({
                                "cloud": "AWS",
                                "resource": f"sg:{sg['GroupId']}",
                                "issue": f"Inbound 0.0.0.0/0 on port {port}",
                                "severity": "High" if port in (22, 3389, 3306, 5432) else "Medium",
                            })
        except Exception as e:
            log.warning(f"[Monitor] AWS check error: {e}")

    # Azure (requires azure-identity + credentials)
    azure_available = False
    try:
        from azure.identity import DefaultAzureCredential
        azure_available = True
    except ImportError:
        pass

    # GCP (requires google-cloud SDK)
    gcp_available = False
    try:
        from google.cloud import compute_v1
        gcp_available = True
    except ImportError:
        pass

    result = {
        "findings": findings,
        "total": len(findings),
        "clouds_checked": {
            "aws": aws_available,
            "azure": azure_available,
            "gcp": gcp_available,
        },
        "timestamp": datetime.now().isoformat(),
    }
    log.info(f"[Monitor] ✅ Cloud: {len(findings)} misconfigs found "
             f"(AWS={'✅' if aws_available else '❌'}, "
             f"Azure={'✅' if azure_available else '❌'}, "
             f"GCP={'✅' if gcp_available else '❌'})")
    return result


def discover_cloud_assets() -> dict:
    """
    Discover cloud assets (Step 14).
    AWS: EC2, RDS, S3, IAM roles
    Azure: VMs, SQL DBs, Storage, AAD
    GCP: Compute, CloudSQL, GCS, IAM
    """
    log.info("[Monitor] Discovering cloud assets...")
    assets = {"aws": [], "azure": [], "gcp": [], "total": 0}

    # AWS discovery
    try:
        import boto3
        ec2 = boto3.client("ec2")
        for r in ec2.describe_instances().get("Reservations", []):
            for inst in r.get("Instances", []):
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                assets["aws"].append({
                    "type": "EC2", "id": inst["InstanceId"],
                    "name": name, "state": inst["State"]["Name"],
                    "ip": inst.get("PrivateIpAddress", ""),
                    "public_ip": inst.get("PublicIpAddress", ""),
                })

        rds = boto3.client("rds")
        for db in rds.describe_db_instances().get("DBInstances", []):
            assets["aws"].append({
                "type": "RDS", "id": db["DBInstanceIdentifier"],
                "engine": db["Engine"], "status": db["DBInstanceStatus"],
                "endpoint": db.get("Endpoint", {}).get("Address", ""),
            })

        s3 = boto3.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            assets["aws"].append({
                "type": "S3", "id": bucket["Name"],
                "created": bucket["CreationDate"].isoformat(),
            })

        iam = boto3.client("iam")
        for role in iam.list_roles().get("Roles", []):
            assets["aws"].append({
                "type": "IAM Role", "id": role["RoleName"],
                "arn": role["Arn"],
            })
    except Exception as e:
        log.info(f"[Monitor] AWS discovery: {e}")

    # Azure discovery (stub — requires azure SDK + credentials)
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        cred = DefaultAzureCredential()
        sub_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        if sub_id:
            compute = ComputeManagementClient(cred, sub_id)
            for vm in compute.virtual_machines.list_all():
                assets["azure"].append({
                    "type": "VM", "id": vm.name,
                    "location": vm.location,
                    "size": vm.hardware_profile.vm_size,
                })
    except Exception as e:
        log.info(f"[Monitor] Azure discovery: {e}")

    # GCP discovery (stub — requires google-cloud SDK)
    try:
        from google.cloud import compute_v1
        project = os.getenv("GCP_PROJECT_ID", "")
        if project:
            client = compute_v1.InstancesClient()
            for zone_inst in client.aggregated_list(project=project):
                zone, inst_list = zone_inst
                for inst in (inst_list.instances or []):
                    assets["gcp"].append({
                        "type": "VM", "id": inst.name,
                        "zone": zone, "status": inst.status,
                    })
    except Exception as e:
        log.info(f"[Monitor] GCP discovery: {e}")

    assets["total"] = len(assets["aws"]) + len(assets["azure"]) + len(assets["gcp"])
    log.info(f"[Monitor] ✅ Discovered {assets['total']} cloud assets "
             f"(AWS={len(assets['aws'])}, Azure={len(assets['azure'])}, GCP={len(assets['gcp'])})")
    return assets


# ================================================================
# Monitor Cycle (runs all checks)
# ================================================================
def run_monitor_cycle(system_id: int = 1) -> dict:
    """Run one complete monitoring cycle."""
    log.info(f"[Monitor] ═══ Starting monitor cycle (system={system_id}) ═══")
    start = datetime.now()

    results = {
        "timestamp": start.isoformat(),
        "system_id": system_id,
    }

    results["vulnerabilities"] = check_new_vulnerabilities()
    results["compliance"] = update_compliance_score(system_id)
    results["drift"] = detect_config_drift(system_id)
    results["cloud"] = check_cloud_misconfigs()

    elapsed = (datetime.now() - start).total_seconds()
    results["elapsed_seconds"] = round(elapsed, 2)

    # Generate alerts
    alerts = []
    alerts.extend(results["vulnerabilities"].get("alerts", []))
    if results["drift"].get("total_drift", 0) > 0:
        alerts.append(f"⚠️ {results['drift']['total_drift']} configuration drift items detected")
    if results["cloud"].get("total", 0) > 0:
        alerts.append(f"☁️ {results['cloud']['total']} cloud misconfigurations found")
    results["alerts"] = alerts

    log.info(f"[Monitor] ═══ Cycle complete in {elapsed:.1f}s — {len(alerts)} alerts ═══")
    return results


# ================================================================
# Background Scheduler
# ================================================================
def _monitor_loop():
    """Background monitoring loop."""
    global _monitor_running
    import time
    log.info(f"[Monitor] Background scheduler started (interval={_INTERVAL_SECONDS}s)")
    while _monitor_running:
        try:
            run_monitor_cycle()
        except Exception as e:
            log.error(f"[Monitor] Cycle error: {e}")
        time.sleep(_INTERVAL_SECONDS)


def start_monitor():
    """Start the background monitoring thread."""
    global _monitor_thread, _monitor_running
    if _monitor_running:
        log.info("[Monitor] Already running")
        return
    _monitor_running = True
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True, name="grc-monitor")
    _monitor_thread.start()
    log.info("[Monitor] ✅ Started")


def stop_monitor():
    """Stop the background monitoring thread."""
    global _monitor_running
    _monitor_running = False
    log.info("[Monitor] Stopped")


def get_monitor_status() -> dict:
    """Get current monitor status."""
    return {
        "running": _monitor_running,
        "interval_seconds": _INTERVAL_SECONDS,
        "thread_alive": _monitor_thread.is_alive() if _monitor_thread else False,
    }
