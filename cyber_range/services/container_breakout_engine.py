"""
Expedite Strike — Container Breakout & Cloud Kubernetes Escape Engine
=====================================================================
Audits containerized workloads and cloud metadata for breakout vectors:
  1. Docker Socket Mount Escape (/var/run/docker.sock) (T1611)
  2. Kubernetes Service Account Token Harvesting (T1552.007)
  3. Cloud Instance Metadata Service (IMDSv1 vs IMDSv2 IAM Token Extraction) (T1552.005)
  4. Privileged Container Execution Flags (--privileged)
"""

from typing import List, Dict, Any


class ContainerBreakoutEngine:
    """Evaluates container breakout vectors and cloud metadata exposures."""

    @classmethod
    def audit_container_foothold(cls, host: str, container_telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit local container environment for breakout opportunities."""
        findings = []

        # 1. Docker Socket Mount Check
        if container_telemetry.get("docker_sock_present"):
            findings.append({
                "title": f"Container Breakout: Mounted Docker Socket on {host}",
                "severity": "Critical",
                "cvss": 10.0,
                "host": host,
                "cve": "CWE-250 (Execution with Unnecessary Privileges)",
                "category": "Container Escape",
                "scanner": "CONTAINER_ENGINE",
                "mitre_id": "T1611",
                "mitre_name": "Escape to Host: Docker Socket Mounting",
                "description": f"The host Docker daemon socket ('/var/run/docker.sock') is mounted inside the container on '{host}'. An unprivileged container user can communicate with the Docker API to spawn a privileged container with root host filesystem access.",
                "evidence": f"Mounted Path: /var/run/docker.sock (Unix Domain Socket RW)",
                "remediation": "Unmount /var/run/docker.sock from application containers. Use rootless Docker or Podman if container management is required.",
            })

        # 2. Kubernetes Service Account Token Harvesting
        if container_telemetry.get("k8s_token_present"):
            findings.append({
                "title": f"Exposed Kubernetes Service Account Token on {host}",
                "severity": "High",
                "cvss": 8.5,
                "host": host,
                "cve": "CWE-522",
                "category": "Kubernetes Security",
                "scanner": "CONTAINER_ENGINE",
                "mitre_id": "T1552.007",
                "mitre_name": "Unsecured Credentials: Container API Tokens",
                "description": f"Default service account token mounted at '/var/run/secrets/kubernetes.io/serviceaccount/token'. Unauthenticated API queries may allow cluster traversal and secret enumeration.",
                "evidence": f"Token Location: /var/run/secrets/kubernetes.io/serviceaccount/token",
                "remediation": "Disable automountServiceAccountToken in Pod specifications: 'automountServiceAccountToken: false'.",
            })

        # 3. AWS / Cloud IMDSv1 SSRF Vulnerability
        if container_telemetry.get("imdsv1_active"):
            findings.append({
                "title": f"AWS Instance Metadata Service v1 (IMDSv1) Enabled on {host}",
                "severity": "High",
                "cvss": 8.6,
                "host": host,
                "cve": "CWE-918 (Server-Side Request Forgery)",
                "category": "Cloud Security",
                "scanner": "CONTAINER_ENGINE",
                "mitre_id": "T1552.005",
                "mitre_name": "Unsecured Credentials: Cloud Instance Metadata API",
                "description": f"Target host '{host}' allows querying IMDSv1 at 'http://169.254.169.254/latest/meta-data/' without session tokens. Any SSRF flaw enables attackers to extract temporary IAM role STS credentials.",
                "evidence": "IMDS Endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "remediation": "Enforce IMDSv2 exclusively (require HTTP PUT session token with hop limit = 1).",
            })

        return findings
