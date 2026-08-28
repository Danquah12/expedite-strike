"""
Expedite Strike — Enterprise ITSM, SOAR & Alert Dispatch Engine
===============================================================
Dispatches findings, Fix-as-Code bundles, and critical breach alerts to:
  1. Atlassian Jira (Issue creation with CVSS, mitigation, and attachments)
  2. ServiceNow SecOps / Incident REST API
  3. Slack & Microsoft Teams Webhook Broadcasts
"""

import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional


class ITSMSyncEngine:
    """Manages bi-directional synchronization between security findings and ITSM systems."""

    @classmethod
    def generate_jira_issue(cls, finding: Dict[str, Any], project_key: str = "SEC") -> Dict[str, Any]:
        """Generate Atlassian Jira REST API v3 compliant issue payload."""
        title = finding.get("title", "Security Finding")
        sev = finding.get("severity", "High").capitalize()
        desc = finding.get("description", "Vulnerability detected by Expedite Strike.")
        remediation = finding.get("remediation", "Review and apply security patch.")
        cvss = finding.get("cvss", 7.5)
        mitre = finding.get("mitre_id", "T1190")

        jira_payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[{sev.upper()}] {title} (CVSS {cvss})",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": f"Vulnerability Details:\n{desc}\n\n"},
                                {"type": "text", "text": f"MITRE ATT&CK: {mitre}\n"},
                                {"type": "text", "text": f"Target Host: {finding.get('host', 'Perimeter')}\n\n"},
                                {"type": "text", "text": f"Remediation Guidance:\n{remediation}\n"}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": "Bug" if sev in ("Critical", "High") else "Task"},
                "priority": {"name": "Highest" if sev == "Critical" else "High" if sev == "High" else "Medium"},
                "labels": ["expedite-strike", "security-remediation", f"mitre-{mitre}".lower()],
            }
        }
        return jira_payload

    @classmethod
    def generate_servicenow_incident(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ServiceNow Table API (incident) compliant payload."""
        title = finding.get("title", "Security Finding")
        sev = str(finding.get("severity", "High")).lower()
        impact = "1" if sev == "critical" else "2" if sev == "high" else "3"

        return {
            "short_description": f"Expedite Strike Alert: {title}",
            "description": f"Host: {finding.get('host')}\nCVSS: {finding.get('cvss')}\nDetails: {finding.get('description')}\nRemediation: {finding.get('remediation')}",
            "impact": impact,
            "urgency": impact,
            "category": "Security",
            "subcategory": "Vulnerability",
            "caller_id": "Expedite Strike Autonomous Agent",
        }

    @classmethod
    def dispatch_slack_alert(cls, webhook_url: str, finding: Dict[str, Any]) -> bool:
        """Send rich BlockKit notification to Slack / Teams webhook."""
        if not webhook_url:
            return False

        sev = str(finding.get("severity", "High")).upper()
        color = "#ef4444" if sev == "CRITICAL" else "#f59e0b" if sev == "HIGH" else "#3b82f6"

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": f"🚨 {sev} Exposure Detected: {finding.get('title')}", "emoji": True}
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Target Host:*\n`{finding.get('host', 'Unknown')}`"},
                                {"type": "mrkdwn", "text": f"*CVSS Score:*\n`{finding.get('cvss', 7.5)}`"},
                                {"type": "mrkdwn", "text": f"*MITRE TTP:*\n`{finding.get('mitre_id', 'T1190')}`"},
                                {"type": "mrkdwn", "text": f"*Scanner Engine:*\n`{finding.get('scanner', 'ExpediteStrike')}`"}
                            ]
                        },
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Remediation Guidance:*\n_{finding.get('remediation', 'N/A')}_"}
                        }
                    ]
                }
            ]
        }

        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False
