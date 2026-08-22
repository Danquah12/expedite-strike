"""
AD Security Tools — Scope & Policy Engine
==========================================
Enforces assessment scope, authorized targets, and operational modes.
"""

import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Tool risk classifications
TOOL_RISK = {
    # Discovery tools — read-only
    "discover_domain": "passive",
    "enumerate_users": "passive",
    "enumerate_groups": "passive",
    "enumerate_computers": "passive",
    "enumerate_dcs": "passive",
    "enumerate_gpos": "passive",
    "enumerate_trusts": "passive",
    "enumerate_spns": "passive",
    # Analysis tools — read-only
    "analyze_kerberos": "passive",
    "analyze_ldap": "passive",
    "analyze_smb": "passive",
    "analyze_ntlm": "passive",
    "analyze_adcs": "passive",
    "analyze_acls": "passive",
    "analyze_passwords": "passive",
    # Correlation — no network access
    "build_attack_paths": "passive",
    "correlate_risks": "passive",
    "calculate_exposure": "passive",
    # Validation — safe PoC
    "validate_kerberoast": "validation",
    "validate_asrep": "validation",
    "validate_smb_signing": "validation",
    # Exploitation — requires approval
    "exploit_kerberoast": "exploitation",
    "exploit_dcsync": "exploitation",
    "exploit_pth": "exploitation",
}


class AssessmentScope:
    """Defines and enforces the boundaries of an AD security assessment."""

    def __init__(self, assessment_id: str, authorized_domains: list = None,
                 authorized_ips: list = None, mode: str = "passive",
                 allowed_techniques: list = None,
                 prohibited_techniques: list = None):
        self.assessment_id = assessment_id
        self.authorized_domains = [d.lower() for d in (authorized_domains or [])]
        self.authorized_ips = authorized_ips or []
        self.mode = mode  # passive | validation | exploitation
        self.allowed_techniques = allowed_techniques or []
        self.prohibited_techniques = prohibited_techniques or []
        self._action_log = []

    def validate_action(self, tool_name: str, target: str) -> dict:
        """Validate whether a tool invocation is authorized."""
        result = {"authorized": True, "reason": "Within scope", "tool": tool_name, "target": target}

        # 1. Check tool risk level vs mode
        tool_risk = TOOL_RISK.get(tool_name, "exploitation")
        mode_levels = {"passive": 0, "validation": 1, "exploitation": 2}
        if mode_levels.get(tool_risk, 2) > mode_levels.get(self.mode, 0):
            result["authorized"] = False
            result["reason"] = (f"Tool '{tool_name}' requires '{tool_risk}' mode "
                                f"but assessment is in '{self.mode}' mode")
            self._log_action(tool_name, target, "BLOCKED", result["reason"])
            return result

        # 2. Check target IP authorization
        if target and self.authorized_ips:
            ip_ok = False
            for auth_ip in self.authorized_ips:
                try:
                    if "/" in auth_ip:
                        network = ipaddress.ip_network(auth_ip, strict=False)
                        if ipaddress.ip_address(target) in network:
                            ip_ok = True
                            break
                    elif target == auth_ip:
                        ip_ok = True
                        break
                except ValueError:
                    if target == auth_ip:
                        ip_ok = True
                        break
            if not ip_ok:
                result["authorized"] = False
                result["reason"] = f"Target {target} is OUT OF SCOPE"
                self._log_action(tool_name, target, "BLOCKED", result["reason"])
                return result

        # 3. Check prohibited techniques
        if tool_name in self.prohibited_techniques:
            result["authorized"] = False
            result["reason"] = f"Tool '{tool_name}' is explicitly prohibited"
            self._log_action(tool_name, target, "BLOCKED", result["reason"])
            return result

        self._log_action(tool_name, target, "AUTHORIZED", "Within scope")
        return result

    def _log_action(self, tool: str, target: str, status: str, reason: str):
        """Log every scope check for audit trail."""
        from datetime import datetime, timezone
        self._action_log.append({
            "assessment_id": self.assessment_id,
            "tool": tool,
            "target": target,
            "authorization": status,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def get_audit_log(self) -> list:
        """Return full audit trail of scope decisions."""
        return list(self._action_log)


def create_scope(assessment_id: str, domains: list = None,
                 ips: list = None, mode: str = "passive") -> AssessmentScope:
    """Create a new assessment scope."""
    return AssessmentScope(
        assessment_id=assessment_id,
        authorized_domains=domains,
        authorized_ips=ips,
        mode=mode,
    )
