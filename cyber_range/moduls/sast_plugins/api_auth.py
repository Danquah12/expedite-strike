"""
api_auth.py — API Authorization / Broken Object Level Authorization (BOLA) plugin
Detects missing access control checks around object-level data retrieval (OWASP API-1).
"""
import re
from .base_plugin import BasePlugin


class APIAuthPlugin(BasePlugin):
    name        = "API Authorization Checker"
    description = "Flags potential Broken Object Level Authorization (BOLA/IDOR) patterns"
    engine_tag  = "Plugin-APIAuth"

    RULES = [
        (
            # get_user / get_object called without nearby auth check
            r'get_user\s*\(',
            "check_auth|is_authenticated|has_permission|authorize|require_auth|login_required|@jwt",
            "PI-API-001", "Possible BOLA — get_user Without Auth Check",
            "HIGH", "CWE-639",
            "Object retrieved by ID (get_user) with no visible authorization check nearby. "
            "Verify the caller owns or is permitted to access this resource.",
            "if not user.can_access(requested_id): raise PermissionError('Forbidden')",
        ),
        (
            r'get_by_id\s*\(|find_by_id\s*\(|\.objects\.get\s*\(',
            "check_auth|is_authenticated|has_permission|authorize|permission_required|login_required",
            "PI-API-002", "Object Lookup Without Visible Auth Check",
            "HIGH", "CWE-639",
            "Object fetched by ID without a clear authorization guard. "
            "Scope queries to the authenticated user's own records.",
            "obj = Model.objects.get(pk=pk, owner=request.user)",
        ),
        (
            r'request\.args\.get\s*\(|request\.params\s*\[|params\[',
            "check_auth|is_authenticated|authorize|login_required|require_auth",
            "PI-API-003", "Request Param Used Without Auth Context",
            "MEDIUM", "CWE-284",
            "Request parameter accessed without a visible authentication check. "
            "Ensure the endpoint is protected by an auth middleware.",
            "",
        ),
    ]

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []
        lines = content.splitlines()
        content_lower = content.lower()
        for rule in self.RULES:
            trigger_pat, guard_pat, rid, rname, sev, cwe, msg, fix = rule
            trigger_compiled = re.compile(trigger_pat, re.IGNORECASE)
            guard_present = bool(re.search(guard_pat, content, re.IGNORECASE))
            if guard_present:
                continue  # Auth guard found somewhere in the file — skip
            for i, line in enumerate(lines, 1):
                if trigger_compiled.search(line):
                    findings.append(self.make_finding(
                        rule_id=rid, rule=rname, severity=sev, cwe=cwe,
                        message=msg, line=i, code=line, fix=fix,
                        engine=self.engine_tag,
                    ))
        return findings
