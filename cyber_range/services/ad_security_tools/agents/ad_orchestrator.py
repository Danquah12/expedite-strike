"""
AD Security AI — Multi-Agent Orchestrator with LLM Reasoning
=============================================================
The LLM plans and reasons. The Python tools execute.

Architecture:
    ┌────────────────────────────────────────┐
    │         LLM Reasoning Layer            │
    │  (Interprets, correlates, plans next)  │
    └──────────────────┬─────────────────────┘
                       │ decides which tool
                       ▼
    ┌────────────────────────────────────────┐
    │        Tool Validation Layer           │
    │   (Scope check, risk level, audit)     │
    └──────────────────┬─────────────────────┘
                       │ authorized
                       ▼
    ┌────────────────────────────────────────┐
    │     Deterministic Python Tools         │
    │  (15 tools — no LLM in execution)      │
    └──────────────────┬─────────────────────┘
                       │ structured output
                       ▼
    ┌────────────────────────────────────────┐
    │        Evidence Store                  │
    │  (Postgres + SQLite)                   │
    └────────────────────────────────────────┘

Reasoning Loop:
    PLAN → DISCOVER → ANALYZE GAP → COLLECT MORE → CORRELATE → RANK → REPORT
"""

import time
import json
import os
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ── LLM Integration (Google Gemini) ──────────────────────────────────
# The LLM is ONLY used for reasoning — never for direct execution.

_LLM_AVAILABLE = False
_gemini_model = None

try:
    import google.generativeai as genai
    _api_key = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
    if _api_key:
        genai.configure(api_key=_api_key)
        _gemini_model = genai.GenerativeModel(
            "gemini-3.6-flash",
            system_instruction=(
                "You are an AD security analyst AI. You ONLY analyze and reason about "
                "security evidence. You do NOT execute commands or access systems. "
                "You receive structured tool outputs and determine: "
                "1) What security issues exist, 2) What additional analysis is needed, "
                "3) How findings correlate into attack paths, 4) Priority recommendations. "
                "Be concise. Return structured analysis."
            ),
            generation_config=genai.GenerationConfig(
                max_output_tokens=1000,
                temperature=0.1,
            ),
        )
        _LLM_AVAILABLE = True
        logger.info("[LLM] Google Gemini initialized (gemini-2.0-flash)")
except ImportError:
    pass
except Exception as e:
    logger.warning(f"[LLM] Gemini init error: {e}")


def _llm_reason(prompt: str, context: str = "") -> str:
    """Ask Gemini to reason about security findings. Never executes commands."""
    if not _LLM_AVAILABLE or not _gemini_model:
        return ""
    try:
        full_prompt = f"Context:\n{context}\n\nQuestion:\n{prompt}" if context else prompt
        response = _gemini_model.generate_content(full_prompt)
        return response.text.strip() if response.text else ""
    except Exception as e:
        logger.warning(f"[LLM] Gemini reasoning error: {e}")
        return ""


def _llm_plan_next_tools(discovery_results: dict, findings_so_far: list) -> list:
    """LLM decides which analysis tools to prioritize based on discovery results."""
    if not _LLM_AVAILABLE:
        return []  # Fall back to running all tools

    summary = {
        "users_found": discovery_results.get("users", 0),
        "spns_found": discovery_results.get("spns", 0),
        "dcs_found": discovery_results.get("dcs", 0),
        "trusts_found": discovery_results.get("trusts", 0),
        "open_ports": discovery_results.get("domain_info", {}).get("dc_ports", []),
        "findings_count": len(findings_so_far),
        "has_asrep": any("AS-REP" in f.get("title", "") for f in findings_so_far),
        "has_kerberoast": any("Kerberoast" in f.get("title", "") for f in findings_so_far),
        "has_anon_ldap": any("Anonymous LDAP" in f.get("title", "") for f in findings_so_far),
        "has_pwd_desc": any("Password in Description" in f.get("title", "") for f in findings_so_far),
    }

    prompt = (
        "Given these AD discovery results, which analysis tools should I prioritize?\n"
        f"Results: {json.dumps(summary)}\n\n"
        "Available tools: analyze_kerberos, analyze_ldap, analyze_smb, "
        "analyze_ntlm, analyze_adcs, analyze_acls, analyze_passwords\n\n"
        "Return a JSON array of tool names in priority order. "
        "Include reasoning for the top 3 choices."
    )

    response = _llm_reason(prompt)
    # Parse tool names from response
    tools = []
    for tool in ["analyze_kerberos", "analyze_ldap", "analyze_smb",
                 "analyze_ntlm", "analyze_adcs", "analyze_acls", "analyze_passwords"]:
        if tool in response:
            tools.append(tool)
    return tools


def _llm_correlate_findings(findings: list, attack_paths: list) -> str:
    """LLM provides narrative analysis of correlated findings."""
    if not _LLM_AVAILABLE:
        return ""

    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
        "high": sum(1 for f in findings if f.get("severity") == "High"),
        "attack_paths": len(attack_paths),
        "top_findings": [{"title": f["title"], "severity": f["severity"],
                          "mitre": f.get("mitre_id", "")}
                         for f in findings[:15]],
    }

    prompt = (
        "Analyze these AD security assessment results and provide:\n"
        "1. Executive summary (2-3 sentences)\n"
        "2. Top 3 most dangerous attack paths with step-by-step explanation\n"
        "3. Priority remediation recommendations\n\n"
        f"Assessment data: {json.dumps(summary)}"
    )
    return _llm_reason(prompt)


# ── Deterministic Reasoning Engine (fallback when no LLM) ────────────

def _deterministic_plan(discovery_results: dict, findings: list) -> list:
    """Rule-based tool prioritization when LLM is unavailable."""
    priority = []

    # If SPNs found → Kerberos analysis is critical
    if discovery_results.get("spns", 0) > 0 or \
       any("Kerberoast" in f.get("title", "") or "AS-REP" in f.get("title", "") for f in findings):
        priority.append("analyze_kerberos")

    # If ports 389/636 open → LDAP analysis
    ports = discovery_results.get("domain_info", {}).get("dc_ports", [])
    if 389 in ports or 636 in ports:
        priority.append("analyze_ldap")

    # If port 445 open → SMB analysis
    if 445 in ports:
        priority.append("analyze_smb")

    # NTLM is always relevant
    priority.append("analyze_ntlm")

    # If DCs found → Password policy matters
    if discovery_results.get("dcs", 0) > 0:
        priority.append("analyze_passwords")

    # AD CS check
    priority.append("analyze_adcs")

    # ACL audit
    priority.append("analyze_acls")

    return priority


# ═══════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class ADSecurityOrchestrator:
    """
    Multi-agent AD security orchestrator with LLM reasoning layer.

    The LLM decides WHAT to do. The Python tools do the WORK.
    """

    def __init__(self, target_ip: str, domain: str = "",
                 username: str = "", password: str = "",
                 mode: str = "passive", log_fn: Callable = None):
        self.target_ip = target_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.mode = mode
        self._log_fn = log_fn
        self._start_time = None
        self.tools_invoked = []
        self.all_findings = []
        self.assessment_id = ""

    def _log(self, msg):
        if self._log_fn:
            self._log_fn(msg)

    def _invoke_tool(self, tool_fn, tool_name: str, **kwargs) -> dict:
        """Invoke a deterministic tool. Log evidence."""
        start = time.time()
        self._log(f"  ▶ {tool_name}")
        try:
            result = tool_fn(**kwargs)
            elapsed = time.time() - start
            status = result.get("status", "?")
            finding_count = len(result.get("findings", []))
            self.tools_invoked.append({
                "tool": tool_name, "status": status,
                "findings": finding_count,
                "duration": round(elapsed, 2),
            })
            # Collect findings with source attribution
            for f in result.get("findings", []):
                f["source_tool"] = tool_name
                self.all_findings.append(f)
            # Log evidence
            try:
                from ..evidence.evidence_store import log_evidence
                eid = log_evidence(self.assessment_id, tool_name,
                                   self.target_ip, result.get("raw_output", "")[:5000])
                result.setdefault("evidence_ids", []).append(eid)
            except Exception:
                pass
            return result
        except Exception as e:
            self._log(f"    ⚠ {tool_name}: {e}")
            self.tools_invoked.append({
                "tool": tool_name, "status": "error",
                "findings": 0, "duration": round(time.time() - start, 2),
            })
            return {"tool": tool_name, "status": "error", "findings": [], "data": {}}

    def run_full_assessment(self) -> dict:
        """
        Execute full AD security assessment with reasoning loop.

        PLAN → DISCOVER → ANALYZE (adaptive) → CORRELATE → SCORE → REPORT
        """
        self._start_time = time.time()

        self._log(f"\n{'━'*60}")
        self._log(f"  🏢 AD SECURITY AI — ENTERPRISE ASSESSMENT")
        self._log(f"  Target: {self.target_ip}")
        self._log(f"  Domain: {self.domain or 'Auto-detect'}")
        self._log(f"  Mode:   {self.mode.upper()}")
        self._log(f"  LLM:    {'Active ✓' if _LLM_AVAILABLE else 'Deterministic rules'}")
        self._log(f"{'━'*60}")

        # ── Initialize evidence store ────────────────────────────────
        try:
            from ..evidence.evidence_store import create_assessment, complete_assessment, save_finding as ev_save
            self.assessment_id = create_assessment(
                org="Assessment", domain=self.domain or self.target_ip,
                scope=self.target_ip, mode=self.mode
            )
            self._log(f"  📋 Assessment: {self.assessment_id}")
        except Exception as e:
            self._log(f"  ⚠ Evidence store: {e}")
            self.assessment_id = f"AD-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # ── Initialize scope engine ──────────────────────────────────
        scope = None
        try:
            from ..gateway.scope_engine import create_scope
            scope = create_scope(self.assessment_id, ips=[self.target_ip], mode=self.mode)
            self._log(f"  🔒 Scope: {self.mode} mode, target {self.target_ip}")
        except Exception:
            pass

        creds = {"target_ip": self.target_ip, "username": self.username,
                 "password": self.password, "domain": self.domain,
                 "log_fn": self._log_fn}

        # ═════════════════════════════════════════════════════════════
        # PHASE 1: DISCOVERY (always runs all 8 tools)
        # ═════════════════════════════════════════════════════════════
        self._log(f"\n{'═'*60}")
        self._log(f"  📡 PHASE 1: DISCOVERY")
        self._log(f"{'═'*60}")

        from ..discovery.discovery_tools import (
            discover_domain, enumerate_users, enumerate_groups,
            enumerate_computers, enumerate_dcs, enumerate_gpos,
            enumerate_trusts, enumerate_spns
        )

        domain_result = self._invoke_tool(discover_domain, "discover_domain", **creds)
        users_result = self._invoke_tool(enumerate_users, "enumerate_users", **creds)
        groups_result = self._invoke_tool(enumerate_groups, "enumerate_groups", **creds)
        computers_result = self._invoke_tool(enumerate_computers, "enumerate_computers", **creds)
        dcs_result = self._invoke_tool(enumerate_dcs, "enumerate_dcs", **creds)
        gpos_result = self._invoke_tool(enumerate_gpos, "enumerate_gpos", **creds)
        trusts_result = self._invoke_tool(enumerate_trusts, "enumerate_trusts", **creds)
        spns_result = self._invoke_tool(enumerate_spns, "enumerate_spns", **creds)

        discovery_summary = {
            "domain_info": domain_result.get("data", {}),
            "users": users_result.get("data", {}).get("total", 0),
            "groups": len(groups_result.get("data", {}).get("groups", [])),
            "computers": len(computers_result.get("data", {}).get("computers", [])),
            "dcs": len(dcs_result.get("data", {}).get("dcs", [])),
            "gpos": len(gpos_result.get("data", {}).get("gpos", [])),
            "trusts": len(trusts_result.get("data", {}).get("trusts", [])),
            "spns": len(spns_result.get("data", {}).get("spns", [])),
        }

        self._log(f"\n  📊 Discovery: {discovery_summary['users']} users, "
                  f"{discovery_summary['spns']} SPNs, {discovery_summary['dcs']} DCs")

        # ═════════════════════════════════════════════════════════════
        # PHASE 2: ADAPTIVE ANALYSIS (LLM or deterministic planning)
        # ═════════════════════════════════════════════════════════════
        self._log(f"\n{'═'*60}")
        self._log(f"  🔍 PHASE 2: ADAPTIVE ANALYSIS")
        self._log(f"{'═'*60}")

        from ..analysis.analysis_tools import (
            analyze_kerberos, analyze_ldap, analyze_smb,
            analyze_ntlm, analyze_adcs, analyze_acls, analyze_passwords
        )

        tool_map = {
            "analyze_kerberos": (analyze_kerberos, {**creds, "discovery_data": users_result.get("data")}),
            "analyze_ldap": (analyze_ldap, creds),
            "analyze_smb": (analyze_smb, {"target_ip": self.target_ip, "log_fn": self._log_fn}),
            "analyze_ntlm": (analyze_ntlm, {"target_ip": self.target_ip, "log_fn": self._log_fn}),
            "analyze_adcs": (analyze_adcs, creds),
            "analyze_acls": (analyze_acls, {**creds, "discovery_data": users_result.get("data")}),
            "analyze_passwords": (analyze_passwords, creds),
        }

        # Ask the LLM (or deterministic engine) to prioritize
        if _LLM_AVAILABLE:
            self._log(f"  🧠 LLM planning analysis priority...")
            priority_tools = _llm_plan_next_tools(discovery_summary, self.all_findings)
            if not priority_tools:
                priority_tools = list(tool_map.keys())
            self._log(f"  🧠 LLM priority: {' → '.join(priority_tools)}")
        else:
            priority_tools = _deterministic_plan(discovery_summary, self.all_findings)
            self._log(f"  ⚙ Deterministic priority: {' → '.join(priority_tools)}")

        # Ensure all tools run (append any missing)
        for t in tool_map:
            if t not in priority_tools:
                priority_tools.append(t)

        # Execute in priority order
        for tool_name in priority_tools:
            if tool_name in tool_map:
                fn, params = tool_map[tool_name]
                # Scope check
                if scope:
                    check = scope.validate_action(tool_name, self.target_ip)
                    if not check["authorized"]:
                        self._log(f"    🚫 {tool_name}: {check['reason']}")
                        continue
                self._invoke_tool(fn, tool_name, **params)

        self._log(f"\n  📊 Analysis: {len(self.all_findings)} total findings")

        # ═════════════════════════════════════════════════════════════
        # PHASE 3: GAP ANALYSIS (LLM reasoning on what's missing)
        # ═════════════════════════════════════════════════════════════
        if _LLM_AVAILABLE and len(self.all_findings) > 0:
            self._log(f"\n{'═'*60}")
            self._log(f"  🧠 PHASE 3: LLM GAP ANALYSIS")
            self._log(f"{'═'*60}")

            gap_analysis = _llm_reason(
                "Based on these AD findings, what critical security aspects "
                "might we have missed? What additional evidence should be collected?",
                json.dumps([{"title": f["title"], "severity": f["severity"],
                             "category": f.get("category", "")}
                            for f in self.all_findings[:20]])
            )
            if gap_analysis:
                self._log(f"  🧠 Gap analysis: {gap_analysis[:200]}...")

        # ═════════════════════════════════════════════════════════════
        # PHASE 4: CORRELATION (deterministic + LLM narrative)
        # ═════════════════════════════════════════════════════════════
        self._log(f"\n{'═'*60}")
        self._log(f"  🔗 PHASE 4: RISK CORRELATION")
        self._log(f"{'═'*60}")

        from ..correlation.correlation_engine import (
            build_attack_paths, correlate_risks, calculate_exposure
        )

        # Deterministic correlation (always runs)
        paths_result = build_attack_paths(self.all_findings,
                                          discovery_data=users_result.get("data"),
                                          log_fn=self._log_fn)
        correlation_result = correlate_risks(self.all_findings, log_fn=self._log_fn)
        exposure_result = calculate_exposure(
            self.all_findings,
            correlations=correlation_result.get("correlations", []),
            attack_paths=paths_result.get("paths", []),
            log_fn=self._log_fn
        )

        # LLM narrative correlation (optional enhancement)
        ai_narrative = ""
        if _LLM_AVAILABLE and self.all_findings:
            self._log(f"  🧠 LLM generating attack narrative...")
            ai_narrative = _llm_correlate_findings(
                self.all_findings, paths_result.get("paths", [])
            )
            if ai_narrative:
                self._log(f"  🧠 AI Narrative: {ai_narrative[:200]}...")

        # ═════════════════════════════════════════════════════════════
        # PHASE 5: EVIDENCE PERSISTENCE
        # ═════════════════════════════════════════════════════════════
        try:
            from ..evidence.evidence_store import save_finding as ev_save, complete_assessment
            for f in self.all_findings:
                ev_save(self.assessment_id, f.get("title", ""),
                        f.get("severity", "Medium"), f.get("description", ""),
                        f.get("affected_object", ""), [],
                        f.get("mitre_id", ""), f.get("nist_csf", ""),
                        f.get("cis_control", ""), 0.0,
                        f.get("confidence", 0.8), f.get("category", "AD"),
                        f.get("remediation", ""))
            complete_assessment(self.assessment_id,
                                exposure_result.get("total_score", 0))
        except Exception as e:
            self._log(f"  ⚠ Evidence persistence: {e}")

        # ═════════════════════════════════════════════════════════════
        # FINAL REPORT
        # ═════════════════════════════════════════════════════════════
        duration = round(time.time() - self._start_time, 1)
        sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.all_findings:
            s = f.get("severity", "Low")
            if s in sev:
                sev[s] += 1

        score = exposure_result.get("total_score", 0)
        label = exposure_result.get("risk_label", "?")

        self._log(f"\n{'━'*60}")
        self._log(f"  📊 AD SECURITY ASSESSMENT COMPLETE")
        self._log(f"{'━'*60}")
        self._log(f"  Assessment:   {self.assessment_id}")
        self._log(f"  Duration:     {duration}s")
        self._log(f"  Tools Run:    {len(self.tools_invoked)}")
        self._log(f"  Findings:     {len(self.all_findings)}")
        self._log(f"    Critical:   {sev['Critical']}")
        self._log(f"    High:       {sev['High']}")
        self._log(f"    Medium:     {sev['Medium']}")
        self._log(f"    Low:        {sev['Low']}")
        self._log(f"  Attack Paths: {paths_result.get('total_paths', 0)}")
        self._log(f"  Correlations: {len(correlation_result.get('correlations', []))}")
        self._log(f"  Score:        {score}/100 ({label})")
        self._log(f"  LLM:          {'Active' if _LLM_AVAILABLE else 'Deterministic'}")
        self._log(f"  Evidence DB:  {'Postgres' if _USE_PG else 'SQLite'}")
        self._log(f"{'━'*60}")

        # ═════════════════════════════════════════════════════════════
        # PHASE 6: PDF REPORT GENERATION
        # ═════════════════════════════════════════════════════════════
        report_path = ""
        try:
            from ..reporting.report_generator import generate_report
            result_data = {
                "assessment_id": self.assessment_id,
                "target": self.target_ip,
                "domain": self.domain,
                "findings": self.all_findings,
                "correlations": correlation_result.get("correlations", []),
                "attack_paths": paths_result.get("paths", []),
                "exposure_score": exposure_result,
                "discovery": discovery_summary,
                "tools_invoked": self.tools_invoked,
                "ai_narrative": ai_narrative,
                "duration_seconds": duration,
            }
            report_path = generate_report(result_data, log_fn=self._log_fn)
            self._log(f"  📄 PDF Report: {report_path}")
        except Exception as e:
            self._log(f"  ⚠ PDF report generation: {e}")

        return {
            "assessment_id": self.assessment_id,
            "target": self.target_ip,
            "domain": self.domain,
            "status": "complete",
            "phases_completed": ["discovery", "analysis", "correlation", "scoring", "reporting"],
            "discovery": discovery_summary,
            "findings": self.all_findings,
            "correlations": correlation_result.get("correlations", []),
            "attack_paths": paths_result.get("paths", []),
            "exposure_score": exposure_result,
            "tools_invoked": self.tools_invoked,
            "ai_narrative": ai_narrative,
            "report_path": report_path,
            "duration_seconds": duration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ── Public API ───────────────────────────────────────────────────────

def run_ad_security_assessment(target_ip: str, domain: str = "",
                               username: str = "", password: str = "",
                               mode: str = "passive",
                               log_fn: Callable = None) -> dict:
    """Run a full AD security assessment. Main entry point."""
    orchestrator = ADSecurityOrchestrator(
        target_ip, domain=domain, username=username,
        password=password, mode=mode, log_fn=log_fn
    )
    return orchestrator.run_full_assessment()
