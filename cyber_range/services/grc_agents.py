# ================================================================
# grc_agents.py  —  AI Agent Orchestrator for GRC
#
# 5 Specialized Agents + LangGraph Workflow:
#   Vulnerability → Control Mapping → POA&M → Risk Score
#
# Usage:
#   from cyber_range.services.grc_agents import run_grc_pipeline
#   result = run_grc_pipeline(system_id=1)
#
#   from cyber_range.services.grc_agents import compliance_chat
#   answer = compliance_chat("Explain AC-2 implementation")
# ================================================================

import os
import json
import logging
from datetime import date, datetime, timedelta
from typing import TypedDict, Annotated

log = logging.getLogger(__name__)

# ── LLM Setup ────────────────────────────────────────────────────
_OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")


def _call_llm(prompt: str, max_tokens: int = 800) -> str:
    """Call GPT-4o-mini via OpenAI SDK."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=_OPENAI_KEY)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        log.error(f"[GRC Agent] LLM error: {e}")
        return f"LLM Error: {e}"


# ── Data Helpers ─────────────────────────────────────────────────
def _get_neo4j_vulns() -> list[dict]:
    """Pull vulnerability data from Neo4j."""
    try:
        from neo4j import GraphDatabase
        pw = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
        with driver.session() as s:
            result = s.run("""
                MATCH (h:Host)-[:RUNS_SERVICE]->(svc:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN h.ip AS host, svc.name AS service, svc.port AS port,
                       v.cve AS cve, v.cvss AS cvss, v.source AS source
                LIMIT 200
            """)
            vulns = [dict(r) for r in result]
        driver.close()

        if not vulns:
            # Fallback: findings
            driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
            with driver.session() as s:
                result = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(svc:Service)-[:HAS_FINDING]->(f:Finding)
                    RETURN h.ip AS host, svc.name AS service, svc.port AS port,
                           f.name AS cve, coalesce(f.cvss, 5.0) AS cvss, f.source AS source,
                           f.severity AS severity
                    LIMIT 200
                """)
                vulns = [dict(r) for r in result]
            driver.close()
        return vulns
    except Exception as e:
        log.error(f"[Asset Agent] Neo4j error: {e}")
        return []


def _get_pg_controls() -> list[dict]:
    """Pull NIST controls from PostgreSQL."""
    try:
        from cyber_range.services.pg_engine import pg_execute
        return pg_execute("SELECT control_id, family, family_name, title, baseline_mod FROM controls ORDER BY control_id")
    except Exception:
        return []


def _cvss_to_risk(cvss) -> str:
    try:
        c = float(cvss or 0)
    except (ValueError, TypeError):
        c = 0
    if c >= 9.0: return "Critical"
    if c >= 7.0: return "High"
    if c >= 4.0: return "Medium"
    return "Low"


def _risk_due_days(level: str) -> int:
    return {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}.get(level, 90)


# ── NIST Keyword Map ─────────────────────────────────────────────
_NIST_MAP = {
    "tls": "SC-8", "ssl": "SC-8", "certificate": "SC-8",
    "cve": "RA-5", "vulnerability": "RA-5", "exploit": "RA-5",
    "patch": "SI-2", "update": "SI-2", "outdated": "SI-2",
    "password": "IA-5", "credential": "IA-5", "authentication": "IA-2",
    "access": "AC-6", "privilege": "AC-6", "admin": "AC-2",
    "log": "AU-6", "audit": "AU-6", "monitor": "AU-6",
    "firewall": "SC-7", "port": "SC-7", "boundary": "SC-7",
    "encrypt": "SC-28", "crypto": "SC-12",
    "config": "CM-6", "baseline": "CM-2", "misconfigur": "CM-6",
    "malware": "SI-3", "virus": "SI-3",
    "incident": "IR-4", "intrusion": "IR-4",
    "injection": "SI-10", "sql": "SI-10", "xss": "SI-10",
    "remote": "AC-17", "ssh": "AC-17", "rdp": "AC-17",
    "ftp": "CM-7", "snmp": "CM-7", "smb": "CM-7",
    "backup": "CP-9", "recovery": "CP-9",
}


# ================================================================
# AGENT 1: Asset Agent
# ================================================================
def asset_agent(state: dict) -> dict:
    """
    Discovers assets from Neo4j graph.
    Returns: list of unique hosts with their services.
    """
    log.info("[Asset Agent] Discovering assets from Neo4j...")
    vulns = _get_neo4j_vulns()

    assets = {}
    for v in vulns:
        host = v.get("host", "unknown")
        if host not in assets:
            assets[host] = {"host": host, "services": [], "vuln_count": 0}
        svc = f"{v.get('service', '?')}:{v.get('port', '?')}"
        if svc not in assets[host]["services"]:
            assets[host]["services"].append(svc)
        assets[host]["vuln_count"] += 1

    state["assets"] = list(assets.values())
    state["raw_vulns"] = vulns
    state["status"] = f"Asset Agent: found {len(assets)} hosts, {len(vulns)} vulnerabilities"
    log.info(f"[Asset Agent] ✅ {len(assets)} hosts, {len(vulns)} vulns")
    return state


# ================================================================
# AGENT 2: Vulnerability Agent
# ================================================================
def vulnerability_agent(state: dict) -> dict:
    """
    Enriches vulnerability data with risk levels and deduplication.
    """
    log.info("[Vulnerability Agent] Enriching vulnerabilities...")
    vulns = state.get("raw_vulns", [])

    enriched = []
    seen = set()
    for v in vulns:
        cve = v.get("cve", "") or ""
        host = v.get("host", "unknown")
        key = f"{cve}:{host}" if cve else f"{v.get('service', '')}:{host}:{len(enriched)}"
        if key in seen:
            continue
        seen.add(key)

        cvss = v.get("cvss", 5.0)
        risk = _cvss_to_risk(cvss)
        enriched.append({
            "cve": cve,
            "host": host,
            "service": v.get("service", "unknown"),
            "port": v.get("port", ""),
            "cvss": cvss,
            "risk_level": risk,
            "source": v.get("source", ""),
            "severity": v.get("severity", risk),
        })

    # Sort by CVSS descending
    enriched.sort(key=lambda x: float(x.get("cvss", 0) or 0), reverse=True)

    state["vulnerabilities"] = enriched
    state["status"] = f"Vulnerability Agent: enriched {len(enriched)} unique vulnerabilities"
    log.info(f"[Vulnerability Agent] ✅ {len(enriched)} unique vulns enriched")
    return state


# ================================================================
# AGENT 3: Compliance Mapping Agent
# ================================================================
def compliance_mapping_agent(state: dict) -> dict:
    """
    Maps vulnerabilities to NIST 800-53 controls.
    Uses keyword matching + AI for ambiguous cases.
    """
    log.info("[Compliance Agent] Mapping vulns to NIST controls...")
    vulns = state.get("vulnerabilities", [])
    controls = _get_pg_controls()
    control_titles = {c["control_id"]: c["title"] for c in controls} if controls else {}

    mapped = []
    ai_batch = []

    for v in vulns:
        text = f"{v.get('cve', '')} {v.get('service', '')} {v.get('source', '')}".lower()
        ctrl = "RA-5"  # default
        for kw, nist in _NIST_MAP.items():
            if kw in text:
                ctrl = nist
                break

        v["nist_control"] = ctrl
        v["control_title"] = control_titles.get(ctrl, ctrl)
        mapped.append(v)

        # Queue top 10 for AI-enhanced mapping
        if len(ai_batch) < 10 and v.get("cve"):
            ai_batch.append(v)

    # AI-enhanced mapping for top items
    if ai_batch:
        try:
            batch_text = "\n".join(
                f"{i+1}. {v['cve']} on {v['host']}:{v.get('port', '')} ({v.get('service', '')})"
                for i, v in enumerate(ai_batch)
            )
            prompt = f"""Map each vulnerability to the most relevant NIST 800-53 control.
Return ONLY the control IDs, one per line, numbered to match:

{batch_text}"""
            resp = _call_llm(prompt, 300)
            lines = [l.strip() for l in resp.strip().split("\n") if l.strip()]
            for i, line in enumerate(lines[:len(ai_batch)]):
                # Extract control ID from response
                import re
                match = re.search(r'([A-Z]{2}-\d+)', line)
                if match:
                    ctrl_id = match.group(1)
                    ai_batch[i]["nist_control"] = ctrl_id
                    ai_batch[i]["control_title"] = control_titles.get(ctrl_id, ctrl_id)
        except Exception as e:
            log.warning(f"[Compliance Agent] AI mapping failed: {e}")

    state["mapped_vulns"] = mapped
    families = {}
    for v in mapped:
        fam = v["nist_control"].split("-")[0]
        families[fam] = families.get(fam, 0) + 1

    state["control_families_hit"] = families
    state["status"] = f"Compliance Agent: mapped {len(mapped)} vulns to {len(families)} NIST families"
    log.info(f"[Compliance Agent] ✅ {len(mapped)} mappings, {len(families)} families")
    return state


# ================================================================
# AGENT 4: POA&M Agent
# ================================================================
def poam_agent(state: dict) -> dict:
    """
    Generates POA&M items from mapped vulnerabilities.
    Uses AI for remediation plans on top items.
    """
    log.info("[POA&M Agent] Generating POA&M items...")
    vulns = state.get("mapped_vulns", [])
    today = date.today()

    poam_items = []
    for i, v in enumerate(vulns):
        risk = v.get("risk_level", "Medium")
        due = today + timedelta(days=_risk_due_days(risk))
        poam_items.append({
            "poam_id": f"POAM-{i+1:04d}",
            "weakness": v.get("cve") or f"{v.get('service', 'unknown')} finding",
            "host": v.get("host", ""),
            "service": v.get("service", ""),
            "nist_control": v.get("nist_control", "RA-5"),
            "control_title": v.get("control_title", ""),
            "cvss": v.get("cvss", 0),
            "risk_level": risk,
            "status": "Open",
            "due_date": due.isoformat(),
            "source": v.get("source", ""),
            "remediation": "",
            "milestones": "",
        })

    # AI remediation for top 10
    top_items = [p for p in poam_items if p["risk_level"] in ("Critical", "High")][:10]
    if top_items:
        try:
            batch = "\n".join(
                f"{i+1}. {p['weakness']} on {p['host']} (Control: {p['nist_control']})"
                for i, p in enumerate(top_items)
            )
            prompt = f"""For each vulnerability below, provide:
- One-line remediation action
- 3 milestone steps

Format each as:
N. REMEDIATION: <action>
   M1: <step1> | M2: <step2> | M3: <step3>

{batch}"""
            resp = _call_llm(prompt, 1200)
            lines = resp.strip().split("\n")
            idx = 0
            for line in lines:
                line = line.strip()
                if "REMEDIATION:" in line and idx < len(top_items):
                    top_items[idx]["remediation"] = line.split("REMEDIATION:")[-1].strip()
                elif line.startswith("M1:") or "M1:" in line:
                    if idx < len(top_items):
                        top_items[idx]["milestones"] = line.strip()
                    idx += 1
        except Exception as e:
            log.warning(f"[POA&M Agent] AI remediation failed: {e}")

    # Fallback for items without remediation
    for p in poam_items:
        if not p["remediation"]:
            p["remediation"] = f"Remediate {p['weakness']} per {p['nist_control']} guidance"
            p["milestones"] = "M1: Assess impact | M2: Apply fix | M3: Verify and document"

    state["poam_items"] = poam_items
    state["status"] = f"POA&M Agent: generated {len(poam_items)} items ({len(top_items)} AI-enhanced)"
    log.info(f"[POA&M Agent] ✅ {len(poam_items)} POA&M items")
    return state


# ================================================================
# AGENT 5: Risk Agent
# ================================================================
def risk_agent(state: dict) -> dict:
    """
    Calculates risk scores and generates risk register entries.
    Produces compliance score and risk heatmap data.
    """
    log.info("[Risk Agent] Computing risk scores...")
    poam_items = state.get("poam_items", [])
    vulns = state.get("mapped_vulns", [])

    # Risk register entries
    risks = []
    seen_risks = set()
    for v in vulns:
        ctrl = v.get("nist_control", "RA-5")
        risk_key = f"{ctrl}:{v.get('host', '')}"
        if risk_key in seen_risks:
            continue
        seen_risks.add(risk_key)

        cvss = float(v.get("cvss", 0) or 0)
        # Map CVSS to likelihood (1-5) and impact (1-5)
        if cvss >= 9.0:
            likelihood, impact = 5, 5
        elif cvss >= 7.0:
            likelihood, impact = 4, 4
        elif cvss >= 4.0:
            likelihood, impact = 3, 3
        else:
            likelihood, impact = 2, 2

        risk_score = likelihood * impact
        if risk_score >= 20:    risk_level = "Critical"
        elif risk_score >= 12:  risk_level = "High"
        elif risk_score >= 6:   risk_level = "Medium"
        else:                   risk_level = "Low"

        risks.append({
            "risk_id": f"RISK-{len(risks)+1:04d}",
            "title": f"Unmitigated {v.get('risk_level', 'Medium')} vulnerability on {v.get('host', '?')}",
            "control": ctrl,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "host": v.get("host", ""),
            "cve": v.get("cve", ""),
        })

    # Summary statistics
    total_vulns = len(vulns)
    critical = sum(1 for v in vulns if v.get("risk_level") == "Critical")
    high = sum(1 for v in vulns if v.get("risk_level") == "High")
    open_poams = sum(1 for p in poam_items if p.get("status") == "Open")
    overdue = sum(1 for p in poam_items if p.get("due_date") and p["due_date"] < date.today().isoformat() and p.get("status") != "Closed")

    # Heatmap data (5x5 grid)
    heatmap = [[0]*5 for _ in range(5)]
    for r in risks:
        li = min(r["likelihood"]-1, 4)
        im = min(r["impact"]-1, 4)
        heatmap[li][im] += 1

    # Compliance score (based on control coverage)
    families_hit = state.get("control_families_hit", {})
    total_families = 20  # NIST 800-53 Rev 5
    coverage = round(len(families_hit) / total_families * 100, 1) if families_hit else 0

    state["risks"] = risks
    state["risk_heatmap"] = heatmap
    state["summary"] = {
        "total_vulnerabilities": total_vulns,
        "critical": critical,
        "high": high,
        "total_poams": len(poam_items),
        "open_poams": open_poams,
        "overdue_poams": overdue,
        "total_risks": len(risks),
        "compliance_coverage": coverage,
        "families_assessed": len(families_hit),
        "timestamp": datetime.now().isoformat(),
    }
    state["status"] = f"Risk Agent: {len(risks)} risks, compliance coverage {coverage}%"
    log.info(f"[Risk Agent] ✅ {len(risks)} risks, {coverage}% compliance coverage")
    return state


# ================================================================
# LangGraph Workflow Orchestrator
# ================================================================
def run_grc_pipeline(system_id: int = 1) -> dict:
    """
    Execute the full GRC agent pipeline:
    Asset → Vulnerability → Compliance Mapping → POA&M → Risk Score

    Uses LangGraph if available, falls back to sequential execution.
    """
    log.info(f"[GRC Pipeline] Starting for system_id={system_id}")
    state = {"system_id": system_id, "status": "Starting pipeline..."}

    try:
        from langgraph.graph import StateGraph, END

        class GrcState(TypedDict):
            system_id: int
            status: str
            assets: list
            raw_vulns: list
            vulnerabilities: list
            mapped_vulns: list
            control_families_hit: dict
            poam_items: list
            risks: list
            risk_heatmap: list
            summary: dict

        # Build the graph
        builder = StateGraph(GrcState)
        builder.add_node("asset_agent", asset_agent)
        builder.add_node("vulnerability_agent", vulnerability_agent)
        builder.add_node("compliance_mapping_agent", compliance_mapping_agent)
        builder.add_node("poam_agent", poam_agent)
        builder.add_node("risk_agent", risk_agent)

        builder.set_entry_point("asset_agent")
        builder.add_edge("asset_agent", "vulnerability_agent")
        builder.add_edge("vulnerability_agent", "compliance_mapping_agent")
        builder.add_edge("compliance_mapping_agent", "poam_agent")
        builder.add_edge("poam_agent", "risk_agent")
        builder.add_edge("risk_agent", END)

        graph = builder.compile()

        # Initialize state
        init_state: GrcState = {
            "system_id": system_id,
            "status": "Starting...",
            "assets": [],
            "raw_vulns": [],
            "vulnerabilities": [],
            "mapped_vulns": [],
            "control_families_hit": {},
            "poam_items": [],
            "risks": [],
            "risk_heatmap": [],
            "summary": {},
        }

        result = graph.invoke(init_state)
        log.info("[GRC Pipeline] ✅ Complete via LangGraph")
        return result

    except ImportError:
        log.warning("[GRC Pipeline] LangGraph not available — running sequentially")
        state = asset_agent(state)
        state = vulnerability_agent(state)
        state = compliance_mapping_agent(state)
        state = poam_agent(state)
        state = risk_agent(state)
        log.info("[GRC Pipeline] ✅ Complete (sequential fallback)")
        return state
    except Exception as e:
        log.error(f"[GRC Pipeline] Error: {e}")
        import traceback
        traceback.print_exc()
        # Still try sequential
        state = asset_agent(state)
        state = vulnerability_agent(state)
        state = compliance_mapping_agent(state)
        state = poam_agent(state)
        state = risk_agent(state)
        return state


# ================================================================
# AI Compliance Assistant (Step 12)
# ================================================================

_COMPLIANCE_SYSTEM_PROMPT = """You are an expert AI Compliance Assistant for a Federal GRC (Governance, Risk, and Compliance) platform.

You have deep knowledge of:
- NIST 800-53 Rev 5 (all 20 control families, 1000+ controls)
- FedRAMP (Low, Moderate, High baselines)
- DISA STIGs (Security Technical Implementation Guides)
- FIPS 199/200 (security categorization)
- RMF (Risk Management Framework) lifecycle
- POA&M (Plan of Action & Milestones) processes
- SSP (System Security Plan) development

When answering questions:
1. Be specific and cite exact control IDs (e.g., AC-2, IA-5(1))
2. Provide actionable guidance, not just theory
3. Include implementation examples when relevant
4. Reference FedRAMP requirements when applicable
5. Suggest evidence artifacts needed for compliance
6. Use professional GRC terminology

Format responses with clear headers, bullet points, and control references."""


def compliance_chat(user_message: str, context: dict = None) -> str:
    """
    AI Compliance Assistant chat.
    Answers questions about NIST, FedRAMP, STIGs, and GRC processes.

    Args:
        user_message: User's question
        context: Optional dict with system_id, recent_vulns, etc.
    """
    # Build context-aware prompt
    ctx_parts = []
    if context:
        if context.get("system_name"):
            ctx_parts.append(f"Current system: {context['system_name']}")
        if context.get("impact_level"):
            ctx_parts.append(f"Impact level: {context['impact_level']}")
        if context.get("recent_vulns"):
            ctx_parts.append(f"Recent vulnerabilities: {len(context['recent_vulns'])}")

    ctx_str = "\n".join(ctx_parts) if ctx_parts else "No specific system context."

    prompt = f"""{_COMPLIANCE_SYSTEM_PROMPT}

CURRENT CONTEXT:
{ctx_str}

USER QUESTION:
{user_message}

Provide a thorough, actionable response:"""

    return _call_llm(prompt, max_tokens=1200)


def explain_vulnerability(cve_or_title: str) -> str:
    """Explain a vulnerability and its compliance implications."""
    return compliance_chat(
        f"Explain this vulnerability in detail and its compliance implications: {cve_or_title}. "
        f"Include: 1) What it is, 2) NIST 800-53 controls it violates, 3) FedRAMP impact, "
        f"4) Remediation steps, 5) Required evidence artifacts."
    )


def generate_implementation_statement(control_id: str) -> str:
    """Generate an implementation statement for a NIST control."""
    return compliance_chat(
        f"Generate a complete implementation statement for NIST 800-53 control {control_id}. "
        f"Include: 1) Control description, 2) Implementation narrative for a Federal system, "
        f"3) Responsible party, 4) Implementation status assessment, 5) Evidence artifacts needed. "
        f"Format as an official SSP implementation statement."
    )


def get_evidence_requirements(control_id: str) -> str:
    """List required evidence artifacts for a control."""
    return compliance_chat(
        f"What evidence artifacts are required for NIST 800-53 control {control_id}? "
        f"List each artifact with: 1) Name, 2) Description, 3) Format (PDF/screenshot/log/etc), "
        f"4) How often it must be updated, 5) FedRAMP-specific requirements if any."
    )
