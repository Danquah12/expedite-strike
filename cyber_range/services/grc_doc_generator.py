# ================================================================
# grc_doc_generator.py — Automated GRC Documentation Engine
#
# Generates:
#   1. SSP  (System Security Plan)
#   2. SAR  (Security Assessment Report)
#   3. POA&M Report (Plan of Action & Milestones)
#   4. Risk Assessment
#   5. ATO Package  (Authority to Operate)
#
# Usage:
#   from cyber_range.services.grc_doc_generator import GrcDocGenerator
#   gen = GrcDocGenerator(system_id=1)
#   ssp  = gen.generate_ssp()
#   sar  = gen.generate_sar()
#   poam = gen.generate_poam_report()
#   risk = gen.generate_risk_assessment()
#   ato  = gen.generate_ato_package()
# ================================================================

import os
import json
import logging
from datetime import date, datetime

log = logging.getLogger(__name__)


def _call_llm(prompt: str, max_tokens: int = 1500) -> str:
    """Call GPT-4o-mini for document generation."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return resp.choices[0].message.content or ""
    except Exception as e:
        log.error(f"[DocGen] LLM error: {e}")
        return f"[AI content generation unavailable: {e}]"


def _get_system_info(system_id: int) -> dict:
    """Get system information from PostgreSQL."""
    try:
        from cyber_range.services.pg_engine import pg_execute
        rows = pg_execute("""
            SELECT s.*, o.name AS org_name, o.acronym AS org_acronym
            FROM systems s LEFT JOIN organizations o ON s.org_id = o.id
            WHERE s.id = %s
        """, (system_id,))
        return rows[0] if rows else {
            "name": "VulnIntel Platform", "acronym": "VINTEL",
            "impact_level": "Moderate", "system_type": "Major Application",
            "org_name": "Security Operations", "org_acronym": "SECOPS",
            "description": "Unified Vulnerability Intelligence Platform",
            "status": "Operational",
        }
    except Exception:
        return {
            "name": "VulnIntel Platform", "acronym": "VINTEL",
            "impact_level": "Moderate", "system_type": "Major Application",
            "org_name": "Security Operations", "org_acronym": "SECOPS",
        }


def _get_controls(system_id: int) -> list[dict]:
    """Get NIST controls from PostgreSQL."""
    try:
        from cyber_range.services.pg_engine import pg_execute
        return pg_execute("""
            SELECT c.control_id, c.family, c.family_name, c.title,
                   COALESCE(sc.status, 'Not Assessed') AS impl_status,
                   sc.implementation_notes
            FROM controls c
            LEFT JOIN system_controls sc ON sc.control_id = c.id AND sc.system_id = %s
            WHERE c.baseline_mod = TRUE
            ORDER BY c.control_id
        """, (system_id,))
    except Exception:
        return []


def _get_vulns(system_id: int = None) -> list[dict]:
    """Get vulnerabilities from PostgreSQL and/or Neo4j."""
    vulns = []
    # Try PostgreSQL first
    try:
        from cyber_range.services.pg_engine import pg_execute
        vulns = pg_execute("""
            SELECT * FROM grc_vulnerabilities
            WHERE status = 'Open'
            ORDER BY cvss DESC NULLS LAST LIMIT 100
        """)
    except Exception:
        pass

    # Fallback/supplement from Neo4j
    if not vulns:
        try:
            from neo4j import GraphDatabase
            pw = os.environ.get("NEO4J_PASSWORD", "Adomaa12@")
            driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", pw))
            with driver.session() as s:
                result = s.run("""
                    MATCH (h:Host)-[:RUNS_SERVICE]->(svc:Service)-[:HAS_FINDING]->(f:Finding)
                    RETURN h.ip AS host, svc.port AS port, f.name AS title,
                           f.severity AS severity, f.source AS source,
                           coalesce(f.cve, '') AS cve
                    ORDER BY f.severity DESC LIMIT 100
                """)
                vulns = [dict(r) for r in result]
            driver.close()
        except Exception:
            pass
    return vulns


def _get_poams(system_id: int = None) -> list[dict]:
    """Get POA&M items from PostgreSQL."""
    try:
        from cyber_range.services.pg_engine import pg_execute
        return pg_execute("""
            SELECT * FROM poam WHERE status != 'Closed'
            ORDER BY CASE risk_level WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                     WHEN 'Medium' THEN 3 ELSE 4 END, due_date ASC
        """)
    except Exception:
        return []


def _get_risks(system_id: int = None) -> list[dict]:
    """Get risk entries from PostgreSQL."""
    try:
        from cyber_range.services.pg_engine import pg_execute
        return pg_execute("SELECT * FROM risks WHERE status != 'Closed' ORDER BY risk_score DESC")
    except Exception:
        return []


# ================================================================
# Document Generator Class
# ================================================================
class GrcDocGenerator:
    """AI-powered GRC document generator."""

    def __init__(self, system_id: int = 1):
        self.system_id = system_id
        self.sys = _get_system_info(system_id)
        self.today = date.today().isoformat()
        self.sys_name = self.sys.get("name", "System")
        self.org_name = self.sys.get("org_name", "Organization")
        self.impact = self.sys.get("impact_level", "Moderate")

    # ── SSP (System Security Plan) ───────────────────────────────
    def generate_ssp(self) -> str:
        """Generate a complete System Security Plan."""
        controls = _get_controls(self.system_id)
        vulns = _get_vulns(self.system_id)

        # Group controls by family
        families = {}
        implemented = 0
        for c in controls:
            fam = c.get("family", "XX")
            families.setdefault(fam, []).append(c)
            if c.get("impl_status") == "Implemented":
                implemented += 1

        total = len(controls) or 1

        # Build control family summaries table
        fam_table = "| Family | Name | Total | Implemented | Status |\n|--------|------|-------|-------------|--------|\n"
        for fam, ctrls in sorted(families.items()):
            impl = sum(1 for c in ctrls if c.get("impl_status") == "Implemented")
            fam_name = ctrls[0].get("family_name", fam) if ctrls else fam
            pct = round(impl / len(ctrls) * 100) if ctrls else 0
            status = "✅" if pct >= 80 else ("⚠️" if pct >= 50 else "❌")
            fam_table += f"| {fam} | {fam_name} | {len(ctrls)} | {impl} | {status} {pct}% |\n"

        # AI-generated sections
        description = _call_llm(
            f"Write a 2-paragraph system description for an SSP for '{self.sys_name}', "
            f"a {self.sys.get('system_type', 'Major Application')} at the {self.impact} impact level. "
            f"Organization: {self.org_name}. This is a cybersecurity vulnerability intelligence platform.",
            400
        )

        boundary = _call_llm(
            f"Write the Authorization Boundary section for '{self.sys_name}' SSP. "
            f"Describe the boundary of a web-based security platform with: Neo4j graph DB, "
            f"PostgreSQL relational DB, Python/Dash web app, RESTful APIs, scanner integrations. "
            f"Impact level: {self.impact}.",
            400
        )

        return f"""# System Security Plan (SSP)
## {self.sys_name}

| Field | Value |
|-------|-------|
| **System Name** | {self.sys_name} |
| **System Acronym** | {self.sys.get('acronym', 'N/A')} |
| **Organization** | {self.org_name} |
| **Impact Level** | {self.impact} |
| **System Type** | {self.sys.get('system_type', 'Major Application')} |
| **Status** | {self.sys.get('status', 'Operational')} |
| **Date** | {self.today} |

---

## 1. System Description

{description}

## 2. Authorization Boundary

{boundary}

## 3. Control Implementation Summary

- **Total Controls (FedRAMP {self.impact}):** {total}
- **Implemented:** {implemented} ({round(implemented/total*100)}%)
- **Open Vulnerabilities:** {len(vulns)}

{fam_table}

## 4. Control Implementations

"""  + "\n".join(
            f"### {c['control_id']} — {c.get('title', '')}\n"
            f"- **Status:** {c.get('impl_status', 'Not Assessed')}\n"
            f"- **Notes:** {c.get('implementation_notes', 'No implementation notes recorded.')}\n"
            for c in controls[:50]
        ) + f"""

---

## 5. Open Vulnerabilities

| # | CVE/Title | Host | Severity | Source |
|---|-----------|------|----------|--------|
""" + "\n".join(
            f"| {i+1} | {v.get('cve') or v.get('title', 'N/A')} | {v.get('host', '?')} | {v.get('severity', '?')} | {v.get('source', '?')} |"
            for i, v in enumerate(vulns[:30])
        ) + f"""

---
*Generated by VulnIntel GRC Engine — {self.today}*
"""

    # ── SAR (Security Assessment Report) ─────────────────────────
    def generate_sar(self) -> str:
        """Generate a Security Assessment Report."""
        controls = _get_controls(self.system_id)
        vulns = _get_vulns(self.system_id)
        poams = _get_poams(self.system_id)

        total = len(controls) or 1
        implemented = sum(1 for c in controls if c.get("impl_status") == "Implemented")
        partial = sum(1 for c in controls if c.get("impl_status") == "Partially Implemented")
        not_impl = sum(1 for c in controls if c.get("impl_status") in ("Not Implemented", "Not Assessed"))

        # Severity breakdown
        sev_counts = {}
        for v in vulns:
            s = v.get("severity", "Medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        # AI executive summary
        exec_summary = _call_llm(
            f"Write a professional executive summary for a Security Assessment Report (SAR). "
            f"System: {self.sys_name}, Impact: {self.impact}, {total} controls assessed, "
            f"{implemented} implemented, {partial} partial, {not_impl} not implemented. "
            f"{len(vulns)} open vulnerabilities ({sev_counts.get('Critical', 0)} critical, "
            f"{sev_counts.get('High', 0)} high). {len(poams)} open POA&M items. "
            f"Provide an overall risk assessment and recommendation.",
            500
        )

        risk_rating = _call_llm(
            f"Based on {implemented}/{total} controls implemented, {sev_counts.get('Critical',0)} critical "
            f"and {sev_counts.get('High',0)} high vulns, provide a risk rating (Low/Moderate/High/Very High) "
            f"and 3 key findings and 3 recommendations. Format with headers.",
            500
        )

        return f"""# Security Assessment Report (SAR)
## {self.sys_name}

| Field | Value |
|-------|-------|
| **System** | {self.sys_name} ({self.sys.get('acronym', '')}) |
| **Organization** | {self.org_name} |
| **Impact Level** | {self.impact} |
| **Assessment Date** | {self.today} |
| **Assessor** | VulnIntel Automated Assessment Engine |

---

## 1. Executive Summary

{exec_summary}

## 2. Assessment Scope

- **Controls Assessed:** {total} (FedRAMP {self.impact} baseline)
- **Assessment Method:** Automated analysis of control implementations, vulnerability scans, and system configurations

## 3. Assessment Results

| Category | Count | Percentage |
|----------|-------|-----------|
| Implemented | {implemented} | {round(implemented/total*100)}% |
| Partially Implemented | {partial} | {round(partial/total*100)}% |
| Not Implemented | {not_impl} | {round(not_impl/total*100)}% |

### Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {sev_counts.get('Critical', 0)} |
| High | {sev_counts.get('High', 0)} |
| Medium | {sev_counts.get('Medium', 0)} |
| Low | {sev_counts.get('Low', 0)} |
| **Total Open** | **{len(vulns)}** |

### POA&M Summary
- **Open Items:** {len(poams)}
- **Critical/High:** {sum(1 for p in poams if p.get('risk_level') in ('Critical', 'High'))}

## 4. Risk Rating & Recommendations

{risk_rating}

---

## 5. Detailed Findings

""" + "\n".join(
            f"### Finding {i+1}: {v.get('cve') or v.get('title', 'N/A')}\n"
            f"- **Host:** {v.get('host', '?')}\n"
            f"- **Severity:** {v.get('severity', '?')}\n"
            f"- **Source:** {v.get('source', '?')}\n"
            for i, v in enumerate(vulns[:20])
        ) + f"""

---
*Generated by VulnIntel GRC Engine — {self.today}*
"""

    # ── POA&M Report ─────────────────────────────────────────────
    def generate_poam_report(self) -> str:
        """Generate a formatted POA&M report."""
        poams = _get_poams(self.system_id)
        vulns = _get_vulns(self.system_id)

        total = len(poams)
        critical = sum(1 for p in poams if p.get("risk_level") == "Critical")
        high = sum(1 for p in poams if p.get("risk_level") == "High")
        overdue = sum(
            1 for p in poams
            if p.get("due_date") and str(p["due_date"]) < self.today
        )

        poam_table = "| # | POAM ID | Weakness | Risk | CVSS | Status | Due Date | Remediation |\n"
        poam_table += "|---|---------|----------|------|------|--------|----------|-------------|\n"
        for i, p in enumerate(poams[:50]):
            poam_table += (
                f"| {i+1} | {p.get('poam_id', '?')} | {str(p.get('weakness', '?'))[:40]} | "
                f"{p.get('risk_level', '?')} | {p.get('cvss', '?')} | {p.get('status', '?')} | "
                f"{p.get('due_date', '?')} | {str(p.get('remediation', ''))[:50]} |\n"
            )

        return f"""# Plan of Action & Milestones (POA&M)
## {self.sys_name}

| Field | Value |
|-------|-------|
| **System** | {self.sys_name} |
| **Date** | {self.today} |
| **Total Items** | {total} |
| **Critical** | {critical} |
| **High** | {high} |
| **Overdue** | {overdue} |

---

## Summary

- **Total POA&M Items:** {total}
- **Critical Risk:** {critical}
- **High Risk:** {high}
- **Medium Risk:** {sum(1 for p in poams if p.get('risk_level') == 'Medium')}
- **Overdue Items:** {overdue}
- **Open Vulnerabilities:** {len(vulns)}

## POA&M Items

{poam_table}

---
*Generated by VulnIntel GRC Engine — {self.today}*
"""

    # ── Risk Assessment ──────────────────────────────────────────
    def generate_risk_assessment(self) -> str:
        """Generate a Risk Assessment report."""
        vulns = _get_vulns(self.system_id)
        risks = _get_risks(self.system_id)

        # Build risk matrix
        sev = {}
        for v in vulns:
            s = v.get("severity", "Medium")
            sev[s] = sev.get(s, 0) + 1

        ai_analysis = _call_llm(
            f"Write a risk analysis section for a Risk Assessment. System: {self.sys_name}, "
            f"Impact Level: {self.impact}. Vulnerabilities: {sev.get('Critical',0)} critical, "
            f"{sev.get('High',0)} high, {sev.get('Medium',0)} medium, {sev.get('Low',0)} low. "
            f"Total risks: {len(risks)}. Provide: 1) Overall risk posture, 2) Top risk factors, "
            f"3) Risk treatment recommendations, 4) Residual risk statement.",
            600
        )

        heatmap = """
## Risk Heatmap (Likelihood × Impact)

|  | Impact 1 | Impact 2 | Impact 3 | Impact 4 | Impact 5 |
|--|----------|----------|----------|----------|----------|
| **Likelihood 5** | 🟢 | 🟡 | 🟠 | 🔴 | 🔴 |
| **Likelihood 4** | 🟢 | 🟡 | 🟠 | 🟠 | 🔴 |
| **Likelihood 3** | 🟢 | 🟢 | 🟡 | 🟠 | 🟠 |
| **Likelihood 2** | 🟢 | 🟢 | 🟢 | 🟡 | 🟡 |
| **Likelihood 1** | 🟢 | 🟢 | 🟢 | 🟢 | 🟡 |
"""

        return f"""# Risk Assessment Report
## {self.sys_name}

| Field | Value |
|-------|-------|
| **System** | {self.sys_name} |
| **Organization** | {self.org_name} |
| **Impact Level** | {self.impact} |
| **Date** | {self.today} |

---

## 1. Vulnerability Summary

| Severity | Count | Risk Level |
|----------|-------|------------|
| Critical | {sev.get('Critical', 0)} | 🔴 Very High |
| High | {sev.get('High', 0)} | 🟠 High |
| Medium | {sev.get('Medium', 0)} | 🟡 Medium |
| Low | {sev.get('Low', 0)} | 🟢 Low |
| **Total** | **{len(vulns)}** | — |

{heatmap}

## 2. Risk Analysis

{ai_analysis}

## 3. Risk Register

| # | Risk ID | Title | L | I | Score | Level |
|---|---------|-------|---|---|-------|-------|
""" + "\n".join(
            f"| {i+1} | {r.get('risk_id', '?')} | {str(r.get('title', '?'))[:50]} | "
            f"{r.get('likelihood', '?')} | {r.get('impact', '?')} | {r.get('risk_score', '?')} | "
            f"{r.get('risk_level', '?')} |"
            for i, r in enumerate(risks[:30])
        ) + f"""

---
*Generated by VulnIntel GRC Engine — {self.today}*
"""

    # ── ATO Package ──────────────────────────────────────────────
    def generate_ato_package(self) -> str:
        """Generate an Authority to Operate (ATO) package summary."""
        controls = _get_controls(self.system_id)
        vulns = _get_vulns(self.system_id)
        poams = _get_poams(self.system_id)

        total = len(controls) or 1
        implemented = sum(1 for c in controls if c.get("impl_status") == "Implemented")
        score = round(implemented / total * 100, 1)

        sev = {}
        for v in vulns:
            s = v.get("severity", "Medium")
            sev[s] = sev.get(s, 0) + 1

        # AI recommendation
        recommendation = _call_llm(
            f"As an Authorizing Official, write an ATO recommendation for '{self.sys_name}'. "
            f"Compliance score: {score}%, {implemented}/{total} controls implemented, "
            f"{sev.get('Critical',0)} critical vulns, {sev.get('High',0)} high vulns, "
            f"{len(poams)} open POA&M items. Impact level: {self.impact}. "
            f"Provide: 1) Authorization decision (ATO/ATO with conditions/Deny), "
            f"2) Conditions if applicable, 3) Risk acceptance statement, "
            f"4) Continuous monitoring requirements.",
            600
        )

        return f"""# Authority to Operate (ATO) Package
## {self.sys_name}

| Field | Value |
|-------|-------|
| **System** | {self.sys_name} ({self.sys.get('acronym', '')}) |
| **Organization** | {self.org_name} |
| **Impact Level** | {self.impact} |
| **Compliance Score** | {score}% |
| **Date** | {self.today} |

---

## Package Contents

| Document | Status | Generated |
|----------|--------|-----------|
| System Security Plan (SSP) | ✅ Available | {self.today} |
| Security Assessment Report (SAR) | ✅ Available | {self.today} |
| Plan of Action & Milestones (POA&M) | ✅ Available | {self.today} |
| Risk Assessment | ✅ Available | {self.today} |
| ATO Recommendation | ✅ This Document | {self.today} |

## Current Posture

| Metric | Value |
|--------|-------|
| Total Controls | {total} |
| Implemented | {implemented} ({score}%) |
| Open Vulnerabilities | {len(vulns)} |
| Critical Vulnerabilities | {sev.get('Critical', 0)} |
| High Vulnerabilities | {sev.get('High', 0)} |
| Open POA&M Items | {len(poams)} |

## Authorization Recommendation

{recommendation}

---
*Generated by VulnIntel GRC Engine — {self.today}*
"""

    # ── Generate All ─────────────────────────────────────────────
    def generate_all(self) -> dict:
        """Generate all GRC documents and return as a dict."""
        log.info(f"[DocGen] Generating full ATO package for system {self.system_id}")
        return {
            "ssp": self.generate_ssp(),
            "sar": self.generate_sar(),
            "poam": self.generate_poam_report(),
            "risk_assessment": self.generate_risk_assessment(),
            "ato_package": self.generate_ato_package(),
            "generated_at": datetime.now().isoformat(),
            "system": self.sys,
        }
