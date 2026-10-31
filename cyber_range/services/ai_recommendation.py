"""
ai_recommendation.py
─────────────────────
Generate AI-powered security recommendations from scan results.

Called by the ScanOrchestrator after scoring completes.
Uses the same LLM engine as the rest of the platform.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyber_range.models.scan_result import ScanResult


PROMPT_TEMPLATE = """
You are a senior Active Directory security consultant.

A scan of the domain "{domain}" ({dc_ip}) just completed with these results:

PINGCASTLE
  Global Score : {pc_score}/100  (Level {pc_level})
  Critical findings: {criticals}
  High findings    : {highs}
  Top rules        : {top_rules}

NMAP
  Open ports ({port_count}): {open_ports}

BLOODHOUND
  Paths to Domain Admin : {da_paths}
  Attack paths found    : {attack_paths}

COMPOSITE RISK SCORE: {risk_score}/100  (Level {risk_level})

Write a concise, technical security assessment in this structure:
1. **Executive Summary** (2 sentences)
2. **Critical Remediation Actions** (bullet list, ordered by urgency)
3. **Attack Path Risk** (1 paragraph on BloodHound findings)
4. **Network Exposure** (1 paragraph on Nmap results)
5. **30-day Remediation Roadmap** (3 phases)

Be specific, actionable, and reference CVEs or MITRE ATT&CK techniques where relevant.
"""


def generate_ai_recommendation(result: "ScanResult") -> str:
    """
    Generate an AI narrative for a completed scan.
    Returns empty string if LLM unavailable.
    """
    try:
        # Build context
        criticals = [f.rule for f in result.findings if f.severity == "Critical"]
        highs     = [f.rule for f in result.findings if f.severity == "High"]
        open_ports = [f"{p.port}/{p.protocol} ({p.service})" for p in result.ports[:10]]
        atk_paths  = [f"{p.source}→{p.target}" for p in result.attack_paths[:5]]

        prompt = PROMPT_TEMPLATE.format(
            domain      = result.domain or "corp.local",
            dc_ip       = result.dc_ip or "unknown",
            pc_score    = result.pc_global_score,
            pc_level    = result.pc_risk_level,
            criticals   = len(criticals),
            highs       = len(highs),
            top_rules   = ", ".join(criticals + highs)[:200],
            port_count  = result.nmap_open_count,
            open_ports  = ", ".join(open_ports),
            da_paths    = result.blood_da_paths,
            attack_paths= "; ".join(atk_paths) or "None identified",
            risk_score  = result.risk_score,
            risk_level  = result.risk_level,
        )

        # Use existing platform LLM engine
        from openai import OpenAI
        client = OpenAI()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1200,
        )
        return resp.choices[0].message.content.strip()

    except Exception as e:
        return f"(AI recommendation unavailable: {e})"
