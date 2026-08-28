"""
Expedite Strike — FAIR Quantitative Cyber Risk & Financial Loss Engine
=======================================================================
Implements Factor Analysis of Information Risk (FAIR) mathematical modeling:
  1. Threat Event Frequency (TEF) & Vulnerability (Threat Capability vs Resistance)
  2. Primary Loss: Productivity Outage, Response Incident Costs, Replacement
  3. Secondary Loss: Regulatory Fines (GDPR/HIPAA), Litigation, Customer Churn
  4. Computes Expected Annual Loss (ALE) and Max Probable Financial Exposure ($)
"""

from typing import List, Dict, Any


class FAIRRiskEngine:
    """Calculates dollar-denominated Cyber Value-at-Risk ($) for perimeter findings."""

    # Baseline cost factors based on Ponemon / IBM Cost of Data Breach datasets
    COST_PER_RECORD = 165.0       # Average cost per breached PII record
    OUTAGE_HOURLY_COST = 25000.0  # Business downtime cost per hour
    INCIDENT_RESPONSE_FEE = 45000.0 # Standard forensic response retainer
    MAX_REGULATORY_FINE_PCT = 0.04  # Up to 4% of annual revenue (GDPR benchmark)

    @classmethod
    def calculate_finding_loss(cls, finding: Dict[str, Any], org_annual_revenue: float = 25000000.0) -> Dict[str, Any]:
        """Compute FAIR dollar-quantified risk exposure for an individual finding."""
        cvss = float(finding.get("cvss", 5.0) or 5.0)
        sev = str(finding.get("severity", "Medium")).lower()
        title = (finding.get("title", "") or "").lower()

        # Threat Event Frequency (Annualized probability)
        tef = 0.85 if cvss >= 9.0 else 0.60 if cvss >= 7.0 else 0.35 if cvss >= 4.0 else 0.15

        # Primary Loss calculation
        downtime_hours = 12.0 if "rce" in title or "privesc" in title else 4.0 if sev in ("critical", "high") else 1.0
        productivity_loss = downtime_hours * cls.OUTAGE_HOURLY_COST
        ir_cost = cls.INCIDENT_RESPONSE_FEE if sev in ("critical", "high") else 10000.0

        # Secondary Loss calculation (Regulatory & Churn)
        records_at_risk = 25000 if "database" in title or "sql" in title or "credentials" in title else 5000
        data_breach_cost = records_at_risk * cls.COST_PER_RECORD if sev in ("critical", "high") else 0.0
        regulatory_fine = min(org_annual_revenue * 0.02, 500000.0) if "secret" in title or "admin" in title else 0.0

        max_probable_loss = round(productivity_loss + ir_cost + data_breach_cost + regulatory_fine, 2)
        annualized_loss_expectancy = round(max_probable_loss * tef, 2)

        return {
            "finding_title": finding.get("title"),
            "cvss_score": cvss,
            "threat_event_frequency_pct": round(tef * 100, 1),
            "max_probable_loss_usd": max_probable_loss,
            "annualized_loss_expectancy_usd": annualized_loss_expectancy,
            "loss_breakdown": {
                "business_productivity_outage": productivity_loss,
                "incident_response_forensics": ir_cost,
                "data_breach_liability": data_breach_cost,
                "regulatory_penalty_risk": regulatory_fine,
            },
        }

    @classmethod
    def evaluate_perimeter_financial_risk(cls, findings: List[Dict[str, Any]], org_revenue: float = 25000000.0) -> Dict[str, Any]:
        """Aggregate total perimeter financial loss exposure across all findings."""
        findings = findings or []
        total_ale = 0.0
        total_max_loss = 0.0
        itemized_risks = []

        for f in findings:
            loss_data = cls.calculate_finding_loss(f, org_revenue)
            total_ale += loss_data["annualized_loss_expectancy_usd"]
            total_max_loss = max(total_max_loss, loss_data["max_probable_loss_usd"])
            itemized_risks.append(loss_data)

        # Sort itemized risks by highest financial exposure
        itemized_risks.sort(key=lambda x: x["annualized_loss_expectancy_usd"], reverse=True)

        return {
            "total_annualized_loss_exposure_usd": round(total_ale, 2),
            "max_single_event_loss_usd": round(total_max_loss, 2),
            "currency": "USD",
            "findings_quantified_count": len(findings),
            "top_financial_risks": itemized_risks[:5],
        }
