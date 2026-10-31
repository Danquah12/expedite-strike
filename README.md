# EXPEDITE STRIKE V2 — Proof-Driven Autonomous Penetration Testing & SOC Platform

**Expedite Consults Ltd** · Autonomous Penetration Testing, Cyber Range & Proof-Driven Intelligence Engine (`v2.0`)

---

## Overview

**EXPEDITE STRIKE V2 (ÆGIS · SOC)** combines autonomous network reconnaissance, vulnerability scanning, OWASP web auditing, exploit validation, privilege escalation, and lateral movement analysis with the **8-Component Proof-Driven Intelligence Layer**:

1. **`01. EvidenceValidationEngine & ProvenanceEngine`** ([`cyber_range/services/evidence_intelligence.py`](cyber_range/services/evidence_intelligence.py))
   - **7-State Proof State Machine**: `DISCOVERED`, `OBSERVED`, `VALIDATED`, `EXPLOITABLE`, `CONFIRMED_AUTH`, `CONFIRMED_COMPROMISE`, `REMEDIATION_VERIFIED`.
   - **5-Dimensional Confidence Vector**: `detection_confidence`, `validation_confidence`, `exploitation_confidence`, `impact_confidence`, `evidence_completeness`, `composite_confidence`, and `false_positive_band`.
   - **Immutable SHA-256 Provenance**: Cryptographic evidence hashes and 5-field granular `access_scope`.
2. **`02. FindingDeduplicationEngine`**
   - 3-Level Funnel consolidating repeated scanner observations (`1,559` raw observations $\to$ `90` consolidated host-level security findings across `54` unique vulnerability classes + `25` reconnaissance items + `89` excluded local-scanner self-checks) while preserving 100% of affected endpoints and ports.
3. **`03. VulnerabilityIntelligenceEngine`**
   - Word-boundary CWE/CVE/MITRE resolver (`resolve_safe_cwe`) and semantic consistency validator (`validate_finding_semantics`).
4. **`04. AttackGraphEngine`**
   - 4-stage provenance-backed attack chains (`Initial Access` $\to$ `Credential/Vuln Exploitation` $\to$ `Privilege Escalation` $\to$ `Target Impact`) with per-edge validation states and mathematical path scoring.
5. **`05. RiskIntelligenceEngine`**
   - Reproducible 4-component Evidence-Weighted Risk Score ($R = \min(100, S_{\text{compromise}} + S_{\text{exposure}} + S_{\text{asset}} + S_{\text{reachability}})$) and SLA risk-reduction projections (`24h`, `7d`, `30d`).
6. **`06. RootCauseEngine`**
   - Root-cause classification on deduplicated security findings with 4-tier attribution certainty (`DIRECTLY_ESTABLISHED`, `PROBABLE`, `INFERRED`, `UNKNOWN`).
7. **`07. RemediationAndComplianceEngine`**
   - Vulnerability-specific Immediate/Short-Term/Long-Term remediation plans (`0` generic placeholders) and 4-tier Compliance Evidence Mapping (`PCI-DSS v4.0`, `NIST SP 800-53 Rev. 5`, `ISO/IEC 27001:2022`, `CIS Controls v8`).
8. **`08. ReportQualityEngine`**
   - 13-rule pre-render quality gate (`AC-01` through `AC-13`) and SQLite persistence (`data/v2_intelligence.db`).

---

## Documentation & Verified Artifacts

- **Architecture & Data Model Specification**: [`docs/Finding_and_Evidence_Intelligence_Specification.md`](docs/Finding_and_Evidence_Intelligence_Specification.md)
- **Verified V2 Enterprise Penetration Testing Report (PDF)**: [`docs/XStrike_Pentest_Report_Verified_v2.pdf`](docs/XStrike_Pentest_Report_Verified_v2.pdf)
- **Automated Acceptance Test Suite (`13/13` Passing)**: [`cyber_range/services/test_xstrike_v2_acceptance.py`](cyber_range/services/test_xstrike_v2_acceptance.py)

---

## Quick Start

```bash
# 1. Run the 13-test V2 Acceptance Suite
python cyber_range/services/test_xstrike_v2_acceptance.py

# 2. Start the EXPEDITE STRIKE / AEGIS SOC Server (http://localhost:9011/app/?standalone=1)
python -X utf8 app.py
```
