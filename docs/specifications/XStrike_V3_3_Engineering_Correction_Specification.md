# EXPEDITE STRIKE V3.3 — Engineering Correction & Data-Integrity Specification

> [!IMPORTANT]
> **Objective**: Advance XStrike from **V3.2** to **V3.3** by resolving all six audit findings identified in the review of `XStrike_Pentest_Report_20261031_135123.pdf`. The primary engineering mandate of V3.3 is **canonical data reconciliation, non-contradictory risk mathematics, independent cryptographic trust, and strict proof-state discipline**—without adding noisy scanning features.

---

## 1. Root-Cause Diagnosis of the Six V3.2 Audit Findings

| Audit Issue | What Happened in V3.2 (`XStrike_Pentest_Report_20261031_135123.pdf`) | Root Cause in Code | V3.3 Engineering Resolution |
| :--- | :--- | :--- | :--- |
| **Issue 1 — Inconsistent Finding IDs (`F-64` vs `F-75`, `F-55` vs `F-59`)** | Cover page & Retest Ledger cited `F-64` (`robots.txt`) and `F-55` (`.140:22` SSH), while Executive Summary / Section 8 / Section 10.3 prose cited `F-75` and `F-59`. | `RemediationVerificationEngine` dynamically resolved `finding_id` from the sorted finding list (`F-64` & `F-55` in the 82-finding live runtime state; `F-75` & `F-59` in the 98-finding full cache), while narrative strings in [`evidence_intelligence.py`](file:///d:/XPedite-strike/cyber_range/services/evidence_intelligence.py) and [`pentest_report_pdf.py`](file:///d:/XPedite-strike/cyber_range/services/pentest_report_pdf.py) hardcoded `"F-75"` and `"F-59"`. | **100% Dynamic Registry Interpolation**: Zero hardcoded `F-XX` IDs in any prose, table, or capability description. Every section queries `remediation_workflow` and `security_findings` by `canonical_key`. Added Quality Gate `AC-21` to reject any report where a remediation/retest event is referenced under more than one Finding ID. |
| **Issue 2 — Risk Calculation Discrepancies (`96.3` vs `96.9`, `75.1` vs `75.8`, `T1 RawSum = 0` vs `Cal = 22.6/23.3`)** | Cover & Section 1.4 table showed `96.3 -> 75.1` (or `96.9 -> 75.7`), while Section 8.1 & 10.3 prose hardcoded `96.9 -> 75.8`, and Section 1.4 printed `T1 RawSum = 0 pts` alongside `Cal: 23.3/25.0`. | [`compute_evidence_weighted_risk`](file:///d:/XPedite-strike/cyber_range/services/evidence_intelligence.py#L3356-L3660) returned `s_exposure_calibrated_post_retest` and omitted `post_retest_s_exposure_raw_sum`, whereas [`pentest_report_pdf.py`](file:///d:/XPedite-strike/cyber_range/services/pentest_report_pdf.py) looked up `risk_model.get("post_retest_s_exposure_raw_sum", 0)` (evaluating to `0`) and `risk_model.get("post_retest_s_exposure_calibrated", 23.3)` (evaluating to fallback `23.3`). | **Unified Risk Snapshot Contract**: Expose all T0 and T1 component fields (`post_retest_s_compromise`, `post_retest_s_exposure_raw_sum`, `post_retest_s_exposure_linear`, `post_retest_s_exposure_calibrated`, `post_retest_s_asset`, `post_retest_s_reachability`, `verified_risk_reduction_pts`) and enforce mathematical identity checks in `AC-09` & `AC-21`. |
| **Issue 3 — Retest Scope & Multi-Endpoint Closure Criteria** | HTTP `404` on `/robots.txt` was cited as primary closure proof without requiring per-path verification of all disclosed paths (`/admin`, `/backup`, `/config`, `/private`), and retesting only covered 3 cases. | `RETEST-02` only checked `/robots.txt` and `/admin`, and the engine did not include partial or failed retest states. | **5-Case Retest Ledger & Multi-Endpoint Verification**: `RETEST-02` now verifies `/robots.txt` (`404`) plus all 4 formerly disclosed endpoints (`/admin -> 403`, `/backup -> 404`, `/config -> 403`, `/private -> 403`). Added `RETEST-04-PARTIAL` (`PARTIALLY_REMEDIATED_NOT_CLOSED`) and `RETEST-05-FAILED` (`RETEST_FAILED_STILL_VULNERABLE`). |
| **Issue 4 — Standalone Verifier Trust & 5 Tamper Tests** | Supplying the Ed25519 public key inside the bundle proves internal consistency, not external key authenticity; only 1 tamper test (1-byte mutation) was executed. | [`verify_manifest.py`](file:///d:/XPedite-strike/cyber_range/services/verify_manifest.py) did not pin an out-of-band public-key fingerprint or test deleted/reordered records and substituted keys. | **Pinned Trust Registry & 5-Vector Tamper Suite**: Added out-of-band SHA-256 public-key fingerprint pinning, key ownership/rotation/CRL metadata, RFC 3161-style timestamp token binding, all **5 negative tamper tests** (`modified_record`, `deleted_record`, `reordered_records`, `altered_manifest`, `substituted_public_key`), and embedded the verifier execution log in Section 9. |
| **Issue 5 — Attack Graph Lateral Movement Terminology** | `PIVOT-CYBER-01` (`.139 -> .140`) was labeled `LATERAL_MOVEMENT_SUCCEEDED (Precondition & Peer Service Reachability Verified; Destructive Pivot Withheld by RoE)`. | Conflated a validated lateral precondition (extracted SSH key/hashes + reachable peer port) with an executed cross-host pivot. | **Strict 4-State Lateral Movement Taxonomy**: Separated `LATERAL_MOVEMENT_EXECUTED` (requires both source-host and destination-host session transcripts) from `LATERAL_PRECONDITION_VALIDATED_NOT_EXECUTED` (for `PIVOT-CYBER-01`) and `TESTED_ROUTES_BLOCKED_BY_CONTROL`. |
| **Issue 6 — Specific Vulnerability Classifications (`SMBv1`, `Slowloris`, `SQLi/SSRF`, Backports)** | `VULN_SMBV1_ENABLED` carried `CVE-2017-0144` (`High 7.5`); `VULN_HTTP_SLOWLORIS` (`LIKELY VULNERABLE`) was marked `VALIDATED` (`High 7.5`). | SMBv1 dialect enablement was mapped to EternalBlue's CVE; Slowloris NSE heuristic (`LIKELY VULNERABLE`) was promoted to `VALIDATED` without thread-exhaustion reproduction. | **Strict Classification Guards**: Removed `CVE-2017-0144` from `VULN_SMBV1_ENABLED` (now `Medium 5.3`, `CWE-327`); demoted `VULN_HTTP_SLOWLORIS` (`LIKELY VULNERABLE` heuristic) to `OBSERVED` (`Medium 5.3`); added explicit `VALIDATED_INDICATOR_ONLY` boundaries to `VULN_SQL_INJECTION` and `VULN_WEB_SSRF_MUTILLIDAE`. |

---

## 2. Database Schema Changes (SQLite 7-Table Schema V3.3)

In [`persist_v2_intelligence_snapshot`](file:///d:/XPedite-strike/cyber_range/services/evidence_intelligence.py#L5525-L5700), the SQLite schema (`v2_intelligence.db`) is expanded from 5 tables to **7 normalized tables** so that remediation retests and risk calculation snapshots are first-class relational records:

```sql
-- Existing Tables 1..5 (Updated with V3.3 columns):
-- 1. v2_assessments
-- 2. v2_reconciled_hosts
-- 3. v2_consolidated_findings (Added: baseline_proof_state, post_retest_proof_state, retest_status, mitre_execution_state, exploitability_gate_status)
-- 4. v2_attack_graph_edges (Added: mitre_execution_state)
-- 5. v2_evidence_provenance

-- NEW Table 6: v2_remediation_retests (Single Source of Truth for Retest Ledger)
CREATE TABLE IF NOT EXISTS v2_remediation_retests (
    retest_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    host TEXT NOT NULL,
    port TEXT NOT NULL,
    baseline_state TEXT NOT NULL,
    change_id TEXT NOT NULL,
    retest_command TEXT NOT NULL,
    before_sha256 TEXT NOT NULL,
    after_sha256 TEXT NOT NULL,
    negative_control_sha256 TEXT NOT NULL,
    host_online_confirmed INTEGER NOT NULL,
    vulnerability_eliminated INTEGER NOT NULL,
    transition_decision TEXT NOT NULL,
    post_retest_proof_state TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES v2_consolidated_findings(finding_id)
);

-- NEW Table 7: v2_risk_snapshots (Immutable Audit History of T0 Baseline & T1 Post-Retest Risk)
CREATE TABLE IF NOT EXISTS v2_risk_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    snapshot_phase TEXT NOT NULL, -- 'T0_BASELINE' or 'T1_POST_RETEST_VERIFIED'
    formula_version TEXT NOT NULL,
    calculated_at_utc TEXT NOT NULL,
    active_finding_count INTEGER NOT NULL,
    active_finding_ids_json TEXT NOT NULL,
    s_compromise REAL NOT NULL,
    s_exposure_raw_sum REAL NOT NULL,
    s_exposure_linear REAL NOT NULL,
    s_exposure_calibrated REAL NOT NULL,
    s_asset REAL NOT NULL,
    s_reachability REAL NOT NULL,
    calibrated_total REAL NOT NULL,
    linear_total REAL NOT NULL
);
```

---

## 3. API & Data Contract Specification

### 3.1 Canonical Risk Model Contract (`compute_evidence_weighted_risk`)
Every risk calculation returns a self-verifying dictionary containing both `T0_BASELINE` and `T1_POST_RETEST_VERIFIED` snapshots:

$$\begin{aligned}
S_{\text{exposure,cal}}(T) &= \text{round}\!\left(25.0 \times \left(1 - e^{-\text{RawSum}(T) / 35.0}\right),\; 1\right) \\
R_{\text{cal}}(T) &= \min\!\left(100.0,\; S_{\text{compromise}}(T) + S_{\text{exposure,cal}}(T) + S_{\text{asset}}(T) + S_{\text{reachability}}(T)\right)
\end{aligned}$$

Required keys guaranteed in `risk_model`:
- `formula_version`: `"RiskEngine-V3.3-NonSaturating-Calibrated"`
- `calculated_at_utc`: ISO-8601 UTC timestamp
- `active_finding_ids_t0`: List of all active `finding_id`s in T0 Baseline
- `active_finding_ids_t1`: List of all active `finding_id`s in T1 Post-Retest (excluding only findings where `post_retest_proof_state == "REMEDIATION_VERIFIED"`)
- `s_compromise`, `s_exposure_raw_sum`, `s_exposure`, `s_exposure_calibrated`, `s_asset`, `s_reachability`, `principal_calibrated_score`, `overall_score`
- `post_retest_s_compromise`, `post_retest_s_exposure_raw_sum`, `post_retest_s_exposure_linear`, `post_retest_s_exposure_calibrated`, `post_retest_s_asset`, `post_retest_s_reachability`, `post_retest_calibrated_score`, `post_retest_linear_score`
- `verified_risk_reduction_pts` (negative float, e.g., `-21.2`) and `verified_risk_reduction_calibrated_pts` (positive magnitude, e.g., `21.2`).

### 3.2 Standalone Verifier Contract (`verify_manifest.py`)
```bash
python -m cyber_range.services.verify_manifest \
  --bundle cyber_range/reports/XStrike_Evidence_Bundle.json \
  --pubkey cyber_range/reports/ed25519_pub.pem \
  --expected-pubkey-sha256 <64-hex-pinned-fingerprint>
```
Returns:
- `standalone_verified`: `bool`
- `pinned_public_key_fingerprint_verified`: `bool`
- `key_trust_metadata`: `{ "key_id", "owner_identity", "custody_tier", "rotation_policy", "revocation_status", "rfc3161_timestamp_token" }`
- `tamper_self_tests`:
  1. `modified_record_rejected`: `True`
  2. `deleted_record_rejected`: `True`
  3. `reordered_records_rejected`: `True`
  4. `altered_manifest_rejected`: `True`
  5. `substituted_public_key_rejected`: `True`

---

## 4. Formal V3.3 Regression Test Matrix (10 Mandatory Tests)

Implemented in [`test_xstrike_v2_acceptance.py`](file:///d:/XPedite-strike/cyber_range/services/test_xstrike_v2_acceptance.py):

| Test ID | Test Case | Expected Result |
| :--- | :--- | :--- |
| `REG-01` | Same remediation/retest finding appears under two different IDs across sections | Quality Gate `AC-21` & report assertion **FAIL** immediately |
| `REG-02` | Evidence record is modified (1-byte payload mutation) | Standalone verifier SHA-256 & Merkle root checks **FAIL** (`modified_record_rejected = True`) |
| `REG-03` | Evidence record is deleted from bundle | Standalone verifier record count & Merkle root checks **FAIL** (`deleted_record_rejected = True`) |
| `REG-04` | Evidence records are reordered in bundle | Standalone verifier ordered Merkle leaf digest check **FAILS** (`reordered_records_rejected = True`) |
| `REG-05` | Public key is substituted with an untrusted/rogue Ed25519 key | Trusted-key SHA-256 fingerprint pinning & signature verification **FAIL** (`substituted_public_key_rejected = True`) |
| `REG-06` | Target host is offline during retest (`RETEST-03-NEG-CTRL`) | Alive-host negative control fails; retest is **REJECTED** (`REJECTED_HOST_OFFLINE`) |
| `REG-07` | Vulnerable service is actually disabled & host is online (`RETEST-01`, `RETEST-02`) | Closure verified (`REMEDIATION_VERIFIED`) only after all endpoint & alive-host controls pass |
| `REG-08` | Partial or failed remediation (`RETEST-04-PARTIAL`, `RETEST-05-FAILED`) | Held in active state (`VALIDATED` / `CONFIRMED_AUTH`) with `0.0` pts risk reduction |
| `REG-09` | SQLi/SSRF indicator or Slowloris `LIKELY VULNERABLE` heuristic | SQLi/SSRF held at `VALIDATED` (`VALIDATED_INDICATOR_ONLY`); Slowloris held at `OBSERVED`; SMBv1 has no `CVE-2017-0144` |
| `REG-10` | Risk calculation inputs change (`T0` $\to$ `T1`) | Reproducible risk snapshot generated; component sums exactly equal `R_cal` and `RawSum > 0` matches `S_exposure_cal` |

---

## 5. Release Acceptance Criteria (21-Rule Quality Gate `AC-01` .. `AC-21`)

- **`AC-01` .. `AC-20`**: All 20 V3.2 quality gate checks (with `AC-09` strengthened to verify exact mathematical equality between `post_retest_s_exposure_raw_sum` and `post_retest_s_exposure_calibrated`).
- **`AC-21` (NEW in V3.3)**: **Canonical Finding ID Single-Source-of-Truth, 5-Tamper-Test Standalone Trust & Technical Classification Discipline** — Verifies that:
  1. Every `finding_id` in `remediation_workflow`, `transition_model`, `attack_graph`, `v3_architecture`, and `risk_model` maps 1-to-1 to the canonical `security_findings` registry (`0` orphaned or conflicting IDs),
  2. All 5 negative tamper tests (`modified`, `deleted`, `reordered`, `altered_manifest`, `substituted_pubkey`) pass in `standalone_verification`,
  3. `VULN_SMBV1_ENABLED` does not claim `CVE-2017-0144` and `VULN_HTTP_SLOWLORIS` is held at `OBSERVED`.
