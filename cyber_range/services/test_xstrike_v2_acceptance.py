"""
EXPEDITE STRIKE V3 — Proof-Driven & EvidenceCore V3 Intelligence Upgrade
Automated Acceptance & Regression Test Suite (16-Rule Quality Gate Verification)
"""
import os
import re
import sys
import json
import sqlite3
import tempfile
import unittest

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from cyber_range.services import evidence_intelligence as ei
from cyber_range.services import pentest_report_pdf as prp
from cyber_range.services import nvd_enrichment as nvd


class TestXStrikeV3Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        state_path = os.path.join(WORKSPACE_ROOT, "cyber_range", "scan_cache", "autopentest_state.json")
        with open(state_path, "r", encoding="utf-8") as fh:
            cls.raw_state = json.load(fh)

        cls.temp_db = os.path.join(tempfile.gettempdir(), "test_v3_intelligence.db")
        if os.path.exists(cls.temp_db):
            try:
                os.remove(cls.temp_db)
            except OSError:
                pass

        cls.v2 = ei.correlate_and_enrich_findings(
            raw_findings=cls.raw_state.get("findings", []),
            raw_exploits=cls.raw_state.get("exploits_succeeded", []),
            hosts=cls.raw_state.get("hosts_discovered", []),
            raw_attack_paths=cls.raw_state.get("attack_paths", []),
            assessment_id="TEST-XSTRIKE-V3-ACCEPTANCE",
            db_path=cls.temp_db,
        )

    def test_ac01_no_port_only_confirmed(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            ev = (f.get("evidence") or "").lower()
            pstate = f.get("proof_state", "")
            if "port-open detection only" in ev or "status not verified" in ev:
                self.assertNotIn(pstate, ("CONFIRMED_COMPROMISE", "CONFIRMED_AUTH", "EXPLOITABLE"))

    def test_ac02_confirmed_has_execution_proof_and_7d_proof_vector(self):
        confirmed = [
            f for f in self.v2["security_findings"]
            if f.get("proof_state") in ("CONFIRMED_COMPROMISE", "CONFIRMED_AUTH")
        ]
        vs_f = [f for f in self.v2["security_findings"] if f.get("canonical_key") == "VULN_VSFTPD_234_BACKDOOR"]
        self.assertEqual(len(confirmed), 6, f"Confirmed: {[(f['finding_id'], f['canonical_key'], f['proof_state']) for f in confirmed]} | vsftpd={[(f['finding_id'], f['proof_state'], f['evidence'][:120]) for f in vs_f]}")
        for f in confirmed:
            self.assertTrue(len((f.get("evidence") or "").strip()) >= 15)
            scope = f.get("access_scope") or {}
            for req_key in (
                "authenticated", "file_access", "database_access", "privilege_level",
                "privesc_demonstrated", "access_summary",
                "execution_status", "authentication_status", "exploitability_status",
                "data_access_status", "impact_status", "evidence_confidence"
            ):
                self.assertIn(req_key, scope)

    def test_ac03_eternalblue_and_phpmyadmin_properly_calibrated(self):
        eb_findings = [
            f for f in self.v2["security_findings"]
            if f.get("canonical_key") == "VULN_SMB_ETERNALBLUE_CANDIDATE"
        ]
        self.assertEqual(len(eb_findings), 4)
        for f in eb_findings:
            self.assertEqual(f.get("proof_state"), "OBSERVED")
            self.assertEqual(float(f.get("cvss_score", -1)), 0.0)
            self.assertEqual(f.get("severity"), "Medium")
            self.assertLessEqual(float(f.get("confidence", 100)), 50.0)

        pma_findings = [
            f for f in self.v2["security_findings"]
            if f.get("canonical_key") == "VULN_PHPMYADMIN_EXPOSED"
        ]
        self.assertGreaterEqual(len(pma_findings), 1)
        for pma in pma_findings:
            self.assertEqual(pma.get("proof_state"), "VALIDATED")
            self.assertEqual(pma.get("severity"), "Medium")
            self.assertEqual(float(pma.get("cvss_score", -1)), 5.3)
            self.assertNotIn("no auth! can read/write", (pma.get("evidence") or "").lower())

    def test_ac04_deduplication_and_zero_owasp_category_rollups(self):
        self.assertEqual(self.v2["raw_observation_count"], 1641)
        self.assertEqual(self.v2["excluded_noise_count"], 89)
        pairs = [(f.get("host"), f.get("canonical_key")) for f in self.v2["security_findings"] + self.v2["recon_findings"]]
        self.assertEqual(len(pairs), len(set(pairs)))
        for f in self.v2["security_findings"]:
            self.assertFalse(str(f.get("canonical_key", "")).startswith("VULN_OWASP_A"))
            self.assertNotIn("OWASP A0", f.get("title", ""))

    def test_ac05_scope_and_service_sum_reconciliation(self):
        rec_hosts = self.v2["reconciled_hosts"]
        self.assertEqual(len(rec_hosts), 7)
        self.assertEqual(len([h for h in rec_hosts if h.get("open_port_count", 0) > 0]), 5)
        self.assertEqual(len([h for h in rec_hosts if h.get("open_port_count", 0) == 0]), 2)
        self.assertGreaterEqual(sum(h["open_port_count"] for h in rec_hosts), 53)
        for h in rec_hosts:
            self.assertTrue(bool(h.get("classification_source")))
            self.assertGreater(int(h.get("classification_confidence", 0)), 0)

    def test_ac06_strict_cve_format_and_zero_generic_cwe16(self):
        cve_re = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            cve_val = f.get("cve") or ""
            if cve_val:
                self.assertRegex(cve_val, cve_re, f"Non-CVE identifier in cve field: {cve_val}")
            if f.get("is_security_vulnerability"):
                self.assertNotEqual(f.get("cwe"), "CWE-16", f"Generic CWE-16 on {f.get('finding_id')} ({f.get('canonical_key')})")
            is_valid, issues = ei.validate_finding_semantics(f)
            self.assertTrue(is_valid, f"Semantic mismatch on {f.get('finding_id')}: {issues}")

    def test_ac07_reconnaissance_segregation(self):
        for f in self.v2["security_findings"]:
            self.assertNotEqual(f.get("proof_state"), "DISCOVERED")
            self.assertTrue(f.get("is_security_vulnerability"))
        for r in self.v2["recon_findings"]:
            self.assertEqual(r.get("proof_state"), "DISCOVERED")
            self.assertFalse(r.get("is_security_vulnerability"))
            self.assertEqual(float(r.get("cvss_score", -1)), 0.0)

    def test_ac08_per_host_asset_classification(self):
        host_map = {h["host"]: h["asset_class_label"] for h in self.v2["reconciled_hosts"]}
        self.assertIn("Multi-Role Application & Database Server", host_map.get("192.168.195.139", ""))
        self.assertIn("Workstation / SMB Peer Host", host_map.get("192.168.195.130", ""))
        self.assertIn("Gateway", host_map.get("192.168.195.1", ""))

    def test_ac09_100pct_specific_remediation_coverage(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            rem_text = " ".join([
                str(f.get("remediation_immediate", "")),
                str(f.get("remediation_short", "")),
                str(f.get("remediation_long", "")),
            ]).lower()
            self.assertNotIn("investigate and apply vendor patches", rem_text)
            self.assertNotIn("restrict network exposure to the affected service port using host firewall rules", rem_text)
            self.assertTrue(len(rem_text.strip()) > 30)

    def test_ac10_separated_confidence_and_nvd_band_consistency(self):
        for f in self.v2["security_findings"]:
            c5 = f.get("confidence_5d", {})
            for k in (
                "detection_confidence", "validation_confidence", "exploitation_confidence",
                "impact_confidence", "evidence_completeness", "composite_confidence",
                "evidence_confidence", "exploitability_confidence", "false_positive_band"
            ):
                self.assertIn(k, c5)
            # NVD CVSS v3.1 score-to-severity band check
            sc = float(f.get("cvss_score", 0.0))
            sev = f.get("severity")
            ckey = f.get("canonical_key")
            if ckey == "VULN_SMB_ETERNALBLUE_CANDIDATE":
                self.assertEqual(sc, 0.0)
                self.assertEqual(sev, "Medium")
            elif sev == "Critical":
                self.assertTrue(9.0 <= sc <= 10.0, f"{f.get('finding_id')} Critical has CVSS {sc}")
            elif sev == "High":
                self.assertTrue(7.0 <= sc <= 8.9, f"{f.get('finding_id')} High has CVSS {sc}")
            elif sev == "Medium":
                self.assertTrue(4.0 <= sc <= 6.9, f"{f.get('finding_id')} Medium has CVSS {sc}")
            elif sev == "Low":
                self.assertTrue(0.1 <= sc <= 3.9, f"{f.get('finding_id')} Low has CVSS {sc}")

    def test_ac11_attack_graph_v3_metrics_and_choke_points(self):
        ag = self.v2["attack_graph"]
        self.assertEqual(ag["consolidated_chain_count"], 6)
        self.assertGreaterEqual(len(ag["edges"]), 20)
        self.assertGreaterEqual(len(ag.get("remediation_choke_points", [])), 3)
        for ch in ag["chains"]:
            for k in ("path_feasibility", "path_confidence", "privilege_reached", "asset_impact", "path_length", "remediation_leverage", "path_priority"):
                self.assertIn(k, ch)

    def test_ac12_endpoint_hygiene_zero_external_reference_urls(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            for ep in f.get("affected_endpoints", []):
                ep_l = str(ep).lower()
                self.assertNotIn("w3.org", ep_l)
                self.assertNotIn("nmap.org", ep_l)
                self.assertFalse(ep_l.startswith("/"), f"Unbound relative path in endpoint: {ep}")

    def test_ac13_to_ac18_manifest_sarif_transition_reconciliation_and_18_rule_quality_gate(self):
        qa = self.v2["quality_audit"]
        self.assertTrue(qa["passed"], f"Failed rules: {[c for c in qa['checks'] if not c['passed']]}")
        self.assertEqual(qa["passed_rules"], 18)
        self.assertEqual(qa["total_rules"], 18)

        # AC-17: Verify Dynamic Transition Model has zero stale hardcoded IDs
        tm = self.v2["transition_model"]
        self.assertTrue(tm["reconciled"], f"Transition reconciliation errors: {tm.get('reconciliation_errors')}")
        self.assertEqual(tm["confirmed_compromise_ids"], ["F-01", "F-02"])
        self.assertEqual(tm["confirmed_auth_ids"], ["F-03", "F-04", "F-05", "F-17"])
        self.assertIn("F-06", tm["privesc_ids"])
        self.assertIn("F-09", tm["privesc_ids"])
        self.assertIn("F-18", tm["privesc_ids"])

        # Verify 3-State Post-Exploitation Privesc Lifecycle on F-06, F-09, F-18
        sec_map = {f["finding_id"]: f for f in self.v2["security_findings"]}
        self.assertEqual(sec_map["F-06"]["access_scope"]["privesc_lifecycle_state"], "TECHNIQUE_VALIDATED")
        self.assertEqual(sec_map["F-09"]["access_scope"]["privesc_lifecycle_state"], "PRECONDITION_DISCOVERED")
        self.assertEqual(sec_map["F-18"]["access_scope"]["privesc_lifecycle_state"], "PRECONDITION_DISCOVERED")

        # Verify Risk Model Residual Floor & Host vs Vector Compromise Distinction
        rm = self.v2["risk_model"]
        self.assertEqual(rm["compromised_host_count"], 1)
        self.assertEqual(rm["compromise_vector_count"], 2)
        self.assertEqual(rm["residual_risk_floor"], 1.5)
        self.assertEqual(rm["sla_projections"][-1]["active_vulnerability_score"], 0.0)
        self.assertEqual(rm["sla_projections"][-1]["projected_score"], 1.5)

        # AC-18: Verify Independent Cryptographic & SQLite Snapshot Integrity
        iv = self.v2["integrity_verification"]
        self.assertTrue(iv["verified"], f"Integrity verification mismatches: {iv.get('mismatches')}")
        self.assertTrue(iv["sqlite_snapshot_verified"])
        self.assertEqual(
            iv["sha256_verified_count"],
            len(self.v2["security_findings"]) + len(self.v2["recon_findings"]),
        )

        em = self.v2["evidence_manifest"]
        self.assertEqual(len(em.get("manifest_root_sha256", "")), 64)
        self.assertEqual(len(em.get("manifest_hmac_sha256", "")), 64)

        sarif = self.v2["sarif_report"]
        self.assertEqual(sarif.get("version"), "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(self.v2["security_findings"]))

        pdf_bytes = prp.generate_pdf_report(self.raw_state)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 100000)
        html_doc = prp.generate_html_report(self.raw_state)
        self.assertIn("EXPEDITE STRIKE V3", html_doc)
        self.assertIn("18/18 PASSED", html_doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
