"""
EXPEDITE STRIKE V2 — Proof-Driven Intelligence Upgrade
Automated Acceptance & Regression Test Suite (Deliverable 4)
"""
import os
import sys
import json
import sqlite3
import tempfile
import unittest

APP_DIR = r"D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app"
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from cyber_range.services import evidence_intelligence as ei
from cyber_range.services import pentest_report_pdf as prp
from cyber_range.services import nvd_enrichment as nvd


class TestXStrikeV2Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        state_path = os.path.join(APP_DIR, "cyber_range", "scan_cache", "autopentest_state.json")
        with open(state_path, "r", encoding="utf-8") as fh:
            cls.raw_state = json.load(fh)

        cls.temp_db = os.path.join(tempfile.gettempdir(), "test_v2_intelligence.db")
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
            assessment_id="TEST-XSTRIKE-V2-ACCEPTANCE",
            db_path=cls.temp_db,
        )

    def test_ac01_no_port_only_confirmed(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            ev = (f.get("evidence") or "").lower()
            pstate = f.get("proof_state", "")
            if "port-open detection only" in ev or "status not verified" in ev:
                self.assertNotIn(pstate, ("CONFIRMED_COMPROMISE", "CONFIRMED_AUTH", "EXPLOITABLE"))

    def test_ac02_confirmed_has_execution_proof_and_scope(self):
        confirmed = [
            f for f in self.v2["security_findings"]
            if f.get("proof_state") in ("CONFIRMED_COMPROMISE", "CONFIRMED_AUTH")
        ]
        self.assertEqual(len(confirmed), 6)
        for f in confirmed:
            self.assertTrue(len((f.get("evidence") or "").strip()) >= 15)
            scope = f.get("access_scope") or {}
            for req_key in ("authenticated", "file_access", "database_access", "privilege_level", "privesc_demonstrated", "access_summary"):
                self.assertIn(req_key, scope)

    def test_ac03_eternalblue_downgraded_and_cvss_zero(self):
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

    def test_ac04_deduplication_zero_duplicate_host_keys(self):
        self.assertEqual(self.v2["raw_observation_count"], 1559)
        self.assertEqual(self.v2["excluded_noise_count"], 89)
        self.assertEqual(self.v2["consolidated_security_count"], 90)
        self.assertEqual(self.v2["consolidated_recon_count"], 25)
        pairs = [(f.get("host"), f.get("canonical_key")) for f in self.v2["security_findings"] + self.v2["recon_findings"]]
        self.assertEqual(len(pairs), len(set(pairs)))
        vsftpd = [f for f in self.v2["security_findings"] if f.get("canonical_key") == "VULN_VSFTPD_234_BACKDOOR" and f.get("host") == "192.168.195.139"]
        self.assertEqual(len(vsftpd), 1)
        self.assertEqual(vsftpd[0]["proof_state"], "CONFIRMED_COMPROMISE")
        self.assertGreaterEqual(vsftpd[0]["merged_observation_count"], 3)

    def test_ac05_scope_and_service_sum_reconciliation(self):
        rec_hosts = self.v2["reconciled_hosts"]
        self.assertEqual(len(rec_hosts), 7)
        self.assertEqual(len([h for h in rec_hosts if h.get("open_port_count", 0) > 0]), 5)
        self.assertEqual(len([h for h in rec_hosts if h.get("open_port_count", 0) == 0]), 2)
        self.assertEqual(sum(h["open_port_count"] for h in rec_hosts), 53)

    def test_ac06_word_boundary_cwe_and_semantic_validator(self):
        self.assertEqual(ei.resolve_safe_cwe("Missing Strict-Transport-Security", "enforce HTTPS", "VULN_MISSING_HSTS"), "CWE-319")
        self.assertEqual(ei.resolve_safe_cwe("JavaScript Source File Disclosure", "source code", "RECON_JS_SOURCE_FILE"), "CWE-200")
        self.assertEqual(ei.resolve_safe_cwe("Missing Permissions-Policy Header", "", "VULN_MISSING_PERMISSIONS_POLICY"), "CWE-16")
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
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

    def test_ac09_specific_remediation_coverage(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            rem_text = " ".join([
                str(f.get("remediation_immediate", "")),
                str(f.get("remediation_short", "")),
                str(f.get("remediation_long", "")),
            ]).lower()
            self.assertNotIn("investigate and apply vendor patches", rem_text)
            self.assertTrue(len(rem_text.strip()) > 30)

    def test_ac10_five_dimensional_confidence_and_nvd_integration(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            c5 = f.get("confidence_5d", {})
            for k in ("detection_confidence", "validation_confidence", "exploitation_confidence", "impact_confidence", "evidence_completeness", "composite_confidence", "false_positive_band"):
                self.assertIn(k, c5)
            if f.get("proof_state") == "OBSERVED":
                self.assertLessEqual(float(f.get("confidence", 100)), 50.0)
                self.assertNotIn(f.get("fp_likelihood"), ("Very Low (<5%)", "Low (5-15%)"))
                c_score, _ = nvd.get_confidence_score(f)
                self.assertLessEqual(c_score, 50)

    def test_ac11_attack_graph_provenance_and_4_stages(self):
        ag = self.v2["attack_graph"]
        self.assertEqual(ag["consolidated_chain_count"], 6)
        self.assertGreaterEqual(len(ag["edges"]), 20)
        for ch in ag["chains"]:
            edges = ch.get("edges", [])
            self.assertGreaterEqual(len(edges), 2)
            for edg in edges:
                self.assertTrue(bool(edg.get("evidence_ref")))
                self.assertIn(edg.get("validation_state"), ("CONFIRMED_EXECUTED", "PARTIALLY_VALIDATED", "INFERRED_NOT_EXECUTED"))

    def test_ac12_risk_score_and_sla_monotonic_math(self):
        rm = self.v2["risk_model"]
        raw_sum = round(rm["s_compromise"] + rm["s_exposure"] + rm["s_asset"] + rm["s_reachability"], 1)
        self.assertAlmostEqual(rm["overall_score"], min(100.0, raw_sum), places=1)
        sla = rm["sla_projections"]
        self.assertEqual(len(sla), 4)
        self.assertGreaterEqual(sla[0]["projected_score"], sla[1]["projected_score"])
        self.assertGreaterEqual(sla[1]["projected_score"], sla[2]["projected_score"])
        self.assertGreaterEqual(sla[2]["projected_score"], sla[3]["projected_score"])

    def test_ac13_sqlite_persistence_and_pdf_generation(self):
        qa = self.v2["quality_audit"]
        self.assertTrue(qa["passed"])
        self.assertEqual(qa["passed_rules"], 13)
        self.assertEqual(qa["total_rules"], 13)
        self.assertTrue(os.path.exists(self.v2["sqlite_db_path"]))
        conn = sqlite3.connect(self.v2["sqlite_db_path"])
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM v2_consolidated_findings WHERE assessment_id=?", ("TEST-XSTRIKE-V2-ACCEPTANCE",))
        self.assertEqual(cur.fetchone()[0], 115)
        cur.execute("SELECT passed_rules FROM v2_report_quality_audit WHERE assessment_id=?", ("TEST-XSTRIKE-V2-ACCEPTANCE",))
        self.assertEqual(cur.fetchone()[0], 13)
        conn.close()
        pdf_bytes = prp.generate_pdf_report(self.raw_state)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 100000)
        html_doc = prp.generate_html_report(self.raw_state)
        self.assertIn("EXPEDITE STRIKE V2", html_doc)
        self.assertIn("13/13 PASSED", html_doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
