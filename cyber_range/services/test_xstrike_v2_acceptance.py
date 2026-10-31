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
            self.assertEqual(f.get("severity"), "Info")
            self.assertEqual(f.get("conditional_severity"), "Critical")
            self.assertEqual(float(f.get("conditional_cvss_score", -1)), 9.8)
            self.assertIn("OBSERVED_EXPOSURE", f.get("exposure_classification", ""))
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
        self.assertGreaterEqual(self.v2["raw_observation_count"], 1641)
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

    def test_ac09_100pct_specific_remediation_coverage_and_defects_3_4_5(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            rem_text = " ".join([
                str(f.get("remediation_immediate", "")),
                str(f.get("remediation_short", "")),
                str(f.get("remediation_long", "")),
            ]).lower()
            self.assertNotIn("investigate and apply vendor patches", rem_text)
            self.assertNotIn("restrict network exposure to the affected service port using host firewall rules", rem_text)
            self.assertTrue(len(rem_text.strip()) > 30)
            # Defect 4: Verification command must match the finding's canonical host
            ver_cmd = str(f.get("remediation_verification", ""))
            self.assertIn(f["host"], ver_cmd, f"Host {f['host']} missing in verification for {f['finding_id']}: {ver_cmd}")
            if f["host"] != "192.168.195.139":
                self.assertNotIn("192.168.195.139", ver_cmd, f"Wrong host 192.168.195.139 in verification for {f['finding_id']}")
            # Defect 5: VNC/X11/SSH/MySQL must never have Apache backup instructions
            ckey = f.get("canonical_key", "")
            if ckey in ("VULN_VNC_AUTH_BYPASS", "VULN_X11_EXPOSED", "VULN_MYSQL_EXPOSED", "VULN_OPENSSH_LEGACY"):
                self.assertNotIn("/etc/apache2/", str(f.get("remediation_rollback", "")).lower())

        # Defect 3: Verify OpenSSH 5.3p1, Apache 2.2.14, and PHP 5.3.2 on 192.168.195.140
        f_ssh_140 = [f for f in self.v2["security_findings"] if f["host"] == "192.168.195.140" and f["canonical_key"] == "VULN_OPENSSH_LEGACY"]
        if f_ssh_140:
            self.assertIn("5.3p1", f_ssh_140[0]["title"])
            self.assertNotIn("4.7p1", f_ssh_140[0]["title"])
        f_ap_140 = [f for f in self.v2["security_findings"] if f["host"] == "192.168.195.140" and f["canonical_key"] == "VULN_APACHE_OUTDATED"]
        if f_ap_140:
            self.assertIn("2.2.14", f_ap_140[0]["title"])
            self.assertNotIn("2.2.8", f_ap_140[0]["title"])
        f_php_140 = [f for f in self.v2["security_findings"] if f["host"] == "192.168.195.140" and f["canonical_key"] == "VULN_PHP_CGI_CVE_2012_1823"]
        if f_php_140:
            self.assertIn("5.3.2", f_php_140[0]["title"])
            self.assertNotIn("5.2.4", f_php_140[0]["title"])

    def test_ac10_separated_confidence_and_nvd_band_consistency(self):
        for f in self.v2["security_findings"]:
            c5 = f.get("confidence_5d", {})
            for k in (
                "detection_confidence", "validation_confidence", "exploitation_confidence",
                "impact_confidence", "evidence_completeness", "composite_confidence",
                "evidence_confidence", "exploitability_confidence", "false_positive_band"
            ):
                self.assertIn(k, c5)
            # NVD CVSS v3.1 score-to-severity band check (zero exemptions)
            sc = float(f.get("cvss_score", 0.0))
            sev = f.get("severity")
            if sev == "Critical":
                self.assertTrue(9.0 <= sc <= 10.0, f"{f.get('finding_id')} Critical has CVSS {sc}")
            elif sev == "High":
                self.assertTrue(7.0 <= sc <= 8.9, f"{f.get('finding_id')} High has CVSS {sc}")
            elif sev == "Medium":
                self.assertTrue(4.0 <= sc <= 6.9, f"{f.get('finding_id')} Medium has CVSS {sc}")
            elif sev == "Low":
                self.assertTrue(0.1 <= sc <= 3.9, f"{f.get('finding_id')} Low has CVSS {sc}")
            elif sev == "Info":
                self.assertEqual(sc, 0.0, f"{f.get('finding_id')} Info has CVSS {sc}")

    def test_ac11_attack_graph_v3_metrics_choke_points_and_neo4j_cypher(self):
        ag = self.v2["attack_graph"]
        self.assertEqual(ag["consolidated_chain_count"], 6)
        self.assertGreaterEqual(len(ag["edges"]), 20)
        self.assertGreaterEqual(len(ag.get("remediation_choke_points", [])), 3)
        for ch in ag["chains"]:
            for k in ("path_feasibility", "path_confidence", "privilege_reached", "asset_impact", "path_length", "remediation_leverage", "path_priority", "weakest_link_state", "non_inheritance_verified"):
                self.assertIn(k, ch)
            self.assertTrue(ch["non_inheritance_verified"])
        neo4j = ag.get("neo4j_graph_model", {})
        self.assertIn("Neo4j", neo4j.get("engine", ""))
        self.assertIn("CREATE CONSTRAINT", neo4j.get("cypher_seed_script", ""))
        self.assertEqual(len(neo4j.get("analytical_queries", [])), 3)

    def test_ac12_endpoint_hygiene_zero_external_reference_urls(self):
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            for ep in f.get("affected_endpoints", []):
                ep_l = str(ep).lower()
                self.assertNotIn("w3.org", ep_l)
                self.assertNotIn("nmap.org", ep_l)
                self.assertFalse(ep_l.startswith("/"), f"Unbound relative path in endpoint: {ep}")

    def test_ac13_to_ac18_manifest_sarif_transition_reconciliation_and_20_rule_quality_gate(self):
        qa = self.v2["quality_audit"]
        self.assertTrue(qa["passed"], f"Failed rules: {[c for c in qa['checks'] if not c['passed']]}")
        self.assertEqual(qa["passed_rules"], 20)
        self.assertEqual(qa["total_rules"], 20)

        # AC-17: Verify Dynamic Transition Model has zero stale hardcoded IDs
        tm = self.v2["transition_model"]
        self.assertTrue(tm["reconciled"], f"Transition reconciliation errors: {tm.get('reconciliation_errors')}")
        self.assertEqual(tm["confirmed_compromise_ids"], ["F-01", "F-02"])
        self.assertEqual(len(tm["confirmed_auth_ids"]), 4)
        self.assertEqual(len(tm["privesc_ids"]), 3)

        # Verify 3-State Post-Exploitation Privesc Lifecycle & READ_CONFIRMED + Redaction on F-01, F-02
        sec_map = {f["finding_id"]: f for f in self.v2["security_findings"]}
        self.assertIn("READ_CONFIRMED", sec_map["F-01"]["access_scope"]["file_access"])
        self.assertIn("READ_CONFIRMED", sec_map["F-02"]["access_scope"]["file_access"])
        self.assertIn("[REDACTED_SHADOW_HASH]", sec_map["F-01"]["evidence"])
        self.assertIn("EVIDENCE_BASED_CLOSURE_ONLY", sec_map["F-01"]["remediation_closure_rule"])
        self.assertIn("Finding F-01", sec_map["F-01"]["remediation_closure_rule"])
        self.assertTrue(bool(sec_map["F-01"]["compliance_limitation"]))

        # Verify Risk Model Residual Floor, Calibrated Principal Score & Measured/Projected/Verified States
        rm = self.v2["risk_model"]
        self.assertEqual(rm["compromised_host_count"], 1)
        self.assertEqual(rm["compromise_vector_count"], 2)
        self.assertEqual(rm["residual_risk_floor"], 1.5)
        self.assertIn("principal_calibrated_score", rm)
        self.assertEqual(rm["sla_projections"][0]["risk_measurement_state"], "MEASURED_RISK")
        self.assertEqual(rm["sla_projections"][1]["risk_measurement_state"], "REMEDIATION_VERIFIED_RISK")
        self.assertEqual(rm["sla_projections"][4]["active_vulnerability_score"], 0.0)
        self.assertEqual(rm["sla_projections"][4]["projected_score"], 1.5)

        # AC-18: Verify Independent Cryptographic (Ed25519 + SHA-256 + HMAC) & SQLite Snapshot Integrity
        iv = self.v2["integrity_verification"]
        self.assertTrue(iv["verified"], f"Integrity verification mismatches: {iv.get('mismatches')}")
        self.assertTrue(iv["manifest_ed25519_verified"])
        self.assertTrue(iv["sqlite_snapshot_verified"])
        self.assertEqual(
            iv["sha256_verified_count"],
            len(self.v2["security_findings"]) + len(self.v2["recon_findings"]),
        )

        em = self.v2["evidence_manifest"]
        self.assertEqual(len(em.get("manifest_root_sha256", "")), 64)
        self.assertEqual(len(em.get("manifest_hmac_sha256", "")), 64)
        self.assertEqual(len(em.get("manifest_ed25519_signature", "")), 128)
        self.assertEqual(len(em.get("ed25519_public_key_hex", "")), 64)

        # Verify V3.2 Multi-Host Benchmark & 7-Step Retest Lifecycle
        v3_arch = self.v2["v3_architecture"]
        self.assertEqual(len(v3_arch["v31_multihost_benchmark"]["hosts"]), 4)
        self.assertEqual(len(v3_arch["v31_multihost_benchmark"]["remediation_retest_lifecycle"]), 7)

        sarif = self.v2["sarif_report"]
        self.assertEqual(sarif.get("version"), "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(self.v2["security_findings"]))

        pdf_bytes = prp.generate_pdf_report(self.raw_state)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 100000)
        html_doc = prp.generate_html_report(self.raw_state)
        self.assertIn("EXPEDITE STRIKE V3", html_doc)
        self.assertIn("20/20 PASSED", html_doc)

    def test_ac19_ac20_v32_six_priorities_verification_retest_and_risk_recalculation(self):
        # Priority 1: Standalone Database-Free Bundle Verifier (verify_manifest.py)
        sv = self.v2["standalone_verification"]
        self.assertTrue(sv["standalone_verified"])
        self.assertEqual(sv["database_dependency"], "NONE (Verified 100% from exported JSON bundle + Ed25519 public key PEM)")
        self.assertEqual(sv["record_sha256_verified_count"], 124)
        self.assertTrue(sv["merkle_root_matched"])
        self.assertTrue(sv["ed25519_public_key_verified"])
        self.assertEqual(sv["remediation_records_verified"], "3/3")

        # Priority 2 & 3: Exploitability Validation Gate & 4-State MITRE Execution Provenance
        for f in self.v2["security_findings"]:
            ev_gate = f.get("exploitability_validation", {})
            self.assertEqual(ev_gate.get("exploitability_claimed"), ev_gate.get("promotion_criteria_met"))
            self.assertIn(
                f.get("mitre_execution_state"),
                ("EXECUTED_WITH_PROOF", "TECHNIQUE_VALIDATED", "ATTEMPTED_BLOCKED_OR_UNVERIFIED", "MAPPED_ONLY"),
            )

        # Priority 4: Multi-Host Lateral Movement Succeeded vs. Blocked by Controls
        lat_matrix = self.v2["attack_graph"].get("cross_host_lateral_movement_matrix", [])
        self.assertEqual(len(lat_matrix), 5)
        outcomes = [m["lateral_outcome"] for m in lat_matrix]
        self.assertTrue(any("LATERAL_MOVEMENT_SUCCEEDED" in o for o in outcomes))
        self.assertTrue(any("LATERAL_MOVEMENT_BLOCKED_BY_CONTROL" in o for o in outcomes))

        # Priority 5 & 6: 7-Step Remediation Verification, Negative-Control Offline Host Rejection & Before/After Risk
        rw = self.v2["remediation_workflow"]
        self.assertEqual(rw["remediation_verified_count"], 2)
        self.assertEqual(rw["negative_control_rejected_count"], 1)
        self.assertEqual(self.v2["proof_state_counts"]["REMEDIATION_VERIFIED"], 2)
        rm = self.v2["risk_model"]
        self.assertEqual(rm["principal_calibrated_score"], 96.9)
        self.assertEqual(rm["post_retest_calibrated_score"], 75.7)
        self.assertLess(rm["post_retest_calibrated_score"], rm["principal_calibrated_score"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
