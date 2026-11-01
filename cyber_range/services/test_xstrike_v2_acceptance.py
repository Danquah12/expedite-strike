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

    def test_ac13_to_ac18_manifest_sarif_transition_reconciliation_and_25_rule_quality_gate(self):
        qa = self.v2["quality_audit"]
        self.assertTrue(qa["passed"], f"Failed rules: {[c for c in qa['checks'] if not c['passed']]}")
        self.assertEqual(qa["passed_rules"], 25)
        self.assertEqual(qa["total_rules"], 25)

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

        # Verify V3.5 Multi-Host Benchmark & 7-Step Retest Lifecycle
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
        self.assertIn("EXPEDITE STRIKE V3.5", html_doc)
        self.assertIn("25/25 PASSED", html_doc)

    def test_v33_ten_formal_regression_tests_reg01_to_reg10(self):
        """
        Execute all 10 formal V3.3 regression tests (REG-01 through REG-10) requested in the V3.2 technical review:
          REG-01: Finding ID consistency across database, report, retest ledger, manifest, and risk calculation
          REG-02: Risk calculation consistency across cover, executive summary, SLA table, and section text
          REG-03: Retest rejection when target host is offline (RETEST-03-NEG-CTRL)
          REG-04: Retest rejection when fix is partial (RETEST-04-PARTIAL)
          REG-05: Retest rejection when vulnerability still reproduces (RETEST-05-FAILED)
          REG-06: Standalone bundle verification failure on 1-byte evidence modification
          REG-07: Standalone bundle verification failure on record deletion or reordering
          REG-08: Standalone bundle verification failure on manifest modification or public-key substitution
          REG-09: Attack-graph non-inheritance of executed status to inferred/precondition steps
          REG-10: Exploitability gate blocking scanner-only/heuristic findings from EXPLOITABLE or CONFIRMED_*
        """
        sec_map = {f["finding_id"]: f for f in self.v2["security_findings"]}
        rw = self.v2["remediation_workflow"]
        rm = self.v2["risk_model"]
        sv = self.v2["standalone_verification"]

        # REG-01: Finding ID consistency across Section 3A, Retest Ledger, Lifecycle, and SLA table
        for rec in rw["retest_records"]:
            fid = rec["finding_id"]
            self.assertIn(fid, sec_map, f"REG-01 failed: Retest finding {fid} not in security_findings")
            self.assertEqual(sec_map[fid]["canonical_key"], rec["canonical_key"])
            self.assertEqual(sec_map[fid]["host"], rec["host"])
            # Ensure dynamic ID appears in SLA T1 target_scope
            self.assertIn(fid, rm["sla_projections"][1]["target_scope"])

        # REG-02: Risk calculation mathematical reconciliation & zero missing T1 keys
        self.assertGreater(float(rm["post_retest_s_exposure_raw_sum"]), 0.0, "REG-02 failed: T1 RawSum must not be 0")
        self.assertLess(float(rm["post_retest_s_exposure_raw_sum"]), float(rm["s_exposure_raw_sum"]))
        expected_delta = round(float(rm["principal_calibrated_score"]) - float(rm["post_retest_calibrated_score"]), 1)
        self.assertEqual(float(rm["verified_risk_reduction_pts"]), expected_delta)
        self.assertEqual(float(rm["verified_risk_reduction_calibrated_pts"]), expected_delta)
        self.assertEqual(rm["sla_projections"][0]["calibrated_score"], rm["principal_calibrated_score"])
        self.assertEqual(rm["sla_projections"][1]["calibrated_score"], rm["post_retest_calibrated_score"])

        # REG-03: Retest rejection when target host is offline (RETEST-03-NEG-CTRL)
        r03 = next(r for r in rw["retest_records"] if r["retest_id"] == "RETEST-03-NEG-CTRL")
        self.assertFalse(r03["host_online_confirmed"])
        self.assertIn("REJECTED_HOST_OFFLINE", r03["step6_transition_decision"])
        self.assertEqual(sec_map[r03["finding_id"]]["post_retest_proof_state"], sec_map[r03["finding_id"]]["baseline_proof_state"])
        self.assertNotEqual(sec_map[r03["finding_id"]]["post_retest_proof_state"], "REMEDIATION_VERIFIED")
        self.assertFalse(sec_map[r03["finding_id"]]["remediation_verified"])

        # REG-04: Retest rejection when fix is partial (RETEST-04-PARTIAL)
        r04 = next(r for r in rw["retest_records"] if r["retest_id"] == "RETEST-04-PARTIAL")
        self.assertTrue(r04["host_online_confirmed"])
        self.assertFalse(r04["vulnerability_eliminated"])
        self.assertIn("PARTIALLY_REMEDIATED_NOT_CLOSED", r04["step6_transition_decision"])
        self.assertEqual(sec_map[r04["finding_id"]]["post_retest_proof_state"], "VALIDATED")

        # REG-05: Retest rejection when vulnerability still reproduces (RETEST-05-FAILED)
        r05 = next(r for r in rw["retest_records"] if r["retest_id"] == "RETEST-05-FAILED")
        self.assertTrue(r05["host_online_confirmed"])
        self.assertFalse(r05["vulnerability_eliminated"])
        self.assertIn("RETEST_FAILED_STILL_VULNERABLE", r05["step6_transition_decision"])
        self.assertEqual(sec_map[r05["finding_id"]]["post_retest_proof_state"], "CONFIRMED_AUTH")

        # Also verify RETEST-02 tested all 5 endpoints (/robots.txt, /admin, /backup, /config, /private)
        r02 = next(r for r in rw["retest_records"] if r["retest_id"] == "RETEST-02")
        for ep_path in ("/robots.txt", "/admin", "/backup", "/config", "/private"):
            self.assertIn(ep_path, r02["after_evidence"])

        # REG-06, REG-07, REG-08: Standalone bundle verification & 5 negative tamper tests + pinned key fingerprint
        self.assertTrue(sv["standalone_verified"])
        self.assertTrue(sv["pinned_public_key_fingerprint_verified"])
        self.assertTrue(sv["all_tamper_tests_passed"])
        tamper = sv["tamper_negative_self_tests"]
        self.assertTrue(tamper["modified_record_rejected"], "REG-06 failed")
        self.assertTrue(tamper["deleted_record_rejected"], "REG-07a failed")
        self.assertTrue(tamper["reordered_records_rejected"], "REG-07b failed")
        self.assertTrue(tamper["altered_manifest_rejected"], "REG-08a failed")
        self.assertTrue(tamper["substituted_public_key_rejected"], "REG-08b failed")

        # REG-09: Attack-graph non-inheritance & lateral movement terminology
        lat_matrix = self.v2["attack_graph"].get("cross_host_lateral_movement_matrix", [])
        self.assertEqual(len(lat_matrix), 5)
        p_cyber01 = next(m for m in lat_matrix if m["pivot_id"] == "PIVOT-CYBER-01")
        self.assertEqual(p_cyber01["lateral_outcome"], "LATERAL_PRECONDITION_VALIDATED_NOT_EXECUTED")
        p_cyber02 = next(m for m in lat_matrix if m["pivot_id"] == "PIVOT-CYBER-02")
        self.assertEqual(p_cyber02["lateral_outcome"], "TESTED_ROUTES_BLOCKED_BY_CONTROL")
        p_bench01 = next(m for m in lat_matrix if m["pivot_id"] == "PIVOT-BENCH-01")
        self.assertEqual(p_bench01["lateral_outcome"], "LATERAL_MOVEMENT_SUCCEEDED")
        self.assertTrue(bool(p_bench01.get("source_host_transcript")))
        self.assertTrue(bool(p_bench01.get("destination_host_transcript")))

        # REG-10: Exploitability gate & Issue 6 specific vulnerability classifications (SMBv1, Slowloris, SQLi/SSRF)
        smbv1_list = [f for f in self.v2["security_findings"] if f["canonical_key"] == "VULN_SMBV1_ENABLED"]
        self.assertGreaterEqual(len(smbv1_list), 1)
        for f_smb in smbv1_list:
            self.assertEqual(f_smb["cve"], "", "SMBv1 dialect must not carry CVE-2017-0144")
            self.assertEqual(f_smb["severity"], "Medium")
            self.assertEqual(float(f_smb["cvss_score"]), 5.3)
        slow_list = [f for f in self.v2["security_findings"] if f["canonical_key"] == "VULN_HTTP_SLOWLORIS"]
        self.assertGreaterEqual(len(slow_list), 1)
        for f_sl in slow_list:
            self.assertEqual(f_sl["proof_state"], "OBSERVED")
            self.assertEqual(f_sl["severity"], "Medium")
            self.assertEqual(float(f_sl["cvss_score"]), 5.9)
            self.assertFalse(f_sl["exploitability_validation"]["exploitability_claimed"])

        # REG-11 (V3.5 EPIC 01): Universal Version Consistency (VERSION_REGISTRY = V3.5) across Manifest, RiskEngine, Verifier, Capabilities & Benchmark
        em = self.v2["evidence_manifest"]
        self.assertEqual(em["manifest_version"], "EvidenceCore-V3.5")
        self.assertIn("MANIFEST-XSTRIKE-V3.5-", em["manifest_id"])
        self.assertEqual(rm["formula_version"], "RiskEngine-V3.5-Calibrated-NonSaturating")
        self.assertEqual(sv["verifier_version"], "XStrike-Standalone-Verifier-V3.5")

        # REG-12 (V3.5 EPIC 05): Forecast trajectory mathematical reconciliation across SLA table and Quality Gate AC-09
        sla = rm["sla_projections"]
        self.assertEqual(rm["forecast_24h_calibrated_score"], sla[2]["calibrated_score"])
        self.assertEqual(rm["forecast_7d_calibrated_score"], sla[3]["calibrated_score"])
        self.assertEqual(rm["forecast_30d_calibrated_score"], sla[4]["calibrated_score"])
        ac09_chk = next(c for c in self.v2["quality_audit"]["checks"] if c["rule_id"] == "AC-09")
        self.assertIn(f"24h ({sla[2]['calibrated_score']})", ac09_chk["detail"])
        self.assertIn(f"7d ({sla[3]['calibrated_score']})", ac09_chk["detail"])
        self.assertIn(f"30d ({sla[4]['calibrated_score']})", ac09_chk["detail"])

        # REG-13 (V3.5 EPIC 02): MITRE semantic validation (zero T1068, T1033, or T1190 on direct-root non-web chains; T1210 on vsFTPd & Java RMI)
        for ch in self.v2["attack_graph"]["chains"]:
            if ch["chain_id"] in ("CHAIN-01", "CHAIN-02"):
                for edge in ch["edges"]:
                    self.assertNotIn(edge["technique_id"], ("T1068", "T1033", "T1190"), f"{ch['chain_id']} direct root daemon must not use {edge['technique_id']}")
                self.assertEqual(ch["edges"][2]["technique_id"], "T1059.004")
                self.assertEqual(ch["edges"][2]["privilege_context"]["uid"], 0)
                self.assertEqual(ch["edges"][2]["privilege_context"]["source"], "vulnerable_network_daemon")
                self.assertEqual(ch["edges"][2]["privilege_context"]["privilege_transition"], "NONE")
        for f_rem in [f for f in self.v2["security_findings"] if f["canonical_key"] in ("VULN_VSFTPD_234_BACKDOOR", "VULN_JAVA_RMI_EXPOSED")]:
            self.assertEqual(f_rem["mitre_id"], "T1210")

        # REG-14 (V3.5 EPIC 03): 4-Stage Remediation Lifecycle Gates & REMEDIATION_INCONCLUSIVE on offline host
        self.assertTrue(r05["change_applied"])
        self.assertFalse(r05["service_reloaded"])
        self.assertIn("CHANGE_APPLIED_ONLY_SERVICE_NOT_RELOADED", r05["remediation_lifecycle_stage"])
        self.assertTrue(r04["change_applied"])
        self.assertTrue(r04["service_reloaded"])
        self.assertIn("PARTIAL_ONLY", r04["control_effective"])
        self.assertEqual(r03["retest_outcome_state"], "REMEDIATION_INCONCLUSIVE")
        self.assertIn("REMEDIATION_INCONCLUSIVE", r03["remediation_lifecycle_stage"])
        self.assertIn("REJECTED_HOST_OFFLINE", r03["remediation_lifecycle_stage"])

        # REG-15 (V3.5 EPIC 04): Key custody provenance separation (Lab vs Prod) & Retest Integrity (5/5) vs Closures Accepted (2/5)
        self.assertIn("LAB_PINNED_ED25519_KEYSTORE", sv["active_deployment_custody_tier"])
        self.assertIn("Not Deployed in Lab", sv["enterprise_production_target_architecture"])
        self.assertIn("2/5 Verified Closures Accepted", sv["remediation_closures_accepted_summary"])

        # REG-16 (V3.5 EPIC 01): Zero stale version strings (V3.1, V3.2, V3.3, v3.3, V3.4) in capabilities, benchmark, lateral matrix, or HTML
        v3_arch = self.v2["v3_architecture"]
        for cap in v3_arch["v3_capabilities"]:
            self.assertIn("v3.5", cap["status"])
            for stale_tok in ("v3.3", "V3.3", "V3.2", "V3.4"):
                self.assertNotIn(stale_tok, cap["name"] + " " + cap["status"] + " " + cap["summary"])
        self.assertEqual(v3_arch["v31_multihost_benchmark"]["benchmark_id"], "XSTRIKE-V3.5-MULTIHOST-ENTERPRISE-RANGE")

        # REG-17 (V3.5 EPIC 03): Proof-state normalization — zero user-facing EXPLOITABLE; SUID Nmap uses PRIVILEGE_ESCALATION_PRECONDITION_VALIDATED
        raw_expl = [f for f in self.v2["security_findings"] if f["proof_state"] == "EXPLOITABLE"]
        self.assertEqual(len(raw_expl), 0, "Zero findings may use ambiguous user-facing EXPLOITABLE proof state in V3.5")
        f_nmap = next(f for f in self.v2["security_findings"] if f["canonical_key"] == "VULN_PRIVESC_SUID_NMAP")
        self.assertEqual(f_nmap["proof_state"], "PRIVILEGE_ESCALATION_PRECONDITION_VALIDATED")
        self.assertIn("LOCAL_ESCALATION_PRECONDITION", f_nmap["access_scope"]["privilege_level"])
        self.assertIn("root transition not executed", f_nmap["access_scope"]["privilege_level"])

        # REG-18 (V3.5 EPIC 03): Standardized 4-tier compliance enum & technical control mapping on 100% of findings
        allowed_comp = {"EVIDENCE_OF_CONTROL_FAILURE", "POTENTIAL_CONTROL_GAP", "CONTROL_NOT_ASSESSED", "NO_FAILURE_OBSERVED"}
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            self.assertIn(f["compliance_status"], allowed_comp)
            self.assertTrue(bool(f.get("compliance_technical_control")))

        # REG-19 (V3.5 EPIC 04): 9/9 Tamper & Key-Lifecycle Governance Self-Tests in Standalone Verifier
        for req_test in (
            "modified_record_rejected", "deleted_record_rejected", "reordered_records_rejected",
            "altered_manifest_rejected", "substituted_public_key_rejected",
            "expired_key_window_rejected", "revoked_key_crl_rejected",
            "forged_timestamp_rejected", "deterministic_reproducibility_verified",
        ):
            self.assertTrue(tamper.get(req_test), f"REG-19 failed on {req_test}")
        self.assertTrue(sv["key_rotation_window_verified"])
        self.assertTrue(sv["key_revocation_crl_verified"])
        self.assertTrue(sv["rfc3161_timestamp_token_verified"])
        self.assertTrue(sv["deterministic_reproducibility_verified"])

        # REG-20 (V3.5 EPIC 05 & EPIC 06): Modeled Architectural Floor Assumption & 4-Host Benchmark Seeded Manifest Isolation
        self.assertEqual(sla[2]["forecast_classification"], "HYPOTHETICAL_REMEDIATION_SCENARIO_FORECAST")
        self.assertEqual(sla[3]["forecast_classification"], "HYPOTHETICAL_REMEDIATION_SCENARIO_FORECAST")
        self.assertEqual(sla[4]["forecast_classification"], "MODELED_ARCHITECTURAL_FLOOR_ASSUMPTION")
        self.assertIn("MODELED_ARCHITECTURAL_FLOOR_ASSUMPTION", rm.get("forecast_governance_policy", ""))
        self.assertEqual(len(v3_arch["v31_multihost_benchmark"].get("seeded_vulnerability_manifest", [])), 4)
        self.assertTrue(bool(v3_arch["v31_multihost_benchmark"].get("scenario_isolation_boundary")))

        # REG-21 (V3.5.1 EPIC 01): Per-record version_provenance on 100% of findings & hot-reload protection on verify_manifest
        for f in self.v2["security_findings"] + self.v2["recon_findings"]:
            vp = f.get("version_provenance", {})
            self.assertEqual(vp.get("verifier_version"), "XStrike-Standalone-Verifier-V3.5")
            self.assertEqual(vp.get("evidence_core_version"), "EvidenceCore-V3.5")

        # REG-22 (V3.5.1 EPIC 02): 9-Test Structured Certification Ledger (CERT-01..CERT-09) with strict Zero-None Policy & Key Audit Log
        cert_ledger = sv.get("certification_test_ledger", [])
        self.assertEqual(len(cert_ledger), 9)
        for idx, ct in enumerate(cert_ledger, start=1):
            self.assertEqual(ct["test_id"], f"CERT-0{idx}")
            self.assertIsNotNone(ct["actual_result"], f"{ct['test_id']} actual_result must never be None")
            self.assertNotIn("NONE", str(ct["actual_result"]).upper(), f"{ct['test_id']} must not be NONE")
            self.assertTrue(ct["passed"] is True, f"{ct['test_id']} passed must be True")
            self.assertEqual(ct["certification_decision"], "CERTIFIED_PASS")
            self.assertEqual(ct["failure_reason"], "NONE")
            self.assertTrue(bool(ct.get("evidence_reference")))
        self.assertEqual(len(sv.get("key_operations_audit_log", [])), 3)

        # REG-23 (V3.5.1 EPIC 03): 3-Layer AttackGraph Architecture & Per-Action Risk-Reduction Attribution
        three_layers = self.v2["attack_graph"].get("three_layer_architecture", [])
        self.assertEqual(len(three_layers), 3)
        self.assertEqual(three_layers[0]["layer_id"], "Layer 1: ENTRY_LAYER")
        self.assertEqual(three_layers[1]["layer_id"], "Layer 2: PRIVILEGE_AND_MOVEMENT_LAYER")
        self.assertEqual(three_layers[2]["layer_id"], "Layer 3: IMPACT_LAYER")
        for edge in self.v2["attack_graph"]["edges"]:
            self.assertIn(edge.get("graph_layer"), ("Layer 1: ENTRY_LAYER", "Layer 2: PRIVILEGE_AND_MOVEMENT_LAYER", "Layer 3: IMPACT_LAYER"))
        per_act = rm.get("per_action_risk_attribution", [])
        self.assertEqual(len(per_act), 5)
        self.assertEqual(per_act[0]["s_compromise_delta_pts"], -16.0)
        self.assertEqual(per_act[0]["s_reachability_delta_pts"], -5.0)
        self.assertLess(per_act[1]["raw_exposure_delta_pts"], 0.0)

        # REG-24 (V3.5.1 EPIC 04): Remediation Work Packages (WP-01..WP-06) & 5-Dimension Root-Cause Matrix
        wps = self.v2.get("remediation_work_packages", [])
        self.assertEqual(len(wps), 6)
        total_wp_findings = sum(w["finding_count"] for w in wps)
        self.assertEqual(total_wp_findings, len(self.v2["security_findings"]))
        rc_5d = self.v2.get("root_cause_5d_matrix", [])
        self.assertGreaterEqual(len(rc_5d), 3)
        for r5 in rc_5d:
            self.assertTrue(bool(r5.get("technical_control_failure")))
            self.assertTrue(bool(r5.get("business_consequence")))
            self.assertTrue(bool(r5.get("remediation_owner")))
            self.assertTrue(bool(r5.get("remediation_dependency_and_work_package")))

        # REG-25 (V3.5.1 EPIC 05): Executive Priority Risk View (3 Separated Risk Panels + High-Impact vs Config Hygiene WP-06)
        exec_prio = self.v2.get("executive_priority_view", {})
        self.assertEqual(len(exec_prio.get("three_risk_panels", [])), 3)
        self.assertGreaterEqual(len(exec_prio.get("priority_compromise_and_auth_findings", [])), 6)
        self.assertIn("WP-06", str(exec_prio.get("config_hygiene_consolidation_summary", "")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
