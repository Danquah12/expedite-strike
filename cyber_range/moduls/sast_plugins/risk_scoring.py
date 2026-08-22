"""
risk_scoring.py — CVSS-like Risk Scoring Post-processor

This plugin adds CVSS v3.1-aligned scores and enriched severity to every
finding produced by the scanner. It does not generate findings of its own.

Usage:
    from sast_plugins.risk_scoring import score_finding, score_all_findings
    enriched = score_all_findings(findings)
"""
from .base_plugin import BasePlugin


# ── CVSS v3.1-style base score table ─────────────────────────────────────────
# Keyed by rule_id prefix OR vulnerability keyword.
# Structure: (severity_override, cvss_score, vector_string_short)
CVSS_TABLE: dict[str, tuple[str, float, str]] = {

    # ── Taint Analysis ────────────────────────────────────────────────────────
    "PI-TA-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # SQLi
    "PI-TA-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # SQLi many
    "PI-TA-003": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # os.system
    "PI-TA-004": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # Popen
    "PI-TA-005": ("CRITICAL", 9.0, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # call
    "PI-TA-006": ("CRITICAL", 9.0, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # run
    "PI-TA-007": ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # open
    "PI-TA-008": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # eval
    "PI-TA-009": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # exec
    "PI-TA-010": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # SSTI
    "PI-TA-011": ("HIGH",     8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),  # loads
    "PI-TA-012": ("MEDIUM",   5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),  # format
    "PI-TA-013": ("MEDIUM",   6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),  # redirect
    "PI-TA-014": ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),  # send_file

    # ── SQL Injection ─────────────────────────────────────────────────────────
    "PI-SQL-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-SQL-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-SQL-003": ("HIGH",     8.8, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "PI-SQL-004": ("HIGH",     8.8, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "PI-SQL-005": ("MEDIUM",   6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),

    # ── XSS ──────────────────────────────────────────────────────────────────
    "PI-XSS-001": ("HIGH",     7.4, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "PI-XSS-002": ("HIGH",     7.4, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "PI-XSS-003": ("HIGH",     7.4, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    "PI-XSS-004": ("CRITICAL", 9.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "PI-XSS-005": ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    "PI-XSS-006": ("MEDIUM",   6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "PI-XSS-007": ("HIGH",     7.4, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),

    # ── Secrets ───────────────────────────────────────────────────────────────
    "PI-SEC-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-003": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-004": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-005": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-006": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-007": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-008": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-SEC-009": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),

    # ── Command Injection ─────────────────────────────────────────────────────
    "PI-CMD-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-003": ("HIGH",     9.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-004": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-005": ("HIGH",     8.8, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-006": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-CMD-007": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-CMD-008": ("HIGH",     9.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),

    # ── Crypto ────────────────────────────────────────────────────────────────
    "PI-CRY-001": ("HIGH",     7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-CRY-002": ("HIGH",     7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-CRY-003": ("CRITICAL", 9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-CRY-004": ("CRITICAL", 9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-CRY-005": ("MEDIUM",   5.3, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "PI-CRY-006": ("MEDIUM",   5.3, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "PI-CRY-007": ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-CRY-008": ("CRITICAL", 9.0, "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),

    # ── Deserialization ───────────────────────────────────────────────────────
    "PI-DES-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DES-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DES-003": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DES-004": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DES-005": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DES-006": ("HIGH",     8.8, "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"),
    "PI-DES-007": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),

    # ── Auth / JWT ────────────────────────────────────────────────────────────
    "PI-AUTH-001": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-AUTH-002": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-AUTH-003": ("CRITICAL", 9.5, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-AUTH-004": ("HIGH",     8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-AUTH-005": ("HIGH",     8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "PI-AUTH-006": ("CRITICAL", 9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-AUTH-007": ("MEDIUM",   5.4, "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),

    # ── Path Traversal ────────────────────────────────────────────────────────
    "PI-PT-001":  ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-PT-002":  ("CRITICAL", 9.1, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-PT-003":  ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-PT-004":  ("MEDIUM",   6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "PI-PT-005":  ("HIGH",     7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    "PI-SSRF-001": ("HIGH",    8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "PI-SSRF-002": ("HIGH",    8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "PI-SSRF-003": ("MEDIUM",  5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "PI-SSRF-004": ("MEDIUM",  6.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),

    # ── API Auth / BOLA ───────────────────────────────────────────────────────
    "PI-API-001": ("HIGH",     8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "PI-API-002": ("HIGH",     8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "PI-API-003": ("MEDIUM",   5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),

    # ── Vulnerable Dependencies ───────────────────────────────────────────────
    "PI-DEP-001": ("CRITICAL", 10.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # log4shell
    "PI-DEP-002": ("CRITICAL",  9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-DEP-003": ("HIGH",      8.1, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PI-DEP-004": ("HIGH",      7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-DEP-005": ("CRITICAL",  9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "PI-DEP-006": ("MEDIUM",    5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "PI-DEP-007": ("HIGH",      8.8, "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    "PI-DEP-008": ("HIGH",      7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-DEP-009": ("HIGH",      7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-DEP-010": ("HIGH",      7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PI-DEP-011": ("HIGH",      7.4, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PI-DEP-012": ("CRITICAL", 10.0, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # Struts
    "PI-DEP-013": ("CRITICAL",  9.8, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),  # jackson
}

# Fallback by severity when rule_id not matched
_SEV_FALLBACK: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "INFO":     0.0,
}


def score_finding(finding: dict) -> dict:
    """
    Enrich a single finding dict with CVSS score and vector string.
    Adds keys: cvss_score (float), cvss_vector (str).
    Upgrades severity if the table entry is higher.
    """
    rule_id = finding.get("id", "")
    entry   = CVSS_TABLE.get(rule_id)

    if entry:
        sev_override, score, vector = entry
        # Only upgrade severity, never downgrade
        sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        cur_sev   = finding.get("severity", "INFO").upper()
        if sev_order.index(sev_override) > sev_order.index(cur_sev):
            finding["severity"] = sev_override
        finding["cvss_score"]  = score
        finding["cvss_vector"] = vector
    else:
        # Fallback: use severity to assign a default score
        sev   = finding.get("severity", "INFO").upper()
        score = _SEV_FALLBACK.get(sev, 5.0)
        finding.setdefault("cvss_score",  score)
        finding.setdefault("cvss_vector", "")

    return finding


def score_all_findings(findings: list[dict]) -> list[dict]:
    """Apply score_finding() to every item in a list and return the enriched list."""
    return [score_finding(f) for f in findings]


# ── Plugin stub (required for auto-discovery) ─────────────────────────────────
class RiskScoringPlugin(BasePlugin):
    """
    Post-processor plugin — does not generate findings directly.
    Scoring is applied via score_all_findings() inside _full_scan().
    """
    name        = "Risk Scoring (CVSS)"
    description = "Assigns CVSS v3.1-aligned scores to all findings"
    engine_tag  = "Plugin-RiskScore"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        return []   # scoring is applied as a post-pass, not per-finding
