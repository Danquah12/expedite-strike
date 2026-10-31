import os
from app.parsers import nmap_parser, openvas_parser, zap_parser
from .merge_feeds import load_findings_to_db, deduplicate
from app.parsers import burp_parser

findings = burp_parser.parse_burp("/opt/vuln_intel/feeds/burp/Burpsuite.xml")

# Ensure DB schema is always in sync before importing feeds
import sys, os
sys.path.insert(0, os.path.abspath('/opt/vuln_intel'))
from tools.sync_schema import sync_schema

# Run automatic schema synchronization before processing
sync_schema()

DB_PATH = "/opt/vuln_intel/vuln_intel.db"


def import_xml(path):
    """
    Detect the scanner type from filename, parse using proper parser,
    deduplicate, and insert into vuln_intel.db.
    """
    name = os.path.basename(path).lower()
    if "nmap" in name or "scan" in name:
        findings = nmap_parser.parse_nmap(path)
        src = "nmap"
    elif "openvas" in name or "report" in name:
        findings = openvas_parser.parse_openvas(path)
        src = "openvas"
    elif "zap" in name:
        findings = zap_parser.parse_zap(path)
        src = "zap"
    else:
        raise ValueError(f"Unknown scanner type for {path}")

    logging.info(f"[+] Parsed {len(findings)} findings from {src}")
    if not findings:
        return

    findings = deduplicate(findings)
    load_findings_to_db(findings, DB_PATH)
    logging.info(f"[✓] Imported {len(findings)} findings from {src}")


# app/xml_parser.py
"""
Top-level XML import wrapper for scanner feeds.

Usage:
    from app.xml_parser import import_xml
    import_xml("/root/vuln_intel/feeds/burp/Burpsuite.xml")
"""

import os
import logging

# Import from package-level app.* so relative imports work when you run
# from project root (/root/vuln_intel)
from app.parsers import nmap_parser, openvas_parser, zap_parser, burp_parser
from app.merge_feeds import load_findings_to_db, deduplicate

# Path to your SQLite DB (adjust if your DB path is different)
DB_PATH = "/root/vuln_intel/vuln_intel.db"

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _detect_source_from_filename(path: str) -> str:
    """Return one of: 'nmap', 'openvas', 'zap', 'burp' or raise ValueError."""
    name = os.path.basename(path).lower()
    if "nmap" in name or "scan" in name:
        return "nmap"
    if "openvas" in name or "openvas" in name or "openvas" in name or "report" in name:
        return "openvas"
    if "zap" in name:
        return "zap"
    # Burp often has "burp", "burpsuite", or "burpsuite.xml" in filename
    if "burp" in name or "burpsuite" in name:
        return "burp"
    raise ValueError(f"Unknown scanner type for file: {path}")


def import_xml(path: str) -> None:
    """
    Parse an XML scan export at 'path', deduplicate findings, and insert them into DB.

    - path: absolute or relative path to the XML file
    - The function logs progress and returns None. Exceptions will propagate for caller to handle.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"XML file not found: {path}")

    src = _detect_source_from_filename(path)
    LOG.info("Detected source=%s for file=%s", src, path)

    # Call the correct parser
    if src == "nmap":
        findings = nmap_parser.parse_nmap(path)
    elif src == "openvas":
        findings = openvas_parser.parse_openvas(path)
    elif src == "zap":
        findings = zap_parser.parse_zap(path)
    elif src == "burp":
        findings = burp_parser.parse_burp(path)
    else:
        # should never hit due to detection above
        raise ValueError(f"No parser available for source: {src}")

    LOG.info("[+] Parsed %d findings from %s", len(findings) if findings is not None else 0, src)

    # Nothing to do
    if not findings:
        LOG.info("[i] No findings to import from %s", path)
        return

    # Deduplicate and load to DB
    try:
        findings = deduplicate(findings)
    except Exception as e:
        LOG.exception("Failed to deduplicate findings: %s", e)
        raise

    try:
        load_findings_to_db(findings, DB_PATH)
    except Exception as e:
        LOG.exception("Failed to load findings to DB: %s", e)
        raise

    LOG.info("[✓] Imported %d findings from %s into %s", len(findings), src, DB_PATH)

# ==========================================================
# Auto-healing + auto-clean DB logic for vuln_intel pipeline
# Ensures DB and schema are valid, consistent, and optimized
# ==========================================================
import os, sys, sqlite3, logging, datetime, shutil
sys.path.insert(0, os.path.abspath('/root/vuln_intel'))

from tools.sync_schema import sync_schema
from tools.rebuild_findings_table import rebuild_findings_table

DB_PATH = "/root/vuln_intel/vuln_intel.db"
BACKUP_DIR = "/root/vuln_intel/backups"
EXPECTED_COLUMNS = {
    "id", "title", "description", "cve_id", "host", "port", "service",
    "protocol", "severity", "source", "import_date",
    "vuln_name", "remediation", "path", "timestamp"
}

def ensure_db_ready():
    """Ensure vuln_intel.db exists, valid schema, no ghost columns."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    try:
        # Recreate database if missing
        if not os.path.exists(DB_PATH):
            logging.warning("⚠️ vuln_intel.db not found — rebuilding fresh database...")
            rebuild_findings_table()
            return

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Check table existence
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings';")
        exists = cur.fetchone()
        if not exists:
            logging.warning("⚠️ 'findings' table missing — rebuilding database...")
            rebuild_findings_table()
            conn.close()
            return

        # Check integrity
        cur.execute("PRAGMA integrity_check;")
        result = cur.fetchone()
        if not result or result[0] != "ok":
            logging.error(f"❌ DB integrity issue: {result[0]} — rebuilding database...")
            rebuild_findings_table()
            conn.close()
            return

        # Check for ghost columns
        cur.execute("PRAGMA table_info(findings);")
        existing_cols = {row[1] for row in cur.fetchall()}

        extra_cols = existing_cols - EXPECTED_COLUMNS
        missing_cols = EXPECTED_COLUMNS - existing_cols

        if extra_cols:
            logging.warning(f"🧹 Found ghost columns: {', '.join(extra_cols)} — rebuilding clean schema...")
            backup_path = os.path.join(
                BACKUP_DIR,
                f"vuln_intel_ghostfix_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.bak"
            )
            shutil.copy2(DB_PATH, backup_path)
            logging.info(f"🩵 Backup created at: {backup_path}")
            rebuild_findings_table()
            conn.close()
            return

        if missing_cols:
            logging.info(f"🩵 Missing columns detected: {', '.join(missing_cols)} — syncing schema...")
            sync_schema()

        # All checks passed — ensure indexes are intact
        cur.execute("PRAGMA index_list(findings);")
        indexes = {row[1] for row in cur.fetchall()}
        required_indexes = {"idx_findings_cve", "idx_findings_host", "idx_findings_source", "idx_findings_import_date"}
        if not required_indexes.issubset(indexes):
            logging.info("⚙️ Some indexes missing — triggering rebuild for optimization...")
            rebuild_findings_table()

        conn.close()
        logging.info("✅ Database verified, cleaned, and synchronized successfully.")

    except Exception as e:
        logging.error(f"❌ Database validation failed: {e}")
        rebuild_findings_table()
        sync_schema()

# Run once during import initialization
ensure_db_ready()
# ==========================================================

