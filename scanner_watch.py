#!/usr/bin/env python3
"""
scanner_watch.py
================
Daemon that watches /mnt/scans/incoming/ (and all subdirectories) for new
scanner output files and immediately ingests them into BOTH:

  1. Neo4j   — via ScanIngestor().auto_detect_and_ingest()
  2. SQLite  — via findings_service.save_finding() for every parsed finding

Supported scanners (auto-detected from filename / content):
  nmap/       → nmap XML  (.xml containing <nmaprun)
  zap/        → OWASP ZAP JSON  (.json containing "site"+"alerts")
  nuclei/     → Nuclei JSONL  (.json/.jsonl containing "template-id")
  burp/       → Burp Suite XML  (.xml containing <issues>)
  openvas/    → OpenVAS XML  (.xml containing <report>+<result>)
  custom/     → anything else  (content-sniffed, then passed to ScanIngestor)

Adding a NEW scanner: just drop its output into /mnt/scans/incoming/<scanner_name>/
No code changes required — auto_detect_and_ingest() handles it.

Usage:
    python3 scanner_watch.py                 # run as daemon (blocks)
    python3 scanner_watch.py --once FILE     # ingest one file and exit
    python3 scanner_watch.py --poll          # force polling mode (no watchdog)

Log:
    /opt/vuln_intel/scanner_watch.log

── Systemd unit (save as /etc/systemd/system/scanner-watch.service) ────────────
[Unit]
Description=VulnIntel Scanner Auto-Ingest Watcher
After=network.target neo4j.service

[Service]
Type=simple
User=kali
WorkingDirectory=/opt/vuln_intel/app
ExecStart=/usr/bin/python3 /opt/vuln_intel/app/scanner_watch.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
────────────────────────────────────────────────────────────────────────────────
Enable:
    sudo systemctl daemon-reload
    sudo systemctl enable --now scanner-watch
"""

import os
import sys
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
WATCH_DIR    = Path("/mnt/scans/incoming")
LOG_FILE     = "/opt/vuln_intel/scanner_watch.log"
POLL_SECS    = 5          # fallback polling interval
SETTLE_SECS  = 2          # wait after file creation before parsing
PROCESSED_EXT = ".processed"   # sidecar flag file

# ── Scanner source → human module name ───────────────────────────────────────
_SOURCE_MODULE = {
    "nmap":       "Nmap",
    "zap":        "ZAP",
    "nuclei":     "Nuclei",
    "burp":       "Burp Suite",
    "openvas":    "OpenVAS",
    "bloodhound": "BloodHound",
    "aegisprobe": "AegisProbe",
    "nessus":     "Nessus",
    "stig_ckl":   "STIG",
    "scap_xccdf": "SCAP",
}
_ZAP_SEV   = {"3": "High", "2": "Medium", "1": "Low", "0": "Information"}

def _cvss_sev(cvss) -> str:
    try:
        c = float(cvss)
        if c >= 9.0: return "Critical"
        if c >= 7.0: return "High"
        if c >= 4.0: return "Medium"
        if c > 0:    return "Low"
    except Exception:
        pass
    return "Medium"

# ── Logging setup ─────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("scanner_watch")


# ── Import app modules ────────────────────────────────────────────────────────
APP_DIR = Path(__file__).parent
sys.path.insert(0, str(APP_DIR))

def _get_ingestor():
    from cyber_range.services.scan_ingestor import ScanIngestor
    return ScanIngestor()

def _save_to_sqlite(findings: list, source: str):
    """Write parsed findings into the SQLite findings_service database."""
    try:
        from cyber_range.services import findings_service as fs
        module = _SOURCE_MODULE.get(source.lower(), source.title())
        count  = 0
        for f in findings:
            # Determine severity
            riskcode = str(f.get("riskcode") or "")
            cvss_raw = f.get("cvss")
            if riskcode in _ZAP_SEV:
                sev = _ZAP_SEV[riskcode]
            elif cvss_raw is not None:
                sev = _cvss_sev(cvss_raw)
            else:
                sev = str(f.get("severity", "Medium")).capitalize()
                if sev not in ("Critical", "High", "Medium", "Low", "Information"):
                    sev = "Medium"

            title = (f.get("name") or f.get("title") or "Unknown Finding").strip()
            host  = (f.get("host") or "").strip()
            desc  = (f.get("description") or f.get("evidence") or "").strip()[:500]
            cve   = (f.get("cve") or "").strip()

            fs.save_finding(module, title, sev, host, desc, cve)
            count += 1
        log.info(f"  → SQLite: {count} findings saved (module='{module}')")
        return count
    except Exception as e:
        log.error(f"  → SQLite write failed: {e}")
        return 0


def _save_to_postgres(findings: list, source: str):
    """
    Write parsed findings into PostgreSQL grc_vulnerabilities table.
    Uses UPSERT to avoid duplicates (keyed on vuln_id + host + port).
    """
    try:
        from cyber_range.services.pg_engine import pg_execute, _PG_AVAILABLE
        if not _PG_AVAILABLE:
            return 0

        module = _SOURCE_MODULE.get(source.lower(), source.title())
        count  = 0
        for f in findings:
            host     = (f.get("host") or "unknown").strip()
            port_raw = f.get("port") or "0"
            try:
                port = int(str(port_raw).split("/")[0])
            except (ValueError, TypeError):
                port = 0
            svc      = (f.get("service") or "unknown").strip()[:100]
            title    = (f.get("name") or f.get("title") or "Unknown Finding").strip()[:200]
            desc     = (f.get("description") or f.get("evidence") or "").strip()[:500]
            cve      = (f.get("cve") or "").strip()
            plugin   = f.get("plugin_id") or f.get("rule_id") or ""
            severity = (f.get("severity") or "Medium").strip()

            # Build vuln_id: prefer CVE, fallback to plugin_id, then name hash
            vuln_id  = cve or plugin or f"{source}:{title[:50]}"

            # Parse CVSS
            cvss_raw = f.get("cvss")
            cvss = None
            if cvss_raw:
                try:
                    cvss = round(float(cvss_raw), 1)
                except (ValueError, TypeError):
                    cvss = None

            pg_execute("""
                INSERT INTO grc_vulnerabilities
                    (vuln_id, host, service, port, cvss, severity,
                     title, description, source, status, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Open', NOW())
                ON CONFLICT (vuln_id, host, port) DO UPDATE SET
                    severity    = EXCLUDED.severity,
                    cvss        = COALESCE(EXCLUDED.cvss, grc_vulnerabilities.cvss),
                    title       = EXCLUDED.title,
                    description = EXCLUDED.description,
                    last_seen   = NOW()
            """, (
                vuln_id, host, svc, port, cvss, severity,
                title, desc, module,
            ), fetch=False)
            count += 1

        log.info(f"  → PostgreSQL: {count} findings upserted into grc_vulnerabilities")
        return count
    except Exception as e:
        log.error(f"  → PostgreSQL write failed: {e}")
        return 0


def _detect_source(path: Path) -> str:
    """Infer scanner source from directory name and file content."""
    # 1. Parent directory hint (e.g. /mnt/scans/incoming/nmap/file.xml)
    parent = path.parent.name.lower()
    for key in _SOURCE_MODULE:
        if key in parent:
            return key

    # 2. Extension hint
    ext = path.suffix.lower()
    if ext == ".nessus":    return "nessus"
    if ext == ".ckl":       return "stig_ckl"

    # 3. Filename hint
    name = path.name.lower()
    if "nmap" in name:   return "nmap"
    if "nuclei" in name: return "nuclei"
    if "zap" in name:    return "zap"
    if "burp" in name:   return "burp"
    if "openvas" in name: return "openvas"
    if "aegis" in name:  return "aegisprobe"
    if "nessus" in name or "tenable" in name: return "nessus"
    if "stig" in name or "ckl" in name: return "stig_ckl"
    if "xccdf" in name or "scap" in name: return "scap_xccdf"

    # 4. Content sniff
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            head = fh.read(1024)
        if "<nmaprun"    in head: return "nmap"
        if "<issues>"    in head: return "burp"
        if "<report>"    in head and "<result>" in head: return "openvas"
        if '"template-id"' in head or '"matched-at"' in head: return "nuclei"
        if '"site"'      in head and '"alerts"' in head: return "zap"
        if '"findings"'  in head: return "aegisprobe"
        if "NessusClientData" in head or "<Policy>" in head: return "nessus"
        if "<CHECKLIST>" in head or "<STIG_INFO>" in head: return "stig_ckl"
        if "<Benchmark" in head or "<TestResult" in head: return "scap_xccdf"
    except Exception:
        pass

    return "unknown"


def _is_scan_file(path: Path) -> bool:
    """Return True if this file looks like a scanner report (not a sidecar)."""
    if path.suffix.lower() in (".processed", ".meta", ".log", ".tmp"):
        return False
    if path.name.startswith("."):
        return False
    if path.suffix.lower() not in (".xml", ".json", ".jsonl", ".html", ".txt", ".nessus", ".ckl"):
        return False
    return True


def _processed_flag(path: Path) -> Path:
    return path.with_suffix(path.suffix + PROCESSED_EXT)


def ingest_file(path: Path):
    """Main ingestion routine for a single file."""
    if not path.is_file():
        return
    flag = _processed_flag(path)
    if flag.exists():
        log.debug(f"Already processed: {path.name}")
        return
    if not _is_scan_file(path):
        return

    log.info(f"📄 New scan file detected: {path}")
    time.sleep(SETTLE_SECS)  # wait for write to complete

    if not path.is_file():
        log.warning(f"  File disappeared before ingestion: {path}")
        return

    source  = _detect_source(path)
    log.info(f"  Detected scanner: {source.upper()}")

    # ── 1. Parse findings ─────────────────────────────────────────────
    parsed_findings = []
    try:
        ingestor = _get_ingestor()
        # Get parsed findings for SQLite/PostgreSQL using scan_ingestor parsers
        from cyber_range.services import scan_ingestor as si
        # Build parser function name for this source
        _xml_sources = ("nmap", "burp", "openvas", "nessus")
        _name_overrides = {"stig_ckl": "_parse_ckl", "scap_xccdf": "_parse_xccdf"}
        if source in _name_overrides:
            parse_fn_name = _name_overrides[source]
        elif source in _xml_sources:
            parse_fn_name = f"_parse_{source}_xml"
        else:
            parse_fn_name = f"_parse_{source}_json"
        parse_fn = getattr(si, parse_fn_name, None) or getattr(si, f"_parse_{source}", None)
        # Ultimate fallback: use ScanIngestor.PARSERS dict
        if parse_fn is None:
            parse_fn = si.ScanIngestor.PARSERS.get(source)
        if parse_fn:
            parsed_findings = parse_fn(str(path))
            log.info(f"  Parsed {len(parsed_findings)} raw findings")
    except Exception as e:
        log.warning(f"  Parser error (will still try Neo4j): {e}")

    # ── 2. Write to Neo4j via ScanIngestor ───────────────────────────
    neo4j_count = 0
    try:
        def _log_neo4j(msg):
            log.info(f"  [Neo4j] {msg.strip()}")

        ingestor = _get_ingestor()
        if source != "unknown":
            neo4j_count = ingestor.ingest(str(path), source, on_output=_log_neo4j)
        else:
            neo4j_count = ingestor.auto_detect_and_ingest(str(path), on_output=_log_neo4j)
        log.info(f"  → Neo4j: {neo4j_count} findings written")
    except Exception as e:
        log.error(f"  → Neo4j write failed: {e}")

    # ── 3. Write to SQLite ────────────────────────────────────────────
    pg_count = 0
    if parsed_findings:
        for f in parsed_findings:
            f.setdefault("source", source)
        _save_to_sqlite(parsed_findings, source)

        # ── 3.5 Write to PostgreSQL (grc_vulnerabilities) ────────────
        pg_count = _save_to_postgres(parsed_findings, source)
    elif neo4j_count > 0:
        log.info("  → SQLite: skipped (no parsed findings available from parser)")

    # ── 4. Mark as processed ──────────────────────────────────────────
    flag.write_text(
        f"processed:{datetime.utcnow().isoformat()}\n"
        f"source:{source}\nneo4j:{neo4j_count}\npg:{pg_count}\n"
    )
    log.info(f"✅ Done: {path.name} ({source}, neo4j={neo4j_count}, pg={pg_count})")


# ── Watcher implementations ───────────────────────────────────────────────────

def _run_watchdog(watch_dir: Path):
    """Use watchdog library for instant inotify-based file watching."""
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class ScanHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                ingest_file(Path(event.src_path))

        def on_moved(self, event):
            if not event.is_directory:
                ingest_file(Path(event.dest_path))

    observer = Observer()
    observer.schedule(ScanHandler(), str(watch_dir), recursive=True)
    observer.start()
    log.info(f"🔍 Watchdog watching {watch_dir} (recursive, inotify)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def _run_polling(watch_dir: Path, interval: int = POLL_SECS):
    """Polling fallback when watchdog is not installed."""
    log.info(f"🔍 Polling {watch_dir} every {interval}s (install watchdog for inotify)")
    known: set = set()
    while True:
        try:
            current = {p for p in watch_dir.rglob("*") if p.is_file()}
            new_files = current - known
            for path in sorted(new_files):
                ingest_file(path)
            known = current
        except Exception as e:
            log.error(f"Poll error: {e}")
        time.sleep(interval)


def run_daemon(watch_dir: Path, force_poll: bool = False):
    """Start the watcher daemon."""
    watch_dir.mkdir(parents=True, exist_ok=True)
    # Scan ALL existing unprocessed files first
    log.info("🔄 Scanning existing unprocessed files on startup...")
    for path in sorted(watch_dir.rglob("*")):
        if path.is_file() and _is_scan_file(path) and not _processed_flag(path).exists():
            ingest_file(path)

    if force_poll:
        _run_polling(watch_dir)
        return
    try:
        import watchdog  # noqa: F401
        _run_watchdog(watch_dir)
    except ImportError:
        log.warning("watchdog not installed — falling back to polling. "
                    "Install it with: pip install watchdog")
        _run_polling(watch_dir)


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VulnIntel Scanner Auto-Ingest Watcher"
    )
    parser.add_argument(
        "--once", metavar="FILE",
        help="Ingest a single file then exit"
    )
    parser.add_argument(
        "--poll", action="store_true",
        help="Force polling mode (bypass watchdog)"
    )
    parser.add_argument(
        "--watch-dir", default=str(WATCH_DIR),
        help=f"Directory to watch (default: {WATCH_DIR})"
    )
    args = parser.parse_args()

    if args.once:
        log.info(f"Single-file mode: {args.once}")
        ingest_file(Path(args.once))
        sys.exit(0)

    run_daemon(Path(args.watch_dir), force_poll=args.poll)
