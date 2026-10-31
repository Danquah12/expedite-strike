#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Initialize SQLite database for Unified Vulnerability Intelligence Dashboard
Creates: findings, trend_metrics tables
Populates sample data for testing
"""

import sqlite3
from datetime import datetime
from pathlib import Path

# -------------------- Paths --------------------
BASE_DIR = Path("/root/vuln_intel/app")
DB_PATH = BASE_DIR / "data" / "findings.db"

(DB_PATH.parent).mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(str(DB_PATH))
cur = conn.cursor()

# -------------------- Create Tables --------------------
print("[+] Creating tables...")

cur.execute("""
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id TEXT,
    name TEXT,
    cvss REAL,
    severity TEXT,
    host TEXT,
    port TEXT,
    scanner TEXT,
    timestamp TEXT
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS trend_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    soc_health INTEGER,
    risk_velocity REAL,
    created_at TEXT
)
""")

# -------------------- Insert Sample Findings --------------------
print("[+] Inserting sample vulnerability data...")
sample_findings = [
    ("1001", "Apache Log4j Remote Code Execution (CVE-2021-44228)", 9.8, "Critical", "10.0.0.5", "443", "Nmap", datetime.now().isoformat()),
    ("1002", "OpenSSL Heartbleed Vulnerability (CVE-2014-0160)", 7.5, "High", "10.0.0.6", "443", "OpenVAS", datetime.now().isoformat()),
    ("1003", "Outdated jQuery Library Detected", 5.4, "Medium", "10.0.0.7", "80", "BurpSuite", datetime.now().isoformat()),
    ("1004", "Deprecated TLS Version in Use", 3.7, "Low", "10.0.0.8", "443", "Nessus", datetime.now().isoformat())
]

cur.executemany("""
INSERT INTO findings (plugin_id, name, cvss, severity, host, port, scanner, timestamp)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", sample_findings)

# -------------------- Insert Sample SOC Metrics --------------------
print("[+] Inserting SOC and risk velocity metrics...")
sample_metrics = [
    (95, 2.1, datetime.now().isoformat()),
    (88, 3.7, datetime.now().isoformat()),
    (91, 1.8, datetime.now().isoformat())
]

cur.executemany("""
INSERT INTO trend_metrics (soc_health, risk_velocity, created_at)
VALUES (?, ?, ?)
""", sample_metrics)

conn.commit()
conn.close()

print("\n✅ Database initialized successfully!")
print(f"Database path: {DB_PATH}")
