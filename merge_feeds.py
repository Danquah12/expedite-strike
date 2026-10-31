import os, sqlite3, json, datetime

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    host TEXT,
    port TEXT,
    service TEXT,
    severity TEXT,
    vuln_name TEXT,
    description TEXT,
    remediation TEXT,
    path TEXT,
    timestamp TEXT
);
"""

def init_db(db_path):
    """Create DB and schema if not exists."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(DB_SCHEMA)
        conn.commit()
    print(f"[merge_feeds] ✅ Database ready at {db_path}")

def deduplicate(findings):
    """Simple deduplication by unique tuple of (host, vuln_name, source)."""
    seen, unique = set(), []
    for f in findings:
        key = (f.get("host"), f.get("vuln_name"), f.get("source"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    print(f"[merge_feeds] Deduplicated {len(findings)} → {len(unique)} findings")
    return unique

def load_findings_to_db(findings, db_path):
    """Insert parsed findings into the SQLite DB."""
    init_db(db_path)
    if not findings:
        print("[merge_feeds] ⚠ No findings to insert.")
        return

    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        for f in findings:
            cur.execute("""
                INSERT INTO findings (
                    source, host, port, service, severity,
                    vuln_name, description, remediation, path, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f.get("source"),
                f.get("host"),
                f.get("port"),
                f.get("service"),
                f.get("severity"),
                f.get("vuln_name"),
                f.get("description"),
                f.get("remediation"),
                f.get("path"),
                datetime.datetime.utcnow().isoformat(),
            ))
        conn.commit()
    print(f"[merge_feeds] ✅ Inserted {len(findings)} findings into {db_path}")

def export_json(db_path, out_path=None):
    """Dump all findings to JSON for quick inspection."""
    if not os.path.exists(db_path):
        print(f"[merge_feeds] ❌ DB not found at {db_path}")
        return
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM findings").fetchall()
    data = [dict(row) for row in rows]
    out_path = out_path or db_path.replace(".db", "_dump.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[merge_feeds] 💾 Exported {len(data)} findings → {out_path}")
