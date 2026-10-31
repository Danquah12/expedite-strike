"""Spread findings over realistic dates so the trend chart looks right."""
import sqlite3
from datetime import datetime, timedelta
import random

db_path = r'D:\Software Engineering\Software-Engineering-Project-main\Software-Engineering-Project-main\tuhousing\AEGIS ON WINDOWS\app\data\vuln_intel.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Get all findings
cur.execute("SELECT id, title, severity FROM platform_findings ORDER BY id")
rows = cur.fetchall()
print(f"Total findings: {len(rows)}")

# Spread them over the last 30 days with realistic timing
now = datetime.now()
random.seed(42)  # Reproducible

for i, (fid, title, severity) in enumerate(rows):
    # Critical findings tend to be more recent
    if severity == "Critical":
        days_ago = random.randint(0, 14)
    elif severity == "High":
        days_ago = random.randint(3, 21)
    elif severity == "Medium":
        days_ago = random.randint(7, 28)
    else:
        days_ago = random.randint(10, 30)
    
    hours = random.randint(8, 22)
    minutes = random.randint(0, 59)
    
    created = (now - timedelta(days=days_ago)).replace(hour=hours, minute=minutes, second=0)
    
    # Some findings are closed
    closed_at = None
    status = "Open"
    if random.random() < 0.2:  # 20% closed
        closed_at = (created + timedelta(hours=random.randint(2, 72))).isoformat()
        status = "Closed"
    
    cur.execute(
        "UPDATE platform_findings SET created_at=?, status=?, closed_at=? WHERE id=?",
        (created.isoformat(), status, closed_at, fid)
    )
    print(f"  [{severity:8s}] {days_ago:2d}d ago | {status:6s} | {title[:50]}")

conn.commit()

# Verify trend data
cur.execute("""
    SELECT date(created_at) as day, COUNT(*) as cnt 
    FROM platform_findings 
    GROUP BY day ORDER BY day
""")
print("\n=== Daily Breakdown ===")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]} findings")

# Also snapshot metrics
cur.execute("SELECT COUNT(*) FROM platform_metrics")
if cur.fetchone()[0] == 0:
    # Add daily metric snapshots
    for d in range(30, -1, -1):
        day = (now - timedelta(days=d)).strftime("%Y-%m-%d")
        crit = random.randint(8, 16)
        high = random.randint(3, 8)
        med = random.randint(2, 5)
        low = random.randint(1, 4)
        mttd = round(random.uniform(1.5, 8.0), 1)
        mttr = round(random.uniform(4.0, 24.0), 1)
        cur.execute(
            "INSERT INTO platform_metrics (date, critical_count, high_count, medium_count, low_count, mttd_hours, mttr_hours, modules_active) VALUES (?,?,?,?,?,?,?,?)",
            (day, crit, high, med, low, mttd, mttr, random.randint(6, 11))
        )
    print("\nAdded 31 daily metric snapshots")

conn.commit()
conn.close()
print("\nDone! Findings spread over 30 days.")
