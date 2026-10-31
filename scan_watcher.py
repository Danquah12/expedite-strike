import os
import json
import time
from datetime import datetime

import run as pentest_engine

SCAN_DIRS = {
    "nmap": "/mnt/scans/incoming/nmap",
    "zap": "/mnt/scans/incoming/zap",
}

STATE_FILE = "state/processed_scans.json"

# 🔁 TEST MODE: 10 minutes
SCAN_INTERVAL = 10 * 60  # 600 seconds


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"processed_files": []}

    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def find_new_scans(state):
    new_files = []

    for scan_type, directory in SCAN_DIRS.items():
        if not os.path.exists(directory):
            continue

        for fname in os.listdir(directory):
            full_path = os.path.join(directory, fname)

            if not os.path.isfile(full_path):
                continue

            if full_path not in state["processed_files"]:
                new_files.append(full_path)

    return new_files


def run_cycle():
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n[{timestamp}] Scan watcher running...")

    state = load_state()
    new_scans = find_new_scans(state)

    if not new_scans:
        print("ℹ️  No new scan files detected.")
        return

    print(f"✅ Detected {len(new_scans)} new scan file(s):")
    for f in new_scans:
        print(f"   + {f}")

    print("🚀 Triggering automated penetration testing framework...")
    pentest_engine.run_framework()

    state["processed_files"].extend(new_scans)
    save_state(state)

    print("✔ Processing complete. State updated.")


def main():
    print("🕵️ Scan watcher started (10-minute interval – TEST MODE)")
    while True:
        run_cycle()
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
