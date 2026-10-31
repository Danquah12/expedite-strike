import os, json
from datetime import datetime

SCAN_DIRS = {
    "nmap": "/mnt/scans/incoming/nmap",
    "zap": "/mnt/scans/incoming/zap",
}

STATE_FILE = "state/processed_scans.json"


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"processed_files": []}
    return json.load(open(STATE_FILE))


def save_state(state):
    os.makedirs("state", exist_ok=True)
    json.dump(state, open(STATE_FILE, "w"), indent=2)


def check_for_new_scans():
    state = load_state()
    new_files = []

    for _, directory in SCAN_DIRS.items():
        if not os.path.exists(directory):
            continue

        for f in os.listdir(directory):
            path = os.path.join(directory, f)
            if os.path.isfile(path) and path not in state["processed_files"]:
                new_files.append(path)

    if new_files:
        state["processed_files"].extend(new_files)
        save_state(state)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "new_files": new_files,
    }
