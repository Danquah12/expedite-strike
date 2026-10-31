#!/usr/bin/env python3

# =================================================
# Standard library imports
# =================================================
import os
import sys
import time
import socket
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# =================================================
# Third-party imports
# =================================================
from dotenv import load_dotenv
from neo4j import GraphDatabase

# =================================================
# Paths & constants
# =================================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, ".."))

PYTHON_BIN = sys.executable
REQUIREMENTS_FILE = os.path.join(PROJECT_ROOT, "requirements.txt")

DASH_HOST = "127.0.0.1"
DASH_PORT = 8050
DASH_URL = f"http://{DASH_HOST}:{DASH_PORT}"

# Ensure project root is importable
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# =================================================
# Load environment (.env optional)
# =================================================
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# =================================================
# Neo4j normalization & validation
# =================================================
def normalize_neo4j_env():
    if not os.getenv("NEO4J_PASSWORD") and os.getenv("NEO4J_PASS"):
        os.environ["NEO4J_PASSWORD"] = os.getenv("NEO4J_PASS")

    if not os.getenv("NEO4J_PASSWORD"):
        os.environ["NEO4J_PASSWORD"] = "Adomaa12@"

    if not os.getenv("NEO4J_URI"):
        os.environ["NEO4J_URI"] = "bolt://localhost:7687"

    if not os.getenv("NEO4J_USER"):
        os.environ["NEO4J_USER"] = "neo4j"


def verify_neo4j():
    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"),
        auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD")),
    )
    try:
        with driver.session() as session:
            session.run("RETURN 1")
    finally:
        driver.close()

# =================================================
# OpenVAS normalization
# =================================================
def normalize_openvas_env():
    if not os.getenv("OPENVAS_PASSWORD"):
        os.environ["OPENVAS_PASSWORD"] = "3bc08a39-d780-4b2b-83b8-a1e172ba8868"
    if not os.getenv("OPENVAS_USER"):
        os.environ["OPENVAS_USER"] = "admin"

# =================================================
# Utility helpers
# =================================================
def wait_for_port(host, port, timeout=20):
    start = time.time()
    while time.time() - start < timeout:
        try:
            socket.create_connection((host, port), timeout=1)
            return True
        except OSError:
            time.sleep(0.5)
    return False


def bootstrap_dependencies(set_progress):
    set_progress(10, "Installing dependencies…")
    subprocess.run(
        [PYTHON_BIN, "-m", "pip", "install", "--no-cache-dir", "-r", REQUIREMENTS_FILE],
        check=True,
    )
    set_progress(20, "Dependencies ready")

# =================================================
# Launcher GUI
# =================================================
class LauncherGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Vulnerability Intelligence Platform")
        self.geometry("520x320")
        self.resizable(False, False)

        self.cancelled = threading.Event()

        ttk.Label(self, text="Vulnerability Intelligence Platform",
                  font=("Segoe UI", 12, "bold")).pack(pady=12)

        self.progress = ttk.Progressbar(self, length=460)
        self.progress.pack(pady=10)

        self.status = ttk.Label(self, text="Ready")
        self.status.pack()

        btns = ttk.Frame(self)
        btns.pack(pady=15)

        ttk.Button(btns, text="Start", command=self.start).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Cancel", command=self.cancel).grid(row=0, column=1, padx=6)

    # ------------------------------
    # Thread-safe dialog
    # ------------------------------
    def ask_string_mainthread(self, title, prompt):
        result = {"val": None}
        done = threading.Event()

        def _show():
            result["val"] = simpledialog.askstring(title, prompt, parent=self)
            done.set()

        self.after(0, _show)

        while not done.is_set():
            time.sleep(0.05)

        return result["val"]

    # ------------------------------
    # Controls
    # ------------------------------
    def start(self):
        threading.Thread(target=self.run_pipeline, daemon=True).start()

    def cancel(self):
        self.cancelled.set()
        self.destroy()

    # ------------------------------
    # Pipeline
    # ------------------------------
    def run_pipeline(self):
        try:
            self.status.config(text="Preparing environment…")

            normalize_neo4j_env()
            normalize_openvas_env()
            verify_neo4j()

            bootstrap_dependencies(self.set_progress)

            targets = self.ask_string_mainthread(
                "Network Targets",
                "Enter IPs / CIDRs / hostnames (comma-separated):"
            )
            urls = self.ask_string_mainthread(
                "Web Targets",
                "Enter URLs for ZAP/Burp (comma-separated):"
            )

            targets = [t.strip() for t in (targets or "").split(",") if t.strip()]
            urls = [u.strip() for u in (urls or "").split(",") if u.strip()]

            if not targets:
                raise RuntimeError("No network targets provided")

            from importers.nmap_import import NmapIngestor
            from cyber_range.services.openvas_ingest import OpenVASIngestor
            from cyber_range.services.zap_ingest import ZAPIngestor
            from cyber_range.services.burp_ingest import BurpIngestor

            self.set_progress(40, "Running Nmap…")
            NmapIngestor().scan_and_ingest(targets)

            self.set_progress(60, "Running OpenVAS…")
            OpenVASIngestor().run_scan(targets)

            if urls:
                self.set_progress(75, "Running ZAP…")
                for u in urls:
                    ZAPIngestor().run_scan(u)

                self.set_progress(85, "Running Burp…")
                for u in urls:
                    BurpIngestor().run_scan_and_ingest(u)

            self.set_progress(95, "Starting dashboard…")
            subprocess.Popen([PYTHON_BIN, "app.py"], cwd=APP_DIR)

            if wait_for_port(DASH_HOST, DASH_PORT):
                subprocess.Popen(["firefox", DASH_URL])
                self.destroy()
            else:
                raise RuntimeError("Dashboard failed to start")

        except Exception as e:
            messagebox.showerror("Launcher Error", str(e))

    def set_progress(self, value, text=None):
        self.progress["value"] = value
        if text:
            self.status.config(text=text)
        self.update_idletasks()

# =================================================
# Entrypoint
# =================================================
if __name__ == "__main__":
    LauncherGUI().mainloop()
