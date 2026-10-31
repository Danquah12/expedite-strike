"""
Expedite Strike — Service Watchdog
===================================
Runs app.py in a loop with auto-restart on crash.
Designed to be registered as a Windows Scheduled Task.

Usage:
    python service_watchdog.py          # Run with auto-restart
    python service_watchdog.py --stop   # Create stop file to gracefully halt
"""
import subprocess
import time
import os
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
STOP_FILE = os.path.join(APP_DIR, ".stop_service")
LOG_FILE = os.path.join(APP_DIR, "logs", "watchdog.log")

os.makedirs(os.path.join(APP_DIR, "logs"), exist_ok=True)


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def main():
    if "--stop" in sys.argv:
        with open(STOP_FILE, "w") as f:
            f.write("stop")
        log("Stop file created — service will halt after current scan")
        return

    # Remove stop file if exists
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)

    log("═" * 60)
    log("Expedite Strike Service Watchdog starting")
    log(f"App directory: {APP_DIR}")
    log(f"Python: {PYTHON}")
    log("═" * 60)

    restart_count = 0
    MAX_RAPID_RESTARTS = 5
    last_start = 0

    while True:
        # Check for stop file
        if os.path.exists(STOP_FILE):
            log("Stop file detected — shutting down")
            break

        # Rate-limit rapid restarts
        now = time.time()
        if now - last_start < 10:
            restart_count += 1
            if restart_count >= MAX_RAPID_RESTARTS:
                log(f"Too many rapid restarts ({MAX_RAPID_RESTARTS}) — "
                    f"waiting 60s before retry")
                time.sleep(60)
                restart_count = 0
        else:
            restart_count = 0

        last_start = time.time()
        log(f"Starting Expedite Strike (restart #{restart_count})...")

        try:
            # Set environment
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            agentic_path = r"D:\Agentic-AI"
            if os.path.exists(agentic_path):
                env["PATH"] = agentic_path + ";" + env.get("PATH", "")

            proc = subprocess.Popen(
                [PYTHON, "app.py"],
                cwd=APP_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            log(f"Process started (PID {proc.pid})")

            # Stream output to log
            for line in proc.stdout:
                try:
                    text = line.decode("utf-8", errors="replace").rstrip()
                    if text:
                        print(text, flush=True)
                except Exception:
                    pass

            proc.wait()
            rc = proc.returncode
            log(f"Process exited with code {rc}")

        except Exception as e:
            log(f"Error launching process: {e}")
            time.sleep(5)
            continue

        # Check for stop file again
        if os.path.exists(STOP_FILE):
            log("Stop file detected — not restarting")
            break

        log("Restarting in 5 seconds...")
        time.sleep(5)

    log("Watchdog shutting down")


if __name__ == "__main__":
    main()
