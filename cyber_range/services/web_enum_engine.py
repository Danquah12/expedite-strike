"""
web_enum_engine.py
==================
Multi-stage web reconnaissance engine.

Pipeline per target (stages skipped if tool not installed):
  Stage 1  httpx     — Probe live host, grab title / status / tech
  Stage 2  katana    — Crawl URLs (depth 3)
  Stage 3  nuclei    — Vulnerability scan (crit/high/med templates)
  Stage 4  ffuf      — Directory brute-force (common.txt)
  Stage 5  Neo4j     — Ingest all findings

Same public API as ParallelEnumerationEngine:
    engine = WebEnumerationEngine()
    engine.start(targets, on_output=..., on_complete=...)
    engine.cancel()
"""

import os
import re
import json
import shutil
import signal
import threading
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

# ── Tuning ───────────────────────────────────────────────────────────
MAX_PARALLEL   = 5
RAM_THRESHOLD  = 85.0

# Best-guess wordlist paths (common.txt)
_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

# Nuclei template paths
_NUCLEI_TEMPLATES = [
    os.path.expanduser("~/nuclei-templates"),
    "/opt/nuclei-templates",
    "/usr/share/nuclei-templates",
]


def _tool_path(name: str) -> str | None:
    """Return absolute path to a tool binary, or None if not found."""
    return shutil.which(name)


def _find_wordlist() -> str | None:
    for p in _WORDLIST_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def _find_nuclei_templates() -> str | None:
    for p in _NUCLEI_TEMPLATES:
        if os.path.isdir(p):
            return p
    return None


def is_ip_target(target: str) -> bool:
    """Return True if the target looks like an IP address (v4 or v6) or CIDR."""
    import ipaddress
    clean = target.strip().split(":")[0]  # strip port if present
    try:
        ipaddress.ip_network(clean, strict=False)
        return True
    except ValueError:
        return False


# ── Result container ──────────────────────────────────────────────────
class WebTargetResult:
    def __init__(self, target: str):
        self.target   = target
        self.status   = "pending"   # pending | scanning | done | failed | cancelled
        self.findings = 0
        self.urls     = []
        self.techs    = []
        self.error    = ""


# ── Main engine ───────────────────────────────────────────────────────
class WebEnumerationEngine:
    """
    Parallel web recon engine.

    Usage:
        eng = WebEnumerationEngine()
        eng.start(targets, on_output=print, on_complete=lambda c,r: None)
    """

    def __init__(self):
        self._cancel_flag = threading.Event()
        self._processes:  dict[str, subprocess.Popen] = {}
        self._proc_lock  = threading.Lock()
        self._results:   dict[str, WebTargetResult] = {}

        cpu = os.cpu_count() or 2
        self._max_workers = max(1, min(cpu - 1, MAX_PARALLEL))

        # Discover available tools once at init — httpx removed (use Python lib instead)
        self.tools = {
            "katana":   _tool_path("katana"),
            "nuclei":   _tool_path("nuclei"),
            "ffuf":     _tool_path("ffuf"),
            "subfinder":_tool_path("subfinder"),
        }
        self.wordlist         = _find_wordlist()
        self.nuclei_templates = _find_nuclei_templates()

    def _probe_web(self, url: str, on_output, tag: str) -> dict:
        """
        Stage 1: Python-native HTTP probe (no external binary needed).
        Returns dict with keys: status, title, server, content_type, techs.
        """
        info = {"status": None, "title": "", "server": "", "content_type": "", "techs": []}
        try:
            import httpx as _httpx
            with _httpx.Client(follow_redirects=True, timeout=12,
                               verify=False, headers={"User-Agent": "WebEnum/1.0"}) as c:
                r = c.get(url)
                info["status"] = r.status_code
                info["server"] = r.headers.get("server", "")
                info["content_type"] = r.headers.get("content-type", "")
                # Extract title
                import re as _re
                m = _re.search(r"<title[^>]*>([^<]{1,120})</title>", r.text, _re.IGNORECASE)
                info["title"] = m.group(1).strip() if m else ""
                # Tech fingerprinting from headers
                tech_hints = []
                for h, v in r.headers.items():
                    hl = h.lower()
                    if "x-powered-by" in hl: tech_hints.append(v)
                    if "x-generator"  in hl: tech_hints.append(v)
                    if "x-aspnet"     in hl: tech_hints.append("ASP.NET")
                if info["server"]:            tech_hints.append(info["server"])
                info["techs"] = list(dict.fromkeys(tech_hints))  # dedupe
                on_output(
                    f"[WebEnum] ✓ Probe: {url} → {r.status_code} | "
                    f"'{info['title'][:50]}' | tech: {info['techs'] or ['unknown']}\n"
                )
        except ImportError:
            # Fallback: use urllib (stdlib, always available)
            try:
                import urllib.request as _ur, ssl as _ssl
                ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                req = _ur.Request(url, headers={"User-Agent": "WebEnum/1.0"})
                with _ur.urlopen(req, timeout=12, context=ctx) as resp:
                    info["status"] = resp.status
                    info["server"] = resp.headers.get("Server", "")
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                    import re as _re
                    m = _re.search(r"<title[^>]*>([^<]{1,120})</title>", body, _re.IGNORECASE)
                    info["title"] = m.group(1).strip() if m else ""
                    on_output(f"[WebEnum] ✓ Probe: {url} → {info['status']} | '{info['title'][:50]}'\n")
            except Exception as e:
                on_output(f"[WebEnum] ⚠ Probe failed: {e}\n")
        except Exception as e:
            on_output(f"[WebEnum] ⚠ Probe failed: {e}\n")
        return info


    def start(self, targets: list[str], on_output, on_complete) -> threading.Thread:
        """Start parallel web recon (non-blocking). Returns the daemon thread."""
        if not targets:
            raise ValueError("WebEnumerationEngine requires at least one target.")
        self._cancel_flag.clear()
        self._results = {t: WebTargetResult(t) for t in targets}
        thread = threading.Thread(
            target=self._run, args=(targets, on_output, on_complete), daemon=True
        )
        thread.start()
        return thread

    def cancel(self):
        self._cancel_flag.set()
        with self._proc_lock:
            for proc in list(self._processes.values()):
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        pass
        return True

    def get_results(self) -> dict:
        return {
            t: {"status": r.status, "findings": r.findings, "error": r.error}
            for t, r in self._results.items()
        }

    # ── Internal ─────────────────────────────────────────────────────

    def _ram_ok(self) -> bool:
        if not _PSUTIL:
            return True
        return psutil.virtual_memory().percent < RAM_THRESHOLD

    def _run_proc(self, cmd: list[str], on_output, tag: str,
                  timeout: int = 300) -> tuple[int, list[str]]:
        """
        Run a subprocess, stream stdout line-by-line via on_output.
        Returns (returncode, list_of_output_lines).
        """
        lines = []
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, preexec_fn=os.setsid,
            )
            with self._proc_lock:
                self._processes[tag] = proc

            for line in proc.stdout:
                if self._cancel_flag.is_set():
                    break
                stripped = line.rstrip()
                if stripped:
                    on_output(f"  [{tag}] {stripped}\n")
                    lines.append(stripped)

            proc.wait(timeout=5)
            return proc.returncode, lines
        except FileNotFoundError:
            return -1, []
        except Exception as e:
            on_output(f"  [{tag}] ⚠ {e}\n")
            return -1, []
        finally:
            with self._proc_lock:
                self._processes.pop(tag, None)

    def _scan_target(self, target: str, on_output) -> WebTargetResult:
        result = self._results[target]
        result.status = "scanning"

        # RAM guard
        waited = 0
        while not self._ram_ok() and waited < 30:
            on_output(f"[WebEnum] ⚠ RAM >{RAM_THRESHOLD}% — waiting… ({target})\n")
            threading.Event().wait(5); waited += 5
        if not self._ram_ok():
            result.status = "failed"
            result.error  = "RAM threshold exceeded"
            return result

        # Normalise target → ensure scheme for web tools
        raw_target = target
        if not target.startswith("http"):
            # Default to https, fall back to http if 443 fails
            url_target = f"https://{target}"
        else:
            url_target = target

        tag = re.sub(r"[^\w]", "_", raw_target)[:30]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        tmp_dir = f"/tmp/web_enum_{tag}_{timestamp}"
        os.makedirs(tmp_dir, exist_ok=True)

        on_output(f"\n[WebEnum] ▶ {raw_target}\n")

        # ── STAGE 1: Python-native HTTP probe (always runs) ──────────
        on_output(f"[WebEnum] 📡 Stage 1 — Probing: {url_target}\n")
        probe_info = self._probe_web(url_target, on_output, tag)
        result.techs = probe_info.get("techs", [])

        # ── STAGE 2: katana (URL crawl) ──────────────────────────────
        katana_out = os.path.join(tmp_dir, "katana.txt")
        crawled_urls = []
        if self.tools["katana"] and not self._cancel_flag.is_set():
            on_output(f"[WebEnum] 🕷 Stage 2 — katana crawl: {url_target}\n")
            cmd = [
                self.tools["katana"],
                "-u", url_target,
                "-depth", "3",
                "-silent",
                "-o", katana_out,
                "-timeout", "10",
                "-c", "5",          # 5 concurrent
            ]
            self._run_proc(cmd, on_output, f"katana/{tag}")
            if os.path.exists(katana_out):
                with open(katana_out) as fh:
                    crawled_urls = [l.strip() for l in fh if l.strip()]
                result.urls = crawled_urls[:200]
                on_output(f"[WebEnum] ✓ katana done — {len(crawled_urls)} URLs\n")
        else:
            on_output(f"[WebEnum] ⏭ katana not installed — skipping Stage 2\n")

        # Write URL list for nuclei input
        url_list_file = os.path.join(tmp_dir, "targets.txt")
        with open(url_list_file, "w") as fh:
            fh.write(url_target + "\n")
            for u in crawled_urls[:100]:
                fh.write(u + "\n")

        # ── STAGE 3: nuclei (vuln scan) ──────────────────────────────
        nuclei_out = os.path.join(tmp_dir, "nuclei.jsonl")
        nuclei_findings = []
        if self.tools["nuclei"] and not self._cancel_flag.is_set():
            on_output(f"[WebEnum] 🔴 Stage 3 — nuclei scan: {url_target}\n")
            cmd = [
                self.tools["nuclei"],
                "-l", url_list_file,
                "-severity", "critical,high,medium",
                "-json-export", nuclei_out,
                "-silent",
                "-timeout", "10",
                "-rate-limit", "50",
            ]
            if self.nuclei_templates:
                cmd += ["-t", self.nuclei_templates]
            self._run_proc(cmd, on_output, f"nuclei/{tag}", timeout=600)
            if os.path.exists(nuclei_out):
                try:
                    with open(nuclei_out) as fh:
                        for line in fh:
                            try:
                                nuclei_findings.append(json.loads(line))
                            except Exception:
                                pass
                    on_output(f"[WebEnum] ✓ nuclei done — {len(nuclei_findings)} findings\n")
                except Exception:
                    pass
        else:
            on_output(f"[WebEnum] ⏭ nuclei not installed — skipping Stage 3\n")

        # ── STAGE 4: ffuf (directory brute-force) ────────────────────
        ffuf_out = os.path.join(tmp_dir, "ffuf.json")
        ffuf_findings = []
        if self.tools["ffuf"] and self.wordlist and not self._cancel_flag.is_set():
            on_output(f"[WebEnum] 📂 Stage 4 — ffuf dir brute: {url_target}\n")
            cmd = [
                self.tools["ffuf"],
                "-u", f"{url_target}/FUZZ",
                "-w", self.wordlist,
                "-o", ffuf_out,
                "-of", "json",
                "-t", "50",          # 50 threads
                "-mc", "200,204,301,302,307,401,403,405",
                "-timeout", "10",
                "-s",                # silent mode
            ]
            self._run_proc(cmd, on_output, f"ffuf/{tag}", timeout=180)
            if os.path.exists(ffuf_out):
                try:
                    data = json.load(open(ffuf_out))
                    ffuf_findings = data.get("results", [])
                    on_output(f"[WebEnum] ✓ ffuf done — {len(ffuf_findings)} paths\n")
                except Exception:
                    pass
        else:
            on_output(f"[WebEnum] ⏭ ffuf/wordlist not available — skipping Stage 4\n")

        # ── STAGE 5: Neo4j ingest ─────────────────────────────────────
        if not self._cancel_flag.is_set():
            on_output(f"[WebEnum] 💾 Stage 5 — ingesting to Neo4j\n")
            try:
                from cyber_range.services.web_enum_ingest import WebEnumIngest
                ingestor = WebEnumIngest()
                count = ingestor.ingest(
                    target=raw_target,
                    url=url_target,
                    techs=result.techs,
                    urls=result.urls,
                    nuclei_findings=nuclei_findings,
                    ffuf_findings=ffuf_findings,
                    on_output=on_output,
                )
                result.findings = count
                on_output(f"[WebEnum] ✓ {raw_target} → {count} findings in Neo4j\n")
            except Exception as e:
                on_output(f"[WebEnum] ⚠ Neo4j ingest error: {e}\n")

        result.status = "done"
        return result

    def _run(self, targets: list[str], on_output, on_complete):
        tools_available = [k for k, v in self.tools.items() if v]
        on_output(
            f"\n{'='*60}\n"
            f"[WebEnum] Starting web recon pipeline\n"
            f"  Targets  : {len(targets)}\n"
            f"  Workers  : {self._max_workers}\n"
            f"  Tools    : {', '.join(tools_available) or 'none — all stages skipped'}\n"
            f"  Wordlist : {self.wordlist or 'not found'}\n"
            f"  Nuclei-T : {self.nuclei_templates or 'not found'}\n"
            f"{'='*60}\n\n"
        )

        cancelled = False
        max_workers = max(1, min(len(targets), self._max_workers))

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(self._scan_target, t, on_output): t for t in targets}
                for future in as_completed(futures):
                    if self._cancel_flag.is_set():
                        cancelled = True
                        break
                    try:
                        future.result()
                    except Exception as e:
                        t = futures[future]
                        on_output(f"[WebEnum] ✗ Unhandled error for {t}: {e}\n")
        except Exception as e:
            on_output(f"[WebEnum] ✗ Engine error: {e}\n")
            cancelled = True

        done    = sum(1 for r in self._results.values() if r.status == "done")
        failed  = sum(1 for r in self._results.values() if r.status == "failed")
        total_f = sum(r.findings for r in self._results.values())

        on_output(
            f"\n{'='*60}\n"
            f"[WebEnum] Web recon complete\n"
            f"  Done   : {done}/{len(targets)}\n"
            f"  Failed : {failed}\n"
            f"  Total findings: {total_f}\n"
            f"{'='*60}\n"
        )
        on_complete(cancelled or self._cancel_flag.is_set(), self._results)


__all__ = ["WebEnumerationEngine", "WebTargetResult", "is_ip_target"]
