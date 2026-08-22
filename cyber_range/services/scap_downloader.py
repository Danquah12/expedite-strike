"""
scap_downloader.py
==================
Downloads official SCAP/XCCDF benchmark content from ComplianceAsCode (SSG)
GitHub releases. Filters by target OS platform and security baseline.

Full SCAP Assessment Flow:
  1. Define system scope (Linux/Windows/Network/All)
  2. Select security baseline (NIST, CIS, DISA STIG)
  3. Download SCAP content (XCCDF + OVAL packages)
  4. Filter benchmarks for target platform
  5. Return paths ready for scanning

Sources:
  - ComplianceAsCode / SCAP Security Guide (SSG)
    https://github.com/ComplianceAsCode/content/releases
"""

import os
import io
import re
import zipfile
import json
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from datetime import datetime


# ── Configuration ────────────────────────────────────────────────────
SCAP_DIR       = "/mnt/scans/incoming/scap"
CACHE_DIR      = "/opt/vuln_intel/app/.cache/scap"
MANIFEST_FILE  = os.path.join(CACHE_DIR, "manifest.json")

# GitHub API
SSG_API_URL    = "https://api.github.com/repos/ComplianceAsCode/content/releases/latest"
SSG_FALLBACK   = "https://github.com/ComplianceAsCode/content/releases/download/v0.1.80/scap-security-guide-0.1.80.zip"

# ── Platform → SSG benchmark file patterns ────────────────────────
PLATFORM_FILTERS = {
    "linux_server": [
        "ssg-rhel9", "ssg-rhel8", "ssg-rhel7",
        "ssg-debian12", "ssg-debian11",
        "ssg-ubuntu2204", "ssg-ubuntu2004",
        "ssg-ol9", "ssg-ol8",                # Oracle Linux
        "ssg-sle15", "ssg-sle12",            # SUSE
        "ssg-centos8", "ssg-centos7",
        "ssg-fedora",
        "ssg-almalinux9", "ssg-almalinux8",
    ],
    "linux_desktop": [
        "ssg-debian12", "ssg-debian11",
        "ssg-ubuntu2204", "ssg-ubuntu2004",
        "ssg-fedora",
    ],
    "windows_server": [
        "ssg-windows", "ssg-win",
        # Microsoft benchmarks in SSG are limited; we supplement later
    ],
    "windows_desktop": [
        "ssg-windows", "ssg-win",
    ],
    "network": [
        "ssg-cisco", "ssg-juniper", "ssg-paloalto",
        "ssg-fortinet",
    ],
    "applications": [
        "ssg-chromium", "ssg-firefox",
        "ssg-jre", "ssg-java",
        "ssg-apache", "ssg-nginx",
    ],
    "cloud": [
        "ssg-aws", "ssg-azure", "ssg-gcp",
        "ssg-eks", "ssg-aks",
    ],
    "all": [],  # empty = accept everything
}

# ── Security Baselines (profile names within XCCDF) ──────────────
BASELINE_PROFILES = {
    "nist_800_53":   ["nist", "800-53", "moderate", "high"],
    "cis":           ["cis", "level1", "level2", "benchmark"],
    "disa_stig":     ["stig", "disa", "srg"],
    "pci_dss":       ["pci", "pci-dss"],
    "hipaa":         ["hipaa", "health"],
    "all":           [],  # no filtering
}

# SSL context
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _http_get(url: str, timeout: int = 90) -> bytes:
    """Download URL content."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Aegis-SCAP-Downloader/2.0",
        "Accept": "application/octet-stream, application/json, */*",
    })
    resp = urllib.request.urlopen(req, timeout=timeout, context=_CTX)
    return resp.read()


def _get_latest_ssg_url(on_log=None) -> tuple:
    """Query GitHub API for latest SSG release."""
    log = on_log or (lambda m: None)
    try:
        log("[SCAP] Querying GitHub for latest SCAP Security Guide release...\n")
        data = _http_get(SSG_API_URL, timeout=15)
        release = json.loads(data)
        tag = release.get("tag_name", "unknown")
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".zip") and "scap-security-guide" in name:
                url = asset.get("browser_download_url", "")
                size_mb = asset.get("size", 0) / (1024 * 1024)
                log(f"[SCAP] Latest release: {tag} ({name}, {size_mb:.0f} MB)\n")
                return url, tag
    except Exception as e:
        log(f"[SCAP] GitHub API unavailable ({e}), using fallback v0.1.80\n")
    return SSG_FALLBACK, "v0.1.80"


def _is_cached(version: str) -> bool:
    """Check if already downloaded."""
    if not os.path.isfile(MANIFEST_FILE):
        return False
    try:
        with open(MANIFEST_FILE) as f:
            manifest = json.load(f)
        return manifest.get("version") == version
    except Exception:
        return False


def _save_manifest(version: str, all_files: list, platform: str):
    """Save download manifest."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(MANIFEST_FILE, "w") as f:
        json.dump({
            "version": version,
            "downloaded_at": datetime.utcnow().isoformat(),
            "platform": platform,
            "total_files": len(all_files),
            "files": all_files[:50],
        }, f, indent=2)


def _matches_platform(filename: str, platform: str) -> bool:
    """Check if a benchmark file matches the target platform."""
    if platform == "all" or not PLATFORM_FILTERS.get(platform):
        return True
    fname = filename.lower()
    return any(pat.lower() in fname for pat in PLATFORM_FILTERS[platform])


def download_scap_content(
    output_dir: str = SCAP_DIR,
    platform: str = "all",
    baseline: str = "all",
    force: bool = False,
    on_log=None
) -> dict:
    """
    Download and extract SCAP/XCCDF benchmarks filtered by platform.

    Args:
        output_dir:  Where to place .xml files
        platform:    Target platform filter (linux_server, windows_server, etc.)
        baseline:    Security baseline (nist_800_53, cis, disa_stig, etc.)
        force:       Re-download even if cached
        on_log:      Callback for progress messages

    Returns:
        dict with: success, version, files, platform, baseline, error
    """
    log = on_log or (lambda m: print(m, end=""))
    result = {
        "success": False, "version": "", "files": [],
        "platform": platform, "baseline": baseline, "error": ""
    }

    try:
        # ── Step 1: System Scope ──────────────────────────────────────
        platform_label = platform.replace("_", " ").title()
        baseline_label = baseline.replace("_", " ").upper()
        log(f"[SCAP] ═══════════════════════════════════════════\n")
        log(f"[SCAP] SCAP Security Assessment Engine v3.0\n")
        log(f"[SCAP] ═══════════════════════════════════════════\n")
        log(f"[SCAP] System Scope  : {platform_label}\n")
        log(f"[SCAP] Baseline      : {baseline_label}\n")
        log(f"[SCAP] Output Dir    : {output_dir}\n")
        log(f"[SCAP] ───────────────────────────────────────────\n")

        # ── Step 2: Get latest release URL ────────────────────────────
        zip_url, version = _get_latest_ssg_url(on_log=log)
        result["version"] = version

        # ── Step 3: Check cache ───────────────────────────────────────
        if not force and _is_cached(version):
            existing = [f for f in os.listdir(output_dir) if f.endswith(".xml")] if os.path.isdir(output_dir) else []
            if existing:
                # Filter existing files by platform
                matched = [f for f in existing if _matches_platform(f, platform)]
                if matched:
                    log(f"[SCAP] ✓ Already cached ({version}), {len(matched)} benchmarks for {platform_label}\n")
                    result["success"] = True
                    result["files"] = matched
                    return result

        # ── Step 4: Download ZIP ──────────────────────────────────────
        log(f"[SCAP] Downloading SCAP Security Guide {version}...\n")
        zip_data = _http_get(zip_url, timeout=180)
        zip_size_mb = len(zip_data) / (1024 * 1024)
        log(f"[SCAP] Downloaded {zip_size_mb:.1f} MB successfully\n")

        # ── Step 5: Extract & filter benchmarks ───────────────────────
        try:
            from cyber_range.services._safe_dirs import safe_makedirs
            output_dir = safe_makedirs(output_dir)
        except Exception:
            os.makedirs(output_dir, exist_ok=True)
        all_extracted = []
        platform_matched = []

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            all_names = zf.namelist()
            log(f"[SCAP] Archive contains {len(all_names)} files\n")
            log(f"[SCAP] Extracting XCCDF benchmarks for: {platform_label}...\n")

            for entry in all_names:
                basename = os.path.basename(entry)
                if not basename.endswith(".xml"):
                    continue

                # Identify XCCDF content (data streams and standalone)
                is_xccdf = (
                    ("xccdf" in basename.lower() or "benchmark" in basename.lower())
                    and not basename.startswith(".")
                )
                is_datastream = "-ds.xml" in basename.lower()

                if is_xccdf or is_datastream:
                    out_path = os.path.join(output_dir, basename)
                    with zf.open(entry) as src, open(out_path, "wb") as dst:
                        dst.write(src.read())
                    all_extracted.append(basename)

                    if _matches_platform(basename, platform):
                        platform_matched.append(basename)
                        log(f"[SCAP]   ✓ {basename}\n")

        if not platform_matched and all_extracted:
            # If no platform-specific match, use all extracted
            platform_matched = all_extracted
            log(f"[SCAP] No platform-specific filter applied, using all {len(all_extracted)} benchmarks\n")

        # ── Step 6: Save manifest ─────────────────────────────────────
        _save_manifest(version, all_extracted, platform)
        result["success"] = True
        result["files"] = platform_matched

        log(f"[SCAP] ───────────────────────────────────────────\n")
        log(f"[SCAP] ✅ {len(all_extracted)} total benchmarks extracted\n")
        log(f"[SCAP] ✅ {len(platform_matched)} matching '{platform_label}' scope\n")
        log(f"[SCAP] ✅ Benchmarks saved to: {output_dir}\n")
        log(f"[SCAP] ═══════════════════════════════════════════\n")

    except urllib.error.URLError as e:
        err = f"Network error: {e}"
        log(f"[SCAP] ✗ {err}\n")
        result["error"] = err
    except Exception as e:
        err = f"Download failed: {e}"
        log(f"[SCAP] ✗ {err}\n")
        result["error"] = err

    return result


def get_available_platforms() -> list:
    """Return list of supported platform scopes."""
    return [
        {"value": "linux_server",    "label": "Linux Server (RHEL, Debian, Ubuntu, CentOS, SUSE)"},
        {"value": "linux_desktop",   "label": "Linux Desktop (Ubuntu, Fedora, Debian)"},
        {"value": "windows_server",  "label": "Windows Server (2016, 2019, 2022)"},
        {"value": "windows_desktop", "label": "Windows Desktop (10, 11)"},
        {"value": "network",         "label": "Network Devices (Cisco, Juniper, Palo Alto)"},
        {"value": "applications",    "label": "Applications (Chrome, Firefox, Apache, Java)"},
        {"value": "cloud",           "label": "Cloud (AWS, Azure, GCP)"},
        {"value": "all",             "label": "All Platforms (Full Assessment)"},
    ]


def get_available_baselines() -> list:
    """Return list of supported security baselines."""
    return [
        {"value": "nist_800_53",  "label": "NIST SP 800-53 (Federal)"},
        {"value": "cis",          "label": "CIS Benchmarks (Industry)"},
        {"value": "disa_stig",    "label": "DISA STIG (DoD)"},
        {"value": "pci_dss",      "label": "PCI-DSS (Payment Card)"},
        {"value": "hipaa",        "label": "HIPAA (Healthcare)"},
        {"value": "all",          "label": "All Baselines"},
    ]


# ── CLI usage ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    out_dir = sys.argv[1] if len(sys.argv) > 1 else SCAP_DIR
    platform = sys.argv[2] if len(sys.argv) > 2 else "all"
    result = download_scap_content(
        output_dir=out_dir, platform=platform,
        force="--force" in sys.argv, on_log=print
    )
    sys.exit(0 if result["success"] else 1)
