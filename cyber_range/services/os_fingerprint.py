"""
os_fingerprint.py
=================
Auto-detect the target OS to select the correct SSG benchmark.

Methods (in priority order):
  1. SSH banner grab → parse for distro/version
  2. nmap OS detection (if available)
  3. HTTP Server header heuristics
  4. TCP stack fingerprint heuristics

Returns a dict with:
  - os_family: "rhel", "ubuntu", "debian", "centos", "almalinux", "fedora",
               "ol" (Oracle Linux), "windows", "ocp" (OpenShift), "unknown"
  - os_version: e.g. "8", "9", "22.04"
  - confidence: float 0.0-1.0
  - method: how it was detected
  - recommended_benchmark: filename like "ssg-rhel9-ds.xml"
"""

import re
import socket
import subprocess

_TIMEOUT = 5

# Map OS family → SSG benchmark filename
_BENCHMARK_MAP = {
    "rhel7":       "ssg-ol7-ds.xml",       # RHEL 7 uses OL7 as closest match
    "rhel8":       "ssg-rhel8-ds.xml",
    "rhel9":       "ssg-rhel9-ds.xml",
    "centos7":     "ssg-ol7-ds.xml",
    "centos8":     "ssg-centos8-ds.xml",
    "almalinux9":  "ssg-almalinux9-ds.xml",
    "ol7":         "ssg-ol7-ds.xml",
    "ol8":         "ssg-ol8-ds.xml",
    "ol9":         "ssg-ol9-ds.xml",
    "ol10":        "ssg-ol10-ds.xml",
    "debian12":    "ssg-debian12-ds.xml",
    "debian11":    "ssg-debian12-ds.xml",  # closest match
    "ubuntu22.04": "ssg-ubuntu2204-ds.xml",
    "ubuntu24.04": "ssg-ubuntu2404-ds.xml",
    "ubuntu20.04": "ssg-ubuntu2204-ds.xml",  # closest match
    "fedora":      "ssg-fedora-ds.xml",
    "cs9":         "ssg-cs9-ds.xml",
    "cs10":        "ssg-cs10-ds.xml",
    "kali":        "ssg-debian12-ds.xml",  # Kali is Debian-based
    "windows":     None,  # no SSG for windows via DataStream
}


def _ssh_banner(host: str) -> dict:
    """Grab SSH banner and parse OS info."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect((host, 22))
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        sock.close()

        if not banner:
            return {}

        result = {"method": "ssh_banner", "raw": banner}
        b = banner.lower()

        # Parse SSH banner for OS clues
        # OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 → Ubuntu 22.04
        if "ubuntu" in b:
            result["os_family"] = "ubuntu"
            # Try to extract version from build string
            m = re.search(r"ubuntu[_-]?(\d+)", b)
            if "openssh_9.6" in b or "openssh_9.7" in b or "openssh_9.8" in b:
                result["os_version"] = "24.04"
            elif "openssh_8.9" in b or "openssh_9.0" in b:
                result["os_version"] = "22.04"
            elif "openssh_8.2" in b or "openssh_8.4" in b:
                result["os_version"] = "20.04"
            else:
                result["os_version"] = "22.04"  # default
            result["confidence"] = 0.8
        elif "debian" in b or "deb" in b:
            result["os_family"] = "debian"
            if "openssh_9." in b:
                result["os_version"] = "12"
            else:
                result["os_version"] = "12"
            result["confidence"] = 0.7
        elif "el9" in b or "redhat" in b and "9" in b:
            result["os_family"] = "rhel"
            result["os_version"] = "9"
            result["confidence"] = 0.8
        elif "el8" in b or "redhat" in b and "8" in b:
            result["os_family"] = "rhel"
            result["os_version"] = "8"
            result["confidence"] = 0.8
        elif "fedora" in b:
            result["os_family"] = "fedora"
            result["os_version"] = ""
            result["confidence"] = 0.7
        elif "centos" in b:
            result["os_family"] = "centos"
            result["os_version"] = "8"
            result["confidence"] = 0.7
        else:
            # Generic Linux from OpenSSH
            if "openssh" in b:
                result["os_family"] = "linux"
                result["os_version"] = ""
                result["confidence"] = 0.3

        return result
    except Exception:
        return {}


def _nmap_os(host: str) -> dict:
    """Use nmap -O for OS detection (requires root or nmap installed)."""
    try:
        r = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "-T4", host],
            capture_output=True, text=True, timeout=30
        )
        output = r.stdout.lower()

        result = {"method": "nmap_os", "raw": output[:500]}

        # Parse nmap output
        for line in output.splitlines():
            if "running:" in line or "os details:" in line:
                detail = line.split(":", 1)[1].strip()
                if "ubuntu" in detail:
                    result["os_family"] = "ubuntu"
                    m = re.search(r"(\d+\.\d+)", detail)
                    result["os_version"] = m.group(1) if m else "22.04"
                    result["confidence"] = 0.85
                elif "debian" in detail:
                    result["os_family"] = "debian"
                    m = re.search(r"(\d+)", detail)
                    result["os_version"] = m.group(1) if m else "12"
                    result["confidence"] = 0.85
                elif "red hat" in detail or "rhel" in detail or "centos" in detail:
                    result["os_family"] = "rhel"
                    m = re.search(r"(\d+)", detail)
                    result["os_version"] = m.group(1) if m else "9"
                    result["confidence"] = 0.85
                elif "fedora" in detail:
                    result["os_family"] = "fedora"
                    result["os_version"] = ""
                    result["confidence"] = 0.8
                elif "windows" in detail:
                    result["os_family"] = "windows"
                    result["os_version"] = ""
                    result["confidence"] = 0.9
                elif "linux" in detail:
                    # Generic Linux — try kernel version
                    result["os_family"] = "linux"
                    m = re.search(r"(\d+\.\d+)", detail)
                    result["os_version"] = m.group(1) if m else ""
                    result["confidence"] = 0.5

        return result if "os_family" in result else {}
    except Exception:
        return {}


def _http_server_header(host: str) -> dict:
    """Infer OS from HTTP Server header."""
    try:
        import ssl
        from urllib.request import Request, urlopen

        for scheme, port in [("https", 443), ("http", 80), ("http", 8080)]:
            try:
                url = f"{scheme}://{host}/"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = Request(url, headers={"User-Agent": "Aegis-OS-Fingerprint/1.0"})
                resp = urlopen(req, timeout=_TIMEOUT, context=ctx)
                server = resp.headers.get("server", "").lower()
                x_powered = resp.headers.get("x-powered-by", "").lower()

                result = {"method": "http_header", "raw": f"Server: {server}, X-Powered-By: {x_powered}"}

                combined = server + " " + x_powered
                if "ubuntu" in combined:
                    result.update(os_family="ubuntu", os_version="22.04", confidence=0.5)
                elif "debian" in combined:
                    result.update(os_family="debian", os_version="12", confidence=0.5)
                elif "red hat" in combined or "el8" in combined or "el9" in combined:
                    result.update(os_family="rhel", os_version="9", confidence=0.5)
                elif "centos" in combined:
                    result.update(os_family="centos", os_version="8", confidence=0.5)
                elif "fedora" in combined:
                    result.update(os_family="fedora", os_version="", confidence=0.5)
                elif "win" in combined or "iis" in combined:
                    result.update(os_family="windows", os_version="", confidence=0.6)

                if "os_family" in result:
                    return result
            except Exception:
                continue
        return {}
    except Exception:
        return {}


def fingerprint(host: str, on_log=None) -> dict:
    """
    Auto-detect OS of target host.

    Returns:
        {
            "os_family": str,
            "os_version": str,
            "confidence": float,
            "method": str,
            "recommended_benchmark": str or None,
            "raw": str
        }
    """
    log = on_log or (lambda m: None)

    # Try methods in priority order
    for detect_fn, label in [
        (_ssh_banner, "SSH banner"),
        (_nmap_os, "nmap OS detection"),
        (_http_server_header, "HTTP Server header"),
    ]:
        log(f"[OS-FP]   Trying {label}...\n")
        result = detect_fn(host)
        if result and "os_family" in result:
            family = result["os_family"]
            version = result.get("os_version", "")
            conf = result.get("confidence", 0.0)

            # Select best benchmark
            key = f"{family}{version}"
            benchmark = _BENCHMARK_MAP.get(key)
            if not benchmark and family in ("rhel", "centos", "almalinux"):
                benchmark = _BENCHMARK_MAP.get(f"{family}{version[0]}" if version else "rhel9")
            if not benchmark and family == "linux":
                benchmark = "ssg-debian12-ds.xml"  # safe default for generic Linux

            result["recommended_benchmark"] = benchmark
            log(f"[OS-FP]   Detected: {family} {version} (confidence: {conf:.0%}, via {result.get('method', '?')})\n")
            if benchmark:
                log(f"[OS-FP]   Recommended benchmark: {benchmark}\n")
            return result

    # No detection
    log(f"[OS-FP]   Could not determine target OS\n")
    return {
        "os_family": "unknown",
        "os_version": "",
        "confidence": 0.0,
        "method": "none",
        "recommended_benchmark": None,
        "raw": "",
    }


__all__ = ["fingerprint"]
