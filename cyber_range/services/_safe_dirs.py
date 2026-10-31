# -*- coding: utf-8 -*-
"""
Safe directory creation for read-only filesystem fallback.
If /mnt/scans is read-only, redirect to /opt/vuln_intel/app/scans/.
"""
import os

_APP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_FALLBACK_BASE = os.path.join(_APP_ROOT, "scans")


def safe_makedirs(path: str) -> str:
    """Try to create `path`. If the filesystem is read-only, remap
    /mnt/scans/... → /opt/vuln_intel/app/scans/... and return the new path."""
    try:
        os.makedirs(path, exist_ok=True)
        return path
    except OSError:
        # Remap: /mnt/scans/incoming/zap → <APP>/scans/incoming/zap
        if "/mnt/scans" in path:
            relative = path.split("/mnt/scans")[-1].lstrip("/")
            new_path = os.path.join(_FALLBACK_BASE, relative)
        else:
            new_path = os.path.join(_FALLBACK_BASE, os.path.basename(path))
        os.makedirs(new_path, exist_ok=True)
        return new_path
