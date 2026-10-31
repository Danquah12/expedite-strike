# =========================================
# utils_cve.py — Centralized CVE/CWE Parsing
# =========================================

import re

# -----------------------------------------
# CVE Extraction (CVE-YYYY-NNNN)
# -----------------------------------------
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(text: str):
    """
    Extract CVE identifiers from free text.
    Returns a list of unique CVE strings.
    """
    if not text:
        return []

    found = CVE_REGEX.findall(str(text))
    return list(set(c.upper() for c in found))


# -----------------------------------------
# CWE Extraction (CWE-NNN)
# -----------------------------------------
CWE_REGEX = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)

def extract_cwe(text: str):
    """
    Extract CWE identifiers from text.
    Example: 'This issue maps to CWE-79 and CWE-89'
    Returns unique CWE strings.
    """
    if not text:
        return []

    found = CWE_REGEX.findall(str(text))
    return list(set(c.upper() for c in found))
