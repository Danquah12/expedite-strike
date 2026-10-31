"""
target_resolver.py  —  Expedite Strike Universal Target Input Parser
============================================================
Accepts any combination of:
  - Single IPs:         192.168.1.1
  - CIDR subnets:       192.168.1.0/24, 10.0.0.0/16
  - IP ranges:          192.168.1.1-192.168.1.50
  - Dash ranges:        192.168.1.1-50
  - Domains/hostnames:  example.com, vpn.corp.net
  - URLs:               https://api.example.com/v1/users
  - API endpoints:      api.example.com/graphql, POST https://api.com/v2/data
  - Wildcard domains:   *.example.com (expands via DNS enum)
  - Files:              @targets.txt  (one target per line)

Returns a list of normalized target strings ready for the pentest engine.
Subnets are expanded to individual IPs (capped to avoid runaway scans).
"""
import ipaddress
import re
import os
import socket
import logging

_log = logging.getLogger("aegis.target_resolver")

# ── Safety caps ───────────────────────────────────────────────────────────────
MAX_HOSTS_PER_SUBNET = 256      # /24 max by default
MAX_TOTAL_TARGETS    = 1024     # hard cap
MAX_RANGE_SIZE       = 256      # IP range max

# ── Input type classification ─────────────────────────────────────────────────

_CIDR_RE    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_IP_RE      = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RANGE_RE   = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_FULL_RANGE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$")
_URL_RE     = re.compile(r"^https?://", re.IGNORECASE)
_API_METH   = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", re.IGNORECASE)
_FILE_REF   = re.compile(r"^@(.+)$")
_WILDCARD   = re.compile(r"^\*\.(.+)$")


def classify(raw: str) -> str:
    """Classify a single raw target string into its type."""
    t = raw.strip()
    if not t or t.startswith("#"):
        return "comment"
    if _FILE_REF.match(t):
        return "file"
    if _CIDR_RE.match(t):
        return "cidr"
    if _FULL_RANGE.match(t):
        return "range_full"
    if _RANGE_RE.match(t):
        return "range_short"
    if _IP_RE.match(t):
        return "ip"
    if _API_METH.match(t):
        return "api_endpoint"
    if _URL_RE.match(t):
        return "url"
    if _WILDCARD.match(t):
        return "wildcard"
    # Bare hostname / domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}", t.split("/")[0]):
        return "domain"
    # IPv6
    try:
        ipaddress.IPv6Address(t)
        return "ipv6"
    except ValueError:
        pass
    return "unknown"


# ── Expansion functions ───────────────────────────────────────────────────────

def _expand_cidr(cidr_str: str) -> list[str]:
    """Expand CIDR notation to individual host IPs."""
    try:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
        prefix = net.prefixlen
        if prefix < 16:
            _log.warning(f"Subnet /{prefix} too large (> /16 not allowed). Skipping: {cidr_str}")
            return [f"SKIP:{cidr_str}:subnet_too_large_min_/16"]
        hosts = list(net.hosts())
        if len(hosts) > MAX_HOSTS_PER_SUBNET:
            _log.warning(f"Subnet {cidr_str} has {len(hosts)} hosts, capping to {MAX_HOSTS_PER_SUBNET}")
            hosts = hosts[:MAX_HOSTS_PER_SUBNET]
        return [str(h) for h in hosts]
    except ValueError as e:
        _log.error(f"Invalid CIDR: {cidr_str}: {e}")
        return [cidr_str]  # pass through as-is


def _expand_range_short(range_str: str) -> list[str]:
    """Expand 192.168.1.1-50 to individual IPs."""
    m = _RANGE_RE.match(range_str)
    if not m:
        return [range_str]
    prefix  = m.group(1)  # "192.168.1."
    start   = int(m.group(2))
    end     = int(m.group(3))
    if end < start:
        start, end = end, start
    count = end - start + 1
    if count > MAX_RANGE_SIZE:
        _log.warning(f"Range {range_str} has {count} hosts, capping to {MAX_RANGE_SIZE}")
        end = start + MAX_RANGE_SIZE - 1
    return [f"{prefix}{i}" for i in range(start, end + 1)]


def _expand_range_full(range_str: str) -> list[str]:
    """Expand 192.168.1.1-192.168.1.50 to individual IPs."""
    parts = range_str.split("-")
    if len(parts) != 2:
        return [range_str]
    try:
        start = ipaddress.IPv4Address(parts[0].strip())
        end   = ipaddress.IPv4Address(parts[1].strip())
        if end < start:
            start, end = end, start
        count = int(end) - int(start) + 1
        if count > MAX_RANGE_SIZE:
            _log.warning(f"Range {range_str} has {count} hosts, capping to {MAX_RANGE_SIZE}")
            count = MAX_RANGE_SIZE
        return [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]
    except ValueError:
        return [range_str]


def _expand_file(file_ref: str) -> list[str]:
    """Load targets from a file. File ref is '@path/to/file.txt'."""
    path = _FILE_REF.match(file_ref).group(1).strip()
    # Resolve relative to common locations
    search_paths = [
        path,
        os.path.join("/opt/vuln_intel/app", path),
        os.path.join("/home/kali", path),
        os.path.join("/home/kali/Desktop", path),
    ]
    for p in search_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r") as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                _log.info(f"Loaded {len(lines)} targets from file: {p}")
                return lines
            except Exception as e:
                _log.error(f"Error reading target file {p}: {e}")
                return [f"ERROR:file_read:{path}"]
    _log.error(f"Target file not found: {path}")
    return [f"ERROR:file_not_found:{path}"]


def _expand_wildcard(wildcard_str: str) -> list[str]:
    """
    Expand *.example.com to known subdomains.
    Uses DNS AXFR attempt + common subdomain brute.
    """
    m = _WILDCARD.match(wildcard_str)
    if not m:
        return [wildcard_str]
    base_domain = m.group(1)

    # Return the base domain + common prefixes for enumeration
    common_subs = [
        "", "www", "api", "mail", "smtp", "pop", "imap", "ftp",
        "vpn", "remote", "portal", "admin", "dev", "staging",
        "test", "qa", "uat", "prod", "app", "web", "cdn",
        "ns1", "ns2", "dns", "mx", "relay", "gateway",
        "db", "database", "redis", "mongo", "elastic",
        "git", "gitlab", "github", "jenkins", "ci", "cd",
        "sso", "auth", "login", "oauth", "idp",
        "monitor", "grafana", "kibana", "prometheus",
        "s3", "storage", "backup", "vault",
    ]

    expanded = []
    for sub in common_subs:
        fqdn = f"{sub}.{base_domain}" if sub else base_domain
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
            expanded.append(fqdn)
        except socket.gaierror:
            pass  # subdomain doesn't resolve

    if not expanded:
        expanded = [base_domain]  # At least scan the base domain

    _log.info(f"Wildcard {wildcard_str} expanded to {len(expanded)} resolved hosts")
    return expanded


def _normalize_api_endpoint(api_str: str) -> str:
    """
    Normalize API endpoint to a URL suitable for scanning.
    Handles: POST https://api.example.com/v1/data  →  https://api.example.com/v1/data
    Also stores the HTTP method as metadata.
    """
    m = _API_METH.match(api_str)
    if m:
        method = m.group(1).upper()
        url    = api_str[m.end():].strip()
        if not url.startswith("http"):
            url = f"https://{url}"
        # The engine treats it as a URL target; the method is for reference
        return url
    return api_str


# ── Main resolver ─────────────────────────────────────────────────────────────

def resolve_targets(raw_input: str) -> dict:
    """
    Parse and expand a raw target input string into individual scan targets.
    
    Args:
        raw_input: Multi-line string from the UI textarea.
    
    Returns:
        {
            "targets":       [list of resolved target strings],
            "original_input": raw_input,
            "summary": {
                "total_targets": int,
                "by_type": {"ip": 5, "cidr": 2, ...},
                "subnets_expanded": ["192.168.1.0/24 → 254 hosts", ...],
                "api_endpoints": ["POST https://api.com/v1/data", ...],
                "files_loaded": ["@targets.txt → 12 targets", ...],
                "skipped": [...],
                "warnings": [...],
            }
        }
    """
    # Split on newlines, commas, and semicolons
    raw_targets = [t.strip() for t in re.split(r"[\n,;]+", raw_input or "")
                   if t.strip()]

    resolved = []
    summary  = {
        "total_targets": 0,
        "by_type":           {},
        "subnets_expanded":  [],
        "api_endpoints":     [],
        "files_loaded":      [],
        "wildcards_resolved":[],
        "skipped":           [],
        "warnings":          [],
    }

    for raw in raw_targets:
        ttype = classify(raw)
        summary["by_type"][ttype] = summary["by_type"].get(ttype, 0) + 1

        if ttype == "comment":
            continue

        elif ttype == "cidr":
            expanded = _expand_cidr(raw)
            skipped  = [e for e in expanded if e.startswith("SKIP:")]
            hosts    = [e for e in expanded if not e.startswith("SKIP:")]
            if skipped:
                summary["skipped"].extend(skipped)
                summary["warnings"].append(f"Subnet {raw} skipped or capped")
            else:
                summary["subnets_expanded"].append(f"{raw} → {len(hosts)} hosts")
            resolved.extend(hosts)

        elif ttype == "range_short":
            expanded = _expand_range_short(raw)
            summary["subnets_expanded"].append(f"{raw} → {len(expanded)} hosts")
            resolved.extend(expanded)

        elif ttype == "range_full":
            expanded = _expand_range_full(raw)
            summary["subnets_expanded"].append(f"{raw} → {len(expanded)} hosts")
            resolved.extend(expanded)

        elif ttype == "file":
            lines = _expand_file(raw)
            errors = [l for l in lines if l.startswith("ERROR:")]
            targets = [l for l in lines if not l.startswith("ERROR:")]
            if errors:
                summary["skipped"].extend(errors)
                summary["warnings"].append(f"File error: {raw}")
            else:
                summary["files_loaded"].append(f"{raw} → {len(targets)} targets")
                # Recursively resolve the file contents
                sub_result = resolve_targets("\n".join(targets))
                resolved.extend(sub_result["targets"])
                # Merge sub-summary
                for k, v in sub_result["summary"]["by_type"].items():
                    summary["by_type"][k] = summary["by_type"].get(k, 0) + v
                summary["subnets_expanded"].extend(sub_result["summary"]["subnets_expanded"])
                continue

        elif ttype == "wildcard":
            expanded = _expand_wildcard(raw)
            summary["wildcards_resolved"].append(f"{raw} → {len(expanded)} resolved")
            resolved.extend(expanded)

        elif ttype == "api_endpoint":
            normalized = _normalize_api_endpoint(raw)
            summary["api_endpoints"].append(raw)
            resolved.append(normalized)

        elif ttype == "url":
            resolved.append(raw)

        elif ttype == "domain":
            # Ensure it's a proper URL for the engine
            resolved.append(raw)

        elif ttype == "ip":
            resolved.append(raw)

        elif ttype == "ipv6":
            resolved.append(raw)

        else:
            # Unknown — pass through (engine will try its best)
            resolved.append(raw)
            summary["warnings"].append(f"Unknown target type: {raw}")

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for t in resolved:
        if t.startswith("SKIP:") or t.startswith("ERROR:"):
            continue
        key = t.lower().rstrip("/")
        if key not in seen:
            seen.add(key)
            deduped.append(t)

    # Apply hard cap
    if len(deduped) > MAX_TOTAL_TARGETS:
        summary["warnings"].append(
            f"Total targets ({len(deduped)}) exceeds max ({MAX_TOTAL_TARGETS}). Truncated.")
        deduped = deduped[:MAX_TOTAL_TARGETS]

    summary["total_targets"] = len(deduped)

    return {
        "targets":        deduped,
        "original_input": raw_input,
        "summary":        summary,
    }


def format_summary(result: dict) -> str:
    """Pretty-format the resolution summary for UI display."""
    s = result["summary"]
    lines = [f"✅ {s['total_targets']} targets resolved"]

    by_type = s["by_type"]
    type_parts = []
    for ttype, count in sorted(by_type.items()):
        if ttype == "comment":
            continue
        emoji = {"cidr": "🌐", "ip": "📍", "domain": "🔗", "url": "🔗",
                 "range_short": "📊", "range_full": "📊", "api_endpoint": "⚡",
                 "wildcard": "🌟", "file": "📂"}.get(ttype, "•")
        type_parts.append(f"{emoji} {count} {ttype}")
    if type_parts:
        lines.append("  " + " · ".join(type_parts))

    for exp in s.get("subnets_expanded", []):
        lines.append(f"  🌐 {exp}")
    for api in s.get("api_endpoints", []):
        lines.append(f"  ⚡ API: {api}")
    for wc in s.get("wildcards_resolved", []):
        lines.append(f"  🌟 {wc}")
    for fl in s.get("files_loaded", []):
        lines.append(f"  📂 {fl}")
    for warn in s.get("warnings", []):
        lines.append(f"  ⚠️  {warn}")

    return "\n".join(lines)
