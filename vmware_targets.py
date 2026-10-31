# Expedite Strike VMware Lab Targets Configuration
# Auto-discovered from VMnet8 (NAT) subnet scan
# Generated: 2026-08-15

VMWARE_LAB_TARGETS = {
    "subnet": "192.168.195.0/24",
    "gateway": "192.168.195.2",
    "host": "192.168.195.1",  # Expedite Strike host (Windows)

    "targets": [
        {
            "ip": "192.168.195.137",
            "hostname": "vm-137",
            "os_guess": "Windows",
            "status": "alive",
            "open_ports": [],
            "notes": "Responds to ping, TTL=128"
        },
        {
            "ip": "192.168.195.138",
            "hostname": "Windows Server 2012",
            "os_guess": "Windows Server 2012",
            "status": "alive",
            "open_ports": [135, 139, 445],
            "notes": "SMB/RPC open, firewall disabled"
        },
        {
            "ip": "192.168.195.128",
            "hostname": "pfSense",
            "os_guess": "FreeBSD/pfSense",
            "status": "in-arp",
            "open_ports": [],
            "notes": "In ARP table but not responding to ping"
        },
    ],

    # All IPs as scan target string (newline separated for Expedite Strike target-input)
    "target_list": "192.168.195.137\n192.168.195.138\n192.168.195.128",

    # CIDR for full subnet scan
    "cidr_target": "192.168.195.0/24",
}


def get_target_string():
    """Return newline-separated target IPs for Expedite Strike scan input."""
    return VMWARE_LAB_TARGETS["target_list"]


def get_all_ips():
    """Return list of all target IPs."""
    return [t["ip"] for t in VMWARE_LAB_TARGETS["targets"]]


if __name__ == "__main__":
    print("=== Expedite Strike VMware Lab Targets ===")
    for t in VMWARE_LAB_TARGETS["targets"]:
        ports = ", ".join(str(p) for p in t["open_ports"]) or "none"
        print(f"  {t['ip']:20s} | {t['hostname']:25s} | ports: {ports}")
    print(f"\nTarget string:\n{get_target_string()}")
