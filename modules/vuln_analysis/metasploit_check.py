import subprocess
from modules.vuln_analysis.metasploit_map import METASPLOIT_CHECK_MAP


class MetasploitCheckModule:
    """
    Runs Metasploit in CHECK-ONLY mode for lab validation.
    """

    def execute(self, context):
        context.msf_validation = {}

        for host, data in context.hosts.items():
            context.msf_validation[host] = []

            for port, svc in data["services"].items():
                service = svc["service"].lower()
                version = svc.get("version", "").lower()

                module = self._lookup_module(service, version)

                if not module:
                    continue

                result = self._run_check(module, host, port)
                context.msf_validation[host].append({
                    "service": service,
                    "port": port,
                    "module": module,
                    "check_result": result
                })

    def _lookup_module(self, service, version):
        if service not in METASPLOIT_CHECK_MAP:
            return None

        for v, module in METASPLOIT_CHECK_MAP[service].items():
            if v in version:
                return module

        return None

    def _run_check(self, module, host, port):
        cmd = (
            f"use {module}; "
            f"set RHOSTS {host}; "
            f"set RPORT {port}; "
            f"check; "
            f"exit"
        )

        result = subprocess.run(
            ["msfconsole", "-q", "-x", cmd],
            capture_output=True,
            text=True,
            timeout=60
        )

        if "appears to be vulnerable" in result.stdout.lower():
            return "vulnerable (check)"
        if "not vulnerable" in result.stdout.lower():
            return "not vulnerable"
        return "inconclusive"
