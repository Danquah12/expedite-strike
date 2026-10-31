import subprocess


class MetasploitSearchModule:
    """
    Queries Metasploit local module database in search-only mode to identify
    relevant exploit or auxiliary modules based on discovered services.
    """

    def execute(self, context):
        context.msf_candidates = {}

        for host, data in context.hosts.items():
            context.msf_candidates[host] = []

            for port, svc in data["services"].items():
                service = svc.get("service", "").lower()
                version = svc.get("version", "").lower()

                keyword = self._derive_keyword(service, version)
                if not keyword:
                    continue

                results = self._search(keyword)

                for module in results:
                    context.msf_candidates[host].append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "search_keyword": keyword,
                        "module": module
                    })

    def _derive_keyword(self, service, version):
        """
        Derives a Metasploit search keyword from service/version fingerprints.
        Explicit mapping only — no guessing.
        """

        v = version.lower()

        if service == "http":
            # Apache HTTPD common in lab environments
            if v.startswith("2.") or "apache" in v:
                return "apache"

        if service == "ftp":
            if "vsftpd" in v or "2.3.4" in v:
                return "vsftpd"

        if service == "ssh":
            return "openssh"

        if service == "mysql":
            return "mysql"

        if service == "postgresql":
            return "postgres"

        return None

    def _search(self, keyword):
        if not keyword:
            return []

        cmd = [
            "msfconsole",
            "-q",
            "-x",
            f"search name:{keyword}; exit"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45
            )
        except Exception:
            return []

        return self._parse_search_output(result.stdout)

    def _parse_search_output(self, output):
        """
        Parses Metasploit search output and extracts module paths.
        """

        modules = []

        for line in output.splitlines():
            line = line.strip()

            # Skip headers and separators
            if not line or line.startswith(("Matching Modules", "=", "-", "#")):
                continue

            parts = line.split()

            # Expected format:
            # index  exploit/xxx/yyy  date  rank  check  description
            if len(parts) >= 2 and (
                parts[1].startswith("exploit/")
                or parts[1].startswith("auxiliary/")
            ):
                modules.append(parts[1])

        return modules
