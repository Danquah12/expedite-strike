from plugins.base_provider import ExploitProvider


class MetasploitProvider(ExploitProvider):

    def name(self):
        return "Metasploit"

    def query(self, service_name, service_version):
        results = []

        if service_name == "ssh" and "OpenSSH" in service_version:
            results.append({
                "source": self.name(),
                "service": "OpenSSH",
                "version_range": "7.x",
                "exploit_class": "User Enumeration",
                "impact": "Information disclosure",
                "post_exploitation": "Credential-based access possible"
            })

        return results
