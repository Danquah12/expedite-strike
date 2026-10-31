class ExploitProvider:
    """
    Base class for exploit intelligence providers.
    Providers must return metadata only.
    """

    def name(self):
        raise NotImplementedError

    def query(self, service_name, service_version):
        """
        Returns a list of exploit metadata dictionaries.

        NO exploit code.
        NO payloads.
        NO commands.
        """
        raise NotImplementedError

