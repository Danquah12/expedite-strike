class ScopeModule:
    """
    Defines scope and authorization.
    """

    def __init__(self, target, authorized):
        self.target = target
        self.authorized = authorized

    def execute(self, context):
        if not self.authorized:
            raise PermissionError("Assessment not authorized")

        context.scope = {
            "target": self.target,
            "authorized": self.authorized,
            "standard": ["PTES", "NIST SP 800-115"]
        }
