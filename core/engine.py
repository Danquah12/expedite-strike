class FrameworkEngine:
    """
    Executes registered PTES modules in order.
    """

    def __init__(self, context):
        self.context = context
        self.modules = []

    def register_module(self, module):
        self.modules.append(module)

    def run(self):
        for module in self.modules:
            module.execute(self.context)
