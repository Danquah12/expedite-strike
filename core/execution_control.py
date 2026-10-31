class ExecutionControl:
    cancel_requested = False

    @classmethod
    def request_cancel(cls):
        cls.cancel_requested = True

    @classmethod
    def reset(cls):
        cls.cancel_requested = False

    @classmethod
    def should_cancel(cls):
        return cls.cancel_requested
