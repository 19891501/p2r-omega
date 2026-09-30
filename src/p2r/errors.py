class P2RError(Exception):
    """Base error carrying a stable machine-readable code."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        detail = f": {message}" if message else ""
        super().__init__(f"{code}{detail}")


class VerifyError(P2RError):
    pass


class RegistryError(P2RError):
    pass


class ExecutionError(P2RError):
    pass


class PreDispatchError(ExecutionError):
    """Action failed before any external dispatch was performed.

    The adapter is making a contractual statement here. Core never infers
    that a generic exception happened before dispatch.
    """

    pass
