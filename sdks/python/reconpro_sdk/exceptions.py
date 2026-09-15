"""Typed error for reconpro SDK failures."""


class SdkError(Exception):
    """Raised when the reconpro CLI fails, times out, or cannot be started.

    Attributes:
        exit_code: CLI process exit code (int), or -1 for spawn/timeout failures.
        stderr:   captured stderr text of the CLI process.
        command:  the argument list that was executed (never a shell string).
    """

    def __init__(self, message, *, exit_code=-1, stderr="", command=None):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr
        self.command = command

    def __repr__(self):  # pragma: no cover - debug aid
        return f"SdkError({self.args[0]!r}, exit_code={self.exit_code!r})"
