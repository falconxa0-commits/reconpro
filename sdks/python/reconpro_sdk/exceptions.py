"""Typed, structured errors for reconpro SDK failures.

Every failure mode has a stable machine-readable ``code`` (see sdks/POLICY.md
§5). Codes are only ever ADDED, never renamed.
"""

from __future__ import annotations

# Error codes (contract — see sdks/POLICY.md)
BIN_NOT_FOUND = "BIN_NOT_FOUND"
TIMEOUT = "TIMEOUT"
NON_ZERO_EXIT = "NON_ZERO_EXIT"
INVALID_JSON = "INVALID_JSON"
INVALID_TARGET = "INVALID_TARGET"
UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"

ERROR_CODES = (
    BIN_NOT_FOUND,
    TIMEOUT,
    NON_ZERO_EXIT,
    INVALID_JSON,
    INVALID_TARGET,
    UNSUPPORTED_FORMAT,
)


class SdkError(Exception):
    """Raised when the reconpro CLI fails, times out, or produces bad output.

    Attributes:
        code:      machine-readable failure code (one of ``ERROR_CODES``).
        exit_code: CLI process exit code (int), or ``None`` for spawn/timeout/
                   decode failures where no meaningful exit code exists.
        stderr:    captured stderr text of the CLI process (may be empty).
        command:   the argument list that was executed (never a shell string).
    """

    def __init__(self, message: str, *, code: str = NON_ZERO_EXIT,
                 exit_code: int | None = None, stderr: str = "",
                 command: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.stderr = stderr
        self.command = command

    def __repr__(self):  # pragma: no cover - debug aid
        return f"SdkError(code={self.code!r}, exit_code={self.exit_code!r}: {self.args[0]!r})"


class TargetValidationError(SdkError):
    """Client-side rejection of a malformed target (defence in depth)."""

    def __init__(self, message: str):
        super().__init__(message, code=INVALID_TARGET)


class UnsupportedFormatError(SdkError):
    """Client-side rejection of an unsupported export format."""

    def __init__(self, message: str):
        super().__init__(message, code=UNSUPPORTED_FORMAT)
