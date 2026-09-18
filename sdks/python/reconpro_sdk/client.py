"""Thin subprocess wrapper around the reconpro CLI binary (>= 11.2.0).

The SDK never links the CLI as a library: every call spawns
``reconpro <command> --json`` as a subprocess with an **argument list**
(never a shell string) and parses the JSON from STDOUT. The CLI's pretty UI
is printed to STDERR (docker/kubectl convention) and is captured only for
error reporting.

Configuration (constructor kwargs or environment):
    RECONPRO_BINARY   path to (or name of) the reconpro binary (default:
                      ``reconpro``, resolved via PATH by the OS)
    RECONPRO_TIMEOUT  per-call timeout in seconds (default 300)

CLI exit-code contract: 0 success · 1 runtime error · 2 usage error ·
130 interrupted. Non-zero exits raise ``SdkError(code=NON_ZERO_EXIT)`` with
``.exit_code`` and ``.stderr`` attached.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .exceptions import (
    BIN_NOT_FOUND,
    INVALID_JSON,
    NON_ZERO_EXIT,
    TIMEOUT,
    SdkError,
    TargetValidationError,
    UnsupportedFormatError,
)
from .models import ScanResult

__all__ = ["ReconProClient", "SdkError"]

DEFAULT_BINARY = "reconpro"
DEFAULT_TIMEOUT = 300.0
EXPORT_FORMATS = ("sarif", "md", "json", "html")
INVALID_TARGET_CHARS = ";$`&|<>(){}[]!*'\"\\\n\r\t "


def _validate_target(target: str) -> str:
    """Client-side target validation: reject shell metacharacters before spawning.

    Defence in depth — arguments are passed as a list, so no shell injection
    is possible anyway; this catches obvious mistakes early with a clear error.
    """
    text = target.strip() if isinstance(target, str) else ""
    if not text:
        raise TargetValidationError("target must be a non-empty string")
    bad = sorted(set(text) & set(INVALID_TARGET_CHARS))
    if bad:
        raise TargetValidationError(
            "target contains shell metacharacters: "
            + " ".join(repr(c) for c in bad)
        )
    return text


class ReconProClient:
    """SDK client that always shells out with an ARGUMENT LIST (never a shell string)."""

    def __init__(self, binary_path: str | None = None,
                 timeout: float | None = None):
        self.binary_path = (
            binary_path
            or os.environ.get("RECONPRO_BINARY")
            or DEFAULT_BINARY
        )
        timeout_env = os.environ.get("RECONPRO_TIMEOUT")
        self.timeout = float(
            timeout if timeout is not None
            else (timeout_env if timeout_env not in (None, "") else DEFAULT_TIMEOUT)
        )

    # ── internals ─────────────────────────────────────────────────────
    def build_command(self, cli_args) -> list[str]:
        """Argument list passed to subprocess.run (unit-testable, no shell involved)."""
        return [self.binary_path, *cli_args]

    def _run(self, cli_args) -> tuple[str, str]:
        """Run the CLI; return (stdout, stderr). Raise ``SdkError`` on failure."""
        cmd = self.build_command(cli_args)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise SdkError(
                f"reconpro CLI timed out after {self.timeout:g}s",
                code=TIMEOUT, exit_code=None, stderr="", command=cmd,
            ) from exc
        except FileNotFoundError as exc:
            raise SdkError(
                f"reconpro binary not found: {self.binary_path!r} "
                f"(set binary_path or RECONPRO_BINARY)",
                code=BIN_NOT_FOUND, exit_code=None, stderr="", command=cmd,
            ) from exc
        except OSError as exc:  # permission denied, exec format error, ...
            raise SdkError(
                f"failed to start {self.binary_path}: {exc}",
                code=BIN_NOT_FOUND, exit_code=None, stderr="", command=cmd,
            ) from exc
        if proc.returncode != 0:
            raise SdkError(
                f"reconpro CLI exited with code {proc.returncode}",
                code=NON_ZERO_EXIT, exit_code=proc.returncode,
                stderr=proc.stderr, command=cmd,
            )
        return proc.stdout, proc.stderr

    def _run_json(self, cli_args, output_file: str | None = None) -> ScanResult:
        """Run a ``--json`` command and decode the typed result.

        JSON source: STDOUT normally; when ``-o`` is used the CLI writes the
        JSON **only** to the output file and leaves stdout empty, so the file
        is read back instead.
        """
        stdout, _ = self._run(cli_args)
        if output_file is not None:
            try:
                stdout = Path(output_file).read_text(encoding="utf-8")
            except OSError as exc:
                raise SdkError(
                    f"reconpro CLI wrote no JSON to {output_file}: {exc}",
                    code=INVALID_JSON, exit_code=None, stderr=stdout[:500],
                ) from exc
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise SdkError(
                f"reconpro CLI produced invalid JSON: {exc}",
                code=INVALID_JSON, exit_code=None,
                stderr=stdout[:500],
            ) from exc
        if not isinstance(data, dict):
            raise SdkError(
                f"reconpro CLI JSON output was {type(data).__name__}, expected an object",
                code=INVALID_JSON, exit_code=None, stderr=stdout[:500],
            )
        return ScanResult.from_dict(data)

    @staticmethod
    def _output_file_args(output_file: str | None) -> list[str]:
        if output_file is None:
            return []
        if not str(output_file).strip():
            raise ValueError("output_file must be a non-empty path when given")
        return ["-o", str(output_file)]

    # ── public API ────────────────────────────────────────────────────
    def version(self) -> str:
        """Verification ping: run ``reconpro --version`` → e.g. 'ReconPro 11.2.0'.

        Raises ``SdkError`` (with the exit code / stderr attached) when the
        binary is missing, times out, or exits non-zero — so a successful
        return doubles as a liveness + version check.
        """
        return self._run(["--version"])[0].strip()

    def scan(self, target: str, *, output_file: str | None = None,
             modules: list[str] | None = None,
             insecure: bool = False) -> ScanResult:
        """Full remote scan of a domain/URL → typed ``ScanResult``.

        ``output_file`` additionally persists the JSON via the CLI's ``-o``.
        Offline truth-layer note: scanning a nonexistent ``*.invalid`` target
        returns instantly with ``grade == "U"`` and
        ``target_validation.state == UNREACHABLE_TARGET``.
        """
        text = _validate_target(target)
        args = ["scan", text]
        if modules:
            args += ["--modules", ",".join(modules)]
        if insecure:
            args.append("--insecure")
        args += ["--json", *self._output_file_args(output_file)]
        return self._run_json(args, output_file)

    def vibesec(self, target: str, *, output_file: str | None = None) -> ScanResult:
        """Run the vibesec module against a target → typed ``ScanResult``."""
        text = _validate_target(target)
        return self._run_json(
            ["vibesec", text, "--json", *self._output_file_args(output_file)],
            output_file,
        )

    def audit(self, *, output_file: str | None = None) -> ScanResult:
        """Local host/dev-environment audit → typed ``ScanResult`` (offline)."""
        return self._run_json(
            ["audit", "--json", *self._output_file_args(output_file)], output_file
        )

    def dev(self, path: str = ".", *, output_file: str | None = None) -> ScanResult:
        """Scan a local directory path → typed ``ScanResult`` (offline)."""
        text = path.strip() if isinstance(path, str) else ""
        if not text:
            raise ValueError("path must be a non-empty string")
        return self._run_json(
            ["dev", text, "--json", *self._output_file_args(output_file)],
            output_file,
        )

    def doctor(self) -> ScanResult:
        """Local health check → typed ``ScanResult`` (offline)."""
        return self._run_json(["doctor", "--json"])

    def export(self, path: str, format: str = "sarif") -> str:
        """Export the last scan to ``path`` via ``reconpro export``.

        The format is auto-detected by the CLI from the extension; ``format``
        is used to append an extension when ``path`` has none and is validated
        client-side. Returns the path written.
        """
        fmt = str(format).lower().strip()
        if fmt not in EXPORT_FORMATS:
            raise UnsupportedFormatError(
                f"unsupported export format {format!r}; expected one of {EXPORT_FORMATS}"
            )
        if not str(path).strip():
            raise ValueError("export path must be non-empty")
        out = Path(path)
        if not out.suffix:
            out = Path(f"{out}.{fmt}")
        self._run(["export", str(out)])
        return str(out)
