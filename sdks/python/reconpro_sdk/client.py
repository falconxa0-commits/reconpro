"""Thin subprocess wrapper around the reconpro CLI (`python -m reconpro.cli`).

Configuration (constructor kwargs or environment):
    RECONPRO_PYTHON   python executable used to run the CLI (default /home/z/.venv/bin/python3)
    RECONPRO_ROOT     directory containing the reconpro package; used as subprocess cwd
    RECONPRO_TIMEOUT  per-call timeout in seconds (default 120)

Verified CLI quirks (reconpro 11.1.0):
    * `--version` and `doctor --json` write to STDOUT.
    * `history` has NO `--json` flag (passing it exits 2 with an argparse usage
      error on STDERR); the human table also goes to STDERR.  history() therefore
      returns raw text, not parsed JSON.
    * `export` takes a single output path; the format is auto-detected from the
      file extension (.sarif/.md/.json/.html).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .exceptions import SdkError

DEFAULT_PYTHON = "/home/z/.venv/bin/python3"
DEFAULT_ROOT = "/home/z/my-project/download/reconpro-github"
DEFAULT_TIMEOUT = 120.0
MODULE_ARGS = ("-m", "reconpro.cli")
EXPORT_FORMATS = ("sarif", "md", "json", "html")
INVALID_TARGET_CHARS = ";$`&|<>(){}[]!*'\"\\\n\r\t "


def _validate_target(target: str) -> str:
    """Client-side target validation: reject shell metacharacters before spawning."""
    text = target.strip() if isinstance(target, str) else ""
    if not text:
        raise ValueError("target must be a non-empty string")
    bad = sorted(set(text) & set(INVALID_TARGET_CHARS))
    if bad:
        raise ValueError(f"target contains shell metacharacters: {' '.join(repr(c) for c in bad)}")
    return text


class ReconProClient:
    """SDK client that always shells out with an ARGUMENT LIST (never a shell string)."""

    def __init__(self, python_path: str | None = None, root: str | None = None,
                 timeout: float | None = None):
        self.python_path = python_path or os.environ.get("RECONPRO_PYTHON", DEFAULT_PYTHON)
        self.root = root or os.environ.get("RECONPRO_ROOT", DEFAULT_ROOT)
        self.timeout = float(timeout or os.environ.get("RECONPRO_TIMEOUT", DEFAULT_TIMEOUT))

    # ── internals ─────────────────────────────────────────────────────
    def build_command(self, cli_args) -> list[str]:
        """Argument list passed to subprocess.run (unit-testable, no shell involved)."""
        return [self.python_path, *MODULE_ARGS, *cli_args]

    def _run(self, cli_args) -> tuple[str, str]:
        cmd = self.build_command(cli_args)
        try:
            proc = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise SdkError(f"reconpro CLI timed out after {self.timeout:g}s",
                           exit_code=-1, stderr="", command=cmd) from exc
        except OSError as exc:  # bad python path, missing cwd, ...
            raise SdkError(f"failed to start {self.python_path}: {exc}",
                           exit_code=-1, stderr="", command=cmd) from exc
        if proc.returncode != 0:
            raise SdkError(f"reconpro CLI exited with code {proc.returncode}",
                           exit_code=proc.returncode, stderr=proc.stderr, command=cmd)
        return proc.stdout, proc.stderr

    def _run_json(self, cli_args):
        stdout, _ = self._run(cli_args)
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise SdkError(f"reconpro CLI produced invalid JSON: {exc}",
                           exit_code=-1, stderr=stdout[:500]) from exc

    # ── public API ────────────────────────────────────────────────────
    def version(self) -> str:
        """Return the CLI version string, e.g. 'ReconPro 11.1.0'."""
        return self._run(["--version"])[0].strip()

    def doctor(self) -> dict:
        """Run the local health check; returns the parsed JSON report."""
        return self._run_json(["doctor", "--json"])

    def history(self, target: str | None = None, limit: int = 10) -> str:
        """Return scan history as raw text (CLI quirk: no --json flag for history)."""
        args = ["history", "--limit", str(limit)]
        if target is not None:
            args.append(_validate_target(target))
        stdout, stderr = self._run(args)
        return (stderr or stdout).strip()

    def scan(self, target: str) -> dict:
        """Full remote scan of a domain/URL; returns parsed JSON. Hits the network."""
        return self._run_json(["scan", _validate_target(target), "--json"])

    def export(self, path: str, format: str = "sarif") -> str:
        """Export the last scan to `path` (format from extension). Returns the path used."""
        fmt = str(format).lower().strip()
        if fmt not in EXPORT_FORMATS:
            raise ValueError(f"unsupported export format {format!r}; expected one of {EXPORT_FORMATS}")
        out = Path(path)
        if not out.suffix:
            out = Path(f"{out}.{fmt}")
        self._run(["export", str(out)])
        return str(out)
