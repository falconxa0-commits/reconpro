"""Parent-side plugin runner — spawns the sandboxed worker OS process.

Every plugin execution goes through here: a separate Python interpreter
(``python -m reconpro.plugin_sdk.worker``) with its own PID, its own
session (so we can SIGKILL the whole group), a minimal environment and a
wall-clock deadline.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .permissions import PermissionSet

_REPO_ROOT = str(Path(__file__).resolve().parents[2])

_KINDS = ("ok", "violation", "timeout", "crash", "invalid_output", "process_error")


@dataclass
class RunResult:
    """Structured outcome of one sandboxed plugin run."""

    ok: bool
    kind: str                      # one of _KINDS
    pid: Optional[int]             # worker OS pid (proves PID separation)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    audit_violations: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    exit_code: Optional[int] = None
    stderr_tail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "kind": self.kind, "pid": self.pid,
            "findings": self.findings, "error": self.error,
            "audit_violations": self.audit_violations,
            "duration_ms": self.duration_ms, "exit_code": self.exit_code,
            "stderr_tail": self.stderr_tail[:2000],
        }


class PluginRunner:
    """Spawns sandboxed worker processes and speaks the JSON IPC protocol."""

    def __init__(
        self,
        python_exe: Optional[str] = None,
        memory_mb: int = 128,
        cpu_seconds: int = 10,
        wall_timeout_s: float = 15.0,
        fsize_mb: int = 16,
        max_output_bytes: int = 1_048_576,
        env_allowlist: Sequence[str] = (),
        keep_workdir: bool = False,
    ) -> None:
        self.python_exe = python_exe or sys.executable
        self.memory_mb = memory_mb
        self.cpu_seconds = cpu_seconds
        self.wall_timeout_s = wall_timeout_s
        self.fsize_mb = fsize_mb
        self.max_output_bytes = max_output_bytes
        self.env_allowlist = tuple(env_allowlist)
        self.keep_workdir = keep_workdir

    # ── public API ────────────────────────────────────────────────
    def execute(
        self,
        plugin_path: str | Path,
        permissions: Optional[PermissionSet] = None,
        args: Optional[Dict[str, Any]] = None,
        workdir: Optional[str | Path] = None,
    ) -> RunResult:
        """Run one plugin inside the sandbox; never raises."""
        permissions = permissions or PermissionSet()
        args = args or {}
        plugin_path = str(Path(plugin_path).resolve())
        plugin_dir = str(Path(plugin_path).parent)

        own_workdir = workdir is None
        if own_workdir:
            workdir = tempfile.mkdtemp(prefix="reconpro-sbx-")
        workdir = str(Path(workdir))

        job = self._build_job(plugin_path, plugin_dir, workdir, permissions, args)
        env = self._build_env(workdir, permissions)

        started = time.monotonic()
        proc = None
        try:
            proc = subprocess.Popen(
                [self.python_exe, "-m", "reconpro.plugin_sdk.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=workdir,
                start_new_session=True,  # own process group → group SIGKILL
            )
            assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
            try:
                out, err = proc.communicate(
                    (json.dumps(job) + "\n").encode("utf-8"),
                    timeout=self.wall_timeout_s)
            except subprocess.TimeoutExpired:
                self._kill_group(proc)
                out, err = proc.communicate()
                return RunResult(
                    ok=False, kind="timeout", pid=proc.pid,
                    error=(f"plugin exceeded wall-clock limit of "
                           f"{self.wall_timeout_s:.0f}s and was SIGKILLed"),
                    duration_ms=int((time.monotonic() - started) * 1000),
                    exit_code=proc.returncode,
                    stderr_tail=err.decode("utf-8", "replace") if err else "",
                )
            duration_ms = int((time.monotonic() - started) * 1000)
            return self._parse_result(out, err, proc, duration_ms)
        except Exception as exc:  # spawn failures etc.
            return RunResult(
                ok=False, kind="process_error", pid=None,
                error=f"failed to start sandbox worker: {exc}",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        finally:
            if own_workdir and not self.keep_workdir:
                _rmtree_quiet(workdir)

    # ── internals ─────────────────────────────────────────────────
    def _build_job(self, plugin_path: str, plugin_dir: str, workdir: str,
                   permissions: PermissionSet,
                   args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "plugin_path": plugin_path,
            "plugin_dir": plugin_dir,
            "workdir": workdir,
            "permissions": permissions.as_dict(),
            "args": args,
            "limits": {
                "memory_mb": self.memory_mb,
                "cpu_s": self.cpu_seconds,
                "fsize_mb": self.fsize_mb,
                "max_output_bytes": self.max_output_bytes,
            },
            "system_roots": _system_roots(),
        }

    def _build_env(self, workdir: str, permissions: PermissionSet) -> Dict[str, str]:
        env: Dict[str, str] = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": workdir,
            "TMPDIR": workdir,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": _REPO_ROOT,
            "PYTHONUNBUFFERED": "1",
            "RECONPRO_SANDBOX": "1",
        }
        for name in permissions.env_allowlist():
            if name in os.environ:
                env[name] = os.environ[name]
        # never leak these even if allowlisted
        for dangerous in ("RECONPRO_RELEASE_KEY", "AWS_SECRET_ACCESS_KEY",
                          "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            env.pop(dangerous, None)
        return env

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def _parse_result(self, out: bytes, err: bytes, proc: subprocess.Popen,
                      duration_ms: int) -> RunResult:
        stderr_text = err.decode("utf-8", "replace") if err else ""
        exit_code = proc.returncode
        if not out:
            return RunResult(
                ok=False, kind="process_error", pid=proc.pid,
                error=(f"worker produced no result on stdout "
                       f"(exit={exit_code}); stderr tail: {stderr_text[-500:]}"),
                duration_ms=duration_ms, exit_code=exit_code,
                stderr_tail=stderr_text)
        text = out.decode("utf-8", "replace").strip()
        line = text.splitlines()[-1] if text else ""
        try:
            status = json.loads(line)
        except (ValueError, IndexError):
            return RunResult(
                ok=False, kind="process_error", pid=proc.pid,
                error=f"worker result is not JSON: {line[:200]!r}",
                duration_ms=duration_ms, exit_code=exit_code,
                stderr_tail=stderr_text)
        kind = status.get("kind", "process_error")
        if kind not in _KINDS:
            kind = "process_error"
        return RunResult(
            ok=bool(status.get("ok", False)),
            kind=kind,
            pid=status.get("worker_pid", proc.pid),
            findings=status.get("findings", []) or [],
            error=str(status.get("error", "")),
            audit_violations=status.get("audit_violations", []) or [],
            duration_ms=int(status.get("duration_ms", duration_ms)),
            exit_code=exit_code,
            stderr_tail=stderr_text,
        )


def _system_roots() -> List[str]:
    roots: List[str] = []
    for entry in sys.path:
        if entry and os.path.isdir(entry):
            roots.append(os.path.realpath(entry))
    for prefix in (sys.prefix, getattr(sys, "base_prefix", sys.prefix)):
        if prefix and os.path.isdir(prefix):
            roots.append(os.path.realpath(prefix))
    # stdlib source/headers not always on sys.path
    roots.append(os.path.realpath("/usr/lib/python3"))
    return roots


def _rmtree_quiet(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
