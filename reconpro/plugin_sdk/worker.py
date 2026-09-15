"""Sandbox worker — runs INSIDE the isolated OS process.

Invoked as::

    python -m reconpro.plugin_sdk.worker < job.json  > result.json

Guarantees provided to the parent (all enforced BEFORE plugin code loads):

* separate OS process and PID (spawned by :mod:`reconpro.plugin_sdk.runner`);
* resource limits — RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CORE;
* a CPython audit hook (cannot be uninstalled) that blocks:
  - process creation   (subprocess.Popen / os.system / os.exec* / os.spawn* /
                        os.fork / posix_spawn)
  - privilege changes  (os.setuid / setgid / setgroups / setreuid / ...)
  - socket creation    (unless permissions.network)
  - filesystem writes  outside workdir + granted roots (realpath-resolved —
                        symlinks cannot escape)
  - filesystem reads   default-DENY: only workdir, plugin dir, python system
                        dirs, tmp, safe /dev nodes, granted roots
  - banned imports     (subprocess / ctypes / multiprocessing)
* minimal environment (constructed by the parent — secrets never enter);
* plugin stdout is redirected to stderr so the result pipe stays clean.

The result is a single JSON line written on a dup'ed copy of the original
stdout descriptor; the exit code is 0 for delivered results (including
sandbox violations — they are *results*, not crashes).
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import resource
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .permissions import (
    BANNED_IMPORTS,
    SAFE_DEV_FILES,
)

VIOLATION_EXIT = 101

_BLOCKED_EVENT_HELPERS = {
    "subprocess.Popen": "process creation",
    "os.system": "process creation",
    "os.exec": "process creation",
    "os.spawn": "process creation",
    "os.posix_spawn": "process creation",
    "os.fork": "process creation",
    "os.forkpty": "process creation",
    "os.vfork": "process creation",
    "os.setuid": "privilege change",
    "os.setgid": "privilege change",
    "os.setgroups": "privilege change",
    "os.setreuid": "privilege change",
    "os.setregid": "privilege change",
    "os.initgroups": "privilege change",
    "os.kill": "signal delivery",
}

_WRITE_EVENTS = {
    "os.rename": 1,   # arg index of destination... we check both 0 and 1
    "os.replace": 1,
    "os.remove": 0,
    "os.unlink": 0,
    "os.rmdir": 0,
    "os.mkdir": 0,
    "os.makedirs": 0,
    "os.symlink": 1,
    "os.link": 1,
    "os.truncate": 0,
    "os.chmod": 0,
    "os.chown": 0,
    "os.fchmod": -1,
    "os.fchown": -1,
}


class _Blocked(RuntimeError):
    """Internal marker — raised to abort a blocked operation."""


class _Policy:
    """Runtime filesystem/network policy derived from the job spec."""

    def __init__(self, job: Dict[str, Any]) -> None:
        perms = job.get("permissions", {})
        self.network: bool = bool(perms.get("network", False))
        self.plugin_file: str = job["plugin_path"]
        self.plugin_dir: str = job["plugin_dir"]
        self.workdir: str = job["workdir"]
        read_roots: List[str] = [self.workdir, self.plugin_file]
        # SDK plugins (dir with plugin.toml) may read their whole dir;
        # loose .py plugins get exactly their own file — nothing more.
        if os.path.isfile(os.path.join(self.plugin_dir, "plugin.toml")):
            read_roots.append(self.plugin_dir)
        # python system dirs
        read_roots.extend(job.get("system_roots", []))
        read_roots.extend(p for p in perms.get("fs_read", []))
        self.read_roots: Tuple[str, ...] = tuple(
            os.path.realpath(r) for r in read_roots if r)
        write_roots: List[str] = [self.workdir]
        write_roots.extend(p for p in perms.get("fs_write", []))
        self.write_roots: Tuple[str, ...] = tuple(
            os.path.realpath(r) for r in write_roots if r)

    # ── decisions ─────────────────────────────────────────────────
    def _is_own_bytecode_cache(self, resolved: str) -> bool:
        """True for `<plugin_dir>/__pycache__/<plugin-stem>.cpython-*.pyc`.

        The import machinery probes this path (audit fires even when the
        file does not exist).  Only the plugin's OWN cache stem is allowed —
        other plugins' bytecode stays unreadable.
        """
        plugin_dir = self.plugin_dir.rstrip(os.sep)
        if not resolved.startswith(plugin_dir + os.sep):
            return False
        rest = resolved[len(plugin_dir) + 1:]
        if not rest.startswith("__pycache__" + os.sep):
            return False
        stem = os.path.basename(self.plugin_file)
        if stem.endswith(".py"):
            stem = stem[:-3]
        leaf = rest[len("__pycache__") + 1:]
        return leaf.startswith(stem + ".") and (".pyc" in leaf or ".opt-" in leaf)

    def check_path(self, path: str, mode: str) -> Optional[str]:
        """Return a violation reason or None if allowed.

        ``mode`` is one of 'read' | 'write' | 'stat'.
        """
        try:
            resolved = os.path.realpath(str(path))
        except (TypeError, ValueError, OSError):
            return f"unresolvable path {path!r}"
        if resolved in SAFE_DEV_FILES:
            return None  # /dev/null etc.
        if mode == "read" and self._is_own_bytecode_cache(resolved):
            return None
        if mode == "write":
            if not self._under(resolved, self.write_roots):
                return f"write outside sandbox ({resolved})"
            return None
        # read / stat
        if self._under(resolved, self.read_roots):
            return None
        return f"read outside sandbox ({resolved})"

    @staticmethod
    def _under(path: str, roots: Tuple[str, ...]) -> bool:
        for root in roots:
            if path == root or path.startswith(root.rstrip(os.sep) + os.sep):
                return True
        return False

    def check_import(self, module: str) -> Optional[str]:
        top = module.split(".")[0] if module else ""
        if top in BANNED_IMPORTS:
            return f"banned import {top!r}"
        return None


class _Sandbox:
    def __init__(self, policy: _Policy) -> None:
        self.policy = policy
        self.violations: List[Dict[str, Any]] = []
        self.killed_reason: Optional[str] = None

    def record(self, event: str, detail: str, args: tuple) -> None:
        entry = {
            "event": event,
            "detail": detail,
            "args": _safe_repr(args),
        }
        if len(self.violations) < 64:  # cap the log
            self.violations.append(entry)

    # ── the audit hook (installed with sys.addaudithook — permanent) ──
    def hook(self, event: str, args: tuple) -> None:
        try:
            self._check(event, args)
        except _Blocked:
            raise
        except Exception:  # never crash the host on policy bugs
            pass

    def _check(self, event: str, args: tuple) -> None:
        p = self.policy
        if event in _BLOCKED_EVENT_HELPERS:
            self.record(event, _BLOCKED_EVENT_HELPERS[event], args)
            self.killed_reason = self.killed_reason or f"{event}: {_BLOCKED_EVENT_HELPERS[event]}"
            raise _Blocked(f"sandbox: {_BLOCKED_EVENT_HELPERS[event]} is forbidden")

        if event == "socket.__new__":
            if not p.network:
                self.record(event, "socket creation without network permission", args)
                self.killed_reason = self.killed_reason or "socket: network permission not granted"
                raise _Blocked("sandbox: network access not granted")
            return

        if event == "import":
            module = args[0] if args else ""
            reason = p.check_import(str(module))
            if reason:
                self.record(event, reason, args)
                self.killed_reason = self.killed_reason or reason
                raise _Blocked(f"sandbox: {reason}")
            return

        if event in ("open", "os.open"):
            # args: (path, mode, flags) — mode may be None for os.open
            if not args:
                return
            path = args[0]
            if not isinstance(path, (str, bytes, os.PathLike)):
                return
            mode = ""
            if len(args) > 1 and isinstance(args[1], str):
                mode = args[1]
            flags = 0
            if len(args) > 2 and isinstance(args[2], int):
                flags = args[2]
            writing = (
                any(c in mode for c in "wax+")
                or (event == "os.open" and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            )
            kind = "write" if writing else "read"
            reason = p.check_path(os.fspath(path) if isinstance(path, os.PathLike) else str(path), kind)
            if reason:
                self.record(event, reason, args)
                if kind == "write" or self.killed_reason is None:
                    self.killed_reason = self.killed_reason or reason
                raise _Blocked(f"sandbox: {reason}")
            return

        if event in _WRITE_EVENTS:
            # mutation events: check every str arg as a path
            for a in args:
                if isinstance(a, (str, os.PathLike)):
                    reason = p.check_path(str(a), "write")
                    if reason:
                        self.record(event, reason, args)
                        raise _Blocked(f"sandbox: {reason}")
            return

        if event == "ctypes.dlopen":
            self.record(event, "ctypes library load", args)
            raise _Blocked("sandbox: ctypes is forbidden")

    # ── verdict ───────────────────────────────────────────────────
    def violation_summary(self) -> Optional[str]:
        if not self.violations:
            return None
        first = self.violations[0]
        return f"{len(self.violations)} violation(s); first: {first['event']}: {first['detail']}"


def _safe_repr(args: tuple) -> list:
    out = []
    for a in args:
        try:
            r = repr(a)
            if len(r) > 200:
                r = r[:200] + "…"
            out.append(r)
        except Exception:
            out.append("<unreprable>")
    return out


# ── resource limits ───────────────────────────────────────────────────────

def _apply_limits(limits: Dict[str, Any]) -> None:
    memory_bytes = int(limits.get("memory_mb", 128)) * 1024 * 1024
    cpu_seconds = int(limits.get("cpu_s", 10))
    fsize_bytes = int(limits.get("fsize_mb", 16)) * 1024 * 1024
    nofile = int(limits.get("nofile", 64))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 2))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass


# ── plugin loading & invocation ───────────────────────────────────────────

def _load_plugin(plugin_path: str):
    spec = importlib.util.spec_from_file_location(
        f"_reconpro_sandboxed_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load plugin from {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # plugin top-level executes here (sandboxed)
    return module


def _invoke_run(run, kwargs: Dict[str, Any]) -> Any:
    try:
        sig = inspect.signature(run)
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return run(**kwargs)
        accepted = {k: v for k, v in kwargs.items() if k in params}
        return run(**accepted)
    except TypeError:
        return run()


_REQUIRED_KEYS = {"title", "severity", "category"}
_MAX_TITLE = 512
_MAX_FINDINGS = 1000


def _validate_findings(result: Any, max_bytes: int) -> Tuple[bool, str, List[Dict[str, Any]]]:
    if not isinstance(result, list):
        return False, "plugin must return a list", []
    if len(result) > _MAX_FINDINGS:
        return False, f"too many findings ({len(result)} > {_MAX_FINDINGS})", []
    validated: List[Dict[str, Any]] = []
    for item in result:
        if not isinstance(item, dict):
            return False, "every finding must be a dict", validated
        if not _REQUIRED_KEYS.issubset(item):
            return False, "finding missing required keys (title/severity/category)", validated
        title = item["title"]
        if not isinstance(title, str) or not title.strip():
            return False, "finding title must be a non-empty string", validated
        if len(title) > _MAX_TITLE:
            item = dict(item)
            item["title"] = title[:_MAX_TITLE] + "…"
        validated.append(item)
    try:
        blob = json.dumps(validated, default=str)
    except (TypeError, ValueError):
        return False, "findings are not JSON-serialisable", []
    if len(blob) > max_bytes:
        return False, f"output_size: {len(blob)} > {max_bytes} bytes", []
    return True, "", validated


# ── main ──────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        job_raw = sys.stdin.buffer.read()
        job = json.loads(job_raw.decode("utf-8"))
    except Exception as exc:
        sys.stderr.write(f"[worker] bad job: {exc}\n")
        os._exit(2)

    _apply_limits(job.get("limits", {}))
    policy = _Policy(job)
    sandbox = _Sandbox(policy)
    sys.addaudithook(sandbox.hook)

    # keep a private copy of the original stdout for the result envelope
    result_fd = os.dup(1)
    os.dup2(2, 1)          # fd 1 now mirrors stderr: plugin prints stay in logs
    sys.stdout = sys.stderr

    pid = os.getpid()
    started = _now_ms()
    status: Dict[str, Any] = {
        "worker_pid": pid,
        "ok": False,
        "kind": "crash",
        "error": "",
        "findings": [],
        "audit_violations": [],
        "duration_ms": 0,
    }

    try:
        mod = _load_plugin(job["plugin_path"])
        run = getattr(mod, "run", None)
        if not callable(run):
            status.update(kind="invalid_output",
                          error="plugin has no callable run()")
        else:
            raw = _invoke_run(run, job.get("args", {}))
            ok, reason, findings = _validate_findings(
                raw, int(job.get("limits", {}).get("max_output_bytes", 1_048_576)))
            if sandbox.killed_reason:
                status.update(kind="violation", error=sandbox.violation_summary() or sandbox.killed_reason)
            elif not ok:
                status.update(kind="invalid_output", error=reason)
            else:
                status.update(ok=True, kind="ok", findings=findings)
    except _Blocked as exc:
        status.update(kind="violation", error=str(exc))
    except SystemExit as exc:  # plugin called sys.exit
        status.update(kind="crash", error=f"plugin called sys.exit({exc.code})")
    except BaseException:
        tb = traceback.format_exc(limit=8)
        status.update(kind="crash", error=tb.strip()[-2000:])

    status["audit_violations"] = sandbox.violations
    status["duration_ms"] = _now_ms() - started
    if sandbox.killed_reason and status["kind"] == "ok":
        status.update(ok=False, kind="violation",
                      error=sandbox.violation_summary() or sandbox.killed_reason)

    payload = (json.dumps(status, default=str) + "\n").encode("utf-8")
    try:
        os.write(result_fd, payload)
        os.close(result_fd)
    except OSError:
        pass
    sys.stderr.flush()
    exit_code = 0 if status["kind"] in ("ok", "violation", "invalid_output", "crash") else VIOLATION_EXIT
    os._exit(exit_code)


def _now_ms() -> int:
    import time
    return int(time.monotonic() * 1000)


if __name__ == "__main__":
    main()
