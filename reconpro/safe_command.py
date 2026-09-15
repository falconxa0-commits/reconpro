"""Shell-free command execution for ReconPro.

Security contract
-----------------
This module NEVER invokes a shell (``shell=False`` everywhere).  Commands
are tokenised with :mod:`shlex` and executed as argument lists, which
removes the shell-injection class of vulnerabilities.

To preserve the behaviour of legacy call sites that passed shell command
*strings*, a small, well-defined subset of shell syntax is emulated in
Python — never by spawning a shell:

* output redirections (``2>/dev/null``, ``2>NUL``, ``2>&1``, ``>/dev/null``)
  are dropped: stderr is captured separately and returned to the caller,
* ``A || B`` fallback: run ``A``; if it fails, run ``B``,
* ``A | B`` pipelines: stages are executed as real subprocesses with
  stdout chained into the next stage's stdin,
* Windows-style ``%VAR%`` environment expansion and the ``echo`` builtin
  are emulated in-process (matters only on Windows hosts).

Anything outside this subset (globbing, ``$()``, backticks, ``&&``, ``;``,
heredocs, ...) is NOT interpreted — those tokens are passed to the target
program as literal arguments, exactly like any other argument-list call.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from typing import Sequence, Tuple, Union

__all__ = ["run_command", "split_pipeline", "CommandError"]

Command = Union[str, Sequence[str]]


class CommandError(ValueError):
    """Raised when a command string cannot be executed safely."""


_REDIRECT_TARGETS = {"/dev/null", "NUL", "nul", "Nul"}
_FD_TOKENS = {"0", "1", "2"}


def _is_redirect(tokens: list[str], i: int) -> bool:
    """True if tokens[i:] start a redirect clause we can safely drop."""
    t = tokens[i]
    # forms: "2>" / ">" / ">>" / ">&"
    if t in (">", ">>", ">&"):
        j = i + 1
        # ">&1" style: target is a digit
        if t == ">&":
            return j < len(tokens) and tokens[j] in _FD_TOKENS
        return j < len(tokens) and tokens[j] in _REDIRECT_TARGETS
    # "2>" / "2>>" / "2>&"  — fd prefix emitted as its own token
    if t in _FD_TOKENS and i + 1 < len(tokens) and tokens[i + 1] in (">", ">>", ">&"):
        j = i + 2
        if tokens[i + 1] == ">&":
            return j < len(tokens) and tokens[j] in _FD_TOKENS
        return j < len(tokens) and tokens[j] in _REDIRECT_TARGETS
    return False


def _skip_redirect(tokens: list[str], i: int) -> int:
    """Return the index just past the redirect clause starting at i."""
    t = tokens[i]
    if t in (">", ">>", ">&"):
        return i + 2
    if t in _FD_TOKENS and i + 1 < len(tokens) and tokens[i + 1] in (">", ">>", ">&"):
        return i + 3
    return i + 1


def _expand_env_percent(tokens: list[str]) -> list[str]:
    """Expand Windows-style %VAR% tokens from os.environ (no-op elsewhere)."""
    out = []
    for tok in tokens:
        if len(tok) > 2 and tok.startswith("%") and tok.endswith("%"):
            val = os.environ.get(tok[1:-1])
            if val is not None:
                out.append(val)
                continue
        out.append(tok)
    return out


def split_pipeline(cmd: str) -> list[list[list[str]]]:
    """Tokenise a command string into ``||``-separated pipeline groups.

    Each group is a list of pipeline stages; each stage is an argv list.
    Redirection clauses are removed (stderr is captured by the runner).
    """
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError as exc:
        raise CommandError(f"unparsable command: {exc}") from exc

    # strip redirect clauses
    cleaned: list[str] = []
    i = 0
    while i < len(tokens):
        if _is_redirect(tokens, i):
            i = _skip_redirect(tokens, i)
            continue
        cleaned.append(tokens[i])
        i += 1
    cleaned = _expand_env_percent(cleaned)

    # split on || (fallback alternatives), then | (pipeline stages)
    groups: list[list[list[str]]] = []
    current: list[list[str]] = []
    stage: list[str] = []
    for tok in cleaned:
        if tok == "||":
            if stage:
                current.append(stage)
                stage = []
            if current:
                groups.append(current)
                current = []
        elif tok == "|":
            current.append(stage)
            stage = []
        else:
            stage.append(tok)
    if stage:
        current.append(stage)
    if current:
        groups.append(current)

    if not groups or not any(any(g) for g in groups):
        raise CommandError("empty command")
    return groups


def _echo_builtin(argv: list[str]) -> Tuple[int, str]:
    """In-process emulation of the ``echo`` builtin (never spawns a shell)."""
    return 0, " ".join(argv[1:])


def _ulimit_core() -> Tuple[int, str]:
    """In-process emulation of ``ulimit -c`` (reads this process's rlimit)."""
    try:
        import resource
    except ImportError:  # Windows
        return -1, ""
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError):
        return -1, ""
    if soft == resource.RLIM_INFINITY:
        return 0, "unlimited"
    return 0, str(soft)


def _run_stage(argv: list[str], timeout: float, input_text: str | None) -> Tuple[int, str, str]:
    """Run one pipeline stage without a shell. Returns (rc, stdout, stderr)."""
    if argv and argv[0] == "echo":
        rc, out = _echo_builtin(argv)
        return rc, out, ""
    if argv[:2] == ["ulimit", "-c"]:
        rc, out = _ulimit_core()
        return rc, out, ""
    try:
        proc = subprocess.run(  # noqa: S603 — argument list, shell=False
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        raise
    except (FileNotFoundError, PermissionError, OSError):
        return 127, "", ""


def _run_group(stages: list[list[str]], timeout: float) -> Tuple[int, str]:
    """Run one pipeline group; returns (last-stage returncode, output)."""
    stdout_acc = ""
    stderr_acc = ""
    rc = 127
    for idx, argv in enumerate(stages):
        if not argv:
            return -1, ""
        data = stdout_acc if idx > 0 else None
        try:
            rc, out, err = _run_stage(argv, timeout, data)
        except subprocess.TimeoutExpired:
            raise
        stdout_acc = out
        stderr_acc += err
    return rc, (stdout_acc + stderr_acc).strip()


def run_command(cmd: Command, timeout: float = 10) -> Tuple[int, str]:
    """Execute *cmd* **without a shell** and return ``(returncode, output)``.

    ``cmd`` may be a pre-split argument list (used verbatim) or a command
    string (tokenised with shlex; ``||``, ``|`` and redirections are
    emulated in Python — see the module docstring).
    """
    if isinstance(cmd, (list, tuple)):
        argvs = [list(cmd)]
        if not argvs[0]:
            return -1, ""
        try:
            rc, out, err = _run_stage(argvs[0], timeout, None)
        except subprocess.TimeoutExpired:
            return -1, ""
        return rc, (out + err).strip()

    try:
        groups = split_pipeline(cmd)
    except CommandError:
        return -1, ""

    last_rc, last_out = -1, ""
    for stages in groups:  # `||` fallback: first group that succeeds wins
        try:
            rc, out = _run_group(stages, timeout)
        except subprocess.TimeoutExpired:
            return -1, ""
        last_rc, last_out = rc, out
        if rc == 0:
            return rc, out
    return last_rc, last_out
