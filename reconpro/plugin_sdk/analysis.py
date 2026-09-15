"""Static (AST) analysis of plugin source — executed BEFORE anything runs.

Two classes of findings:
* ``BLOCKING``  — the plugin may never run (subprocess/ctypes/eval/exec/...)
* ``ADVISORY``  — reported, but run may proceed (e.g. writes inside workdir)

The gate function :func:`check_runnable` combines violations with the
granted permissions: e.g. a ``socket`` import is blocking unless the
manifest granted ``network``.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .permissions import BANNED_IMPORTS, NETWORK_IMPORTS, PermissionSet

# calls on the ``os`` module that create processes — always forbidden
_OS_PROCESS_CALLS = {
    "system", "popen", "fork", "forkpty", "vfork",
    "execv", "execve", "execvp", "execvpe", "execvl", "execle", "execl", "execlp",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle",
    "spawnlp", "spawnlpe", "posix_spawn", "posix_spawnp",
}

_DANGER_BUILTINS = {"eval", "exec", "compile", "__import__"}

_DESERIALIZE_CALLS = {"loads", "load"}  # pickle/marshal module attr

_ADVISORY_WRITES = {"open"}


class ViolationType:
    SUBPROCESS = "subprocess"
    OS_PROCESS = "os-process"
    CTYPES = "ctypes"
    EVAL_EXEC = "eval-exec"
    DYNAMIC_IMPORT = "dynamic-import"
    UNSAFE_DESERIALIZE = "unsafe-deserialize"
    NETWORK_WITHOUT_PERMISSION = "network-without-permission"
    BANNED_IMPORT = "banned-import"
    WRITE_HINT = "write-hint"
    MUTATION_HINT = "mutation-hint"


BLOCKING_TYPES = {
    ViolationType.SUBPROCESS, ViolationType.OS_PROCESS, ViolationType.CTYPES,
    ViolationType.EVAL_EXEC, ViolationType.DYNAMIC_IMPORT,
    ViolationType.UNSAFE_DESERIALIZE,
    ViolationType.NETWORK_WITHOUT_PERMISSION, ViolationType.BANNED_IMPORT,
}


@dataclass(frozen=True)
class Violation:
    kind: str          # ViolationType.*
    detail: str
    line: int = 0
    blocking: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {"kind": self.kind, "detail": self.detail,
                "line": self.line, "blocking": self.blocking}

    def __str__(self) -> str:  # pragma: no cover - debug aid
        flag = "BLOCK" if self.blocking else "advise"
        return f"[{flag}] {self.kind} line {self.line}: {self.detail}"


def _top_module(name: str) -> str:
    return name.split(".")[0]


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: List[Violation] = []
        # module names imported under some binding, e.g. {"os": ["os"]}
        self.imported: Dict[str, str] = {}
        self.from_imports: Dict[str, List[str]] = {}

    # ── imports ────────────────────────────────────────────────────
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = _top_module(alias.name)
            self.imported[alias.asname or alias.name] = alias.name
            self._check_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                self._record(ViolationType.DYNAMIC_IMPORT,
                             f"star import from {module!r} hides static analysis",
                             node.lineno)
                continue
            binding = alias.asname or alias.name
            self.imported[binding] = f"{module}.{alias.name}"
            self.from_imports.setdefault(module, []).append(binding)
            self._check_import(f"{module}.{alias.name}", node.lineno, imported_name=alias.name)
        self.generic_visit(node)

    def _check_import(self, full_name: str, lineno: int,
                      imported_name: Optional[str] = None) -> None:
        top = _top_module(full_name)
        leaf = imported_name or full_name.split(".")[-1]
        if top in BANNED_IMPORTS or leaf in BANNED_IMPORTS:
            self._record(ViolationType.BANNED_IMPORT,
                         f"import of {full_name!r} is forbidden in the sandbox",
                         lineno)
        elif top in NETWORK_IMPORTS or leaf in NETWORK_IMPORTS:
            self.violations.append(Violation(
                ViolationType.NETWORK_WITHOUT_PERMISSION,
                f"network-capable import {full_name!r} requires permissions.network",
                lineno, blocking=True))  # gate may downgrade to advisory if granted

    # ── calls ──────────────────────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # builtins: eval/exec/compile/__import__
        if isinstance(func, ast.Name) and func.id in _DANGER_BUILTINS:
            self._record(ViolationType.EVAL_EXEC,
                         f"call to builtin {func.id}() is forbidden", node.lineno)
        # module.attr(...) patterns
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = func.value.id
            attr = func.attr
            self._check_module_call(module, attr, node)
        # deep attribute: a.b.c() — check tail for os.system-style usage
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute):
            if func.value.attr == "system" or func.attr in _OS_PROCESS_CALLS:
                base = self._dotted_name(func)
                if base and any(part == "os" for part in base.split(".")):
                    self._record(ViolationType.OS_PROCESS,
                                 f"call to {'.'.join(base.split('.')[:-1])}.{func.attr}()",
                                 node.lineno)
        # pickle.loads / marshal.loads / dill.loads
        if isinstance(func, ast.Attribute) and func.attr in _DESERIALIZE_CALLS:
            base = self._dotted_name(func)
            if base and _top_module(base) in {"pickle", "marshal", "dill", "shelve"}:
                self._record(ViolationType.UNSAFE_DESERIALIZE,
                             f"{base}() can execute arbitrary code", node.lineno)
        self.generic_visit(node)

    def _check_module_call(self, module: str, attr: str,
                           node: ast.Call) -> None:
        resolved = self.imported.get(module, module)
        top = _top_module(resolved)
        if attr in _OS_PROCESS_CALLS and top == "os":
            self._record(ViolationType.OS_PROCESS,
                         f"os.{attr}() creates processes (forbidden)", node.lineno)
        elif top == "subprocess" or (top == "os" and attr == "system"):
            self._record(ViolationType.SUBPROCESS,
                         f"subprocess call via {module}.{attr}()", node.lineno)
        elif top == "ctypes":
            self._record(ViolationType.CTYPES,
                         f"ctypes call {module}.{attr}() bypasses the sandbox", node.lineno)
        elif top == "pickle" and attr in _DESERIALIZE_CALLS:
            self._record(ViolationType.UNSAFE_DESERIALIZE,
                         f"pickle.{attr}() is unsafe deserialization", node.lineno)
        elif top == "socket":
            self.violations.append(Violation(
                ViolationType.NETWORK_WITHOUT_PERMISSION,
                f"socket call {module}.{attr}() requires permissions.network",
                node.lineno, blocking=True))
        elif top == "importlib" and attr == "import_module":
            self._record(ViolationType.DYNAMIC_IMPORT,
                         "importlib.import_module() bypasses static import checks",
                         node.lineno)
        elif module == "os" and attr in {"chmod", "chown", "setuid", "setgid",
                                          "setgroups", "setreuid", "setregid"}:
            self.violations.append(Violation(
                ViolationType.MUTATION_HINT,
                f"os.{attr}() will be audited by the runtime sandbox",
                node.lineno, blocking=False))

    # ── open() writes are advisory only ────────────────────────────
    def visit_Open_ctx(self, node: ast.Call) -> None:  # pragma: no cover - helper
        pass

    def _dotted_name(self, node: ast.AST) -> Optional[str]:
        parts: List[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    def _record(self, kind: str, detail: str, lineno: int) -> None:
        self.violations.append(Violation(kind, detail, lineno, blocking=True))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # __subclasses__ / __globals__ tricks
        if node.attr in {"__subclasses__", "__globals__", "__builtins__", "__code__"}:
            self.violations.append(Violation(
                ViolationType.EVAL_EXEC,
                f"access to dunder attribute {node.attr} (escape-hatch pattern)",
                node.lineno, blocking=False))
        self.generic_visit(node)


def analyze_source(source: str) -> List[Violation]:
    """AST-analyse plugin source.  Syntax errors produce a BLOCKING violation."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Violation("syntax-error", f"plugin does not compile: {exc}",
                          exc.lineno or 0, True)]
    visitor = _Visitor()
    visitor.visit(tree)
    return visitor.violations


def check_runnable(source: str,
                   permissions: PermissionSet) -> Tuple[bool, List[Violation]]:
    """Gate: may this plugin run under the granted permissions?

    Returns (ok, violations-with-final-block-flags).  Network violations are
    downgraded to advisory when ``permissions.network`` is True.
    """
    violations = analyze_source(source)
    final: List[Violation] = []
    ok = True
    for v in violations:
        if v.kind == ViolationType.NETWORK_WITHOUT_PERMISSION and permissions.network:
            v = Violation(v.kind, v.detail + " [network granted]", v.line, blocking=False)
        final.append(v)
        if v.blocking and v.kind != "syntax-error":
            ok = False
        elif v.kind == "syntax-error":
            ok = False
    return ok, final


def summarize(violations: List[Violation]) -> str:
    if not violations:
        return "clean"
    blocking = [v for v in violations if v.blocking]
    if blocking:
        return f"{len(blocking)} blocking violation(s): " + "; ".join(
            f"{v.kind}@L{v.line}({v.detail})" for v in blocking[:5])
    return f"{len(violations)} advisory note(s)"
