"""Lazy rich bindings for the CLI — keeps cold startup under budget.

``reconpro --version`` must complete in <100 ms; importing ``rich`` alone
costs ~110 ms.  This module provides drop-in names that resolve to the
real rich classes on FIRST USE (constructor call / attribute access) and
then replace themselves in the caller's globals.

Supported patterns (everything cli.py actually does):
* ``console.print(...)`` / ``console.status(...)`` — proxy object
* ``Panel(...)``, ``Table(...)``, ``Text(...)``, ``Group(...)``,
  ``Progress(...)``, ``SpinnerColumn()``, ... — constructor shims
* ``Console(...)`` — constructor shim
"""
from __future__ import annotations

import sys
from typing import Any


class _ConsoleProxy:
    """Stand-in for rich.console.Console; resolves on first use."""

    __slots__ = ()

    _real: Any = None

    def __getattr__(self, name: str) -> Any:
        cls = type(self)
        if cls._real is None:
            from rich.console import Console
            cls._real = Console(file=sys.stderr)
        return getattr(cls._real, name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        cls = type(self)
        if cls._real is None:
            from rich.console import Console
            cls._real = Console(file=sys.stderr)
        return cls._real(*args, **kwargs)

    # rich's Progress/Live do `with console:` — delegate the protocol
    def __enter__(self) -> Any:
        return type(self)._real.__enter__() if type(self)._real is not None \
            else self.__getattr__("is_terminal") and type(self)._real.__enter__()

    def __exit__(self, *exc: Any) -> Any:
        if type(self)._real is not None:
            return type(self)._real.__exit__(*exc)
        return False


console = _ConsoleProxy()


class _LazyClass:
    """Stand-in for a rich class; constructs the real thing on first call."""

    __slots__ = ("_module", "_name")

    def __init__(self, module: str, name: str) -> None:
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_name", name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        import importlib
        real = getattr(importlib.import_module(self._module), self._name)
        # cache in this module so future references skip the shim
        globals()[self._name] = real
        return real(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        import importlib
        real = getattr(importlib.import_module(self._module), self._name)
        globals()[self._name] = real
        return getattr(real, name)

    def __setattr__(self, name: str, value: Any) -> None:
        import importlib
        real = getattr(importlib.import_module(self._module), self._name)
        globals()[self._name] = real
        setattr(real, name, value)


Console = _LazyClass("rich.console", "Console")
Group = _LazyClass("rich.console", "Group")
Panel = _LazyClass("rich.panel", "Panel")
Progress = _LazyClass("rich.progress", "Progress")
SpinnerColumn = _LazyClass("rich.progress", "SpinnerColumn")
TextColumn = _LazyClass("rich.progress", "TextColumn")
TimeElapsedColumn = _LazyClass("rich.progress", "TimeElapsedColumn")
Table = _LazyClass("rich.table", "Table")
Text = _LazyClass("rich.text", "Text")


def escape(text: str) -> str:
    """Escape dynamic text so Rich does not interpret markup tags in it.

    Any attacker-influenced string (exception messages, plugin ids, paths,
    scan targets) interpolated into a ``console.print(f"...")`` MUST be
    wrapped in this, otherwise bracketed content like ``[red]`` or a regex
    character class is silently parsed (and stripped) as Rich markup —
    a terminal content-spoofing vector.
    """
    from rich.markup import escape as _escape
    return _escape(text)


def preload() -> None:
    """Force-import rich now (for callers that want warm behavior)."""
    import importlib
    for module_name in ("rich.console", "rich.panel", "rich.progress",
                        "rich.table", "rich.text"):
        importlib.import_module(module_name)
    _ = console.is_terminal  # touch → instantiate the real console
