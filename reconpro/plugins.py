"""Plugin system for ReconPro (sandboxed).

Plugins live under ``~/.reconpro/plugins/``:

* **SDK plugins** — ``<id>/plugin.toml`` + ``<id>/main.py`` (signed,
  permissioned, verified at install time).
* **Legacy plugins** — loose ``<name>.py`` files with a ``run()`` function
  (unsigned, run at your own risk — but ALWAYS inside the OS-process
  sandbox).

Security invariants (enforced by :mod:`reconpro.plugin_sdk`):

1. Discovery NEVER imports or executes plugin code (AST metadata only).
2. Execution ALWAYS happens in a separate OS process with resource limits,
   an audit hook blocking network/process/privilege/path escapes, a
   minimal environment and a wall-clock deadline.
3. Static analysis gates every run: subprocess/ctypes/eval/exec style
   plugins are refused before they ever load.
"""
from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

from .constants import PLUGIN_DIR
from .http_layer import Finding


def _ensure_plugin_dir() -> None:
    try:
        PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create plugin directory %s: %s", PLUGIN_DIR, e)


# ═══════════════════════════════════════════════════════════════════════════
# Discovery — metadata only, ZERO execution (fixes the import-time RCE)
# ═══════════════════════════════════════════════════════════════════════════

def _plugin_has_run(source: str) -> bool:
    """AST check for a top-level callable ``run`` — without executing it."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
            return True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "run":
                    return isinstance(node.value, ast.Lambda)
    return False


def discover_plugins(use_sandbox: bool = True) -> Dict[str, Dict[str, Any]]:
    """Discover all plugins **without executing any plugin code**.

    Returns ``{plugin_id: {name, description, path, source, version,
    trusted, runner}}``.  ``runner`` is always ``None`` now — execution
    goes exclusively through :func:`run_plugin` / the plugin_sdk runner.
    """
    _ensure_plugin_dir()
    plugins: Dict[str, Dict[str, Any]] = {}
    if not PLUGIN_DIR.is_dir():
        return plugins

    try:
        from .plugin_sdk import PluginManager
        manager = PluginManager(root=Path(PLUGIN_DIR))
        for info in manager.list_plugins():
            plugins[info.id] = {
                "name": info.name,
                "description": info.description,
                "path": str(info.path),
                "source": info.source,
                "version": info.version,
                "trusted": info.trusted,
                "runner": None,  # execution is sandbox-only; no in-process callables
            }
    except Exception:
        logger.debug("plugin_sdk discovery failed", exc_info=True)

    # Legacy loose .py files (compat): AST-validated, never imported here.
    for py_file in sorted(PLUGIN_DIR.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        plugin_id = py_file.stem
        if plugin_id in plugins:
            continue  # SDK version wins
        try:
            source = py_file.read_text(errors="replace")
        except OSError:
            continue
        # extract NAME/DESCRIPTION module constants without execution
        name, desc = plugin_id.upper(), "Legacy plugin (unsigned)"
        try:
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in ("NAME", "DESCRIPTION") \
                                and isinstance(node.value.value, str):
                            if target.id == "NAME":
                                name = node.value.value
                            else:
                                desc = node.value.value
        except SyntaxError:
            continue  # broken plugins are skipped, never crash discovery
        if not _plugin_has_run(source):
            continue
        plugins[plugin_id] = {
            "name": name,
            "description": desc,
            "path": str(py_file),
            "source": "legacy",
            "version": "0.0.0",
            "trusted": False,
            "runner": None,
        }
    return plugins


# ═══════════════════════════════════════════════════════════════════════════
# Execution — mandatory OS-process sandbox via plugin_sdk
# ═══════════════════════════════════════════════════════════════════════════

def run_plugin(plugin_id: str, target: str, base_url: str = "",
               timeout: int = 8, verify_tls: bool = True,
               use_sandbox: bool = True) -> List[Any]:
    """Run a plugin inside the OS-process sandbox. Always sandboxed.

    ``use_sandbox`` is accepted for API compatibility and ignored — there
    is no unsandboxed path (security policy).

    Returns validated finding dicts on success; error ``Finding`` objects
    on failure (sandbox violation / timeout / crash / bad output).
    """
    try:
        from .plugin_sdk import PluginManager, PluginRunner, PermissionSet
        from .plugin_sdk.analysis import check_runnable, summarize
    except ImportError:
        logger.error("plugin_sdk unavailable — refusing to execute plugin %r", plugin_id)
        return [_error_finding(plugin_id, target,
                               "Plugin execution refused: plugin_sdk unavailable")]

    plugins = discover_plugins()
    if plugin_id not in plugins:
        return [Finding(
            title=f"Plugin '{plugin_id}' not found",
            severity="info", category="plugin",
            module="plugin",
            description=f"No plugin named '{plugin_id}' in {PLUGIN_DIR}",
            evidence="", asset=target, points_deducted=0,
        )]

    info = plugins[plugin_id]

    # Static-analysis gate (refuse before loading anything).
    try:
        source = Path(info["path"]).read_text(errors="replace")
        permissions = PermissionSet()
        runnable, violations = check_runnable(source, permissions)
        if not runnable:
            detail = summarize(violations)
            logger.warning("Plugin '%s' refused by static analysis: %s", plugin_id, detail)
            return [_error_finding(plugin_id, target,
                                   f"Plugin refused by static analysis: {detail}")]
    except OSError as e:
        return [_error_finding(plugin_id, target, f"cannot read plugin source: {e}")]

    runner = PluginRunner(cpu_seconds=timeout, wall_timeout_s=float(timeout) + 4.0)
    result = runner.execute(
        info["path"],
        permissions=permissions,
        args={"target": target, "base_url": base_url,
              "timeout": timeout, "verify_tls": verify_tls},
    )

    if result.kind == "ok" and result.ok:
        # validated dicts (title/severity/category guaranteed)
        return result.findings

    if result.kind == "timeout":
        return [_error_finding(plugin_id, target, result.error, severity="medium")]

    if result.kind == "violation":
        logger.warning("Plugin '%s' sandbox violation: %s", plugin_id, result.error)
        return [_error_finding(plugin_id, target,
                               f"sandbox error: {result.error}", severity="low")]

    # crash / invalid_output / process_error → sandbox error findings
    detail = result.error or result.kind
    if "list" in detail.lower() or "dict" in detail.lower() or "keys" in detail.lower() \
            or result.kind == "invalid_output":
        detail = f"sandbox error: {detail}"
    return [_error_finding(plugin_id, target, f"sandbox error: {detail}", severity="low")]


def _error_finding(plugin_id: str, target: str, description: str,
                   severity: str = "low") -> Finding:
    return Finding(
        title=f"Plugin '{plugin_id}' sandbox error",
        severity=severity, category="plugin",
        module="plugin",
        description=description,
        evidence="", asset=target, points_deducted=0,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Templates
# ═══════════════════════════════════════════════════════════════════════════

def create_plugin_template(name: str) -> str:
    """Create a template plugin file (legacy layout). Returns the path."""
    from .plugin_sdk.scaffold import create_legacy_template
    _ensure_plugin_dir()
    return str(create_legacy_template(PLUGIN_DIR, name))


def create_plugin_skeleton(name: str, dest: Optional[Path] = None) -> str:
    """Create a signed-ready SDK plugin skeleton (plugin.toml + main.py)."""
    from .plugin_sdk.scaffold import create_plugin_skeleton as _skel
    return str(_skel(dest or PLUGIN_DIR, name))


# ═══════════════════════════════════════════════════════════════════════════
# PLUGIN HOOK SYSTEM — in-process event hooks (registered by code, never
# auto-loaded from plugin files)
# ═══════════════════════════════════════════════════════════════════════════

_HOOK_REGISTRY: Dict[str, List[Callable]] = {}
_PLUGIN_META: Dict[str, Dict[str, Any]] = {}
_PLUGIN_HOOKS_FILE = PLUGIN_DIR / "_hooks.json"


class HookManager:
    """Central event hook system for plugins.

    Hooks:
        pre_scan      — Before scan starts. Args: (target, base_url, modules)
        post_scan     — After scan completes. Args: (target, findings, score)
        pre_finding   — Before a finding is recorded. Args: (finding_dict). Return modified finding or None.
        post_finding  — After a finding is recorded. Args: (finding_dict)
        pre_report    — Before report generation. Args: (findings, format). Can modify findings.
        post_report   — After report generated. Args: (report_path, format)
        new_target    — When a new target is discovered. Args: (target_url)
        vulnerability — When a vulnerability is confirmed. Args: (finding_dict, severity)
        error         — When an error occurs. Args: (error_msg, context)
    """

    HOOK_NAMES = [
        "pre_scan", "post_scan", "pre_finding", "post_finding",
        "pre_report", "post_report", "new_target", "vulnerability", "error",
    ]

    @classmethod
    def register(cls, hook_name: str, callback: Callable, priority: int = 100) -> bool:
        """Register a callback for a hook. Lower priority = runs first."""
        if hook_name not in cls.HOOK_NAMES:
            return False
        if hook_name not in _HOOK_REGISTRY:
            _HOOK_REGISTRY[hook_name] = []
        _HOOK_REGISTRY[hook_name].append((priority, callback))
        _HOOK_REGISTRY[hook_name].sort(key=lambda x: x[0])
        return True

    @classmethod
    def unregister(cls, hook_name: str, callback: Callable) -> bool:
        """Remove a specific callback."""
        if hook_name not in _HOOK_REGISTRY:
            return False
        _HOOK_REGISTRY[hook_name] = [
            (p, cb) for p, cb in _HOOK_REGISTRY[hook_name] if cb is not callback
        ]
        return True

    @classmethod
    def fire(cls, hook_name: str, *args, **kwargs) -> Any:
        """Execute all callbacks registered for a hook.
        If any callback returns a non-None value, it short-circuits and returns that value."""
        results = []
        for priority, callback in _HOOK_REGISTRY.get(hook_name, []):
            try:
                result = callback(*args, **kwargs)
                results.append(result)
                if result is not None:
                    return result  # Short-circuit
            except Exception:
                logger.debug("Hook callback error in '%s': %s", hook_name, callback, exc_info=True)
        return None

    @classmethod
    def clear(cls, hook_name: Optional[str] = None):
        """Clear hooks. If hook_name is None, clear all."""
        if hook_name:
            _HOOK_REGISTRY.pop(hook_name, None)
        else:
            _HOOK_REGISTRY.clear()

    @classmethod
    def list_hooks(cls) -> Dict[str, int]:
        """List all registered hooks with callback counts."""
        return {name: len(cbs) for name, cbs in _HOOK_REGISTRY.items()}

    @classmethod
    def save_hooks(cls):
        """Persist hook metadata to disk (names only — callables cannot be
        serialised; see load_hooks)."""
        _ensure_plugin_dir()
        data = {}
        for name, callbacks in _HOOK_REGISTRY.items():
            data[name] = [f"{getattr(cb, '__module__', '?')}.{getattr(cb, '__name__', '?')}" for _, cb in callbacks]
        with open(_PLUGIN_HOOKS_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_hooks(cls):
        """Load hook metadata from disk.

        Returns a dict mapping hook names to lists of qualified function-name
        strings that were registered at save time.  This is **metadata only**;
        the actual callback callables cannot be restored from a JSON file.
        Plugins must re-register their hooks at import time.
        """
        if _PLUGIN_HOOKS_FILE.exists():
            try:
                with open(_PLUGIN_HOOKS_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                logger.debug("Failed to load hooks metadata from %s", _PLUGIN_HOOKS_FILE, exc_info=True)
        return {}


def register_plugin(name: str, version: str = "1.0.0", description: str = "",
                    author: str = "", hooks: Optional[Dict[str, Callable]] = None) -> bool:
    """Register an in-process plugin with metadata and optional hooks."""
    _PLUGIN_META[name] = {
        "name": name,
        "version": version,
        "description": description,
        "author": author,
        "registered": True,
    }

    if hooks:
        for hook_name, callback in hooks.items():
            HookManager.register(hook_name, callback)

    return True


def get_registered_plugins() -> Dict[str, Dict[str, Any]]:
    """Get metadata for all registered in-process plugins."""
    return dict(_PLUGIN_META)


def load_all_plugins(use_sandbox: bool = True) -> Dict[str, Dict[str, Any]]:
    """Discover all plugins (metadata only — hooks are never auto-registered
    from plugin files; that was the import-time RCE vector)."""
    plugins = discover_plugins()
    for plugin_id, plugin_info in plugins.items():
        _PLUGIN_META.setdefault(plugin_id, {
            "name": plugin_id,
            "description": plugin_info.get("description", ""),
            "registered": True,
        })
    return plugins
