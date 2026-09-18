"""ReconPro v11 — Diagnostic Tools.

Self-diagnosis and debugging utilities for ReconPro.
Helps users and developers identify issues quickly.
"""
from __future__ import annotations

import importlib
import os
import platform
import shutil
import socket
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .constants import (
    MEMORY_DIR,
    PLUGIN_DIR,
    RECONPRO_HOME,
    SCAN_HISTORY_DIR,
    __version__,
)
from .registry import (
    ALL_MODULES,
    DEFAULT_LOCAL_MODULES,
    DEFAULT_MODULES,
    LOCAL_MODULES,
    MODULE_REGISTRY,
    get_module_runner,
)


def _check(label: str, fn: Callable[[], Any]) -> Dict[str, Any]:
    """Run a single diagnostic check and return structured result."""
    try:
        value = fn()
        return {"label": label, "status": "ok", "value": value}
    except Exception as e:
        return {"label": label, "status": "error", "error": str(e)}


def run_diagnostics() -> Dict[str, Any]:
    """Run full system diagnostic.

    Checks:
    - Python version and compatibility
    - ReconPro version and installation path
    - Module registry integrity (all runners callable)
    - Plugin directory status
    - Scan history status
    - Configuration file presence
    - Disk space for scan data
    - Network connectivity (DNS resolution)
    - SSL certificate verification
    - Memory availability

    Returns structured diagnostic report with status per check.
    """
    checks: List[Dict[str, Any]] = []

    # 1. Python version
    def _py_ver():
        major, minor, micro = sys.version_info[:3]
        return f"{major}.{minor}.{micro}"

    checks.append(_check(
        "python_version",
        lambda: {"version": _py_ver(), "compatible": sys.version_info >= (3, 9)},
    ))

    # 2. ReconPro version
    checks.append(_check(
        "reconpro_version",
        lambda: {"version": __version__, "path": str(Path(__file__).parent.resolve())},
    ))

    # 3. Module registry integrity
    def _registry_check():
        broken = []
        for mid in ALL_MODULES:
            runner = get_module_runner(mid)
            if runner is None or not callable(runner):
                broken.append(mid)
        return {"total": len(ALL_MODULES), "broken": broken, "integrity": len(broken) == 0}

    checks.append(_check("module_registry", _registry_check))

    # 4. Plugin directory status
    def _plugin_check():
        exists = PLUGIN_DIR.exists()
        count = len(list(PLUGIN_DIR.glob("*.py"))) if exists else 0
        return {"exists": exists, "count": count, "path": str(PLUGIN_DIR)}

    checks.append(_check("plugin_directory", _plugin_check))

    # 5. Scan history status
    def _history_check():
        exists = SCAN_HISTORY_DIR.exists()
        count = len(list(SCAN_HISTORY_DIR.glob("*.json"))) if exists else 0
        return {"exists": exists, "count": count, "path": str(SCAN_HISTORY_DIR)}

    checks.append(_check("scan_history", _history_check))

    # 6. Configuration file presence
    def _config_check():
        config_file = RECONPRO_HOME / "config.json"
        return {"exists": config_file.exists(), "path": str(config_file)}

    checks.append(_check("configuration", _config_check))

    # 7. Disk space for scan data
    def _disk_check():
        try:
            usage = shutil.disk_usage(str(RECONPRO_HOME))
            free_gb = round(usage.free / (1024 ** 3), 2)
            total_gb = round(usage.total / (1024 ** 3), 2)
            return {"free_gb": free_gb, "total_gb": total_gb, "sufficient": free_gb >= 1.0}
        except OSError:
            return {"free_gb": 0, "total_gb": 0, "sufficient": False}

    checks.append(_check("disk_space", _disk_check))

    # 8. Network connectivity (DNS resolution)
    def _dns_check():
        try:
            start = time.time()
            socket.gethostbyname("dns.google")
            elapsed = round(time.time() - start, 3)
            return {"reachable": True, "latency_ms": round(elapsed * 1000)}
        except socket.gaierror:
            return {"reachable": False, "latency_ms": None}

    checks.append(_check("network_dns", _dns_check))

    # 9. SSL certificate verification
    def _ssl_check():
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(("google.com", 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="google.com") as ssock:
                    return {"valid": True, "version": ssock.version()}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    checks.append(_check("ssl_certificate", _ssl_check))

    # 10. Memory availability
    def _mem_check():
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            return {"soft_limit": soft, "hard_limit": hard}
        except (ImportError, ValueError):
            # resource module not available on all platforms (e.g., Windows)
            try:
                import psutil  # type: ignore
                mem = psutil.virtual_memory()
                return {"available_mb": round(mem.available / (1024 ** 2), 1), "total_mb": round(mem.total / (1024 ** 2), 1)}
            except ImportError:
                return {"status": "platform_info_unavailable"}

    checks.append(_check("memory", _mem_check))

    ok_count = sum(1 for c in checks if c["status"] == "ok")
    return {
        "timestamp": datetime.now().isoformat(),
        "total_checks": len(checks),
        "passed": ok_count,
        "failed": len(checks) - ok_count,
        "checks": checks,
    }


def health_check() -> Dict[str, str]:
    """Quick health check. Returns {category: status}."""
    result: Dict[str, str] = {}

    # Python compatibility
    result["python"] = "ok" if sys.version_info >= (3, 9) else "error"

    # Module registry
    broken = sum(1 for mid in ALL_MODULES if get_module_runner(mid) is None)
    result["modules"] = "ok" if broken == 0 else f"warning ({broken} broken)"

    # Plugin dir
    result["plugins"] = "ok" if PLUGIN_DIR.exists() else "missing"

    # History dir
    result["history"] = "ok" if SCAN_HISTORY_DIR.exists() else "missing"

    # Config
    config_file = RECONPRO_HOME / "config.json"
    result["config"] = "ok" if config_file.exists() else "default"

    # Network
    try:
        socket.gethostbyname("dns.google")
        result["network"] = "ok"
    except socket.gaierror:
        result["network"] = "unreachable"

    # Home dir
    result["home"] = "ok" if RECONPRO_HOME.exists() else "missing"

    return result


def get_version_info() -> Dict[str, str]:
    """Detailed version information."""
    return {
        "reconpro": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "module_count": str(len(ALL_MODULES)),
        "remote_modules": str(len(MODULE_REGISTRY)),
        "local_modules": str(len(LOCAL_MODULES)),
        "default_modules": str(len(DEFAULT_MODULES)),
        "default_local_modules": str(len(DEFAULT_LOCAL_MODULES)),
        "installation_path": str(Path(__file__).parent.resolve()),
        "reconpro_home": str(RECONPRO_HOME),
        "executable": sys.executable,
    }


def generate_debug_report() -> str:
    """Generate a text debug report for issue reporting."""
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("  ReconPro v11 — Debug Report")
    lines.append(f"  Generated: {datetime.now().isoformat()}")
    lines.append("=" * 70)
    lines.append("")

    # Version info
    vi = get_version_info()
    lines.append("VERSION INFORMATION")
    lines.append("-" * 40)
    for k, v in vi.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    # Health check
    lines.append("HEALTH CHECK")
    lines.append("-" * 40)
    hc = health_check()
    for k, v in hc.items():
        lines.append(f"  {k}: {v}")
    lines.append("")

    # Module status
    lines.append("MODULE STATUS")
    lines.append("-" * 40)
    ms = module_status()
    for m in ms:
        status_icon = "✓" if m["runner_status"] else "✗"
        mod_type = "remote" if m["type"] == "remote" else "local"
        lines.append(
            f"  [{status_icon}] {m['name']} ({mod_type}) "
            f"lines≈{m.get('estimated_lines', '?')}"
        )
    lines.append("")

    # Diagnostics summary
    diag = run_diagnostics()
    lines.append("DIAGNOSTICS SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Passed: {diag['passed']}/{diag['total_checks']}")
    for c in diag["checks"]:
        if c["status"] != "ok":
            lines.append(f"  [!] {c['label']}: {c.get('error', 'unknown')}")
    lines.append("")

    # Environment
    lines.append("ENVIRONMENT")
    lines.append("-" * 40)
    lines.append(f"  CWD: {os.getcwd()}")
    lines.append(f"  PATH: {os.environ.get('PATH', '<not set>')[:200]}...")
    lines.append(f"  TERM: {os.environ.get('TERM', '<not set>')}")
    lines.append(f"  LANG: {os.environ.get('LANG', '<not set>')}")
    lines.append("")

    lines.append("=" * 70)
    lines.append("  End of debug report")
    lines.append("=" * 70)
    return "\n".join(lines)


def module_status() -> List[Dict[str, Any]]:
    """Status of all registered modules.

    For each module: name, type (remote/local), runner status,
    estimated complexity (line count if available).
    """
    results: List[Dict[str, Any]] = []

    # Remote modules
    for mid, entry in MODULE_REGISTRY.items():
        runner = entry.get("runner")
        runner_ok = runner is not None and callable(runner)
        mod_file = _estimate_module_lines(mid)
        results.append({
            "id": mid,
            "name": entry.get("name", mid),
            "type": "remote",
            "runner_status": runner_ok,
            "estimated_lines": mod_file,
            "color": entry.get("color", ""),
        })

    # Local modules
    for mid, entry in LOCAL_MODULES.items():
        runner = entry.get("runner")
        runner_ok = runner is not None and callable(runner)
        mod_file = _estimate_module_lines(mid)
        results.append({
            "id": mid,
            "name": entry.get("name", mid),
            "type": "local",
            "runner_status": runner_ok,
            "estimated_lines": mod_file,
            "color": entry.get("color", ""),
        })

    return results


def _estimate_module_lines(module_id: str) -> Optional[int]:
    """Try to count lines in a module file."""
    try:
        # Map module_id to file name
        file_map = {
            "quantum_fingerprint": "quantum_fingerprint.py",
            "dark_web_monitor": "dark_web_monitor.py",
            "info_ops": "free_info_ops.py",
            "steganography_detector": "steganography_detector.py",
            "covert_channel": "covert_channel.py",
            "zero_day_hunter": "zero_day_hunter.py",
            "infrastructure_ghost": "infrastructure_ghost.py",
            "signal_intelligence": "signal_intelligence.py",
            "nation_state_attributor": "nation_state_attributor.py",
            "weaponized_report": "weaponized_report.py",
            "honeypot_dance": "honeypot_dance.py",
            "dead_drop": "dead_drop.py",
        }
        filename = file_map.get(module_id, f"{module_id}.py")
        mod_path = Path(__file__).parent / "modules" / filename
        if mod_path.exists():
            return sum(1 for _ in mod_path.open("r", encoding="utf-8", errors="ignore"))
        return None
    except Exception:
        return None


def validate_config() -> List[Dict[str, Any]]:
    """Validate current configuration and report issues."""
    issues: List[Dict[str, Any]] = []

    # Check ReconPro home directory exists
    if not RECONPRO_HOME.exists():
        issues.append({
            "severity": "warning",
            "category": "paths",
            "message": f"ReconPro home directory does not exist: {RECONPRO_HOME}",
            "suggestion": "Run any ReconPro command to initialize directories.",
        })

    # Check scan history directory
    if not SCAN_HISTORY_DIR.exists():
        issues.append({
            "severity": "warning",
            "category": "paths",
            "message": f"Scan history directory does not exist: {SCAN_HISTORY_DIR}",
            "suggestion": "Scan history will be created on first scan.",
        })

    # Check plugin directory
    if not PLUGIN_DIR.exists():
        issues.append({
            "severity": "info",
            "category": "paths",
            "message": f"Plugin directory does not exist: {PLUGIN_DIR}",
            "suggestion": "Plugin directory will be created when loading plugins.",
        })

    # Check memory directory
    if not MEMORY_DIR.exists():
        issues.append({
            "severity": "info",
            "category": "paths",
            "message": f"Memory directory does not exist: {MEMORY_DIR}",
            "suggestion": "Knowledge graph memory will be created on first use.",
        })

    # Check config file
    config_file = RECONPRO_HOME / "config.json"
    if config_file.exists():
        try:
            import json
            with open(config_file, "r", encoding="utf-8", errors="strict") as f:
                cfg = json.load(f)
            if not isinstance(cfg, dict):
                issues.append({
                    "severity": "error",
                    "category": "config",
                    "message": "config.json is not a valid JSON object.",
                    "suggestion": "Check config.json syntax.",
                })
        except json.JSONDecodeError as e:
            issues.append({
                "severity": "error",
                "category": "config",
                "message": f"config.json has invalid JSON: {e}",
                "suggestion": "Fix JSON syntax in config.json.",
            })
        except (UnicodeDecodeError, OSError) as e:
            # Binary/corrupted/unreadable config must never crash the doctor
            issues.append({
                "severity": "error",
                "category": "config",
                "message": f"config.json is unreadable or corrupted: {e}",
                "suggestion": "Delete config.json to regenerate defaults: "
                              f"rm {config_file}",
            })
    else:
        issues.append({
            "severity": "info",
            "category": "config",
            "message": "No config.json found — using defaults.",
            "suggestion": "Create config.json to customize settings.",
        })

    # Check module registry integrity
    broken_modules = []
    for mid in ALL_MODULES:
        runner = get_module_runner(mid)
        if runner is None or not callable(runner):
            broken_modules.append(mid)
    if broken_modules:
        issues.append({
            "severity": "error",
            "category": "modules",
            "message": f"{len(broken_modules)} modules have broken runners: {broken_modules}",
            "suggestion": "Reinstall ReconPro or check module files.",
        })

    # Check Python version
    if sys.version_info < (3, 9):
        issues.append({
            "severity": "error",
            "category": "python",
            "message": f"Python {sys.version_info.major}.{sys.version_info.minor} is below minimum (3.9).",
            "suggestion": "Upgrade to Python 3.9 or higher.",
        })

    # Check disk space
    try:
        usage = shutil.disk_usage(str(RECONPRO_HOME))
        free_gb = usage.free / (1024 ** 3)
        if free_gb < 0.5:
            issues.append({
                "severity": "warning",
                "category": "disk",
                "message": f"Low disk space: {free_gb:.2f} GB free.",
                "suggestion": "Free up disk space for scan data storage.",
            })
    except OSError:
        issues.append({
            "severity": "warning",
            "category": "disk",
            "message": "Cannot determine disk space.",
            "suggestion": "Check filesystem permissions.",
        })

    # Check network
    try:
        socket.gethostbyname("dns.google")
    except socket.gaierror:
        issues.append({
            "severity": "warning",
            "category": "network",
            "message": "DNS resolution failed — network may be offline.",
            "suggestion": "Check network connection for scan functionality.",
        })

    return issues
