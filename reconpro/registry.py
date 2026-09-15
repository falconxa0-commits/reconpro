"""ReconPro v11 — Module Registry.

Centralized registry for all scanning modules. Both scanner.py and engine.py
import from here, eliminating circular coupling.

This file is the SINGLE SOURCE OF TRUTH for:
- MODULE_REGISTRY (all remote modules)
- LOCAL_MODULES (machine audit modules)
- ALL_MODULES (combined)
- DEFAULT_MODULES (run with `reconpro scan`)
- DEFAULT_LOCAL_MODULES (run with `reconpro audit`)
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

# Lazy imports to avoid circular deps — these are resolved at scan time
_MOD_RUNNERS = {}


def _get_runners() -> Dict[str, Callable]:
    """Lazy-load all module runners. Cached after first call."""
    if _MOD_RUNNERS:
        return _MOD_RUNNERS

    from .modules import (
        run_recon, run_vibesec, run_auth, run_chain,
        run_bot, run_gorgon, run_oblivion, run_nhi,
        run_host, run_dev, run_doctor, run_pegasus,
        run_cloud_recon, run_team,
        run_quantum_fingerprint, run_dark_web_monitor, run_info_ops,
        run_steganography_detector, run_covert_channel, run_zero_day_hunter,
        run_infrastructure_ghost, run_signal_intelligence, run_nation_state_attributor,
        run_weaponized_report, run_honeypot_dance, run_dead_drop,
        run_container_sec, run_iac_audit,
    )

    _MOD_RUNNERS.update({
        "run_recon": run_recon,
        "run_vibesec": run_vibesec,
        "run_auth": run_auth,
        "run_chain": run_chain,
        "run_bot": run_bot,
        "run_gorgon": run_gorgon,
        "run_oblivion": run_oblivion,
        "run_nhi": run_nhi,
        "run_host": run_host,
        "run_dev": run_dev,
        "run_doctor": run_doctor,
        "run_pegasus": run_pegasus,
        "run_cloud_recon": run_cloud_recon,
        "run_team": run_team,
        "run_quantum_fingerprint": run_quantum_fingerprint,
        "run_dark_web_monitor": run_dark_web_monitor,
        "run_info_ops": run_info_ops,
        "run_steganography_detector": run_steganography_detector,
        "run_covert_channel": run_covert_channel,
        "run_zero_day_hunter": run_zero_day_hunter,
        "run_infrastructure_ghost": run_infrastructure_ghost,
        "run_signal_intelligence": run_signal_intelligence,
        "run_nation_state_attributor": run_nation_state_attributor,
        "run_weaponized_report": run_weaponized_report,
        "run_honeypot_dance": run_honeypot_dance,
        "run_dead_drop": run_dead_drop,
        "run_container_sec": run_container_sec,
        "run_iac_audit": run_iac_audit,
    })
    return _MOD_RUNNERS


def build_module_registry() -> Dict[str, Dict[str, Any]]:
    """Build the full MODULE_REGISTRY dict. Called at import time."""
    r = _get_runners()

    return {
        # Core remote modules
        "recon":    {"name": "RECON",         "runner": r["run_recon"],    "color": "cyan"},
        "auth":     {"name": "AUTH BYPASS",   "runner": r["run_auth"],     "color": "yellow"},
        "chain":    {"name": "CHAIN HUNTER",  "runner": r["run_chain"],    "color": "magenta"},
        "bot":      {"name": "BOT HUNTER",    "runner": r["run_bot"],      "color": "red"},
        "gorgon":   {"name": "GORGON ULTRA",  "runner": r["run_gorgon"],   "color": "bright_red"},
        "oblivion": {"name": "OBLIVION",      "runner": r["run_oblivion"], "color": "bright_magenta"},
        "vibesec":  {"name": "VIBESEC",       "runner": r["run_vibesec"],  "color": "bright_green"},
        "nhi":      {"name": "NHI GRAPH",     "runner": r["run_nhi"],      "color": "cyan"},
        "pegasus":  {"name": "PEGASUS HUNTER", "runner": r["run_pegasus"],  "color": "bright_red"},
        "cloud_recon": {"name": "CLOUD RECON", "runner": r["run_cloud_recon"], "color": "bright_cyan"},
        "team":     {"name": "TEAM",          "runner": r["run_team"],      "color": "cyan"},

        # v9.2.0 / v10: 12 advanced modules
        "quantum_fingerprint":    {"name": "QUANTUM FINGERPRINT",   "runner": r["run_quantum_fingerprint"],    "color": "bright_cyan"},
        "dark_web_monitor":       {"name": "DARK WEB MONITOR",      "runner": r["run_dark_web_monitor"],       "color": "bright_red"},
        "info_ops":               {"name": "INFO OPS",             "runner": r["run_info_ops"],               "color": "magenta"},
        "steganography_detector": {"name": "STEGANO DETECTOR",      "runner": r["run_steganography_detector"], "color": "yellow"},
        "covert_channel":         {"name": "COVERT CHANNEL",        "runner": r["run_covert_channel"],         "color": "red"},
        "zero_day_hunter":        {"name": "ZERO-DAY HUNTER",       "runner": r["run_zero_day_hunter"],        "color": "bright_red"},
        "infrastructure_ghost":    {"name": "INFRA GHOST",           "runner": r["run_infrastructure_ghost"],    "color": "cyan"},
        "signal_intelligence":     {"name": "SIGINT",                "runner": r["run_signal_intelligence"],     "color": "bright_magenta"},
        "nation_state_attributor": {"name": "NATION-STATE ATTR",    "runner": r["run_nation_state_attributor"], "color": "bright_red"},
        "weaponized_report":      {"name": "WEAPONIZED REPORT",     "runner": r["run_weaponized_report"],      "color": "red"},
        "honeypot_dance":         {"name": "HONEYPOT DANCE",        "runner": r["run_honeypot_dance"],         "color": "yellow"},
        "dead_drop":              {"name": "DEAD DROP",             "runner": r["run_dead_drop"],              "color": "bright_cyan"},

        # Orphaned modules now registered
        "container_sec":           {"name": "CONTAINER SEC",          "runner": r["run_container_sec"],         "color": "bright_yellow"},
        "iac_audit":               {"name": "IaC AUDIT",              "runner": r["run_iac_audit"],            "color": "bright_green"},
    }


def build_local_modules() -> Dict[str, Dict[str, Any]]:
    """Build the LOCAL_MODULES dict for machine audit."""
    r = _get_runners()
    return {
        "host":   {"name": "HOST AUDIT",   "runner": r["run_host"],   "color": "bright_yellow"},
        "dev":    {"name": "DEV SEC",      "runner": r["run_dev"],    "color": "bright_cyan"},
        "doctor": {"name": "DOCTOR",       "runner": r["run_doctor"], "color": "bright_green"},
    }


# ── Build registries at module load ────────────────────────────────────
MODULE_REGISTRY: Dict[str, Dict[str, Any]] = build_module_registry()
LOCAL_MODULES: Dict[str, Dict[str, Any]] = build_local_modules()

# Combined module list for --all scans
ALL_MODULES: List[str] = list(MODULE_REGISTRY.keys()) + list(LOCAL_MODULES.keys())

# Default modules for remote scans
DEFAULT_MODULES: List[str] = [
    "recon", "vibesec", "auth", "chain", "oblivion", "gorgon", "bot", "pegasus",
    "quantum_fingerprint", "dark_web_monitor", "info_ops",
    "steganography_detector", "covert_channel", "zero_day_hunter",
    "infrastructure_ghost", "signal_intelligence", "nation_state_attributor",
    "weaponized_report", "honeypot_dance", "dead_drop",
]

# Default modules for local audits
DEFAULT_LOCAL_MODULES: List[str] = ["host", "dev", "doctor"]


# DEAD CODE: consider removal
def get_module_runner(module_id: str) -> Optional[Callable]:
    """Get the runner function for a module ID. Returns None if not found."""
    if module_id in MODULE_REGISTRY:
        return MODULE_REGISTRY[module_id].get("runner")
    if module_id in LOCAL_MODULES:
        return LOCAL_MODULES[module_id].get("runner")
    return None


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def is_local_module(module_id: str) -> bool:
    """Check if a module ID is a local (machine audit) module."""
    return module_id in LOCAL_MODULES


def is_remote_module(module_id: str) -> bool:
    """Check if a module ID is a remote (network) module."""
    return module_id in MODULE_REGISTRY


# DEAD CODE: consider removal
def get_module_info(module_id: str) -> Optional[Dict[str, Any]]:
    """Get full module info including metadata."""
    if module_id in MODULE_REGISTRY:
        return MODULE_REGISTRY[module_id]
    if module_id in LOCAL_MODULES:
        return LOCAL_MODULES[module_id]
    return None


# DEAD CODE: consider removal
def list_remote_modules() -> List[str]:
    """List remote module IDs sorted alphabetically."""
    return sorted(MODULE_REGISTRY.keys())


# DEAD CODE: consider removal
def list_local_modules() -> List[str]:
    """List local module IDs sorted alphabetically."""
    return sorted(LOCAL_MODULES.keys())


def get_module_color(module_id: str) -> str:
    """Get display color for a module."""
    entry = get_module_info(module_id)
    return entry.get("color", "white") if entry else "white"


# ── Module Dependency Graph ──────────────────────────────────────────


MODULE_DEPENDENCIES: Dict[str, List[str]] = {
    # Core remote modules
    "recon": [],                              # no deps — base data gathering
    "auth": ["recon"],                       # needs recon results (subdomains, endpoints)
    "chain": ["recon"],                      # needs recon for asset chain analysis
    "bot": ["recon", "chain"],              # needs recon + chain for bot detection patterns
    "gorgon": ["recon"],                     # needs recon for deep analysis
    "oblivion": ["recon"],                   # needs recon endpoints
    "vibesec": ["recon", "auth"],           # needs recon + auth for scoring
    "nhi": ["recon", "chain"],              # needs recon + chain for graph
    "pegasus": ["recon"],                    # needs recon for pegasus pattern matching
    "cloud_recon": ["recon"],                # needs recon for cloud correlation
    "team": ["recon"],                       # needs recon for team analysis

    # Advanced modules (v9.2+)
    "quantum_fingerprint": ["recon"],        # needs recon for HTTP timing
    "dark_web_monitor": [],                   # independent — passive monitoring
    "info_ops": ["recon"],                   # needs recon for deception analysis
    "steganography_detector": ["recon"],     # needs recon responses to analyze
    "covert_channel": ["recon"],             # needs recon for traffic analysis
    "zero_day_hunter": ["recon"],            # needs recon for pattern matching
    "infrastructure_ghost": ["recon"],       # needs recon for infra cloning
    "signal_intelligence": ["recon"],        # needs recon for traffic patterns
    "nation_state_attributor": ["recon", "signal_intelligence"],  # needs sigint context
    "weaponized_report": ["recon"],          # needs recon findings
    "honeypot_dance": ["recon"],             # needs recon for honeypot detection
    "dead_drop": ["recon"],                  # needs recon for dead drop analysis

    # Local modules
    "host": [],                               # independent — local audit
    "dev": [],                                # independent — code scanning
    "doctor": ["host"],                      # needs host audit results
    "container_sec": ["dev"],                # needs dev results for container analysis
    "iac_audit": ["dev"],                    # needs dev results for IaC scanning
}


def get_execution_order(modules: List[str]) -> List[List[str]]:
    """Topologically sort *modules* respecting :data:`MODULE_DEPENDENCIES`.

    Returns a list of **groups** (lists of module IDs).  Modules in the
    same group have no dependency on each other and can safely run in
    parallel.  Groups must be executed in order.

    Raises
    ------
    ValueError
        If a circular dependency is detected among the requested modules.
    """
    # Build a sub-graph restricted to the requested modules.
    available = set(modules)
    graph: Dict[str, List[str]] = {}
    in_degree: Dict[str, int] = {}
    for m in modules:
        deps = [d for d in MODULE_DEPENDENCIES.get(m, []) if d in available]
        graph[m] = deps
        in_degree[m] = len(deps)

    # Kahn's algorithm
    queue = [m for m in modules if in_degree[m] == 0]
    groups: List[List[str]] = []

    while queue:
        groups.append(sorted(queue))  # deterministic ordering within a group
        next_queue: List[str] = []
        for m in queue:
            for dependent in modules:
                if m in graph.get(dependent, []):
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        next_queue.append(dependent)
        queue = next_queue

    # Check for cycles
    processed = set(m for g in groups for m in g)
    if processed != available:
        cycle = available - processed
        raise ValueError(
            f"Circular dependency detected among modules: {', '.join(sorted(cycle))}"
        )

    return groups


def visualize_dependencies(modules: Optional[List[str]] = None) -> str:
    """Return a text-art dependency graph.

    If *modules* is ``None``, all known modules are shown.
    """
    if modules is None:
        modules = sorted(MODULE_DEPENDENCIES.keys())

    lines: List[str] = []
    lines.append("Module Dependency Graph")
    lines.append("=" * 50)

    for m in modules:
        deps = MODULE_DEPENDENCIES.get(m, [])
        if not deps:
            lines.append(f"  {m}")
        else:
            lines.append(f"  {m}")
            for d in deps:
                lines.append(f"    └── {d}")

    lines.append("")

    # Execution order
    try:
        order = get_execution_order(modules)
        lines.append("Execution Order (parallel groups):")
        lines.append("-" * 50)
        for i, group in enumerate(order):
            label = " (can run in parallel)" if len(group) > 1 else ""
            lines.append(f"  Wave {i + 1}: {', '.join(group)}{label}")
    except ValueError as e:
        lines.append(f"  ERROR: {e}")

    return "\n".join(lines)

