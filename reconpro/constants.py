"""ReconPro v11 — Central Constants.

Single source of truth for severity orderings, colors, thresholds,
version strings, and shared magic numbers. Every module imports from here.

THIS FILE IS THE CANONICAL DEFINITION. Do NOT duplicate these values elsewhere.
"""

from __future__ import annotations

# ── Version ───────────────────────────────────────────────────────────
__version__ = "11.1.0"

# ── Severity System ────────────────────────────────────────────────────
# Canonical ordering: lower numeric value = higher severity
SEVERITY_LEVELS: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
VALID_SEVERITIES: frozenset[str] = frozenset(SEVERITY_LEVELS.keys())

# Sort key function for findings
# DEAD CODE: consider removal
def severity_sort_key(severity: str) -> int:
    """Return sort key for severity (lower = more severe)."""
    return SEVERITY_LEVELS.get(severity.lower(), 99)


# ── Grade System ────────────────────────────────────────────────────────
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A+"),
    (80, "A"),
    (65, "B"),
    (50, "C"),
    (35, "D"),
    (0,  "F"),
]
VALID_GRADES: frozenset[str] = frozenset(g for _, g in GRADE_THRESHOLDS)


# ── CLI Colors (Rich console) ──────────────────────────────────────────
SEV_COLORS: dict[str, str] = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}

GRADE_COLORS: dict[str, str] = {
    "A+": "bright_green",
    "A": "green",
    "B": "yellow",
    "C": "red",
    "D": "bright_red",
    "F": "bold bright_red",
}


# ── SARIF Severity Mapping ─────────────────────────────────────────────
SARIF_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


# ── Badge Color Map ─────────────────────────────────────────────────────
BADGE_COLOR_MAP: dict[str, str] = {
    "A+": "brightgreen", "A": "green", "B": "yellow",
    "C": "red", "D": "orange", "F": "red",
}


# ── Network Defaults ───────────────────────────────────────────────────
DEFAULT_TIMEOUT: int = 8
DEFAULT_RATE_LIMIT: float = 10.0
DEFAULT_BODY_LIMIT: int = 16384  # 16 KB
DEFAULT_MAX_WORKERS: int = 4

# User-Agent string
USER_AGENT: str = (
    "ReconPro/11.1.0 (Enterprise Security Scanner; "
    "+https://github.com/falconxa0-commits/reconpro)"
)


# ── DREAD Score Defaults ───────────────────────────────────────────────
DREAD_SCORE_MAP: dict[str, float] = {
    "critical": 0.9,
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3,
    "info": 0.1,
}


# ── Scoring Constants ────────────────────────────────────────────────────
MAX_SCORE: int = 100
MIN_SCORE: int = 0


# ── Paths ───────────────────────────────────────────────────────────────
from pathlib import Path

RECONPRO_HOME: Path = Path.home() / ".reconpro"
SCAN_HISTORY_DIR: Path = RECONPRO_HOME / "scans"
PLUGIN_DIR: Path = RECONPRO_HOME / "plugins"
MEMORY_DIR: Path = RECONPRO_HOME / "memory"
KNOWLEDGE_GRAPH_FILE: Path = MEMORY_DIR / "graph.json"
PLUGIN_HOOKS_FILE: Path = PLUGIN_DIR / "_hooks.json"
TOOLS_DIR: Path = RECONPRO_HOME / "tools"
