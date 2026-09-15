"""ReconPro v11 — Quality Intelligence System.

Provides intelligent, multi-dimensional code quality analysis for the
ReconPro codebase. Uses the stdlib ``ast`` module for static analysis —
zero external dependencies.

Classes:
    QualityDimension   — Score for a single quality dimension (0-100)
    QualityTrend      — Historical quality tracking with regression detection
    QualityGate       — Threshold-based quality gatekeeper
    QualityIntelligence — Main orchestrator for comprehensive quality analysis

Storage:
    Snapshots are persisted at RECONPRO_HOME/memory/quality_snapshots.json
    Gate history at   RECONPRO_HOME/memory/quality_gate_history.json

NOTE: This module analyses *source-code quality*, NOT scan findings.
      Cross-validation of scan results lives in cross_validator.py.
"""
from __future__ import annotations

import ast
import json
import logging
import math
import os
import re
import tokenize
import io
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .constants import (
    GRADE_THRESHOLDS,
    MAX_SCORE,
    MIN_SCORE,
    RECONPRO_HOME,
    SEVERITY_LEVELS,
    VALID_GRADES,
    VALID_SEVERITIES,
    MEMORY_DIR,
)

logger = logging.getLogger(__name__)

# ── Snapshot / gate persistence paths ──────────────────────────────────
SNAPSHOTS_FILE: Path = MEMORY_DIR / "quality_snapshots.json"
GATE_HISTORY_FILE: Path = MEMORY_DIR / "quality_gate_history.json"

# ── Default dimension weights for composite scoring ─────────────────────
DEFAULT_DIMENSION_WEIGHTS: Dict[str, float] = {
    "complexity": 0.12,
    "coverage": 0.18,
    "type_safety": 0.12,
    "documentation": 0.14,
    "security": 0.15,
    "maintainability": 0.12,
    "reliability": 0.10,
    "consistency": 0.07,
}

# ── Security anti-patterns detected via AST/string analysis ─────────────
_SECURITY_ANTI_PATTERNS: List[Tuple[str, str]] = [
    # (regex_pattern, description)
    (r"\beval\s*\(", "use of eval()"),
    (r"\bexec\s*\(", "use of exec()"),
    (r"\bcompile\s*\([^)]*['\"]exec['\"]", "compile with exec mode"),
    (r"\b__import__\s*\(", "dynamic import via __import__"),
    (r"\bpickle\.loads?\s*\(", "pickle deserialization (unsafe)"),
    (r"\bmarshal\.loads?\s*\(", "marshal deserialization (unsafe)"),
    (r"\bsubprocess\.[Cc]all\s*\([^)]*shell\s*=\s*True", "shell=True in subprocess"),
    (r"\bos\.system\s*\(", "os.system() command injection risk"),
    (r"\byaml\.load\s*\([^)]*\)", "yaml.load without Loader (unsafe)"),
    (r"\bhasattr\s*\(.*__\w+__\s*,", "attribute name introspection"),
    (r"\bgetattr\s*\([^)]*__\w+__\s*,", "dunder attribute access"),
    (r"\bssl\._create_unverified_context\s*\(", "SSL verification disabled"),
    (r"verify\s*=\s*False", "certificate verification disabled"),
    (r"check_hostname\s*=\s*False", "hostname verification disabled"),
    (r"\bhashlib\.md5\s*\(", "weak hash algorithm (MD5)"),
    (r"\bhashlib\.sha1\s*\(", "weak hash algorithm (SHA1)"),
    (r"\btempfile\.mktemp\s*\(", "mktemp is insecure (race condition)"),
    (r"# noqa", "noqa comment (suppressed linting)"),
    (r"# type:\s*ignore", "type: ignore comment"),
    (r"\.except.*:\s*$", "bare or overly broad except"),
    (r"\bpass\s*$", "bare pass (possible stub)"),
]

# ── Naming conventions ─────────────────────────────────────────────────
_NAMING_PATTERNS: Dict[str, re.Pattern[str]] = {
    "function": re.compile(r"^[a-z_][a-z0-9_]*$"),
    "class": re.compile(r"^[A-Z][a-zA-Z0-9]*$"),
    "constant": re.compile(r"^[A-Z_][A-Z0-9_]*$"),
    "private_method": re.compile(r"^_[a-z_][a-z0-9_]*$"),
    "dunder_method": re.compile(r"^__[a-z_][a-z0-9_]*__$"),
}


# ════════════════════════════════════════════════════════════════════════
# QualityDimension — Single dimension score
# ════════════════════════════════════════════════════════════════════════


@dataclass
class QualityDimension:
    """Score and metadata for a single quality dimension.

    Attributes:
        name:        Dimension identifier (e.g. "complexity").
        score:       Normalised score 0-100 (higher is better).
        weight:      Weight in composite calculation (0.0-1.0).
        severity:    ReconPro severity level (from constants.py).
        grade:       ReconPro letter grade (from constants.py).
        details:     Human-readable explanation / metric breakdown.
        metrics:     Raw metric values for this dimension.
    """

    name: str
    score: float = 0.0
    weight: float = 0.0
    severity: str = "info"
    grade: str = "F"
    details: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 1),
            "weight": self.weight,
            "severity": self.severity,
            "grade": self.grade,
            "details": self.details,
            "metrics": self.metrics,
        }


# ════════════════════════════════════════════════════════════════════════
# QualityTrend — Historical tracking
# ════════════════════════════════════════════════════════════════════════


@dataclass
class QualitySnapshot:
    """A single quality snapshot at a point in time."""

    timestamp: str
    composite_score: float
    dimensions: Dict[str, float]
    file_count: int
    total_loc: int
    repository_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "composite_score": round(self.composite_score, 1),
            "dimensions": {k: round(v, 1) for k, v in self.dimensions.items()},
            "file_count": self.file_count,
            "total_loc": self.total_loc,
            "repository_path": self.repository_path,
        }


class QualityTrend:
    """Track quality over time, detect regressions, project trajectory.

    Snapshots are persisted at RECONPRO_HOME/memory/quality_snapshots.json.
    """

    MAX_SNAPSHOTS: int = 500

    def __init__(self) -> None:
        self._snapshots: List[QualitySnapshot] = []
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load snapshots from disk."""
        try:
            if SNAPSHOTS_FILE.exists():
                raw = json.loads(SNAPSHOTS_FILE.read_text(encoding="utf-8"))
                for entry in raw:
                    self._snapshots.append(QualitySnapshot(
                        timestamp=entry["timestamp"],
                        composite_score=entry["composite_score"],
                        dimensions=entry.get("dimensions", {}),
                        file_count=entry.get("file_count", 0),
                        total_loc=entry.get("total_loc", 0),
                        repository_path=entry.get("repository_path", ""),
                    ))
                logger.debug("Loaded %d quality snapshots", len(self._snapshots))
        except Exception as exc:
            logger.warning("Failed to load quality snapshots: %s", exc)
            self._snapshots = []

    def _save(self) -> None:
        """Persist snapshots to disk."""
        try:
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            data = [s.to_dict() for s in self._snapshots]
            SNAPSHOTS_FILE.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
            logger.debug("Saved %d quality snapshots", len(self._snapshots))
        except Exception as exc:
            logger.error("Failed to save quality snapshots: %s", exc)

    # ── Public API ───────────────────────────────────────────────────────

    def record_snapshot(
        self,
        composite_score: float,
        dimensions: Dict[str, float],
        file_count: int = 0,
        total_loc: int = 0,
        repository_path: str = "",
    ) -> QualitySnapshot:
        """Record a new quality snapshot and persist it.

        Returns the created snapshot.
        """
        snapshot = QualitySnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            composite_score=composite_score,
            dimensions=dict(dimensions),
            file_count=file_count,
            total_loc=total_loc,
            repository_path=repository_path,
        )
        self._snapshots.append(snapshot)

        # Trim to MAX_SNAPSHOTS
        if len(self._snapshots) > self.MAX_SNAPSHOTS:
            self._snapshots = self._snapshots[-self.MAX_SNAPSHOTS:]

        self._save()
        return snapshot

    def get_snapshots(self) -> List[QualitySnapshot]:
        """Return all recorded snapshots (newest last)."""
        return list(self._snapshots)

    def get_latest(self) -> Optional[QualitySnapshot]:
        """Return the most recent snapshot, or None."""
        return self._snapshots[-1] if self._snapshots else None

    def compare_with_previous(self) -> Optional[Dict[str, Any]]:
        """Compare the latest snapshot against the previous one.

        Returns a dict with delta information, or None if fewer than 2
        snapshots exist.
        """
        if len(self._snapshots) < 2:
            return None

        current = self._snapshots[-1]
        previous = self._snapshots[-2]

        score_delta = current.composite_score - previous.composite_score

        # Per-dimension deltas
        dim_deltas: Dict[str, float] = {}
        all_dims = set(previous.dimensions) | set(current.dimensions)
        for dim in sorted(all_dims):
            prev_val = previous.dimensions.get(dim, 0.0)
            curr_val = current.dimensions.get(dim, 0.0)
            dim_deltas[dim] = round(curr_val - prev_val, 1)

        # Identify regressions (any dimension dropped by > 5 points)
        regressions = [
            dim for dim, delta in dim_deltas.items() if delta < -5.0
        ]
        improvements = [
            dim for dim, delta in dim_deltas.items() if delta > 5.0
        ]

        direction = "improving" if score_delta > 2 else (
            "regressing" if score_delta < -2 else "stable"
        )

        return {
            "current_timestamp": current.timestamp,
            "previous_timestamp": previous.timestamp,
            "score_delta": round(score_delta, 1),
            "direction": direction,
            "dimension_deltas": dim_deltas,
            "regressions": regressions,
            "improvements": improvements,
        }

    def detect_regressions(self, threshold: float = 5.0) -> List[Dict[str, Any]]:
        """Scan all snapshot pairs for regressions exceeding *threshold*.

        Returns a list of regression events.
        """
        regressions: List[Dict[str, Any]] = []
        for i in range(1, len(self._snapshots)):
            prev = self._snapshots[i - 1]
            curr = self._snapshots[i]
            delta = curr.composite_score - prev.composite_score
            if delta < -threshold:
                # Find which dimensions regressed
                dim_regs = []
                all_dims = set(prev.dimensions) | set(curr.dimensions)
                for dim in sorted(all_dims):
                    d = curr.dimensions.get(dim, 0.0) - prev.dimensions.get(dim, 0.0)
                    if d < -threshold:
                        dim_regs.append({
                            "dimension": dim,
                            "before": round(prev.dimensions.get(dim, 0.0), 1),
                            "after": round(curr.dimensions.get(dim, 0.0), 1),
                            "delta": round(d, 1),
                        })
                regressions.append({
                    "from_timestamp": prev.timestamp,
                    "to_timestamp": curr.timestamp,
                    "score_delta": round(delta, 1),
                    "regressed_dimensions": dim_regs,
                })
        return regressions

    def project_trajectory(self, snapshots_ahead: int = 5) -> Optional[Dict[str, Any]]:
        """Simple linear regression to project quality trajectory.

        Returns projection data or None if fewer than 3 snapshots exist.
        """
        if len(self._snapshots) < 3:
            return None

        scores = [s.composite_score for s in self._snapshots]
        n = len(scores)

        # Linear regression: y = mx + b
        x_vals = list(range(n))
        x_mean = sum(x_vals) / n
        y_mean = sum(scores) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, scores))
        denominator = sum((x - x_mean) ** 2 for x in x_vals)

        if denominator == 0:
            return None

        slope = numerator / denominator
        intercept = y_mean - slope * x_mean

        # Project forward
        projected: List[float] = []
        for i in range(n, n + snapshots_ahead):
            proj = intercept + slope * i
            projected.append(round(max(0.0, min(100.0, proj)), 1))

        # Trend description
        if slope > 0.5:
            trend = "improving"
        elif slope < -0.5:
            trend = "declining"
        else:
            trend = "stable"

        return {
            "slope": round(slope, 3),
            "intercept": round(intercept, 1),
            "trend": trend,
            "projected_scores": projected,
            "current_score": round(scores[-1], 1),
            "data_points": n,
        }


# ════════════════════════════════════════════════════════════════════════
# QualityGate — Threshold gatekeeper
# ════════════════════════════════════════════════════════════════════════


@dataclass
class GateResult:
    """Result of evaluating a quality gate."""

    gate_name: str
    passed: bool
    timestamp: str
    score: float
    threshold: float
    failures: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_name": self.gate_name,
            "passed": self.passed,
            "timestamp": self.timestamp,
            "score": self.score,
            "threshold": self.threshold,
            "failures": self.failures,
            "actions_taken": self.actions_taken,
        }


class QualityGate:
    """Gatekeeper for quality thresholds.

    Gates are defined with per-dimension minimums and optional actions
    (callables) triggered on failure.
    """

    def __init__(self, load_history: bool = False) -> None:
        self._gates: Dict[str, Dict[str, Any]] = {}
        # Hermetic by default: history starts empty and is never seeded
        # from disk (auto-loading leaked cross-run state into fresh
        # instances).  Pass load_history=True to opt in to reading the
        # on-disk archive (e.g. for cross-session dashboards); every
        # instance still APPENDS to the archive via _save_history.
        self._history: List[GateResult] = []
        if load_history:
            self._load_history_from_disk()

    # ── Persistence ──────────────────────────────────────────────────────

    def _load_history(self) -> None:
        """Load gate history from disk."""
        try:
            if GATE_HISTORY_FILE.exists():
                raw = json.loads(GATE_HISTORY_FILE.read_text(encoding="utf-8"))
                for entry in raw:
                    self._history.append(GateResult(
                        gate_name=entry["gate_name"],
                        passed=entry["passed"],
                        timestamp=entry["timestamp"],
                        score=entry.get("score", 0.0),
                        threshold=entry.get("threshold", 0.0),
                        failures=entry.get("failures", []),
                        actions_taken=entry.get("actions_taken", []),
                    ))
        except Exception as exc:
            logger.warning("Failed to load gate history: %s", exc)
            self._history = []

    def _load_history_from_disk(self) -> None:
        """Opt-in: seed session history from the on-disk archive."""
        try:
            if GATE_HISTORY_FILE.exists():
                raw = json.loads(GATE_HISTORY_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    for entry in raw:
                        self._history.append(GateResult(
                            gate_name=entry.get("gate_name", "?"),
                            passed=entry.get("passed", False),
                            timestamp=entry.get("timestamp", ""),
                            score=entry.get("score", 0.0),
                            threshold=entry.get("threshold", 0.0),
                            failures=entry.get("failures", []),
                            actions_taken=entry.get("actions_taken", []),
                        ))
        except Exception as exc:
            logger.warning("Failed to load gate history: %s", exc)
            self._history = []

    def _save_history(self) -> None:
        """Append this session's gate results to the on-disk archive."""
        try:
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            archive: list = []
            if GATE_HISTORY_FILE.exists():
                try:
                    archive = json.loads(GATE_HISTORY_FILE.read_text(encoding="utf-8"))
                    if not isinstance(archive, list):
                        archive = []
                except (json.JSONDecodeError, OSError):
                    archive = []
            archive.extend(r.to_dict() for r in self._history)
            GATE_HISTORY_FILE.write_text(
                json.dumps(archive[-1000:], indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed to save gate history: %s", exc)

    # ── Public API ───────────────────────────────────────────────────────

    def define_gate(
        self,
        name: str,
        thresholds: Dict[str, float],
        actions: Optional[List[Callable[[], None]]] = None,
    ) -> None:
        """Define a quality gate.

        Args:
            name:        Unique gate identifier.
            thresholds:  Dict mapping dimension name to minimum score.
                         Use "_composite" for the overall score threshold.
            actions:      Optional list of callables invoked on gate failure.
        """
        self._gates[name] = {
            "thresholds": dict(thresholds),
            "actions": actions or [],
        }
        logger.info("Defined quality gate '%s' with %d thresholds", name, len(thresholds))

    def evaluate(
        self,
        gate_name: str,
        quality_data: Dict[str, Any],
    ) -> GateResult:
        """Evaluate a named gate against quality data.

        Args:
            gate_name:    Name of a previously defined gate.
            quality_data: Dict with "composite_score" (float) and
                          "dimensions" (dict of dimension_name -> score).

        Returns:
            GateResult with pass/fail status and failure details.
        """
        if gate_name not in self._gates:
            logger.warning("Gate '%s' not defined, auto-passing", gate_name)
            result = GateResult(
                gate_name=gate_name,
                passed=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                score=quality_data.get("composite_score", 0.0),
                threshold=0.0,
                failures=[{"dimension": "_gate_not_found", "message": f"Gate '{gate_name}' is not defined"}],
            )
            self._history.append(result)
            self._save_history()
            return result

        gate_def = self._gates[gate_name]
        thresholds = gate_def["thresholds"]
        actions = gate_def["actions"]

        composite_score = quality_data.get("composite_score", 0.0)
        dimensions = quality_data.get("dimensions", {})

        failures: List[Dict[str, Any]] = []
        composite_threshold = thresholds.get("_composite", 0.0)

        # Check composite threshold
        if composite_threshold > 0 and composite_score < composite_threshold:
            failures.append({
                "dimension": "_composite",
                "message": f"Composite score {composite_score:.1f} below threshold {composite_threshold:.1f}",
                "actual": round(composite_score, 1),
                "required": composite_threshold,
            })

        # Check per-dimension thresholds
        for dim_name, min_score in thresholds.items():
            if dim_name == "_composite":
                continue
            actual = dimensions.get(dim_name, 0.0)
            if actual < min_score:
                failures.append({
                    "dimension": dim_name,
                    "message": f"{dim_name} score {actual:.1f} below threshold {min_score:.1f}",
                    "actual": round(actual, 1),
                    "required": min_score,
                })

        passed = len(failures) == 0

        # Execute failure actions
        actions_taken: List[str] = []
        if not passed and actions:
            for action in actions:
                try:
                    action()
                    actions_taken.append(action.__name__)
                except Exception as exc:
                    actions_taken.append(f"{action.__name__} (failed: {exc})")
                    logger.error("Gate action %s failed: %s", action.__name__, exc)

        result = GateResult(
            gate_name=gate_name,
            passed=passed,
            timestamp=datetime.now(timezone.utc).isoformat(),
            score=composite_score,
            threshold=composite_threshold,
            failures=failures,
            actions_taken=actions_taken,
        )

        self._history.append(result)
        self._save_history()

        status = "PASSED" if passed else "FAILED"
        logger.info(
            "Gate '%s' %s (score=%.1f, threshold=%.1f)",
            gate_name, status, composite_score, composite_threshold,
        )
        return result

    def get_gate_history(self, gate_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return gate evaluation history, optionally filtered by name."""
        results = self._history
        if gate_name is not None:
            results = [r for r in results if r.gate_name == gate_name]
        return [r.to_dict() for r in results]

    def get_gate_pass_rate(self, gate_name: Optional[str] = None) -> float:
        """Return pass rate as a fraction (0.0-1.0)."""
        results = self._history
        if gate_name is not None:
            results = [r for r in results if r.gate_name == gate_name]
        if not results:
            return 0.0
        return sum(1 for r in results if r.passed) / len(results)


# ════════════════════════════════════════════════════════════════════════
# AST Analysis Helpers
# ════════════════════════════════════════════════════════════════════════


def _parse_file_safe(file_path: str) -> Optional[ast.AST]:
    """Parse a Python file, returning None on any error."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        return ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, OSError) as exc:
        logger.debug("Cannot parse %s: %s", file_path, exc)
        return None


class _ASTAnalyzer(ast.NodeVisitor):
    """Collects code metrics from an AST tree."""

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.total_loc: int = len(source_lines)
        self.blank_lines: int = 0
        self.comment_lines: int = 0
        self.functions: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.imports: List[str] = []
        self.max_nesting_depth: int = 0
        self.total_branches: int = 0
        self.has_type_hints: int = 0
        self.total_params: int = 0
        self.docstring_count: int = 0
        self.docstring_targets: int = 0
        self.except_handlers: int = 0
        self.bare_except_handlers: int = 0
        self.try_blocks: int = 0
        self.security_issues: List[Dict[str, Any]] = []
        self.naming_violations: List[Dict[str, Any]] = []
        self._current_depth: int = 0

        # Count blanks and comments
        for line in source_lines:
            stripped = line.strip()
            if not stripped:
                self.blank_lines += 1
            elif stripped.startswith("#"):
                self.comment_lines += 1

    # ── Visitors ─────────────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.AST) -> None:  # type: ignore[override]
        self._analyse_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AST) -> None:  # type: ignore[override]
        self._analyse_function(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.AST) -> None:  # type: ignore[override]
        name = getattr(node, "name", "")
        bases = [getattr(b, "id", "") if isinstance(b, ast.Name) else "" for b in getattr(node, "bases", [])]
        docstring = ast.get_docstring(node)
        has_doc = docstring is not None

        # Check class naming
        if name and not _NAMING_PATTERNS["class"].match(name) and not name.startswith("_"):
            self.naming_violations.append({
                "name": name, "kind": "class", "line": getattr(node, "lineno", 0),
            })

        self.classes.append({
            "name": name,
            "bases": bases,
            "has_docstring": has_doc,
            "line": getattr(node, "lineno", 0),
            "end_line": getattr(node, "end_lineno", 0),
        })
        if has_doc:
            self.docstring_count += 1
        self.docstring_targets += 1

        self.generic_visit(node)

    def visit_Import(self, node: ast.AST) -> None:  # type: ignore[override]
        for alias in getattr(node, "names", []):
            self.imports.append(getattr(alias, "name", ""))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.AST) -> None:  # type: ignore[override]
        module = getattr(node, "module", "") or ""
        for alias in getattr(node, "names", []):
            self.imports.append(f"{module}.{getattr(alias, 'name', '')}")
        self.generic_visit(node)

    def visit_If(self, node: ast.AST) -> None:  # type: ignore[override]
        self.total_branches += 1
        self._current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self._current_depth)
        self.generic_visit(node)
        self._current_depth -= 1

    def visit_For(self, node: ast.AST) -> None:  # type: ignore[override]
        self.total_branches += 1
        self._current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self._current_depth)
        self.generic_visit(node)
        self._current_depth -= 1

    def visit_While(self, node: ast.AST) -> None:  # type: ignore[override]
        self.total_branches += 1
        self._current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self._current_depth)
        self.generic_visit(node)
        self._current_depth -= 1

    def visit_With(self, node: ast.AST) -> None:  # type: ignore[override]
        self.total_branches += 1
        self._current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self._current_depth)
        self.generic_visit(node)
        self._current_depth -= 1

    def visit_Try(self, node: ast.AST) -> None:  # type: ignore[override]
        self.try_blocks += 1
        for handler in getattr(node, "handlers", []):
            self.except_handlers += 1
            exc_type = getattr(handler, "type", None)
            if exc_type is None:
                self.bare_except_handlers += 1
        self.generic_visit(node)

    # ── Helpers ──────────────────────────────────────────────────────────

    def _analyse_function(self, node: ast.AST) -> None:
        """Analyse a function/method node."""
        name = getattr(node, "name", "")
        args = getattr(node, "args", None)
        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", 0)
        func_loc = max(1, (end_lineno or lineno) - lineno + 1)
        docstring = ast.get_docstring(node)
        has_doc = docstring is not None

        # Parameter analysis
        param_count = 0
        hinted_params = 0
        returns_hinted = False

        if args:
            all_args = (
                list(getattr(args, "posonlyargs", [])) +
                list(getattr(args, "args", [])) +
                list(getattr(args, "kwonlyargs", []))
            )
            param_count = len(all_args)
            for arg in all_args:
                if getattr(arg, "annotation", None) is not None:
                    hinted_params += 1
            if getattr(args, "vararg", None) and getattr(args.vararg, "annotation", None):
                hinted_params += 1
                param_count += 1
            if getattr(args, "kwarg", None) and getattr(args.kwarg, "annotation", None):
                hinted_params += 1
                param_count += 1

        self.total_params += param_count
        self.has_type_hints += hinted_params

        if getattr(node, "returns", None) is not None:
            returns_hinted = True

        # Count nested branches
        branch_count = 0
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                branch_count += 1

        # Check naming (skip dunder methods and private)
        if (
            name
            and not name.startswith("__")
            and not name.startswith("_")
            and not _NAMING_PATTERNS["function"].match(name)
        ):
            self.naming_violations.append({
                "name": name, "kind": "function", "line": lineno,
            })

        self.functions.append({
            "name": name,
            "loc": func_loc,
            "params": param_count,
            "hinted_params": hinted_params,
            "returns_hinted": returns_hinted,
            "has_docstring": has_doc,
            "branches": branch_count,
            "line": lineno,
        })

        if has_doc:
            self.docstring_count += 1
        self.docstring_targets += 1


def _scan_security_patterns(source: str) -> List[Dict[str, Any]]:
    """Scan source text for security anti-patterns."""
    issues: List[Dict[str, Any]] = []
    for line_no, line in enumerate(source.splitlines(), 1):
        for pattern, description in _SECURITY_ANTI_PATTERNS:
            if re.search(pattern, line):
                issues.append({
                    "line": line_no,
                    "pattern": description,
                    "snippet": line.strip()[:100],
                })
    return issues


def _estimate_test_coverage(source_lines: List[str]) -> Dict[str, Any]:
    """Estimate test coverage heuristically from test file content.

    This is NOT an actual coverage measurement — it estimates the
    *quality* of test files (assertions per function, etc.).
    """
    total_lines = len(source_lines)
    if total_lines == 0:
        return {"assert_count": 0, "test_function_count": 0, "mock_count": 0, "asserts_per_test": 0.0, "quality_estimate": 0.0}

    assert_count = sum(1 for line in source_lines if re.search(r"\bassert\b", line))
    test_funcs = sum(1 for line in source_lines if re.search(r"\bdef\s+test_", line))
    mock_count = sum(1 for line in source_lines if re.search(r"\b(mock|patch|MagicMock)\b", line))

    # Heuristic: quality based on asserts-per-test-function ratio
    if test_funcs > 0:
        asserts_per_test = assert_count / test_funcs
    else:
        asserts_per_test = 0.0

    # Score: more asserts per test, more mocks = better
    quality = min(100.0, asserts_per_test * 15 + mock_count * 2)
    quality = max(0.0, quality)

    return {
        "assert_count": assert_count,
        "test_function_count": test_funcs,
        "mock_count": mock_count,
        "asserts_per_test": round(asserts_per_test, 2),
        "quality_estimate": round(quality, 1),
    }


def _compute_maintainability_index(
    total_loc: int,
    comment_lines: int,
    blank_lines: int,
    max_nesting: int,
    avg_func_loc: float,
) -> float:
    """Compute a maintainability index (0-100).

    Inspired by the original Maintainability Index formula but
    adapted for simplicity and stdlib-only operation.
    """
    if total_loc == 0:
        return 100.0

    code_loc = max(1, total_loc - comment_lines - blank_lines)
    comment_ratio = comment_lines / total_loc

    # Penalise long functions
    func_length_penalty = max(0.0, (avg_func_loc - 30) / 70) * 30  # 30 LOC is ideal

    # Penalise deep nesting
    nesting_penalty = max(0.0, (max_nesting - 3) / 7) * 25  # 3 levels is ideal

    # Reward comments
    comment_bonus = comment_ratio * 20

    raw = 100.0 - func_length_penalty - nesting_penalty + comment_bonus
    return max(0.0, min(100.0, round(raw, 1)))


def _assign_severity(score: float) -> str:
    """Map a quality score (0-100) to a ReconPro severity."""
    if score >= 80:
        return "low"
    elif score >= 60:
        return "medium"
    elif score >= 40:
        return "high"
    return "critical"


def _assign_grade(score: float) -> str:
    """Map a quality score (0-100) to a ReconPro grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _assign_dimension_grade(score: float) -> str:
    """Stricter grade thresholds for individual dimensions."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


# ════════════════════════════════════════════════════════════════════════
# QualityIntelligence — Main orchestrator
# ════════════════════════════════════════════════════════════════════════


class QualityIntelligence:
    """Comprehensive quality analysis for Python source code.

    Usage:
        qi = QualityIntelligence()

        # Analyse a single file
        result = qi.analyze_code_quality("/path/to/file.py")

        # Analyse entire repository
        repo_result = qi.analyze_repository_quality("/path/to/repo")

        # Get composite score
        print(qi.get_quality_score())

        # Get formatted report
        print(qi.get_quality_report())
    """

    def __init__(
        self,
        repository_path: Optional[str] = None,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self._repo_path = repository_path
        self._weights = dict(weights or DEFAULT_DIMENSION_WEIGHTS)
        self._dimensions: Dict[str, QualityDimension] = {}
        self._file_analyses: Dict[str, Dict[str, Any]] = {}
        self._composite_score: float = 0.0
        self._thresholds: Dict[str, float] = {
            "_composite": 60.0,  # Default: reject below 60
        }
        self._trend = QualityTrend()
        self._gate = QualityGate()
        self._total_files: int = 0
        self._total_loc: int = 0

        # Define a default "release" gate
        self._gate.define_gate(
            "release_ready",
            {"_composite": 60.0, "security": 50.0, "reliability": 40.0},
        )

    # ── Public API ───────────────────────────────────────────────────────

    def analyze_code_quality(self, file_path: str) -> Dict[str, Any]:
        """Analyse a single file's quality.

        Returns a dict with per-dimension scores and file-level metrics.
        """
        file_path = os.path.abspath(file_path)
        logger.info("Analysing code quality: %s", file_path)

        # Read source
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except OSError as exc:
            logger.error("Cannot read %s: %s", file_path, exc)
            return {
                "file": file_path,
                "error": f"Cannot read file: {exc}",
                "dimensions": {},
            }

        source_lines = source.splitlines()
        tree = _parse_file_safe(file_path)

        if tree is None:
            # Can't parse — give minimal analysis
            return {
                "file": file_path,
                "loc": len(source_lines),
                "error": "Failed to parse file (syntax error)",
                "dimensions": {},
                "overall_score": 0.0,
            }

        # Run AST analyser
        analyser = _ASTAnalyzer(source_lines)
        analyser.visit(tree)

        # Security pattern scan
        security_issues = _scan_security_patterns(source)

        # Is this a test file? (check filename and immediate parent dir only)
        path_obj = Path(file_path)
        is_test = (
            path_obj.name.startswith("test_")
            or path_obj.name.endswith("_test.py")
            or path_obj.parent.name == "tests"
            or path_obj.parent.name == "test"
        )

        # Compute dimension scores
        dimensions = self._compute_dimensions(
            analyser, security_issues, is_test, source
        )

        # Store
        self._file_analyses[file_path] = {
            "dimensions": {k: v.to_dict() for k, v in dimensions.items()},
            "analyzer": analyser,
            "security_issues": security_issues,
            "loc": len(source_lines),
        }

        # An empty file has no measurable quality — scoring "dimensions"
        # against zero code would inflate the result (91/100 for 0 LOC).
        if not source_lines or not source.strip():
            overall = 0.0
        else:
            overall = round(self._weighted_score(dimensions), 1)

        return {
            "file": file_path,
            "loc": len(source_lines),
            "overall_score": overall,
            "dimensions": {k: v.to_dict() for k, v in dimensions.items()},
            "security_issues": security_issues,
            "functions": len(analyser.functions),
            "classes": len(analyser.classes),
        }

    def analyze_repository_quality(
        self,
        repository_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyse all Python files in a repository.

        Args:
            repository_path: Root directory. Defaults to the path
                             provided at construction time.

        Returns:
            Repository-level quality analysis dict.
        """
        repo = repository_path or self._repo_path
        if not repo:
            logger.error("No repository path specified")
            return {"error": "No repository path specified", "dimensions": {}}

        repo = os.path.abspath(repo)
        logger.info("Analysing repository quality: %s", repo)

        # Collect all Python files
        py_files: List[str] = []
        for root, _dirs, files in os.walk(repo):
            # Skip hidden directories, __pycache__, .git, etc.
            skip_parts = {"__pycache__", ".git", ".tox", ".eggs", "node_modules", ".venv", "venv"}
            if any(part in skip_parts for part in Path(root).parts):
                continue
            for fname in sorted(files):
                if fname.endswith(".py"):
                    py_files.append(os.path.join(root, fname))

        if not py_files:
            return {"error": "No Python files found", "dimensions": {}}

        # Aggregate metrics across all files
        aggregate = _ASTAnalyzer([])
        total_security_issues: List[Dict[str, Any]] = []
        all_dimensions: List[Dict[str, QualityDimension]] = []
        total_loc = 0
        file_count = 0

        for fpath in py_files:
            result = self.analyze_code_quality(fpath)
            if "error" in result and "dimensions" not in result:
                continue
            if not result.get("dimensions"):
                continue

            file_count += 1
            total_loc += result.get("loc", 0)
            total_security_issues.extend(result.get("security_issues", []))

            # Reconstruct dimensions for aggregation
            file_dims: Dict[str, QualityDimension] = {}
            for dim_name, dim_data in result.get("dimensions", {}).items():
                file_dims[dim_name] = QualityDimension(
                    name=dim_name,
                    score=dim_data["score"],
                    weight=dim_data["weight"],
                    metrics=dim_data.get("metrics", {}),
                )
            all_dimensions.append(file_dims)

        # Compute aggregate dimensions
        agg_dimensions = self._aggregate_dimensions(all_dimensions)
        self._dimensions = agg_dimensions
        self._total_files = file_count
        self._total_loc = total_loc

        # Compute composite
        self._composite_score = self._weighted_score(agg_dimensions)

        # Record snapshot
        dim_scores = {k: v.score for k, v in agg_dimensions.items()}
        self._trend.record_snapshot(
            composite_score=self._composite_score,
            dimensions=dim_scores,
            file_count=file_count,
            total_loc=total_loc,
            repository_path=repo,
        )

        # Evaluate default gate
        gate_result = self._gate.evaluate(
            "release_ready",
            {"composite_score": self._composite_score, "dimensions": dim_scores},
        )

        # Trend analysis
        comparison = self._trend.compare_with_previous()
        trajectory = self._trend.project_trajectory()

        return {
            "repository": repo,
            "file_count": file_count,
            "total_loc": total_loc,
            "composite_score": round(self._composite_score, 1),
            "grade": _assign_grade(self._composite_score),
            "dimensions": {k: v.to_dict() for k, v in agg_dimensions.items()},
            "security_issues_total": len(total_security_issues),
            "security_issues_sample": total_security_issues[:20],
            "gate_result": gate_result.to_dict(),
            "trend": comparison,
            "trajectory": trajectory,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_quality_score(self) -> float:
        """Return the current composite quality score (0-100).

        If no analysis has been run yet, returns 0.0.
        """
        return round(self._composite_score, 1)

    def get_quality_dimensions(self) -> Dict[str, Dict[str, Any]]:
        """Return the current quality dimension breakdown.

        Each dimension includes name, score, weight, severity, grade,
        and detailed metrics.
        """
        if not self._dimensions:
            return {}
        return {k: v.to_dict() for k, v in self._dimensions.items()}

    def track_quality_over_time(self) -> Dict[str, Any]:
        """Return quality trend data.

        Includes snapshots, comparison with previous, regression
        detection, and trajectory projection.
        """
        snapshots = self._trend.get_snapshots()
        comparison = self._trend.compare_with_previous()
        regressions = self._trend.detect_regressions()
        trajectory = self._trend.project_trajectory()

        return {
            "snapshot_count": len(snapshots),
            "latest_snapshot": self._trend.get_latest().to_dict() if self._trend.get_latest() else None,
            "comparison": comparison,
            "regressions": regressions,
            "trajectory": trajectory,
            "snapshots": [s.to_dict() for s in snapshots[-20:]],  # Last 20
        }

    def get_quality_report(self) -> str:
        """Generate a formatted quality report string."""
        lines: List[str] = []
        lines.append("=" * 70)
        lines.append("  ReconPro Quality Intelligence Report")
        lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("=" * 70)
        lines.append("")

        # Composite score
        score = self._composite_score
        grade = _assign_grade(score)
        lines.append(f"COMPOSITE SCORE: {score:.1f}/100  (Grade: {grade})")
        lines.append(f"Files analysed: {self._total_files}  |  Total LOC: {self._total_loc}")
        lines.append("")

        # Dimensions breakdown
        lines.append("-" * 70)
        lines.append(f"{'Dimension':<20s} {'Score':>6s} {'Weight':>7s} {'Grade':>6s} {'Severity':>10s}")
        lines.append("-" * 70)

        for dim_name, dim in self._dimensions.items():
            lines.append(
                f"{dim.name:<20s} {dim.score:>5.1f}/100 {dim.weight:>6.2f}  "
                f"{dim.grade:>5s} {dim.severity:>10s}"
            )
        lines.append("")

        # Dimension details
        for dim_name, dim in self._dimensions.items():
            if dim.details:
                lines.append(f"  [{dim_name}] {dim.details}")
                if dim.metrics:
                    for mk, mv in dim.metrics.items():
                        if isinstance(mv, float):
                            lines.append(f"    - {mk}: {mv:.1f}")
                        else:
                            lines.append(f"    - {mk}: {mv}")
        lines.append("")

        # Trend info
        trend_data = self.track_quality_over_time()
        if trend_data["comparison"]:
            comp = trend_data["comparison"]
            lines.append("TREND: " + comp["direction"].upper())
            lines.append(f"  Score delta: {comp['score_delta']:+.1f}")
            if comp["regressions"]:
                lines.append(f"  Regressed dimensions: {', '.join(comp['regressions'])}")
            if comp["improvements"]:
                lines.append(f"  Improved dimensions: {', '.join(comp['improvements'])}")
        else:
            lines.append("TREND: Insufficient data (need 2+ snapshots)")
        lines.append("")

        # Gate status
        gate_history = self._gate.get_gate_history("release_ready")
        if gate_history:
            latest = gate_history[-1]
            status = "PASSED" if latest["passed"] else "FAILED"
            lines.append(f"GATE 'release_ready': {status} (score={latest['score']:.1f}, threshold={latest['threshold']:.1f})")
            if latest["failures"]:
                for fail in latest["failures"]:
                    lines.append(f"  - {fail['message']}")
        lines.append("")

        lines.append("=" * 70)
        lines.append("  End of Quality Intelligence Report")
        lines.append("=" * 70)

        return "\n".join(lines)

    def set_quality_threshold(self, thresholds: Dict[str, float]) -> None:
        """Set minimum acceptable quality thresholds.

        Args:
            thresholds: Dict mapping dimension name (or "_composite")
                         to minimum acceptable score (0-100).
        """
        self._thresholds = dict(thresholds)
        logger.info("Updated quality thresholds: %s", thresholds)

    # ── Trend / Gate accessors ───────────────────────────────────────────

    @property
    def trend(self) -> QualityTrend:
        """Access the quality trend tracker."""
        return self._trend

    @property
    def gate(self) -> QualityGate:
        """Access the quality gate system."""
        return self._gate

    # ── Internal: dimension computation ──────────────────────────────────

    def _compute_dimensions(
        self,
        analyzer: _ASTAnalyzer,
        security_issues: List[Dict[str, Any]],
        is_test: bool,
        source: str,
    ) -> Dict[str, QualityDimension]:
        """Compute all 8 quality dimensions for a single file."""
        dimensions: Dict[str, QualityDimension] = {}

        dimensions["complexity"] = self._dim_complexity(analyzer)
        dimensions["coverage"] = self._dim_coverage(analyzer, is_test, source)
        dimensions["type_safety"] = self._dim_type_safety(analyzer)
        dimensions["documentation"] = self._dim_documentation(analyzer)
        dimensions["security"] = self._dim_security(analyzer, security_issues)
        dimensions["maintainability"] = self._dim_maintainability(analyzer)
        dimensions["reliability"] = self._dim_reliability(analyzer)
        dimensions["consistency"] = self._dim_consistency(analyzer)

        return dimensions

    def _dim_complexity(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score code complexity (LOC per function, nesting depth)."""
        if not a.functions:
            return QualityDimension(
                name="complexity", score=100.0, weight=self._weights["complexity"],
                severity="info", grade="A+", details="No functions to analyse.",
            )

        avg_loc = sum(f["loc"] for f in a.functions) / len(a.functions)
        max_loc = max(f["loc"] for f in a.functions)
        max_nesting = a.max_nesting_depth
        total_branches = a.total_branches

        # Scoring: penalise large functions and deep nesting
        loc_score = max(0, 100 - (avg_loc - 20) * 2)  # 20 LOC = perfect
        loc_score = max(0, min(100, loc_score))

        nesting_score = max(0, 100 - (max_nesting - 2) * 12)  # 2 levels = perfect
        nesting_score = max(0, min(100, nesting_score))

        # Long function penalty
        long_funcs = sum(1 for f in a.functions if f["loc"] > 50)
        long_penalty = long_funcs * 5

        score = max(0, min(100, (loc_score * 0.4 + nesting_score * 0.4 + 20) - long_penalty))

        return QualityDimension(
            name="complexity",
            score=round(score, 1),
            weight=self._weights["complexity"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"avg_func_loc={avg_loc:.0f}, max_func_loc={max_loc}, max_nesting={max_nesting}, branches={total_branches}",
            metrics={
                "avg_func_loc": round(avg_loc, 1),
                "max_func_loc": max_loc,
                "max_nesting_depth": max_nesting,
                "total_branches": total_branches,
                "long_functions": long_funcs,
                "function_count": len(a.functions),
            },
        )

    def _dim_coverage(self, a: _ASTAnalyzer, is_test: bool, source: str) -> QualityDimension:
        """Score test coverage estimation."""
        if is_test:
            # Evaluate test quality instead
            source_lines = source.splitlines()
            est = _estimate_test_coverage(source_lines)
            score = est["quality_estimate"]
            return QualityDimension(
                name="coverage",
                score=score,
                weight=self._weights["coverage"],
                severity=_assign_severity(score),
                grade=_assign_dimension_grade(score),
                details=f"Test file quality: {est['test_function_count']} tests, {est['assert_count']} asserts, {est['asserts_per_test']:.1f} asserts/test",
                metrics=est,
            )

        # For non-test files: estimate based on whether test file likely exists
        # This is a heuristic — real coverage requires instrumentation
        # We give a baseline score for non-test files since we can't
        # truly measure coverage without running tests
        score = 50.0  # Neutral estimate for non-test files

        return QualityDimension(
            name="coverage",
            score=score,
            weight=self._weights["coverage"],
            severity="medium",
            grade=_assign_dimension_grade(score),
            details="Non-test file; coverage requires test execution (estimated baseline)",
            metrics={"estimated": True, "note": "Real coverage requires running test suite"},
        )

    def _dim_type_safety(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score type hint coverage."""
        if a.total_params == 0 and not a.functions:
            return QualityDimension(
                name="type_safety", score=100.0, weight=self._weights["type_safety"],
                severity="info", grade="A+", details="No functions to analyse.",
            )

        if a.total_params == 0:
            return QualityDimension(
                name="type_safety", score=80.0, weight=self._weights["type_safety"],
                severity="low", grade="A-", details="Functions exist but have no parameters.",
            )

        param_ratio = a.has_type_hints / a.total_params

        # Check return type hints
        funcs_with_return = 0
        funcs_total = len(a.functions)
        for f in a.functions:
            if f["returns_hinted"]:
                funcs_with_return += 1
        return_ratio = funcs_with_return / funcs_total if funcs_total > 0 else 1.0

        score = (param_ratio * 60 + return_ratio * 40)
        score = max(0, min(100, score))

        return QualityDimension(
            name="type_safety",
            score=round(score, 1),
            weight=self._weights["type_safety"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"param_hints={a.has_type_hints}/{a.total_params} ({param_ratio:.0%}), return_hints={funcs_with_return}/{funcs_total} ({return_ratio:.0%})",
            metrics={
                "params_hinted": a.has_type_hints,
                "total_params": a.total_params,
                "param_hint_ratio": round(param_ratio, 3),
                "returns_hinted": funcs_with_return,
                "total_functions": funcs_total,
                "return_hint_ratio": round(return_ratio, 3),
            },
        )

    def _dim_documentation(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score docstring coverage."""
        if a.docstring_targets == 0:
            if a.total_loc > 20:
                # File has code but no documentable targets
                return QualityDimension(
                    name="documentation",
                    score=20.0,
                    weight=self._weights["documentation"],
                    severity="high",
                    grade="D",
                    details="File has code but no functions or classes with docstrings.",
                    metrics={"docstring_count": 0, "targets": 0},
                )
            return QualityDimension(
                name="documentation", score=100.0, weight=self._weights["documentation"],
                severity="info", grade="A+", details="Empty file.",
            )

        ratio = a.docstring_count / a.docstring_targets
        score = ratio * 100

        return QualityDimension(
            name="documentation",
            score=round(score, 1),
            weight=self._weights["documentation"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"docstrings={a.docstring_count}/{a.docstring_targets} ({ratio:.0%}), comments={a.comment_lines}",
            metrics={
                "docstring_count": a.docstring_count,
                "documentable_targets": a.docstring_targets,
                "docstring_ratio": round(ratio, 3),
                "comment_lines": a.comment_lines,
            },
        )

    def _dim_security(self, a: _ASTAnalyzer, issues: List[Dict[str, Any]]) -> QualityDimension:
        """Score security (lower anti-pattern count = higher score)."""
        issue_count = len(issues)

        # Start at 100, deduct per issue
        deductions = {
            "use of eval()": 20,
            "use of exec()": 20,
            "pickle deserialization (unsafe)": 15,
            "marshal deserialization (unsafe)": 15,
            "os.system() command injection risk": 15,
            "shell=True in subprocess": 12,
            "SSL verification disabled": 10,
            "certificate verification disabled": 8,
            "hostname verification disabled": 8,
            "yaml.load without Loader (unsafe)": 12,
            "compile with exec mode": 15,
            "weak hash algorithm (MD5)": 8,
            "weak hash algorithm (SHA1)": 5,
            "mktemp is insecure (race condition)": 10,
            "dynamic import via __import__": 8,
            "attribute name introspection": 3,
            "dunder attribute access": 3,
            "noqa comment (suppressed linting)": 2,
            "type: ignore comment": 2,
            "bare or overly broad except": 3,
            "bare pass (possible stub)": 1,
        }

        total_deduction = 0
        for issue in issues:
            pattern_desc = issue.get("pattern", "")
            total_deduction += deductions.get(pattern_desc, 3)

        score = max(0, 100 - total_deduction)

        # Also penalise bare except
        if a.bare_except_handlers > 0:
            score = max(0, score - a.bare_except_handlers * 8)

        return QualityDimension(
            name="security",
            score=round(score, 1),
            weight=self._weights["security"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"anti_patterns={issue_count}, bare_except={a.bare_except_handlers}, security_deduction={total_deduction}",
            metrics={
                "anti_pattern_count": issue_count,
                "bare_except_handlers": a.bare_except_handlers,
                "total_deduction": total_deduction,
                "issues_sample": issues[:10],
            },
        )

    def _dim_maintainability(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score maintainability index."""
        avg_func_loc = (
            sum(f["loc"] for f in a.functions) / len(a.functions)
            if a.functions else 0
        )

        score = _compute_maintainability_index(
            total_loc=a.total_loc,
            comment_lines=a.comment_lines,
            blank_lines=a.blank_lines,
            max_nesting=a.max_nesting_depth,
            avg_func_loc=avg_func_loc,
        )

        return QualityDimension(
            name="maintainability",
            score=score,
            weight=self._weights["maintainability"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"loc={a.total_loc}, comments={a.comment_lines}, blank={a.blank_lines}, avg_func_loc={avg_func_loc:.0f}",
            metrics={
                "total_loc": a.total_loc,
                "code_loc": a.total_loc - a.comment_lines - a.blank_lines,
                "comment_lines": a.comment_lines,
                "blank_lines": a.blank_lines,
                "avg_func_loc": round(avg_func_loc, 1),
                "max_nesting": a.max_nesting_depth,
            },
        )

    def _dim_reliability(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score error handling quality."""
        if not a.functions:
            return QualityDimension(
                name="reliability", score=100.0, weight=self._weights["reliability"],
                severity="info", grade="A+", details="No functions to analyse.",
            )

        # Ratio of try blocks to functions (more error handling = better)
        try_ratio = a.try_blocks / len(a.functions)

        # Penalise bare excepts
        bare_penalty = a.bare_except_handlers * 15

        # Reward having any error handling
        handling_bonus = min(40, try_ratio * 100)

        # Base score
        base = 50.0
        score = max(0, min(100, base + handling_bonus - bare_penalty))

        return QualityDimension(
            name="reliability",
            score=round(score, 1),
            weight=self._weights["reliability"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"try_blocks={a.try_blocks}, except_handlers={a.except_handlers}, bare_except={a.bare_except_handlers}",
            metrics={
                "try_blocks": a.try_blocks,
                "except_handlers": a.except_handlers,
                "bare_except_handlers": a.bare_except_handlers,
                "try_ratio": round(try_ratio, 3),
                "functions": len(a.functions),
            },
        )

    def _dim_consistency(self, a: _ASTAnalyzer) -> QualityDimension:
        """Score naming/style consistency."""
        violations = a.naming_violations
        violation_count = len(violations)

        # Score: start at 100, deduct per violation
        score = max(0, 100 - violation_count * 8)

        # Check for TODO/FIXME/HACK comments
        todo_count = sum(
            1 for line in a.source_lines
            if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", line, re.IGNORECASE)
        )
        todo_penalty = min(20, todo_count * 3)
        score = max(0, score - todo_penalty)

        # Check for mixed indentation (tabs vs spaces)
        tab_lines = sum(1 for line in a.source_lines if "\t" in line)
        tab_penalty = min(15, tab_lines * 0.5)
        score = max(0, score - tab_penalty)

        return QualityDimension(
            name="consistency",
            score=round(score, 1),
            weight=self._weights["consistency"],
            severity=_assign_severity(score),
            grade=_assign_dimension_grade(score),
            details=f"naming_violations={violation_count}, todos={todo_count}, tab_lines={tab_lines}",
            metrics={
                "naming_violations": violation_count,
                "naming_violation_details": violations[:10],
                "todo_count": todo_count,
                "tab_lines": tab_lines,
            },
        )

    # ── Internal: aggregation ────────────────────────────────────────────

    def _aggregate_dimensions(
        self,
        file_dimensions: List[Dict[str, QualityDimension]],
    ) -> Dict[str, QualityDimension]:
        """Aggregate per-file dimensions into repository-level dimensions.

        Uses weighted averages across all files.
        """
        if not file_dimensions:
            return {}

        dim_names = DEFAULT_DIMENSION_WEIGHTS.keys()
        aggregated: Dict[str, QualityDimension] = {}

        for dim_name in dim_names:
            scores = []
            all_metrics: List[Dict[str, Any]] = []
            weight = self._weights.get(dim_name, 0.1)

            for file_dims in file_dimensions:
                dim = file_dims.get(dim_name)
                if dim is not None:
                    scores.append(dim.score)
                    if dim.metrics:
                        all_metrics.append(dim.metrics)

            if not scores:
                aggregated[dim_name] = QualityDimension(
                    name=dim_name, score=0.0, weight=weight,
                    severity="critical", grade="F",
                    details="No data available.",
                )
                continue

            avg_score = sum(scores) / len(scores)

            # Merge metrics (sum numeric values)
            merged_metrics: Dict[str, Any] = {}
            for m in all_metrics:
                for k, v in m.items():
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        merged_metrics[k] = merged_metrics.get(k, 0) + v

            aggregated[dim_name] = QualityDimension(
                name=dim_name,
                score=round(avg_score, 1),
                weight=weight,
                severity=_assign_severity(avg_score),
                grade=_assign_dimension_grade(avg_score),
                details=f"average across {len(scores)} files",
                metrics=merged_metrics,
            )

        return aggregated

    # DEAD CODE: consider removal
    def _weighted_score(self, dimensions: Dict[str, QualityDimension]) -> float:
        """Compute weighted composite score from dimensions."""
        if not dimensions:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for dim_name, dim in dimensions.items():
            w = self._weights.get(dim_name, 0.1)
            weighted_sum += dim.score * w
            total_weight += w

        if total_weight == 0:
            return 0.0

        return max(MIN_SCORE, min(MAX_SCORE, weighted_sum / total_weight))


# ════════════════════════════════════════════════════════════════════════
# Convenience functions
# ════════════════════════════════════════════════════════════════════════


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def analyze_file(file_path: str) -> Dict[str, Any]:
    """Quick-analyse a single file's quality."""
    qi = QualityIntelligence()
    return qi.analyze_code_quality(file_path)


# DEAD CODE: consider removal
def analyze_repository(repository_path: str) -> Dict[str, Any]:
    """Quick-analyse a repository's quality."""
    qi = QualityIntelligence(repository_path=repository_path)
    return qi.analyze_repository_quality()


def get_quality_trend() -> Dict[str, Any]:
    """Get quality trend data without running analysis."""
    trend = QualityTrend()
    qi = QualityIntelligence()
    return qi.track_quality_over_time()


__all__ = [
    "QualityDimension",
    "QualitySnapshot",
    "QualityTrend",
    "QualityGate",
    "GateResult",
    "QualityIntelligence",
    "analyze_file",
    "analyze_repository",
    "get_quality_trend",
]
