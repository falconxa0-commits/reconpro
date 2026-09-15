"""ReconPro v11 — Auto Engineering Pipeline.

Orchestrates automated engineering workflows for continuous quality
assurance. Combines health checks, code drift detection, quality
gates, and metrics tracking into a single pipeline.

Pure Python. Zero external dependencies. Full type hints.

Classes:
    EngineeringMetrics    – Collect and persist engineering metrics
    EngineeringBaseline   – Capture and compare repository snapshots
    EngineeringPipeline   – Orchestrate full engineering workflows

Usage:
    from reconpro.auto_engineering import EngineeringPipeline

    pipeline = EngineeringPipeline()
    result = pipeline.engineering_workflow(repo_path=".")
    print(result["quality_gate"]["passed"])
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .constants import RECONPRO_HOME

logger = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────

METRICS_DIR: Path = RECONPRO_HOME / "metrics"
BASELINE_DIR: Path = RECONPRO_HOME / "baselines"

# Default quality gate thresholds
DEFAULT_QUALITY_THRESHOLDS: Dict[str, float] = {
    "min_test_pass_rate": 80.0,
    "max_debt_ratio": 30.0,
    "max_complexity": 20.0,
    "max_drift_score": 50.0,
    "min_health_checks_passed": 0.7,
    "max_drift_events": 10,
}

# File extensions considered source code for analysis
_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".yml", ".yaml", ".toml",
    ".json", ".xml", ".html", ".css", ".scss", ".sql", ".r",
    ".lua", ".pl", ".ex", ".exs", ".hs", ".ml", ".vim",
})

# Directories to skip during repository walks
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "__pycache__", ".tox", ".venv", "venv",
    "env", ".env", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".eggs", "*.egg-info", ".hg", ".svn",
    "target", ".gradle", ".idea", ".vscode", ".DS_Store",
    "coverage", ".coverage", ".nyc_output", ".next", ".nuxt",
    ".reconpro", ".cache",
})


# ═══════════════════════════════════════════════════════════════════════
# EngineeringMetrics
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class MetricsSnapshot:
    """Point-in-time snapshot of engineering metrics."""
    timestamp: str = ""
    test_pass_rate: float = 0.0
    test_total: int = 0
    test_passed: int = 0
    test_failed: int = 0
    test_skipped: int = 0
    coverage_percent: float = 0.0
    debt_ratio: float = 0.0
    debt_items: int = 0
    complexity_avg: float = 0.0
    complexity_max: float = 0.0
    file_count: int = 0
    total_lines: int = 0
    source_lines: int = 0
    pipeline_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "test_pass_rate": round(self.test_pass_rate, 2),
            "test_total": self.test_total,
            "test_passed": self.test_passed,
            "test_failed": self.test_failed,
            "test_skipped": self.test_skipped,
            "coverage_percent": round(self.coverage_percent, 2),
            "debt_ratio": round(self.debt_ratio, 2),
            "debt_items": self.debt_items,
            "complexity_avg": round(self.complexity_avg, 2),
            "complexity_max": round(self.complexity_max, 2),
            "file_count": self.file_count,
            "total_lines": self.total_lines,
            "source_lines": self.source_lines,
            "pipeline_duration_ms": round(self.pipeline_duration_ms, 2),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MetricsSnapshot:
        return cls(
            timestamp=data.get("timestamp", ""),
            test_pass_rate=float(data.get("test_pass_rate", 0.0)),
            test_total=int(data.get("test_total", 0)),
            test_passed=int(data.get("test_passed", 0)),
            test_failed=int(data.get("test_failed", 0)),
            test_skipped=int(data.get("test_skipped", 0)),
            coverage_percent=float(data.get("coverage_percent", 0.0)),
            debt_ratio=float(data.get("debt_ratio", 0.0)),
            debt_items=int(data.get("debt_items", 0)),
            complexity_avg=float(data.get("complexity_avg", 0.0)),
            complexity_max=float(data.get("complexity_max", 0.0)),
            file_count=int(data.get("file_count", 0)),
            total_lines=int(data.get("total_lines", 0)),
            source_lines=int(data.get("source_lines", 0)),
            pipeline_duration_ms=float(data.get("pipeline_duration_ms", 0.0)),
        )


class EngineeringMetrics:
    """Collect, track, and persist engineering metrics.

    Tracks test pass rate, coverage trend, debt ratio, and complexity
    trend over time. Persists snapshots to JSON files at
    ``RECONPRO_HOME/metrics/``.

    Parameters
    ----------
    repo_path : str | Path
        Root directory of the repository to analyze.
    metrics_dir : Path | None
        Directory for persisted metrics. Defaults to ``METRICS_DIR``.
    """

    def __init__(
        self,
        repo_path: str | Path = ".",
        metrics_dir: Optional[Path] = None,
    ) -> None:
        self._repo = Path(repo_path).resolve()
        self._metrics_dir = metrics_dir or METRICS_DIR
        self._metrics_dir.mkdir(parents=True, exist_ok=True)
        self._history_file = self._metrics_dir / "engineering_metrics.json"
        self._snapshots: List[MetricsSnapshot] = []
        self._load_history()

    # -- Persistence -----------------------------------------------------

    def _load_history(self) -> None:
        """Load historical metrics from disk."""
        if not self._history_file.exists():
            return
        try:
            with open(self._history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data.get("snapshots", [])
            self._snapshots = [MetricsSnapshot.from_dict(s) for s in raw_list]
        except (json.JSONDecodeError, OSError, KeyError, TypeError):
            logger.debug("Could not load metrics history", exc_info=True)
            self._snapshots = []

    def _save_history(self) -> None:
        """Persist current metrics to disk."""
        try:
            data = {
                "repo_path": str(self._repo),
                "updated": datetime.now(timezone.utc).isoformat(),
                "total_snapshots": len(self._snapshots),
                "snapshots": [s.to_dict() for s in self._snapshots],
            }
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except OSError:
            logger.debug("Could not save metrics history", exc_info=True)

    # -- Metric Collection ------------------------------------------------

    def collect_current_metrics(self) -> MetricsSnapshot:
        """Analyze the repository and return a fresh metrics snapshot.

        Walks the repository tree, counts files and lines, estimates
        cyclomatic complexity for Python files, and calculates a
        synthetic debt ratio.
        """
        t0 = time.perf_counter()
        file_count = 0
        total_lines = 0
        source_lines = 0
        complexity_values: List[float] = []
        debt_markers = 0

        for fpath in self._walk_source_files():
            file_count += 1
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            lines = content.splitlines()
            line_count = len(lines)
            total_lines += line_count

            if fpath.suffix in _SOURCE_EXTENSIONS:
                source_lines += line_count

                # Estimate complexity for Python files
                if fpath.suffix == ".py":
                    cx = self._estimate_complexity(lines)
                    complexity_values.append(cx)

                    # Count debt markers (TODO, FIXME, HACK, XXX)
                    for line in lines:
                        stripped = line.strip().upper()
                        if stripped.startswith(("# TODO", "# FIXME", "# HACK", "# XXX")):
                            debt_markers += 1

        # Calculate aggregate metrics
        complexity_avg = (
            sum(complexity_values) / len(complexity_values)
            if complexity_values else 0.0
        )
        complexity_max = max(complexity_values) if complexity_values else 0.0
        debt_ratio = (
            (debt_markers / source_lines * 100.0)
            if source_lines > 0 else 0.0
        )

        # Cap debt_ratio at 100
        debt_ratio = min(debt_ratio, 100.0)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        snapshot = MetricsSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            debt_ratio=debt_ratio,
            debt_items=debt_markers,
            complexity_avg=complexity_avg,
            complexity_max=complexity_max,
            file_count=file_count,
            total_lines=total_lines,
            source_lines=source_lines,
            pipeline_duration_ms=elapsed_ms,
        )

        return snapshot

    def record_snapshot(self, snapshot: MetricsSnapshot) -> None:
        """Append a snapshot to history and persist."""
        self._snapshots.append(snapshot)
        # Keep last 100 snapshots to prevent unbounded growth
        if len(self._snapshots) > 100:
            self._snapshots = self._snapshots[-100:]
        self._save_history()

    # -- Trend Analysis ---------------------------------------------------

    def get_coverage_trend(self, n: int = 10) -> List[float]:
        """Return the last *n* coverage values from history."""
        recent = self._snapshots[-n:]
        return [s.coverage_percent for s in recent if s.coverage_percent > 0]

    def get_debt_trend(self, n: int = 10) -> List[float]:
        """Return the last *n* debt ratio values from history."""
        recent = self._snapshots[-n:]
        return [s.debt_ratio for s in recent]

    def get_complexity_trend(self, n: int = 10) -> List[float]:
        """Return the last *n* average complexity values from history."""
        recent = self._snapshots[-n:]
        return [s.complexity_avg for s in recent]

    def get_test_pass_rate_trend(self, n: int = 10) -> List[float]:
        """Return the last *n* test pass rate values from history."""
        recent = self._snapshots[-n:]
        return [s.test_pass_rate for s in recent if s.test_pass_rate > 0]

    def get_latest_snapshot(self) -> Optional[MetricsSnapshot]:
        """Return the most recent snapshot, or None if no history."""
        return self._snapshots[-1] if self._snapshots else None

    def get_snapshot_count(self) -> int:
        """Return the number of stored snapshots."""
        return len(self._snapshots)

    # -- Helpers ----------------------------------------------------------

    def _walk_source_files(self) -> List[Path]:
        """Yield all source files in the repository, skipping _SKIP_DIRS."""
        files: List[Path] = []
        if not self._repo.is_dir():
            return files
        try:
            for root, dirs, filenames in os.walk(self._repo):
                # Prune skipped directories in-place
                dirs[:] = [
                    d for d in dirs
                    if d not in _SKIP_DIRS and not d.startswith(".")
                    if d not in {"__pycache__", "node_modules"}
                ]
                dirs[:] = [
                    d for d in dirs
                    if d not in _SKIP_DIRS
                ]
                for fname in sorted(filenames):
                    fpath = Path(root) / fname
                    if fpath.suffix in _SOURCE_EXTENSIONS:
                        files.append(fpath)
        except OSError:
            logger.debug("Error walking repository", exc_info=True)
        return files

    @staticmethod
    def _estimate_complexity(lines: List[str]) -> float:
        """Estimate cyclomatic complexity for a Python file.

        Counts branch-inducing keywords: ``if``, ``elif``, ``for``,
        ``while``, ``except``, ``with``, ``and``, ``or``. Adds 1 for
        the base path.

        Ignores lines inside comments and strings (best-effort heuristic).
        """
        complexity = 1.0  # Base path
        branch_keywords = re.compile(
            r"\b(if|elif|for|while|except|with)\b|\b(and|or)\b"
        )
        in_multiline_string = False
        for line in lines:
            stripped = line.strip()
            # Simple heuristic for triple-quoted strings
            triple_count = stripped.count('"""') + stripped.count("'''")
            if triple_count % 2 != 0:
                in_multiline_string = not in_multiline_string
            if in_multiline_string:
                continue
            # Skip comment-only lines
            if stripped.startswith("#"):
                continue
            complexity += len(branch_keywords.findall(stripped))
        return complexity

    def to_dict(self) -> Dict[str, Any]:
        """Return the full metrics state as a dictionary."""
        return {
            "repo_path": str(self._repo),
            "metrics_dir": str(self._metrics_dir),
            "snapshot_count": len(self._snapshots),
            "latest": (
                self._snapshots[-1].to_dict() if self._snapshots else None
            ),
            "coverage_trend": self.get_coverage_trend(),
            "debt_trend": self.get_debt_trend(),
            "complexity_trend": self.get_complexity_trend(),
            "test_pass_rate_trend": self.get_test_pass_rate_trend(),
        }


# ═══════════════════════════════════════════════════════════════════════
# EngineeringBaseline
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class FileFingerprint:
    """Fingerprint of a single source file."""
    path: str
    size_bytes: int = 0
    line_count: int = 0
    sha256: str = ""
    complexity: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "sha256": self.sha256,
            "complexity": round(self.complexity, 2),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileFingerprint:
        return cls(
            path=data.get("path", ""),
            size_bytes=int(data.get("size_bytes", 0)),
            line_count=int(data.get("line_count", 0)),
            sha256=data.get("sha256", ""),
            complexity=float(data.get("complexity", 0.0)),
        )


@dataclass
class BaselineSnapshot:
    """Complete baseline snapshot of a repository."""
    name: str = ""
    timestamp: str = ""
    repo_path: str = ""
    files: List[FileFingerprint] = field(default_factory=list)
    total_files: int = 0
    total_lines: int = 0
    total_size_bytes: int = 0
    avg_complexity: float = 0.0
    max_complexity: float = 0.0
    composite_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "repo_path": self.repo_path,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "total_size_bytes": self.total_size_bytes,
            "avg_complexity": round(self.avg_complexity, 2),
            "max_complexity": round(self.max_complexity, 2),
            "composite_hash": self.composite_hash,
            "files": [f.to_dict() for f in self.files],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BaselineSnapshot:
        files = [FileFingerprint.from_dict(f) for f in data.get("files", [])]
        return cls(
            name=data.get("name", ""),
            timestamp=data.get("timestamp", ""),
            repo_path=data.get("repo_path", ""),
            files=files,
            total_files=int(data.get("total_files", 0)),
            total_lines=int(data.get("total_lines", 0)),
            total_size_bytes=int(data.get("total_size_bytes", 0)),
            avg_complexity=float(data.get("avg_complexity", 0.0)),
            max_complexity=float(data.get("max_complexity", 0.0)),
            composite_hash=data.get("composite_hash", ""),
        )


@dataclass
class DriftReport:
    """Result of comparing current state against a baseline."""
    baseline_name: str = ""
    baseline_timestamp: str = ""
    current_timestamp: str = ""
    files_added: List[str] = field(default_factory=list)
    files_removed: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    drift_events: List[Dict[str, Any]] = field(default_factory=list)
    drift_score: float = 0.0
    regression_detected: bool = False
    regression_details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_name": self.baseline_name,
            "baseline_timestamp": self.baseline_timestamp,
            "current_timestamp": self.current_timestamp,
            "files_added": self.files_added,
            "files_removed": self.files_removed,
            "files_modified": self.files_modified,
            "total_changes": (
                len(self.files_added) + len(self.files_removed)
                + len(self.files_modified)
            ),
            "drift_events": self.drift_events,
            "drift_score": round(self.drift_score, 2),
            "regression_detected": self.regression_detected,
            "regression_details": self.regression_details,
        }


class EngineeringBaseline:
    """Manage engineering baselines for a repository.

    Captures snapshots of repository state (file manifests with
    hashes and complexity estimates), compares current state against
    baselines, and tracks regression status.

    Baselines are persisted to ``RECONPRO_HOME/baselines/<name>.json``.

    Parameters
    ----------
    repo_path : str | Path
        Root directory of the repository.
    baseline_dir : Path | None
        Directory for persisted baselines.
    """

    def __init__(
        self,
        repo_path: str | Path = ".",
        baseline_dir: Optional[Path] = None,
    ) -> None:
        self._repo = Path(repo_path).resolve()
        self._baseline_dir = baseline_dir or BASELINE_DIR
        self._baseline_dir.mkdir(parents=True, exist_ok=True)

    # -- Public API -------------------------------------------------------

    def capture_snapshot(self, name: str = "") -> BaselineSnapshot:
        """Capture a baseline snapshot of the current repository state.

        Parameters
        ----------
        name : str
            Baseline name. Defaults to ``"auto_<timestamp>"``.

        Returns
        -------
        BaselineSnapshot
            The captured baseline.
        """
        if not name:
            name = f"auto_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        fingerprints: List[FileFingerprint] = []
        total_lines = 0
        total_size = 0
        complexity_values: List[float] = []
        hash_parts: List[str] = []

        metrics = EngineeringMetrics(repo_path=self._repo)
        source_files = metrics._walk_source_files()

        for fpath in source_files:
            rel_path = str(fpath.relative_to(self._repo))
            try:
                content = fpath.read_bytes()
            except OSError:
                continue

            sha = hashlib.sha256(content).hexdigest()
            text_content = content.decode("utf-8", errors="ignore")
            lines = text_content.splitlines()
            line_count = len(lines)

            complexity = 0.0
            if fpath.suffix == ".py":
                complexity = EngineeringMetrics._estimate_complexity(lines)

            fp = FileFingerprint(
                path=rel_path,
                size_bytes=len(content),
                line_count=line_count,
                sha256=sha,
                complexity=complexity,
            )
            fingerprints.append(fp)
            total_lines += line_count
            total_size += len(content)
            if complexity > 0:
                complexity_values.append(complexity)
            hash_parts.append(f"{rel_path}:{sha[:16]}")

        avg_complexity = (
            sum(complexity_values) / len(complexity_values)
            if complexity_values else 0.0
        )
        max_complexity = max(complexity_values) if complexity_values else 0.0
        composite_hash = hashlib.sha256(
            "\n".join(sorted(hash_parts)).encode()
        ).hexdigest()[:32]

        snapshot = BaselineSnapshot(
            name=name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            repo_path=str(self._repo),
            files=sorted(fingerprints, key=lambda f: f.path),
            total_files=len(fingerprints),
            total_lines=total_lines,
            total_size_bytes=total_size,
            avg_complexity=avg_complexity,
            max_complexity=max_complexity,
            composite_hash=composite_hash,
        )

        self._save_baseline(snapshot)
        return snapshot

    def compare(
        self,
        baseline_name: Optional[str] = None,
        baseline: Optional[BaselineSnapshot] = None,
    ) -> DriftReport:
        """Compare current repository state against a baseline.

        Parameters
        ----------
        baseline_name : str | None
            Name of a previously saved baseline.
        baseline : BaselineSnapshot | None
            An in-memory baseline object. Takes precedence over
            *baseline_name*.

        Returns
        -------
        DriftReport
            Detailed comparison results.
        """
        if baseline is None:
            if baseline_name is None:
                # Use the most recent baseline
                baseline = self._load_latest_baseline()
            else:
                baseline = self.load_baseline(baseline_name)

        if baseline is None:
            return DriftReport(
                baseline_name=baseline_name or "",
                current_timestamp=datetime.now(timezone.utc).isoformat(),
                regression_details=["No baseline found for comparison"],
            )

        # Build current state index
        current_fps: Dict[str, FileFingerprint] = {}
        metrics = EngineeringMetrics(repo_path=self._repo)
        for fpath in metrics._walk_source_files():
            rel_path = str(fpath.relative_to(self._repo))
            try:
                content = fpath.read_bytes()
            except OSError:
                continue
            text_content = content.decode("utf-8", errors="ignore")
            lines = text_content.splitlines()
            complexity = 0.0
            if fpath.suffix == ".py":
                complexity = EngineeringMetrics._estimate_complexity(lines)
            current_fps[rel_path] = FileFingerprint(
                path=rel_path,
                size_bytes=len(content),
                line_count=len(lines),
                sha256=hashlib.sha256(content).hexdigest(),
                complexity=complexity,
            )

        # Build baseline index
        baseline_map: Dict[str, FileFingerprint] = {
            f.path: f for f in baseline.files
        }

        current_paths = set(current_fps.keys())
        baseline_paths = set(baseline_map.keys())

        added = sorted(current_paths - baseline_paths)
        removed = sorted(baseline_paths - current_paths)
        common = current_paths & baseline_paths

        modified: List[str] = []
        drift_events: List[Dict[str, Any]] = []
        regression_details: List[str] = []

        for path in sorted(common):
            cur = current_fps[path]
            base = baseline_map[path]

            if cur.sha256 != base.sha256:
                modified.append(path)
                event: Dict[str, Any] = {
                    "path": path,
                    "type": "CONTENT_CHANGE",
                    "severity": "low",
                }

                # Detect regression: significant complexity increase
                if cur.complexity > 0 and base.complexity > 0:
                    cx_delta = cur.complexity - base.complexity
                    if cx_delta > 10:
                        event["severity"] = "high"
                        event["detail"] = (
                            f"Complexity surged by {cx_delta:.1f} "
                            f"(from {base.complexity:.1f} to {cur.complexity:.1f})"
                        )
                        regression_details.append(event["detail"])
                    elif cx_delta > 5:
                        event["severity"] = "medium"
                        event["detail"] = (
                            f"Complexity increased by {cx_delta:.1f} "
                            f"(from {base.complexity:.1f} to {cur.complexity:.1f})"
                        )

                # Detect regression: significant line count increase
                line_delta = cur.line_count - base.line_count
                if line_delta > 100:
                    event["severity"] = max(
                        event.get("severity", "low"), "medium"
                    )
                    if "detail" not in event:
                        event["detail"] = (
                            f"File grew by {line_delta} lines"
                        )

                drift_events.append(event)

        # New files add complexity
        for path in added:
            cur = current_fps[path]
            if cur.complexity > 15:
                regression_details.append(
                    f"New file {path} has high complexity ({cur.complexity:.1f})"
                )

        # Removed files might be regression (deleted tests, docs)
        for path in removed:
            base = baseline_map[path]
            if "test" in path.lower():
                regression_details.append(
                    f"Test file removed: {path}"
                )

        # Calculate drift score
        total_changes = len(added) + len(removed) + len(modified)
        drift_score = self._calculate_drift_score(
            added=added,
            removed=removed,
            modified=modified,
            drift_events=drift_events,
            regression_details=regression_details,
        )

        return DriftReport(
            baseline_name=baseline.name,
            baseline_timestamp=baseline.timestamp,
            current_timestamp=datetime.now(timezone.utc).isoformat(),
            files_added=added,
            files_removed=removed,
            files_modified=modified,
            drift_events=drift_events,
            drift_score=drift_score,
            regression_detected=len(regression_details) > 0,
            regression_details=regression_details,
        )

    def load_baseline(self, name: str) -> Optional[BaselineSnapshot]:
        """Load a named baseline from disk."""
        path = self._baseline_dir / f"{name}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return BaselineSnapshot.from_dict(data)
        except (json.JSONDecodeError, OSError, KeyError, TypeError):
            logger.debug("Could not load baseline %s", name, exc_info=True)
            return None

    def list_baselines(self) -> List[Dict[str, str]]:
        """List all saved baselines with name and timestamp."""
        results: List[Dict[str, str]] = []
        if not self._baseline_dir.exists():
            return results
        for fpath in sorted(self._baseline_dir.glob("*.json")):
            baseline = self.load_baseline(fpath.stem)
            if baseline:
                results.append({
                    "name": baseline.name,
                    "timestamp": baseline.timestamp,
                    "total_files": str(baseline.total_files),
                    "total_lines": str(baseline.total_lines),
                })
        return results

    def delete_baseline(self, name: str) -> bool:
        """Delete a saved baseline. Returns True on success."""
        path = self._baseline_dir / f"{name}.json"
        if not path.exists():
            return False
        try:
            path.unlink()
            return True
        except OSError:
            return False

    # -- Internal ---------------------------------------------------------

    def _save_baseline(self, snapshot: BaselineSnapshot) -> None:
        """Persist a baseline to disk."""
        path = self._baseline_dir / f"{snapshot.name}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)
        except OSError:
            logger.debug("Could not save baseline %s", snapshot.name, exc_info=True)

    def _load_latest_baseline(self) -> Optional[BaselineSnapshot]:
        """Load the most recently created baseline."""
        baselines = self.list_baselines()
        if not baselines:
            return None
        # list_baselines returns sorted by filename; get the last one
        latest = baselines[-1]
        return self.load_baseline(latest["name"])

    @staticmethod
    def _calculate_drift_score(
        added: List[str],
        removed: List[str],
        modified: List[str],
        drift_events: List[Dict[str, Any]],
        regression_details: List[str],
    ) -> float:
        """Calculate a 0-100 drift score.

        Higher score = more drift. Regression indicators boost the score.
        """
        if not added and not removed and not modified:
            return 0.0

        # Base score from change volume
        total_changes = len(added) + len(removed) + len(modified)
        volume_score = min(total_changes * 2.0, 40.0)

        # Severity weighting
        severity_weights = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 5.0}
        event_score = 0.0
        for event in drift_events:
            sev = event.get("severity", "low")
            event_score += severity_weights.get(sev, 1.0)
        event_score = min(event_score, 30.0)

        # Regression penalty
        regression_penalty = min(len(regression_details) * 5.0, 30.0)

        return min(volume_score + event_score + regression_penalty, 100.0)


# ═══════════════════════════════════════════════════════════════════════
# EngineeringPipeline
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class QualityGateResult:
    """Result of a quality gate evaluation."""
    passed: bool = False
    score: float = 0.0
    max_score: float = 100.0
    thresholds: Dict[str, float] = field(default_factory=dict)
    evaluations: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "score": round(self.score, 2),
            "max_score": self.max_score,
            "thresholds": dict(self.thresholds),
            "evaluations": dict(self.evaluations),
            "failures": list(self.failures),
            "warnings": list(self.warnings),
        }


class EngineeringPipeline:
    """Orchestrate automated engineering workflows.

    Combines health checks, drift detection, quality gates, and
    metrics collection into a unified pipeline. Integrates with
    existing ReconPro modules (diagnostics, drift_monitor, cross_validator,
    observability) rather than duplicating their functionality.

    Parameters
    ----------
    repo_path : str | Path
        Repository root to analyze.
    thresholds : dict[str, float] | None
        Quality gate thresholds. Defaults to ``DEFAULT_QUALITY_THRESHOLDS``.
    metrics_dir : Path | None
        Override for metrics storage directory.
    baseline_dir : Path | None
        Override for baseline storage directory.
    """

    def __init__(
        self,
        repo_path: str | Path = ".",
        thresholds: Optional[Dict[str, float]] = None,
        metrics_dir: Optional[Path] = None,
        baseline_dir: Optional[Path] = None,
    ) -> None:
        self._repo = Path(repo_path).resolve()
        self._thresholds = thresholds or dict(DEFAULT_QUALITY_THRESHOLDS)
        self._metrics = EngineeringMetrics(
            repo_path=self._repo,
            metrics_dir=metrics_dir,
        )
        self._baseline = EngineeringBaseline(
            repo_path=self._repo,
            baseline_dir=baseline_dir,
        )

    # -- Public API -------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Run repository health diagnostics.

        Delegates to ``diagnostics.health_check()``,
        ``diagnostics.validate_config()``, and
        ``diagnostics.run_diagnostics()`` for comprehensive results.

        Returns
        -------
        dict
            Structured health report with status per category,
            config validation issues, and summary statistics.
        """
        result: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_path": str(self._repo),
        }

        # 1. Quick health check from diagnostics module
        try:
            from .diagnostics import health_check as diag_health
            result["health"] = diag_health()
        except Exception as exc:
            logger.debug("Health check error: %s", exc, exc_info=True)
            result["health"] = {"error": str(exc)}

        # 2. Config validation from diagnostics module
        try:
            from .diagnostics import validate_config
            result["config_issues"] = validate_config()
        except Exception as exc:
            logger.debug("Config validation error: %s", exc, exc_info=True)
            result["config_issues"] = []

        # 3. Full diagnostics from diagnostics module
        try:
            from .diagnostics import run_diagnostics
            diag_result = run_diagnostics()
            result["diagnostics"] = {
                "total": diag_result.get("total_checks", 0),
                "passed": diag_result.get("passed", 0),
                "failed": diag_result.get("failed", 0),
                "checks": diag_result.get("checks", []),
            }
            result["health_score"] = self._compute_health_score(diag_result)
        except Exception as exc:
            logger.debug("Full diagnostics error: %s", exc, exc_info=True)
            result["diagnostics"] = {"error": str(exc)}
            result["health_score"] = 0.0

        # 4. Repository-specific checks
        repo_health = self._check_repository_health()
        result["repository"] = repo_health

        return result

    def drift_detection(
        self,
        baseline_name: Optional[str] = None,
        create_baseline_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Detect code drift from baselines.

        Compares the current repository state against the most recent
        baseline (or a named one). If no baseline exists and
        *create_baseline_if_missing* is True, captures one automatically.

        Parameters
        ----------
        baseline_name : str | None
            Specific baseline to compare against.
        create_baseline_if_missing : bool
            Auto-capture a baseline if none exists.

        Returns
        -------
        dict
            Drift detection results including drift score, changed files,
            and regression details.
        """
        result: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_path": str(self._repo),
        }

        # Check infrastructure drift monitor availability
        try:
            from .drift_monitor import InfrastructureDriftMonitor
            result["infra_drift_available"] = True
        except ImportError:
            result["infra_drift_available"] = False

        # Check if we have any baselines
        existing = self._baseline.list_baselines()
        if not existing and create_baseline_if_missing:
            snapshot = self._baseline.capture_snapshot(
                name=f"initial_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            )
            result["auto_baseline_created"] = True
            result["baseline"] = snapshot.to_dict()
            result["drift"] = {
                "drift_score": 0.0,
                "message": "Initial baseline captured; no drift to report",
            }
            return result

        # Run drift comparison
        drift_report = self._baseline.compare(baseline_name=baseline_name)
        result["drift"] = drift_report.to_dict()

        return result

    def quality_gate(
        self,
        metrics_snapshot: Optional[MetricsSnapshot] = None,
        drift_report: Optional[DriftReport] = None,
        health_result: Optional[Dict[str, Any]] = None,
    ) -> QualityGateResult:
        """Enforce quality thresholds before merge.

        Evaluates metrics, drift, and health against configured
        thresholds. Returns a detailed pass/fail result.

        Parameters
        ----------
        metrics_snapshot : MetricsSnapshot | None
            Current metrics. Collected automatically if None.
        drift_report : DriftReport | None
            Drift comparison result. Run automatically if None.
        health_result : dict | None
            Health check result. Run automatically if None.

        Returns
        -------
        QualityGateResult
            Pass/fail result with per-threshold evaluations.
        """
        # Collect data if not provided
        if metrics_snapshot is None:
            metrics_snapshot = self._metrics.collect_current_metrics()

        if drift_report is None:
            drift_report = self._baseline.compare()

        if health_result is None:
            health_result = self.health_check()

        evaluations: Dict[str, Dict[str, Any]] = {}
        failures: List[str] = []
        warnings: List[str] = []
        score_deductions = 0.0

        # 1. Test pass rate gate
        test_rate = metrics_snapshot.test_pass_rate
        min_test_rate = self._thresholds.get("min_test_pass_rate", 80.0)
        test_pass = test_rate >= min_test_rate or test_rate == 0.0  # 0 = no tests run, not a failure
        evaluations["test_pass_rate"] = {
            "value": test_rate,
            "threshold": min_test_rate,
            "passed": test_pass,
        }
        if not test_pass and test_rate > 0:
            failures.append(
                f"Test pass rate {test_rate:.1f}% below threshold {min_test_rate:.1f}%"
            )
            score_deductions += 25.0

        # 2. Debt ratio gate
        debt = metrics_snapshot.debt_ratio
        max_debt = self._thresholds.get("max_debt_ratio", 30.0)
        debt_pass = debt <= max_debt
        evaluations["debt_ratio"] = {
            "value": debt,
            "threshold": max_debt,
            "passed": debt_pass,
        }
        if not debt_pass:
            failures.append(
                f"Debt ratio {debt:.1f}% exceeds threshold {max_debt:.1f}%"
            )
            score_deductions += 20.0
        elif debt > max_debt * 0.7:
            warnings.append(
                f"Debt ratio {debt:.1f}% approaching threshold {max_debt:.1f}%"
            )

        # 3. Complexity gate
        complexity = metrics_snapshot.complexity_max
        max_cx = self._thresholds.get("max_complexity", 20.0)
        cx_pass = complexity <= max_cx
        evaluations["complexity"] = {
            "value": complexity,
            "threshold": max_cx,
            "passed": cx_pass,
        }
        if not cx_pass:
            failures.append(
                f"Max complexity {complexity:.1f} exceeds threshold {max_cx:.1f}"
            )
            score_deductions += 15.0

        # 4. Drift score gate
        drift_score = drift_report.drift_score
        max_drift = self._thresholds.get("max_drift_score", 50.0)
        drift_pass = drift_score <= max_drift
        evaluations["drift_score"] = {
            "value": drift_score,
            "threshold": max_drift,
            "passed": drift_pass,
        }
        if not drift_pass:
            failures.append(
                f"Drift score {drift_score:.1f} exceeds threshold {max_drift:.1f}"
            )
            score_deductions += 20.0
        elif drift_score > max_drift * 0.7:
            warnings.append(
                f"Drift score {drift_score:.1f} approaching threshold {max_drift:.1f}"
            )

        # 5. Drift events volume gate
        total_drift_events = (
            len(drift_report.files_added)
            + len(drift_report.files_removed)
            + len(drift_report.files_modified)
        )
        max_events = self._thresholds.get("max_drift_events", 10)
        events_pass = total_drift_events <= max_events
        evaluations["drift_events"] = {
            "value": total_drift_events,
            "threshold": max_events,
            "passed": events_pass,
        }
        if not events_pass:
            failures.append(
                f"Drift events ({total_drift_events}) exceed threshold ({max_events})"
            )
            score_deductions += 10.0

        # 6. Health check gate
        health_score = health_result.get("health_score", 0.0)
        min_health = self._thresholds.get("min_health_checks_passed", 0.7)
        health_pass = health_score >= min_health
        evaluations["health_checks"] = {
            "value": health_score,
            "threshold": min_health,
            "passed": health_pass,
        }
        if not health_pass:
            failures.append(
                f"Health score {health_score:.1f}% below threshold {min_health:.1f}%"
            )
            score_deductions += 10.0

        # 7. Regression check
        if drift_report.regression_detected:
            failures.append(
                f"Regression detected: {len(drift_report.regression_details)} issue(s)"
            )
            score_deductions += 15.0
            for detail in drift_report.regression_details:
                warnings.append(f"Regression: {detail}")

        # Calculate aggregate score
        score = max(0.0, 100.0 - score_deductions)
        passed = len(failures) == 0

        return QualityGateResult(
            passed=passed,
            score=score,
            thresholds=dict(self._thresholds),
            evaluations=evaluations,
            failures=failures,
            warnings=warnings,
        )

    def engineering_workflow(
        self,
        create_baseline_if_missing: bool = True,
        record_metrics: bool = True,
    ) -> Dict[str, Any]:
        """Run the full engineering pipeline.

        Executes health check, drift detection, metrics collection,
        and quality gate evaluation in sequence.

        Parameters
        ----------
        create_baseline_if_missing : bool
            Auto-capture a baseline if none exists during drift detection.
        record_metrics : bool
            Whether to persist metrics snapshot to history.

        Returns
        -------
        dict
            Complete pipeline result with all sub-results and
            aggregate quality gate verdict.
        """
        pipeline_start = time.perf_counter()
        result: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_path": str(self._repo),
            "pipeline": "engineering_workflow",
        }

        # Step 1: Health check
        t0 = time.perf_counter()
        health = self.health_check()
        result["health_check"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "result": health,
        }

        # Step 2: Drift detection
        t0 = time.perf_counter()
        drift = self.drift_detection(
            create_baseline_if_missing=create_baseline_if_missing,
        )
        result["drift_detection"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "result": drift,
        }

        # Step 3: Metrics collection
        t0 = time.perf_counter()
        metrics_snapshot = self._metrics.collect_current_metrics()
        if record_metrics:
            self._metrics.record_snapshot(metrics_snapshot)
        result["metrics"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "snapshot": metrics_snapshot.to_dict(),
            "trends": {
                "coverage": self._metrics.get_coverage_trend(),
                "debt": self._metrics.get_debt_trend(),
                "complexity": self._metrics.get_complexity_trend(),
                "test_pass_rate": self._metrics.get_test_pass_rate_trend(),
            },
        }

        # Step 4: Quality gate
        t0 = time.perf_counter()
        drift_report = DriftReport()
        drift_data = drift.get("drift", {})
        if isinstance(drift_data, dict):
            drift_report = DriftReport(
                baseline_name=drift_data.get("baseline_name", ""),
                baseline_timestamp=drift_data.get("baseline_timestamp", ""),
                current_timestamp=drift_data.get("current_timestamp", ""),
                files_added=drift_data.get("files_added", []),
                files_removed=drift_data.get("files_removed", []),
                files_modified=drift_data.get("files_modified", []),
                drift_events=drift_data.get("drift_events", []),
                drift_score=drift_data.get("drift_score", 0.0),
                regression_detected=drift_data.get("regression_detected", False),
                regression_details=drift_data.get("regression_details", []),
            )

        gate = self.quality_gate(
            metrics_snapshot=metrics_snapshot,
            drift_report=drift_report,
            health_result=health,
        )
        result["quality_gate"] = {
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "result": gate.to_dict(),
        }

        # Aggregate summary
        total_ms = (time.perf_counter() - pipeline_start) * 1000.0
        result["summary"] = {
            "total_duration_ms": round(total_ms, 2),
            "quality_gate_passed": gate.passed,
            "quality_gate_score": gate.score,
            "drift_score": drift_report.drift_score,
            "health_score": health.get("health_score", 0.0),
            "regression_detected": drift_report.regression_detected,
            "files_analyzed": metrics_snapshot.file_count,
        }

        # Emit observability event via plugin hook if available
        try:
            from .plugins import HookManager
            HookManager.fire(
                "engineering_workflow_complete",
                result=result,
            )
        except Exception:
            pass

        return result

    # -- Properties -------------------------------------------------------

    @property
    def metrics(self) -> EngineeringMetrics:
        """Access the underlying metrics collector."""
        return self._metrics

    @property
    def baseline_manager(self) -> EngineeringBaseline:
        """Access the underlying baseline manager."""
        return self._baseline

    # -- Internal Helpers --------------------------------------------------

    @staticmethod
    def _compute_health_score(diag_result: Dict[str, Any]) -> float:
        """Compute a 0-100 health score from diagnostics results."""
        total = diag_result.get("total_checks", 0)
        passed = diag_result.get("passed", 0)
        if total == 0:
            return 100.0
        return round(passed / total * 100.0, 2)

    # DEAD CODE: consider removal
    def _check_repository_health(self) -> Dict[str, Any]:
        """Run repository-specific health checks.

        Checks:
        - Repository directory exists and is accessible
        - Source file count
        - Presence of test files
        - Presence of configuration files
        - Presence of documentation
        """
        checks: Dict[str, Any] = {}

        # Directory exists
        checks["repo_exists"] = self._repo.is_dir()

        # Count source files
        source_files = self._metrics._walk_source_files()
        checks["source_file_count"] = len(source_files)

        # Test file detection
        test_files = [
            f for f in source_files
            if "test" in f.name.lower()
            or "tests" in f.parts
            or "test_" in f.name
            or f.name.startswith("test_")
            or f.name.endswith("_test.py")
        ]
        checks["test_file_count"] = len(test_files)
        checks["has_tests"] = len(test_files) > 0

        # Configuration file detection
        config_patterns = [
            "setup.py", "setup.cfg", "pyproject.toml",
            "package.json", "Cargo.toml", "go.mod",
            "Makefile", "CMakeLists.txt", "build.gradle",
            ".github", ".gitlab-ci.yml", "Jenkinsfile",
        ]
        found_configs = []
        for pattern in config_patterns:
            if (self._repo / pattern).exists():
                found_configs.append(pattern)
        checks["config_files"] = found_configs
        checks["has_build_config"] = len(found_configs) > 0

        # Documentation detection
        doc_patterns = ["README.md", "README.rst", "README.txt", "docs/"]
        found_docs = []
        for pattern in doc_patterns:
            if (self._repo / pattern).exists():
                found_docs.append(pattern)
        checks["documentation_files"] = found_docs
        checks["has_documentation"] = len(found_docs) > 0

        # VCS detection
        checks["has_vcs"] = (self._repo / ".git").is_dir()

        return checks


# ═══════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def run_engineering_workflow(
    repo_path: str = ".",
    thresholds: Optional[Dict[str, float]] = None,
    record_metrics: bool = True,
) -> Dict[str, Any]:
    """Convenience function to run the full engineering workflow.

    Parameters
    ----------
    repo_path : str
        Repository root directory.
    thresholds : dict[str, float] | None
        Quality gate thresholds.
    record_metrics : bool
        Whether to persist metrics.

    Returns
    -------
    dict
        Complete pipeline result.

    Usage::

        result = run_engineering_workflow("/path/to/repo")
        if result["summary"]["quality_gate_passed"]:
            print("All quality gates passed!")
    """
    pipeline = EngineeringPipeline(
        repo_path=repo_path,
        thresholds=thresholds,
    )
    return pipeline.engineering_workflow(record_metrics=record_metrics)


# DEAD CODE: consider removal
def run_quality_gate(
    repo_path: str = ".",
    thresholds: Optional[Dict[str, float]] = None,
) -> QualityGateResult:
    """Convenience function to run only the quality gate.

    Parameters
    ----------
    repo_path : str
        Repository root directory.
    thresholds : dict[str, float] | None
        Quality gate thresholds.

    Returns
    -------
    QualityGateResult
        Pass/fail result.
    """
    pipeline = EngineeringPipeline(
        repo_path=repo_path,
        thresholds=thresholds,
    )
    return pipeline.quality_gate()


def capture_baseline(
    repo_path: str = ".",
    name: str = "",
) -> BaselineSnapshot:
    """Convenience function to capture a baseline snapshot.

    Parameters
    ----------
    repo_path : str
        Repository root directory.
    name : str
        Baseline name. Defaults to auto-generated.

    Returns
    -------
    BaselineSnapshot
        The captured baseline.
    """
    baseline = EngineeringBaseline(repo_path=repo_path)
    return baseline.capture_snapshot(name=name)
