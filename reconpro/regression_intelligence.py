"""ReconPro v11.2.0 — Regression Intelligence System.

Provides intelligent regression detection and management for the ReconPro
platform.  This is the *intelligence layer* that sits above the specific
test suites in ``tests/test_regression_v11.py`` and
``tests/test_security_regression.py``.

Core responsibilities:
    - Capture and version performance/behaviour baselines
    - Detect regressions by comparing current results against baselines
    - Classify regressions (performance, correctness, API, behaviour)
    - Assess impact severity
    - Track regression history and analyse trends
    - Generate comprehensive regression reports

Persistence:
    - Baselines:  RECONPRO_HOME/memory/regression_baseline.json
    - History:    RECONPRO_HOME/memory/regression_history.json

Zero external dependencies — pure Python + stdlib only.
"""

from __future__ import annotations

import json
import logging
import math
import os
import statistics
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import RECONPRO_HOME, MEMORY_DIR, SEVERITY_LEVELS

# ── Module paths ──────────────────────────────────────────────────────────

_BASELINE_PATH: Path = MEMORY_DIR / "regression_baseline.json"
_HISTORY_PATH: Path = MEMORY_DIR / "regression_history.json"

logger = logging.getLogger("reconpro.regression_intelligence")

# ── Enumerations ─────────────────────────────────────────────────────────


class RegressionType(str, Enum):
    """Classification of regression types."""
    PERFORMANCE = "performance"
    CORRECTNESS = "correctness"
    API = "api"
    BEHAVIOUR = "behaviour"


class RegressionSeverity(str, Enum):
    """Impact severity levels for detected regressions."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RegressionStatus(str, Enum):
    """Lifecycle status of a regression record."""
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    INVESTIGATING = "investigating"
    FIXED = "fixed"
    WONTFIX = "wontfix"
    FALSE_POSITIVE = "false_positive"


# ── Data Classes ─────────────────────────────────────────────────────────


@dataclass
class RegressionRecord:
    """Immutable record of a single detected regression.

    Attributes:
        id: Unique identifier (UUID4).
        type: Classification (performance, correctness, api, behaviour).
        description: Human-readable description of the regression.
        baseline_value: The expected/baseline value.
        current_value: The observed current value.
        delta: Absolute difference |current - baseline|.
        severity: Impact severity.
        affected_component: Module, function, or subsystem affected.
        detected_at: ISO-8601 timestamp of detection.
        status: Current lifecycle status.
        evidence: Dict of supporting evidence (metrics, stack traces, etc.).
    """
    id: str = ""
    type: RegressionType = RegressionType.PERFORMANCE
    description: str = ""
    baseline_value: Any = None
    current_value: Any = None
    delta: float = 0.0
    severity: RegressionSeverity = RegressionSeverity.MEDIUM
    affected_component: str = ""
    detected_at: str = ""
    status: RegressionStatus = RegressionStatus.DETECTED
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "id": self.id,
            "type": self.type.value if isinstance(self.type, RegressionType) else self.type,
            "description": self.description,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "delta": self.delta,
            "severity": self.severity.value if isinstance(self.severity, RegressionSeverity) else self.severity,
            "affected_component": self.affected_component,
            "detected_at": self.detected_at,
            "status": self.status.value if isinstance(self.status, RegressionStatus) else self.status,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegressionRecord":
        """Deserialize from a dict, converting enum strings back."""
        type_val = data.get("type", "performance")
        if isinstance(type_val, str):
            type_val = RegressionType(type_val)

        sev_val = data.get("severity", "medium")
        if isinstance(sev_val, str):
            sev_val = RegressionSeverity(sev_val)

        status_val = data.get("status", "detected")
        if isinstance(status_val, str):
            status_val = RegressionStatus(status_val)

        return cls(
            id=data.get("id", ""),
            type=type_val,
            description=data.get("description", ""),
            baseline_value=data.get("baseline_value"),
            current_value=data.get("current_value"),
            delta=float(data.get("delta", 0.0)),
            severity=sev_val,
            affected_component=data.get("affected_component", ""),
            detected_at=data.get("detected_at", ""),
            status=status_val,
            evidence=data.get("evidence", {}),
        )


# ── BaselineManager ──────────────────────────────────────────────────────


class BaselineManager:
    """Manages regression baselines with versioning and persistence.

    Stores baselines at ``RECONPRO_HOME/memory/regression_baseline.json``.
    Each baseline entry is versioned by timestamp and can be compared,
    exported, and imported.

    Usage::

        bm = BaselineManager()
        bm.capture("score_bounds", {"min": 0, "max": 100})
        bm.capture("module_count", {"remote": 25, "local": 3})
        baseline = bm.get("score_bounds")
        bm.export("/tmp/baselines.json")
    """

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._path = storage_path or _BASELINE_PATH
        self._baselines: Dict[str, List[Dict[str, Any]]] = {}
        self._ensure_dir()
        self._load()

    def _ensure_dir(self) -> None:
        """Ensure the memory directory exists."""
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> None:
        """Load baselines from disk."""
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    self._baselines = json.load(fh)
                logger.debug("Loaded %d baseline keys from %s",
                              len(self._baselines), self._path)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load baselines: %s", exc)
                self._baselines = {}

    def _save(self) -> None:
        """Persist baselines to disk."""
        try:
            self._ensure_dir()
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(self._baselines, fh, indent=2, default=str)
            logger.debug("Saved %d baseline keys to %s",
                          len(self._baselines), self._path)
        except OSError as exc:
            logger.error("Failed to save baselines: %s", exc)

    # ── Public API ──────────────────────────────────────────────────────

    def capture(
        self,
        key: str,
        value: Any,
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Capture a baseline measurement under *key*.

        Args:
            key: Unique baseline identifier (e.g. ``"score_bounds"``).
            value: The baseline value (dict, list, number, string).
            label: Optional human-readable label.
            metadata: Optional extra context.

        Returns:
            The stored baseline entry dict.
        """
        entry: Dict[str, Any] = {
            "key": key,
            "value": value,
            "label": label,
            "metadata": metadata or {},
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "version": len(self._baselines.get(key, [])) + 1,
        }
        self._baselines.setdefault(key, []).append(entry)
        self._save()
        logger.info("Captured baseline '%s' v%d", key, entry["version"])
        return entry

    def get(self, key: str, version: Optional[int] = None) -> Optional[Any]:
        """Retrieve a baseline value.

        Args:
            key: Baseline identifier.
            version: Specific version (latest if None).

        Returns:
            The baseline value, or None if not found.
        """
        entries = self._baselines.get(key)
        if not entries:
            return None
        if version is not None:
            for e in entries:
                if e.get("version") == version:
                    return e.get("value")
            return None
        return entries[-1].get("value")

    def get_entry(self, key: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a full baseline entry (including metadata).

        Args:
            key: Baseline identifier.
            version: Specific version (latest if None).

        Returns:
            The full baseline entry dict, or None.
        """
        entries = self._baselines.get(key)
        if not entries:
            return None
        if version is not None:
            for e in entries:
                if e.get("version") == version:
                    return e
            return None
        return entries[-1]

    def list_keys(self) -> List[str]:
        """Return all baseline keys."""
        return sorted(self._baselines.keys())

    def versions(self, key: str) -> int:
        """Return the number of versions for *key*."""
        return len(self._baselines.get(key, []))

    def compare_versions(
        self, key: str, v_a: int, v_b: int
    ) -> Optional[Dict[str, Any]]:
        """Compare two versions of the same baseline.

        Returns a dict with ``version_a``, ``version_b``, ``value_a``,
        ``value_b``, and ``same`` (bool).
        """
        val_a = self.get(key, v_a)
        val_b = self.get(key, v_b)
        if val_a is None or val_b is None:
            return None
        return {
            "key": key,
            "version_a": v_a,
            "version_b": v_b,
            "value_a": val_a,
            "value_b": val_b,
            "same": val_a == val_b,
        }

    def compare_to_latest(
        self, key: str, current_value: Any
    ) -> Optional[Dict[str, Any]]:
        """Compare a *current_value* against the latest baseline for *key*.

        Returns a dict with ``baseline``, ``current``, ``same``, and
        ``entry`` metadata.
        """
        latest = self.get_entry(key)
        if latest is None:
            return None
        baseline_value = latest.get("value")
        return {
            "key": key,
            "baseline": baseline_value,
            "current": current_value,
            "same": baseline_value == current_value,
            "entry": latest,
        }

    def export(self, path: str) -> str:
        """Export all baselines to a JSON file.

        Args:
            path: Destination file path.

        Returns:
            The absolute path written.
        """
        abs_path = os.path.abspath(path)
        os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as fh:
            json.dump(self._baselines, fh, indent=2, default=str)
        logger.info("Exported %d baseline keys to %s",
                    len(self._baselines), abs_path)
        return abs_path

    def import_baseline(self, path: str, overwrite: bool = False) -> int:
        """Import baselines from a JSON file.

        Args:
            path: Source file path.
            overwrite: Replace existing keys if True, merge otherwise.

        Returns:
            Number of keys imported.
        """
        with open(path, "r", encoding="utf-8") as fh:
            incoming = json.load(fh)

        count = 0
        for key, entries in incoming.items():
            if overwrite or key not in self._baselines:
                self._baselines[key] = entries
                count += 1
            else:
                # Merge: append new versions
                for e in entries:
                    e_ver = e.get("version", 0)
                    existing_vers = {ex.get("version") for ex in self._baselines[key]}
                    if e_ver not in existing_vers:
                        self._baselines[key].append(e)
                        count += 1
        self._save()
        logger.info("Imported %d baseline keys from %s", count, path)
        return count

    def remove(self, key: str) -> bool:
        """Remove a baseline key entirely."""
        if key in self._baselines:
            del self._baselines[key]
            self._save()
            return True
        return False

    def clear(self) -> int:
        """Remove all baselines. Returns count of removed keys."""
        count = len(self._baselines)
        self._baselines.clear()
        self._save()
        return count

    @property
    def all_baselines(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the full baseline dict (read-only copy semantics)."""
        return dict(self._baselines)


# ── RegressionDetector ──────────────────────────────────────────────────


class RegressionDetector:
    """Detection algorithms for identifying regressions.

    Provides multiple detection strategies:
        - **Performance regression**: Threshold-based (absolute % and
          absolute value)
        - **Correctness regression**: Test failure pattern detection
        - **API regression**: Interface signature changes
        - **Statistical regression**: Trend analysis using stdlib
          ``statistics``

    All detectors return ``RegressionRecord`` objects or empty lists.
    """

    # Default detection thresholds
    DEFAULT_PERF_PERCENT_THRESHOLD: float = 10.0  # 10% degradation
    DEFAULT_PERF_ABSOLUTE_THRESHOLD: float = 5.0
    DEFAULT_STAT_MIN_SAMPLES: int = 5
    DEFAULT_STAT_Z_THRESHOLD: float = 2.0

    def __init__(
        self,
        perf_percent: Optional[float] = None,
        perf_absolute: Optional[float] = None,
        stat_min_samples: Optional[int] = None,
        stat_z_threshold: Optional[float] = None,
    ) -> None:
        self._perf_percent = (
            perf_percent if perf_percent is not None
            else self.DEFAULT_PERF_PERCENT_THRESHOLD
        )
        self._perf_absolute = (
            perf_absolute if perf_absolute is not None
            else self.DEFAULT_PERF_ABSOLUTE_THRESHOLD
        )
        self._stat_min_samples = (
            stat_min_samples if stat_min_samples is not None
            else self.DEFAULT_STAT_MIN_SAMPLES
        )
        self._stat_z_threshold = (
            stat_z_threshold if stat_z_threshold is not None
            else self.DEFAULT_STAT_Z_THRESHOLD
        )

    # ── Performance Detection ──────────────────────────────────────────

    def detect_performance_regressions(
        self,
        baselines: Dict[str, float],
        current: Dict[str, float],
        component: str = "",
        percent_threshold: Optional[float] = None,
        absolute_threshold: Optional[float] = None,
    ) -> List[RegressionRecord]:
        """Detect performance regressions by comparing numeric metrics.

        A performance regression is flagged when the current value exceeds
        the baseline by either:
            1. *percent_threshold* % (default 10%) of the baseline value, OR
            2. *absolute_threshold* (default 5.0) absolute units

        Higher-is-worse metrics (e.g. latency, error rate): current > baseline
        is a regression.
        Lower-is-worse metrics (e.g. score, throughput): current < baseline
        is a regression.  These should be stored as negative values in both
        *baselines* and *current*.

        Args:
            baselines: Dict mapping metric_name -> baseline_value.
            current: Dict mapping metric_name -> current_value.
            component: Affected component name.
            percent_threshold: Override default % threshold.
            absolute_threshold: Override default absolute threshold.

        Returns:
            List of RegressionRecord for each detected regression.
        """
        pct_thr = percent_threshold if percent_threshold is not None else self._perf_percent
        abs_thr = absolute_threshold if absolute_threshold is not None else self._perf_absolute
        regressions: List[RegressionRecord] = []

        for metric, baseline_val in baselines.items():
            if metric not in current:
                continue
            cur_val = current[metric]

            if not isinstance(baseline_val, (int, float)) or not isinstance(cur_val, (int, float)):
                continue

            # Skip zero baselines for percentage calc
            if baseline_val == 0 and cur_val == 0:
                continue

            delta = cur_val - baseline_val
            pct_change = abs(delta / baseline_val * 100) if baseline_val != 0 else float("inf")

            is_regression = False
            if delta > 0 and baseline_val >= 0:
                # Higher-is-worse: current > baseline is bad
                is_regression = pct_change >= pct_thr or abs(delta) >= abs_thr
            elif delta < 0 and baseline_val < 0:
                # Lower-is-worse (negative convention): current < baseline
                # means cur is more negative = worse
                is_regression = pct_change >= pct_thr or abs(delta) >= abs_thr

            if is_regression:
                severity = self._performance_severity(pct_change, delta)
                regressions.append(RegressionRecord(
                    type=RegressionType.PERFORMANCE,
                    description=(
                        f"Performance regression in '{metric}': "
                        f"baseline={baseline_val}, current={cur_val}, "
                        f"delta={delta:+.2f} ({pct_change:.1f}%)"
                    ),
                    baseline_value=baseline_val,
                    current_value=cur_val,
                    delta=delta,
                    severity=severity,
                    affected_component=component or metric,
                    evidence={
                        "metric": metric,
                        "percent_change": round(pct_change, 2),
                        "absolute_change": round(delta, 4),
                        "percent_threshold": pct_thr,
                        "absolute_threshold": abs_thr,
                    },
                ))

        return regressions

    def _performance_severity(
        self, percent_change: float, delta: float
    ) -> RegressionSeverity:
        """Map performance degradation magnitude to severity."""
        if percent_change >= 50 or abs(delta) >= 50:
            return RegressionSeverity.CRITICAL
        elif percent_change >= 25 or abs(delta) >= 20:
            return RegressionSeverity.HIGH
        elif percent_change >= 10 or abs(delta) >= 5:
            return RegressionSeverity.MEDIUM
        else:
            return RegressionSeverity.LOW

    # ── Correctness Detection ──────────────────────────────────────────

    def detect_correctness_regressions(
        self,
        baseline_results: Dict[str, bool],
        current_results: Dict[str, bool],
        component: str = "",
    ) -> List[RegressionRecord]:
        """Detect correctness regressions from pass/fail patterns.

        A correctness regression occurs when a test or check that previously
        passed now fails.

        Args:
            baseline_results: Dict mapping test_name -> True/False.
            current_results: Dict mapping test_name -> True/False.
            component: Affected component name.

        Returns:
            List of RegressionRecord for newly-failing checks.
        """
        regressions: List[RegressionRecord] = []

        for test_name, baseline_pass in baseline_results.items():
            if test_name not in current_results:
                continue
            current_pass = current_results[test_name]
            if baseline_pass and not current_pass:
                severity = RegressionSeverity.HIGH
                regressions.append(RegressionRecord(
                    type=RegressionType.CORRECTNESS,
                    description=(
                        f"Correctness regression: '{test_name}' "
                        f"previously passed, now fails"
                    ),
                    baseline_value=True,
                    current_value=False,
                    delta=1.0,
                    severity=severity,
                    affected_component=component or test_name,
                    evidence={
                        "test": test_name,
                        "baseline_passed": True,
                        "current_passed": False,
                    },
                ))

        return regressions

    # ── API Detection ──────────────────────────────────────────────────

    def detect_api_regressions(
        self,
        baseline_api: Dict[str, Dict[str, Any]],
        current_api: Dict[str, Dict[str, Any]],
        component: str = "",
    ) -> List[RegressionRecord]:
        """Detect API regressions from interface signature changes.

        Compares API signatures represented as dicts:
            ``{"func_name": {"params": [...], "return_type": "...", "exists": True}}``

        Flags:
            - Functions removed (``exists: True -> False``)
            - Required parameters added
            - Return type changed
            - Functions removed entirely

        Args:
            baseline_api: Baseline API signatures.
            current_api: Current API signatures.
            component: Affected component name.

        Returns:
            List of RegressionRecord for API changes.
        """
        regressions: List[RegressionRecord] = []

        for func_name, baseline_sig in baseline_api.items():
            if func_name not in current_api:
                regressions.append(RegressionRecord(
                    type=RegressionType.API,
                    description=f"API regression: '{func_name}' removed entirely",
                    baseline_value={"exists": True, **baseline_sig},
                    current_value=None,
                    delta=1.0,
                    severity=RegressionSeverity.CRITICAL,
                    affected_component=component or func_name,
                    evidence={"func": func_name, "change": "removed"},
                ))
                continue

            cur_sig = current_api[func_name]

            # Check if function was removed
            if baseline_sig.get("exists", True) and not cur_sig.get("exists", True):
                regressions.append(RegressionRecord(
                    type=RegressionType.API,
                    description=f"API regression: '{func_name}' marked as removed",
                    baseline_value=baseline_sig,
                    current_value=cur_sig,
                    delta=1.0,
                    severity=RegressionSeverity.CRITICAL,
                    affected_component=component or func_name,
                    evidence={"func": func_name, "change": "disabled"},
                ))

            # Check for required parameters added
            base_params = set(baseline_sig.get("params", []))
            cur_params = set(cur_sig.get("params", []))
            new_required = cur_params - base_params
            optional_new = cur_sig.get("optional_params", set())
            new_required -= optional_new

            if new_required:
                regressions.append(RegressionRecord(
                    type=RegressionType.API,
                    description=(
                        f"API regression: '{func_name}' gained required "
                        f"parameters: {sorted(new_required)}"
                    ),
                    baseline_value=sorted(base_params),
                    current_value=sorted(cur_params),
                    delta=float(len(new_required)),
                    severity=RegressionSeverity.HIGH,
                    affected_component=component or func_name,
                    evidence={
                        "func": func_name,
                        "change": "required_params_added",
                        "new_params": sorted(new_required),
                    },
                ))

            # Check for return type changes
            base_return = baseline_sig.get("return_type", "")
            cur_return = cur_sig.get("return_type", "")
            if base_return and cur_return and base_return != cur_return:
                regressions.append(RegressionRecord(
                    type=RegressionType.API,
                    description=(
                        f"API regression: '{func_name}' return type changed "
                        f"from '{base_return}' to '{cur_return}'"
                    ),
                    baseline_value=base_return,
                    current_value=cur_return,
                    delta=1.0,
                    severity=RegressionSeverity.MEDIUM,
                    affected_component=component or func_name,
                    evidence={
                        "func": func_name,
                        "change": "return_type_changed",
                        "old": base_return,
                        "new": cur_return,
                    },
                ))

        return regressions

    # ── Statistical Detection ──────────────────────────────────────────

    def detect_statistical_regressions(
        self,
        metric_name: str,
        values: List[float],
        new_value: float,
        component: str = "",
        min_samples: Optional[int] = None,
        z_threshold: Optional[float] = None,
    ) -> List[RegressionRecord]:
        """Detect statistical regressions using z-score analysis.

        Builds a distribution from historical *values* and checks if
        *new_value* is an outlier beyond *z_threshold* standard deviations.

        A regression is detected when the new value significantly deviates
        in the *worse* direction.  For positive-metrics (higher is worse,
        e.g. latency), deviations above are regressions.  The detector
        auto-detects direction by checking if the new value is above the
        mean (positive deviation = regression for higher-is-worse).

        Args:
            metric_name: Name of the metric being checked.
            values: Historical values to build the distribution.
            new_value: The new value to check.
            component: Affected component name.
            min_samples: Minimum historical samples required (default 5).
            z_threshold: Z-score threshold (default 2.0).

        Returns:
            List of RegressionRecord (0 or 1).
        """
        min_samp = min_samples if min_samples is not None else self._stat_min_samples
        z_thr = z_threshold if z_threshold is not None else self._stat_z_threshold

        if len(values) < min_samp:
            return []

        try:
            mean_val = statistics.mean(values)
            stdev = statistics.stdev(values) if len(values) > 1 else 0.0
        except (statistics.StatisticsError, ZeroDivisionError):
            return []

        if stdev == 0:
            return []

        z_score = (new_value - mean_val) / stdev

        # Detect if this is a regression (significant deviation)
        is_regression = abs(z_score) >= z_thr

        if not is_regression:
            return []

        # Determine severity from z-score magnitude
        severity = self._statistical_severity(z_score)

        direction = "above" if z_score > 0 else "below"
        regressions = [RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description=(
                f"Statistical regression in '{metric_name}': "
                f"z-score={z_score:.2f} ({direction} mean), "
                f"mean={mean_val:.2f}, stdev={stdev:.2f}, "
                f"new={new_value:.2f}"
            ),
            baseline_value={"mean": round(mean_val, 4), "stdev": round(stdev, 4)},
            current_value=new_value,
            delta=z_score,
            severity=severity,
            affected_component=component or metric_name,
            evidence={
                "metric": metric_name,
                "z_score": round(z_score, 4),
                "mean": round(mean_val, 4),
                "stdev": round(stdev, 4),
                "sample_count": len(values),
                "z_threshold": z_thr,
                "direction": direction,
            },
        )]

        return regressions

    def _statistical_severity(self, z_score: float) -> RegressionSeverity:
        """Map z-score magnitude to severity."""
        abs_z = abs(z_score)
        if abs_z >= 4.0:
            return RegressionSeverity.CRITICAL
        elif abs_z >= 3.0:
            return RegressionSeverity.HIGH
        elif abs_z >= 2.0:
            return RegressionSeverity.MEDIUM
        else:
            return RegressionSeverity.LOW

    # ── Behaviour Detection ────────────────────────────────────────────

    def detect_behaviour_regressions(
        self,
        baseline_findings: List[Dict[str, Any]],
        current_findings: List[Dict[str, Any]],
        component: str = "",
    ) -> List[RegressionRecord]:
        """Detect behaviour regressions by comparing finding patterns.

        Uses the delta engine's comparison logic to identify:
            - New findings of critical/high severity (new vulnerabilities)
            - Severity escalations on existing findings
            - Significant increase in total finding count

        Args:
            baseline_findings: List of baseline finding dicts.
            current_findings: List of current finding dicts.
            component: Affected component name.

        Returns:
            List of RegressionRecord for behavioural changes.
        """
        regressions: List[RegressionRecord] = []

        baseline_by_title = {
            f.get("title", "") or "": f for f in baseline_findings
        }
        current_by_title = {
            f.get("title", "") or "": f for f in current_findings
        }
        baseline_titles = set(baseline_by_title.keys())
        current_titles = set(current_by_title.keys())

        # New findings
        new_titles = current_titles - baseline_titles
        for title in sorted(new_titles):
            finding = current_by_title[title]
            sev = (finding.get("severity") or "").lower()
            if sev in ("critical", "high"):
                regressions.append(RegressionRecord(
                    type=RegressionType.BEHAVIOUR,
                    description=(
                        f"New {sev}-severity finding detected: '{title}'"
                    ),
                    baseline_value=None,
                    current_value=sev,
                    delta=1.0,
                    severity=(
                        RegressionSeverity.CRITICAL
                        if sev == "critical"
                        else RegressionSeverity.HIGH
                    ),
                    affected_component=component or finding.get("module", "unknown"),
                    evidence={
                        "finding": title,
                        "severity": sev,
                        "change": "new_finding",
                        "finding_data": finding,
                    },
                ))

        # Severity escalations on persistent findings
        persistent_titles = baseline_titles & current_titles
        for title in sorted(t for t in persistent_titles if t is not None):
            base_sev = (baseline_by_title[title].get("severity") or "").lower()
            cur_sev = (current_by_title[title].get("severity") or "").lower()
            base_rank = SEVERITY_LEVELS.get(base_sev, 99)
            cur_rank = SEVERITY_LEVELS.get(cur_sev, 99)
            if cur_rank < base_rank:  # Lower number = higher severity = worse
                regressions.append(RegressionRecord(
                    type=RegressionType.BEHAVIOUR,
                    description=(
                        f"Severity escalation: '{title}' changed from "
                        f"{base_sev} to {cur_sev}"
                    ),
                    baseline_value=base_sev,
                    current_value=cur_sev,
                    delta=float(base_rank - cur_rank),
                    severity=(
                        RegressionSeverity.CRITICAL
                        if cur_sev == "critical"
                        else RegressionSeverity.HIGH
                    ),
                    affected_component=component or current_by_title[title].get("module", "unknown"),
                    evidence={
                        "finding": title,
                        "old_severity": base_sev,
                        "new_severity": cur_sev,
                        "change": "severity_escalation",
                    },
                ))

        # Significant finding count increase
        base_count = len(baseline_findings)
        cur_count = len(current_findings)
        if base_count > 0:
            count_pct = (cur_count - base_count) / base_count * 100
            if count_pct >= 50 and (cur_count - base_count) >= 3:
                regressions.append(RegressionRecord(
                    type=RegressionType.BEHAVIOUR,
                    description=(
                        f"Finding count increased significantly: "
                        f"{base_count} -> {cur_count} (+{count_pct:.1f}%)"
                    ),
                    baseline_value=base_count,
                    current_value=cur_count,
                    delta=float(cur_count - base_count),
                    severity=RegressionSeverity.MEDIUM,
                    affected_component=component or "global",
                    evidence={
                        "change": "count_increase",
                        "baseline_count": base_count,
                        "current_count": cur_count,
                        "percent_change": round(count_pct, 2),
                    },
                ))

        return regressions


# ── RegressionIntelligence ─────────────────────────────────────────────


class RegressionIntelligence:
    """Top-level regression intelligence orchestrator.

    Combines ``BaselineManager`` and ``RegressionDetector`` into a unified
    API for baseline capture, regression detection, classification, impact
    assessment, history tracking, and report generation.

    Usage::

        ri = RegressionIntelligence()
        ri.capture_baseline("scan_results", my_scan_data)

        regressions = ri.detect_regression(current_scan_data)
        for r in regressions:
            print(f"[{r.severity.value}] {r.description}")

        report = ri.generate_regression_report()
        print(report)
    """

    def __init__(
        self,
        baseline_path: Optional[Path] = None,
        history_path: Optional[Path] = None,
        perf_percent: Optional[float] = None,
        perf_absolute: Optional[float] = None,
    ) -> None:
        self._baseline_mgr = BaselineManager(
            storage_path=baseline_path or _BASELINE_PATH
        )
        self._history_path = history_path or _HISTORY_PATH
        self._history: List[RegressionRecord] = []
        self._detector = RegressionDetector(
            perf_percent=perf_percent,
            perf_absolute=perf_absolute,
        )
        self._load_history()

    def _ensure_dir(self) -> None:
        self._history_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_history(self) -> None:
        """Load regression history from disk."""
        self._ensure_dir()
        if self._history_path.exists():
            try:
                with open(self._history_path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                self._history = [RegressionRecord.from_dict(r) for r in raw]
                logger.debug("Loaded %d regression history records", len(self._history))
            except (json.JSONDecodeError, OSError, TypeError) as exc:
                logger.warning("Failed to load regression history: %s", exc)
                self._history = []

    def _save_history(self) -> None:
        """Persist regression history to disk."""
        try:
            self._ensure_dir()
            with open(self._history_path, "w", encoding="utf-8") as fh:
                json.dump(
                    [r.to_dict() for r in self._history],
                    fh,
                    indent=2,
                    default=str,
                )
            logger.debug("Saved %d regression history records", len(self._history))
        except OSError as exc:
            logger.error("Failed to save regression history: %s", exc)

    # ── Baseline Capture ──────────────────────────────────────────────

    def capture_baseline(
        self,
        key: str,
        data: Dict[str, Any],
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Capture a performance/behavior baseline.

        The baseline data should be a scan result dict or a metrics dict.
        The system stores it under *key* for later comparison.

        Args:
            key: Unique baseline identifier.
            data: Scan results or metrics to baseline.
            label: Human-readable label.
            metadata: Additional context.

        Returns:
            The stored baseline entry.
        """
        return self._baseline_mgr.capture(key, data, label=label, metadata=metadata)

    # ── Regression Detection ──────────────────────────────────────────

    def detect_regression(
        self,
        current_results: Dict[str, Any],
        baseline_key: Optional[str] = None,
        performance_metrics: Optional[Dict[str, float]] = None,
        correctness_results: Optional[Dict[str, bool]] = None,
        api_signatures: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[RegressionRecord]:
        """Run full regression detection against current results.

        Compares *current_results* against the baseline stored at
        *baseline_key* (or all baselines if None).

        If specific metric dicts are provided, only those detectors run.
        Otherwise, the system extracts metrics from the scan data dicts.

        Args:
            current_results: Current scan result or metric dict.
            baseline_key: Specific baseline to compare against (None = all).
            performance_metrics: Explicit perf metrics to check.
            correctness_results: Explicit pass/fail results.
            api_signatures: Explicit API signatures.

        Returns:
            List of detected RegressionRecord.
        """
        all_regressions: List[RegressionRecord] = []

        # 1. Performance regression from scan data
        if baseline_key is not None:
            baseline_data = self._baseline_mgr.get(baseline_key)
            if baseline_data and isinstance(baseline_data, dict) and isinstance(current_results, dict):
                perf_regs = self._detect_scan_performance_regression(
                    baseline_data, current_results
                )
                all_regressions.extend(perf_regs)

                # Behaviour regressions from findings
                behav_regs = self._detector.detect_behaviour_regressions(
                    baseline_data.get("findings", []),
                    current_results.get("findings", []),
                    component=current_results.get("target", ""),
                )
                all_regressions.extend(behav_regs)

        # 2. Explicit performance metrics
        if performance_metrics:
            baseline_metrics: Dict[str, float] = {}
            keys_to_check = [baseline_key] if baseline_key else self._baseline_mgr.list_keys()
            for bk in keys_to_check:
                bv = self._baseline_mgr.get(bk)
                if isinstance(bv, dict):
                    for k, v in bv.items():
                        if isinstance(v, (int, float)):
                            baseline_metrics[k] = float(v)

            if baseline_metrics:
                perf_regs = self._detector.detect_performance_regressions(
                    baseline_metrics, performance_metrics
                )
                all_regressions.extend(perf_regs)

        # 3. Explicit correctness results
        if correctness_results is not None:
            baseline_correctness: Dict[str, bool] = {}
            keys_to_check = [baseline_key] if baseline_key else self._baseline_mgr.list_keys()
            for bk in keys_to_check:
                bv = self._baseline_mgr.get(bk)
                if isinstance(bv, dict):
                    for k, v in bv.items():
                        if isinstance(v, bool):
                            baseline_correctness[k] = v

            if baseline_correctness:
                corr_regs = self._detector.detect_correctness_regressions(
                    baseline_correctness, correctness_results
                )
                all_regressions.extend(corr_regs)

        # 4. Explicit API signatures
        if api_signatures is not None:
            baseline_api: Dict[str, Dict[str, Any]] = {}
            keys_to_check = [baseline_key] if baseline_key else self._baseline_mgr.list_keys()
            for bk in keys_to_check:
                bv = self._baseline_mgr.get(bk)
                if isinstance(bv, dict):
                    for k, v in bv.items():
                        if isinstance(v, dict) and ("params" in v or "return_type" in v):
                            baseline_api[k] = v

            if baseline_api:
                api_regs = self._detector.detect_api_regressions(
                    baseline_api, api_signatures
                )
                all_regressions.extend(api_regs)

        # Record all detected regressions in history
        for reg in all_regressions:
            self._history.append(reg)

        if all_regressions:
            self._save_history()
            logger.warning("Detected %d regressions", len(all_regressions))
        else:
            logger.info("No regressions detected")

        return all_regressions

    def _detect_scan_performance_regression(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
    ) -> List[RegressionRecord]:
        """Detect performance regressions from scan result dicts."""
        baseline_metrics: Dict[str, float] = {}
        current_metrics: Dict[str, float] = {}

        # Extract common numeric metrics from scan results
        for metric_key in ("total_score", "findings_count", "scan_duration_ms"):
            base_val = baseline.get(metric_key)
            cur_val = current.get(metric_key)
            if isinstance(base_val, (int, float)) and isinstance(cur_val, (int, float)):
                baseline_metrics[metric_key] = float(base_val)
                current_metrics[metric_key] = float(cur_val)

        # Score is higher-is-better — invert so the detector's
        # "higher is worse" semantics apply correctly.
        # baseline 90 → inverted 10,  current 50 → inverted 50
        # delta = 50 - 10 = 40 (positive = regression = correct)
        if "total_score" in baseline_metrics and "total_score" in current_metrics:
            baseline_metrics["total_score"] = 100.0 - baseline_metrics["total_score"]
            current_metrics["total_score"] = 100.0 - current_metrics["total_score"]

        # Severity counts — more critical/high is worse
        base_sev = baseline.get("severity_counts", {})
        cur_sev = current.get("severity_counts", {})
        for sev in ("critical", "high"):
            b_count = base_sev.get(sev, 0)
            c_count = cur_sev.get(sev, 0)
            if b_count > 0 or c_count > 0:
                baseline_metrics[f"count_{sev}"] = float(b_count)
                current_metrics[f"count_{sev}"] = float(c_count)

        if not baseline_metrics:
            return []

        target = current.get("target", baseline.get("target", ""))
        return self._detector.detect_performance_regressions(
            baseline_metrics, current_metrics, component=target
        )

    # ── Classification ──────────────────────────────────────────────────

    @staticmethod
    def classify_regression(regression: RegressionRecord) -> Dict[str, Any]:
        """Classify a regression and return a classification report.

        Args:
            regression: The RegressionRecord to classify.

        Returns:
            Dict with ``type``, ``subtype``, ``confidence``, and
            ``recommendation``.
        """
        r = regression
        reg_type = r.type.value if isinstance(r.type, RegressionType) else str(r.type)

        classification: Dict[str, str] = {"type": reg_type}

        # Subtype based on evidence
        evidence = r.evidence
        if reg_type == "performance":
            metric = evidence.get("metric", "")
            if "score" in metric:
                classification["subtype"] = "score_degradation"
                classification["recommendation"] = (
                    "Review scoring algorithm changes; check for new "
                    "findings or changed severity weights."
                )
            elif "latency" in metric or "duration" in metric or "time" in metric:
                classification["subtype"] = "performance_slowdown"
                classification["recommendation"] = (
                    "Profile scan execution; identify bottlenecks in "
                    "HTTP probes or module execution."
                )
            elif "count" in metric:
                classification["subtype"] = "count_increase"
                classification["recommendation"] = (
                    "Investigate new vulnerabilities or changed detection "
                    "rules producing more findings."
                )
            else:
                classification["subtype"] = "metric_anomaly"
                classification["recommendation"] = "Review metric definition and collection logic."
        elif reg_type == "correctness":
            test = evidence.get("test", "")
            classification["subtype"] = "test_failure"
            classification["recommendation"] = (
                f"Debug failing test '{test}'; check for logic changes "
                "or updated expected values."
            )
        elif reg_type == "api":
            change = evidence.get("change", "")
            if change == "removed":
                classification["subtype"] = "api_removal"
                classification["recommendation"] = "Restore function or update callers."
            elif change == "required_params_added":
                classification["subtype"] = "breaking_change"
                classification["recommendation"] = "Make new parameters optional with defaults."
            elif change == "return_type_changed":
                classification["subtype"] = "type_change"
                classification["recommendation"] = "Restore original return type or migrate callers."
            else:
                classification["subtype"] = "api_change"
                classification["recommendation"] = "Review API documentation and callers."
        elif reg_type == "behaviour":
            change = evidence.get("change", "")
            if change == "new_finding":
                classification["subtype"] = "new_vulnerability"
                classification["recommendation"] = "Investigate new finding; verify it is a true positive."
            elif change == "severity_escalation":
                classification["subtype"] = "escalation"
                classification["recommendation"] = "Verify severity change is intentional."
            elif change == "count_increase":
                classification["subtype"] = "finding_count_spike"
                classification["recommendation"] = "Review detection rules for false positives."
            else:
                classification["subtype"] = "behaviour_change"
                classification["recommendation"] = "Review detection logic and expected behavior."
        else:
            classification["subtype"] = "unknown"
            classification["recommendation"] = "Manual investigation required."

        # Confidence score
        delta = abs(r.delta)
        if delta >= 1.0 or (isinstance(evidence.get("percent_change"), (int, float))
                            and evidence["percent_change"] >= 25):
            classification["confidence"] = "high"
        elif delta >= 0.1:
            classification["confidence"] = "medium"
        else:
            classification["confidence"] = "low"

        return classification

    # ── Impact Assessment ───────────────────────────────────────────────

    @staticmethod
    def assess_impact(regression: RegressionRecord) -> Dict[str, Any]:
        """Assess the impact severity and business impact of a regression.

        Args:
            regression: The RegressionRecord to assess.

        Returns:
            Dict with ``severity``, ``business_impact``, ``scope``,
            ``urgency``, and ``suggested_action``.
        """
        sev = regression.severity.value if isinstance(regression.severity, RegressionSeverity) else str(regression.severity)
        reg_type = regression.type.value if isinstance(regression.type, RegressionType) else str(regression.type)

        impact: Dict[str, Any] = {"severity": sev}

        # Business impact mapping
        business_impact_map = {
            "critical": {
                "level": "critical",
                "description": "System functionality severely degraded. "
                               "Immediate attention required.",
                "scope": "enterprise",
                "urgency": "immediate",
                "suggested_action": "Block deployment; hotfix required.",
            },
            "high": {
                "level": "high",
                "description": "Significant degradation affecting key workflows.",
                "scope": "team",
                "urgency": "high",
                "suggested_action": "Prioritise fix in next sprint; "
                                   "consider reverting if widespread.",
            },
            "medium": {
                "level": "medium",
                "description": "Moderate impact; workaround may exist.",
                "scope": "module",
                "urgency": "medium",
                "suggested_action": "Schedule fix; monitor for escalation.",
            },
            "low": {
                "level": "low",
                "description": "Minor impact; likely cosmetic or edge case.",
                "scope": "component",
                "urgency": "low",
                "suggested_action": "Track in backlog; fix opportunistically.",
            },
            "info": {
                "level": "informational",
                "description": "No functional impact; informational only.",
                "scope": "none",
                "urgency": "none",
                "suggested_action": "Document and monitor.",
            },
        }

        biz = business_impact_map.get(sev, business_impact_map["info"])
        impact["business_impact"] = biz["description"]
        impact["scope"] = biz["scope"]
        impact["urgency"] = biz["urgency"]
        impact["suggested_action"] = biz["suggested_action"]

        # Cross-severity adjustments by type
        if reg_type == "correctness" and sev in ("low", "info"):
            # Correctness failures are never truly low-impact
            impact["severity"] = "medium"
            impact["urgency"] = "medium"
            impact["suggested_action"] = "Investigate test failure; may indicate deeper issue."

        if reg_type == "api" and sev == "medium":
            # API changes affect all callers
            impact["scope"] = "team"
            impact["suggested_action"] = "Audit callers for breakage; update documentation."

        return impact

    # ── History & Trends ──────────────────────────────────────────────

    def get_regression_history(
        self,
        regression_type: Optional[RegressionType] = None,
        severity: Optional[RegressionSeverity] = None,
        status: Optional[RegressionStatus] = None,
        component: Optional[str] = None,
        limit: int = 100,
    ) -> List[RegressionRecord]:
        """Retrieve regression history with optional filters.

        Args:
            regression_type: Filter by type.
            severity: Filter by severity.
            status: Filter by status.
            component: Filter by affected component (substring match).
            limit: Maximum records to return.

        Returns:
            List of matching RegressionRecord, newest first.
        """
        results = self._history
        if regression_type is not None:
            results = [r for r in results if r.type == regression_type]
        if severity is not None:
            results = [r for r in results if r.severity == severity]
        if status is not None:
            results = [r for r in results if r.status == status]
        if component is not None:
            results = [
                r for r in results
                if component.lower() in r.affected_component.lower()
            ]
        # Sort by detection time, newest first
        results.sort(key=lambda r: r.detected_at, reverse=True)
        return results[:limit]

    def get_regression_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyse regression trends over time.

        Returns a trends report with:
            - ``total_regressions``: Count in period
            - ``by_type``: Breakdown by RegressionType
            - ``by_severity``: Breakdown by RegressionSeverity
            - ``by_status``: Breakdown by RegressionStatus
            - ``by_component``: Top affected components
            - ``daily_counts``: Regression count per day
            - ``severity_trend``: Trend direction for severity
            - ``most_common_type``: Most frequent type
            - ``resolution_rate``: % of fixed regressions

        Args:
            days: Analysis period in days.

        Returns:
            Trends report dict.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400

        # Filter records by time
        recent: List[RegressionRecord] = []
        for r in self._history:
            try:
                dt = datetime.fromisoformat(r.detected_at.replace("Z", "+00:00"))
                if dt.timestamp() >= cutoff:
                    recent.append(r)
            except (ValueError, AttributeError):
                # Include records we can't parse (safer to include)
                recent.append(r)

        # Type breakdown
        by_type: Dict[str, int] = {}
        for r in recent:
            key = r.type.value if isinstance(r.type, RegressionType) else str(r.type)
            by_type[key] = by_type.get(key, 0) + 1

        # Severity breakdown
        by_severity: Dict[str, int] = {}
        for r in recent:
            key = r.severity.value if isinstance(r.severity, RegressionSeverity) else str(r.severity)
            by_severity[key] = by_severity.get(key, 0) + 1

        # Status breakdown
        by_status: Dict[str, int] = {}
        for r in recent:
            key = r.status.value if isinstance(r.status, RegressionStatus) else str(r.status)
            by_status[key] = by_status.get(key, 0) + 1

        # Component breakdown
        by_component: Dict[str, int] = {}
        for r in recent:
            comp = r.affected_component or "unknown"
            by_component[comp] = by_component.get(comp, 0) + 1

        # Daily counts
        daily_counts: Dict[str, int] = {}
        for r in recent:
            try:
                dt = datetime.fromisoformat(r.detected_at.replace("Z", "+00:00"))
                day_str = dt.strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                day_str = "unknown"
            daily_counts[day_str] = daily_counts.get(day_str, 0) + 1

        # Most common type
        most_common_type = max(by_type, key=by_type.get) if by_type else "none"

        # Resolution rate
        total = len(recent) or 1
        fixed_count = by_status.get("fixed", 0)
        resolution_rate = round(fixed_count / total * 100, 1)

        # Severity trend (simple: compare recent week vs prior week)
        week_ago = datetime.now(timezone.utc).timestamp() - 7 * 86400
        recent_week: List[RegressionRecord] = []
        prior_week: List[RegressionRecord] = []
        for r in recent:
            try:
                dt = datetime.fromisoformat(r.detected_at.replace("Z", "+00:00"))
                if dt.timestamp() >= week_ago:
                    recent_week.append(r)
                else:
                    prior_week.append(r)
            except (ValueError, AttributeError):
                pass

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        def _avg_severity(records: List[RegressionRecord]) -> float:
            if not records:
                return 0.0
            total_sev = sum(
                severity_order.get(
                    r.severity.value if isinstance(r.severity, RegressionSeverity) else str(r.severity), 0
                )
                for r in records
            )
            return total_sev / len(records)

        recent_avg = _avg_severity(recent_week)
        prior_avg = _avg_severity(prior_week)
        if recent_avg > prior_avg + 0.1:
            severity_trend = "worsening"
        elif recent_avg < prior_avg - 0.1:
            severity_trend = "improving"
        else:
            severity_trend = "stable"

        return {
            "period_days": days,
            "total_regressions": len(recent),
            "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
            "by_severity": dict(sorted(by_severity.items(), key=lambda x: x[1], reverse=True)),
            "by_status": dict(sorted(by_status.items(), key=lambda x: x[1], reverse=True)),
            "by_component": dict(sorted(by_component.items(), key=lambda x: x[1], reverse=True)),
            "daily_counts": dict(sorted(daily_counts.items())),
            "severity_trend": severity_trend,
            "most_common_type": most_common_type,
            "resolution_rate": resolution_rate,
        }

    # ── Report Generation ──────────────────────────────────────────────

    def generate_regression_report(
        self,
        days: int = 30,
        include_history: bool = True,
        include_trends: bool = True,
    ) -> str:
        """Generate a comprehensive regression summary report.

        Args:
            days: Period to cover.
            include_history: Include individual regression records.
            include_trends: Include trend analysis.

        Returns:
            Markdown-formatted report string.
        """
        lines: List[str] = []

        # Header
        lines.append("# ReconPro Regression Intelligence Report")
        lines.append(
            f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*"
        )
        lines.append(f"*Period: last {days} days*")
        lines.append("")

        # Baseline summary
        lines.append("## Baseline Summary")
        keys = self._baseline_mgr.list_keys()
        if keys:
            lines.append(f"**{len(keys)}** baselines tracked:")
            for key in keys:
                versions = self._baseline_mgr.versions(key)
                entry = self._baseline_mgr.get_entry(key)
                label = entry.get("label", "") if entry else ""
                label_part = f" ({label})" if label else ""
                lines.append(f"- `{key}`: {versions} version(s){label_part}")
        else:
            lines.append("No baselines captured yet.")
        lines.append("")

        # Trends
        if include_trends:
            lines.append("## Trend Analysis")
            trends = self.get_regression_trends(days)
            lines.append(f"- **Total regressions:** {trends['total_regressions']}")
            lines.append(f"- **Most common type:** {trends['most_common_type']}")
            lines.append(f"- **Severity trend:** {trends['severity_trend']}")
            lines.append(f"- **Resolution rate:** {trends['resolution_rate']}%")

            if trends["by_type"]:
                lines.append("")
                lines.append("**By type:**")
                for t, c in trends["by_type"].items():
                    lines.append(f"  - {t}: {c}")

            if trends["by_severity"]:
                lines.append("")
                lines.append("**By severity:**")
                for s, c in trends["by_severity"].items():
                    sev_icon = {"critical": "CRIT", "high": "HIGH",
                                "medium": "MED", "low": "LOW", "info": "INFO"}.get(s, s)
                    lines.append(f"  - [{sev_icon}] {s}: {c}")

            if trends["by_status"]:
                lines.append("")
                lines.append("**By status:**")
                for st, c in trends["by_status"].items():
                    lines.append(f"  - {st}: {c}")

            if trends["daily_counts"]:
                lines.append("")
                lines.append("**Daily counts:**")
                for day, cnt in sorted(trends["daily_counts"].items()):
                    bar = "#" * min(cnt, 40)
                    lines.append(f"  - {day}: {cnt:>3} {bar}")
            lines.append("")

        # Individual regressions
        if include_history:
            lines.append("## Detected Regressions")
            recent = self.get_regression_history(limit=50)
            if recent:
                for i, reg in enumerate(recent, 1):
                    sev = reg.severity.value if isinstance(reg.severity, RegressionSeverity) else str(reg.severity)
                    rtype = reg.type.value if isinstance(reg.type, RegressionType) else str(reg.type)
                    lines.append(f"### {i}. [{sev.upper()}] {rtype}")
                    lines.append(f"- **ID:** `{reg.id}`")
                    lines.append(f"- **Component:** {reg.affected_component}")
                    lines.append(f"- **Detected:** {reg.detected_at}")
                    lines.append(f"- **Status:** {reg.status.value if isinstance(reg.status, RegressionStatus) else str(reg.status)}")
                    lines.append(f"- **Description:** {reg.description}")
                    if reg.evidence:
                        ev_summary = json.dumps(reg.evidence, indent=2, default=str)[:300]
                        lines.append(f"- **Evidence:** `{ev_summary}`")
                    lines.append("")
            else:
                lines.append("No regressions detected in this period. All clear.")
                lines.append("")

        lines.append("---")
        lines.append("*ReconPro v11.1.0 Regression Intelligence System*")

        return "\n".join(lines)

    # ── Status Management ───────────────────────────────────────────────

    def update_regression_status(
        self,
        regression_id: str,
        new_status: RegressionStatus,
    ) -> bool:
        """Update the status of a regression record.

        Args:
            regression_id: ID of the regression to update.
            new_status: New status value.

        Returns:
            True if updated, False if not found.
        """
        for r in self._history:
            if r.id == regression_id:
                r.status = new_status
                self._save_history()
                logger.info(
                    "Regression %s status updated to %s",
                    regression_id, new_status.value,
                )
                return True
        return False

    # DEAD CODE: consider removal
    def dismiss_regression(
        self,
        regression_id: str,
        reason: str = "",
    ) -> bool:
        """Mark a regression as false positive.

        Args:
            regression_id: ID of the regression to dismiss.
            reason: Optional reason for dismissal.

        Returns:
            True if dismissed, False if not found.
        """
        for r in self._history:
            if r.id == regression_id:
                r.status = RegressionStatus.FALSE_POSITIVE
                if reason:
                    r.evidence["dismissal_reason"] = reason
                self._save_history()
                logger.info("Regression %s dismissed: %s", regression_id, reason)
                return True
        return False


# ── Convenience Exports ─────────────────────────────────────────────────

# DEAD CODE: consider removal
# DEAD CODE: consider removal
def capture_baseline(
    key: str,
    data: Dict[str, Any],
    label: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience function: capture a baseline."""
    ri = RegressionIntelligence()
    return ri.capture_baseline(key, data, label=label, metadata=metadata)


# DEAD CODE: consider removal
def detect_regressions(
    current_results: Dict[str, Any],
    baseline_key: Optional[str] = None,
) -> List[RegressionRecord]:
    """Convenience function: detect regressions."""
    ri = RegressionIntelligence()
    return ri.detect_regression(current_results, baseline_key=baseline_key)


def regression_report(days: int = 30) -> str:
    """Convenience function: generate a regression report."""
    ri = RegressionIntelligence()
    return ri.generate_regression_report(days=days)
