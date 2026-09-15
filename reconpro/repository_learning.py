"""ReconPro Age III — Repository Learning Engine.

Learns from the repository's own patterns: scan results, test outcomes,
error records, and code changes.  Extracts frequency, correlation, trend,
and anomaly patterns using only the Python standard library.

This module is distinct from ``pattern_of_life.py`` (which tracks *target*
behaviour).  Here we learn from the *repository's* own operational
behaviour — what fails, what succeeds, how things change over time.

Exports:
    LearnedPattern     – single learned pattern with confidence
    PatternStore       – persistent pattern storage with ageing/merging
    PatternExtractor   – statistical pattern extraction from raw events
    PatternQuery       – query interface for learned patterns
    RepositoryLearner  – main entry-point that ties everything together
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import statistics
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import RECONPRO_HOME, MEMORY_DIR

logger = logging.getLogger(__name__)

# ── Storage path ────────────────────────────────────────────────────────
PATTERN_FILE: Path = MEMORY_DIR / "learned_patterns.json"

# ── Pattern type constants ──────────────────────────────────────────────
PATTERN_FREQUENCY = "frequency"
PATTERN_CORRELATION = "correlation"
PATTERN_TREND = "trend"
PATTERN_ANOMALY = "anomaly"

VALID_PATTERN_TYPES: frozenset[str] = frozenset({
    PATTERN_FREQUENCY, PATTERN_CORRELATION, PATTERN_TREND, PATTERN_ANOMALY,
})

# ── Confidence thresholds ───────────────────────────────────────────────
DEFAULT_MIN_CONFIDENCE: float = 0.1
DEFAULT_MAX_PATTERNS: int = 5000
DEFAULT_AGE_HALF_LIFE_DAYS: float = 30.0
PRUNE_BELOW_CONFIDENCE: float = 0.05
MERGE_SIMILARITY_THRESHOLD: float = 0.85

# ── Learning source constants ───────────────────────────────────────────
SOURCE_SCAN = "scan"
SOURCE_TEST = "test"
SOURCE_ERROR = "error"
SOURCE_CODE_CHANGE = "code_change"

VALID_SOURCES: frozenset[str] = frozenset({
    SOURCE_SCAN, SOURCE_TEST, SOURCE_ERROR, SOURCE_CODE_CHANGE,
})


# ═══════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class LearnedPattern:
    """A single learned pattern with confidence scoring.

    Attributes:
        pattern_id:    SHA-256 derived unique identifier.
        pattern_type:  One of frequency, correlation, trend, anomaly.
        key:           Primary key identifying the pattern (e.g. module name,
                       error type, correlation pair).
        description:   Human-readable description of the pattern.
        confidence:    0.0–1.0 confidence score.
        support:       Number of observations backing this pattern.
        source:        Origin of the learning event (scan, test, error,
                       code_change).
        created_at:    ISO-8601 timestamp of first observation.
        updated_at:    ISO-8601 timestamp of most recent observation.
        metadata:      Extensible dict for additional pattern data.
    """
    pattern_id: str = ""
    pattern_type: str = PATTERN_FREQUENCY
    key: str = ""
    description: str = ""
    confidence: float = 0.0
    support: int = 0
    source: str = ""
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now_iso()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.pattern_id:
            self.pattern_id = self._compute_id()

    def _compute_id(self) -> str:
        raw = f"{self.pattern_type}:{self.key}:{self.source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def age_hours(self) -> float:
        """Hours since last update."""
        try:
            updated = datetime.fromisoformat(self.updated_at)
            delta = datetime.now(timezone.utc) - updated
            return max(0.0, delta.total_seconds() / 3600.0)
        except (ValueError, TypeError):
            return 0.0

    def decayed_confidence(self, half_life_days: float = DEFAULT_AGE_HALF_LIFE_DAYS) -> float:
        """Confidence reduced by exponential decay based on age."""
        hours = self.age_hours()
        half_life_hours = half_life_days * 24.0
        if half_life_hours <= 0:
            return self.confidence
        decay_factor = 0.5 ** (hours / half_life_hours)
        return max(0.0, self.confidence * decay_factor)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "key": self.key,
            "description": self.description,
            "confidence": round(self.confidence, 6),
            "support": self.support,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> LearnedPattern:
        return cls(
            pattern_id=d.get("pattern_id", ""),
            pattern_type=d.get("pattern_type", PATTERN_FREQUENCY),
            key=d.get("key", ""),
            description=d.get("description", ""),
            confidence=float(d.get("confidence", 0.0)),
            support=int(d.get("support", 0)),
            source=d.get("source", ""),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
            metadata=dict(d.get("metadata", {})),
        )


# ═══════════════════════════════════════════════════════════════════════════
# PatternStore — Persistent pattern storage with ageing/merging/pruning
# ═══════════════════════════════════════════════════════════════════════════


class PatternStore:
    """Persistent pattern storage.

    Features:
    - Store patterns with confidence scores
    - Age patterns (old patterns lose confidence via exponential decay)
    - Merge similar patterns
    - Prune low-confidence patterns
    - Thread-safe JSON persistence
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        max_patterns: int = DEFAULT_MAX_PATTERNS,
        half_life_days: float = DEFAULT_AGE_HALF_LIFE_DAYS,
        prune_threshold: float = PRUNE_BELOW_CONFIDENCE,
        merge_threshold: float = MERGE_SIMILARITY_THRESHOLD,
    ) -> None:
        self._path = path or PATTERN_FILE
        self._max_patterns = max(max_patterns, 1)
        self._half_life_days = half_life_days
        self._prune_threshold = prune_threshold
        self._merge_threshold = merge_threshold
        self._lock = threading.RLock()
        self._patterns: Dict[str, LearnedPattern] = {}
        self._loaded: bool = False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> None:
        """Load patterns from disk."""
        with self._lock:
            self._patterns.clear()
            if not self._path.exists():
                self._loaded = True
                return
            try:
                text = self._path.read_text(encoding="utf-8")
                data = json.loads(text) if text.strip() else {}
                raw_patterns = data.get("patterns", {})
                for pid, pdict in raw_patterns.items():
                    try:
                        self._patterns[pid] = LearnedPattern.from_dict(pdict)
                    except Exception:
                        logger.debug("Skipping corrupt pattern %s", pid)
                self._loaded = True
                logger.info(
                    "Loaded %d learned patterns from %s",
                    len(self._patterns), self._path,
                )
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load patterns from %s: %s", self._path, exc)
                self._loaded = True

    def save(self) -> None:
        """Persist current patterns to disk."""
        with self._lock:
            self._ensure_dir()
            try:
                data: Dict[str, Any] = {
                    "patterns": {
                        pid: p.to_dict()
                        for pid, p in self._patterns.items()
                    },
                    "saved_at": _now_iso(),
                    "total_patterns": len(self._patterns),
                }
                tmp = self._path.with_suffix(".tmp")
                tmp.write_text(
                    json.dumps(data, indent=2, default=str),
                    encoding="utf-8",
                )
                tmp.replace(self._path)
                logger.debug("Saved %d patterns to %s", len(self._patterns), self._path)
            except OSError as exc:
                logger.error("Failed to save patterns to %s: %s", self._path, exc)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, pattern: LearnedPattern) -> Optional[LearnedPattern]:
        """Add or update a pattern.  Returns the stored pattern."""
        with self._lock:
            self._ensure_loaded()
            pid = pattern.pattern_id
            existing = self._patterns.get(pid)
            if existing is not None:
                # Merge: weighted average confidence, increment support
                new_conf = _weighted_avg(
                    existing.confidence, existing.support,
                    pattern.confidence, pattern.support,
                )
                existing.confidence = min(1.0, new_conf)
                existing.support += pattern.support
                existing.updated_at = pattern.updated_at or _now_iso()
                if pattern.description and not existing.description:
                    existing.description = pattern.description
                if pattern.metadata:
                    existing.metadata.update(pattern.metadata)
                logger.debug("Updated pattern %s (conf=%.3f, sup=%d)", pid, existing.confidence, existing.support)
                return existing
            else:
                self._patterns[pid] = pattern
                logger.debug("Added pattern %s (type=%s)", pid, pattern.pattern_type)
                return pattern

    def get(self, pattern_id: str) -> Optional[LearnedPattern]:
        """Retrieve a pattern by ID."""
        with self._lock:
            self._ensure_loaded()
            return self._patterns.get(pattern_id)

    def remove(self, pattern_id: str) -> bool:
        """Remove a pattern by ID."""
        with self._lock:
            self._ensure_loaded()
            return self._patterns.pop(pattern_id, None) is not None

    def all_patterns(self) -> List[LearnedPattern]:
        """Return a snapshot of all stored patterns."""
        with self._lock:
            self._ensure_loaded()
            return list(self._patterns.values())

    def count(self) -> int:
        with self._lock:
            self._ensure_loaded()
            return len(self._patterns)

    # ------------------------------------------------------------------
    # Ageing & Pruning
    # ------------------------------------------------------------------

    def decay_all(self) -> int:
        """Apply exponential decay to all pattern confidences.

        Returns the number of patterns that were decayed.
        """
        decayed = 0
        with self._lock:
            self._ensure_loaded()
            for p in self._patterns.values():
                old_conf = p.confidence
                p.confidence = p.decayed_confidence(self._half_life_days)
                if p.confidence < old_conf - 1e-9:
                    decayed += 1
        return decayed

    def prune(self) -> int:
        """Remove patterns below the prune confidence threshold.

        Also enforces the max_patterns cap (LRU by last update).
        Returns count of removed patterns.
        """
        removed = 0
        with self._lock:
            self._ensure_loaded()
            # 1. Remove below threshold
            to_remove: List[str] = []
            for pid, p in self._patterns.items():
                if p.decayed_confidence(self._half_life_days) < self._prune_threshold:
                    to_remove.append(pid)
            for pid in to_remove:
                del self._patterns[pid]
                removed += 1

            # 2. Enforce cap — remove oldest-updated first
            if len(self._patterns) > self._max_patterns:
                sorted_pids = sorted(
                    self._patterns.keys(),
                    key=lambda k: self._patterns[k].updated_at,
                )
                excess = len(self._patterns) - self._max_patterns
                for pid in sorted_pids[:excess]:
                    del self._patterns[pid]
                    removed += 1

        if removed:
            logger.info("Pruned %d patterns (store now has %d)", removed, len(self._patterns))
        return removed

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def merge_similar(self) -> int:
        """Merge patterns that are sufficiently similar.

        Two patterns are similar when they share the same type and source,
        and their keys have a Jaccard similarity above the threshold.
        Returns the number of merges performed.
        """
        merged_count = 0
        with self._lock:
            self._ensure_loaded()
            # Group by (type, source)
            groups: Dict[Tuple[str, str], List[str]] = defaultdict(list)
            for pid, p in self._patterns.items():
                groups[(p.pattern_type, p.source)].append(pid)

            for (ptype, psource), pids in groups.items():
                if len(pids) < 2:
                    continue
                consumed: Set[str] = set()
                for i in range(len(pids)):
                    if pids[i] in consumed:
                        continue
                    for j in range(i + 1, len(pids)):
                        if pids[j] in consumed:
                            continue
                        pa = self._patterns[pids[i]]
                        pb = self._patterns[pids[j]]
                        if self._is_similar(pa, pb):
                            # Merge pb into pa
                            pa.confidence = min(1.0, _weighted_avg(
                                pa.confidence, pa.support,
                                pb.confidence, pb.support,
                            ))
                            pa.support += pb.support
                            pa.updated_at = _now_iso()
                            if not pa.description and pb.description:
                                pa.description = pb.description
                            pa.metadata.update(pb.metadata)
                            del self._patterns[pids[j]]
                            consumed.add(pids[j])
                            merged_count += 1
        if merged_count:
            logger.info("Merged %d similar pattern pairs", merged_count)
        return merged_count

    def _is_similar(self, a: LearnedPattern, b: LearnedPattern) -> bool:
        """Jaccard similarity on tokenised keys."""
        tokens_a = set(a.key.lower().split(":"))
        tokens_b = set(b.key.lower().split(":"))
        if not tokens_a or not tokens_b:
            return False
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union) >= self._merge_threshold

    def clear(self) -> int:
        """Remove all patterns. Returns the count removed."""
        with self._lock:
            self._ensure_loaded()
            n = len(self._patterns)
            self._patterns.clear()
            return n


# ═══════════════════════════════════════════════════════════════════════════
# PatternExtractor — Statistical pattern extraction from raw events
# ═══════════════════════════════════════════════════════════════════════════


class PatternExtractor:
    """Extract patterns from raw data using stdlib statistics.

    Extracts four kinds of patterns:
    1. Frequency — common failures, common findings, recurring events.
    2. Correlation — module A failure co-occurs with module B.
    3. Trend — metrics degrading/improving over time.
    4. Anomaly — events that deviate significantly from the norm.
    """

    # ── Frequency extraction ──────────────────────────────────────────

    def extract_frequency(
        self,
        items: List[str],
        source: str = SOURCE_SCAN,
        min_occurrences: int = 2,
        max_patterns: int = 20,
    ) -> List[LearnedPattern]:
        """Extract frequency patterns from a list of item identifiers.

        Parameters
        ----------
        items:
            List of string identifiers (e.g. finding titles, error messages,
            module names).
        source:
            Origin of the data (scan, test, error, code_change).
        min_occurrences:
            Minimum count to be considered a pattern.
        max_patterns:
            Cap on number of patterns returned.

        Returns
        -------
        List of LearnedPattern sorted by confidence (descending).
        """
        if not items:
            return []

        counter = Counter(items)
        total = len(items)
        patterns: List[LearnedPattern] = []

        for item, count in counter.most_common(max_patterns):
            if count < min_occurrences:
                continue
            freq = count / total
            confidence = min(1.0, freq * 2.0)  # Scale so 50% freq → 1.0
            patterns.append(LearnedPattern(
                pattern_type=PATTERN_FREQUENCY,
                key=f"freq:{item}",
                description=f"'{item}' occurs {count} times ({freq:.1%} of events)",
                confidence=round(confidence, 6),
                support=count,
                source=source,
                metadata={"frequency": round(freq, 6), "total_events": total},
            ))

        logger.debug("Extracted %d frequency patterns from %d items", len(patterns), total)
        return patterns

    # ── Correlation extraction ────────────────────────────────────────

    def extract_correlation(
        self,
        event_sets: List[Set[str]],
        source: str = SOURCE_SCAN,
        min_co_occurrence: int = 2,
        max_patterns: int = 20,
    ) -> List[LearnedPattern]:
        """Extract correlation patterns from co-occurring item sets.

        Parameters
        ----------
        event_sets:
            Each element is a set of items that occurred together in a
            single event (e.g. modules that had findings in one scan).
        source:
            Origin of the data.
        min_co_occurrence:
            Minimum co-occurrence count.
        max_patterns:
            Cap on returned patterns.

        Returns
        -------
        List of LearnedPattern with correlation data in metadata.
        """
        if not event_sets:
            return []

        n_events = len(event_sets)
        pair_counts: Dict[Tuple[str, str], int] = Counter()
        item_counts: Counter = Counter()

        for item_set in event_sets:
            items = sorted(item_set)
            for item in items:
                item_counts[item] += 1
            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    pair_counts[(items[i], items[j])] += 1

        patterns: List[LearnedPattern] = []
        for (a, b), co_count in pair_counts.most_common(max_patterns):
            if co_count < min_co_occurrence:
                continue
            # Normalised pointwise mutual information (simplified)
            p_a = item_counts[a] / n_events
            p_b = item_counts[b] / n_events
            p_ab = co_count / n_events
            if p_a > 0 and p_b > 0 and p_ab > 0:
                log_joint = math.log(p_ab)
                log_product = math.log(p_a * p_b)
                log_neg_joint = -log_joint
                if log_neg_joint > 0:
                    npmi = max(-1.0, min(1.0, (log_joint - log_product) / log_neg_joint))
                else:
                    npmi = 0.0
            else:
                npmi = 0.0

            confidence = min(1.0, (co_count / n_events) * 3.0)
            key = f"corr:{a}:{b}"
            patterns.append(LearnedPattern(
                pattern_type=PATTERN_CORRELATION,
                key=key,
                description=(
                    f"'{a}' and '{b}' co-occur in {co_count}/{n_events} events"
                    f" (NPMI={npmi:.3f})"
                ),
                confidence=round(confidence, 6),
                support=co_count,
                source=source,
                metadata={
                    "item_a": a,
                    "item_b": b,
                    "co_occurrence": co_count,
                    "total_events": n_events,
                    "npmi": round(npmi, 6),
                    "p_a": round(p_a, 6),
                    "p_b": round(p_b, 6),
                },
            ))

        logger.debug("Extracted %d correlation patterns from %d event sets", len(patterns), n_events)
        return patterns

    # ── Trend extraction ──────────────────────────────────────────────

    def extract_trend(
        self,
        time_series: List[Tuple[float, float]],
        source: str = SOURCE_SCAN,
        min_points: int = 3,
    ) -> List[LearnedPattern]:
        """Extract trend patterns from a time series.

        Parameters
        ----------
        time_series:
            List of (timestamp, value) tuples.  Timestamps are assumed
            to be monotonically increasing.
        source:
            Origin of the data.
        min_points:
            Minimum data points required for trend detection.

        Returns
        -------
        List of LearnedPattern (0 or 1) describing the detected trend.
        """
        if len(time_series) < min_points:
            return []

        values = [v for _, v in time_series]
        timestamps = [t for t, _ in time_series]
        n = len(values)

        # Simple linear regression via least squares
        x_mean = statistics.mean(range(n))
        y_mean = statistics.mean(values)

        ss_xx = sum((i - x_mean) ** 2 for i in range(n))
        ss_xy = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))

        if ss_xx == 0:
            return []

        slope = ss_xy / ss_xx
        intercept = y_mean - slope * x_mean

        # R-squared
        ss_res = sum((v - (slope * i + intercept)) ** 2 for i, v in enumerate(values))
        ss_tot = sum((v - y_mean) ** 2 for v in values)
        r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

        # Standard deviation of residuals for anomaly detection context
        if n > 2:
            residuals = [v - (slope * i + intercept) for i, v in enumerate(values)]
            try:
                residual_std = statistics.stdev(residuals)
            except statistics.StatisticsError:
                residual_std = 0.0
        else:
            residual_std = 0.0

        # Determine direction
        if abs(slope) < 1e-9:
            direction = "stable"
        elif slope > 0:
            direction = "increasing"
        else:
            direction = "decreasing"

        # Confidence based on R² and data point count
        confidence = min(1.0, r_squared * (n / 10.0))

        # Only report meaningful trends
        if confidence < 0.1:
            return []

        key = f"trend:{direction}:{source}"
        pattern = LearnedPattern(
            pattern_type=PATTERN_TREND,
            key=key,
            description=(
                f"{direction} trend (slope={slope:.4f}, R²={r_squared:.4f})"
                f" over {n} data points"
            ),
            confidence=round(confidence, 6),
            support=n,
            source=source,
            metadata={
                "direction": direction,
                "slope": round(slope, 8),
                "intercept": round(intercept, 8),
                "r_squared": round(r_squared, 6),
                "n_points": n,
                "residual_std": round(residual_std, 8),
                "y_mean": round(y_mean, 6),
                "time_start": round(timestamps[0], 2),
                "time_end": round(timestamps[-1], 2),
            },
        )

        logger.debug(
            "Extracted trend pattern: %s (conf=%.3f, slope=%.4f)",
            direction, confidence, slope,
        )
        return [pattern]

    # ── Anomaly extraction ────────────────────────────────────────────

    def extract_anomaly(
        self,
        values: List[float],
        source: str = SOURCE_SCAN,
        key_prefix: str = "anomaly",
        z_threshold: float = 2.0,
        max_patterns: int = 10,
    ) -> List[LearnedPattern]:
        """Extract anomaly patterns using z-score based outlier detection.

        Parameters
        ----------
        values:
            List of numeric observations.
        source:
            Origin of the data.
        key_prefix:
            Prefix for the pattern key.
        z_threshold:
            Z-score threshold for anomaly detection.
        max_patterns:
            Cap on returned patterns.

        Returns
        -------
        List of LearnedPattern for detected anomalies.
        """
        if len(values) < 3:
            return []

        try:
            mean_val = statistics.mean(values)
            stdev_val = statistics.stdev(values)
        except statistics.StatisticsError:
            return []

        if stdev_val == 0:
            return []

        patterns: List[LearnedPattern] = []
        for i, v in enumerate(values):
            z = (v - mean_val) / stdev_val
            if abs(z) >= z_threshold:
                direction = "high" if v > mean_val else "low"
                confidence = min(1.0, abs(z) / 5.0)  # Scale: z=5 → 1.0
                patterns.append(LearnedPattern(
                    pattern_type=PATTERN_ANOMALY,
                    key=f"{key_prefix}:{direction}:{i}",
                    description=(
                        f"Anomalous {direction} value {v:.4f} at index {i}"
                        f" (z={z:.2f}, mean={mean_val:.4f})"
                    ),
                    confidence=round(confidence, 6),
                    support=1,
                    source=source,
                    metadata={
                        "value": v,
                        "z_score": round(z, 6),
                        "mean": round(mean_val, 6),
                        "stdev": round(stdev_val, 6),
                        "index": i,
                        "direction": direction,
                    },
                ))

        # Cap and sort by confidence
        patterns.sort(key=lambda p: p.confidence, reverse=True)
        patterns = patterns[:max_patterns]

        logger.debug(
            "Extracted %d anomaly patterns from %d values (threshold=%.1f)",
            len(patterns), len(values), z_threshold,
        )
        return patterns

    # ── Composite extraction from scan results ────────────────────────

    def extract_from_scan_result(
        self,
        scan_result: Dict[str, Any],
    ) -> List[LearnedPattern]:
        """Extract all pattern types from a scan result dictionary."""
        all_patterns: List[LearnedPattern] = []
        target = scan_result.get("target", "unknown")
        findings = scan_result.get("findings", [])
        modules = scan_result.get("modules", [])
        score = scan_result.get("total_score", scan_result.get("score", 0))
        timestamp = scan_result.get("timestamp", scan_result.get("scanned_at", ""))

        # 1. Frequency: common finding categories, severities, modules
        finding_titles = [f.get("title", "") for f in findings if isinstance(f, dict)]
        if finding_titles:
            all_patterns.extend(
                self.extract_frequency(finding_titles, source=SOURCE_SCAN)
            )

        finding_severities = [f.get("severity", "info").lower() for f in findings if isinstance(f, dict)]
        if finding_severities:
            sev_patterns = self.extract_frequency(finding_severities, source=SOURCE_SCAN, max_patterns=5)
            for p in sev_patterns:
                p.key = f"sev_freq:{target}:{p.key.split(':', 1)[-1]}"
            all_patterns.extend(sev_patterns)

        finding_modules = [f.get("module", "") for f in findings if isinstance(f, dict) if f.get("module")]
        if finding_modules:
            mod_patterns = self.extract_frequency(finding_modules, source=SOURCE_SCAN, max_patterns=10)
            for p in mod_patterns:
                p.key = f"mod_freq:{target}:{p.key.split(':', 1)[-1]}"
            all_patterns.extend(mod_patterns)

        # 2. Correlation: modules that have findings together
        if finding_modules:
            # Group modules per finding, deduplicate per scan
            module_sets: List[Set[str]] = []
            seen_combos: Set[frozenset] = set()
            mods_in_scan: Set[str] = set(finding_modules)
            if mods_in_scan and frozenset(mods_in_scan) not in seen_combos:
                module_sets.append(mods_in_scan)
                seen_combos.add(frozenset(mods_in_scan))
            if module_sets:
                all_patterns.extend(
                    self.extract_correlation(module_sets, source=SOURCE_SCAN)
                )

        # 3. Trend: score over time (if we have historical scores in metadata)
        score_history = scan_result.get("score_history", [])
        if not score_history and score:
            # Use single data point — no trend yet
            pass
        if score_history:
            all_patterns.extend(
                self.extract_trend(score_history, source=SOURCE_SCAN)
            )

        return all_patterns

    # ── Composite extraction from test results ────────────────────────

    def extract_from_test_result(
        self,
        test_result: Dict[str, Any],
    ) -> List[LearnedPattern]:
        """Extract patterns from test outcome data."""
        all_patterns: List[LearnedPattern] = []

        tests = test_result.get("tests", [])
        if not tests:
            # Treat top-level fields as a single test result
            tests = [test_result]

        # 1. Frequency of test names that fail
        failed_names: List[str] = []
        for t in tests:
            if isinstance(t, dict):
                if t.get("status") == "failed" or t.get("passed") is False:
                    failed_names.append(t.get("name", t.get("test_name", "unknown")))

        if failed_names:
            all_patterns.extend(
                self.extract_frequency(failed_names, source=SOURCE_TEST, min_occurrences=1)
            )

        # 2. Anomaly: test duration outliers
        durations: List[float] = []
        for t in tests:
            if isinstance(t, dict) and "duration" in t:
                try:
                    durations.append(float(t["duration"]))
                except (TypeError, ValueError):
                    pass

        if len(durations) >= 3:
            all_patterns.extend(
                self.extract_anomaly(durations, source=SOURCE_TEST, key_prefix="test_duration")
            )

        # 3. Score trend over test runs
        score_history = test_result.get("score_history", test_result.get("scores", []))
        if isinstance(score_history, list) and len(score_history) >= 3:
            # Try to convert to (timestamp, value) tuples
            ts_pairs: List[Tuple[float, float]] = []
            for entry in score_history:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    try:
                        ts_pairs.append((float(entry[0]), float(entry[1])))
                    except (TypeError, ValueError):
                        pass
                elif isinstance(entry, dict):
                    try:
                        ts = entry.get("timestamp", entry.get("time", 0))
                        val = entry.get("score", entry.get("value", 0))
                        ts_pairs.append((float(ts), float(val)))
                    except (TypeError, ValueError):
                        pass
            if len(ts_pairs) >= 3:
                all_patterns.extend(
                    self.extract_trend(ts_pairs, source=SOURCE_TEST)
                )

        return all_patterns

    # ── Composite extraction from error records ───────────────────────

    def extract_from_error(
        self,
        error_record: Dict[str, Any],
    ) -> List[LearnedPattern]:
        """Extract patterns from error/failure records."""
        all_patterns: List[LearnedPattern] = []

        errors = error_record.get("errors", [])
        if not errors:
            errors = [error_record]

        # 1. Frequency: common error types/messages
        error_types: List[str] = []
        error_modules: List[str] = []
        for e in errors:
            if isinstance(e, dict):
                etype = e.get("error_type", e.get("type", e.get("exception", "unknown")))
                emodule = e.get("module", e.get("source", ""))
                error_types.append(etype)
                if emodule:
                    error_modules.append(emodule)

        if error_types:
            all_patterns.extend(
                self.extract_frequency(error_types, source=SOURCE_ERROR, min_occurrences=1)
            )
        if error_modules:
            all_patterns.extend(
                self.extract_frequency(error_modules, source=SOURCE_ERROR, min_occurrences=1, max_patterns=10)
            )

        # 2. Correlation: modules that error together
        if len(error_modules) >= 2:
            module_sets: List[Set[str]] = []
            seen: Set[frozenset] = set()
            combo = frozenset(error_modules)
            if combo not in seen:
                module_sets.append(set(error_modules))
                seen.add(combo)
            all_patterns.extend(
                self.extract_correlation(module_sets, source=SOURCE_ERROR)
            )

        return all_patterns

    # ── Composite extraction from code changes ────────────────────────

    def extract_from_code_change(
        self,
        change: Dict[str, Any],
    ) -> List[LearnedPattern]:
        """Extract patterns from code modification records."""
        all_patterns: List[LearnedPattern] = []

        files = change.get("files", change.get("changed_files", []))
        if not files:
            files = [change.get("file", "")]

        # 1. Frequency: commonly changed files/modules
        file_names: List[str] = [f for f in files if isinstance(f, str) and f]
        if file_names:
            all_patterns.extend(
                self.extract_frequency(file_names, source=SOURCE_CODE_CHANGE)
            )

        # 2. Frequency of change types
        change_types: List[str] = []
        for f in files:
            if isinstance(f, dict):
                ct = f.get("change_type", f.get("action", "modified"))
                change_types.append(ct)
        if change_types:
            all_patterns.extend(
                self.extract_frequency(change_types, source=SOURCE_CODE_CHANGE, max_patterns=5)
            )

        # 3. Trend: size of changes over time
        size_history = change.get("size_history", [])
        if isinstance(size_history, list) and len(size_history) >= 3:
            ts_pairs: List[Tuple[float, float]] = []
            for entry in size_history:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    try:
                        ts_pairs.append((float(entry[0]), float(entry[1])))
                    except (TypeError, ValueError):
                        pass
            if len(ts_pairs) >= 3:
                all_patterns.extend(
                    self.extract_trend(ts_pairs, source=SOURCE_CODE_CHANGE)
                )

        # 4. Anomaly: unusually large changes
        sizes: List[float] = []
        for f in files:
            if isinstance(f, dict):
                for size_key in ("lines_added", "lines_changed", "size"):
                    if size_key in f:
                        try:
                            sizes.append(float(f[size_key]))
                        except (TypeError, ValueError):
                            pass
        if len(sizes) >= 3:
            all_patterns.extend(
                self.extract_anomaly(sizes, source=SOURCE_CODE_CHANGE, key_prefix="change_size")
            )

        return all_patterns


# ═══════════════════════════════════════════════════════════════════════════
# PatternQuery — Query learned patterns
# ═══════════════════════════════════════════════════════════════════════════


class PatternQuery:
    """Query interface for learned patterns.

    Supports filtering by:
    - Type (frequency, correlation, trend, anomaly)
    - Confidence (minimum threshold)
    - Recency (max age in hours)
    - Source (scan, test, error, code_change)
    - Key substring match
    - Correlation with specific items
    """

    def __init__(self, store: PatternStore) -> None:
        self._store = store

    def query(
        self,
        *,
        pattern_type: Optional[str] = None,
        min_confidence: float = 0.0,
        max_age_hours: Optional[float] = None,
        source: Optional[str] = None,
        key_contains: Optional[str] = None,
        limit: int = 100,
        sort_by: str = "confidence",
        sort_desc: bool = True,
    ) -> List[LearnedPattern]:
        """Query patterns with optional filters.

        Parameters
        ----------
        pattern_type:
            Filter to a specific pattern type.
        min_confidence:
            Minimum (decayed) confidence threshold.
        max_age_hours:
            Maximum age of the pattern's last update.
        source:
            Filter to a specific learning source.
        key_contains:
            Substring match on pattern key.
        limit:
            Maximum number of results.
        sort_by:
            Field to sort by (confidence, support, updated_at).
        sort_desc:
            Sort descending if True.

        Returns
        -------
        Filtered and sorted list of LearnedPattern.
        """
        patterns = self._store.all_patterns()

        # Apply filters
        if pattern_type is not None:
            patterns = [p for p in patterns if p.pattern_type == pattern_type]
        if source is not None:
            patterns = [p for p in patterns if p.source == source]
        if key_contains is not None:
            lc = key_contains.lower()
            patterns = [p for p in patterns if lc in p.key.lower()]
        if min_confidence > 0:
            patterns = [
                p for p in patterns
                if p.decayed_confidence(self._store._half_life_days) >= min_confidence
            ]
        if max_age_hours is not None:
            patterns = [
                p for p in patterns
                if p.age_hours() <= max_age_hours
            ]

        # Sort
        if sort_by == "confidence":
            patterns.sort(key=lambda p: p.decayed_confidence(self._store._half_life_days), reverse=sort_desc)
        elif sort_by == "support":
            patterns.sort(key=lambda p: p.support, reverse=sort_desc)
        elif sort_by == "updated_at":
            patterns.sort(key=lambda p: p.updated_at, reverse=sort_desc)

        return patterns[:limit]

    def get_correlations_for(
        self,
        item: str,
        min_confidence: float = 0.1,
    ) -> List[LearnedPattern]:
        """Find all correlation patterns involving *item*."""
        lc = item.lower()
        results = [
            p for p in self._store.all_patterns()
            if p.pattern_type == PATTERN_CORRELATION
            and lc in p.key.lower()
            and p.decayed_confidence(self._store._half_life_days) >= min_confidence
        ]
        results.sort(key=lambda p: p.confidence, reverse=True)
        return results

    def get_frequent_failures(
        self,
        source: Optional[str] = None,
        min_confidence: float = 0.2,
        limit: int = 20,
    ) -> List[LearnedPattern]:
        """Get the most frequent failure/error patterns."""
        patterns = self.query(
            pattern_type=PATTERN_FREQUENCY,
            source=source,
            min_confidence=min_confidence,
            limit=limit,
        )
        return patterns

    def get_active_trends(
        self, min_confidence: float = 0.1) -> List[LearnedPattern]:
        """Get all active trend patterns."""
        return self.query(
            pattern_type=PATTERN_TREND,
            min_confidence=min_confidence,
        )

    def get_recent_anomalies(
        self,
        max_age_hours: float = 168.0,  # 7 days
        min_confidence: float = 0.2,
    ) -> List[LearnedPattern]:
        """Get recent anomaly patterns."""
        return self.query(
            pattern_type=PATTERN_ANOMALY,
            max_age_hours=max_age_hours,
            min_confidence=min_confidence,
        )


# ═══════════════════════════════════════════════════════════════════════════
# RepositoryLearner — Main entry-point
# ═══════════════════════════════════════════════════════════════════════════


class RepositoryLearner:
    """Learns from the repository's own events and patterns.

    Provides a unified interface to:
    - Feed scan results, test outcomes, errors, and code changes
    - Extract statistical patterns automatically
    - Query learned patterns for predictions
    - Persist and maintain pattern knowledge over time

    Usage
    -----
    >>> learner = RepositoryLearner()
    >>> learner.learn_from_scan({"target": "example.com", "findings": [...]})
    >>> learner.learn_from_test({"tests": [{"name": "xss", "passed": False}]})
    >>> patterns = learner.get_learned_patterns()
    >>> prediction = learner.predict_outcome({"module": "recon", "target": "x.com"})
    """

    def __init__(
        self,
        store: Optional[PatternStore] = None,
        auto_save: bool = True,
        auto_prune: bool = True,
        prune_interval: int = 50,  # Prune every N learn calls
    ) -> None:
        self._store = store or PatternStore()
        self._extractor = PatternExtractor()
        self._query = PatternQuery(self._store)
        self._auto_save = auto_save
        self._auto_prune = auto_prune
        self._prune_interval = max(prune_interval, 1)
        self._learn_count: int = 0
        self._stats: Dict[str, int] = {
            "total_learn_calls": 0,
            "scan_learn_calls": 0,
            "test_learn_calls": 0,
            "error_learn_calls": 0,
            "code_change_learn_calls": 0,
            "patterns_extracted": 0,
            "patterns_stored": 0,
            "predictions_made": 0,
            "prune_runs": 0,
        }

    # ------------------------------------------------------------------
    # Learning interface
    # ------------------------------------------------------------------

    def learn_from_scan(self, scan_result: Dict[str, Any]) -> int:
        """Extract and store patterns from a scan result.

        Parameters
        ----------
        scan_result:
            Dictionary with keys like ``target``, ``findings``,
            ``modules``, ``total_score``, ``score_history``.

        Returns
        -------
        Number of new/updated patterns stored.
        """
        if not scan_result or not isinstance(scan_result, dict):
            logger.warning("learn_from_scan: empty or invalid input")
            return 0

        self._stats["scan_learn_calls"] += 1
        self._stats["total_learn_calls"] += 1

        try:
            patterns = self._extractor.extract_from_scan_result(scan_result)
        except Exception:
            logger.exception("learn_from_scan: extraction failed")
            return 0

        stored = self._store_and_maintain(patterns)
        logger.info(
            "learn_from_scan: %d patterns extracted, %d stored for target='%s'",
            len(patterns), stored, scan_result.get("target", "unknown"),
        )
        return stored

    def learn_from_test(self, test_result: Dict[str, Any]) -> int:
        """Extract and store patterns from test outcomes.

        Parameters
        ----------
        test_result:
            Dictionary with ``tests`` (list of dicts with ``name``,
            ``status``/``passed``, ``duration``), or ``score_history``.

        Returns
        -------
        Number of new/updated patterns stored.
        """
        if not test_result or not isinstance(test_result, dict):
            logger.warning("learn_from_test: empty or invalid input")
            return 0

        self._stats["test_learn_calls"] += 1
        self._stats["total_learn_calls"] += 1

        try:
            patterns = self._extractor.extract_from_test_result(test_result)
        except Exception:
            logger.exception("learn_from_test: extraction failed")
            return 0

        stored = self._store_and_maintain(patterns)
        logger.info(
            "learn_from_test: %d patterns extracted, %d stored",
            len(patterns), stored,
        )
        return stored

    def learn_from_error(self, error_record: Dict[str, Any]) -> int:
        """Extract and store patterns from error/failure records.

        Parameters
        ----------
        error_record:
            Dictionary with ``errors`` (list of dicts with ``error_type``,
            ``module``, ``message``), or a single error dict.

        Returns
        -------
        Number of new/updated patterns stored.
        """
        if not error_record or not isinstance(error_record, dict):
            logger.warning("learn_from_error: empty or invalid input")
            return 0

        self._stats["error_learn_calls"] += 1
        self._stats["total_learn_calls"] += 1

        try:
            patterns = self._extractor.extract_from_error(error_record)
        except Exception:
            logger.exception("learn_from_error: extraction failed")
            return 0

        stored = self._store_and_maintain(patterns)
        logger.info(
            "learn_from_error: %d patterns extracted, %d stored",
            len(patterns), stored,
        )
        return stored

    def learn_from_code_change(self, change: Dict[str, Any]) -> int:
        """Extract and store patterns from code modification records.

        Parameters
        ----------
        change:
            Dictionary with ``files`` (list of file paths or dicts with
            ``change_type``, ``lines_added``), ``size_history``.

        Returns
        -------
        Number of new/updated patterns stored.
        """
        if not change or not isinstance(change, dict):
            logger.warning("learn_from_code_change: empty or invalid input")
            return 0

        self._stats["code_change_learn_calls"] += 1
        self._stats["total_learn_calls"] += 1

        try:
            patterns = self._extractor.extract_from_code_change(change)
        except Exception:
            logger.exception("learn_from_code_change: extraction failed")
            return 0

        stored = self._store_and_maintain(patterns)
        logger.info(
            "learn_from_code_change: %d patterns extracted, %d stored",
            len(patterns), stored,
        )
        return stored

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def get_learned_patterns(
        self,
        pattern_type: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 100,
    ) -> List[LearnedPattern]:
        """Retrieve learned patterns with optional filters.

        Parameters
        ----------
        pattern_type:
            Filter by type (frequency, correlation, trend, anomaly).
        min_confidence:
            Minimum confidence threshold.
        limit:
            Maximum patterns to return.

        Returns
        -------
        List of matching LearnedPattern.
        """
        return self._query.query(
            pattern_type=pattern_type,
            min_confidence=min_confidence,
            limit=limit,
        )

    def predict_outcome(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Predict outcomes based on learned patterns.

        Uses frequency and correlation patterns to make predictions
        about what is likely to happen given a scenario.

        Parameters
        ----------
        scenario:
            Dictionary describing the situation. Recognised keys:
            - ``module``: scanner module being used
            - ``target``: target being scanned
            - ``finding_type``: type of finding expected
            - ``source``: learning source to query

        Returns
        -------
        Dictionary with:
        - ``predicted_findings``: list of likely finding patterns
        - ``predicted_errors``: list of likely error patterns
        - ``risk_assessment``: overall risk based on learned data
        - ``confidence``: prediction confidence
        - ``supporting_patterns``: patterns that support the prediction
        """
        self._stats["predictions_made"] += 1
        prediction: Dict[str, Any] = {
            "predicted_findings": [],
            "predicted_errors": [],
            "risk_assessment": "unknown",
            "confidence": 0.0,
            "supporting_patterns": [],
        }

        module = scenario.get("module", "")
        source = scenario.get("source", SOURCE_SCAN)
        target = scenario.get("target", "")

        # 1. Find frequency patterns relevant to this scenario
        freq_patterns = self._query.query(
            pattern_type=PATTERN_FREQUENCY,
            source=source,
            min_confidence=0.15,
            limit=10,
        )

        # Filter to module-relevant patterns
        relevant_freq: List[LearnedPattern] = []
        for p in freq_patterns:
            if module and module.lower() in p.key.lower():
                relevant_freq.append(p)
            elif not module:
                relevant_freq.append(p)

        prediction["predicted_findings"] = [
            {
                "pattern": p.key,
                "description": p.description,
                "confidence": round(p.decayed_confidence(), 4),
                "support": p.support,
            }
            for p in relevant_freq[:5]
        ]

        # 2. Find error patterns
        error_patterns = self._query.get_frequent_failures(
            source=SOURCE_ERROR,
            min_confidence=0.15,
            limit=5,
        )

        # Filter to module-relevant
        relevant_errors: List[LearnedPattern] = []
        for p in error_patterns:
            if module and module.lower() in p.key.lower():
                relevant_errors.append(p)
            elif not module:
                relevant_errors.append(p)

        prediction["predicted_errors"] = [
            {
                "pattern": p.key,
                "description": p.description,
                "confidence": round(p.decayed_confidence(), 4),
                "support": p.support,
            }
            for p in relevant_errors[:5]
        ]

        # 3. Correlation patterns for this module
        if module:
            corr_patterns = self._query.get_correlations_for(module, min_confidence=0.1)
            prediction["correlations"] = [
                {
                    "pattern": p.key,
                    "description": p.description,
                    "npmi": p.metadata.get("npmi", 0.0),
                }
                for p in corr_patterns[:5]
            ]

        # 4. Check for degrading trends
        trends = self._query.get_active_trends(min_confidence=0.1)
        degrading = [t for t in trends if t.metadata.get("direction") == "decreasing"]
        improving = [t for t in trends if t.metadata.get("direction") == "increasing"]

        # 5. Overall risk assessment
        all_relevant = relevant_freq + relevant_errors
        if all_relevant:
            avg_conf = statistics.mean(
                [p.decayed_confidence() for p in all_relevant]
            )
            prediction["confidence"] = round(avg_conf, 4)

            if avg_conf >= 0.6:
                prediction["risk_assessment"] = "high"
            elif avg_conf >= 0.3:
                prediction["risk_assessment"] = "medium"
            else:
                prediction["risk_assessment"] = "low"

            # Adjust for trends
            if degrading:
                if prediction["risk_assessment"] == "low":
                    prediction["risk_assessment"] = "medium"
                elif prediction["risk_assessment"] == "medium":
                    prediction["risk_assessment"] = "high"
            elif improving:
                if prediction["risk_assessment"] == "high":
                    prediction["risk_assessment"] = "medium"
                elif prediction["risk_assessment"] == "medium":
                    prediction["risk_assessment"] = "low"

        # 6. Supporting patterns
        prediction["supporting_patterns"] = [
            p.to_dict() for p in (relevant_freq + relevant_errors + trends)[:10]
        ]

        # 7. Recent anomalies
        recent_anomalies = self._query.get_recent_anomalies(max_age_hours=168.0)
        prediction["recent_anomalies"] = [
            {"pattern": p.key, "description": p.description}
            for p in recent_anomalies[:5]
        ]

        return prediction

    def get_learning_stats(self) -> Dict[str, Any]:
        """Return statistics about what has been learned."""
        all_patterns = self._store.all_patterns()
        by_type: Counter = Counter(p.pattern_type for p in all_patterns)
        by_source: Counter = Counter(p.source for p in all_patterns)

        confidences = [p.decayed_confidence(self._store._half_life_days) for p in all_patterns]
        supports = [p.support for p in all_patterns]

        stats: Dict[str, Any] = {
            **self._stats,
            "total_patterns": len(all_patterns),
            "patterns_by_type": dict(by_type),
            "patterns_by_source": dict(by_source),
            "store_max_patterns": self._store._max_patterns,
            "store_count": self._store.count(),
        }

        if confidences:
            try:
                stats["avg_confidence"] = round(statistics.mean(confidences), 4)
                stats["max_confidence"] = round(max(confidences), 4)
                stats["min_confidence"] = round(min(confidences), 4)
            except statistics.StatisticsError:
                pass

        if supports:
            try:
                stats["avg_support"] = round(statistics.mean(supports), 2)
                stats["max_support"] = max(supports)
                stats["total_observations"] = sum(supports)
            except statistics.StatisticsError:
                pass

        return stats

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def _store_and_maintain(self, patterns: List[LearnedPattern]) -> int:
        """Store patterns and run maintenance if needed."""
        stored = 0
        for p in patterns:
            self._store.add(p)
            stored += 1

        self._stats["patterns_extracted"] += len(patterns)
        self._stats["patterns_stored"] += stored
        self._learn_count += 1

        # Periodic maintenance
        if self._auto_prune and self._learn_count % self._prune_interval == 0:
            self._store.prune()
            self._store.merge_similar()
            self._stats["prune_runs"] += 1

        if self._auto_save and stored > 0:
            self._store.save()

        return stored

    def save(self) -> None:
        """Force-save patterns to disk."""
        self._store.save()

    def load(self) -> None:
        """Force-load patterns from disk."""
        self._store.load()

    def prune(self) -> int:
        """Force-prune low-confidence patterns. Returns count removed."""
        removed = self._store.prune()
        self._store.merge_similar()
        self._stats["prune_runs"] += 1
        return removed

    def clear(self) -> int:
        """Clear all learned patterns. Returns count removed."""
        n = self._store.clear()
        if self._auto_save:
            self._store.save()
        return n


# ═══════════════════════════════════════════════════════════════════════════
# Helpers (private)
# ═══════════════════════════════════════════════════════════════════════════


def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# DEAD CODE: consider removal
def _weighted_avg(a_conf: float, a_sup: int, b_conf: float, b_sup: int) -> float:
    """Support-weighted average of two confidence values."""
    total = a_sup + b_sup
    if total == 0:
        return (a_conf + b_conf) / 2.0
    return (a_conf * a_sup + b_conf * b_sup) / total


# ═══════════════════════════════════════════════════════════════════════════
# Module-level convenience API
# ═══════════════════════════════════════════════════════════════════════════


_global_learner: Optional[RepositoryLearner] = None


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def get_repository_learner() -> RepositoryLearner:
    """Get the global RepositoryLearner instance (creates one if needed)."""
    global _global_learner
    if _global_learner is None:
        _global_learner = RepositoryLearner()
    return _global_learner


def reset_repository_learner() -> None:
    """Reset the global learner so the next call creates a fresh one."""
    global _global_learner
    _global_learner = None
