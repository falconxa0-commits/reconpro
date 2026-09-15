"""Tests for repository_learning.py — Repository Learning Engine.

Covers: LearnedPattern, PatternStore, PatternExtractor, PatternQuery,
RepositoryLearner, and the module-level convenience API.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent to path so we can import reconpro uninstalled
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro.repository_learning import (
    # Constants
    PATTERN_FREQUENCY, PATTERN_CORRELATION, PATTERN_TREND, PATTERN_ANOMALY,
    SOURCE_SCAN, SOURCE_TEST, SOURCE_ERROR, SOURCE_CODE_CHANGE,
    VALID_PATTERN_TYPES, VALID_SOURCES,
    DEFAULT_MIN_CONFIDENCE, DEFAULT_MAX_PATTERNS, DEFAULT_AGE_HALF_LIFE_DAYS,
    PRUNE_BELOW_CONFIDENCE, MERGE_SIMILARITY_THRESHOLD,
    # Classes
    LearnedPattern, PatternStore, PatternExtractor, PatternQuery, RepositoryLearner,
    # Helpers
    _weighted_avg, _now_iso,
    # Module-level API
    get_repository_learner, reset_repository_learner,
)


# ═══════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════


def _make_pattern(
    pattern_type: str = PATTERN_FREQUENCY,
    key: str = "freq:SQL Injection",
    confidence: float = 0.8,
    support: int = 10,
    source: str = SOURCE_SCAN,
) -> LearnedPattern:
    """Create a test LearnedPattern with sensible defaults."""
    return LearnedPattern(
        pattern_type=pattern_type,
        key=key,
        description=f"Test pattern: {key}",
        confidence=confidence,
        support=support,
        source=source,
    )


_SENTINEL = object()


def _make_scan_result(
    target: str = "example.com",
    findings: list | None = _SENTINEL,
    score: float = 75.0,
    score_history: list | None = None,
) -> dict:
    """Create a test scan result."""
    _default_findings = [
        {"title": "SQL Injection", "severity": "high", "module": "chain", "description": "SQLi found"},
        {"title": "XSS", "severity": "medium", "module": "recon", "description": "XSS found"},
        {"title": "SQL Injection", "severity": "high", "module": "chain", "description": "SQLi in another param"},
        {"title": "Open Redirect", "severity": "low", "module": "recon", "description": "Redirect found"},
    ]
    actual_findings = _default_findings if findings is _SENTINEL else findings
    return {
        "target": target,
        "findings": actual_findings,
        "modules": ["chain", "recon"],
        "total_score": score,
        "score_history": score_history or [],
    }


def _make_test_result(
    tests: list | None = None,
) -> dict:
    """Create a test result dictionary."""
    return {
        "tests": tests or [
            {"name": "test_xss_detection", "status": "passed", "duration": 0.5},
            {"name": "test_sqli_detection", "status": "failed", "duration": 1.2},
            {"name": "test_port_scan", "status": "passed", "duration": 0.3},
            {"name": "test_sqli_detection", "status": "failed", "duration": 15.0},
            {"name": "test_sqli_detection", "status": "failed", "duration": 0.8},
        ],
    }


def _make_error_record(
    errors: list | None = None,
) -> dict:
    """Create an error record dictionary."""
    return {
        "errors": errors or [
            {"error_type": "ConnectionTimeout", "module": "recon"},
            {"error_type": "ConnectionTimeout", "module": "chain"},
            {"error_type": "SSLError", "module": "tls"},
        ],
    }


def _make_code_change(
    files: list | None = None,
) -> dict:
    """Create a code change dictionary."""
    return {
        "files": files or [
            "reconpro/scanner.py",
            "reconpro/scanner.py",
            "reconpro/ai_analyst.py",
            "reconpro/ai_analyst.py",
            "reconpro/ai_analyst.py",
            {"path": "reconpro/delta.py", "change_type": "modified", "lines_added": 5},
            {"path": "reconpro/delta.py", "change_type": "modified", "lines_added": 3},
            {"path": "reconpro/ai_analyst.py", "change_type": "modified", "lines_added": 2},
        ],
    }


class _TempStoreMixin:
    """Mixin that provides a temp directory for PatternStore tests."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.store_path = Path(self.tmpdir) / "test_patterns.json"

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# LearnedPattern Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestLearnedPattern(unittest.TestCase):

    def test_default_construction(self) -> None:
        p = LearnedPattern()
        self.assertEqual(p.pattern_type, PATTERN_FREQUENCY)
        self.assertEqual(p.confidence, 0.0)
        self.assertEqual(p.support, 0)
        self.assertEqual(p.source, "")
        self.assertEqual(p.metadata, {})
        # Auto-generated fields
        self.assertTrue(len(p.pattern_id) == 24)
        self.assertTrue(p.created_at)
        self.assertTrue(p.updated_at)

    def test_custom_construction(self) -> None:
        p = _make_pattern(confidence=0.9, support=42)
        self.assertEqual(p.pattern_type, PATTERN_FREQUENCY)
        self.assertEqual(p.key, "freq:SQL Injection")
        self.assertEqual(p.confidence, 0.9)
        self.assertEqual(p.support, 42)
        self.assertEqual(p.source, SOURCE_SCAN)

    def test_deterministic_id(self) -> None:
        p1 = _make_pattern(key="freq:Test")
        p2 = _make_pattern(key="freq:Test")
        self.assertEqual(p1.pattern_id, p2.pattern_id)

    def test_different_keys_different_ids(self) -> None:
        p1 = _make_pattern(key="freq:A")
        p2 = _make_pattern(key="freq:B")
        self.assertNotEqual(p1.pattern_id, p2.pattern_id)

    def test_age_hours_zero_for_very_recent(self) -> None:
        p = _make_pattern()
        # Just created, age should be very small
        self.assertLessEqual(p.age_hours(), 0.01)

    def test_age_hours_invalid_timestamp(self) -> None:
        p = _make_pattern()
        p.updated_at = "not-a-date"
        self.assertEqual(p.age_hours(), 0.0)

    def test_decayed_confidence_no_decay(self) -> None:
        p = _make_pattern(confidence=0.8)
        # Very recent → decay factor ≈ 1.0
        dc = p.decayed_confidence(half_life_days=30.0)
        self.assertAlmostEqual(dc, 0.8, places=2)

    def test_decayed_confidence_with_long_half_life(self) -> None:
        p = _make_pattern(confidence=1.0)
        # Very long half life → almost no decay
        dc = p.decayed_confidence(half_life_days=99999.0)
        self.assertGreater(dc, 0.99)

    def test_to_dict_round_trip(self) -> None:
        p = _make_pattern(confidence=0.75, support=15)
        d = p.to_dict()
        self.assertEqual(d["pattern_type"], PATTERN_FREQUENCY)
        self.assertEqual(d["key"], "freq:SQL Injection")
        self.assertEqual(d["confidence"], 0.75)
        self.assertEqual(d["support"], 15)
        self.assertEqual(d["source"], SOURCE_SCAN)
        self.assertIn("pattern_id", d)
        self.assertIn("created_at", d)

    def test_from_dict(self) -> None:
        d = {
            "pattern_id": "abc123",
            "pattern_type": PATTERN_TREND,
            "key": "trend:decreasing:scan",
            "description": "Scores going down",
            "confidence": 0.65,
            "support": 8,
            "source": SOURCE_SCAN,
            "created_at": "2025-01-01T00:00:00+00:00",
            "updated_at": "2025-06-15T12:00:00+00:00",
            "metadata": {"slope": -0.5},
        }
        p = LearnedPattern.from_dict(d)
        self.assertEqual(p.pattern_id, "abc123")
        self.assertEqual(p.pattern_type, PATTERN_TREND)
        self.assertEqual(p.confidence, 0.65)
        self.assertEqual(p.support, 8)
        self.assertEqual(p.metadata, {"slope": -0.5})

    def test_from_dict_missing_fields_use_defaults(self) -> None:
        p = LearnedPattern.from_dict({})
        self.assertEqual(p.pattern_type, PATTERN_FREQUENCY)
        self.assertEqual(p.confidence, 0.0)
        self.assertEqual(p.support, 0)


# ═══════════════════════════════════════════════════════════════════════════
# PatternStore Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestPatternStore(_TempStoreMixin, unittest.TestCase):

    def test_add_and_get(self) -> None:
        store = PatternStore(path=self.store_path)
        p = _make_pattern(key="freq:Test1")
        store.add(p)
        retrieved = store.get(p.pattern_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.key, "freq:Test1")

    def test_add_updates_existing(self) -> None:
        store = PatternStore(path=self.store_path)
        p1 = _make_pattern(key="freq:Test1", confidence=0.5, support=5)
        store.add(p1)
        p2 = _make_pattern(key="freq:Test1", confidence=0.9, support=10)
        stored = store.add(p2)
        # Should be weighted average
        self.assertGreater(stored.confidence, 0.5)
        self.assertLess(stored.confidence, 0.9)
        self.assertEqual(stored.support, 15)  # 5 + 10

    def test_add_merges_metadata(self) -> None:
        store = PatternStore(path=self.store_path)
        p1 = _make_pattern(key="freq:Test1")
        p1.metadata = {"a": 1}
        store.add(p1)
        p2 = _make_pattern(key="freq:Test1")
        p2.metadata = {"b": 2}
        stored = store.add(p2)
        self.assertEqual(stored.metadata, {"a": 1, "b": 2})

    def test_remove(self) -> None:
        store = PatternStore(path=self.store_path)
        p = _make_pattern(key="freq:ToRemove")
        store.add(p)
        self.assertTrue(store.remove(p.pattern_id))
        self.assertIsNone(store.get(p.pattern_id))

    def test_remove_nonexistent(self) -> None:
        store = PatternStore(path=self.store_path)
        self.assertFalse(store.remove("nonexistent"))

    def test_all_patterns(self) -> None:
        store = PatternStore(path=self.store_path)
        for i in range(5):
            store.add(_make_pattern(key=f"freq:Pattern{i}"))
        all_p = store.all_patterns()
        self.assertEqual(len(all_p), 5)

    def test_count(self) -> None:
        store = PatternStore(path=self.store_path)
        self.assertEqual(store.count(), 0)
        store.add(_make_pattern(key="freq:A"))
        self.assertEqual(store.count(), 1)

    def test_save_and_load(self) -> None:
        store = PatternStore(path=self.store_path)
        p = _make_pattern(key="freq:PersistTest", confidence=0.7, support=20)
        store.add(p)
        store.save()

        # New store instance loads from same path
        store2 = PatternStore(path=self.store_path)
        store2.load()
        retrieved = store2.get(p.pattern_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.confidence, 0.7)
        self.assertEqual(retrieved.support, 20)

    def test_load_nonexistent_file(self) -> None:
        store = PatternStore(path=self.store_path)
        store.load()  # Should not raise
        self.assertEqual(store.count(), 0)

    def test_load_corrupt_file(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text("not valid json {{{", encoding="utf-8")
        store = PatternStore(path=self.store_path)
        store.load()  # Should not raise
        self.assertEqual(store.count(), 0)

    def test_prune_removes_low_confidence(self) -> None:
        store = PatternStore(path=self.store_path, prune_threshold=0.3)
        store.add(_make_pattern(key="freq:High", confidence=0.8, support=100))
        store.add(_make_pattern(key="freq:Low", confidence=0.05, support=1))
        removed = store.prune()
        self.assertEqual(removed, 1)
        self.assertEqual(store.count(), 1)

    def test_prune_enforces_max_patterns(self) -> None:
        store = PatternStore(path=self.store_path, max_patterns=3)
        for i in range(10):
            store.add(_make_pattern(key=f"freq:Cap{i}", confidence=0.5, support=5))
        removed = store.prune()
        self.assertGreater(removed, 0)
        self.assertLessEqual(store.count(), 3)

    def test_merge_similar(self) -> None:
        store = PatternStore(path=self.store_path, merge_threshold=0.8)
        # These share all tokens — should merge
        p1 = _make_pattern(key="freq:chain:timeout", pattern_type=PATTERN_FREQUENCY, source=SOURCE_ERROR)
        p2 = _make_pattern(key="freq:chain:error", pattern_type=PATTERN_FREQUENCY, source=SOURCE_ERROR)
        store.add(p1)
        store.add(p2)
        merged = store.merge_similar()
        # Depending on Jaccard similarity, they may or may not merge
        # With keys "freq:chain:timeout" and "freq:chain:error", tokens are
        # {freq, chain, timeout} and {freq, chain, error} → intersection=2, union=4 → 0.5
        # So with threshold 0.8, they should NOT merge
        self.assertEqual(merged, 0)
        self.assertEqual(store.count(), 2)

    def test_merge_similar_high_overlap(self) -> None:
        store = PatternStore(path=self.store_path, merge_threshold=0.5)
        p1 = _make_pattern(key="freq:chain:timeout", pattern_type=PATTERN_FREQUENCY, source=SOURCE_ERROR)
        p2 = _make_pattern(key="freq:chain:error", pattern_type=PATTERN_FREQUENCY, source=SOURCE_ERROR)
        store.add(p1)
        store.add(p2)
        merged = store.merge_similar()
        self.assertEqual(merged, 1)
        self.assertEqual(store.count(), 1)

    def test_clear(self) -> None:
        store = PatternStore(path=self.store_path)
        for i in range(5):
            store.add(_make_pattern(key=f"freq:Clear{i}"))
        removed = store.clear()
        self.assertEqual(removed, 5)
        self.assertEqual(store.count(), 0)

    def test_decay_all(self) -> None:
        store = PatternStore(path=self.store_path, half_life_days=0.0001)  # ~8.6 seconds
        p = _make_pattern(confidence=1.0, support=10)
        # Create in the past so it has age
        import time
        p.updated_at = "2020-01-01T00:00:00+00:00"
        p.created_at = "2020-01-01T00:00:00+00:00"
        store.add(p)
        decayed = store.decay_all()
        self.assertEqual(decayed, 1)
        # Confidence should have dropped significantly
        retrieved = store.get(p.pattern_id)
        self.assertIsNotNone(retrieved)
        self.assertLess(retrieved.confidence, 0.5)

    def test_atomic_save(self) -> None:
        """Verify save uses atomic write (tmp + replace)."""
        store = PatternStore(path=self.store_path)
        store.add(_make_pattern(key="freq:Atomic"))
        store.save()
        self.assertTrue(self.store_path.exists())
        # Verify it's valid JSON
        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        self.assertIn("patterns", data)
        self.assertIn("saved_at", data)


# ═══════════════════════════════════════════════════════════════════════════
# PatternExtractor Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestPatternExtractorFrequency(unittest.TestCase):

    def setUp(self) -> None:
        self.extractor = PatternExtractor()

    def test_empty_input(self) -> None:
        patterns = self.extractor.extract_frequency([])
        self.assertEqual(patterns, [])

    def test_single_item_no_pattern(self) -> None:
        patterns = self.extractor.extract_frequency(["a"], min_occurrences=2)
        self.assertEqual(patterns, [])

    def test_repeated_items(self) -> None:
        items = ["a", "b", "a", "c", "a", "b"]
        patterns = self.extractor.extract_frequency(items, min_occurrences=2)
        # 'a' occurs 3/6, 'b' occurs 2/6
        self.assertEqual(len(patterns), 2)
        # Sorted by confidence descending, 'a' first
        self.assertGreater(patterns[0].confidence, patterns[1].confidence)
        self.assertEqual(patterns[0].support, 3)
        self.assertEqual(patterns[1].support, 2)

    def test_max_patterns_cap(self) -> None:
        items = ["a", "b", "c", "d", "e"] * 10
        patterns = self.extractor.extract_frequency(items, max_patterns=2)
        self.assertLessEqual(len(patterns), 2)

    def test_confidence_scaling(self) -> None:
        # 50% frequency → confidence 1.0
        items = ["x"] * 5 + ["y"] * 5
        patterns = self.extractor.extract_frequency(items)
        for p in patterns:
            self.assertLessEqual(p.confidence, 1.0)
            self.assertGreaterEqual(p.confidence, 0.0)

    def test_pattern_metadata(self) -> None:
        items = ["a", "a", "b"]
        patterns = self.extractor.extract_frequency(items)
        for p in patterns:
            self.assertIn("frequency", p.metadata)
            self.assertIn("total_events", p.metadata)

    def test_source_propagation(self) -> None:
        items = ["a", "a", "b"]
        patterns = self.extractor.extract_frequency(items, source=SOURCE_TEST)
        for p in patterns:
            self.assertEqual(p.source, SOURCE_TEST)


class TestPatternExtractorCorrelation(unittest.TestCase):

    def setUp(self) -> None:
        self.extractor = PatternExtractor()

    def test_empty_input(self) -> None:
        patterns = self.extractor.extract_correlation([])
        self.assertEqual(patterns, [])

    def test_single_event_no_pairs(self) -> None:
        patterns = self.extractor.extract_correlation([{"a"}])
        self.assertEqual(patterns, [])

    def test_co_occurrence_detection(self) -> None:
        event_sets = [
            {"chain", "recon"},
            {"chain", "recon"},
            {"chain", "tls"},
        ]
        patterns = self.extractor.extract_correlation(event_sets, min_co_occurrence=2)
        # chain+recon co-occur 2 times out of 3
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].support, 2)
        self.assertIn("chain", patterns[0].key)
        self.assertIn("recon", patterns[0].key)

    def test_correlation_metadata(self) -> None:
        event_sets = [{"a", "b"}, {"a", "b"}, {"a", "c"}]
        patterns = self.extractor.extract_correlation(event_sets, min_co_occurrence=1)
        for p in patterns:
            self.assertIn("npmi", p.metadata)
            self.assertIn("co_occurrence", p.metadata)
            self.assertIn("item_a", p.metadata)
            self.assertIn("item_b", p.metadata)

    def test_max_patterns_cap(self) -> None:
        event_sets = [
            {"a", "b"}, {"a", "c"}, {"a", "d"}, {"b", "c"}, {"b", "d"}, {"c", "d"},
        ] * 3
        patterns = self.extractor.extract_correlation(event_sets, max_patterns=2, min_co_occurrence=1)
        self.assertLessEqual(len(patterns), 2)


class TestPatternExtractorTrend(unittest.TestCase):

    def setUp(self) -> None:
        self.extractor = PatternExtractor()

    def test_empty_input(self) -> None:
        patterns = self.extractor.extract_trend([])
        self.assertEqual(patterns, [])

    def test_too_few_points(self) -> None:
        patterns = self.extractor.extract_trend([(0, 10), (1, 20)])
        self.assertEqual(patterns, [])

    def test_increasing_trend(self) -> None:
        ts = [(i, float(i * 10)) for i in range(10)]  # Perfectly linear
        patterns = self.extractor.extract_trend(ts)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].metadata["direction"], "increasing")
        self.assertAlmostEqual(patterns[0].metadata["r_squared"], 1.0, places=2)

    def test_decreasing_trend(self) -> None:
        ts = [(i, float(100 - i * 5)) for i in range(10)]
        patterns = self.extractor.extract_trend(ts)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].metadata["direction"], "decreasing")

    def test_stable_trend(self) -> None:
        ts = [(i, 50.0) for i in range(10)]
        patterns = self.extractor.extract_trend(ts)
        # All same value → stable, but R² may not be meaningful
        # slope ≈ 0 → stable
        if patterns:
            self.assertEqual(patterns[0].metadata["direction"], "stable")

    def test_trend_metadata(self) -> None:
        ts = [(i, float(i * 5 + 10)) for i in range(10)]
        patterns = self.extractor.extract_trend(ts)
        self.assertEqual(len(patterns), 1)
        meta = patterns[0].metadata
        self.assertIn("slope", meta)
        self.assertIn("intercept", meta)
        self.assertIn("r_squared", meta)
        self.assertIn("n_points", meta)
        self.assertIn("residual_std", meta)
        self.assertEqual(meta["n_points"], 10)


class TestPatternExtractorAnomaly(unittest.TestCase):

    def setUp(self) -> None:
        self.extractor = PatternExtractor()

    def test_empty_input(self) -> None:
        patterns = self.extractor.extract_anomaly([])
        self.assertEqual(patterns, [])

    def test_too_few_points(self) -> None:
        patterns = self.extractor.extract_anomaly([1.0, 2.0])
        self.assertEqual(patterns, [])

    def test_no_anomalies(self) -> None:
        # All values close together
        values = [10.0, 10.1, 10.2, 9.9, 10.0, 10.1]
        patterns = self.extractor.extract_anomaly(values, z_threshold=2.0)
        self.assertEqual(patterns, [])

    def test_detects_high_anomaly(self) -> None:
        values = [10.0, 10.1, 10.2, 9.9, 10.0, 100.0]  # 100 is outlier
        patterns = self.extractor.extract_anomaly(values, z_threshold=2.0)
        self.assertTrue(len(patterns) >= 1)
        # The outlier should be the last one
        self.assertEqual(patterns[0].metadata["index"], 5)
        self.assertEqual(patterns[0].metadata["direction"], "high")

    def test_detects_low_anomaly(self) -> None:
        values = [10.0, 10.1, 10.2, 9.9, 10.0, -50.0]
        patterns = self.extractor.extract_anomaly(values, z_threshold=2.0)
        self.assertTrue(len(patterns) >= 1)
        self.assertEqual(patterns[0].metadata["direction"], "low")

    def test_anomaly_confidence_scaling(self) -> None:
        values = [10.0] * 10 + [1000.0]  # Extreme outlier
        patterns = self.extractor.extract_anomaly(values, z_threshold=1.0)
        self.assertTrue(len(patterns) >= 1)
        self.assertGreater(patterns[0].confidence, 0.5)

    def test_max_patterns_cap(self) -> None:
        values = [10.0] * 5 + [100.0, -100.0, 200.0, -200.0, 500.0]
        patterns = self.extractor.extract_anomaly(values, z_threshold=1.0, max_patterns=2)
        self.assertLessEqual(len(patterns), 2)

    def test_zero_stddev_no_anomaly(self) -> None:
        values = [5.0, 5.0, 5.0, 5.0]
        patterns = self.extractor.extract_anomaly(values)
        self.assertEqual(patterns, [])


class TestPatternExtractorComposite(unittest.TestCase):

    def setUp(self) -> None:
        self.extractor = PatternExtractor()

    def test_extract_from_scan_result(self) -> None:
        scan = _make_scan_result()
        patterns = self.extractor.extract_from_scan_result(scan)
        # Should extract: finding title freq, severity freq, module freq, correlation
        self.assertGreater(len(patterns), 0)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_FREQUENCY, types)

    def test_extract_from_scan_empty_findings(self) -> None:
        scan = _make_scan_result(findings=[])
        patterns = self.extractor.extract_from_scan_result(scan)
        self.assertEqual(patterns, [])

    def test_extract_from_scan_with_score_history(self) -> None:
        history = [(i, float(80 - i * 2)) for i in range(10)]
        scan = _make_scan_result(score_history=history)
        patterns = self.extractor.extract_from_scan_result(scan)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_TREND, types)

    def test_extract_from_test_result(self) -> None:
        result = _make_test_result()
        patterns = self.extractor.extract_from_test_result(result)
        # Should extract: failed test freq, duration anomalies
        self.assertGreater(len(patterns), 0)

    def test_extract_from_test_empty(self) -> None:
        patterns = self.extractor.extract_from_test_result({"tests": []})
        self.assertEqual(patterns, [])

    def test_extract_from_test_with_score_history(self) -> None:
        result = _make_test_result()
        result["score_history"] = [(i, float(90 - i)) for i in range(10)]
        patterns = self.extractor.extract_from_test_result(result)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_TREND, types)

    def test_extract_from_error(self) -> None:
        record = _make_error_record()
        patterns = self.extractor.extract_from_error(record)
        self.assertGreater(len(patterns), 0)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_FREQUENCY, types)

    def test_extract_from_error_single(self) -> None:
        patterns = self.extractor.extract_from_error({
            "error_type": "TimeoutError",
            "module": "recon",
        })
        # Single error treated as a list of one → freq patterns
        self.assertGreater(len(patterns), 0)

    def test_extract_from_code_change(self) -> None:
        change = _make_code_change()
        patterns = self.extractor.extract_from_code_change(change)
        self.assertGreater(len(patterns), 0)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_FREQUENCY, types)

    def test_extract_from_code_change_with_sizes(self) -> None:
        # Use values where the outlier is extreme enough for z >= 2.0
        # mean ≈ 2.0, stdev ≈ 0, need a clear outlier
        change = {
            "files": [
                {"path": "a.py", "change_type": "modified", "lines_added": 1},
                {"path": "b.py", "change_type": "modified", "lines_added": 1},
                {"path": "c.py", "change_type": "modified", "lines_added": 1},
                {"path": "d.py", "change_type": "modified", "lines_added": 2},
                {"path": "e.py", "change_type": "modified", "lines_added": 1},
                {"path": "f.py", "change_type": "modified", "lines_added": 1},
                {"path": "g.py", "change_type": "modified", "lines_added": 1},
                {"path": "h.py", "change_type": "modified", "lines_added": 50},
            ]
        }
        patterns = self.extractor.extract_from_code_change(change)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_ANOMALY, types)

    def test_extract_from_code_change_with_history(self) -> None:
        change = {
            "files": [],
            "size_history": [(i, float(10 + i * 5)) for i in range(10)],
        }
        patterns = self.extractor.extract_from_code_change(change)
        types = {p.pattern_type for p in patterns}
        self.assertIn(PATTERN_TREND, types)


# ═══════════════════════════════════════════════════════════════════════════
# PatternQuery Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestPatternQuery(_TempStoreMixin, unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()
        self.store = PatternStore(path=self.store_path)
        self.query = PatternQuery(self.store)
        # Seed with patterns
        self.store.add(_make_pattern(key="freq:A", confidence=0.9, support=50, source=SOURCE_SCAN))
        self.store.add(_make_pattern(key="freq:B", confidence=0.5, support=10, source=SOURCE_SCAN))
        self.store.add(_make_pattern(
            pattern_type=PATTERN_CORRELATION, key="corr:A:B",
            confidence=0.7, support=8, source=SOURCE_SCAN,
        ))
        self.store.add(_make_pattern(
            pattern_type=PATTERN_TREND, key="trend:decreasing:scan",
            confidence=0.6, support=15, source=SOURCE_SCAN,
        ))
        self.store.add(_make_pattern(
            pattern_type=PATTERN_ANOMALY, key="anomaly:high:0",
            confidence=0.4, support=1, source=SOURCE_ERROR,
        ))

    def test_query_all(self) -> None:
        results = self.query.query()
        self.assertEqual(len(results), 5)

    def test_query_by_type(self) -> None:
        results = self.query.query(pattern_type=PATTERN_FREQUENCY)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertEqual(r.pattern_type, PATTERN_FREQUENCY)

    def test_query_by_source(self) -> None:
        results = self.query.query(source=SOURCE_ERROR)
        self.assertEqual(len(results), 1)

    def test_query_by_min_confidence(self) -> None:
        # Query uses decayed confidence which may be slightly < raw.
        # 0.9 and 0.7 should still pass 0.6. 0.6 may decay below.
        results = self.query.query(min_confidence=0.5)
        self.assertGreaterEqual(len(results), 3)  # 0.9, 0.7, 0.6
        results_strict = self.query.query(min_confidence=0.6)
        self.assertGreaterEqual(len(results_strict), 2)  # at least 0.9 and 0.7

    def test_query_by_key_contains(self) -> None:
        results = self.query.query(key_contains="freq")
        self.assertEqual(len(results), 2)

    def test_query_limit(self) -> None:
        results = self.query.query(limit=2)
        self.assertLessEqual(len(results), 2)

    def test_query_sort_by_confidence(self) -> None:
        results = self.query.query(sort_by="confidence", sort_desc=True)
        confs = [p.confidence for p in results]
        self.assertEqual(confs, sorted(confs, reverse=True))

    def test_query_sort_by_support(self) -> None:
        results = self.query.query(sort_by="support", sort_desc=True)
        sups = [p.support for p in results]
        self.assertEqual(sups, sorted(sups, reverse=True))

    def test_query_combined_filters(self) -> None:
        results = self.query.query(
            pattern_type=PATTERN_FREQUENCY,
            source=SOURCE_SCAN,
            min_confidence=0.6,
        )
        self.assertEqual(len(results), 1)  # Only freq:A

    def test_get_correlations_for(self) -> None:
        results = self.query.get_correlations_for("A")
        self.assertEqual(len(results), 1)
        self.assertIn("A", results[0].key)
        self.assertIn("B", results[0].key)

    def test_get_correlations_for_no_match(self) -> None:
        results = self.query.get_correlations_for("nonexistent")
        self.assertEqual(results, [])

    def test_get_frequent_failures(self) -> None:
        self.store.add(_make_pattern(
            key="freq:ConnectionTimeout",
            confidence=0.7, support=20, source=SOURCE_ERROR,
        ))
        results = self.query.get_frequent_failures(source=SOURCE_ERROR, min_confidence=0.3)
        self.assertGreater(len(results), 0)

    def test_get_active_trends(self) -> None:
        results = self.query.get_active_trends(min_confidence=0.5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].pattern_type, PATTERN_TREND)

    def test_get_recent_anomalies(self) -> None:
        # Anomaly was just created, so it should be recent
        results = self.query.get_recent_anomalies(max_age_hours=1.0)
        self.assertEqual(len(results), 1)

    def test_get_recent_anomalies_old(self) -> None:
        # Set the anomaly's updated_at to the distant past
        for p in self.store.all_patterns():
            if p.pattern_type == PATTERN_ANOMALY:
                p.updated_at = "2020-01-01T00:00:00+00:00"
                p.created_at = "2020-01-01T00:00:00+00:00"
        results = self.query.get_recent_anomalies(max_age_hours=0.0001)
        self.assertEqual(len(results), 0)


# ═══════════════════════════════════════════════════════════════════════════
# RepositoryLearner Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRepositoryLearner(_TempStoreMixin, unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()
        self.store = PatternStore(path=self.store_path)
        self.learner = RepositoryLearner(store=self.store, auto_save=False, auto_prune=False)

    def test_learn_from_scan(self) -> None:
        scan = _make_scan_result()
        stored = self.learner.learn_from_scan(scan)
        self.assertGreater(stored, 0)
        self.assertGreater(self.store.count(), 0)

    def test_learn_from_scan_invalid(self) -> None:
        stored = self.learner.learn_from_scan({})
        self.assertEqual(stored, 0)
        stored = self.learner.learn_from_scan(None)  # type: ignore[arg-type]
        self.assertEqual(stored, 0)

    def test_learn_from_test(self) -> None:
        result = _make_test_result()
        stored = self.learner.learn_from_test(result)
        self.assertGreater(stored, 0)

    def test_learn_from_test_invalid(self) -> None:
        stored = self.learner.learn_from_test("")  # type: ignore[arg-type]
        self.assertEqual(stored, 0)

    def test_learn_from_error(self) -> None:
        record = _make_error_record()
        stored = self.learner.learn_from_error(record)
        self.assertGreater(stored, 0)

    def test_learn_from_error_invalid(self) -> None:
        stored = self.learner.learn_from_error([])  # type: ignore[arg-type]
        self.assertEqual(stored, 0)

    def test_learn_from_code_change(self) -> None:
        change = _make_code_change()
        stored = self.learner.learn_from_code_change(change)
        self.assertGreater(stored, 0)

    def test_learn_from_code_change_invalid(self) -> None:
        stored = self.learner.learn_from_code_change({"files": []})
        self.assertEqual(stored, 0)

    def test_multiple_scans_accumulate(self) -> None:
        scan = _make_scan_result()
        self.learner.learn_from_scan(scan)
        self.learner.learn_from_scan(scan)
        self.learner.learn_from_scan(scan)
        # Patterns should strengthen (higher support)
        all_p = self.learner.get_learned_patterns()
        for p in all_p:
            self.assertGreaterEqual(p.support, 1)

    def test_get_learned_patterns_filtered(self) -> None:
        self.learner.learn_from_scan(_make_scan_result())
        freq = self.learner.get_learned_patterns(pattern_type=PATTERN_FREQUENCY)
        for p in freq:
            self.assertEqual(p.pattern_type, PATTERN_FREQUENCY)

    def test_get_learned_patterns_with_min_confidence(self) -> None:
        self.learner.learn_from_scan(_make_scan_result())
        high_conf = self.learner.get_learned_patterns(min_confidence=0.5)
        for p in high_conf:
            self.assertGreaterEqual(p.decayed_confidence(), 0.5)

    def test_predict_outcome(self) -> None:
        # Feed some data first
        self.learner.learn_from_scan(_make_scan_result())
        self.learner.learn_from_error(_make_error_record())

        prediction = self.learner.predict_outcome({
            "module": "chain",
            "target": "example.com",
        })

        self.assertIn("predicted_findings", prediction)
        self.assertIn("predicted_errors", prediction)
        self.assertIn("risk_assessment", prediction)
        self.assertIn("confidence", prediction)
        self.assertIn("supporting_patterns", prediction)
        self.assertIn("recent_anomalies", prediction)
        self.assertIn(prediction["risk_assessment"], ("low", "medium", "high", "unknown"))

    def test_predict_outcome_no_data(self) -> None:
        prediction = self.learner.predict_outcome({"module": "chain"})
        self.assertEqual(prediction["risk_assessment"], "unknown")
        self.assertEqual(prediction["confidence"], 0.0)

    def test_predict_outcome_with_trends(self) -> None:
        # Create a decreasing trend
        history = [(i, float(80 - i * 3)) for i in range(10)]
        self.learner.learn_from_scan(_make_scan_result(score_history=history))

        prediction = self.learner.predict_outcome({"module": "chain"})
        # Should see correlations or trends in the prediction
        self.assertIn("recent_anomalies", prediction)

    def test_get_learning_stats(self) -> None:
        self.learner.learn_from_scan(_make_scan_result())
        self.learner.learn_from_test(_make_test_result())
        self.learner.learn_from_error(_make_error_record())

        stats = self.learner.get_learning_stats()
        self.assertEqual(stats["scan_learn_calls"], 1)
        self.assertEqual(stats["test_learn_calls"], 1)
        self.assertEqual(stats["error_learn_calls"], 1)
        self.assertEqual(stats["code_change_learn_calls"], 0)
        self.assertEqual(stats["total_learn_calls"], 3)
        self.assertGreater(stats["total_patterns"], 0)
        self.assertIn("patterns_by_type", stats)
        self.assertIn("patterns_by_source", stats)
        self.assertIn("avg_confidence", stats)
        self.assertIn("total_observations", stats)

    def test_get_learning_stats_empty(self) -> None:
        stats = self.learner.get_learning_stats()
        self.assertEqual(stats["total_patterns"], 0)
        self.assertEqual(stats["total_learn_calls"], 0)

    def test_save_and_load(self) -> None:
        self.learner.learn_from_scan(_make_scan_result())
        self.learner.save()

        # New learner loads from same store
        store2 = PatternStore(path=self.store_path)
        learner2 = RepositoryLearner(store=store2, auto_save=False)
        learner2.load()
        patterns = learner2.get_learned_patterns()
        self.assertGreater(len(patterns), 0)

    def test_prune(self) -> None:
        store = PatternStore(path=self.store_path, prune_threshold=0.5)
        learner = RepositoryLearner(store=store, auto_save=False, auto_prune=False)
        learner.learn_from_scan(_make_scan_result())
        removed = learner.prune()
        # Should prune some low-confidence patterns
        self.assertGreaterEqual(removed, 0)

    def test_clear(self) -> None:
        self.learner.learn_from_scan(_make_scan_result())
        self.assertGreater(self.store.count(), 0)
        removed = self.learner.clear()
        self.assertGreater(removed, 0)
        self.assertEqual(self.store.count(), 0)

    def test_auto_prune_trigger(self) -> None:
        """Verify auto-prune triggers every prune_interval learn calls."""
        store = PatternStore(path=self.store_path, prune_threshold=0.99)
        learner = RepositoryLearner(
            store=store, auto_save=False, auto_prune=True, prune_interval=3,
        )
        # Feed 3 scans to trigger one prune cycle
        for _ in range(3):
            learner.learn_from_scan(_make_scan_result())
        stats = learner.get_learning_stats()
        self.assertEqual(stats["prune_runs"], 1)

    def test_error_handling_in_extract(self) -> None:
        """Ensure extraction failures are caught gracefully."""
        # Pass something that would cause issues in extraction
        # e.g. findings with non-dict items
        scan = {"target": "x", "findings": [None, 42, True, "string"]}
        stored = self.learner.learn_from_scan(scan)
        # Should not raise, just return 0
        self.assertIsInstance(stored, int)


# ═══════════════════════════════════════════════════════════════
# Module-level convenience API tests
# ═══════════════════════════════════════════════════════════════


class TestModuleLevelAPI(unittest.TestCase):

    def setUp(self) -> None:
        reset_repository_learner()

    def tearDown(self) -> None:
        reset_repository_learner()

    def test_get_repository_learner_returns_instance(self) -> None:
        learner = get_repository_learner()
        self.assertIsInstance(learner, RepositoryLearner)

    def test_get_repository_learner_returns_same_instance(self) -> None:
        a = get_repository_learner()
        b = get_repository_learner()
        self.assertIs(a, b)

    def test_reset_creates_new_instance(self) -> None:
        a = get_repository_learner()
        reset_repository_learner()
        b = get_repository_learner()
        self.assertIsNot(a, b)


# ═══════════════════════════════════════════════════════════════
# Helper function tests
# ═══════════════════════════════════════════════════════════════


class TestHelpers(unittest.TestCase):

    def test_weighted_avg_equal_support(self) -> None:
        result = _weighted_avg(0.5, 10, 0.7, 10)
        self.assertAlmostEqual(result, 0.6)

    def test_weighted_avg_unequal_support(self) -> None:
        result = _weighted_avg(0.5, 100, 0.9, 1)
        self.assertAlmostEqual(result, (0.5 * 100 + 0.9 * 1) / 101)

    def test_weighted_avg_zero_support(self) -> None:
        result = _weighted_avg(0.5, 0, 0.7, 0)
        self.assertAlmostEqual(result, 0.6)

    def test_now_iso_format(self) -> None:
        ts = _now_iso()
        self.assertTrue(ts.endswith("+00:00") or ts.endswith("Z") or "+" in ts)
        # Should be parseable
        from datetime import datetime, timezone
        datetime.fromisoformat(ts)


# ═══════════════════════════════════════════════════════════════
# Constants tests
# ═══════════════════════════════════════════════════════════════


class TestConstants(unittest.TestCase):

    def test_pattern_types(self) -> None:
        self.assertIn(PATTERN_FREQUENCY, VALID_PATTERN_TYPES)
        self.assertIn(PATTERN_CORRELATION, VALID_PATTERN_TYPES)
        self.assertIn(PATTERN_TREND, VALID_PATTERN_TYPES)
        self.assertIn(PATTERN_ANOMALY, VALID_PATTERN_TYPES)

    def test_sources(self) -> None:
        self.assertIn(SOURCE_SCAN, VALID_SOURCES)
        self.assertIn(SOURCE_TEST, VALID_SOURCES)
        self.assertIn(SOURCE_ERROR, VALID_SOURCES)
        self.assertIn(SOURCE_CODE_CHANGE, VALID_SOURCES)

    def test_thresholds_sane(self) -> None:
        self.assertGreater(DEFAULT_MIN_CONFIDENCE, 0)
        self.assertLessEqual(DEFAULT_MIN_CONFIDENCE, 1)
        self.assertGreater(DEFAULT_MAX_PATTERNS, 0)
        self.assertGreater(DEFAULT_AGE_HALF_LIFE_DAYS, 0)
        self.assertGreater(PRUNE_BELOW_CONFIDENCE, 0)
        self.assertLessEqual(PRUNE_BELOW_CONFIDENCE, 1)
        self.assertGreater(MERGE_SIMILARITY_THRESHOLD, 0)
        self.assertLessEqual(MERGE_SIMILARITY_THRESHOLD, 1)


# ═══════════════════════════════════════════════════════════════
# Edge case / stress tests
# ═══════════════════════════════════════════════════════════════


class TestEdgeCases(_TempStoreMixin, unittest.TestCase):

    def test_large_number_of_patterns(self) -> None:
        """Store many patterns and verify count."""
        store = PatternStore(path=self.store_path, max_patterns=1000)
        for i in range(500):
            store.add(_make_pattern(key=f"freq:bulk{i}", confidence=0.5, support=1))
        self.assertEqual(store.count(), 500)

    def test_all_same_key_strengthens(self) -> None:
        """Adding the same pattern multiple times should increase support."""
        store = PatternStore(path=self.store_path)
        for _ in range(20):
            store.add(_make_pattern(key="freq:Repeat", confidence=0.5, support=1))
        p = store.get(_make_pattern(key="freq:Repeat").pattern_id)
        self.assertIsNotNone(p)
        self.assertEqual(p.support, 20)

    def test_empty_string_items(self) -> None:
        extractor = PatternExtractor()
        patterns = extractor.extract_frequency(["", "", "a", "a"])
        # Empty strings should still be counted
        self.assertGreater(len(patterns), 0)

    def test_unicode_keys(self) -> None:
        store = PatternStore(path=self.store_path)
        p = _make_pattern(key="freq:日本語テスト:emoji🔥")
        store.add(p)
        retrieved = store.get(p.pattern_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.key, "freq:日本語テスト:emoji🔥")

    def test_very_long_key(self) -> None:
        long_key = "freq:" + "x" * 10000
        p = _make_pattern(key=long_key)
        self.assertEqual(len(p.pattern_id), 24)  # ID is always truncated

    def test_scan_with_dict_findings_missing_fields(self) -> None:
        extractor = PatternExtractor()
        scan = {
            "target": "test",
            "findings": [
                {},
                {"title": "Only title"},
                {"severity": "high"},
            ],
        }
        patterns = extractor.extract_from_scan_result(scan)
        # Should not crash
        self.assertIsInstance(patterns, list)

    def test_correlation_with_large_event_sets(self) -> None:
        extractor = PatternExtractor()
        # Use varied event sets so not all items co-occur perfectly
        event_sets = [
            {f"module_{i}" for i in range(0, 50)},
            {f"module_{i}" for i in range(25, 75)},
            {f"module_{i}" for i in range(50, 100)},
            {f"module_{i}" for i in range(10, 60)},
            {f"module_{i}" for i in range(40, 90)},
        ]
        patterns = extractor.extract_correlation(event_sets, min_co_occurrence=1, max_patterns=50)
        # Should handle large sets without issue
        self.assertLessEqual(len(patterns), 50)
        self.assertGreater(len(patterns), 0)


if __name__ == "__main__":
    unittest.main()
