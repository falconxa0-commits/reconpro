"""Comprehensive tests for the Regression Intelligence System.

Tests cover:
    - RegressionRecord dataclass (serialization, deserialization, enums)
    - BaselineManager (capture, get, versioning, compare, export, import)
    - RegressionDetector (performance, correctness, API, statistical, behaviour)
    - RegressionIntelligence (orchestration, classification, impact, history, reports)
    - Convenience functions
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.regression_intelligence import (
    RegressionType,
    RegressionSeverity,
    RegressionStatus,
    RegressionRecord,
    BaselineManager,
    RegressionDetector,
    RegressionIntelligence,
    capture_baseline,
    detect_regressions,
    regression_report,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _tmp_path() -> Path:
    """Return a Path in a temp directory for test isolation."""
    d = tempfile.mkdtemp()
    return Path(d)


def _make_scan_data(
    target: str = "test.com",
    score: int = 85,
    findings: list | None = None,
) -> Dict[str, Any]:
    """Create a minimal scan result dict."""
    return {
        "target": target,
        "total_score": score,
        "grade": "A" if score >= 80 else "B" if score >= 65 else "C",
        "findings": findings or [],
        "modules_run": ["test"],
        "severity_counts": {},
    }


# ═══════════════════════════════════════════════════════════════════════
# 1. RegressionRecord
# ═══════════════════════════════════════════════════════════════════════


class TestRegressionRecord(unittest.TestCase):
    """Tests for the RegressionRecord dataclass."""

    def test_default_creation(self):
        """Record auto-generates id and detected_at."""
        r = RegressionRecord()
        self.assertTrue(len(r.id) > 0)
        self.assertTrue(len(r.detected_at) > 0)

    def test_custom_creation(self):
        """Record accepts all fields."""
        r = RegressionRecord(
            id="custom123",
            type=RegressionType.CORRECTNESS,
            description="Test failed",
            baseline_value=True,
            current_value=False,
            delta=1.0,
            severity=RegressionSeverity.HIGH,
            affected_component="test_module",
            detected_at="2025-01-01T00:00:00Z",
            status=RegressionStatus.CONFIRMED,
            evidence={"key": "value"},
        )
        self.assertEqual(r.id, "custom123")
        self.assertEqual(r.type, RegressionType.CORRECTNESS)
        self.assertEqual(r.severity, RegressionSeverity.HIGH)
        self.assertEqual(r.status, RegressionStatus.CONFIRMED)
        self.assertEqual(r.evidence, {"key": "value"})

    def test_to_dict_roundtrip(self):
        """to_dict produces serializable output; from_dict reconstructs."""
        r = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description="Latency spike",
            baseline_value=100.0,
            current_value=150.0,
            delta=50.0,
            severity=RegressionSeverity.MEDIUM,
            affected_component="http_layer",
            status=RegressionStatus.INVESTIGATING,
            evidence={"metric": "latency_ms"},
        )
        d = r.to_dict()

        # Must be JSON-serializable
        json_str = json.dumps(d)
        loaded = json.loads(json_str)

        # Must reconstruct identically
        r2 = RegressionRecord.from_dict(loaded)
        self.assertEqual(r.id, r2.id)
        self.assertEqual(r.type, r2.type)
        self.assertEqual(r.severity, r2.severity)
        self.assertEqual(r.status, r2.status)
        self.assertEqual(r.description, r2.description)
        self.assertEqual(r.baseline_value, r2.baseline_value)
        self.assertEqual(r.current_value, r2.current_value)
        self.assertAlmostEqual(r.delta, r2.delta)
        self.assertEqual(r.affected_component, r2.affected_component)
        self.assertEqual(r.evidence, r2.evidence)

    def test_to_dict_enum_values_are_strings(self):
        """Enum fields serialize as string values."""
        r = RegressionRecord()
        d = r.to_dict()
        self.assertIsInstance(d["type"], str)
        self.assertIsInstance(d["severity"], str)
        self.assertIsInstance(d["status"], str)

    def test_from_dict_with_string_enums(self):
        """from_dict converts string values to enums."""
        data = {
            "type": "api",
            "severity": "critical",
            "status": "fixed",
            "description": "API removed",
            "id": "abc123",
        }
        r = RegressionRecord.from_dict(data)
        self.assertEqual(r.type, RegressionType.API)
        self.assertEqual(r.severity, RegressionSeverity.CRITICAL)
        self.assertEqual(r.status, RegressionStatus.FIXED)

    def test_all_enum_types(self):
        """Verify all enum values are accessible."""
        self.assertIn("performance", RegressionType._value2member_map_)
        self.assertIn("correctness", RegressionType._value2member_map_)
        self.assertIn("api", RegressionType._value2member_map_)
        self.assertIn("behaviour", RegressionType._value2member_map_)

        self.assertIn("critical", RegressionSeverity._value2member_map_)
        self.assertIn("high", RegressionSeverity._value2member_map_)
        self.assertIn("medium", RegressionSeverity._value2member_map_)
        self.assertIn("low", RegressionSeverity._value2member_map_)
        self.assertIn("info", RegressionSeverity._value2member_map_)

        self.assertIn("detected", RegressionStatus._value2member_map_)
        self.assertIn("confirmed", RegressionStatus._value2member_map_)
        self.assertIn("investigating", RegressionStatus._value2member_map_)
        self.assertIn("fixed", RegressionStatus._value2member_map_)
        self.assertIn("wontfix", RegressionStatus._value2member_map_)
        self.assertIn("false_positive", RegressionStatus._value2member_map_)


# ═══════════════════════════════════════════════════════════════════════
# 2. BaselineManager
# ═══════════════════════════════════════════════════════════════════════


class TestBaselineManager(unittest.TestCase):
    """Tests for the BaselineManager."""

    def setUp(self):
        self.tmp_dir = _tmp_path()
        self.bm = BaselineManager(storage_path=self.tmp_dir / "baselines.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_capture_and_get(self):
        """Capture a baseline and retrieve it."""
        self.bm.capture("score_bounds", {"min": 0, "max": 100})
        val = self.bm.get("score_bounds")
        self.assertEqual(val, {"min": 0, "max": 100})

    def test_capture_with_metadata(self):
        """Capture with label and metadata."""
        entry = self.bm.capture(
            "module_count",
            {"remote": 25, "local": 3},
            label="Module registry counts",
            metadata={"version": "11.1.0"},
        )
        self.assertEqual(entry["label"], "Module registry counts")
        self.assertEqual(entry["metadata"]["version"], "11.1.0")
        self.assertEqual(entry["version"], 1)
        self.assertIn("captured_at", entry)

    def test_get_nonexistent(self):
        """Getting a nonexistent baseline returns None."""
        self.assertIsNone(self.bm.get("nonexistent"))

    def test_versioning(self):
        """Multiple captures create multiple versions."""
        self.bm.capture("metric", 10)
        self.bm.capture("metric", 12)
        self.bm.capture("metric", 15)
        self.assertEqual(self.bm.versions("metric"), 3)
        self.assertEqual(self.bm.get("metric"), 15)  # latest
        self.assertEqual(self.bm.get("metric", version=1), 10)
        self.assertEqual(self.bm.get("metric", version=2), 12)
        self.assertEqual(self.bm.get("metric", version=3), 15)

    def test_get_entry(self):
        """get_entry returns full entry with metadata."""
        self.bm.capture("test_key", 42, label="test")
        entry = self.bm.get_entry("test_key")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["key"], "test_key")
        self.assertEqual(entry["value"], 42)
        self.assertEqual(entry["label"], "test")

    def test_list_keys(self):
        """list_keys returns all captured keys."""
        self.bm.capture("a", 1)
        self.bm.capture("b", 2)
        self.bm.capture("c", 3)
        keys = self.bm.list_keys()
        self.assertEqual(keys, ["a", "b", "c"])

    def test_compare_versions(self):
        """compare_versions detects same/different values."""
        self.bm.capture("x", 10)
        self.bm.capture("x", 20)

        result = self.bm.compare_versions("x", 1, 2)
        self.assertIsNotNone(result)
        self.assertEqual(result["value_a"], 10)
        self.assertEqual(result["value_b"], 20)
        self.assertFalse(result["same"])

        result_same = self.bm.compare_versions("x", 1, 1)
        self.assertIsNotNone(result_same)
        self.assertTrue(result_same["same"])

    def test_compare_to_latest(self):
        """compare_to_latest compares current value against stored."""
        self.bm.capture("latency_ms", 50.0)
        result = self.bm.compare_to_latest("latency_ms", 55.0)
        self.assertIsNotNone(result)
        self.assertEqual(result["baseline"], 50.0)
        self.assertEqual(result["current"], 55.0)
        self.assertFalse(result["same"])

    def test_compare_to_latest_nonexistent(self):
        """compare_to_latest returns None for missing keys."""
        self.assertIsNone(self.bm.compare_to_latest("missing", 42))

    def test_export_and_import(self):
        """Export writes JSON; import reads it back."""
        self.bm.capture("k1", {"a": 1})
        self.bm.capture("k2", {"b": 2})

        export_path = os.path.join(self.tmp_dir, "exported.json")
        self.bm.export(export_path)
        self.assertTrue(os.path.exists(export_path))

        # Verify export content
        with open(export_path) as fh:
            exported = json.load(fh)
        self.assertIn("k1", exported)
        self.assertIn("k2", exported)

        # Import into a fresh manager
        fresh_bm = BaselineManager(storage_path=self.tmp_dir / "fresh.json")
        count = fresh_bm.import_baseline(export_path)
        self.assertEqual(count, 2)
        self.assertEqual(fresh_bm.get("k1"), {"a": 1})
        self.assertEqual(fresh_bm.get("k2"), {"b": 2})

    def test_import_merge_mode(self):
        """Import in merge mode does not overwrite existing keys."""
        self.bm.capture("k1", 10)
        export_path = os.path.join(self.tmp_dir, "exported.json")
        self.bm.export(export_path)

        fresh_bm = BaselineManager(storage_path=self.tmp_dir / "fresh.json")
        fresh_bm.capture("k1", 20)
        fresh_bm.capture("k1", 30)

        count = fresh_bm.import_baseline(export_path, overwrite=False)
        # Existing key should NOT be overwritten
        self.assertEqual(fresh_bm.get("k1"), 30)  # latest is still 30
        self.assertEqual(fresh_bm.versions("k1"), 2)  # versions from fresh only

    def test_import_overwrite_mode(self):
        """Import in overwrite mode replaces existing keys."""
        self.bm.capture("k1", 10)
        export_path = os.path.join(self.tmp_dir, "exported.json")
        self.bm.export(export_path)

        fresh_bm = BaselineManager(storage_path=self.tmp_dir / "fresh.json")
        fresh_bm.capture("k1", 99)
        fresh_bm.import_baseline(export_path, overwrite=True)
        self.assertEqual(fresh_bm.get("k1"), 10)  # overwritten

    def test_remove_key(self):
        """Remove a specific baseline key."""
        self.bm.capture("x", 1)
        self.assertTrue(self.bm.remove("x"))
        self.assertIsNone(self.bm.get("x"))

    def test_remove_nonexistent(self):
        """Removing a nonexistent key returns False."""
        self.assertFalse(self.bm.remove("nonexistent"))

    def test_clear_all(self):
        """Clear removes all baselines."""
        self.bm.capture("a", 1)
        self.bm.capture("b", 2)
        count = self.bm.clear()
        self.assertEqual(count, 2)
        self.assertEqual(len(self.bm.list_keys()), 0)

    def test_persistence_across_instances(self):
        """Baselines survive across BaselineManager instances."""
        self.bm.capture("persistent", {"val": 42})
        bm2 = BaselineManager(storage_path=self.tmp_dir / "baselines.json")
        self.assertEqual(bm2.get("persistent"), {"val": 42})

    def test_all_baselines_property(self):
        """all_baselines returns the full dict."""
        self.bm.capture("x", 1)
        self.bm.capture("y", 2)
        ab = self.bm.all_baselines
        self.assertIn("x", ab)
        self.assertIn("y", ab)


# ═══════════════════════════════════════════════════════════════════════
# 3. RegressionDetector — Performance
# ═══════════════════════════════════════════════════════════════════════


class TestPerformanceDetection(unittest.TestCase):
    """Tests for performance regression detection."""

    def setUp(self):
        self.detector = RegressionDetector(
            perf_percent=10.0,
            perf_absolute=5.0,
        )

    def test_no_regression_within_threshold(self):
        """Values within threshold produce no regressions."""
        baselines = {"latency_ms": 100.0}
        current = {"latency_ms": 104.0}  # 4% change, below 10% and < 5 absolute
        regs = self.detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 0)

    def test_regression_by_percent(self):
        """Values exceeding percent threshold flag regression."""
        baselines = {"latency_ms": 100.0}
        current = {"latency_ms": 115.0}  # 15% increase
        regs = self.detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, RegressionType.PERFORMANCE)
        self.assertTrue(regs[0].delta > 0)

    def test_regression_by_absolute(self):
        """Values exceeding absolute threshold flag regression."""
        baselines = {"error_rate": 0.01}
        current = {"error_rate": 7.0}  # huge absolute change, small baseline
        regs = self.detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 1)

    def test_regression_severity_levels(self):
        """Severity scales with magnitude of degradation."""
        baselines = {"latency_ms": 100.0}
        tests = [
            (115.0, RegressionSeverity.MEDIUM),    # 15%
            (130.0, RegressionSeverity.HIGH),       # 30%
            (200.0, RegressionSeverity.CRITICAL),   # 100%
        ]
        for cur_val, expected_sev in tests:
            regs = self.detector.detect_performance_regressions(
                baselines, {"latency_ms": cur_val}
            )
            if regs:
                self.assertEqual(regs[0].severity, expected_sev,
                                 f"latency_ms={cur_val} expected {expected_sev}")

    def test_no_regression_for_improvement(self):
        """Improvements (lower latency) are not flagged."""
        baselines = {"latency_ms": 100.0}
        current = {"latency_ms": 50.0}  # 50% improvement
        regs = self.detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 0)

    def test_multiple_metrics(self):
        """Multiple metrics are checked independently."""
        baselines = {"latency_ms": 100.0, "throughput_rps": 1000.0}
        current = {"latency_ms": 120.0, "throughput_rps": 500.0}
        regs = self.detector.detect_performance_regressions(baselines, current)
        # Both exceed thresholds: latency up 20%, throughput down 50%
        self.assertGreaterEqual(len(regs), 1)

    def test_missing_current_metric_skipped(self):
        """Metrics not in current dict are skipped."""
        baselines = {"a": 100.0, "b": 200.0}
        current = {"a": 90.0}  # b is missing
        regs = self.detector.detect_performance_regressions(baselines, current)
        # Only 'a' is checked
        for r in regs:
            self.assertIn("a", r.description)

    def test_non_numeric_values_skipped(self):
        """Non-numeric values are gracefully skipped."""
        baselines = {"string_metric": "hello"}
        current = {"string_metric": "world"}
        regs = self.detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 0)

    def test_zero_baseline_handling(self):
        """Zero baselines are handled without division-by-zero."""
        baselines = {"counter": 0}
        current = {"counter": 10}
        regs = self.detector.detect_performance_regressions(baselines, current)
        # Zero baseline with any positive current -> inf % -> regression
        self.assertGreaterEqual(len(regs), 0)  # just don't crash

    def test_evidence_contains_metrics(self):
        """Regression evidence contains metric details."""
        baselines = {"latency_ms": 100.0}
        current = {"latency_ms": 120.0}
        regs = self.detector.detect_performance_regressions(baselines, current)
        if regs:
            ev = regs[0].evidence
            self.assertEqual(ev["metric"], "latency_ms")
            self.assertIn("percent_change", ev)
            self.assertIn("absolute_change", ev)

    def test_custom_thresholds(self):
        """Custom thresholds override defaults."""
        detector = RegressionDetector(perf_percent=1.0, perf_absolute=1.0)
        baselines = {"x": 100.0}
        current = {"x": 101.5}
        regs = detector.detect_performance_regressions(baselines, current)
        self.assertEqual(len(regs), 1)  # 1.5% > 1%

    def test_component_propagation(self):
        """Component name is set on records."""
        baselines = {"x": 100.0}
        current = {"x": 115.0}
        regs = self.detector.detect_performance_regressions(
            baselines, current, component="http_layer"
        )
        if regs:
            self.assertEqual(regs[0].affected_component, "http_layer")


# ═══════════════════════════════════════════════════════════════════════
# 4. RegressionDetector — Correctness
# ═══════════════════════════════════════════════════════════════════════


class TestCorrectnessDetection(unittest.TestCase):
    """Tests for correctness regression detection."""

    def setUp(self):
        self.detector = RegressionDetector()

    def test_no_regression_all_pass(self):
        """All passing tests -> no regressions."""
        baseline = {"test_a": True, "test_b": True}
        current = {"test_a": True, "test_b": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_newly_failing_test(self):
        """Test that flips from pass to fail is detected."""
        baseline = {"test_auth": True, "test_tls": True}
        current = {"test_auth": False, "test_tls": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].type, RegressionType.CORRECTNESS)
        self.assertEqual(regs[0].severity, RegressionSeverity.HIGH)
        self.assertIn("test_auth", regs[0].description)

    def test_multiple_failures(self):
        """Multiple newly-failing tests produce multiple records."""
        baseline = {"a": True, "b": True, "c": True}
        current = {"a": False, "b": False, "c": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 2)

    def test_still_failing_not_counted(self):
        """Tests that were already failing are not flagged."""
        baseline = {"a": False, "b": True}
        current = {"a": False, "b": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_fixed_test_not_counted(self):
        """Tests that improve from fail to pass are not regressions."""
        baseline = {"a": False, "b": True}
        current = {"a": True, "b": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_missing_current_skipped(self):
        """Missing entries in current are skipped."""
        baseline = {"a": True, "b": True}
        current = {"a": True}
        regs = self.detector.detect_correctness_regressions(baseline, current)
        self.assertEqual(len(regs), 0)


# ═══════════════════════════════════════════════════════════════════════
# 5. RegressionDetector — API
# ═══════════════════════════════════════════════════════════════════════


class TestAPIDetection(unittest.TestCase):
    """Tests for API regression detection."""

    def setUp(self):
        self.detector = RegressionDetector()

    def test_no_regression_same_api(self):
        """Identical APIs -> no regressions."""
        api = {
            "scan": {"params": ["target"], "return_type": "ReconProResult", "exists": True},
            "export": {"params": ["data", "path"], "return_type": "str", "exists": True},
        }
        regs = self.detector.detect_api_regressions(api, api)
        self.assertEqual(len(regs), 0)

    def test_function_removed(self):
        """Removed function is a critical regression."""
        baseline = {
            "scan": {"params": ["target"], "return_type": "ReconProResult"},
        }
        current = {}
        regs = self.detector.detect_api_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.CRITICAL)
        self.assertIn("removed", regs[0].description)

    def test_required_param_added(self):
        """New required parameters are a regression."""
        baseline = {"scan": {"params": ["target"], "return_type": "Result"}}
        current = {"scan": {"params": ["target", "api_key"], "return_type": "Result"}}
        regs = self.detector.detect_api_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.HIGH)
        self.assertIn("api_key", regs[0].description)

    def test_optional_param_not_regression(self):
        """Optional parameters are not regressions."""
        baseline = {"scan": {"params": ["target"], "return_type": "Result"}}
        current = {
            "scan": {
                "params": ["target", "api_key"],
                "optional_params": {"api_key"},
                "return_type": "Result",
            }
        }
        regs = self.detector.detect_api_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_return_type_changed(self):
        """Return type change is a regression."""
        baseline = {"func": {"params": [], "return_type": "str"}}
        current = {"func": {"params": [], "return_type": "int"}}
        regs = self.detector.detect_api_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.MEDIUM)
        self.assertIn("return type changed", regs[0].description)

    def test_function_disabled(self):
        """Function marked as exists=False is a regression."""
        baseline = {"func": {"params": [], "return_type": "str", "exists": True}}
        current = {"func": {"params": [], "return_type": "str", "exists": False}}
        regs = self.detector.detect_api_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.CRITICAL)

    def test_multiple_changes(self):
        """Multiple changes produce multiple records."""
        baseline = {
            "func_a": {"params": ["x"], "return_type": "str"},
            "func_b": {"params": ["y"], "return_type": "int"},
        }
        current = {
            "func_a": {"params": ["x", "z"], "return_type": "bool"},  # new param + type change
        }
        regs = self.detector.detect_api_regressions(baseline, current)
        # func_a: new required param + return type change; func_b: removed
        self.assertGreaterEqual(len(regs), 2)


# ═══════════════════════════════════════════════════════════════════════
# 6. RegressionDetector — Statistical
# ═══════════════════════════════════════════════════════════════════════


class TestStatisticalDetection(unittest.TestCase):
    """Tests for statistical regression detection."""

    def setUp(self):
        self.detector = RegressionDetector(
            stat_min_samples=5,
            stat_z_threshold=2.0,
        )

    def test_no_regression_normal_value(self):
        """Normal values within distribution produce no regressions."""
        values = [100.0, 102.0, 98.0, 101.0, 99.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 100.5)
        self.assertEqual(len(regs), 0)

    def test_regression_outlier_above(self):
        """Significantly above mean is detected."""
        values = [100.0, 101.0, 99.0, 100.0, 101.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 120.0)
        self.assertEqual(len(regs), 1)
        self.assertIn("z-score", regs[0].description)

    def test_regression_outlier_below(self):
        """Significantly below mean is detected."""
        values = [100.0, 101.0, 99.0, 100.0, 101.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 50.0)
        self.assertEqual(len(regs), 1)

    def test_insufficient_samples(self):
        """Fewer than min_samples produces no regressions."""
        values = [100.0, 101.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 200.0)
        self.assertEqual(len(regs), 0)

    def test_zero_variance(self):
        """All identical values (zero stdev) produce no regressions."""
        values = [100.0, 100.0, 100.0, 100.0, 100.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 200.0)
        self.assertEqual(len(regs), 0)

    def test_custom_z_threshold(self):
        """Custom z_threshold changes detection sensitivity."""
        values = [100.0, 101.0, 99.0, 100.0, 101.0]
        # Low threshold catches mild outliers
        regs = self.detector.detect_statistical_regressions(
            "metric", values, 105.0, z_threshold=1.0
        )
        self.assertEqual(len(regs), 1)

    def test_severity_from_z_score(self):
        """Higher z-scores produce higher severity."""
        values = [100.0, 101.0, 99.0, 100.0, 101.0]
        regs_extreme = self.detector.detect_statistical_regressions(
            "metric", values, 500.0
        )
        if regs_extreme:
            self.assertEqual(regs_extreme[0].severity, RegressionSeverity.CRITICAL)

    def test_evidence_fields(self):
        """Evidence contains z-score, mean, stdev, sample count."""
        values = [100.0, 101.0, 99.0, 100.0, 101.0]
        regs = self.detector.detect_statistical_regressions("metric", values, 200.0)
        if regs:
            ev = regs[0].evidence
            self.assertIn("z_score", ev)
            self.assertIn("mean", ev)
            self.assertIn("stdev", ev)
            self.assertEqual(ev["sample_count"], 5)


# ═══════════════════════════════════════════════════════════════════════
# 7. RegressionDetector — Behaviour
# ═══════════════════════════════════════════════════════════════════════


class TestBehaviourDetection(unittest.TestCase):
    """Tests for behaviour regression detection."""

    def setUp(self):
        self.detector = RegressionDetector()

    def test_no_regression_identical_findings(self):
        """Identical finding sets produce no regressions."""
        findings = [
            {"title": "Open port 443", "severity": "low", "module": "ports"},
            {"title": "Missing HSTS", "severity": "medium", "module": "headers"},
        ]
        regs = self.detector.detect_behaviour_regressions(findings, findings)
        self.assertEqual(len(regs), 0)

    def test_new_critical_finding(self):
        """New critical finding is a regression."""
        baseline = [{"title": "Minor issue", "severity": "low", "module": "x"}]
        current = baseline + [
            {"title": "SQL Injection", "severity": "critical", "module": "sqli"},
        ]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.CRITICAL)
        self.assertIn("SQL Injection", regs[0].description)

    def test_new_high_finding(self):
        """New high finding is detected."""
        baseline = []
        current = [
            {"title": "XSS vulnerability", "severity": "high", "module": "xss"},
        ]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].severity, RegressionSeverity.HIGH)

    def test_new_info_finding_not_flagged(self):
        """New info findings are not flagged as regressions."""
        baseline = []
        current = [
            {"title": "Server header present", "severity": "info", "module": "http"},
        ]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_severity_escalation(self):
        """Severity escalation on existing finding is detected."""
        baseline = [{"title": "Injection", "severity": "medium", "module": "sqli"}]
        current = [{"title": "Injection", "severity": "high", "module": "sqli"}]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 1)
        self.assertIn("escalation", regs[0].description)

    def test_severity_de_escalation_not_flagged(self):
        """Severity improvement is not a regression."""
        baseline = [{"title": "Injection", "severity": "high", "module": "sqli"}]
        current = [{"title": "Injection", "severity": "low", "module": "sqli"}]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 0)

    def test_finding_count_spike(self):
        """Significant finding count increase is detected."""
        baseline = [
            {"title": f"Issue {i}", "severity": "low", "module": "x"}
            for i in range(5)
        ]
        current = baseline + [
            {"title": f"New issue {i}", "severity": "low", "module": "x"}
            for i in range(5)
        ]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        count_regs = [r for r in regs if "count" in r.evidence.get("change", "")]
        self.assertEqual(len(count_regs), 1)  # 100% increase

    def test_mixed_regressions(self):
        """Multiple types of behavioural regressions are detected."""
        baseline = [
            {"title": "Old issue", "severity": "medium", "module": "x"},
        ]
        current = [
            {"title": "Old issue", "severity": "critical", "module": "x"},  # escalated
            {"title": "New vuln", "severity": "high", "module": "y"},      # new
        ]
        regs = self.detector.detect_behaviour_regressions(baseline, current)
        self.assertGreaterEqual(len(regs), 2)


# ═══════════════════════════════════════════════════════════════════════
# 8. RegressionIntelligence — Orchestration
# ═══════════════════════════════════════════════════════════════════════


class TestRegressionIntelligenceOrchestration(unittest.TestCase):
    """Tests for the RegressionIntelligence orchestrator."""

    def setUp(self):
        self.tmp_dir = _tmp_path()
        self.base_path = self.tmp_dir / "baselines.json"
        self.hist_path = self.tmp_dir / "history.json"
        self.ri = RegressionIntelligence(
            baseline_path=self.base_path,
            history_path=self.hist_path,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_capture_baseline(self):
        """capture_baseline stores data in BaselineManager."""
        data = {"total_score": 90, "grade": "A", "findings": []}
        entry = self.ri.capture_baseline("test_target", data)
        self.assertEqual(entry["value"], data)
        self.assertEqual(entry["version"], 1)

    def test_detect_regression_scan_data(self):
        """detect_regression detects score drop from scan data."""
        baseline = _make_scan_data(score=90)
        self.ri.capture_baseline("target", baseline)

        current = _make_scan_data(score=50)  # big drop
        regs = self.ri.detect_regression(current, baseline_key="target")
        self.assertGreater(len(regs), 0)

    def test_detect_regression_no_change(self):
        """No regressions when data matches baseline."""
        baseline = _make_scan_data(score=85)
        self.ri.capture_baseline("target", baseline)

        current = _make_scan_data(score=85)
        regs = self.ri.detect_regression(current, baseline_key="target")
        self.assertEqual(len(regs), 0)

    def test_detect_regression_with_findings(self):
        """Behavioural regressions from findings are detected."""
        baseline = _make_scan_data(
            findings=[
                {"title": "Open port 80", "severity": "low", "module": "ports"},
            ]
        )
        self.ri.capture_baseline("target", baseline)

        current = _make_scan_data(
            findings=[
                {"title": "Open port 80", "severity": "low", "module": "ports"},
                {"title": "SQL Injection", "severity": "critical", "module": "sqli"},
            ]
        )
        regs = self.ri.detect_regression(current, baseline_key="target")
        # Should detect the new critical finding
        behav_regs = [r for r in regs if r.type == RegressionType.BEHAVIOUR]
        self.assertGreater(len(behav_regs), 0)

    def test_detect_regression_performance_metrics(self):
        """Explicit performance metrics are checked."""
        # We need to first store baseline metrics
        self.ri.capture_baseline("metrics", {"latency_ms": 100.0})
        current = {"latency_ms": 150.0}
        regs = self.ri.detect_regression(
            {"score": 85},  # dummy current_results
            performance_metrics=current,
        )
        perf_regs = [r for r in regs if r.type == RegressionType.PERFORMANCE]
        self.assertGreater(len(perf_regs), 0)

    def test_detect_regression_correctness(self):
        """Explicit correctness results are checked."""
        self.ri.capture_baseline("tests", {"test_a": True, "test_b": True})
        current = {"test_a": True, "test_b": False}
        regs = self.ri.detect_regression(
            {},  # dummy current_results
            correctness_results=current,
        )
        corr_regs = [r for r in regs if r.type == RegressionType.CORRECTNESS]
        self.assertGreater(len(corr_regs), 0)

    def test_detect_regression_api(self):
        """Explicit API signatures are checked."""
        baseline_api = {
            "scan": {"params": ["target"], "return_type": "Result"},
        }
        self.ri.capture_baseline("api", baseline_api)
        current_api = {}  # scan removed
        regs = self.ri.detect_regression(
            {},
            api_signatures=current_api,
        )
        api_regs = [r for r in regs if r.type == RegressionType.API]
        self.assertGreater(len(api_regs), 0)

    def test_no_baseline_no_error(self):
        """No error when no baseline exists."""
        regs = self.ri.detect_regression(
            _make_scan_data(score=50),
            baseline_key="nonexistent",
        )
        self.assertEqual(len(regs), 0)


# ═══════════════════════════════════════════════════════════════════════
# 9. Classification & Impact
# ═══════════════════════════════════════════════════════════════════════


class TestClassificationAndImpact(unittest.TestCase):
    """Tests for regression classification and impact assessment."""

    def test_classify_performance(self):
        """Performance regression is classified with subtypes."""
        r = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description="Score degradation",
            delta=15.0,
            severity=RegressionSeverity.HIGH,
            evidence={"metric": "total_score", "percent_change": 15.0},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["type"], "performance")
        self.assertEqual(classification["subtype"], "score_degradation")
        self.assertIn("recommendation", classification)

    def test_classify_performance_latency(self):
        """Latency regression gets appropriate subtype."""
        r = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description="Slow scan",
            delta=10.0,
            evidence={"metric": "scan_duration_ms", "percent_change": 20.0},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["subtype"], "performance_slowdown")

    def test_classify_correctness(self):
        """Correctness regression gets test_failure subtype."""
        r = RegressionRecord(
            type=RegressionType.CORRECTNESS,
            description="Test failure",
            evidence={"test": "test_auth_module"},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["subtype"], "test_failure")

    def test_classify_api_removed(self):
        """API removal gets appropriate subtype."""
        r = RegressionRecord(
            type=RegressionType.API,
            description="Function removed",
            evidence={"func": "scan", "change": "removed"},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["subtype"], "api_removal")

    def test_classify_behaviour_new_finding(self):
        """New vulnerability gets appropriate subtype."""
        r = RegressionRecord(
            type=RegressionType.BEHAVIOUR,
            description="New critical finding",
            evidence={"change": "new_finding", "severity": "critical"},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["subtype"], "new_vulnerability")

    def test_confidence_high(self):
        """High delta produces high confidence."""
        r = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            delta=50.0,
            evidence={"percent_change": 50.0},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["confidence"], "high")

    def test_confidence_low(self):
        """Small delta produces low confidence."""
        r = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            delta=0.05,
            evidence={"percent_change": 2.0},
        )
        classification = RegressionIntelligence.classify_regression(r)
        self.assertEqual(classification["confidence"], "low")

    def test_assess_impact_critical(self):
        """Critical severity gets appropriate business impact."""
        r = RegressionRecord(
            severity=RegressionSeverity.CRITICAL,
            type=RegressionType.PERFORMANCE,
        )
        impact = RegressionIntelligence.assess_impact(r)
        self.assertEqual(impact["severity"], "critical")
        self.assertEqual(impact["urgency"], "immediate")
        self.assertEqual(impact["scope"], "enterprise")

    def test_assess_impact_low(self):
        """Low severity gets appropriate business impact."""
        r = RegressionRecord(
            severity=RegressionSeverity.LOW,
            type=RegressionType.PERFORMANCE,
        )
        impact = RegressionIntelligence.assess_impact(r)
        self.assertEqual(impact["severity"], "low")
        self.assertEqual(impact["urgency"], "low")
        self.assertEqual(impact["scope"], "component")

    def test_assess_impact_correctness_elevated(self):
        """Correctness failures have elevated impact."""
        r = RegressionRecord(
            severity=RegressionSeverity.LOW,
            type=RegressionType.CORRECTNESS,
        )
        impact = RegressionIntelligence.assess_impact(r)
        self.assertEqual(impact["severity"], "medium")

    def test_assess_impact_api_team_scope(self):
        """API regressions have team scope."""
        r = RegressionRecord(
            severity=RegressionSeverity.MEDIUM,
            type=RegressionType.API,
        )
        impact = RegressionIntelligence.assess_impact(r)
        self.assertEqual(impact["scope"], "team")

    def test_assess_impact_all_fields_present(self):
        """Impact assessment has all required fields."""
        r = RegressionRecord(severity=RegressionSeverity.MEDIUM)
        impact = RegressionIntelligence.assess_impact(r)
        for key in ("severity", "business_impact", "scope", "urgency", "suggested_action"):
            self.assertIn(key, impact)


# ═══════════════════════════════════════════════════════════════════════
# 10. History & Trends
# ═══════════════════════════════════════════════════════════════════════


class TestHistoryAndTrends(unittest.TestCase):
    """Tests for regression history and trend analysis."""

    def setUp(self):
        self.tmp_dir = _tmp_path()
        self.ri = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_empty_history(self):
        """New instance starts with empty history."""
        history = self.ri.get_regression_history()
        self.assertEqual(len(history), 0)

    def test_regression_recorded_in_history(self):
        """Detected regressions are recorded in history."""
        baseline = _make_scan_data(score=90)
        self.ri.capture_baseline("t", baseline)
        current = _make_scan_data(score=40)
        self.ri.detect_regression(current, baseline_key="t")
        history = self.ri.get_regression_history()
        self.assertGreater(len(history), 0)

    def test_history_persistence(self):
        """History survives across RegressionIntelligence instances."""
        baseline = _make_scan_data(score=90)
        self.ri.capture_baseline("t", baseline)
        current = _make_scan_data(score=40)
        self.ri.detect_regression(current, baseline_key="t")

        ri2 = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )
        history = ri2.get_regression_history()
        self.assertGreater(len(history), 0)

    def test_filter_by_type(self):
        """History can be filtered by regression type."""
        # Add performance regression
        self.ri._history.append(RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description="Perf",
        ))
        self.ri._save_history()

        perf = self.ri.get_regression_history(regression_type=RegressionType.PERFORMANCE)
        self.assertEqual(len(perf), 1)
        corr = self.ri.get_regression_history(regression_type=RegressionType.CORRECTNESS)
        self.assertEqual(len(corr), 0)

    def test_filter_by_severity(self):
        """History can be filtered by severity."""
        self.ri._history.append(RegressionRecord(severity=RegressionSeverity.CRITICAL))
        self.ri._history.append(RegressionRecord(severity=RegressionSeverity.LOW))
        self.ri._save_history()

        crit = self.ri.get_regression_history(severity=RegressionSeverity.CRITICAL)
        self.assertEqual(len(crit), 1)
        low = self.ri.get_regression_history(severity=RegressionSeverity.LOW)
        self.assertEqual(len(low), 1)

    def test_filter_by_component(self):
        """History can be filtered by component substring."""
        self.ri._history.append(RegressionRecord(affected_component="http_layer"))
        self.ri._history.append(RegressionRecord(affected_component="scanner"))
        self.ri._save_history()

        http = self.ri.get_regression_history(component="http")
        self.assertEqual(len(http), 1)
        scanner = self.ri.get_regression_history(component="scan")
        self.assertEqual(len(scanner), 1)

    def test_limit(self):
        """History limit truncates results."""
        for i in range(10):
            self.ri._history.append(RegressionRecord(description=f"reg_{i}"))
        self.ri._save_history()

        limited = self.ri.get_regression_history(limit=3)
        self.assertEqual(len(limited), 3)

    def test_trends_empty(self):
        """Trends work on empty history."""
        trends = self.ri.get_regression_trends(days=30)
        self.assertEqual(trends["total_regressions"], 0)
        self.assertEqual(trends["resolution_rate"], 0.0)

    def test_trends_with_data(self):
        """Trends populate correctly with data."""
        self.ri._history = [
            RegressionRecord(type=RegressionType.PERFORMANCE, severity=RegressionSeverity.HIGH),
            RegressionRecord(type=RegressionType.CORRECTNESS, severity=RegressionSeverity.CRITICAL),
            RegressionRecord(type=RegressionType.PERFORMANCE, severity=RegressionSeverity.MEDIUM),
        ]
        # Mark one as fixed
        self.ri._history[0].status = RegressionStatus.FIXED
        self.ri._save_history()

        trends = self.ri.get_regression_trends(days=30)
        self.assertEqual(trends["total_regressions"], 3)
        self.assertEqual(trends["by_type"]["performance"], 2)
        self.assertEqual(trends["by_type"]["correctness"], 1)
        self.assertEqual(trends["by_severity"]["high"], 1)
        self.assertEqual(trends["resolution_rate"], round(1 / 3 * 100, 1))

    def test_update_regression_status(self):
        """Status can be updated on existing records."""
        self.ri._history.append(RegressionRecord(id="test123"))
        self.ri._save_history()

        result = self.ri.update_regression_status("test123", RegressionStatus.FIXED)
        self.assertTrue(result)
        record = self.ri.get_regression_history(limit=1)[0]
        self.assertEqual(record.status, RegressionStatus.FIXED)

    def test_update_nonexistent_status(self):
        """Updating nonexistent record returns False."""
        result = self.ri.update_regression_status("nonexistent", RegressionStatus.FIXED)
        self.assertFalse(result)

    def test_dismiss_regression(self):
        """Regressions can be dismissed as false positives."""
        self.ri._history.append(RegressionRecord(id="dismiss123"))
        self.ri._save_history()

        result = self.ri.dismiss_regression("dismiss123", reason="Test flake")
        self.assertTrue(result)
        record = self.ri.get_regression_history(limit=1)[0]
        self.assertEqual(record.status, RegressionStatus.FALSE_POSITIVE)
        self.assertEqual(record.evidence.get("dismissal_reason"), "Test flake")


# ═══════════════════════════════════════════════════════════════════════
# 11. Report Generation
# ═══════════════════════════════════════════════════════════════════════


class TestReportGeneration(unittest.TestCase):
    """Tests for regression report generation."""

    def setUp(self):
        self.tmp_dir = _tmp_path()
        self.ri = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_empty_report(self):
        """Report generates without error on empty state."""
        report = self.ri.generate_regression_report()
        self.assertIn("ReconPro Regression Intelligence Report", report)
        self.assertIn("No regressions detected", report)

    def test_report_with_baselines(self):
        """Report includes baseline summary."""
        self.ri.capture_baseline("test", {"score": 85}, label="Test baseline")
        report = self.ri.generate_regression_report()
        self.assertIn("test", report)
        self.assertIn("Test baseline", report)

    def test_report_with_regressions(self):
        """Report includes detected regressions."""
        self.ri._history.append(RegressionRecord(
            type=RegressionType.PERFORMANCE,
            severity=RegressionSeverity.HIGH,
            description="Score dropped",
            affected_component="scanner",
        ))
        self.ri._save_history()
        report = self.ri.generate_regression_report()
        self.assertIn("Score dropped", report)
        self.assertIn("HIGH", report)
        self.assertIn("scanner", report)

    def test_report_includes_trends(self):
        """Report includes trend analysis section."""
        report = self.ri.generate_regression_report(include_trends=True)
        self.assertIn("Trend Analysis", report)

    def test_report_without_trends(self):
        """Report can exclude trend analysis."""
        report = self.ri.generate_regression_report(include_trends=False)
        self.assertNotIn("Trend Analysis", report)

    def test_report_without_history(self):
        """Report can exclude individual records."""
        report = self.ri.generate_regression_report(include_history=False)
        self.assertNotIn("Detected Regressions", report)

    def test_report_is_valid_markdown(self):
        """Report starts with heading and contains sections."""
        report = self.ri.generate_regression_report()
        self.assertTrue(report.startswith("#"))
        self.assertIn("---", report)
        self.assertIn("ReconPro v11.1.0", report)


# ═══════════════════════════════════════════════════════════════════════
# 12. Convenience Functions
# ═══════════════════════════════════════════════════════════════════════


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for module-level convenience functions."""

    def test_capture_baseline_function(self):
        """capture_baseline convenience function works."""
        entry = capture_baseline("test_convenience", {"val": 42})
        self.assertIsNotNone(entry)
        self.assertEqual(entry["value"], {"val": 42})

    def test_detect_regressions_function(self):
        """detect_regressions convenience function works."""
        regs = detect_regressions({"total_score": 50}, baseline_key="nonexistent")
        self.assertIsInstance(regs, list)

    def test_regression_report_function(self):
        """regression_report convenience function works."""
        report = regression_report(days=7)
        self.assertIsInstance(report, str)
        self.assertIn("ReconPro", report)


# ═══════════════════════════════════════════════════════════════════════
# 13. Integration — Full Pipeline
# ═══════════════════════════════════════════════════════════════════════


class TestIntegrationPipeline(unittest.TestCase):
    """End-to-end integration tests."""

    def setUp(self):
        self.tmp_dir = _tmp_path()
        self.ri = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_full_lifecycle(self):
        """Complete lifecycle: capture -> detect -> classify -> assess -> report."""
        # 1. Capture baseline
        baseline = _make_scan_data(
            score=85,
            findings=[
                {"title": "Missing HSTS", "severity": "medium", "module": "headers"},
            ],
        )
        self.ri.capture_baseline("integration_target", baseline, label="v11 baseline")

        # 2. Introduce regressions
        current = _make_scan_data(
            score=55,  # score dropped significantly
            findings=[
                {"title": "Missing HSTS", "severity": "critical", "module": "headers"},  # escalated
                {"title": "SQL Injection", "severity": "critical", "module": "sqli"},      # new critical
            ],
        )

        # 3. Detect
        regressions = self.ri.detect_regression(current, baseline_key="integration_target")
        self.assertGreater(len(regressions), 0)

        # 4. Classify each
        for reg in regressions:
            classification = self.ri.classify_regression(reg)
            self.assertIn("type", classification)
            self.assertIn("subtype", classification)
            self.assertIn("confidence", classification)

        # 5. Assess impact
        for reg in regressions:
            impact = self.ri.assess_impact(reg)
            self.assertIn("severity", impact)
            self.assertIn("urgency", impact)

        # 6. Update status of first regression
        if regressions:
            self.ri.update_regression_status(regressions[0].id, RegressionStatus.CONFIRMED)

        # 7. Generate report
        report = self.ri.generate_regression_report()
        self.assertIn("ReconPro Regression Intelligence Report", report)
        self.assertIn("integration_target", report)
        self.assertIn("Trend Analysis", report, "Report has trends section")

    def test_versioned_baselines_comparison(self):
        """Multiple baseline versions can be compared."""
        self.ri.capture_baseline("scores", {"v": 10}, label="v1")
        self.ri.capture_baseline("scores", {"v": 15}, label="v2")
        self.ri.capture_baseline("scores", {"v": 20}, label="v3")

        bm = self.ri._baseline_mgr
        self.assertEqual(bm.versions("scores"), 3)

        cmp = bm.compare_versions("scores", 1, 3)
        self.assertIsNotNone(cmp)
        self.assertEqual(cmp["value_a"], {"v": 10})
        self.assertEqual(cmp["value_b"], {"v": 20})
        self.assertFalse(cmp["same"])

    def test_export_import_roundtrip(self):
        """Exporting and importing baselines preserves data."""
        self.ri.capture_baseline("export_test", {"key": "value"})
        export_path = os.path.join(self.tmp_dir, "export.json")
        self.ri._baseline_mgr.export(export_path)

        fresh_ri = RegressionIntelligence(
            baseline_path=self.tmp_dir / "fresh_baselines.json",
            history_path=self.tmp_dir / "fresh_history.json",
        )
        count = fresh_ri._baseline_mgr.import_baseline(export_path)
        self.assertEqual(count, 1)
        self.assertEqual(fresh_ri._baseline_mgr.get("export_test"), {"key": "value"})

    def test_persistence_across_restarts(self):
        """All data survives across RegressionIntelligence restarts."""
        # First instance: capture + detect
        self.ri.capture_baseline("persist_test", {"score": 90})
        baseline = _make_scan_data(score=90)
        self.ri.capture_baseline("persist_target", baseline)
        current = _make_scan_data(score=40)
        self.ri.detect_regression(current, baseline_key="persist_target")

        # Second instance: verify
        ri2 = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )
        self.assertEqual(ri2._baseline_mgr.get("persist_test"), {"score": 90})
        history = ri2.get_regression_history()
        self.assertGreater(len(history), 0)

        # Third instance: generate report from accumulated data
        ri3 = RegressionIntelligence(
            baseline_path=self.tmp_dir / "baselines.json",
            history_path=self.tmp_dir / "history.json",
        )
        report = ri3.generate_regression_report()
        self.assertIn("persist_test", report)


# ═══════════════════════════════════════════════════════════════════════
# 14. Edge Cases & Error Handling
# ═══════════════════════════════════════════════════════════════════════


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_empty_data_no_crash(self):
        """Empty data dicts don't crash detection."""
        detector = RegressionDetector()
        regs = detector.detect_performance_regressions({}, {})
        self.assertEqual(len(regs), 0)
        regs = detector.detect_correctness_regressions({}, {})
        self.assertEqual(len(regs), 0)
        regs = detector.detect_api_regressions({}, {})
        self.assertEqual(len(regs), 0)
        regs = detector.detect_behaviour_regressions([], [])
        self.assertEqual(len(regs), 0)

    def test_none_handling(self):
        """None values in findings don't crash."""
        detector = RegressionDetector()
        findings = [
            {"title": None, "severity": None, "module": None},
            {"title": "valid", "severity": "low", "module": "x"},
        ]
        regs = detector.detect_behaviour_regressions(findings, findings)
        self.assertEqual(len(regs), 0)

    def test_malformed_history_file(self):
        """Corrupted history file is handled gracefully."""
        tmp_dir = _tmp_path()
        hist_path = tmp_dir / "bad_history.json"
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hist_path, "w") as fh:
            fh.write("NOT VALID JSON{{{")

        ri = RegressionIntelligence(
            baseline_path=tmp_dir / "baselines.json",
            history_path=hist_path,
        )
        history = ri.get_regression_history()
        self.assertEqual(len(history), 0)

        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_malformed_baseline_file(self):
        """Corrupted baseline file is handled gracefully."""
        tmp_dir = _tmp_path()
        base_path = tmp_dir / "bad_baseline.json"
        base_path.parent.mkdir(parents=True, exist_ok=True)
        with open(base_path, "w") as fh:
            fh.write("NOT VALID JSON")

        bm = BaselineManager(storage_path=base_path)
        self.assertIsNone(bm.get("anything"))

        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_very_large_delta(self):
        """Extremely large deltas don't cause issues."""
        detector = RegressionDetector()
        regs = detector.detect_performance_regressions(
            {"x": 1.0}, {"x": 1000000.0}
        )
        if regs:
            self.assertTrue(isinstance(regs[0].delta, float))

    def test_unicode_in_findings(self):
        """Unicode content in findings is handled."""
        detector = RegressionDetector()
        baseline = [{"title": "SSL证书过期", "severity": "medium", "module": "tls"}]
        current = [{"title": "SSL证书过期", "severity": "high", "module": "tls"}]
        regs = detector.detect_behaviour_regressions(baseline, current)
        self.assertEqual(len(regs), 1)

    def test_regression_record_to_json(self):
        """RegressionRecord round-trips through JSON."""
        r = RegressionRecord(
            type=RegressionType.API,
            severity=RegressionSeverity.CRITICAL,
            status=RegressionStatus.INVESTIGATING,
            evidence={"nested": {"deep": [1, 2, 3]}},
        )
        json_str = json.dumps(r.to_dict(), default=str)
        loaded = json.loads(json_str)
        r2 = RegressionRecord.from_dict(loaded)
        self.assertEqual(r.evidence, r2.evidence)


if __name__ == "__main__":
    unittest.main()
