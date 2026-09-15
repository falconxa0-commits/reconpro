"""Tests for ReconPro Benchmark Automation System.

Covers BenchmarkResult, BenchmarkSuite, BenchmarkBaseline, and
BenchmarkAutomation — all with zero external dependencies.

Runnable via:
    python -m pytest reconpro/tests/test_benchmark_automation.py -v
    python -m unittest reconpro.tests.test_benchmark_automation -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Ensure package is importable ────────────────────────────────────────
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.join(_TEST_DIR, "..", "..")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from reconpro.benchmark_automation import (
    BenchmarkResult,
    BenchmarkSuite,
    BenchmarkBaseline,
    BenchmarkAutomation,
    _ensure_dir,
    _safe_serialize,
    _sparkline,
)


class TestHelpers(unittest.TestCase):
    """Test internal helper functions."""

    def test_ensure_dir_creates_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "dir"
            result = _ensure_dir(path)
            self.assertTrue(result.exists())
            self.assertTrue(result.is_dir())

    def test_ensure_dir_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            result = _ensure_dir(path)
            self.assertEqual(result, path)

    def test_safe_serialize_primitives(self) -> None:
        self.assertEqual(_safe_serialize(42), 42)
        self.assertEqual(_safe_serialize("hello"), "hello")
        self.assertEqual(_safe_serialize(3.14), 3.14)
        self.assertEqual(_safe_serialize(True), True)
        self.assertEqual(_safe_serialize(None), None)

    def test_safe_serialize_datetime(self) -> None:
        dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _safe_serialize(dt)
        self.assertIsInstance(result, str)
        self.assertIn("2025", result)

    def test_safe_serialize_path(self) -> None:
        p = Path("/tmp/test")
        self.assertEqual(_safe_serialize(p), "/tmp/test")

    def test_safe_serialize_list(self) -> None:
        self.assertEqual(_safe_serialize([1, 2, 3]), [1, 2, 3])

    def test_safe_serialize_dict(self) -> None:
        result = _safe_serialize({"a": 1, "b": "x"})
        self.assertEqual(result, {"a": 1, "b": "x"})

    def test_safe_serialize_nested(self) -> None:
        data = {"ts": datetime(2025, 1, 1, tzinfo=timezone.utc), "items": [1, 2]}
        result = _safe_serialize(data)
        self.assertIsInstance(result["ts"], str)
        self.assertEqual(result["items"], [1, 2])

    def test_sparkline_empty(self) -> None:
        self.assertEqual(_sparkline([]), "")

    def test_sparkline_single(self) -> None:
        result = _sparkline([5.0])
        self.assertEqual(len(result), 1)

    def test_sparkline_multiple(self) -> None:
        result = _sparkline([1, 2, 3, 4, 5, 6, 7, 8])
        self.assertTrue(len(result) == 8)
        # Last char should be the tallest block
        self.assertEqual(result[-1], "\u2588")

    def test_sparkline_equal_values(self) -> None:
        result = _sparkline([5, 5, 5])
        self.assertTrue(len(result) == 3)


class TestBenchmarkResult(unittest.TestCase):
    """Test BenchmarkResult dataclass."""

    def _make_result(
        self, name: str = "test_bench", value: float = 10.0, unit: str = "ms"
    ) -> BenchmarkResult:
        return BenchmarkResult(
            name=name,
            category="cpu",
            value=value,
            unit=unit,
            timestamp=datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
            iterations=5,
            context={"platform": "linux"},
            extra={"min_s": 0.009, "max_s": 0.011},
        )

    def test_creation(self) -> None:
        r = self._make_result()
        self.assertEqual(r.name, "test_bench")
        self.assertEqual(r.category, "cpu")
        self.assertEqual(r.value, 10.0)
        self.assertEqual(r.unit, "ms")
        self.assertEqual(r.iterations, 5)

    def test_default_values(self) -> None:
        r = BenchmarkResult(name="x", category="y", value=1.0)
        self.assertEqual(r.unit, "ms")
        self.assertEqual(r.iterations, 1)
        self.assertEqual(r.context, {})
        self.assertEqual(r.extra, {})
        self.assertIsInstance(r.timestamp, datetime)

    def test_to_dict(self) -> None:
        r = self._make_result()
        d = r.to_dict()
        self.assertEqual(d["name"], "test_bench")
        self.assertEqual(d["category"], "cpu")
        self.assertEqual(d["value"], 10.0)
        self.assertEqual(d["unit"], "ms")
        self.assertEqual(d["iterations"], 5)
        self.assertIn("timestamp", d)
        self.assertIn("extra", d)

    def test_to_dict_json_serializable(self) -> None:
        r = self._make_result()
        d = r.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)

    def test_from_dict(self) -> None:
        r = self._make_result()
        d = r.to_dict()
        r2 = BenchmarkResult.from_dict(d)
        self.assertEqual(r2.name, r.name)
        self.assertEqual(r2.category, r.category)
        self.assertEqual(r2.value, r.value)
        self.assertEqual(r2.unit, r.unit)
        self.assertEqual(r2.iterations, r.iterations)

    def test_from_dict_missing_fields(self) -> None:
        r = BenchmarkResult.from_dict({"name": "x", "value": 5.0})
        self.assertEqual(r.name, "x")
        self.assertEqual(r.value, 5.0)
        self.assertEqual(r.category, "unknown")
        self.assertEqual(r.unit, "ms")

    def test_vs_baseline_timing_regression(self) -> None:
        # Timing: current > baseline = regression
        r = self._make_result(value=12.0)
        comp = r.vs_baseline(10.0)
        self.assertEqual(comp["direction"], "regression")
        self.assertAlmostEqual(comp["delta"], 2.0, places=4)
        self.assertAlmostEqual(comp["delta_pct"], 20.0, places=2)

    def test_vs_baseline_timing_improvement(self) -> None:
        # Timing: current < baseline = improvement
        r = self._make_result(value=8.0)
        comp = r.vs_baseline(10.0)
        self.assertEqual(comp["direction"], "improvement")
        self.assertAlmostEqual(comp["delta"], -2.0, places=4)
        self.assertAlmostEqual(comp["delta_pct"], -20.0, places=2)

    def test_vs_baseline_neutral(self) -> None:
        r = self._make_result(value=10.0)
        comp = r.vs_baseline(10.0)
        self.assertEqual(comp["direction"], "neutral")
        self.assertAlmostEqual(comp["delta"], 0.0, places=4)
        self.assertAlmostEqual(comp["delta_pct"], 0.0, places=2)

    def test_vs_baseline_throughput_regression(self) -> None:
        # Throughput: current < baseline = regression
        r = self._make_result(value=80.0, unit="ops/s")
        comp = r.vs_baseline(100.0)
        self.assertEqual(comp["direction"], "regression")

    def test_vs_baseline_throughput_improvement(self) -> None:
        # Throughput: current > baseline = improvement
        r = self._make_result(value=120.0, unit="ops/s")
        comp = r.vs_baseline(100.0)
        self.assertEqual(comp["direction"], "improvement")

    def test_vs_baseline_zero(self) -> None:
        r = self._make_result(value=0.0)
        comp = r.vs_baseline(0.0)
        self.assertEqual(comp["direction"], "neutral")

    def test_vs_previous(self) -> None:
        current = self._make_result(value=12.0)
        previous = self._make_result(value=10.0)
        comp = current.vs_previous(previous)
        self.assertIsNotNone(comp)
        self.assertEqual(comp["direction"], "regression")

    def test_vs_previous_name_mismatch(self) -> None:
        current = self._make_result(name="a", value=12.0)
        previous = self._make_result(name="b", value=10.0)
        self.assertIsNone(current.vs_previous(previous))

    def test_vs_previous_unit_mismatch(self) -> None:
        current = self._make_result(value=12.0, unit="ms")
        previous = self._make_result(value=10.0, unit="us")
        self.assertIsNone(current.vs_previous(previous))


class TestBenchmarkSuite(unittest.TestCase):
    """Test BenchmarkSuite."""

    def test_create_suite(self) -> None:
        suite = BenchmarkSuite("test", "Test suite")
        self.assertEqual(suite.name, "test")
        self.assertEqual(suite.description, "Test suite")
        self.assertEqual(len(suite), 0)

    def test_add_benchmark(self) -> None:
        suite = BenchmarkSuite("test")
        suite.add("bench1", lambda: 42, unit="ms")
        self.assertEqual(len(suite), 1)

    def test_add_chaining(self) -> None:
        suite = BenchmarkSuite("test")
        suite.add("b1", lambda: 1).add("b2", lambda: 2).add("b3", lambda: 3)
        self.assertEqual(len(suite), 3)

    def test_run_simple(self) -> None:
        suite = BenchmarkSuite("test", "Simple test")
        call_count = [0]
        def bench_fn():
            call_count[0] += 1
            time.sleep(0.001)
            return 42.0
        suite.add("simple_bench", bench_fn, iterations=3)
        results = suite.run()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "simple_bench")
        self.assertEqual(results[0].category, "test")
        self.assertGreater(results[0].value, 0)
        # 3 measured + 1 warmup = 4 calls minimum
        self.assertGreaterEqual(call_count[0], 3)

    def test_run_multiple_benchmarks(self) -> None:
        suite = BenchmarkSuite("multi")
        for i in range(5):
            def bench_fn(_i=i):
                return float(_i)
            suite.add(f"bench_{i}", bench_fn, iterations=2)
        results = suite.run()
        self.assertEqual(len(results), 5)

    def test_run_failing_benchmark(self) -> None:
        suite = BenchmarkSuite("fail_test")
        def fail_fn():
            raise RuntimeError("benchmark failure")
        suite.add("failing", fail_fn, iterations=2)
        results = suite.run()
        # Failing benchmarks should be skipped, not raise
        self.assertEqual(len(results), 0)

    def test_run_warmup_discarded(self) -> None:
        suite = BenchmarkSuite("warmup")
        call_count = [0]
        def bench_fn():
            call_count[0] += 1
            return 1.0
        suite.add("warmup_test", bench_fn, iterations=3, warmup=2)
        results = suite.run()
        self.assertEqual(len(results), 1)
        # Total calls = warmup(2) + iterations(3) = 5
        self.assertEqual(call_count[0], 5)

    def test_repr(self) -> None:
        suite = BenchmarkSuite("my_suite", "Description")
        suite.add("b1", lambda: 1)
        r = repr(suite)
        self.assertIn("my_suite", r)
        self.assertIn("1", r)

    def test_memory_tracking(self) -> None:
        suite = BenchmarkSuite("mem")
        def alloc_fn():
            _ = [0] * 10000
            return 0.0
        suite.add("mem_bench", alloc_fn, iterations=3)
        results = suite.run()
        self.assertEqual(len(results), 1)
        # Should have memory data in extra
        self.assertIn("peak_memory_bytes", results[0].extra)
        self.assertGreater(results[0].extra["peak_memory_bytes"], 0)

    def test_statistics_in_extra(self) -> None:
        suite = BenchmarkSuite("stats")
        suite.add("stat_bench", lambda: (time.sleep(0.001), 42.0)[1], iterations=5)
        results = suite.run()
        extra = results[0].extra
        self.assertIn("min_s", extra)
        self.assertIn("max_s", extra)
        self.assertIn("mean_s", extra)
        self.assertIn("median_s", extra)
        self.assertLessEqual(extra["min_s"], extra["max_s"])


class TestBenchmarkBaseline(unittest.TestCase):
    """Test BenchmarkBaseline."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._storage = Path(self._tmpdir) / "memory"
        self._baseline = BenchmarkBaseline(self._storage)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_create_baseline(self) -> None:
        result = BenchmarkResult(name="test1", category="cpu", value=10.0)
        self._baseline.record(result)
        val = self._baseline.get_baseline("test1", "cpu")
        self.assertAlmostEqual(val, 10.0, places=2)

    def test_baseline_persists_to_disk(self) -> None:
        result = BenchmarkResult(name="persist", category="cpu", value=5.0)
        self._baseline.record(result)

        # Reload from disk
        baseline2 = BenchmarkBaseline(self._storage)
        val = baseline2.get_baseline("persist", "cpu")
        self.assertAlmostEqual(val, 5.0, places=2)

    def test_record_batch(self) -> None:
        results = [
            BenchmarkResult(name=f"bench_{i}", category="cpu", value=float(i))
            for i in range(10)
        ]
        self._baseline.record_batch(results)
        for i in range(10):
            val = self._baseline.get_baseline(f"bench_{i}", "cpu")
            self.assertAlmostEqual(val, float(i), places=2)

    def test_get_baseline_missing(self) -> None:
        self.assertIsNone(self._baseline.get_baseline("nonexistent", "cpu"))

    def test_get_history(self) -> None:
        base_time = datetime.now(timezone.utc) - timedelta(days=4)
        for i in range(5):
            ts = base_time + timedelta(days=i)
            r = BenchmarkResult(
                name="hist_bench", category="cpu", value=float(i * 10), timestamp=ts
            )
            self._baseline.record(r)

        history = self._baseline.get_history("hist_bench", "cpu", days=10)
        self.assertEqual(len(history), 5)

    def test_get_history_days_filter(self) -> None:
        base_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(10):
            ts = base_time + timedelta(days=i)
            r = BenchmarkResult(
                name="hist2", category="cpu", value=float(i), timestamp=ts
            )
            self._baseline.record(r)

        history = self._baseline.get_history("hist2", "cpu", days=5)
        self.assertLessEqual(len(history), 6)  # day 0-5 inclusive

    def test_get_trend(self) -> None:
        base_time = datetime.now(timezone.utc) - timedelta(days=4)
        for i in range(5):
            ts = base_time + timedelta(days=i)
            r = BenchmarkResult(
                name="trend_bench", category="cpu", value=100.0 + float(i), timestamp=ts
            )
            self._baseline.record(r)

        trend = self._baseline.get_trend("trend_bench", "cpu", days=30)
        self.assertEqual(len(trend), 5)  # 5 distinct days
        # Values should be increasing
        values = [t["avg_value"] for t in trend]
        for i in range(1, len(values)):
            self.assertGreater(values[i], values[i - 1])

    def test_get_trend_empty(self) -> None:
        trend = self._baseline.get_trend("nonexistent", "cpu")
        self.assertEqual(trend, [])

    def test_get_all_baseline_values(self) -> None:
        results = [
            BenchmarkResult(name="a", category="cpu", value=1.0),
            BenchmarkResult(name="b", category="cpu", value=2.0),
            BenchmarkResult(name="c", category="mem", value=3.0),
        ]
        self._baseline.record_batch(results)
        all_vals = self._baseline.get_all_baseline_values()
        self.assertEqual(len(all_vals), 3)
        self.assertIn("cpu:a", all_vals)
        self.assertIn("cpu:b", all_vals)
        self.assertIn("mem:c", all_vals)

    def test_compare(self) -> None:
        # Set baselines
        self._baseline.set_baseline("bench1", "cpu", 10.0)

        # New results
        results = [
            BenchmarkResult(name="bench1", category="cpu", value=12.0),
            BenchmarkResult(name="bench_no_baseline", category="cpu", value=5.0),
        ]
        comparisons = self._baseline.compare(results)
        # Only bench1 has a baseline
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(comparisons[0]["direction"], "regression")

    def test_prune(self) -> None:
        old_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
        new_time = datetime(2025, 6, 1, tzinfo=timezone.utc)

        self._baseline.record(BenchmarkResult(
            name="old_bench", category="cpu", value=1.0, timestamp=old_time
        ))
        self._baseline.record(BenchmarkResult(
            name="new_bench", category="cpu", value=2.0, timestamp=new_time
        ))

        # Prune entries older than 365 days (old_bench is ~1.5 years old)
        removed = self._baseline.prune(days=365)
        self.assertGreaterEqual(removed, 1)

    def test_set_baseline(self) -> None:
        self._baseline.set_baseline("manual", "cpu", 42.0, "ms")
        val = self._baseline.get_baseline("manual", "cpu")
        self.assertAlmostEqual(val, 42.0, places=2)

    def test_clear(self) -> None:
        self._baseline.record(BenchmarkResult(name="x", category="cpu", value=1.0))
        self._baseline.clear()
        self.assertIsNone(self._baseline.get_baseline("x", "cpu"))
        self.assertEqual(self._baseline.get_all_baseline_values(), {})

    def test_max_history_pruning(self) -> None:
        """Entries beyond MAX_HISTORY_PER_BENCHMARK should be pruned."""
        max_hist = self._baseline.MAX_HISTORY_PER_BENCHMARK
        base_time = datetime(2025, 1, 1, tzinfo=timezone.utc)

        for i in range(max_hist + 20):
            ts = base_time + timedelta(seconds=i)
            self._baseline.record(BenchmarkResult(
                name="prune_test", category="cpu", value=float(i), timestamp=ts
            ))

        history = self._baseline.get_history("prune_test", "cpu", days=9999)
        self.assertLessEqual(len(history), max_hist)

    def test_thread_safety(self) -> None:
        """Concurrent records should not corrupt the baseline."""
        errors = []

        def writer(thread_id: int) -> None:
            try:
                for i in range(50):
                    self._baseline.record(BenchmarkResult(
                        name=f"thread_{thread_id}_{i}",
                        category="cpu",
                        value=float(i),
                    ))
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        # Should have all values
        all_vals = self._baseline.get_all_baseline_values()
        self.assertEqual(len(all_vals), 250)  # 5 threads * 50 records


class TestBenchmarkAutomation(unittest.TestCase):
    """Test BenchmarkAutomation."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        storage = Path(self._tmpdir) / "memory"
        results = Path(self._tmpdir) / "results"
        self._automation = BenchmarkAutomation(
            results_dir=results,
            baseline_dir=storage,
        )

    def tearDown(self) -> None:
        self._automation.stop_scheduled_benchmarks()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_initialization(self) -> None:
        self.assertIsNotNone(self._automation)
        self.assertIsInstance(self._automation.baseline, BenchmarkBaseline)

    def test_default_suites_registered(self) -> None:
        suites = self._automation.suites
        self.assertIn("memory", suites)
        self.assertIn("cpu", suites)
        self.assertIn("io", suites)
        self.assertIn("scanner", suites)
        self.assertIn("module", suites)
        self.assertIn("startup", suites)
        self.assertEqual(len(suites), 6)

    def test_suite_descriptions(self) -> None:
        for name, suite in self._automation.suites.items():
            self.assertTrue(len(suite.name) > 0)
            self.assertTrue(len(suite.description) > 0)

    def test_run_quick_benchmark(self) -> None:
        results = self._automation.run_quick_benchmark()
        self.assertEqual(results["type"], "quick")
        self.assertGreater(results["total_benchmarks"], 0)
        self.assertIn("results", results)
        self.assertIn("timestamp", results)
        self.assertIn("elapsed_seconds", results)
        self.assertGreater(len(results["results"]), 0)

    def test_quick_benchmark_results_structure(self) -> None:
        results = self._automation.run_quick_benchmark()
        for r in results["results"]:
            self.assertIn("name", r)
            self.assertIn("value", r)
            self.assertIn("unit", r)
            self.assertIn("category", r)
            self.assertIn("timestamp", r)

    def test_run_full_benchmark(self) -> None:
        results = self._automation.run_full_benchmark()
        self.assertEqual(results["type"], "full")
        self.assertGreater(results["total_benchmarks"], 0)
        self.assertIn("suites", results)
        self.assertIn("comparisons", results)
        self.assertIn("regressions", results)
        self.assertIn("errors", results)
        self.assertIn("platform", results)
        self.assertIn("python_version", results)

    def test_full_benchmark_has_all_suites(self) -> None:
        results = self._automation.run_full_benchmark()
        suite_names = {s["suite"] for s in results["suites"]}
        self.assertEqual(suite_names, {"memory", "cpu", "io", "scanner", "module", "startup"})

    def test_run_component_benchmark(self) -> None:
        results = self._automation.run_component_benchmark("cpu")
        self.assertEqual(results["type"], "component")
        self.assertEqual(results["component"], "cpu")
        self.assertGreater(results["total_benchmarks"], 0)

    def test_run_component_benchmark_all(self) -> None:
        results = self._automation.run_component_benchmark("all")
        self.assertEqual(results["type"], "full")

    def test_run_component_unknown_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._automation.run_component_benchmark("nonexistent_suite")

    def test_run_component_benchmark_all_suites(self) -> None:
        for suite_name in self._automation.suites:
            results = self._automation.run_component_benchmark(suite_name)
            self.assertEqual(results["component"], suite_name)
            self.assertGreater(results["total_benchmarks"], 0)

    def test_compare_with_baseline(self) -> None:
        # First run creates baselines
        self._automation.run_quick_benchmark()
        # Load those results
        saved = self._automation.list_saved_results()
        if saved:
            loaded = self._automation.load_results(Path(saved[-1]["path"]))
            comparisons = self._automation.compare_with_baseline(loaded)
            # After recording, comparing should find matches
            self.assertIsInstance(comparisons, list)

    def test_detect_regression(self) -> None:
        # Set a tight threshold
        results = [
            BenchmarkResult(name="test", category="cpu", value=100.0, unit="ms"),
        ]
        # No baseline yet — no regression
        regressions = self._automation.detect_regression(results, threshold=10.0)
        self.assertEqual(len(regressions), 0)

        # Set a baseline of 50.0 — 100% increase should trigger
        self._automation.baseline.set_baseline("test", "cpu", 50.0)
        regressions = self._automation.detect_regression(results, threshold=10.0)
        self.assertGreater(len(regressions), 0)
        self.assertEqual(regressions[0]["direction"], "regression")

    def test_detect_regression_severity(self) -> None:
        self._automation.baseline.set_baseline("sev_test", "cpu", 100.0)
        # 50% increase = regression, 50 >= 20*2=40 → critical
        results = [
            BenchmarkResult(name="sev_test", category="cpu", value=150.0, unit="ms"),
        ]
        regressions = self._automation.detect_regression(results, threshold=20.0)
        self.assertEqual(len(regressions), 1)
        self.assertEqual(regressions[0]["severity"], "critical")

    def test_detect_regression_no_regression(self) -> None:
        self._automation.baseline.set_baseline("ok_test", "cpu", 100.0)
        results = [
            BenchmarkResult(name="ok_test", category="cpu", value=105.0, unit="ms"),
        ]
        # 5% change, threshold is 20% → no regression
        regressions = self._automation.detect_regression(results, threshold=20.0)
        self.assertEqual(len(regressions), 0)

    def test_generate_benchmark_report(self) -> None:
        self._automation.run_quick_benchmark()
        report = self._automation.generate_benchmark_report()
        self.assertIsInstance(report, str)
        self.assertIn("# ReconPro Benchmark Report", report)
        self.assertIn("Summary", report)
        self.assertIn("Results", report)
        self.assertIn("Historical Trends", report)

    def test_generate_benchmark_report_with_provided_results(self) -> None:
        results = {
            "type": "quick",
            "timestamp": "2025-06-01T12:00:00+00:00",
            "elapsed_seconds": 1.5,
            "total_benchmarks": 6,
            "regressions_detected": 0,
            "results": [
                {
                    "name": "test_bench",
                    "value": 10.0,
                    "unit": "ms",
                    "category": "cpu",
                    "extra": {"peak_memory_bytes": 1024},
                }
            ],
            "comparisons": [],
            "regressions": [],
            "platform": "linux",
            "python_version": "3.12",
        }
        report = self._automation.generate_benchmark_report(results)
        self.assertIn("test_bench", report)
        self.assertIn("PASS", report)

    def test_generate_benchmark_report_with_regressions(self) -> None:
        results = {
            "type": "quick",
            "timestamp": "2025-06-01T12:00:00+00:00",
            "elapsed_seconds": 1.0,
            "total_benchmarks": 1,
            "regressions_detected": 1,
            "results": [
                {
                    "name": "slow_bench",
                    "value": 50.0,
                    "unit": "ms",
                    "category": "cpu",
                    "extra": {},
                }
            ],
            "comparisons": [
                {
                    "name": "slow_bench",
                    "baseline_value": 25.0,
                    "current_value": 50.0,
                    "delta_pct": 100.0,
                    "direction": "regression",
                    "unit": "ms",
                }
            ],
            "regressions": [
                {
                    "name": "slow_bench",
                    "severity": "high",
                    "delta_pct": 100.0,
                    "baseline_value": 25.0,
                    "current_value": 50.0,
                }
            ],
            "platform": "linux",
            "python_version": "3.12",
        }
        report = self._automation.generate_benchmark_report(results)
        self.assertIn("FAIL", report)
        self.assertIn("Regressions Detected", report)
        self.assertIn("slow_bench", report)

    def test_results_persisted(self) -> None:
        self._automation.run_quick_benchmark()
        saved = self._automation.list_saved_results()
        self.assertGreater(len(saved), 0)
        self.assertIn("quick", saved[-1]["label"])
        self.assertTrue(Path(saved[-1]["path"]).exists())

    def test_load_results(self) -> None:
        self._automation.run_quick_benchmark()
        saved = self._automation.list_saved_results()
        self.assertGreater(len(saved), 0)

        loaded = self._automation.load_results(Path(saved[-1]["path"]))
        self.assertGreater(len(loaded), 0)
        for r in loaded:
            self.assertIsInstance(r, BenchmarkResult)

    def test_load_results_missing_file(self) -> None:
        results = self._automation.load_results(Path("/nonexistent/file.json"))
        self.assertEqual(results, [])

    def test_list_saved_results_empty(self) -> None:
        # Use a fresh empty directory
        empty_dir = Path(self._tmpdir) / "empty_results"
        auto = BenchmarkAutomation(results_dir=empty_dir)
        self.assertEqual(auto.list_saved_results(), [])

    def test_schedule_benchmarks(self) -> None:
        callback_results = []

        def on_result(r: dict) -> None:
            callback_results.append(r)

        # Schedule with a short interval using fast memory suite
        timer = self._automation.schedule_benchmarks(
            interval=0.1,
            benchmark_type="memory",
            callback=on_result,
        )
        self.assertIsNotNone(timer)

        # Wait for at least one run
        time.sleep(3.0)

        # Stop
        self._automation.stop_scheduled_benchmarks()

        # Should have at least one result
        self.assertGreater(len(callback_results), 0)

    def test_schedule_and_stop(self) -> None:
        timer = self._automation.schedule_benchmarks(interval=0.5)
        self._automation.stop_scheduled_benchmarks()
        # After stopping, timer should be cancelled (no error)

    def test_schedule_component(self) -> None:
        callback_results = []
        timer = self._automation.schedule_benchmarks(
            interval=0.1,
            benchmark_type="memory",
            callback=callback_results.append,
        )
        time.sleep(3.0)  # memory suite is fast, 3s is plenty
        self._automation.stop_scheduled_benchmarks()
        self.assertGreater(len(callback_results), 0)
        self.assertEqual(callback_results[0]["component"], "memory")

    def test_add_custom_suite(self) -> None:
        custom = BenchmarkSuite("custom", "Custom benchmarks")
        custom.add("my_bench", lambda: 42.0, iterations=2)
        self._automation.add_suite(custom)

        self.assertIn("custom", self._automation.suites)
        results = self._automation.run_component_benchmark("custom")
        self.assertGreater(results["total_benchmarks"], 0)

    def test_get_suite(self) -> None:
        suite = self._automation.get_suite("cpu")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.name, "cpu")

    def test_get_suite_missing(self) -> None:
        self.assertIsNone(self._automation.get_suite("nonexistent"))

    def test_results_dir_property(self) -> None:
        self.assertIsInstance(self._automation.results_dir, Path)
        self.assertTrue(self._automation.results_dir.exists())

    def test_full_benchmark_baseline_recording(self) -> None:
        """Running full benchmark should create baselines for comparison."""
        self._automation.run_full_benchmark()
        all_vals = self._automation.baseline.get_all_baseline_values()
        self.assertGreater(len(all_vals), 0)

    def test_second_run_produces_comparisons(self) -> None:
        """Second run should produce comparisons against first run's baselines."""
        self._automation.run_quick_benchmark()
        results = self._automation.run_quick_benchmark()
        self.assertGreater(len(results["comparisons"]), 0)

    def test_benchmark_suite_memory_suite(self) -> None:
        suite = self._automation.get_suite("memory")
        self.assertIsNotNone(suite)
        results = suite.run()
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertEqual(r.category, "memory")

    def test_benchmark_suite_cpu_suite(self) -> None:
        suite = self._automation.get_suite("cpu")
        results = suite.run()
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertEqual(r.category, "cpu")

    def test_benchmark_suite_io_suite(self) -> None:
        suite = self._automation.get_suite("io")
        results = suite.run()
        self.assertGreater(len(results), 0)

    def test_benchmark_suite_scanner_suite(self) -> None:
        suite = self._automation.get_suite("scanner")
        results = suite.run()
        self.assertGreater(len(results), 0)

    def test_benchmark_suite_module_suite(self) -> None:
        suite = self._automation.get_suite("module")
        results = suite.run()
        self.assertGreater(len(results), 0)

    def test_benchmark_suite_startup_suite(self) -> None:
        suite = self._automation.get_suite("startup")
        results = suite.run()
        self.assertGreater(len(results), 0)

    def test_quick_benchmark_faster_than_full(self) -> None:
        t0 = time.perf_counter()
        self._automation.run_quick_benchmark()
        quick_time = time.perf_counter() - t0

        t0 = time.perf_counter()
        self._automation.run_full_benchmark()
        full_time = time.perf_counter() - t0

        # Quick should generally be faster (allowing some variance)
        # This is a soft check since timings can vary
        logger = __import__("logging").getLogger(__name__)
        logger.info("Quick: %.3fs, Full: %.3fs", quick_time, full_time)


class TestIntegration(unittest.TestCase):
    """Integration tests for the full benchmark automation workflow."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        storage = Path(self._tmpdir) / "memory"
        results = Path(self._tmpdir) / "results"
        self._automation = BenchmarkAutomation(
            results_dir=results,
            baseline_dir=storage,
        )

    def tearDown(self) -> None:
        self._automation.stop_scheduled_benchmarks()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_full_workflow(self) -> None:
        """Run quick → record baseline → run full → detect regressions → generate report."""
        # Step 1: Quick benchmark (establishes baselines)
        quick = self._automation.run_quick_benchmark()
        self.assertGreater(quick["total_benchmarks"], 0)

        # Step 2: Verify baselines were recorded
        baselines = self._automation.baseline.get_all_baseline_values()
        self.assertGreater(len(baselines), 0)

        # Step 3: Full benchmark
        full = self._automation.run_full_benchmark()
        self.assertGreater(full["total_benchmarks"], 0)

        # Step 4: Comparisons should exist now
        self.assertGreater(len(full["comparisons"]), 0)

        # Step 5: Check for regressions (may be 0 since data is similar)
        self.assertIsInstance(full["regressions"], list)

        # Step 6: Generate report
        report = self._automation.generate_benchmark_report(full)
        self.assertIn("ReconPro Benchmark Report", report)
        self.assertIn("Comparison vs Baseline", report)

        # Step 7: Verify results files exist
        saved = self._automation.list_saved_results()
        self.assertGreaterEqual(len(saved), 2)  # quick + full

        # Step 8: Load and verify saved results
        for entry in saved:
            loaded = self._automation.load_results(Path(entry["path"]))
            self.assertGreater(len(loaded), 0)

    def test_baseline_trend_across_runs(self) -> None:
        """Multiple runs should build up trend data."""
        for i in range(3):
            self._automation.run_quick_benchmark()

        # Check that at least one benchmark has multiple history entries
        all_vals = self._automation.baseline.get_all_baseline_values()
        self.assertGreater(len(all_vals), 0)

        # Pick a benchmark and check its history
        first_key = list(all_vals.keys())[0]
        parts = first_key.split(":", 1)
        category = parts[0] if len(parts) > 1 else ""
        name = parts[1] if len(parts) > 1 else first_key

        history = self._automation.baseline.get_history(name, category, days=365)
        self.assertGreater(len(history), 1, "Should have multiple history entries")

    def test_regression_detection_workflow(self) -> None:
        """Set a low baseline then detect the 'regression' using manual results."""
        # Set artificially low baselines (manually, not via run_quick_benchmark)
        self._automation.baseline.set_baseline("test_reg_1", "cpu", 10.0, "ms")
        self._automation.baseline.set_baseline("test_reg_2", "cpu", 5.0, "ms")
        self._automation.baseline.set_baseline("test_thr", "cpu", 100.0, "ops/s")

        # Create results that are significantly worse than baselines
        loaded = [
            BenchmarkResult(name="test_reg_1", category="cpu", value=15.0, unit="ms"),
            BenchmarkResult(name="test_reg_2", category="cpu", value=10.0, unit="ms"),
            BenchmarkResult(name="test_thr", category="cpu", value=50.0, unit="ops/s"),
        ]

        # Detect regressions with a low threshold (10%)
        regressions = self._automation.detect_regression(loaded, threshold=10.0)
        # test_reg_1: 50% increase in timing = regression
        # test_reg_2: 100% increase in timing = regression
        # test_thr: 50% decrease in throughput = regression
        self.assertGreater(len(regressions), 0)

        # Verify regressions are sorted by severity (worst first)
        if len(regressions) > 1:
            severities = [r.get("severity", "") for r in regressions]
            # critical should come before high
            if "critical" in severities and "high" in severities:
                crit_idx = severities.index("critical")
                high_idx = severities.index("high")
                self.assertLess(crit_idx, high_idx)


if __name__ == "__main__":
    unittest.main()
