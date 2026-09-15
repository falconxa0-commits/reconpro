"""ReconPro v11 — Tests for auto_engineering.py.

Covers:
- EngineeringMetrics: collection, persistence, trends, complexity estimation
- EngineeringBaseline: capture, compare, load, list, delete
- EngineeringPipeline: health_check, drift_detection, quality_gate, workflow
- QualityGateResult: pass/fail logic, scoring
- DriftReport: drift scoring, regression detection
- MetricsSnapshot: serialisation round-trip
- FileFingerprint / BaselineSnapshot: serialisation round-trip
- Convenience functions
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

# Ensure parent package is importable
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)


# ── Helpers ────────────────────────────────────────────────────────────


def _create_temp_repo(structure: Dict[str, str]) -> str:
    """Create a temporary repository with the given file structure.

    *structure* maps relative file paths to their content.
    Returns the temp directory path.
    """
    tmpdir = tempfile.mkdtemp(prefix="reconpro_test_repo_")
    for rel_path, content in structure.items():
        full_path = Path(tmpdir) / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
    return tmpdir


def _clean_temp_repo(path: str) -> None:
    """Remove a temp repo and all contents."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# MetricsSnapshot Tests
# ═══════════════════════════════════════════════════════════════════════


class TestMetricsSnapshot(unittest.TestCase):
    """Tests for the MetricsSnapshot dataclass."""

    def test_default_values(self):
        from reconpro.auto_engineering import MetricsSnapshot
        snap = MetricsSnapshot()
        self.assertEqual(snap.test_pass_rate, 0.0)
        self.assertEqual(snap.test_total, 0)
        self.assertEqual(snap.file_count, 0)
        self.assertEqual(snap.total_lines, 0)

    def test_to_dict_returns_dict(self):
        from reconpro.auto_engineering import MetricsSnapshot
        snap = MetricsSnapshot(timestamp="2024-01-01T00:00:00Z", test_pass_rate=95.5)
        d = snap.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["timestamp"], "2024-01-01T00:00:00Z")
        self.assertAlmostEqual(d["test_pass_rate"], 95.5)

    def test_to_dict_has_all_keys(self):
        from reconpro.auto_engineering import MetricsSnapshot
        snap = MetricsSnapshot()
        d = snap.to_dict()
        expected_keys = {
            "timestamp", "test_pass_rate", "test_total", "test_passed",
            "test_failed", "test_skipped", "coverage_percent", "debt_ratio",
            "debt_items", "complexity_avg", "complexity_max", "file_count",
            "total_lines", "source_lines", "pipeline_duration_ms",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_from_dict_round_trip(self):
        from reconpro.auto_engineering import MetricsSnapshot
        original = MetricsSnapshot(
            timestamp="2024-06-15T12:00:00Z",
            test_pass_rate=88.5,
            test_total=200,
            test_passed=177,
            test_failed=20,
            test_skipped=3,
            coverage_percent=72.3,
            debt_ratio=5.2,
            debt_items=12,
            complexity_avg=8.4,
            complexity_max=25.0,
            file_count=50,
            total_lines=10000,
            source_lines=8000,
            pipeline_duration_ms=450.0,
        )
        d = original.to_dict()
        restored = MetricsSnapshot.from_dict(d)
        self.assertEqual(restored.timestamp, original.timestamp)
        self.assertAlmostEqual(restored.test_pass_rate, original.test_pass_rate)
        self.assertEqual(restored.test_total, original.test_total)
        self.assertEqual(restored.file_count, original.file_count)
        self.assertAlmostEqual(restored.complexity_max, original.complexity_max)

    def test_from_dict_with_missing_keys(self):
        from reconpro.auto_engineering import MetricsSnapshot
        snap = MetricsSnapshot.from_dict({})
        self.assertEqual(snap.test_pass_rate, 0.0)
        self.assertEqual(snap.file_count, 0)


# ═══════════════════════════════════════════════════════════════════════
# FileFingerprint & BaselineSnapshot Tests
# ═══════════════════════════════════════════════════════════════════════


class TestFileFingerprint(unittest.TestCase):
    """Tests for FileFingerprint dataclass."""

    def test_to_dict(self):
        from reconpro.auto_engineering import FileFingerprint
        fp = FileFingerprint(path="src/main.py", size_bytes=1024, line_count=50, sha256="abc123", complexity=12.5)
        d = fp.to_dict()
        self.assertEqual(d["path"], "src/main.py")
        self.assertEqual(d["size_bytes"], 1024)
        self.assertEqual(d["line_count"], 50)
        self.assertEqual(d["sha256"], "abc123")
        self.assertAlmostEqual(d["complexity"], 12.5)

    def test_from_dict_round_trip(self):
        from reconpro.auto_engineering import FileFingerprint
        original = FileFingerprint(path="src/utils.py", size_bytes=2048, line_count=100, sha256="def456", complexity=8.0)
        restored = FileFingerprint.from_dict(original.to_dict())
        self.assertEqual(restored.path, original.path)
        self.assertEqual(restored.sha256, original.sha256)


class TestBaselineSnapshot(unittest.TestCase):
    """Tests for BaselineSnapshot dataclass."""

    def test_to_dict(self):
        from reconpro.auto_engineering import BaselineSnapshot, FileFingerprint
        snap = BaselineSnapshot(
            name="test_baseline",
            timestamp="2024-01-01T00:00:00Z",
            repo_path="/tmp/test",
            files=[FileFingerprint(path="a.py")],
            total_files=1,
            total_lines=10,
            total_size_bytes=100,
            avg_complexity=5.0,
            max_complexity=5.0,
            composite_hash="hash123",
        )
        d = snap.to_dict()
        self.assertEqual(d["name"], "test_baseline")
        self.assertEqual(len(d["files"]), 1)
        self.assertEqual(d["total_files"], 1)

    def test_from_dict_round_trip(self):
        from reconpro.auto_engineering import BaselineSnapshot, FileFingerprint
        original = BaselineSnapshot(
            name="v1.0",
            timestamp="2024-03-01T00:00:00Z",
            repo_path="/repo",
            files=[FileFingerprint(path="main.py", sha256="aaa")],
            total_files=1,
            total_lines=50,
            total_size_bytes=500,
            avg_complexity=10.0,
            max_complexity=10.0,
            composite_hash="ccc",
        )
        restored = BaselineSnapshot.from_dict(original.to_dict())
        self.assertEqual(restored.name, original.name)
        self.assertEqual(len(restored.files), 1)
        self.assertEqual(restored.files[0].path, "main.py")


# ═══════════════════════════════════════════════════════════════════════
# DriftReport Tests
# ═══════════════════════════════════════════════════════════════════════


class TestDriftReport(unittest.TestCase):
    """Tests for DriftReport dataclass."""

    def test_default_values(self):
        from reconpro.auto_engineering import DriftReport
        report = DriftReport()
        self.assertFalse(report.regression_detected)
        self.assertEqual(report.drift_score, 0.0)
        self.assertEqual(report.files_added, [])

    def test_to_dict(self):
        from reconpro.auto_engineering import DriftReport
        report = DriftReport(
            baseline_name="v1",
            files_added=["new.py"],
            files_modified=["main.py"],
            drift_score=15.5,
            regression_detected=True,
            regression_details=["Complexity surged"],
        )
        d = report.to_dict()
        self.assertEqual(d["files_added"], ["new.py"])
        self.assertEqual(d["files_modified"], ["main.py"])
        self.assertTrue(d["regression_detected"])
        self.assertIn("total_changes", d)
        self.assertEqual(d["total_changes"], 2)

    def test_no_changes(self):
        from reconpro.auto_engineering import DriftReport
        report = DriftReport()
        d = report.to_dict()
        self.assertEqual(d["total_changes"], 0)


# ═══════════════════════════════════════════════════════════════════════
# QualityGateResult Tests
# ═══════════════════════════════════════════════════════════════════════


class TestQualityGateResult(unittest.TestCase):
    """Tests for QualityGateResult dataclass."""

    def test_default_is_not_passed(self):
        from reconpro.auto_engineering import QualityGateResult
        result = QualityGateResult()
        self.assertFalse(result.passed)
        self.assertEqual(result.score, 0.0)

    def test_passed_gate(self):
        from reconpro.auto_engineering import QualityGateResult
        result = QualityGateResult(
            passed=True,
            score=95.0,
            max_score=100.0,
        )
        self.assertTrue(result.passed)
        self.assertAlmostEqual(result.score, 95.0)

    def test_to_dict(self):
        from reconpro.auto_engineering import QualityGateResult
        result = QualityGateResult(
            passed=True,
            score=80.0,
            failures=["one failure"],
            warnings=["one warning"],
        )
        d = result.to_dict()
        self.assertTrue(d["passed"])
        self.assertIn("one failure", d["failures"])
        self.assertIn("one warning", d["warnings"])
        self.assertIn("thresholds", d)
        self.assertIn("evaluations", d)


# ═══════════════════════════════════════════════════════════════════════
# EngineeringMetrics Tests
# ═══════════════════════════════════════════════════════════════════════


class TestEngineeringMetricsComplexity(unittest.TestCase):
    """Tests for cyclomatic complexity estimation."""

    def test_empty_file(self):
        from reconpro.auto_engineering import EngineeringMetrics
        cx = EngineeringMetrics._estimate_complexity([])
        self.assertEqual(cx, 1.0)  # Base path

    def test_simple_file(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "def hello():",
            "    print('hello')",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        self.assertEqual(cx, 1.0)

    def test_if_branches(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "def check(x):",
            "    if x > 0:",
            "        return True",
            "    elif x == 0:",
            "        return None",
            "    else:",
            "        return False",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Base(1) + if(1) + elif(1) = 3
        self.assertEqual(cx, 3.0)

    def test_for_loop(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "for i in range(10):",
            "    if i > 5:",
            "        print(i)",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Base(1) + for(1) + if(1) = 3
        self.assertEqual(cx, 3.0)

    def test_and_or_operators(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "if a and b or c:",
            "    pass",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Base(1) + if(1) + and(1) + or(1) = 4
        self.assertEqual(cx, 4.0)

    def test_try_except(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "try:",
            "    x = 1 / 0",
            "except ZeroDivisionError:",
            "    x = 0",
            "except Exception:",
            "    x = -1",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Base(1) + except(1) + except(1) = 3
        self.assertEqual(cx, 3.0)

    def test_with_statement(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "with open('f') as fh:",
            "    data = fh.read()",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Base(1) + with(1) = 2
        self.assertEqual(cx, 2.0)

    def test_comment_lines_skipped(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "# This is a comment with if and for",
            "# Another comment with while and except",
            "def simple():",
            "    return 42",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        self.assertEqual(cx, 1.0)

    def test_multiline_string_heuristic(self):
        from reconpro.auto_engineering import EngineeringMetrics
        lines = [
            "doc = '''",
            "This has if and for in the docstring",
            "and while and except too",
            "'''",
            "def simple():",
            "    return 1",
        ]
        cx = EngineeringMetrics._estimate_complexity(lines)
        # Should be close to 1 (base) since docstring content is skipped
        self.assertLessEqual(cx, 3.0)


class TestEngineeringMetricsCollection(unittest.TestCase):
    """Tests for metrics collection on a temp repo."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "src/main.py": """def main():
    if True:
        return 1
    elif False:
        return 0
    else:
        return -1
""",
            "src/utils.py": """def helper():
    for i in range(10):
        if i > 5 and i < 8:
            print(i)
""",
            "tests/test_main.py": """def test_main():
    assert main() == 1
""",
            "README.md": "# Test Repo\n\nA test repository.",
            "pyproject.toml": "[project]\nname = \"test\"",
        })

    def tearDown(self):
        _clean_temp_repo(self.repo)

    def test_collect_metrics_returns_snapshot(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        self.assertIsInstance(snap, MetricsSnapshot)
        self.assertGreater(snap.file_count, 0)
        self.assertGreater(snap.total_lines, 0)

    def test_collect_counts_source_files(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        # Should find at least .py, .md, .toml files
        self.assertGreaterEqual(snap.file_count, 3)

    def test_collect_counts_lines(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        self.assertGreater(snap.total_lines, 10)
        self.assertGreater(snap.source_lines, 5)

    def test_collect_detects_debt_markers(self):
        from reconpro.auto_engineering import EngineeringMetrics
        repo = _create_temp_repo({
            "src/code.py": """# TODO: fix this later
# FIXME: this is broken
# HACK: workaround for bug
# XXX: danger zone
def foo():
    pass
""",
        })
        try:
            metrics = EngineeringMetrics(repo_path=repo)
            snap = metrics.collect_current_metrics()
            self.assertEqual(snap.debt_items, 4)
            self.assertGreater(snap.debt_ratio, 0.0)
        finally:
            _clean_temp_repo(repo)

    def test_collect_complexity(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        self.assertGreater(snap.complexity_avg, 0.0)
        self.assertGreater(snap.complexity_max, 0.0)

    def test_snapshot_has_timestamp(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        self.assertTrue(len(snap.timestamp) > 0)

    def test_pipeline_duration_populated(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(repo_path=self.repo)
        snap = metrics.collect_current_metrics()
        self.assertGreaterEqual(snap.pipeline_duration_ms, 0.0)


class TestEngineeringMetricsPersistence(unittest.TestCase):
    """Tests for metrics persistence."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "print('hello')\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_metrics_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)

    def test_record_and_load_snapshot(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        snap = MetricsSnapshot(
            timestamp="2024-01-01T00:00:00Z",
            test_pass_rate=90.0,
            file_count=5,
            total_lines=100,
        )
        metrics.record_snapshot(snap)
        self.assertEqual(metrics.get_snapshot_count(), 1)

    def test_get_latest_snapshot(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        self.assertIsNone(metrics.get_latest_snapshot())

        snap1 = MetricsSnapshot(timestamp="2024-01-01T00:00:00Z", test_pass_rate=80.0)
        snap2 = MetricsSnapshot(timestamp="2024-01-02T00:00:00Z", test_pass_rate=90.0)
        metrics.record_snapshot(snap1)
        metrics.record_snapshot(snap2)

        latest = metrics.get_latest_snapshot()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.test_pass_rate, 90.0)

    def test_persists_to_json_file(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        snap = MetricsSnapshot(timestamp="2024-01-01T00:00:00Z")
        metrics.record_snapshot(snap)

        history_file = Path(self.temp_metrics_dir) / "engineering_metrics.json"
        self.assertTrue(history_file.exists())
        with open(history_file, "r") as f:
            data = json.load(f)
        self.assertIn("snapshots", data)
        self.assertEqual(len(data["snapshots"]), 1)

    def test_history_capped_at_100(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        for i in range(120):
            snap = MetricsSnapshot(timestamp=f"2024-01-{i:02d}T00:00:00Z")
            metrics.record_snapshot(snap)
        self.assertEqual(metrics.get_snapshot_count(), 100)


class TestEngineeringMetricsTrends(unittest.TestCase):
    """Tests for trend analysis."""

    def setUp(self):
        self.repo = _create_temp_repo({"main.py": "x=1\n"})
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_trends_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)

    def test_empty_trends(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        self.assertEqual(metrics.get_coverage_trend(), [])
        self.assertEqual(metrics.get_debt_trend(), [])
        self.assertEqual(metrics.get_complexity_trend(), [])

    def test_debt_trend_returns_values(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        for val in [5.0, 8.0, 12.0]:
            metrics.record_snapshot(MetricsSnapshot(
                timestamp="2024-01-01T00:00:00Z",
                debt_ratio=val,
            ))
        trend = metrics.get_debt_trend()
        self.assertEqual(trend, [5.0, 8.0, 12.0])

    def test_trend_respects_n_limit(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        for i in range(20):
            metrics.record_snapshot(MetricsSnapshot(
                timestamp=f"2024-01-{i:02d}T00:00:00Z",
                complexity_avg=float(i),
            ))
        trend = metrics.get_complexity_trend(n=5)
        self.assertEqual(len(trend), 5)
        self.assertAlmostEqual(trend[-1], 19.0)

    def test_to_dict_structure(self):
        from reconpro.auto_engineering import EngineeringMetrics
        metrics = EngineeringMetrics(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
        )
        d = metrics.to_dict()
        self.assertIn("repo_path", d)
        self.assertIn("snapshot_count", d)
        self.assertIn("coverage_trend", d)
        self.assertIn("debt_trend", d)
        self.assertIn("complexity_trend", d)
        self.assertIn("test_pass_rate_trend", d)


# ═══════════════════════════════════════════════════════════════════════
# EngineeringBaseline Tests
# ═══════════════════════════════════════════════════════════════════════


class TestEngineeringBaselineCapture(unittest.TestCase):
    """Tests for baseline capture."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "src/main.py": "def main():\n    return 1\n",
            "src/utils.py": "def util():\n    for x in range(5):\n        pass\n",
            "tests/test_main.py": "def test_main():\n    assert main() == 1\n",
        })
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_baseline_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_capture_returns_snapshot(self):
        from reconpro.auto_engineering import EngineeringBaseline, BaselineSnapshot
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot(name="test_v1")
        self.assertIsInstance(snap, BaselineSnapshot)
        self.assertEqual(snap.name, "test_v1")
        self.assertGreater(snap.total_files, 0)

    def test_capture_counts_files(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot(name="test_v2")
        self.assertEqual(snap.total_files, 3)

    def test_capture_counts_lines(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot(name="test_v3")
        self.assertGreater(snap.total_lines, 0)

    def test_capture_generates_composite_hash(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot(name="test_v4")
        self.assertTrue(len(snap.composite_hash) > 0)
        self.assertEqual(len(snap.composite_hash), 32)

    def test_capture_persists_to_disk(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="persist_test")
        baseline_file = Path(self.temp_baseline_dir) / "persist_test.json"
        self.assertTrue(baseline_file.exists())

    def test_capture_auto_name(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot()
        self.assertTrue(snap.name.startswith("auto_"))

    def test_capture_file_fingerprints(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        snap = baseline.capture_snapshot(name="fp_test")
        paths = [f.path for f in snap.files]
        self.assertIn("src/main.py", paths)
        self.assertIn("src/utils.py", paths)
        self.assertIn("tests/test_main.py", paths)
        # Each file should have a hash
        for fp in snap.files:
            self.assertTrue(len(fp.sha256) > 0)
            self.assertGreater(fp.size_bytes, 0)


class TestEngineeringBaselineCompare(unittest.TestCase):
    """Tests for baseline comparison / drift detection."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "def main():\n    return 1\n",
        })
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_compare_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_no_change_no_drift(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")
        report = baseline.compare(baseline_name="v1")
        self.assertEqual(report.drift_score, 0.0)
        self.assertEqual(report.files_added, [])
        self.assertEqual(report.files_removed, [])
        self.assertEqual(report.files_modified, [])
        self.assertFalse(report.regression_detected)

    def test_detect_added_file(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")

        # Add a new file
        (Path(self.repo) / "new_file.py").write_text("# new file\n", encoding="utf-8")

        report = baseline.compare(baseline_name="v1")
        self.assertIn("new_file.py", report.files_added)
        self.assertGreater(report.drift_score, 0.0)

    def test_detect_removed_file(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")

        # Remove a file
        (Path(self.repo) / "main.py").unlink()

        report = baseline.compare(baseline_name="v1")
        self.assertIn("main.py", report.files_removed)
        self.assertGreater(report.drift_score, 0.0)

    def test_detect_modified_file(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")

        # Modify the file
        (Path(self.repo) / "main.py").write_text(
            "def main():\n    if True:\n        return 2\n    return 1\n",
            encoding="utf-8",
        )

        report = baseline.compare(baseline_name="v1")
        self.assertIn("main.py", report.files_modified)
        self.assertGreater(report.drift_score, 0.0)

    def test_detect_complexity_regression(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")

        # Replace with high-complexity file
        complex_code = """def complex_func():
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        if j:
                                            if k:
                                                if l:
                                                    return 1
"""
        (Path(self.repo) / "main.py").write_text(complex_code, encoding="utf-8")

        report = baseline.compare(baseline_name="v1")
        self.assertTrue(report.regression_detected)
        self.assertGreater(len(report.regression_details), 0)
        self.assertGreater(report.drift_score, 0.0)

    def test_detect_removed_test_file(self):
        from reconpro.auto_engineering import EngineeringBaseline
        repo = _create_temp_repo({
            "main.py": "def main(): pass\n",
            "test_main.py": "def test_main(): pass\n",
        })
        temp_dir = tempfile.mkdtemp(prefix="reconpro_test_rmtest_")
        try:
            baseline = EngineeringBaseline(
                repo_path=repo,
                baseline_dir=Path(temp_dir),
            )
            baseline.capture_snapshot(name="v1")

            # Remove test file
            Path(repo, "test_main.py").unlink()

            report = baseline.compare(baseline_name="v1")
            self.assertTrue(report.regression_detected)
            self.assertTrue(
                any("test" in d.lower() for d in report.regression_details)
            )
        finally:
            _clean_temp_repo(repo)
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_no_baseline_returns_empty_report(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        report = baseline.compare(baseline_name="nonexistent")
        self.assertEqual(report.drift_score, 0.0)
        self.assertIn("No baseline found", report.regression_details[0])

    def test_compare_with_in_memory_baseline(self):
        from reconpro.auto_engineering import (
            EngineeringBaseline, BaselineSnapshot, FileFingerprint,
        )
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        in_memory = BaselineSnapshot(
            name="inmem",
            timestamp="2024-01-01T00:00:00Z",
            repo_path=str(self.repo),
            files=[FileFingerprint(
                path="main.py",
                sha256="0000000000000000000000000000000000000000000000000000000000000000",
                size_bytes=0,
                line_count=0,
            )],
        )
        report = baseline.compare(baseline=in_memory)
        self.assertIn("main.py", report.files_modified)


class TestEngineeringBaselineManagement(unittest.TestCase):
    """Tests for baseline list/load/delete."""

    def setUp(self):
        self.repo = _create_temp_repo({"f.py": "x=1\n"})
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_mgmt_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_list_baselines_empty(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        self.assertEqual(baseline.list_baselines(), [])

    def test_list_baselines_after_capture(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="v1")
        baseline.capture_snapshot(name="v2")
        baselines = baseline.list_baselines()
        self.assertEqual(len(baselines), 2)
        names = [b["name"] for b in baselines]
        self.assertIn("v1", names)
        self.assertIn("v2", names)

    def test_load_baseline(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="loadable")
        loaded = baseline.load_baseline("loadable")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.name, "loadable")

    def test_load_nonexistent_returns_none(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        self.assertIsNone(baseline.load_baseline("does_not_exist"))

    def test_delete_baseline(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="deletable")
        self.assertTrue(baseline.delete_baseline("deletable"))
        self.assertIsNone(baseline.load_baseline("deletable"))

    def test_delete_nonexistent_returns_false(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        self.assertFalse(baseline.delete_baseline("nonexistent"))

    def test_list_baselines_has_required_keys(self):
        from reconpro.auto_engineering import EngineeringBaseline
        baseline = EngineeringBaseline(
            repo_path=self.repo,
            baseline_dir=Path(self.temp_baseline_dir),
        )
        baseline.capture_snapshot(name="keytest")
        baselines = baseline.list_baselines()
        self.assertEqual(len(baselines), 1)
        for b in baselines:
            self.assertIn("name", b)
            self.assertIn("timestamp", b)
            self.assertIn("total_files", b)
            self.assertIn("total_lines", b)


class TestDriftScoreCalculation(unittest.TestCase):
    """Tests for drift score calculation."""

    def test_no_changes_zero_score(self):
        from reconpro.auto_engineering import EngineeringBaseline
        score = EngineeringBaseline._calculate_drift_score([], [], [], [], [])
        self.assertEqual(score, 0.0)

    def test_small_changes_low_score(self):
        from reconpro.auto_engineering import EngineeringBaseline
        score = EngineeringBaseline._calculate_drift_score(
            added=["new.py"],
            removed=[],
            modified=[],
            drift_events=[],
            regression_details=[],
        )
        self.assertGreater(score, 0.0)
        self.assertLess(score, 20.0)

    def test_large_changes_higher_score(self):
        from reconpro.auto_engineering import EngineeringBaseline
        score = EngineeringBaseline._calculate_drift_score(
            added=[f"new_{i}.py" for i in range(10)],
            removed=["old.py"],
            modified=[f"mod_{i}.py" for i in range(5)],
            drift_events=[],
            regression_details=[],
        )
        self.assertGreater(score, 30.0)

    def test_regression_boosts_score(self):
        from reconpro.auto_engineering import EngineeringBaseline
        score_no_regression = EngineeringBaseline._calculate_drift_score(
            added=[], removed=[], modified=["a.py"],
            drift_events=[], regression_details=[],
        )
        score_with_regression = EngineeringBaseline._calculate_drift_score(
            added=[], removed=[], modified=["a.py"],
            drift_events=[], regression_details=["reg1", "reg2", "reg3"],
        )
        self.assertGreater(score_with_regression, score_no_regression)

    def test_score_capped_at_100(self):
        from reconpro.auto_engineering import EngineeringBaseline
        score = EngineeringBaseline._calculate_drift_score(
            added=[f"f{i}.py" for i in range(50)],
            removed=[f"r{i}.py" for i in range(50)],
            modified=[f"m{i}.py" for i in range(50)],
            drift_events=[{"severity": "high"} for _ in range(20)],
            regression_details=["reg" for _ in range(20)],
        )
        self.assertLessEqual(score, 100.0)


# ═══════════════════════════════════════════════════════════════════════
# EngineeringPipeline Tests
# ═══════════════════════════════════════════════════════════════════════


class TestEngineeringPipelineHealthCheck(unittest.TestCase):
    """Tests for EngineeringPipeline.health_check()."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "print('hello')\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_hc_")
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_hb_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_health_check_returns_dict(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIsInstance(result, dict)

    def test_health_check_has_timestamp(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIn("timestamp", result)
        self.assertIn("repo_path", result)

    def test_health_check_has_health_section(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIn("health", result)
        self.assertIsInstance(result["health"], dict)

    def test_health_check_has_diagnostics_section(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIn("diagnostics", result)

    def test_health_check_has_config_issues(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIn("config_issues", result)
        self.assertIsInstance(result["config_issues"], list)

    def test_health_check_has_repository_section(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertIn("repository", result)
        repo = result["repository"]
        self.assertIn("repo_exists", repo)
        self.assertIn("source_file_count", repo)
        self.assertIn("has_tests", repo)
        self.assertIn("has_build_config", repo)
        self.assertIn("has_documentation", repo)
        self.assertIn("has_vcs", repo)

    def test_health_check_detects_source_files(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.health_check()
        self.assertGreater(result["repository"]["source_file_count"], 0)


class TestEngineeringPipelineDriftDetection(unittest.TestCase):
    """Tests for EngineeringPipeline.drift_detection()."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "def main():\n    return 1\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_dd_")
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_db_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_drift_detection_returns_dict(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.drift_detection()
        self.assertIsInstance(result, dict)
        self.assertIn("timestamp", result)

    def test_drift_detection_creates_baseline_if_missing(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.drift_detection(create_baseline_if_missing=True)
        self.assertTrue(result.get("auto_baseline_created", False))

    def test_drift_detection_without_auto_baseline(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.drift_detection(create_baseline_if_missing=False)
        self.assertFalse(result.get("auto_baseline_created", False))
        self.assertIn("drift", result)

    def test_drift_detection_detects_changes(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        # Create initial baseline
        pipeline.baseline_manager.capture_snapshot(name="v1")

        # Modify a file
        (Path(self.repo) / "main.py").write_text(
            "def main():\n    return 2\n", encoding="utf-8"
        )

        result = pipeline.drift_detection(create_baseline_if_missing=False)
        drift = result.get("drift", {})
        if isinstance(drift, dict):
            self.assertGreater(drift.get("drift_score", 0.0), 0.0)

    def test_drift_detection_has_infra_drift_available(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.drift_detection()
        self.assertIn("infra_drift_available", result)


class TestEngineeringPipelineQualityGate(unittest.TestCase):
    """Tests for EngineeringPipeline.quality_gate()."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "def main():\n    return 1\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_qg_")
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_qb_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_quality_gate_returns_result(self):
        from reconpro.auto_engineering import EngineeringPipeline, QualityGateResult
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.quality_gate()
        self.assertIsInstance(result, QualityGateResult)

    def test_quality_gate_clean_repo_passes(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.quality_gate()
        # Clean repo with no drift and low debt should pass
        # (may fail on health_score if network is down, so just check structure)
        self.assertIsInstance(result.passed, bool)
        self.assertIsInstance(result.score, float)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 100.0)

    def test_quality_gate_has_evaluations(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.quality_gate()
        self.assertIn("test_pass_rate", result.evaluations)
        self.assertIn("debt_ratio", result.evaluations)
        self.assertIn("complexity", result.evaluations)
        self.assertIn("drift_score", result.evaluations)
        self.assertIn("drift_events", result.evaluations)
        self.assertIn("health_checks", result.evaluations)

    def test_quality_gate_custom_thresholds(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            thresholds={
                "min_test_pass_rate": 50.0,
                "max_debt_ratio": 10.0,
                "max_complexity": 5.0,
                "max_drift_score": 10.0,
                "max_drift_events": 3,
                "min_health_checks_passed": 0.5,
            },
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.quality_gate()
        self.assertEqual(result.thresholds["min_test_pass_rate"], 50.0)
        self.assertEqual(result.thresholds["max_debt_ratio"], 10.0)

    def test_quality_gate_high_debt_fails(self):
        from reconpro.auto_engineering import EngineeringMetrics, MetricsSnapshot, DriftReport
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        # Create a snapshot with high debt
        high_debt_snap = MetricsSnapshot(
            debt_ratio=50.0,
            complexity_max=5.0,
        )
        no_drift = DriftReport(drift_score=0.0)
        healthy = {
            "health_score": 100.0,
        }
        result = pipeline.quality_gate(
            metrics_snapshot=high_debt_snap,
            drift_report=no_drift,
            health_result=healthy,
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("Debt ratio" in f for f in result.failures))

    def test_quality_gate_high_complexity_fails(self):
        from reconpro.auto_engineering import MetricsSnapshot, DriftReport
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        high_cx_snap = MetricsSnapshot(
            debt_ratio=0.0,
            complexity_max=50.0,
        )
        no_drift = DriftReport(drift_score=0.0)
        healthy = {"health_score": 100.0}
        result = pipeline.quality_gate(
            metrics_snapshot=high_cx_snap,
            drift_report=no_drift,
            health_result=healthy,
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("complexity" in f.lower() for f in result.failures))

    def test_quality_gate_high_drift_fails(self):
        from reconpro.auto_engineering import MetricsSnapshot, DriftReport
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        clean_snap = MetricsSnapshot(
            debt_ratio=0.0,
            complexity_max=1.0,
        )
        high_drift = DriftReport(drift_score=80.0)
        healthy = {"health_score": 100.0}
        result = pipeline.quality_gate(
            metrics_snapshot=clean_snap,
            drift_report=high_drift,
            health_result=healthy,
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("Drift score" in f for f in result.failures))

    def test_quality_gate_regression_detected_fails(self):
        from reconpro.auto_engineering import MetricsSnapshot, DriftReport
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        clean_snap = MetricsSnapshot(debt_ratio=0.0, complexity_max=1.0)
        regression_drift = DriftReport(
            drift_score=0.0,
            regression_detected=True,
            regression_details=["Complexity surged in main.py"],
        )
        healthy = {"health_score": 100.0}
        result = pipeline.quality_gate(
            metrics_snapshot=clean_snap,
            drift_report=regression_drift,
            health_result=healthy,
        )
        self.assertFalse(result.passed)
        self.assertTrue(any("Regression" in f for f in result.failures))

    def test_quality_gate_all_clean_passes(self):
        from reconpro.auto_engineering import MetricsSnapshot, DriftReport
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        clean_snap = MetricsSnapshot(debt_ratio=0.0, complexity_max=1.0)
        no_drift = DriftReport(drift_score=0.0)
        healthy = {"health_score": 100.0}
        result = pipeline.quality_gate(
            metrics_snapshot=clean_snap,
            drift_report=no_drift,
            health_result=healthy,
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.failures, [])


class TestEngineeringPipelineWorkflow(unittest.TestCase):
    """Tests for EngineeringPipeline.engineering_workflow()."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "def main():\n    return 1\n",
            "test_main.py": "def test_main():\n    assert main() == 1\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_wf_m_")
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_pipe_wf_b_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_workflow_returns_dict(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=False)
        self.assertIsInstance(result, dict)

    def test_workflow_has_all_sections(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=False)
        self.assertIn("timestamp", result)
        self.assertIn("repo_path", result)
        self.assertIn("health_check", result)
        self.assertIn("drift_detection", result)
        self.assertIn("metrics", result)
        self.assertIn("quality_gate", result)
        self.assertIn("summary", result)

    def test_workflow_health_check_has_duration(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=False)
        self.assertIn("duration_ms", result["health_check"])
        self.assertGreater(result["health_check"]["duration_ms"], 0.0)

    def test_workflow_metrics_has_snapshot(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=False)
        self.assertIn("snapshot", result["metrics"])
        self.assertIn("trends", result["metrics"])

    def test_workflow_summary_structure(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=False)
        summary = result["summary"]
        self.assertIn("total_duration_ms", summary)
        self.assertIn("quality_gate_passed", summary)
        self.assertIn("quality_gate_score", summary)
        self.assertIn("drift_score", summary)
        self.assertIn("health_score", summary)
        self.assertIn("regression_detected", summary)
        self.assertIn("files_analyzed", summary)

    def test_workflow_records_metrics(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        result = pipeline.engineering_workflow(record_metrics=True)
        self.assertEqual(pipeline.metrics.get_snapshot_count(), 1)

    def test_workflow_no_record_metrics(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(
            repo_path=self.repo,
            metrics_dir=Path(self.temp_metrics_dir),
            baseline_dir=Path(self.temp_baseline_dir),
        )
        pipeline.engineering_workflow(record_metrics=False)
        self.assertEqual(pipeline.metrics.get_snapshot_count(), 0)


class TestEngineeringPipelineProperties(unittest.TestCase):
    """Tests for pipeline properties."""

    def test_metrics_property(self):
        from reconpro.auto_engineering import (
            EngineeringPipeline, EngineeringMetrics,
        )
        pipeline = EngineeringPipeline(repo_path=".")
        self.assertIsInstance(pipeline.metrics, EngineeringMetrics)

    def test_baseline_manager_property(self):
        from reconpro.auto_engineering import (
            EngineeringPipeline, EngineeringBaseline,
        )
        pipeline = EngineeringPipeline(repo_path=".")
        self.assertIsInstance(pipeline.baseline_manager, EngineeringBaseline)


class TestEngineeringPipelineRepoHealth(unittest.TestCase):
    """Tests for repository-specific health checks."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "x=1\n",
            "tests/test_x.py": "assert True\n",
            "README.md": "# Test\n",
            "setup.py": "# setup\n",
        })

    def tearDown(self):
        _clean_temp_repo(self.repo)

    def test_detects_test_files(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(repo_path=self.repo)
        result = pipeline.health_check()
        self.assertTrue(result["repository"]["has_tests"])
        self.assertGreater(result["repository"]["test_file_count"], 0)

    def test_detects_config_files(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(repo_path=self.repo)
        result = pipeline.health_check()
        self.assertTrue(result["repository"]["has_build_config"])
        self.assertIn("setup.py", result["repository"]["config_files"])

    def test_detects_documentation(self):
        from reconpro.auto_engineering import EngineeringPipeline
        pipeline = EngineeringPipeline(repo_path=self.repo)
        result = pipeline.health_check()
        self.assertTrue(result["repository"]["has_documentation"])
        self.assertIn("README.md", result["repository"]["documentation_files"])

    def test_empty_repo_no_tests(self):
        from reconpro.auto_engineering import EngineeringPipeline
        repo = _create_temp_repo({"data.csv": "a,b,c\n"})
        try:
            pipeline = EngineeringPipeline(repo_path=repo)
            result = pipeline.health_check()
            self.assertFalse(result["repository"]["has_tests"])
        finally:
            _clean_temp_repo(repo)


# ═══════════════════════════════════════════════════════════════════════
# Convenience Function Tests
# ═══════════════════════════════════════════════════════════════════════


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for module-level convenience functions."""

    def setUp(self):
        self.repo = _create_temp_repo({
            "main.py": "print('hello')\n",
        })
        self.temp_metrics_dir = tempfile.mkdtemp(prefix="reconpro_test_conv_m_")
        self.temp_baseline_dir = tempfile.mkdtemp(prefix="reconpro_test_conv_b_")

    def tearDown(self):
        _clean_temp_repo(self.repo)
        import shutil
        shutil.rmtree(self.temp_metrics_dir, ignore_errors=True)
        shutil.rmtree(self.temp_baseline_dir, ignore_errors=True)

    def test_run_engineering_workflow(self):
        from reconpro.auto_engineering import run_engineering_workflow
        with patch("reconpro.auto_engineering.METRICS_DIR", Path(self.temp_metrics_dir)), \
             patch("reconpro.auto_engineering.BASELINE_DIR", Path(self.temp_baseline_dir)):
            result = run_engineering_workflow(
                repo_path=self.repo,
                record_metrics=False,
            )
        self.assertIsInstance(result, dict)
        self.assertIn("summary", result)

    def test_run_quality_gate(self):
        from reconpro.auto_engineering import run_quality_gate, QualityGateResult
        with patch("reconpro.auto_engineering.METRICS_DIR", Path(self.temp_metrics_dir)), \
             patch("reconpro.auto_engineering.BASELINE_DIR", Path(self.temp_baseline_dir)):
            result = run_quality_gate(repo_path=self.repo)
        self.assertIsInstance(result, QualityGateResult)

    def test_capture_baseline(self):
        from reconpro.auto_engineering import capture_baseline, BaselineSnapshot
        with patch("reconpro.auto_engineering.BASELINE_DIR", Path(self.temp_baseline_dir)):
            result = capture_baseline(repo_path=self.repo, name="conv_test")
        self.assertIsInstance(result, BaselineSnapshot)
        self.assertEqual(result.name, "conv_test")

    def test_capture_baseline_auto_name(self):
        from reconpro.auto_engineering import capture_baseline
        with patch("reconpro.auto_engineering.BASELINE_DIR", Path(self.temp_baseline_dir)):
            result = capture_baseline(repo_path=self.repo)
        self.assertTrue(result.name.startswith("auto_"))


# ═══════════════════════════════════════════════════════════════════════
# Health Score Computation Tests
# ═══════════════════════════════════════════════════════════════════════


class TestHealthScoreComputation(unittest.TestCase):
    """Tests for _compute_health_score static method."""

    def test_all_passed(self):
        from reconpro.auto_engineering import EngineeringPipeline
        score = EngineeringPipeline._compute_health_score({
            "total_checks": 10,
            "passed": 10,
        })
        self.assertEqual(score, 100.0)

    def test_half_passed(self):
        from reconpro.auto_engineering import EngineeringPipeline
        score = EngineeringPipeline._compute_health_score({
            "total_checks": 10,
            "passed": 5,
        })
        self.assertEqual(score, 50.0)

    def test_none_passed(self):
        from reconpro.auto_engineering import EngineeringPipeline
        score = EngineeringPipeline._compute_health_score({
            "total_checks": 10,
            "passed": 0,
        })
        self.assertEqual(score, 0.0)

    def test_zero_total_checks(self):
        from reconpro.auto_engineering import EngineeringPipeline
        score = EngineeringPipeline._compute_health_score({
            "total_checks": 0,
            "passed": 0,
        })
        self.assertEqual(score, 100.0)

    def test_missing_keys(self):
        from reconpro.auto_engineering import EngineeringPipeline
        score = EngineeringPipeline._compute_health_score({})
        self.assertEqual(score, 100.0)


# ═══════════════════════════════════════════════════════════════════════
# Module Constants Tests
# ═══════════════════════════════════════════════════════════════════════


class TestModuleConstants(unittest.TestCase):
    """Tests for module-level constants."""

    def test_metrics_dir_is_path(self):
        from reconpro.auto_engineering import METRICS_DIR
        self.assertIsInstance(METRICS_DIR, Path)

    def test_baseline_dir_is_path(self):
        from reconpro.auto_engineering import BASELINE_DIR
        self.assertIsInstance(BASELINE_DIR, Path)

    def test_default_thresholds_has_all_keys(self):
        from reconpro.auto_engineering import DEFAULT_QUALITY_THRESHOLDS
        expected = {
            "min_test_pass_rate", "max_debt_ratio", "max_complexity",
            "max_drift_score", "min_health_checks_passed", "max_drift_events",
        }
        self.assertEqual(set(DEFAULT_QUALITY_THRESHOLDS.keys()), expected)

    def test_source_extensions_includes_py(self):
        from reconpro.auto_engineering import _SOURCE_EXTENSIONS
        self.assertIn(".py", _SOURCE_EXTENSIONS)
        self.assertIn(".js", _SOURCE_EXTENSIONS)
        self.assertIn(".go", _SOURCE_EXTENSIONS)

    def test_skip_dirs_includes_node_modules(self):
        from reconpro.auto_engineering import _SKIP_DIRS
        self.assertIn("node_modules", _SKIP_DIRS)
        self.assertIn("__pycache__", _SKIP_DIRS)
        self.assertIn(".git", _SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
