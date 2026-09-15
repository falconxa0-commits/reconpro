"""Tests for reconpro.engineering_workflow — ContinuousEngineeringOrchestrator.

Verifies that the orchestrator calls each subsystem in the correct order,
handles failures gracefully, and produces correct EngineeringCycleResult data.
Uses mocks for all subsystems since they need actual repository state.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import TestCase
from unittest.mock import MagicMock, patch, PropertyMock

# Ensure reconpro package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from reconpro.engineering_workflow import (
    EngineeringCycleResult,
    EngineeringStage,
    ContinuousEngineeringOrchestrator,
    StageResult,
    _FULL_CYCLE_STAGES,
    _VALIDATION_ONLY_STAGES,
    _ENGINEERING_ONLY_STAGES,
)


# ═══════════════════════════════════════════════════════════════════════
#  Test EngineeringStage enum
# ═══════════════════════════════════════════════════════════════════════


class TestEngineeringStage(TestCase):
    """Tests for EngineeringStage enum values and ordering."""

    def test_all_stages_exist(self) -> None:
        """Every expected stage is in the enum."""
        expected = {
            "DIGITAL_TWIN_STATE",
            "DIGITAL_TWIN_ANOMALY",
            "REPOSITORY_MEMORY_RECALL",
            "AUTO_VALIDATION",
            "HEALTH_CHECK",
            "DRIFT_DETECTION",
            "BENCHMARK",
            "REGRESSION_INTELLIGENCE",
            "LEARNING",
            "RECOMMENDATIONS",
            "AUTO_FIX",
            "QUALITY_GATE",
            "QUALITY_INTELLIGENCE",
            "REPORTING",
            "REPOSITORY_MEMORY_PERSIST",
        }
        actual = {s.name for s in EngineeringStage}
        self.assertEqual(expected, actual)

    def test_full_cycle_order(self) -> None:
        """Full cycle has 15 stages in the correct order (a through n)."""
        self.assertEqual(len(_FULL_CYCLE_STAGES), 15)
        # First two should be digital twin stages
        self.assertEqual(_FULL_CYCLE_STAGES[0], EngineeringStage.DIGITAL_TWIN_STATE)
        self.assertEqual(_FULL_CYCLE_STAGES[1], EngineeringStage.DIGITAL_TWIN_ANOMALY)
        # Last should be persist
        self.assertEqual(_FULL_CYCLE_STAGES[-1], EngineeringStage.REPOSITORY_MEMORY_PERSIST)

    def test_validation_only_stages(self) -> None:
        """Validation-only mode has 3 stages: a, c, k."""
        self.assertEqual(len(_VALIDATION_ONLY_STAGES), 3)
        self.assertIn(EngineeringStage.DIGITAL_TWIN_STATE, _VALIDATION_ONLY_STAGES)
        self.assertIn(EngineeringStage.AUTO_VALIDATION, _VALIDATION_ONLY_STAGES)
        self.assertIn(EngineeringStage.QUALITY_GATE, _VALIDATION_ONLY_STAGES)

    def test_engineering_only_stages(self) -> None:
        """Engineering-only mode has 7 stages: d through j."""
        self.assertEqual(len(_ENGINEERING_ONLY_STAGES), 7)
        self.assertEqual(_ENGINEERING_ONLY_STAGES[0], EngineeringStage.HEALTH_CHECK)
        self.assertEqual(_ENGINEERING_ONLY_STAGES[-1], EngineeringStage.AUTO_FIX)


# ═══════════════════════════════════════════════════════════════════════
#  Test StageResult dataclass
# ═══════════════════════════════════════════════════════════════════════


class TestStageResult(TestCase):
    """Tests for StageResult serialization."""

    def test_default_values(self) -> None:
        sr = StageResult(stage=EngineeringStage.HEALTH_CHECK)
        self.assertEqual(sr.stage, EngineeringStage.HEALTH_CHECK)
        self.assertEqual(sr.status, "pass")
        self.assertEqual(sr.duration_s, 0.0)
        self.assertEqual(sr.data, {})
        self.assertEqual(sr.error, "")

    def test_to_dict_roundtrip_keys(self) -> None:
        sr = StageResult(
            stage=EngineeringStage.BENCHMARK,
            status="warn",
            duration_s=1.5,
            data={"foo": "bar"},
            error="test error",
        )
        d = sr.to_dict()
        self.assertEqual(d["stage"], "benchmark")
        self.assertEqual(d["status"], "warn")
        self.assertEqual(d["duration_s"], 1.5)
        self.assertEqual(d["data"], {"foo": "bar"})
        self.assertEqual(d["error"], "test error")


# ═══════════════════════════════════════════════════════════════════════
#  Test EngineeringCycleResult
# ═══════════════════════════════════════════════════════════════════════


class TestEngineeringCycleResult(TestCase):
    """Tests for EngineeringCycleResult serialization and persistence."""

    def test_to_dict_keys(self) -> None:
        result = EngineeringCycleResult(
            cycle_id="test123",
            repository_path="/tmp/repo",
            mode="full",
            overall_status="warn",
            started_at="2025-01-01T00:00:00Z",
            finished_at="2025-01-01T00:01:00Z",
            total_duration_s=60.0,
            stages=[
                StageResult(stage=EngineeringStage.HEALTH_CHECK, status="pass"),
                StageResult(stage=EngineeringStage.AUTO_VALIDATION, status="warn"),
            ],
            metrics={"total_stages": 2, "passed": 1, "failed": 0, "warned": 1, "skipped": 0},
            recommendations_count=3,
            fix_proposals_count=1,
            anomaly_count=0,
            regression_count=2,
        )
        d = result.to_dict()
        self.assertEqual(d["cycle_id"], "test123")
        self.assertEqual(d["mode"], "full")
        self.assertEqual(d["overall_status"], "warn")
        self.assertEqual(len(d["stages"]), 2)
        self.assertEqual(d["recommendations_count"], 3)

    def test_save_and_load(self) -> None:
        """Cycle results can be saved as JSON and loaded back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            save_dir = Path(tmpdir)
            result = EngineeringCycleResult(
                cycle_id="save_load_test",
                repository_path="/tmp/repo",
                mode="full",
                overall_status="pass",
                stages=[
                    StageResult(
                        stage=EngineeringStage.HEALTH_CHECK,
                        status="pass",
                        data={"checks": 5},
                    ),
                ],
                metrics={"total_stages": 1, "passed": 1, "failed": 0, "warned": 0, "skipped": 0},
            )
            result.started_at = "2025-01-01T00:00:00+00:00"
            result.finished_at = "2025-01-01T00:00:10+00:00"
            result.total_duration_s = 10.0

            filepath = result.save(directory=save_dir)
            self.assertTrue(filepath.exists())

            # Verify JSON is valid
            with open(filepath) as f:
                data = json.load(f)
            self.assertEqual(data["cycle_id"], "save_load_test")
            self.assertEqual(len(data["stages"]), 1)

    def test_load_latest(self) -> None:
        """load_latest returns the most recent cycle result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            save_dir = Path(tmpdir)

            # Create an older result
            r1 = EngineeringCycleResult(cycle_id="old", mode="full")
            r1.started_at = "2025-01-01T00:00:00+00:00"
            r1.finished_at = "2025-01-01T00:00:05+00:00"
            r1.total_duration_s = 5.0
            r1.stages = [StageResult(stage=EngineeringStage.HEALTH_CHECK)]
            r1.metrics = {"total_stages": 1, "passed": 1, "failed": 0, "warned": 0, "skipped": 0}
            r1.save(directory=save_dir)
            time.sleep(0.05)  # Ensure distinct filename timestamps

            # Create a newer result
            r2 = EngineeringCycleResult(cycle_id="new", mode="full")
            r2.started_at = "2025-01-02T00:00:00+00:00"
            r2.finished_at = "2025-01-02T00:00:10+00:00"
            r2.total_duration_s = 10.0
            r2.stages = [
                StageResult(stage=EngineeringStage.HEALTH_CHECK),
                StageResult(stage=EngineeringStage.AUTO_VALIDATION),
            ]
            r2.metrics = {"total_stages": 2, "passed": 2, "failed": 0, "warned": 0, "skipped": 0}
            r2.save(directory=save_dir)

            loaded = EngineeringCycleResult.load_latest(directory=save_dir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.cycle_id, "new")
            self.assertEqual(len(loaded.stages), 2)

    def test_load_latest_empty(self) -> None:
        """load_latest returns None when no files exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            loaded = EngineeringCycleResult.load_latest(directory=Path(tmpdir))
            self.assertIsNone(loaded)


# ═══════════════════════════════════════════════════════════════════════
#  Test ContinuousEngineeringOrchestrator — full cycle with mocks
# ═══════════════════════════════════════════════════════════════════════


def _make_mock_system_model() -> MagicMock:
    """Create a mock SystemModel with overall_status."""
    model = MagicMock()
    model.overall_status.return_value = "healthy"
    model.version = "11.1.0"
    model.captured_at = "2025-01-01T00:00:00+00:00"
    return model


def _make_mock_stage_result() -> MagicMock:
    """Create a mock ValidationStageResult / ValidationReport."""
    r = MagicMock()
    r.to_dict.return_value = {
        "total_findings": 0,
        "stages_passed": 7,
        "stages_total": 7,
    }
    r.summary.return_value = "All stages passed"
    return r


def _make_mock_recommendation() -> MagicMock:
    """Create a mock Recommendation."""
    r = MagicMock()
    r.id = "rec-001"
    r.title = "Test recommendation"
    r.severity = "low"
    r.category = "code_quality"
    return r


def _make_mock_fix_proposal() -> MagicMock:
    """Create a mock FixProposal."""
    p = MagicMock()
    p.id = "fix-001"
    p.title = "Test fix"
    p.severity = "medium"
    p.confidence = 0.8
    p.status = "proposed"
    return p


def _make_mock_regression_record() -> MagicMock:
    """Create a mock RegressionRecord."""
    r = MagicMock()
    r.id = "reg-001"
    r.regression_type = MagicMock()
    r.regression_type.value = "performance"
    r.severity = MagicMock()
    r.severity.value = "medium"
    r.description = "Scan latency increased 25%"
    return r


class TestOrchestratorFullCycle(TestCase):
    """Test the full engineering cycle with mocked subsystems."""

    def _make_orchestrator(self) -> ContinuousEngineeringOrchestrator:
        """Create an orchestrator with all subsystems pre-mocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = ContinuousEngineeringOrchestrator(repository_path=tmpdir)

        # Pre-populate lazy-loaded subsystems with mocks
        # 1. EngineeringPipeline
        orch._engineering_pipeline = MagicMock()
        orch._engineering_pipeline.health_check.return_value = {
            "status": "healthy",
            "checks_run": 10,
            "checks_passed": 10,
        }
        orch._engineering_pipeline.drift_detection.return_value = {
            "drift_score": 5.0,
            "drift_events": [],
        }
        mock_qg = MagicMock()
        mock_qg.to_dict.return_value = {
            "passed": True,
            "thresholds_checked": 6,
            "thresholds_passed": 6,
        }
        orch._engineering_pipeline.quality_gate.return_value = mock_qg

        # 2. RepositoryMemory
        orch._repository_memory = MagicMock()
        orch._repository_memory.search.return_value = []

        # 3. DigitalTwin
        orch._digital_twin = MagicMock()
        orch._digital_twin.capture_state.return_value = _make_mock_system_model()
        orch._digital_twin.detect_anomaly.return_value = {
            "anomalies": [],
            "anomaly_count": 0,
        }

        # 4. RepositoryLearner
        orch._repository_learner = MagicMock()
        orch._repository_learner.learn_from_scan.return_value = 0
        orch._repository_learner.learn_from_test.return_value = 0

        # 5. EngineeringRecommender
        orch._engineering_recommender = MagicMock()
        orch._engineering_recommender.recommend_from_diagnostics.return_value = []
        orch._engineering_recommender.recommend_from_drift.return_value = []
        orch._engineering_recommender.recommend_from_test_results.return_value = []
        orch._engineering_recommender.recommend_from_performance.return_value = []
        orch._engineering_recommender.recommend_from_security.return_value = []

        # 6. RegressionIntelligence
        orch._regression_intelligence = MagicMock()
        orch._regression_intelligence.detect_regression.return_value = []
        orch._regression_intelligence.generate_regression_report.return_value = "No regressions detected."

        # 7. ValidationPipeline
        orch._validation_pipeline = MagicMock()
        orch._validation_pipeline.validate_full.return_value = _make_mock_stage_result()

        # 8. BenchmarkAutomation
        orch._benchmark_automation = MagicMock()
        orch._benchmark_automation.run_quick_benchmark.return_value = {
            "total_benchmarks": 5,
            "regressions_detected": 0,
        }

        # 9. AutoFixEngine
        orch._auto_fix_engine = MagicMock()
        orch._auto_fix_engine.propose_fixes.return_value = []

        return orch

    def test_full_cycle_all_stages_pass(self) -> None:
        """Full cycle runs all 15 stages and they all pass."""
        orch = self._make_orchestrator()
        result = orch.run_full_cycle()

        self.assertEqual(len(result.stages), 15)
        self.assertEqual(result.mode, "full")
        self.assertEqual(result.overall_status, "pass")
        self.assertTrue(result.cycle_id)
        self.assertTrue(result.started_at)
        self.assertTrue(result.finished_at)
        self.assertGreater(result.total_duration_s, 0)

        # Verify stage order
        stage_names = [s.stage for s in result.stages]
        for i, expected in enumerate(_FULL_CYCLE_STAGES):
            self.assertEqual(stage_names[i], expected, f"Stage {i} mismatch")

        # All stages should pass
        for sr in result.stages:
            self.assertEqual(sr.status, "pass", f"Stage {sr.stage.value} failed: {sr.error}")

        # Subsystem calls verification
        orch._digital_twin.capture_state.assert_called_once()
        orch._digital_twin.detect_anomaly.assert_called_once()
        orch._repository_memory.search.assert_called()
        orch._validation_pipeline.validate_full.assert_called_once()
        orch._engineering_pipeline.health_check.assert_called_once()
        orch._engineering_pipeline.drift_detection.assert_called_once()
        orch._benchmark_automation.run_quick_benchmark.assert_called_once()
        orch._regression_intelligence.detect_regression.assert_called_once()
        orch._regression_intelligence.generate_regression_report.assert_called_once()
        orch._auto_fix_engine.propose_fixes.assert_called_once()
        orch._engineering_pipeline.quality_gate.assert_called_once()

        # Repository memory persist
        orch._repository_memory.remember.assert_called()

    def test_full_cycle_correct_call_order(self) -> None:
        """Stages execute in the correct order: a → b → c → ... → m."""
        orch = self._make_orchestrator()
        result = orch.run_full_cycle()

        stage_order = [s.stage for s in result.stages]
        expected_order = [s.value for s in _FULL_CYCLE_STAGES]
        actual_order = [s.value for s in stage_order]
        self.assertEqual(actual_order, expected_order)

    def test_full_cycle_aggregate_counts(self) -> None:
        """Aggregate counts (recommendations, fixes, anomalies) are populated."""
        orch = self._make_orchestrator()

        # Set up subsystems to return data that populates counts
        orch._digital_twin.detect_anomaly.return_value = {
            "anomalies": ["anomaly1", "anomaly2"],
            "anomaly_count": 2,
        }
        orch._regression_intelligence.detect_regression.return_value = [
            _make_mock_regression_record(),
        ]
        orch._engineering_recommender.recommend_from_diagnostics.return_value = [
            _make_mock_recommendation(),
            _make_mock_recommendation(),
        ]
        orch._engineering_recommender.recommend_from_drift.return_value = [
            _make_mock_recommendation(),
        ]
        orch._auto_fix_engine.propose_fixes.return_value = [
            _make_mock_fix_proposal(),
        ]

        result = orch.run_full_cycle()

        self.assertEqual(result.anomaly_count, 2)
        self.assertEqual(result.regression_count, 1)
        self.assertEqual(result.recommendations_count, 3)  # 2 + 1
        self.assertEqual(result.fix_proposals_count, 1)

    def test_full_cycle_graceful_degradation(self) -> None:
        """One stage failure does NOT stop the pipeline."""
        orch = self._make_orchestrator()
        # Make drift detection raise an error
        orch._engineering_pipeline.drift_detection.side_effect = RuntimeError("Drift engine error")

        result = orch.run_full_cycle()

        self.assertEqual(len(result.stages), 15)
        # Overall status should be 'fail' because one stage failed
        self.assertEqual(result.overall_status, "fail")

        # Find the failed stage(s) — at least drift_detection must have failed
        failed_stages = [s for s in result.stages if s.status == "fail"]
        self.assertTrue(len(failed_stages) >= 1)
        drift_failures = [s for s in failed_stages if s.stage == EngineeringStage.DRIFT_DETECTION]
        self.assertEqual(len(drift_failures), 1)
        self.assertIn("Drift engine error", drift_failures[0].error)

        # Other stages should still pass
        passing_stages = [s for s in result.stages if s.status == "pass"]
        self.assertGreaterEqual(len(passing_stages), 13)

    def test_full_cycle_multiple_failures(self) -> None:
        """Multiple stage failures are all captured."""
        orch = self._make_orchestrator()
        orch._engineering_pipeline.health_check.side_effect = Exception("Health check boom")
        orch._benchmark_automation.run_quick_benchmark.side_effect = Exception("Benchmark crash")

        result = orch.run_full_cycle()

        failed_stages = [s for s in result.stages if s.status == "fail"]
        self.assertEqual(len(failed_stages), 2)
        self.assertEqual(result.overall_status, "fail")

    def test_full_cycle_warning_status(self) -> None:
        """If no failures but warnings exist, overall is 'warn'."""
        orch = self._make_orchestrator()
        result = orch.run_full_cycle()

        # Manually set a stage to warn
        for sr in result.stages:
            if sr.stage == EngineeringStage.BENCHMARK:
                sr.status = "warn"
                break

        result.overall_status = orch._compute_overall_status(result)
        self.assertEqual(result.overall_status, "warn")

    def test_full_cycle_result_persistence(self) -> None:
        """Full cycle result is persisted to disk as JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            orch = self._make_orchestrator()

            # Override the save directory
            with patch("reconpro.engineering_workflow.ENGINEERING_CYCLES_DIR", Path(tmpdir)):
                result = orch.run_full_cycle()

            # Check a file was created
            files = list(Path(tmpdir).glob("cycle_*.json"))
            self.assertGreater(len(files), 0)

            # Verify JSON content
            with open(files[0]) as f:
                data = json.load(f)
            self.assertEqual(data["mode"], "full")
            self.assertEqual(len(data["stages"]), 15)

    def test_full_cycle_metrics_summary(self) -> None:
        """Result includes accurate metrics summary."""
        orch = self._make_orchestrator()
        result = orch.run_full_cycle()

        self.assertIn("total_stages", result.metrics)
        self.assertEqual(result.metrics["total_stages"], 15)
        self.assertEqual(result.metrics["passed"], 15)
        self.assertEqual(result.metrics["failed"], 0)


# ═══════════════════════════════════════════════════════════════════════
#  Test run_validation_only
# ═══════════════════════════════════════════════════════════════════════


class TestOrchestratorValidationOnly(TestCase):
    """Test the validation-only mode."""

    def _make_orchestrator(self) -> ContinuousEngineeringOrchestrator:
        """Create an orchestrator with mocked subsystems for validation."""
        orch = ContinuousEngineeringOrchestrator(repository_path="/tmp/test")

        orch._digital_twin = MagicMock()
        orch._digital_twin.capture_state.return_value = _make_mock_system_model()

        orch._validation_pipeline = MagicMock()
        mock_report = _make_mock_stage_result()
        orch._validation_pipeline.validate_full.return_value = mock_report

        orch._engineering_pipeline = MagicMock()
        mock_qg = MagicMock()
        mock_qg.to_dict.return_value = {"passed": True}
        orch._engineering_pipeline.quality_gate.return_value = mock_qg

        return orch

    def test_validation_only_runs_three_stages(self) -> None:
        """Validation-only runs exactly 3 stages."""
        orch = self._make_orchestrator()
        result = orch.run_validation_only()

        self.assertEqual(result.mode, "validation_only")
        self.assertEqual(len(result.stages), 3)

        stage_names = [s.stage for s in result.stages]
        self.assertEqual(stage_names, _VALIDATION_ONLY_STAGES)

    def test_validation_only_correct_order(self) -> None:
        """Validation-only runs: state capture, validation, quality gate."""
        orch = self._make_orchestrator()
        result = orch.run_validation_only()

        stage_names = [s.stage.value for s in result.stages]
        self.assertEqual(stage_names, ["digital_twin_state", "auto_validation", "quality_gate"])

    def test_validation_only_calls_correct_subsystems(self) -> None:
        """Validation-only only calls the relevant subsystems."""
        orch = self._make_orchestrator()
        result = orch.run_validation_only()

        orch._digital_twin.capture_state.assert_called_once()
        orch._validation_pipeline.validate_full.assert_called_once()
        orch._engineering_pipeline.quality_gate.assert_called_once()

        # These should NOT be called
        orch._engineering_pipeline.health_check.assert_not_called()
        orch._engineering_pipeline.drift_detection.assert_not_called()

    def test_validation_only_graceful_degradation(self) -> None:
        """One failure in validation-only doesn't crash the pipeline."""
        orch = self._make_orchestrator()
        orch._validation_pipeline.validate_full.side_effect = RuntimeError("Validation boom")

        result = orch.run_validation_only()

        self.assertEqual(len(result.stages), 3)
        failed = [s for s in result.stages if s.status == "fail"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].stage, EngineeringStage.AUTO_VALIDATION)


# ═══════════════════════════════════════════════════════════════════════
#  Test run_engineering_only
# ═══════════════════════════════════════════════════════════════════════


class TestOrchestratorEngineeringOnly(TestCase):
    """Test the engineering-only mode."""

    def _make_orchestrator(self) -> ContinuousEngineeringOrchestrator:
        """Create an orchestrator with mocked subsystems for engineering."""
        orch = ContinuousEngineeringOrchestrator(repository_path="/tmp/test")

        orch._engineering_pipeline = MagicMock()
        orch._engineering_pipeline.health_check.return_value = {"status": "healthy"}
        orch._engineering_pipeline.drift_detection.return_value = {"drift_score": 0.0}

        orch._benchmark_automation = MagicMock()
        orch._benchmark_automation.run_quick_benchmark.return_value = {"regressions_detected": 0}

        orch._regression_intelligence = MagicMock()
        orch._regression_intelligence.detect_regression.return_value = []

        orch._repository_learner = MagicMock()
        orch._repository_learner.learn_from_scan.return_value = 0
        orch._repository_learner.learn_from_test.return_value = 0

        orch._engineering_recommender = MagicMock()
        orch._engineering_recommender.recommend_from_diagnostics.return_value = []
        orch._engineering_recommender.recommend_from_drift.return_value = []
        orch._engineering_recommender.recommend_from_test_results.return_value = []
        orch._engineering_recommender.recommend_from_performance.return_value = []

        orch._auto_fix_engine = MagicMock()
        orch._auto_fix_engine.propose_fixes.return_value = []

        return orch

    def test_engineering_only_runs_seven_stages(self) -> None:
        """Engineering-only runs exactly 7 stages."""
        orch = self._make_orchestrator()
        result = orch.run_engineering_only()

        self.assertEqual(result.mode, "engineering_only")
        self.assertEqual(len(result.stages), 7)

    def test_engineering_only_correct_order(self) -> None:
        """Engineering-only runs: health → drift → benchmark → regression → learn → recs → fix."""
        orch = self._make_orchestrator()
        result = orch.run_engineering_only()

        stage_names = [s.stage for s in result.stages]
        self.assertEqual(stage_names, _ENGINEERING_ONLY_STAGES)

        # Verify exact sequence
        expected_values = [
            "health_check",
            "drift_detection",
            "benchmark",
            "regression_intelligence",
            "learning",
            "recommendations",
            "auto_fix",
        ]
        actual_values = [s.stage.value for s in result.stages]
        self.assertEqual(actual_values, expected_values)

    def test_engineering_only_calls_correct_subsystems(self) -> None:
        """Engineering-only calls health, drift, benchmark, regression, learning, recs, fix."""
        orch = self._make_orchestrator()
        result = orch.run_engineering_only()

        orch._engineering_pipeline.health_check.assert_called_once()
        orch._engineering_pipeline.drift_detection.assert_called_once()
        orch._benchmark_automation.run_quick_benchmark.assert_called_once()
        orch._regression_intelligence.detect_regression.assert_called_once()
        orch._auto_fix_engine.propose_fixes.assert_called_once()

        # These should NOT be called
        orch._engineering_pipeline.quality_gate.assert_not_called()
        if hasattr(orch, '_validation_pipeline') and orch._validation_pipeline is not None:
            orch._validation_pipeline.validate_full.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════
#  Test get_status
# ═══════════════════════════════════════════════════════════════════════


class TestOrchestratorGetStatus(TestCase):
    """Test the get_status method."""

    def test_status_before_any_cycle(self) -> None:
        """get_status returns valid data before any cycle runs."""
        orch = ContinuousEngineeringOrchestrator(repository_path="/tmp/test")
        status = orch.get_status()

        self.assertEqual(status["repository_path"], "/tmp/test")
        self.assertEqual(status["cycle_count"], 0)
        self.assertIsNone(status["last_cycle"])

        # All subsystems should show as not loaded
        subsystems = status["subsystems_loaded"]
        self.assertFalse(any(subsystems.values()))

    def test_status_after_cycle(self) -> None:
        """get_status reflects the last cycle result."""
        orch = ContinuousEngineeringOrchestrator(repository_path="/tmp/test")

        # Pre-mock all subsystems
        for attr in (
            "_engineering_pipeline", "_repository_memory", "_digital_twin",
            "_repository_learner", "_engineering_recommender",
            "_regression_intelligence", "_validation_pipeline",
            "_benchmark_automation", "_auto_fix_engine",
            "_prompt_defense", "_security_policy_engine",
        ):
            setattr(orch, attr, MagicMock())

        orch._engineering_pipeline.health_check.return_value = {"status": "healthy"}
        orch._engineering_pipeline.drift_detection.return_value = {"drift_score": 0.0}
        mock_qg = MagicMock()
        mock_qg.to_dict.return_value = {"passed": True}
        orch._engineering_pipeline.quality_gate.return_value = mock_qg
        orch._digital_twin.capture_state.return_value = _make_mock_system_model()
        orch._digital_twin.detect_anomaly.return_value = {"anomalies": [], "anomaly_count": 0}
        orch._repository_memory.search.return_value = []
        orch._validation_pipeline.validate_full.return_value = _make_mock_stage_result()
        orch._benchmark_automation.run_quick_benchmark.return_value = {"regressions_detected": 0}
        orch._regression_intelligence.detect_regression.return_value = []
        orch._regression_intelligence.generate_regression_report.return_value = "Clean."
        orch._repository_learner.learn_from_scan.return_value = 0
        orch._repository_learner.learn_from_test.return_value = 0
        orch._engineering_recommender.recommend_from_diagnostics.return_value = []
        orch._engineering_recommender.recommend_from_drift.return_value = []
        orch._engineering_recommender.recommend_from_test_results.return_value = []
        orch._engineering_recommender.recommend_from_performance.return_value = []
        orch._auto_fix_engine.propose_fixes.return_value = []
        orch._repository_memory.remember.return_value = MagicMock()

        with patch("reconpro.engineering_workflow.ENGINEERING_CYCLES_DIR",
                    Path(tempfile.mkdtemp())):
            orch.run_full_cycle()

        status = orch.get_status()
        self.assertEqual(status["cycle_count"], 1)
        self.assertIsNotNone(status["last_cycle"])
        self.assertEqual(status["last_cycle"]["mode"], "full")
        self.assertTrue(status["last_cycle"]["overall_status"])

    def test_status_subsystems_loaded(self) -> None:
        """get_status correctly reports which subsystems are loaded."""
        orch = ContinuousEngineeringOrchestrator(repository_path="/tmp/test")

        # Load just two subsystems
        orch._digital_twin = MagicMock()
        orch._repository_memory = MagicMock()

        status = orch.get_status()
        self.assertTrue(status["subsystems_loaded"]["digital_twin"])
        self.assertTrue(status["subsystems_loaded"]["repository_memory"])
        self.assertFalse(status["subsystems_loaded"]["engineering_pipeline"])


# ═══════════════════════════════════════════════════════════════════════
#  Test compute_overall_status
# ═══════════════════════════════════════════════════════════════════════


class TestComputeOverallStatus(TestCase):
    """Test the overall status computation logic."""

    def test_all_pass(self) -> None:
        orch = ContinuousEngineeringOrchestrator()
        result = EngineeringCycleResult(
            stages=[StageResult(stage=EngineeringStage.HEALTH_CHECK, status="pass")]
        )
        self.assertEqual(orch._compute_overall_status(result), "pass")

    def test_any_fail(self) -> None:
        orch = ContinuousEngineeringOrchestrator()
        result = EngineeringCycleResult(stages=[
            StageResult(stage=EngineeringStage.HEALTH_CHECK, status="pass"),
            StageResult(stage=EngineeringStage.DRIFT_DETECTION, status="fail"),
            StageResult(stage=EngineeringStage.BENCHMARK, status="pass"),
        ])
        self.assertEqual(orch._compute_overall_status(result), "fail")

    def test_warn_no_fail(self) -> None:
        orch = ContinuousEngineeringOrchestrator()
        result = EngineeringCycleResult(stages=[
            StageResult(stage=EngineeringStage.HEALTH_CHECK, status="pass"),
            StageResult(stage=EngineeringStage.AUTO_VALIDATION, status="warn"),
        ])
        self.assertEqual(orch._compute_overall_status(result), "warn")

    def test_fail_overrides_warn(self) -> None:
        orch = ContinuousEngineeringOrchestrator()
        result = EngineeringCycleResult(stages=[
            StageResult(stage=EngineeringStage.HEALTH_CHECK, status="warn"),
            StageResult(stage=EngineeringStage.DRIFT_DETECTION, status="fail"),
        ])
        self.assertEqual(orch._compute_overall_status(result), "fail")

    def test_skipped_ignored(self) -> None:
        orch = ContinuousEngineeringOrchestrator()
        result = EngineeringCycleResult(stages=[
            StageResult(stage=EngineeringStage.HEALTH_CHECK, status="pass"),
            StageResult(stage=EngineeringStage.BENCHMARK, status="skipped"),
        ])
        self.assertEqual(orch._compute_overall_status(result), "pass")


# ═══════════════════════════════════════════════════════════════════════
#  Test repository_path override
# ═══════════════════════════════════════════════════════════════════════


class TestRepositoryPathOverride(TestCase):
    """Test that repository_path can be overridden per-cycle."""

    def test_full_cycle_override(self) -> None:
        orch = ContinuousEngineeringOrchestrator(repository_path="/original/path")

        # Pre-mock all subsystems
        for attr in (
            "_engineering_pipeline", "_repository_memory", "_digital_twin",
            "_repository_learner", "_engineering_recommender",
            "_regression_intelligence", "_validation_pipeline",
            "_benchmark_automation", "_auto_fix_engine",
            "_prompt_defense", "_security_policy_engine",
        ):
            setattr(orch, attr, MagicMock())

        orch._engineering_pipeline.health_check.return_value = {"status": "healthy"}
        orch._engineering_pipeline.drift_detection.return_value = {"drift_score": 0.0}
        mock_qg = MagicMock()
        mock_qg.to_dict.return_value = {"passed": True}
        orch._engineering_pipeline.quality_gate.return_value = mock_qg
        orch._digital_twin.capture_state.return_value = _make_mock_system_model()
        orch._digital_twin.detect_anomaly.return_value = {"anomalies": [], "anomaly_count": 0}
        orch._repository_memory.search.return_value = []
        orch._repository_memory.remember.return_value = MagicMock()
        orch._validation_pipeline.validate_full.return_value = _make_mock_stage_result()
        orch._benchmark_automation.run_quick_benchmark.return_value = {"regressions_detected": 0}
        orch._regression_intelligence.detect_regression.return_value = []
        orch._regression_intelligence.generate_regression_report.return_value = "Clean."
        orch._repository_learner.learn_from_scan.return_value = 0
        orch._repository_learner.learn_from_test.return_value = 0
        orch._engineering_recommender.recommend_from_diagnostics.return_value = []
        orch._engineering_recommender.recommend_from_drift.return_value = []
        orch._engineering_recommender.recommend_from_test_results.return_value = []
        orch._engineering_recommender.recommend_from_performance.return_value = []
        orch._auto_fix_engine.propose_fixes.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("reconpro.engineering_workflow.ENGINEERING_CYCLES_DIR",
                        Path(tmpdir)):
                result = orch.run_full_cycle(repository_path="/override/path")

        self.assertEqual(result.repository_path, "/override/path")


if __name__ == "__main__":
    import unittest
    unittest.main()
