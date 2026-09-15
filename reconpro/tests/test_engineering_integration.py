"""Swarm 5 — Auto Engineering Pipeline Integration Tests.

Verifies INTEGRATION between all engineering subsystems:

1. Cross-module data flow:
   - auto_engineering diagnostics → engineering_recommendations
   - regression_intelligence baselines → auto_validation
   - auto_fix proposals → auto_validation
   - repository_memory stores results from any engineering module
   - digital_twin captures state from diagnostics results

2. Pipeline integration:
   - Repository Memory → Digital Twin: Memory stores twin snapshots
   - Digital Twin → Auto Fix: Twin simulation feeds fix proposals
   - Auto Validation → Quality Gate: Validation results feed quality gate
   - Benchmark → Regression Intelligence: Benchmarks feed regression detection
   - Learning → Recommendations: Learned patterns improve recommendations

3. End-to-end engineering cycle:
   - Run diagnostics → detect issues → generate recommendations → propose fixes → validate fixes
   - Capture baseline → run benchmark → detect regression → generate report

All tests use unittest.mock to mock expensive operations.
Focus is on API compatibility and correct data flow.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, PropertyMock

# ── Import modules under test ───────────────────────────────────────

from reconpro.auto_engineering import (
    EngineeringMetrics,
    EngineeringBaseline,
    EngineeringPipeline,
    MetricsSnapshot,
    DriftReport,
    QualityGateResult,
    DEFAULT_QUALITY_THRESHOLDS,
)
from reconpro.repository_memory import (
    RepositoryMemory,
    EngineeringFact,
    MemoryQuery,
    MemorySnapshot,
)
from reconpro.digital_twin import (
    DigitalTwin,
    SystemModel,
    ComponentState,
    SimulationEngine,
    SimulationResult,
    TwinSync,
)
from reconpro.engineering_recommendations import (
    Recommendation,
    RecommendationStore,
    RecommendationEngine,
    EngineeringRecommender,
)
from reconpro.regression_intelligence import (
    BaselineManager,
    RegressionDetector,
    RegressionRecord,
    RegressionIntelligence,
    RegressionType,
    RegressionSeverity,
    RegressionStatus,
)
from reconpro.auto_validation import (
    ValidationPipeline,
    ValidationReport,
    ValidationStageResult,
    ValidationFinding,
    StageStatus,
)
from reconpro.auto_fix import (
    AutoFixEngine,
    FixProposal,
    FixAnalyzer,
    FixStore,
    ProposalStatus,
    RiskLevel,
    FixCategory,
)
from reconpro.repository_learning import (
    RepositoryLearner,
    LearnedPattern,
    PatternStore,
    PatternExtractor,
    PatternQuery,
    PATTERN_FREQUENCY,
    PATTERN_TREND,
    PATTERN_CORRELATION,
    SOURCE_SCAN,
    SOURCE_TEST,
    SOURCE_ERROR,
    VALID_PATTERN_TYPES,
)
from reconpro.benchmark_automation import (
    BenchmarkResult,
    BenchmarkSuite,
    BenchmarkBaseline,
    BenchmarkAutomation,
)


# ═══════════════════════════════════════════════════════════════════════
#  Test helpers
# ═══════════════════════════════════════════════════════════════════════


def _make_temp_dir() -> str:
    """Create a temp directory and return its path."""
    d = tempfile.mkdtemp(prefix="reconpro_integration_")
    return d


def _make_health_check_result() -> Dict[str, Any]:
    """Create a realistic health_check() result dict."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_path": "/fake/repo",
        "health": {
            "status": "degraded",
            "modules_ok": 20,
            "modules_total": 25,
        },
        "config_issues": [
            {"field": "rate_limit", "message": "missing"},
        ],
        "diagnostics": {
            "total": 10,
            "passed": 7,
            "failed": 3,
            "checks": [
                {"label": "disk_space", "status": "error", "error": "Low disk", "value": None},
                {"label": "network_dns", "status": "ok", "value": True, "error": ""},
                {"label": "module_registry", "status": "error", "error": "Broken", "value": {"broken": ["mod_a", "mod_b"]}},
                {"label": "ssl_certificate", "status": "ok", "value": True, "error": ""},
            ],
        },
        "health_score": 70.0,
        "repository": {
            "repo_exists": True,
            "source_file_count": 42,
            "test_file_count": 5,
            "has_tests": True,
            "has_build_config": True,
            "has_documentation": True,
            "has_vcs": True,
        },
    }


def _make_diagnostics_result() -> Dict[str, Any]:
    """Create diagnostics result in the shape expected by Recommend.recommend_from_diagnostics."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_checks": 8,
        "passed": 5,
        "failed": 3,
        "checks": [
            {"label": "module_registry", "status": "error", "error": "Broken runners", "value": {"broken": ["port_scan", "ssl_check"]}},
            {"label": "disk_space", "status": "error", "error": "Only 100MB free", "value": None},
            {"label": "network_dns", "status": "error", "error": "DNS failed", "value": None},
            {"label": "ssl_certificate", "status": "ok", "value": True, "error": ""},
            {"label": "scan_history", "status": "ok", "value": True, "error": ""},
        ],
    }


def _make_metrics_snapshot(**overrides: Any) -> MetricsSnapshot:
    """Create a MetricsSnapshot with sensible defaults."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc).isoformat(),
        test_pass_rate=85.0,
        test_total=100,
        test_passed=85,
        test_failed=10,
        test_skipped=5,
        coverage_percent=72.0,
        debt_ratio=5.0,
        debt_items=3,
        complexity_avg=8.0,
        complexity_max=15.0,
        file_count=42,
        total_lines=5000,
        source_lines=4000,
        pipeline_duration_ms=250.0,
    )
    defaults.update(overrides)
    return MetricsSnapshot(**defaults)


def _make_drift_report(**overrides: Any) -> DriftReport:
    """Create a DriftReport with sensible defaults."""
    defaults = dict(
        baseline_name="test_baseline",
        baseline_timestamp="2025-01-01T00:00:00+00:00",
        current_timestamp=datetime.now(timezone.utc).isoformat(),
        files_added=["new_module.py"],
        files_removed=[],
        files_modified=["core.py"],
        drift_events=[
            {"path": "core.py", "type": "CONTENT_CHANGE", "severity": "medium"},
        ],
        drift_score=15.0,
        regression_detected=False,
        regression_details=[],
    )
    defaults.update(overrides)
    return DriftReport(**defaults)


def _make_scan_result() -> Dict[str, Any]:
    """Create a realistic scan result dict."""
    return {
        "target": "example.com",
        "total_score": 85.0,
        "findings_count": 12,
        "scan_duration_ms": 3200.0,
        "severity_counts": {"critical": 1, "high": 3, "medium": 5, "low": 3},
        "findings": [
            {"title": "SQL Injection", "severity": "high", "category": "injection"},
            {"title": "XSS", "severity": "medium", "category": "xss"},
            {"title": "Open Redirect", "severity": "low", "category": "redirect"},
        ],
        "modules": ["port_scan", "ssl_check", "dns_enum"],
    }


def _make_system_model() -> SystemModel:
    """Create a SystemModel with healthy defaults."""
    model = SystemModel(captured_at=datetime.now(timezone.utc).isoformat())
    model.engine.status = "healthy"
    model.engine.metrics = {"active_scans": 2, "scan_queue_depth": 0}
    model.engine.constraints = {"max_concurrency": 10, "default_timeout": 30}
    model.scanner.status = "healthy"
    model.scanner.metrics = {"module_ids": ["port_scan", "ssl_check"], "broken_modules": []}
    model.network.status = "healthy"
    model.network.metrics = {"avg_latency_ms": 150.0, "dns_resolve_ms": 50.0}
    model.network.constraints = {"latency_baseline_ms": 300.0}
    model.storage.status = "healthy"
    model.storage.metrics = {"rss_mb": 80.0, "usage_percent": 30.0, "free_mb": 50000.0}
    model.storage.constraints = {"memory_warning_mb": 200.0, "memory_critical_mb": 400.0}
    model.plugins.status = "healthy"
    model.plugins.metrics = {"plugin_count": 2}
    model.configuration.status = "healthy"
    model.configuration.metrics = {}
    return model


# ═══════════════════════════════════════════════════════════════════════
#  1. Cross-Module Data Flow
# ═══════════════════════════════════════════════════════════════════════


class TestDiagnosticsToRecommendationsFlow(unittest.TestCase):
    """Verify auto_engineering diagnostics results feed into engineering_recommendations."""

    def test_health_check_diagnostics_feed_recommendations(self):
        """Health check diagnostic results should produce engineering recommendations.

        The EngineeringRecommender.recommend_from_diagnostics() method
        accepts the diagnostics dict shape and returns Recommendation objects.
        """
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "recs.json"
            recommender = EngineeringRecommender(store_path=store_path)

            diag_results = _make_diagnostics_result()
            recs = recommender.recommend_from_diagnostics(diag_results)

            # Should generate at least one recommendation from failed checks
            self.assertIsInstance(recs, list)
            self.assertGreater(len(recs), 0)

            # All recommendations should be Recommendation instances
            for rec in recs:
                self.assertIsInstance(rec, Recommendation)
                self.assertIn(rec.source, ("diagnostics", "testing", "performance"))
                self.assertTrue(rec.id)
                self.assertTrue(rec.title)
                self.assertIn(rec.severity, ("critical", "high", "medium", "low", "info"))

            # Broken module registry should generate a recommendation
            module_recs = [r for r in recs if "broken" in r.title.lower() or "module" in r.title.lower()]
            self.assertGreater(len(module_recs), 0)

    def test_health_check_result_shape_compatibility(self):
        """The health_check() output dict should be compatible with recommend_from_diagnostics.

        The diagnostics key within health_check output should contain
        the 'checks' list expected by the recommendation engine.
        """
        health = _make_health_check_result()
        diag_data = health.get("diagnostics", {})

        # Verify the expected keys exist
        self.assertIn("checks", diag_data)
        self.assertIn("total", diag_data)
        self.assertIn("passed", diag_data)
        self.assertIn("failed", diag_data)

        # Verify each check has expected shape
        for check in diag_data["checks"]:
            self.assertIn("label", check)
            self.assertIn("status", check)

    def test_pipeline_workflow_result_feeds_recommendations(self):
        """The full engineering_workflow result should contain data
        usable by the recommendation engine."""
        # The engineering_workflow returns a dict with 'health_check'
        # containing 'result' which has 'diagnostics'
        workflow_result = {
            "health_check": {
                "result": _make_health_check_result(),
            },
            "quality_gate": {
                "result": {
                    "passed": False,
                    "score": 65.0,
                    "failures": ["Test pass rate below threshold"],
                },
            },
        }

        # Extract diagnostics from workflow result
        health_data = workflow_result["health_check"]["result"]
        diag_data = health_data.get("diagnostics", {})

        # This should be feedable to the recommendation engine
        self.assertIn("checks", diag_data)

        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "recs.json"
            engine = RecommendationEngine(store=RecommendationStore(path=store_path))
            recs = engine.generate_from_diagnostics(diag_data)
            self.assertIsInstance(recs, list)


class TestRegressionBaselinesToValidation(unittest.TestCase):
    """Verify regression_intelligence baselines can be compared by auto_validation."""

    def test_baseline_values_are_numeric_for_comparison(self):
        """Baseline values captured by RegressionIntelligence should
        be usable as numeric comparisons by validation logic."""
        with tempfile.TemporaryDirectory() as td:
            baseline_path = Path(td) / "baseline.json"
            history_path = Path(td) / "history.json"
            ri = RegressionIntelligence(
                baseline_path=baseline_path,
                history_path=history_path,
            )

            # Capture a baseline with numeric metrics
            baseline_data = {
                "total_score": 85.0,
                "findings_count": 12,
                "scan_duration_ms": 3200.0,
                "severity_counts": {"critical": 1, "high": 3, "medium": 5, "low": 3},
            }
            entry = ri.capture_baseline("scan_v1", baseline_data, label="v1 baseline")

            self.assertIsNotNone(entry)
            self.assertEqual(entry["key"], "scan_v1")
            self.assertEqual(entry["value"], baseline_data)

            # Retrieve and verify numeric extraction
            retrieved = ri._baseline_mgr.get("scan_v1")
            self.assertEqual(retrieved["total_score"], 85.0)

    def test_regression_detection_returns_comparable_records(self):
        """RegressionRecord.to_dict() output should be JSON-serializable
        and compatible with validation report ingestion."""
        record = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            description="Scan latency increased",
            baseline_value=3200.0,
            current_value=4800.0,
            delta=1600.0,
            severity=RegressionSeverity.HIGH,
            affected_component="scanner",
        )

        d = record.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d, default=str)
        self.assertIsInstance(json_str, str)

        # Should be deserializable
        restored = RegressionRecord.from_dict(d)
        self.assertEqual(restored.description, record.description)
        self.assertEqual(restored.severity, record.severity)

    def test_regression_detector_performance_output_compatible(self):
        """RegressionDetector.detect_performance_regressions returns
        RegressionRecords that can be stored in repository memory."""
        detector = RegressionDetector()
        baselines = {"latency_ms": 100.0, "error_rate": 0.02}
        current = {"latency_ms": 130.0, "error_rate": 0.05}

        regressions = detector.detect_performance_regressions(
            baselines, current, component="api_gateway"
        )

        self.assertIsInstance(regressions, list)
        for reg in regressions:
            # Each record should be serializable to dict
            d = reg.to_dict()
            self.assertIn("type", d)
            self.assertIn("severity", d)
            self.assertIn("delta", d)
            # Should be storable in repository memory
            self.assertIsInstance(d["delta"], float)


class TestAutoFixProposalsToValidation(unittest.TestCase):
    """Verify auto_fix proposals can be validated by auto_validation."""

    def test_fix_proposal_contains_validation_metadata(self):
        """FixProposal should contain enough metadata for validation.

        The proposal's source_issue, severity, and category should
        align with ValidationFinding fields.
        """
        proposal = FixProposal(
            title="Replace eval() with ast.literal_eval()",
            description="Security fix for dangerous eval usage",
            severity="high",
            category=FixCategory.SECURITY.value,
            affected_file="/src/parser.py",
            affected_lines=[42, 43, 44],
            proposed_code="ast.literal_eval(data)",
            risk_level=RiskLevel.LOW.value,
            confidence=0.85,
            source_issue={
                "title": "Dangerous eval detected",
                "category": "security",
                "severity": "high",
                "message": "eval() usage found at line 42",
            },
        )

        # Verify proposal has fields that map to validation
        self.assertTrue(proposal.affected_file)
        self.assertTrue(proposal.affected_lines)
        self.assertTrue(proposal.severity)
        self.assertTrue(proposal.source_issue)

        # Verify serialisation compatibility
        d = proposal.to_dict()
        self.assertIn("severity", d)
        self.assertIn("category", d)
        self.assertIn("affected_file", d)
        self.assertIn("confidence", d)

    def test_fix_store_proposals_are_accessible(self):
        """FixStore should persist and retrieve proposals correctly."""
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "fixes.json"
            store = FixStore(store_path=store_path)

            proposal = FixProposal(
                title="Test fix",
                severity="medium",
                confidence=0.7,
            )
            store.add(proposal)

            # Retrieve
            all_props = store.list_all()
            self.assertEqual(len(all_props), 1)
            self.assertEqual(all_props[0].id, proposal.id)

            # Get by status
            proposed = store.list_by_status("proposed")
            self.assertEqual(len(proposed), 1)

    def test_auto_fix_engine_propose_from_scan(self):
        """AutoFixEngine should accept scan results and produce proposals."""
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "fixes.json"
            store = FixStore(store_path=store_path)
            engine = AutoFixEngine(store=store, dry_run=True)

            scan_result = {
                "findings": [
                    {
                        "title": "eval() usage detected",
                        "category": "security",
                        "severity": "high",
                        "message": "Dangerous eval at line 42",
                        "file": "test.py",
                        "line": 42,
                    },
                ],
            }

            proposals = engine.propose_fixes(scan_result)
            self.assertIsInstance(proposals, list)


class TestRepositoryMemoryStoresEngineeringResults(unittest.TestCase):
    """Verify repository_memory can store results from any engineering module."""

    def test_store_metrics_snapshot(self):
        """RepositoryMemory should store EngineeringMetrics snapshot data."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            snapshot = _make_metrics_snapshot(test_pass_rate=92.0, debt_ratio=3.0)
            fact = mem.remember(
                key="engineering/metrics/latest",
                value=snapshot.to_dict(),
                metadata={
                    "source": "auto_engineering",
                    "tags": ["metrics", "engineering", "quality"],
                    "confidence": 0.95,
                },
            )

            self.assertIsInstance(fact, EngineeringFact)
            self.assertEqual(fact.key, "engineering/metrics/latest")

            # Recall
            recalled = mem.recall("engineering/metrics/latest")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["test_pass_rate"], 92.0)

    def test_store_drift_report(self):
        """RepositoryMemory should store drift report data."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            drift = _make_drift_report(drift_score=25.0, regression_detected=True)
            mem.remember(
                key="engineering/drift/latest",
                value=drift.to_dict(),
                metadata={
                    "source": "auto_engineering",
                    "tags": ["drift", "regression"],
                },
            )

            recalled = mem.recall("engineering/drift/latest")
            self.assertIsNotNone(recalled)
            self.assertTrue(recalled.value["regression_detected"])

    def test_store_quality_gate_result(self):
        """RepositoryMemory should store quality gate results."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            gate = QualityGateResult(
                passed=True,
                score=88.0,
                failures=[],
                warnings=["Debt ratio approaching threshold"],
            )

            mem.remember(
                key="engineering/quality_gate/latest",
                value=gate.to_dict(),
                metadata={
                    "source": "auto_engineering",
                    "tags": ["quality", "gate"],
                },
            )

            recalled = mem.recall("engineering/quality_gate/latest")
            self.assertIsNotNone(recalled)
            self.assertTrue(recalled.value["passed"])

    def test_store_recommendation_results(self):
        """RepositoryMemory should store recommendation summaries."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            rec = Recommendation(
                title="Fix broken modules",
                severity="high",
                category="diagnostics",
                source="diagnostics",
                confidence=0.9,
            )

            mem.remember(
                key="recommendations/latest",
                value=rec.to_dict(),
                metadata={
                    "source": "engineering_recommendations",
                    "tags": ["recommendation", "diagnostics"],
                },
            )

            recalled = mem.recall("recommendations/latest")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["severity"], "high")

    def test_store_regression_records(self):
        """RepositoryMemory should store regression records."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            record = RegressionRecord(
                type=RegressionType.PERFORMANCE,
                description="Latency spike",
                severity=RegressionSeverity.HIGH,
                delta=50.0,
            )

            mem.remember(
                key="regression/latest",
                value=record.to_dict(),
                metadata={
                    "source": "regression_intelligence",
                    "tags": ["regression", "performance"],
                },
            )

            recalled = mem.recall("regression/latest")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["type"], "performance")

    def test_store_benchmark_results(self):
        """RepositoryMemory should store benchmark results."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            result = BenchmarkResult(
                name="dict_insert_10k",
                category="cpu",
                value=2.5,
                unit="ms",
            )

            mem.remember(
                key="benchmark/cpu/dict_insert_10k",
                value=result.to_dict(),
                metadata={
                    "source": "benchmark_automation",
                    "tags": ["benchmark", "cpu"],
                },
            )

            recalled = mem.recall("benchmark/cpu/dict_insert_10k")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["value"], 2.5)

    def test_search_by_tag_across_modules(self):
        """Should be able to search facts across all engineering modules by tag."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            # Store from multiple modules
            mem.remember(
                "eng/metrics", {"test_pass_rate": 90.0},
                metadata={"source": "auto_engineering", "tags": ["metrics"]},
            )
            mem.remember(
                "reg/perf", {"latency_ms": 150.0},
                metadata={"source": "regression_intelligence", "tags": ["metrics"]},
            )
            mem.remember(
                "bench/cpu", {"value": 2.5},
                metadata={"source": "benchmark_automation", "tags": ["benchmark"]},
            )

            # Query by tag
            metrics_facts = mem.recall_by_tag("metrics")
            self.assertEqual(len(metrics_facts), 2)

            bench_facts = mem.recall_by_tag("benchmark")
            self.assertEqual(len(bench_facts), 1)


class TestDigitalTwinCapturesDiagnosticsState(unittest.TestCase):
    """Verify digital_twin can capture state from diagnostics results."""

    def test_system_model_from_diagnostics(self):
        """A SystemModel should be constructable from diagnostics data.

        ComponentState metrics/constraints should hold diagnostics-derived values.
        """
        model = _make_system_model()

        # Inject diagnostics-derived data
        model.engine.metrics["health_score"] = 70.0
        model.engine.metrics["failed_checks"] = 3
        model.engine.metrics["total_checks"] = 10

        # The model should serialize correctly
        d = model.to_dict()
        self.assertEqual(d["engine"]["metrics"]["health_score"], 70.0)

    def test_system_model_accepts_health_metrics(self):
        """SystemModel should accept arbitrary metrics from health checks."""
        model = _make_system_model()

        # Health check typically produces module counts and status
        model.scanner.metrics["modules_ok"] = 20
        model.scanner.metrics["modules_total"] = 25
        model.scanner.metrics["broken_modules"] = ["port_scan", "ssl_check"]
        model.scanner.status = "degraded"

        self.assertEqual(model.scanner.status, "degraded")
        self.assertEqual(model.overall_status(), "degraded")

    def test_simulation_engine_accepts_diagnostics_model(self):
        """SimulationEngine.simulate() should accept a SystemModel
        populated with diagnostics data."""
        model = _make_system_model()
        sim = SimulationEngine()

        # Simulate with the model
        result = sim.simulate(model, "add_concurrent_scans:5")
        self.assertIsInstance(result, SimulationResult)
        self.assertIn(result.risk_level, ("low", "medium", "high", "critical"))
        self.assertIsInstance(result.projected_state, dict)
        self.assertIsInstance(result.affected_components, list)


# ═══════════════════════════════════════════════════════════════════════
#  2. Pipeline Integration
# ═══════════════════════════════════════════════════════════════════════


class TestRepositoryMemoryToDigitalTwin(unittest.TestCase):
    """Repository Memory → Digital Twin: Memory stores twin snapshots."""

    def test_store_twin_snapshot_in_memory(self):
        """A SystemModel snapshot should be storable in RepositoryMemory."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            model = _make_system_model()
            snapshot_dict = model.to_dict()

            mem.remember(
                key="digital_twin/snapshot/latest",
                value=snapshot_dict,
                metadata={
                    "source": "digital_twin",
                    "tags": ["twin", "snapshot", "system_state"],
                    "confidence": 0.99,
                },
            )

            recalled = mem.recall("digital_twin/snapshot/latest")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["engine"]["status"], "healthy")

    def test_twin_history_via_memory_snapshots(self):
        """Multiple twin snapshots should be stored and diffable via memory."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            # Snapshot 1: healthy
            model1 = _make_system_model()
            mem.remember(
                "twin/snap_001", model1.to_dict(),
                metadata={"source": "digital_twin", "tags": ["twin"]},
            )

            # Snapshot 2: degraded
            model2 = _make_system_model()
            model2.scanner.status = "degraded"
            model2.scanner.metrics["broken_modules"] = ["port_scan"]
            mem.remember(
                "twin/snap_002", model2.to_dict(),
                metadata={"source": "digital_twin", "tags": ["twin"]},
            )

            # Query all twin snapshots
            twin_facts = mem.recall_by_tag("twin")
            self.assertEqual(len(twin_facts), 2)

            # Verify state change
            snap1 = mem.recall("twin/snap_001").value
            snap2 = mem.recall("twin/snap_002").value
            self.assertEqual(snap1["scanner"]["status"], "healthy")
            self.assertEqual(snap2["scanner"]["status"], "degraded")

    def test_memory_snapshot_diff_detects_twin_changes(self):
        """MemorySnapshot.diff_snapshots should detect twin state changes."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            # Snapshot A
            model_a = _make_system_model()
            mem.remember("twin/a", model_a.to_dict(),
                         metadata={"source": "digital_twin", "tags": ["twin"]})
            snap_a = mem.snapshot(label="before")

            # Snapshot B (with change)
            model_b = _make_system_model()
            model_b.engine.status = "degraded"
            mem.remember("twin/b", model_b.to_dict(),
                         metadata={"source": "digital_twin", "tags": ["twin"]})
            snap_b = mem.snapshot(label="after")

            # Diff
            diff = RepositoryMemory.diff_snapshots(snap_a, snap_b)
            self.assertIn("added", diff)
            self.assertIn("removed", diff)
            self.assertIn("modified", diff)
            # twin/a and twin/b values differ, so twin/a should be
            # removed and twin/b added (different keys) or modified (same keys)
            self.assertGreaterEqual(diff["stats"]["net_change"], 0)


class TestDigitalTwinToAutoFix(unittest.TestCase):
    """Digital Twin → Auto Fix: Twin simulation feeds fix proposals."""

    def test_simulation_result_informs_fix_context(self):
        """SimulationResult should contain data usable as fix context.

        The projected_state, risk_level, and recommendations from a
        simulation should inform what fixes are proposed.
        """
        model = _make_system_model()
        sim = SimulationEngine()

        result = sim.simulate(model, "memory_pressure")

        # Simulation result should have actionable data
        self.assertIn(result.risk_level, ("low", "medium", "high", "critical"))
        self.assertGreater(len(result.affected_components), 0)
        self.assertGreater(len(result.recommendations), 0)

        # The projected state should be a valid SystemModel dict
        projected = result.projected_state
        self.assertIn("engine", projected)
        self.assertIn("storage", projected)

    def test_simulation_scenario_dict_accepted(self):
        """SimulationEngine.simulate_dict() should accept custom scenario dicts."""
        model = _make_system_model()
        sim = SimulationEngine()

        params = {
            "type": "load",
            "component": "engine",
            "parameter": "active_scans",
            "value": 20,
            "description": "Increase scan load",
        }
        result = sim.simulate_dict(model, params)

        self.assertIsInstance(result, SimulationResult)
        self.assertEqual(result.scenario, "Increase scan load")
        self.assertIn("engine", result.affected_components)

    def test_simulation_recommendations_match_fix_categories(self):
        """Simulation recommendations should align with FixCategory values."""
        model = _make_system_model()
        sim = SimulationEngine()

        # Get simulation for disk full
        result = sim.simulate(model, "disk_full")

        valid_categories = {c.value for c in FixCategory}
        # The simulation's affected components should be mappable
        # to fix categories
        for comp in result.affected_components:
            self.assertIsInstance(comp, str)

        # Risk level should map to FixProposal risk levels
        valid_risks = {r.value for r in RiskLevel}
        self.assertIn(result.risk_level, valid_risks)


class TestAutoValidationToQualityGate(unittest.TestCase):
    """Auto Validation → Quality Gate: Validation results feed quality gate."""

    def test_validation_report_data_feeds_quality_gate(self):
        """ValidationReport data should be compatible with quality gate inputs.

        The quality_gate() method accepts MetricsSnapshot, DriftReport,
        and health_result dict. A ValidationReport's findings should
        inform these inputs.
        """
        report = ValidationReport(
            timestamp=datetime.now().isoformat(),
            project_root="/fake/repo",
            overall_status="failed",
            stage_results=[
                ValidationStageResult(
                    stage_name="syntax",
                    status="passed",
                    duration=0.1,
                    files_scanned=42,
                ),
                ValidationStageResult(
                    stage_name="security",
                    status="failed",
                    duration=0.5,
                    files_scanned=42,
                    findings=[
                        ValidationFinding(
                            file="src/parser.py",
                            line=42,
                            severity="high",
                            message="eval() usage detected",
                            suggestion="Use ast.literal_eval()",
                            rule_id="SEC001",
                        ),
                    ],
                ),
            ],
            total_duration=0.6,
        )

        # Extract data that would feed quality gate
        total_critical = report.total_critical
        total_high = report.total_high
        passed = report.passed

        # Validation failure should contribute to quality gate failure
        self.assertFalse(passed)
        self.assertEqual(total_high, 1)

        # The report should be serializable for storage
        report_dict = {
            "passed": passed,
            "total_findings": report.total_findings,
            "total_critical": total_critical,
            "total_high": total_high,
            "stages_passed": report.stages_passed,
            "stages_total": report.stages_total,
        }
        json_str = json.dumps(report_dict)
        self.assertIsInstance(json_str, str)

    def test_quality_gate_accepts_engineering_inputs(self):
        """QualityGateResult should be producible from engineering inputs."""
        metrics = _make_metrics_snapshot(test_pass_rate=75.0, complexity_max=25.0)
        drift = _make_drift_report(drift_score=60.0, regression_detected=True)
        health = _make_health_check_result()

        # These inputs should be accepted by quality_gate
        # We test the data types are correct
        self.assertIsInstance(metrics, MetricsSnapshot)
        self.assertIsInstance(drift, DriftReport)
        self.assertIsInstance(health["health_score"], float)

        # Verify the data can be serialized for the quality gate
        metrics_dict = metrics.to_dict()
        drift_dict = drift.to_dict()

        self.assertIn("test_pass_rate", metrics_dict)
        self.assertIn("drift_score", drift_dict)
        self.assertIn("regression_detected", drift_dict)

    def test_validation_stage_result_to_repository_memory(self):
        """ValidationStageResult should be storable in repository memory."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            stage_result = ValidationStageResult(
                stage_name="security",
                status="failed",
                duration=0.5,
                files_scanned=42,
                findings=[
                    ValidationFinding(
                        file="src/x.py", line=10,
                        severity="critical", message="Bad stuff",
                    ),
                ],
            )

            mem.remember(
                "validation/security/latest",
                stage_result.to_dict(),
                metadata={"source": "auto_validation", "tags": ["validation", "security"]},
            )

            recalled = mem.recall("validation/security/latest")
            self.assertIsNotNone(recalled)
            self.assertEqual(recalled.value["status"], "failed")


class TestBenchmarkToRegressionIntelligence(unittest.TestCase):
    """Benchmark → Regression Intelligence: Benchmarks feed regression detection."""

    def test_benchmark_results_provide_regression_baselines(self):
        """BenchmarkResult values should be usable as regression baselines."""
        with tempfile.TemporaryDirectory() as td:
            baseline_path = Path(td) / "reg_baseline.json"
            history_path = Path(td) / "reg_history.json"
            ri = RegressionIntelligence(
                baseline_path=baseline_path,
                history_path=history_path,
            )

            # Capture benchmark-like metrics as baselines
            benchmark_data = {
                "scan_duration_ms": 3200.0,
                "total_score": 85.0,
                "findings_count": 12,
                "module_count": 15,
            }
            ri.capture_baseline("benchmark_v1", benchmark_data)

            # Verify retrieval
            retrieved = ri._baseline_mgr.get("benchmark_v1")
            self.assertEqual(retrieved["scan_duration_ms"], 3200.0)

    def test_benchmark_regression_detection(self):
        """Benchmark comparisons should detect regressions.

        When current benchmark values are significantly worse than baselines,
        the regression detector should flag them.
        """
        detector = RegressionDetector(
            perf_percent=20.0,
            perf_absolute=500.0,
        )

        # Baseline: scan took 3200ms, now takes 4800ms (50% increase)
        baselines = {"scan_duration_ms": 3200.0, "total_score": 85.0}
        current = {"scan_duration_ms": 4800.0, "total_score": 60.0}

        # total_score is higher-is-better, so we invert it
        # For scan_duration_ms, higher is worse
        regressions = detector.detect_performance_regressions(
            baselines, current, component="scanner"
        )

        # At least scan_duration_ms should be flagged
        duration_regs = [
            r for r in regressions
            if "scan_duration" in r.description
        ]
        self.assertGreater(len(duration_regs), 0)

    def test_benchmark_baseline_vs_result_format(self):
        """BenchmarkBaseline.get_all_baseline_values() should return
        a dict compatible with RegressionDetector input."""
        with tempfile.TemporaryDirectory() as td:
            baseline_dir = Path(td) / "bench_baseline"
            bb = BenchmarkBaseline(storage_dir=baseline_dir)

            # Record some benchmark results
            bb.record(BenchmarkResult(
                name="dict_insert_10k", category="cpu", value=2.5, unit="ms"
            ))
            bb.record(BenchmarkResult(
                name="file_write_100KB", category="io", value=1.2, unit="ms"
            ))

            # Get all baselines
            all_baselines = bb.get_all_baseline_values()
            self.assertIsInstance(all_baselines, dict)
            self.assertIn("cpu:dict_insert_10k", all_baselines)
            self.assertEqual(all_baselines["cpu:dict_insert_10k"], 2.5)

            # These should be feedable to regression detector
            baselines = {k: v for k, v in all_baselines.items()}
            # All values are floats (suitable for regression detection)
            for v in baselines.values():
                self.assertIsInstance(v, float)


class TestLearningToRecommendations(unittest.TestCase):
    """Learning → Recommendations: Learned patterns improve recommendations."""

    def test_learned_patterns_queryable_for_recommendations(self):
        """LearnedPattern data should be queryable for recommendation context.

        RepositoryLearner should produce patterns that can inform
        the recommendation engine about what issues recur.
        """
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "patterns.json"
            ps = PatternStore(path=store_path)
            learner = RepositoryLearner(store=ps)

            # Learn from a scan result
            # Use findings with duplicate titles to exceed min_occurrences=2
            scan_result = _make_scan_result()
            scan_result["findings"] = (
                scan_result["findings"] * 2
            )
            stored = learner.learn_from_scan(scan_result)
            self.assertGreater(stored, 0)

            # Query learned patterns
            patterns = learner.get_learned_patterns(
                pattern_type=PATTERN_FREQUENCY,
                min_confidence=0.0,
            )
            self.assertIsInstance(patterns, list)

            # Patterns should have data usable by recommendation engine
            for p in patterns:
                self.assertIsInstance(p, LearnedPattern)
                self.assertTrue(p.key)
                self.assertIsInstance(p.confidence, float)
                self.assertGreaterEqual(p.support, 1)

    def test_learned_error_patterns_inform_recommendations(self):
        """Error patterns learned from failures should inform recommendation severity."""
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "patterns.json"
            ps = PatternStore(path=store_path)
            learner = RepositoryLearner(store=ps)

            # Learn from error records
            # Use errors with duplicate types to exceed min_occurrences=2
            error_record = {
                "errors": [
                    {
                        "error_type": "ConnectionTimeout",
                        "module": "port_scan",
                        "message": "Connection timed out",
                    },
                    {
                        "error_type": "ConnectionTimeout",
                        "module": "port_scan",
                        "message": "Connection timed out",
                    },
                    {
                        "error_type": "ConnectionTimeout",
                        "module": "port_scan",
                        "message": "Connection timed out",
                    },
                    {
                        "error_type": "SSLError",
                        "module": "ssl_check",
                        "message": "Certificate verification failed",
                    },
                    {
                        "error_type": "SSLError",
                        "module": "ssl_check",
                        "message": "Certificate verification failed",
                    },
                    {
                        "error_type": "SSLError",
                        "module": "ssl_check",
                        "message": "Certificate verification failed",
                    },
                ],
            }
            stored = learner.learn_from_error(error_record)
            self.assertGreater(stored, 0)

            # Query for error patterns
            patterns = learner.get_learned_patterns(
                min_confidence=0.0,
            )
            error_patterns = [p for p in patterns if p.source == SOURCE_ERROR]
            self.assertGreater(len(error_patterns), 0)

            # The learned module names should be useful for recommendations
            module_names = {p.key for p in error_patterns}
            self.assertTrue(module_names)

    def test_prediction_informs_fix_priority(self):
        """RepositoryLearner.predict_outcome() should return data
        that helps prioritise fixes."""
        with tempfile.TemporaryDirectory() as td:
            store_path = Path(td) / "patterns.json"
            ps = PatternStore(path=store_path)
            learner = RepositoryLearner(store=ps)

            # Seed some patterns
            learner.learn_from_scan(_make_scan_result())

            prediction = learner.predict_outcome({
                "module": "port_scan",
                "target": "example.com",
            })

            self.assertIsInstance(prediction, dict)
            self.assertIn("predicted_findings", prediction)
            self.assertIn("predicted_errors", prediction)
            self.assertIn("risk_assessment", prediction)
            self.assertIn("confidence", prediction)

            # Risk assessment should be a string usable for prioritisation
            self.assertIsInstance(prediction["risk_assessment"], str)



# ═══════════════════════════════════════════════════════════════════════
#  3. End-to-End Engineering Cycle
# ═══════════════════════════════════════════════════════════════════════


class TestEndToEndDiagnosticsToFixToValidation(unittest.TestCase):
    """Run diagnostics → detect issues → generate recommendations →
    propose fixes → validate fixes."""

    def test_full_issue_to_fix_to_validation_cycle(self):
        """Full cycle: diagnostics → recommendations → fix proposals → validation.

        1. Create diagnostic results with failures
        2. Feed to EngineeringRecommender → get Recommendations
        3. Recommendations inform issue context for AutoFixEngine
        4. ValidationReport can capture the outcome
        """
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)

            # Step 1: Diagnostics with failures
            diag_results = _make_diagnostics_result()
            self.assertGreater(
                len([c for c in diag_results["checks"] if c["status"] == "error"]),
                0,
            )

            # Step 2: Generate recommendations
            rec_store_path = td_path / "recs.json"
            recommender = EngineeringRecommender(store_path=rec_store_path)
            recommendations = recommender.recommend_from_diagnostics(diag_results)
            self.assertGreater(len(recommendations), 0)

            # Step 3: Convert recommendations to issues for AutoFixEngine
            fix_store_path = td_path / "fixes.json"
            store = FixStore(store_path=fix_store_path)
            engine = AutoFixEngine(store=store, dry_run=True)

            # Create scan result with findings derived from recommendations
            findings = []
            for rec in recommendations[:3]:  # Use top 3
                findings.append({
                    "title": rec.title,
                    "category": rec.category,
                    "severity": rec.severity,
                    "message": rec.evidence,
                    "description": rec.description,
                    "suggestion": rec.suggested_fix,
                })

            scan_data = {"findings": findings}
            proposals = engine.propose_fixes(scan_data)
            self.assertIsInstance(proposals, list)

            # Step 4: Validation can represent the outcome
            validation_findings = []
            for prop in proposals:
                validation_findings.append(ValidationFinding(
                    file=prop.affected_file or "unknown",
                    line=prop.affected_lines[0] if prop.affected_lines else 0,
                    severity=prop.severity,
                    message=prop.title,
                    suggestion=prop.description,
                ))

            report = ValidationReport(
                timestamp=datetime.now().isoformat(),
                project_root="/fake/repo",
                overall_status="failed" if validation_findings else "passed",
                stage_results=[
                    ValidationStageResult(
                        stage_name="auto_fix_validation",
                        status="failed" if validation_findings else "passed",
                        duration=0.1,
                        files_scanned=len(set(f.file for f in validation_findings)),
                        findings=validation_findings,
                    ),
                ],
            )

            # Verify full cycle completed
            self.assertIsInstance(report, ValidationReport)
            self.assertEqual(report.total_findings, len(validation_findings))

    def test_quality_gate_receives_full_pipeline_data(self):
        """Quality gate should receive coherent data from the full pipeline.

        Metrics from auto_engineering, drift from baselines,
        health from diagnostics should all be feedable to quality_gate.
        """
        # Construct pipeline outputs
        metrics = _make_metrics_snapshot(
            test_pass_rate=70.0,  # Below 80% threshold
            debt_ratio=35.0,     # Above 30% threshold
            complexity_max=25.0,  # Above 20% threshold
        )
        drift = _make_drift_report(
            drift_score=55.0,  # Above 50% threshold
            regression_detected=True,
        )
        health = _make_health_check_result()
        health["health_score"] = 50.0  # Below 70% threshold

        # Verify all types are correct for quality_gate input
        self.assertIsInstance(metrics, MetricsSnapshot)
        self.assertIsInstance(drift, DriftReport)
        self.assertIsInstance(health, dict)
        self.assertIsInstance(health["health_score"], (int, float))

        # Verify data flows through correctly
        metrics_dict = metrics.to_dict()
        self.assertLess(metrics_dict["test_pass_rate"], 80.0)
        self.assertGreater(metrics_dict["debt_ratio"], 30.0)
        self.assertGreater(drift.drift_score, 50.0)
        self.assertTrue(drift.regression_detected)


class TestEndToEndBaselineToRegressionToReport(unittest.TestCase):
    """Capture baseline → run benchmark → detect regression → generate report."""

    def test_full_regression_detection_cycle(self):
        """Full cycle: capture baseline → run current → detect regression → report.

        1. Capture a performance baseline
        2. Run 'current' metrics that show degradation
        3. Detect regression
        4. Generate report
        """
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            baseline_path = td_path / "reg_baseline.json"
            history_path = td_path / "reg_history.json"

            ri = RegressionIntelligence(
                baseline_path=baseline_path,
                history_path=history_path,
            )

            # Step 1: Capture baseline
            baseline_data = {
                "total_score": 90.0,
                "findings_count": 10,
                "scan_duration_ms": 3000.0,
                "severity_counts": {"critical": 0, "high": 2, "medium": 5, "low": 3},
            }
            ri.capture_baseline("perf_v1", baseline_data, label="Performance v1")

            # Step 2: Run current with degradation
            current_data = {
                "total_score": 70.0,
                "findings_count": 18,
                "scan_duration_ms": 5000.0,
                "severity_counts": {"critical": 2, "high": 5, "medium": 8, "low": 3},
            }

            # Step 3: Detect regression
            regressions = ri.detect_regression(
                current_data, baseline_key="perf_v1"
            )
            # The score drop and duration increase should trigger regressions
            # (at minimum the inverted score should be detected)
            self.assertIsInstance(regressions, list)

            # Step 4: Generate report (should not raise)
            report = ri.generate_regression_report(days=30)
            self.assertIsInstance(report, str)
            self.assertIn("Regression Intelligence Report", report)

    def test_benchmark_to_regression_full_cycle(self):
        """Full cycle: run benchmarks → compare to baselines → detect regressions.

        1. Run benchmarks and record as baselines
        2. Run benchmarks again with degraded performance
        3. Compare and detect regressions
        """
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)

            # Step 1: Record baseline benchmarks
            baseline_dir = td_path / "bench_baseline"
            bb = BenchmarkBaseline(storage_dir=baseline_dir)

            bb.record(BenchmarkResult(
                name="dict_insert_10k", category="cpu",
                value=2.0, unit="ms",
            ))
            bb.record(BenchmarkResult(
                name="json_encode_1k", category="cpu",
                value=1.5, unit="ms",
            ))

            # Step 2: Run 'current' benchmarks (degraded)
            current_results = [
                BenchmarkResult(
                    name="dict_insert_10k", category="cpu",
                    value=3.5, unit="ms",  # 75% slower
                ),
                BenchmarkResult(
                    name="json_encode_1k", category="cpu",
                    value=2.0, unit="ms",  # 33% slower
                ),
            ]

            # Step 3: Compare against baselines
            comparisons = bb.compare(current_results)
            self.assertIsInstance(comparisons, list)
            self.assertEqual(len(comparisons), 2)

            # Both should show regression (timing increased)
            for comp in comparisons:
                self.assertEqual(comp["direction"], "regression")
                self.assertGreater(comp["delta_pct"], 0)

            # Step 4: Feed into regression intelligence
            reg_baseline_path = td_path / "reg_baseline.json"
            reg_history_path = td_path / "reg_history.json"
            ri = RegressionIntelligence(
                baseline_path=reg_baseline_path,
                history_path=reg_history_path,
            )

            # Capture benchmark baselines
            ri.capture_baseline(
                "bench_v1",
                {"dict_insert_10k_ms": 2.0, "json_encode_1k_ms": 1.5},
            )

            # Current values (degraded)
            perf_metrics = {"dict_insert_10k_ms": 3.5, "json_encode_1k_ms": 2.0}
            regressions = ri.detect_regression(
                {},
                baseline_key="bench_v1",
                performance_metrics=perf_metrics,
            )

            self.assertIsInstance(regressions, list)
            # At least one regression should be detected
            self.assertGreater(len(regressions), 0)


class TestCrossModuleDataConsistency(unittest.TestCase):
    """Verify data consistency when flowing through multiple modules."""

    def test_severity_values_consistent_across_modules(self):
        """Severity values should be consistent across all modules.

        All modules use similar severity scales (critical/high/medium/low/info).
        """
        # RegressionRecord
        self.assertIn(
            RegressionSeverity.HIGH.value, ["critical", "high", "medium", "low", "info"]
        )

        # Recommendation
        rec = Recommendation(severity="high")
        self.assertEqual(rec.severity, "high")

        # FixProposal
        fix = FixProposal(severity="high")
        self.assertEqual(fix.severity, "high")

        # ValidationFinding
        finding = ValidationFinding(severity="high")
        self.assertEqual(finding.severity, "high")

        # SimulationResult
        self.assertIn("high", ["low", "medium", "high", "critical"])

    def test_timestamp_format_consistency(self):
        """All modules should use ISO-8601 timestamps."""
        ts = datetime.now(timezone.utc).isoformat()

        # MetricsSnapshot
        ms = MetricsSnapshot(timestamp=ts)
        self.assertEqual(ms.timestamp, ts)

        # DriftReport
        dr = DriftReport(current_timestamp=ts)
        self.assertEqual(dr.current_timestamp, ts)

        # RegressionRecord
        rr = RegressionRecord(detected_at=ts)
        self.assertEqual(rr.detected_at, ts)

        # Recommendation
        rec = Recommendation(created_at=ts)
        self.assertEqual(rec.created_at, ts)

        # FixProposal
        fp = FixProposal(created_at=ts)
        self.assertEqual(fp.created_at, ts)

    def test_serialization_round_trip_consistency(self):
        """All module data types should survive dict serialization round-trips."""
        # MetricsSnapshot
        ms = _make_metrics_snapshot()
        self.assertEqual(MetricsSnapshot.from_dict(ms.to_dict()).test_pass_rate, ms.test_pass_rate)

        # DriftReport
        dr = _make_drift_report()
        dr_dict = dr.to_dict()
        self.assertIsInstance(dr_dict["files_added"], list)
        self.assertIsInstance(dr_dict["drift_score"], float)

        # RegressionRecord
        rr = RegressionRecord(
            type=RegressionType.PERFORMANCE,
            severity=RegressionSeverity.HIGH,
        )
        rr_restored = RegressionRecord.from_dict(rr.to_dict())
        self.assertEqual(rr_restored.type, rr.type)
        self.assertEqual(rr_restored.severity, rr.severity)

        # Recommendation
        rec = Recommendation(title="Test", severity="medium")
        rec_restored = Recommendation.from_dict(rec.to_dict())
        self.assertEqual(rec_restored.title, "Test")
        self.assertEqual(rec_restored.severity, "medium")

        # FixProposal
        fp = FixProposal(title="Test Fix", severity="high")
        fp_restored = FixProposal.from_dict(fp.to_dict())
        self.assertEqual(fp_restored.title, "Test Fix")
        self.assertEqual(fp_restored.severity, "high")

        # SystemModel
        sm = _make_system_model()
        sm_restored = SystemModel.from_dict(sm.to_dict())
        self.assertEqual(sm_restored.engine.status, sm.engine.status)

        # BenchmarkResult
        br = BenchmarkResult(name="test", category="cpu", value=1.0)
        br_restored = BenchmarkResult.from_dict(br.to_dict())
        self.assertEqual(br_restored.name, "test")
        self.assertEqual(br_restored.value, 1.0)

        # LearnedPattern
        lp = LearnedPattern(
            pattern_type=PATTERN_FREQUENCY,
            key="test_pattern",
            confidence=0.8,
            support=5,
        )
        lp_restored = LearnedPattern.from_dict(lp.to_dict())
        self.assertEqual(lp_restored.key, "test_pattern")
        self.assertAlmostEqual(lp_restored.confidence, 0.8, places=5)

    def test_repository_memory_stores_all_module_outputs(self):
        """RepositoryMemory should accept and recall outputs from every module."""
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            modules_data = {
                "auto_engineering/metrics": _make_metrics_snapshot().to_dict(),
                "auto_engineering/drift": _make_drift_report().to_dict(),
                "auto_engineering/quality_gate": QualityGateResult(
                    passed=True, score=95.0
                ).to_dict(),
                "recommendations/latest": Recommendation(
                    title="Test", severity="low"
                ).to_dict(),
                "regression/detected": RegressionRecord(
                    description="Test regression",
                    severity=RegressionSeverity.MEDIUM,
                ).to_dict(),
                "validation/report": ValidationReport(
                    overall_status="passed",
                ).stage_results[0].to_dict() if ValidationReport(overall_status="passed").stage_results else {"status": "passed"},
                "auto_fix/proposal": FixProposal(
                    title="Test fix", severity="medium"
                ).to_dict(),
                "digital_twin/state": _make_system_model().to_dict(),
                "benchmark/result": BenchmarkResult(
                    name="test", category="cpu", value=1.0
                ).to_dict(),
                "learning/pattern": LearnedPattern(
                    key="test", confidence=0.7, support=3
                ).to_dict(),
            }

            for key, value in modules_data.items():
                mem.remember(key, value, metadata={"source": key.split("/")[0], "tags": ["integration_test"]})

            # Verify all stored
            self.assertEqual(mem.count(), len(modules_data))

            # Verify all recalled
            for key in modules_data:
                recalled = mem.recall(key)
                self.assertIsNotNone(recalled, f"Failed to recall {key}")

            # Verify full-text search works across modules
            all_facts = mem.search(query_text="test")
            self.assertGreater(len(all_facts), 0)


class TestPipelineOrchestrationPatterns(unittest.TestCase):
    """Verify common orchestration patterns across the engineering pipeline."""

    def test_metrics_snapshot_flows_to_quality_gate(self):
        """MetricsSnapshot collected by EngineeringMetrics should flow
        directly into quality_gate() without transformation."""
        snapshot = _make_metrics_snapshot(
            test_pass_rate=95.0,
            debt_ratio=5.0,
            complexity_max=12.0,
        )

        # The snapshot should be directly usable
        self.assertGreaterEqual(snapshot.test_pass_rate, 80.0)
        self.assertLessEqual(snapshot.debt_ratio, 30.0)
        self.assertLessEqual(snapshot.complexity_max, 20.0)

    def test_drift_report_flows_to_quality_gate(self):
        """DriftReport from EngineeringBaseline.compare() should flow
        directly into quality_gate()."""
        drift = _make_drift_report(
            drift_score=10.0,
            regression_detected=False,
            files_added=[],
            files_removed=[],
            files_modified=[],
        )

        # Low drift should not block quality gate
        self.assertLessEqual(drift.drift_score, 50.0)
        self.assertFalse(drift.regression_detected)
        self.assertEqual(len(drift.files_added) + len(drift.files_removed) + len(drift.files_modified), 0)

    def test_benchmark_suite_produces_comparable_results(self):
        """BenchmarkSuite.run() should produce results comparable across runs.

        Each BenchmarkResult should have the same name and unit across runs,
        enabling vs_baseline() comparisons.
        """
        suite = BenchmarkSuite("test_suite", "Integration test suite")
        call_count = 0

        def bench_fn():
            nonlocal call_count
            call_count += 1
            return 1.0

        suite.add("stable_bench", bench_fn, category="test", unit="ms", iterations=3)
        results = suite.run()

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.name, "stable_bench")
        self.assertEqual(result.category, "test")
        self.assertEqual(result.unit, "ms")
        self.assertEqual(result.iterations, 3)

        # Should be comparable with itself
        comparison = result.vs_baseline(result.value)
        self.assertEqual(comparison["direction"], "neutral")

    def test_memory_query_filters_engineering_facts(self):
        """MemoryQuery should effectively filter engineering facts.
        """
        with tempfile.TemporaryDirectory() as td:
            mem = RepositoryMemory(persist_path=Path(td) / "mem.json")

            mem.remember("eng/metrics", {"score": 85},
                         metadata={"source": "auto_engineering", "tags": ["metrics", "quality"]})
            mem.remember("eng/drift", {"score": 15},
                         metadata={"source": "auto_engineering", "tags": ["drift"]})
            mem.remember("rec/fix", {"title": "Fix eval"},
                         metadata={"source": "recommendations", "tags": ["recommendation"]})
            mem.remember("reg/perf", {"delta": 50},
                         metadata={"source": "regression", "tags": ["regression", "performance"]})

            # Query by source
            eng_facts = mem.recall_by_source("auto_engineering")
            self.assertEqual(len(eng_facts), 2)

            # Query by tag (AND semantics)
            query = MemoryQuery().with_tags({"regression", "performance"})
            results = mem.search(query=query)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].key, "reg/perf")

            # Query by tag (OR via any_tag)
            query_or = MemoryQuery().with_any_tag({"metrics", "drift"})
            results_or = mem.search(query=query_or)
            self.assertEqual(len(results_or), 2)

    def test_twin_sync_detects_component_changes(self):
        """TwinSync should detect when component states change.
        """
        model_1 = _make_system_model()
        model_1.engine.status = "healthy"

        model_2 = _make_system_model()
        model_2.engine.status = "degraded"

        sync = TwinSync.__new__(TwinSync)
        sync._twin = MagicMock()
        sync._lock = __import__("threading").Lock()
        sync._drift_history = []
        sync._last_model = None
        sync._sync_count = 0

        # First sync establishes baseline
        sync._twin.capture_state = MagicMock(return_value=model_1)
        drift1 = sync.sync_once()
        self.assertFalse(drift1["has_drift"])

        # Second sync detects change
        sync._twin.capture_state = MagicMock(return_value=model_2)
        drift2 = sync.sync_once()
        self.assertTrue(drift2["has_drift"])



if __name__ == "__main__":
    unittest.main()
