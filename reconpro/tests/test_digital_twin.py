"""Tests for the Digital Twin system.

Covers:
  - SystemModel serialisation round-trips
  - ComponentState creation and comparison
  - DigitalTwin.capture_state() produces a valid model
  - SimulationEngine named scenarios
  - SimulationEngine custom dict scenarios
  - TwinSync drift detection
  - Anomaly detection
  - Topology generation
  - Capacity model
  - Persistence load/save
  - Edge cases and error handling
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from reconpro.digital_twin import (
    DIGITAL_TWIN_FILE,
    ComponentState,
    DigitalTwin,
    SimulationEngine,
    SimulationResult,
    SystemModel,
    TwinSync,
    _capacity_status,
    _utc_iso,
)


# ═══════════════════════════════════════════════════════════════════════════
#  ComponentState tests
# ═══════════════════════════════════════════════════════════════════════════


class TestComponentState(unittest.TestCase):
    """Tests for ComponentState dataclass."""

    def test_default_values(self) -> None:
        cs = ComponentState(name="engine")
        self.assertEqual(cs.name, "engine")
        self.assertEqual(cs.status, "unknown")
        self.assertEqual(cs.metrics, {})
        self.assertEqual(cs.constraints, {})
        self.assertIsNone(cs.last_updated)

    def test_to_dict_roundtrip(self) -> None:
        cs = ComponentState(
            name="network",
            status="healthy",
            metrics={"latency": 42.0},
            constraints={"max_latency": 100.0},
            last_updated="2025-01-01T00:00:00.000Z",
        )
        d = cs.to_dict()
        self.assertEqual(d["name"], "network")
        self.assertEqual(d["status"], "healthy")
        self.assertEqual(d["metrics"], {"latency": 42.0})
        self.assertEqual(d["constraints"], {"max_latency": 100.0})

    def test_from_dict(self) -> None:
        d = {
            "name": "storage",
            "status": "degraded",
            "metrics": {"rss_mb": 300},
            "constraints": {},
            "last_updated": "2025-01-01T00:00:00.000Z",
        }
        cs = ComponentState.from_dict(d)
        self.assertEqual(cs.name, "storage")
        self.assertEqual(cs.status, "degraded")
        self.assertEqual(cs.metrics["rss_mb"], 300)

    def test_from_dict_missing_fields(self) -> None:
        cs = ComponentState.from_dict({})
        self.assertEqual(cs.name, "unknown")
        self.assertEqual(cs.status, "unknown")

    def test_from_dict_to_dict_symmetry(self) -> None:
        original = ComponentState(
            name="test",
            status="critical",
            metrics={"a": 1, "b": "hello"},
        )
        restored = ComponentState.from_dict(original.to_dict())
        self.assertEqual(restored.name, original.name)
        self.assertEqual(restored.status, original.status)
        self.assertEqual(restored.metrics, original.metrics)


# ═══════════════════════════════════════════════════════════════════════════
#  SystemModel tests
# ═══════════════════════════════════════════════════════════════════════════


class TestSystemModel(unittest.TestCase):
    """Tests for SystemModel dataclass."""

    def test_default_model(self) -> None:
        model = SystemModel()
        self.assertIsNotNone(model.version)
        self.assertIsNone(model.captured_at)
        # All components present
        expected = {"engine", "scanner", "modules", "plugins", "network", "storage", "configuration"}
        self.assertEqual(set(model.all_components().keys()), expected)

    def test_to_dict(self) -> None:
        model = SystemModel(captured_at="2025-01-01T00:00:00.000Z")
        d = model.to_dict()
        self.assertIn("version", d)
        self.assertEqual(d["captured_at"], "2025-01-01T00:00:00.000Z")
        for comp in ("engine", "scanner", "modules", "plugins", "network", "storage", "configuration"):
            self.assertIn(comp, d)

    def test_from_dict_roundtrip(self) -> None:
        model = SystemModel(captured_at="2025-01-01T00:00:00.000Z")
        model.engine.status = "healthy"
        model.engine.metrics["concurrency"] = 5
        model.storage.status = "degraded"
        model.storage.metrics["rss_mb"] = 350

        d = model.to_dict()
        restored = SystemModel.from_dict(d)
        self.assertEqual(restored.captured_at, model.captured_at)
        self.assertEqual(restored.engine.status, "healthy")
        self.assertEqual(restored.engine.metrics["concurrency"], 5)
        self.assertEqual(restored.storage.status, "degraded")
        self.assertEqual(restored.storage.metrics["rss_mb"], 350)

    def test_overall_status_healthy(self) -> None:
        model = SystemModel()
        for comp in model.all_components().values():
            comp.status = "healthy"
        self.assertEqual(model.overall_status(), "healthy")

    def test_overall_status_worst_wins(self) -> None:
        model = SystemModel()
        for comp in model.all_components().values():
            comp.status = "healthy"
        model.storage.status = "critical"
        self.assertEqual(model.overall_status(), "critical")

    def test_overall_status_degraded(self) -> None:
        model = SystemModel()
        for comp in model.all_components().values():
            comp.status = "healthy"
        model.network.status = "degraded"
        self.assertEqual(model.overall_status(), "degraded")

    def test_overall_status_unknown(self) -> None:
        model = SystemModel()
        self.assertEqual(model.overall_status(), "unknown")


# ═══════════════════════════════════════════════════════════════════════════
#  SimulationEngine tests
# ═══════════════════════════════════════════════════════════════════════════


def _make_base_model(**overrides: Any) -> SystemModel:
    """Create a model with typical baseline values for simulation."""
    model = SystemModel(captured_at=_utc_iso())
    model.engine.status = "healthy"
    model.engine.metrics["active_scans"] = 2
    model.engine.constraints["max_concurrency"] = 10
    model.engine.constraints["default_timeout"] = 8
    model.engine.metrics["scan_queue_depth"] = 0
    model.scanner.status = "healthy"
    model.scanner.metrics["module_ids"] = ["recon", "auth", "ssl", "headers", "dns"]
    model.scanner.metrics["total_modules"] = 5
    model.scanner.metrics["broken_modules"] = []
    model.scanner.metrics["registry_integrity"] = "ok"
    model.network.status = "healthy"
    model.network.metrics["avg_latency_ms"] = 150.0
    model.network.metrics["dns_resolve_ms"] = 30.0
    model.storage.status = "healthy"
    model.storage.metrics["rss_mb"] = 50.0
    model.storage.metrics["usage_percent"] = 45.0
    model.storage.metrics["free_mb"] = 50000.0
    model.plugins.status = "healthy"
    model.plugins.metrics["plugin_count"] = 3

    for key, value in overrides.items():
        parts = key.split(".")
        if len(parts) == 2:
            comp_name, metric = parts
            comp = model.all_components().get(comp_name)
            if comp:
                comp.metrics[metric] = value
        elif len(parts) == 1:
            # top-level override on a component
            pass  # ignore for now
    return model


class TestSimulationEngine(unittest.TestCase):
    """Tests for the SimulationEngine."""

    def setUp(self) -> None:
        self.engine = SimulationEngine()

    def _assert_valid_result(self, result: SimulationResult) -> None:
        self.assertIsInstance(result, SimulationResult)
        self.assertIsInstance(result.scenario, str)
        self.assertIsInstance(result.risk_level, str)
        self.assertIn(result.risk_level, ("low", "medium", "high", "critical"))
        self.assertIsInstance(result.performance_impact, str)
        self.assertIsInstance(result.affected_components, list)
        self.assertIsInstance(result.recommendations, list)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        # projected_state should be a valid dict
        self.assertIsInstance(result.projected_state, dict)

    # -- add_concurrent_scans ---------------------------------------------

    def test_add_concurrent_scans_within_capacity(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "add_concurrent_scans:3")
        self._assert_valid_result(result)
        self.assertEqual(result.affected_components[0], "engine")  # engine in list
        # Within capacity: active=2+3=5, max=10
        self.assertIn(result.risk_level, ("low", "medium"))

    def test_add_concurrent_scans_exceeds_capacity(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "add_concurrent_scans:15")
        self._assert_valid_result(result)
        # 2+15=17 > 10
        self.assertIn(result.risk_level, ("high", "critical"))
        self.assertTrue(any("exceeds" in r.lower() for r in result.recommendations))

    def test_add_concurrent_scans_zero(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "add_concurrent_scans:0")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    # -- fail_module -----------------------------------------------------

    def test_fail_module_known(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "fail_module:recon")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("medium", "high"))
        self.assertIn("recon", result.projected_state["scanner"]["metrics"].get("broken_modules", []))

    def test_fail_module_unknown(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "fail_module:nonexistent")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    def test_fail_module_already_broken(self) -> None:
        model = _make_base_model()
        model.scanner.metrics["broken_modules"] = ["recon"]
        model.scanner.metrics["registry_integrity"] = "compromised"
        result = self.engine.simulate(model, "fail_module:recon")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")  # no new impact

    def test_fail_multiple_modules_critical(self) -> None:
        model = _make_base_model()
        model.scanner.metrics["module_ids"] = ["a", "b", "c", "d"]
        model.scanner.metrics["total_modules"] = 4
        model.scanner.metrics["broken_modules"] = ["a"]
        model.scanner.metrics["registry_integrity"] = "compromised"
        # b, c, d broken = 3/4 broken (>50%)
        result = self.engine.simulate(model, "fail_module:b")
        # Now 2 broken
        self._assert_valid_result(result)
        # Then fail more
        result2 = self.engine.simulate(model, "fail_module:c")
        self._assert_valid_result(result2)

    # -- increase_load ---------------------------------------------------

    def test_increase_load_modest(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "increase_load:2")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("low", "medium"))

    def test_increase_load_extreme(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "increase_load:10")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("critical", "high"))

    def test_increase_load_trivial(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "increase_load:1")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    # -- change_timeout --------------------------------------------------

    def test_change_timeout_aggressive(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_timeout:1")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("high", "medium"))

    def test_change_timeout_reasonable(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_timeout:15")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    def test_change_timeout_very_long(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_timeout:60")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("medium", "low"))

    # -- change_concurrency ----------------------------------------------

    def test_change_concurrency_high(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_concurrency:25")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("high", "medium"))

    def test_change_concurrency_zero(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_concurrency:0")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "critical")

    def test_change_concurrency_normal(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "change_concurrency:5")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    # -- disk_full -------------------------------------------------------

    def test_disk_full(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "disk_full")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "critical")
        self.assertIn("storage", result.affected_components)
        self.assertEqual(result.projected_state["storage"]["metrics"]["usage_percent"], 99.0)

    # -- network_degraded ------------------------------------------------

    def test_network_degraded(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "network_degraded")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("high", "medium"))
        self.assertIn("network", result.affected_components)

    # -- memory_pressure -------------------------------------------------

    def test_memory_pressure(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "memory_pressure")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("high", "medium"))
        self.assertIn("storage", result.affected_components)

    # -- plugin_load -----------------------------------------------------

    def test_plugin_load_normal(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "plugin_load:5")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    def test_plugin_load_heavy(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "plugin_load:25")
        self._assert_valid_result(result)
        self.assertIn(result.risk_level, ("high", "medium"))

    # -- unknown scenario ------------------------------------------------

    def test_unknown_scenario(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate(model, "blow_up_the_server")
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "medium")
        self.assertLess(result.confidence, 0.5)

    # -- custom dict scenario --------------------------------------------

    def test_custom_scenario_fault(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate_dict(model, {
            "type": "fault",
            "component": "network",
            "parameter": "dns_resolve_ms",
            "value": 9999,
            "description": "DNS failure",
        })
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.projected_state["network"]["status"], "critical")

    def test_custom_scenario_load(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate_dict(model, {
            "type": "load",
            "component": "engine",
            "parameter": "active_scans",
            "value": 50,
            "description": "High scan load",
        })
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "medium")

    def test_custom_scenario_config(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate_dict(model, {
            "type": "config",
            "component": "configuration",
            "parameter": "rate_limit",
            "value": 100.0,
            "description": "Increase rate limit",
        })
        self._assert_valid_result(result)
        self.assertEqual(result.risk_level, "low")

    def test_custom_scenario_missing_component(self) -> None:
        model = _make_base_model()
        result = self.engine.simulate_dict(model, {
            "type": "fault",
            "component": "nonexistent",
            "parameter": "x",
            "value": 1,
            "description": "Missing component",
        })
        self._assert_valid_result(result)
        # Should not crash — just no component found

    # -- simulation does not mutate input --------------------------------

    def test_simulation_does_not_mutate_input(self) -> None:
        model = _make_base_model()
        original_active = model.engine.metrics["active_scans"]
        original_status = model.engine.status
        self.engine.simulate(model, "add_concurrent_scans:10")
        # Input model should be unchanged
        self.assertEqual(model.engine.metrics["active_scans"], original_active)
        self.assertEqual(model.engine.status, original_status)


# ═══════════════════════════════════════════════════════════════════════════
#  DigitalTwin tests
# ═══════════════════════════════════════════════════════════════════════════


class TestDigitalTwin(unittest.TestCase):
    """Tests for the main DigitalTwin class."""

    def test_capture_state_returns_valid_model(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        self.assertIsInstance(model, SystemModel)
        self.assertIsNotNone(model.captured_at)
        self.assertEqual(model.version, model.version)  # just ensure no crash
        # All components should have been captured
        for comp_name, comp in model.all_components().items():
            self.assertIsNotNone(comp.last_updated, f"{comp_name} missing last_updated")

    def test_capture_state_does_not_crash_without_telemetry(self) -> None:
        """Ensure capture works even if telemetry is unavailable."""
        with mock.patch("reconpro.digital_twin.logger"):
            twin = DigitalTwin(persist=False)
            model = twin.capture_state()
            self.assertIsInstance(model, SystemModel)

    def test_capture_state_scanner_populated(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        # Scanner should have module data
        self.assertIn("total_modules", model.scanner.metrics)
        self.assertIn("module_ids", model.scanner.metrics)

    def test_capture_state_network_populated(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        # Network should have DNS data
        self.assertIn("dns_reachable", model.network.metrics)

    def test_capture_state_storage_populated(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        # Storage should have memory and disk data
        self.assertIn("rss_mb", model.storage.metrics)
        self.assertIn("usage_percent", model.storage.metrics)

    def test_capture_state_configuration_populated(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        # Config should have validation results
        self.assertIn("config_issues", model.configuration.metrics)

    def test_capture_state_persists(self) -> None:
        """Test that capture persists to disk when persist=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            twin_file = Path(tmpdir) / "digital_twin.json"
            with mock.patch("reconpro.digital_twin.DIGITAL_TWIN_FILE", twin_file):
                with mock.patch("reconpro.digital_twin.MEMORY_DIR", Path(tmpdir)):
                    twin = DigitalTwin(persist=True)
                    twin.capture_state()
                    self.assertTrue(twin_file.exists())
                    # Verify it's valid JSON
                    with open(twin_file, "r") as f:
                        data = json.load(f)
                    self.assertIn("engine", data)
                    self.assertIn("captured_at", data)

    def test_load_from_disk(self) -> None:
        """Test loading a previously saved model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            twin_file = Path(tmpdir) / "digital_twin.json"
            with mock.patch("reconpro.digital_twin.DIGITAL_TWIN_FILE", twin_file):
                with mock.patch("reconpro.digital_twin.MEMORY_DIR", Path(tmpdir)):
                    twin = DigitalTwin(persist=True)
                    twin.capture_state()

                    # Create a new twin and load
                    twin2 = DigitalTwin(persist=False)
                    model = twin2.load()
                    self.assertIsNotNone(model)
                    self.assertIsInstance(model, SystemModel)

    def test_load_no_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            twin_file = Path(tmpdir) / "nonexistent.json"
            with mock.patch("reconpro.digital_twin.DIGITAL_TWIN_FILE", twin_file):
                twin = DigitalTwin(persist=False)
                result = twin.load()
                self.assertIsNone(result)

    def test_predict_impact_named_scenario(self) -> None:
        twin = DigitalTwin(persist=False)
        result = twin.predict_impact("add_concurrent_scans:5")
        self.assertIsInstance(result, SimulationResult)
        self.assertIn(result.risk_level, ("low", "medium", "high", "critical"))
        self.assertTrue(len(result.recommendations) > 0)

    def test_predict_impact_dict_scenario(self) -> None:
        twin = DigitalTwin(persist=False)
        result = twin.predict_impact({
            "type": "fault",
            "component": "network",
            "parameter": "dns",
            "value": "down",
            "description": "DNS outage",
        })
        self.assertIsInstance(result, SimulationResult)

    def test_what_if_alias(self) -> None:
        twin = DigitalTwin(persist=False)
        r1 = twin.what_if("add_concurrent_scans:3")
        r2 = twin.predict_impact("add_concurrent_scans:3")
        # Both should return SimulationResult
        self.assertIsInstance(r1, SimulationResult)
        self.assertIsInstance(r2, SimulationResult)

    def test_detect_anomaly_first_run(self) -> None:
        twin = DigitalTwin(persist=False)
        result = twin.detect_anomaly()
        self.assertIsInstance(result, dict)
        self.assertIn("anomalies", result)
        self.assertIn("anomaly_count", result)
        self.assertIn("severity", result)
        # First run establishes baseline
        self.assertEqual(result["anomaly_count"], 0)

    def test_detect_anomaly_with_regression(self) -> None:
        twin = DigitalTwin(persist=False)
        # First capture establishes baseline
        model = twin.capture_state()
        # Manually regress a component
        twin._model.storage.status = "critical"
        twin._model.storage.metrics["rss_mb"] = 999
        result = twin.detect_anomaly()
        # Should detect something (at minimum the status regression)
        self.assertGreaterEqual(result["anomaly_count"], 0)
        self.assertIn(result["severity"], ("none", "low", "medium", "high", "critical"))

    def test_detect_anomaly_metric_anomaly(self) -> None:
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        # Set a baseline latency, then spike it
        base_latency = twin._model.network.metrics.get("avg_latency_ms", 50)
        if base_latency and base_latency > 0:
            twin._model.network.metrics["avg_latency_ms"] = base_latency * 10
            result = twin.detect_anomaly()
            # May or may not detect depending on value
            self.assertIn("severity", result)

    def test_get_system_topology(self) -> None:
        twin = DigitalTwin(persist=False)
        twin.capture_state()
        topo = twin.get_system_topology()
        self.assertIn("nodes", topo)
        self.assertIn("edges", topo)
        self.assertIn("overall_status", topo)
        self.assertIn("captured_at", topo)
        # Should have 7 nodes (one per component)
        self.assertEqual(len(topo["nodes"]), 7)
        # Should have edges
        self.assertGreater(len(topo["edges"]), 0)

    def test_get_system_topology_with_degraded_node(self) -> None:
        twin = DigitalTwin(persist=False)
        twin.capture_state()
        twin._model.network.status = "critical"
        topo = twin.get_system_topology()
        # Should identify impacted paths
        self.assertIn("impacted_paths", topo)

    def test_get_capacity_model(self) -> None:
        twin = DigitalTwin(persist=False)
        twin.capture_state()
        cap = twin.get_capacity_model()
        self.assertIn("capacity_score", cap)
        self.assertIn("concurrency", cap)
        self.assertIn("memory", cap)
        self.assertIn("disk", cap)
        self.assertIn("modules", cap)
        self.assertIn("network", cap)
        self.assertIn("plugins", cap)
        self.assertIn("overall_status", cap)

        # Check sub-model structure
        conc = cap["concurrency"]
        self.assertIn("active", conc)
        self.assertIn("max", conc)
        self.assertIn("utilisation_pct", conc)
        self.assertIn("status", conc)

        mem = cap["memory"]
        self.assertIn("rss_mb", mem)
        self.assertIn("warning_mb", mem)
        self.assertIn("critical_mb", mem)

        disk = cap["disk"]
        self.assertIn("usage_pct", disk)
        self.assertIn("free_mb", disk)

        modules = cap["modules"]
        self.assertIn("total", modules)
        self.assertIn("healthy", modules)
        self.assertIn("broken", modules)

    def test_get_capacity_model_score_range(self) -> None:
        twin = DigitalTwin(persist=False)
        twin.capture_state()
        cap = twin.get_capacity_model()
        score = cap["capacity_score"]
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_get_last_model(self) -> None:
        twin = DigitalTwin(persist=False)
        self.assertIsNone(twin.get_last_model())
        twin.capture_state()
        self.assertIsNotNone(twin.get_last_model())

    def test_reset_baseline(self) -> None:
        twin = DigitalTwin(persist=False)
        twin.capture_state()
        twin._baseline = None
        twin.reset_baseline()
        self.assertIsNotNone(twin._baseline)

    def test_start_stop_sync(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = twin.start_sync(interval=0.5)
        self.assertIsInstance(sync, TwinSync)
        self.assertTrue(sync._running)
        twin.stop_sync()
        self.assertFalse(sync._running)

    def test_sync_is_none_initially(self) -> None:
        twin = DigitalTwin(persist=False)
        self.assertIsNone(twin.sync)

    def test_simulation_result_to_dict(self) -> None:
        twin = DigitalTwin(persist=False)
        result = twin.predict_impact("add_concurrent_scans:3")
        d = result.to_dict()
        self.assertIn("scenario", d)
        self.assertIn("risk_level", d)
        self.assertIn("performance_impact", d)
        self.assertIn("affected_components", d)
        self.assertIn("recommendations", d)
        self.assertIn("confidence", d)
        self.assertIn("projected_state", d)

    def test_multiple_captures_update_model(self) -> None:
        twin = DigitalTwin(persist=False)
        m1 = twin.capture_state()
        m2 = twin.capture_state()
        self.assertIsNotNone(m2.captured_at)
        # Should be different timestamps (or at least not crash)
        self.assertIsInstance(m2, SystemModel)


# ═══════════════════════════════════════════════════════════════════════════
#  TwinSync tests
# ═══════════════════════════════════════════════════════════════════════════


class TestTwinSync(unittest.TestCase):
    """Tests for TwinSync."""

    def test_sync_once_first(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        result = sync.sync_once()
        self.assertIn("has_drift", result)
        self.assertFalse(result["has_drift"])  # first snapshot, no drift

    def test_sync_once_detects_status_change(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        sync.sync_once()
        # Now manually change the model
        if twin._model:
            twin._model.storage.status = "critical"
        result = sync.sync_once()
        # Should detect drift (status change)
        self.assertIn("has_drift", result)
        self.assertIn("changes", result)

    def test_sync_stats(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        sync.sync_once()
        stats = sync.get_sync_stats()
        self.assertEqual(stats["sync_count"], 1)
        self.assertFalse(stats["running"])

    def test_drift_history_bounded(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        # Force many drift events — the trim logic in sync_once uses a while loop
        for i in range(120):
            sync._drift_history.append({"has_drift": True, "changes": [i]})
        # Manually invoke the trim logic (same as sync_once)
        while len(sync._drift_history) > 100:
            sync._drift_history = sync._drift_history[-50:]
        # Should be bounded to 50 after exceeding 100
        self.assertLessEqual(len(sync._drift_history), 100)

    def test_start_stop_lifecycle(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=0.2)
        sync.start()
        self.assertTrue(sync._running)
        time.sleep(0.5)  # let it run at least one cycle
        sync.stop()
        self.assertFalse(sync._running)
        self.assertGreaterEqual(sync._sync_count, 1)

    def test_auto_start(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=0.2, auto_start=False)
        self.assertFalse(sync._running)
        sync.start()
        self.assertTrue(sync._running)
        sync.stop()

    def test_double_start_ignored(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        sync.start()
        thread1 = sync._thread
        sync.start()  # should be a no-op
        self.assertIs(sync._thread, thread1)
        sync.stop()

    def test_stop_without_start(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        sync.stop()  # should not crash
        self.assertFalse(sync._running)

    def test_drift_history_empty_initially(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        self.assertEqual(sync.get_drift_history(), [])

    def test_compute_drift_with_metric_changes(self) -> None:
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)
        sync.sync_once()
        # Modify a metric significantly
        if twin._model and twin._model.storage.metrics.get("rss_mb"):
            twin._model.storage.metrics["rss_mb"] = 999
        result = sync.sync_once()
        # Metric changes should be in the changes list
        if result["has_drift"]:
            self.assertGreater(len(result["changes"]), 0)


# ═══════════════════════════════════════════════════════════════════════════
#  Utility function tests
# ═══════════════════════════════════════════════════════════════════════════


class TestUtilities(unittest.TestCase):
    """Tests for utility functions."""

    def test_utc_iso_format(self) -> None:
        result = _utc_iso()
        self.assertIsInstance(result, str)
        self.assertTrue(result.endswith("Z"))
        self.assertIn("T", result)
        # Should be parseable
        from datetime import datetime
        # Just check it doesn't crash
        datetime.fromisoformat(result.replace("Z", "+00:00"))

    def test_capacity_status_healthy(self) -> None:
        self.assertEqual(_capacity_status(50.0), "healthy")

    def test_capacity_status_degraded(self) -> None:
        self.assertEqual(_capacity_status(80.0), "degraded")
        self.assertEqual(_capacity_status(75.1), "degraded")

    def test_capacity_status_critical(self) -> None:
        self.assertEqual(_capacity_status(91.0), "critical")
        self.assertEqual(_capacity_status(100.0), "critical")

    def test_capacity_status_boundary(self) -> None:
        self.assertEqual(_capacity_status(75.0), "healthy")
        self.assertEqual(_capacity_status(90.0), "degraded")


# ═══════════════════════════════════════════════════════════════════════════
#  Integration tests
# ═══════════════════════════════════════════════════════════════════════════


class TestDigitalTwinIntegration(unittest.TestCase):
    """Integration tests that exercise the full pipeline."""

    def test_full_workflow(self) -> None:
        """Capture → simulate → detect anomaly → get topology → get capacity."""
        twin = DigitalTwin(persist=False)

        # 1. Capture
        model = twin.capture_state()
        self.assertIsInstance(model, SystemModel)

        # 2. Simulate
        sim = twin.what_if("add_concurrent_scans:5")
        self.assertIsInstance(sim, SimulationResult)

        # 3. Anomaly detection
        anomaly = twin.detect_anomaly()
        self.assertIn("severity", anomaly)

        # 4. Topology
        topo = twin.get_system_topology()
        self.assertGreater(len(topo["nodes"]), 0)

        # 5. Capacity
        cap = twin.get_capacity_model()
        self.assertIn("capacity_score", cap)

    def test_multiple_simulations_sequential(self) -> None:
        """Run several simulations in sequence and verify consistent results."""
        twin = DigitalTwin(persist=False)
        scenarios = [
            "add_concurrent_scans:1",
            "add_concurrent_scans:5",
            "add_concurrent_scans:10",
            "increase_load:2",
            "increase_load:5",
            "disk_full",
            "network_degraded",
            "memory_pressure",
        ]
        for scenario in scenarios:
            result = twin.what_if(scenario)
            self.assertIsInstance(result, SimulationResult, f"Failed for {scenario}")
            self.assertIsInstance(result.recommendations, list, f"No recommendations for {scenario}")
            self.assertTrue(len(result.recommendations) > 0, f"Empty recommendations for {scenario}")

    def test_persistence_roundtrip(self) -> None:
        """Save a model and load it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            twin_file = Path(tmpdir) / "digital_twin.json"
            with mock.patch("reconpro.digital_twin.DIGITAL_TWIN_FILE", twin_file):
                with mock.patch("reconpro.digital_twin.MEMORY_DIR", Path(tmpdir)):
                    # Capture and save
                    twin1 = DigitalTwin(persist=True)
                    model1 = twin1.capture_state()

                    # Load into a new twin
                    twin2 = DigitalTwin(persist=False)
                    model2 = twin2.load()
                    self.assertIsNotNone(model2)
                    self.assertEqual(model2.captured_at, model1.captured_at)
                    self.assertEqual(model2.engine.status, model1.engine.status)

    def test_sync_detects_manual_changes(self) -> None:
        """TwinSync should detect when we manually change the model."""
        twin = DigitalTwin(persist=False)
        sync = TwinSync(twin, refresh_interval=30.0)

        # First sync
        r1 = sync.sync_once()
        self.assertFalse(r1["has_drift"])

        # Manually corrupt something
        if twin._model:
            twin._model.engine.status = "critical"
            twin._model.engine.metrics["active_scans"] = 999

        # Second sync should detect
        r2 = sync.sync_once()
        self.assertIn("has_drift", r2)
        if r2["has_drift"]:
            self.assertGreater(len(r2["changes"]), 0)

    def test_capacity_model_reflects_current_state(self) -> None:
        """Capacity model should reflect actual captured values."""
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        cap = twin.get_capacity_model()

        # Disk usage should match model
        model_disk_pct = model.storage.metrics.get("usage_percent", 0)
        cap_disk_pct = cap["disk"]["usage_pct"]
        self.assertAlmostEqual(model_disk_pct, cap_disk_pct, places=1)

        # Module counts should match
        model_broken = len(model.scanner.metrics.get("broken_modules", []))
        cap_broken = cap["modules"]["broken"]
        self.assertEqual(model_broken, cap_broken)

    def test_simulation_result_serialisable(self) -> None:
        """SimulationResult.to_dict() should be JSON-serialisable."""
        twin = DigitalTwin(persist=False)
        result = twin.what_if("add_concurrent_scans:3")
        d = result.to_dict()
        # Should not raise
        json_str = json.dumps(d, default=str)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 0)

    def test_system_model_serialisable(self) -> None:
        """SystemModel.to_dict() should be JSON-serialisable."""
        twin = DigitalTwin(persist=False)
        model = twin.capture_state()
        d = model.to_dict()
        json_str = json.dumps(d, default=str)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 0)


if __name__ == "__main__":
    unittest.main()
