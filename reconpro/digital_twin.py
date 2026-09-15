"""ReconPro v11 — Digital Twin System.

Provides a virtual model of the running ReconPro runtime for meta-level
reasoning about system state, capacity, risk, and hypothetical scenarios.

Components
──────────
    SystemModel          – dataclass representing the full system state
    DigitalTwin          – main facade: snapshot, predict, detect anomalies
    SimulationEngine     – run what-if scenarios without touching the real system
    TwinSync             – keep the twin in sync with the live system

Zero external dependencies. Pure Python. Thread-safe.
JSON persistence at RECONPRO_HOME/memory/digital_twin.json.
"""

from __future__ import annotations

import copy
import json
import logging
import math
import os
import shutil
import socket
import ssl
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIMEOUT,
    MEMORY_DIR,
    PLUGIN_DIR,
    RECONPRO_HOME,
    SCAN_HISTORY_DIR,
    __version__,
)

logger = logging.getLogger(__name__)

# ── Persistence path ─────────────────────────────────────────────────────
DIGITAL_TWIN_FILE: Path = MEMORY_DIR / "digital_twin.json"

# ── Capacity baselines (heuristic defaults) ─────────────────────────────
# These are used when we cannot measure a value from the live system.
_MEMORY_WARNING_MB: float = 200.0
_MEMORY_CRITICAL_MB: float = 400.0
_DISK_WARNING_PCT: float = 75.0
_DISK_CRITICAL_PCT: float = 90.0
_SCAN_LATENCY_BASELINE_MS: float = 3000.0  # expected ms per-module
_CONNECTION_LATENCY_BASELINE_MS: float = 150.0


# ═══════════════════════════════════════════════════════════════════════════
#  SystemModel — dataclass representing full system state
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ComponentState:
    """State, health, metrics, and constraints for a single component."""
    name: str
    status: str = "unknown"  # healthy | degraded | critical | unknown | disabled
    metrics: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "metrics": self.metrics,
            "constraints": self.constraints,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComponentState":
        return cls(
            name=data.get("name", "unknown"),
            status=data.get("status", "unknown"),
            metrics=data.get("metrics", {}),
            constraints=data.get("constraints", {}),
            last_updated=data.get("last_updated"),
        )


@dataclass
class SystemModel:
    """Full virtual model of the ReconPro runtime.

    Components
    ----------
    engine       : ScanEngine state (concurrency, active scans, rate limits)
    scanner      : Module registry state (registered modules, broken runners)
    modules      : Per-module health and performance data
    plugins      : Plugin directory and hook state
    network      : Connection pool, DNS, SSL, latency
    storage      : Disk usage, memory usage, scan history
    configuration: Config file presence and validated settings

    Metadata
    ---------
    captured_at  : ISO-8601 UTC timestamp of the snapshot
    version      : ReconPro version that produced this model
    """

    engine: ComponentState = field(
        default_factory=lambda: ComponentState(name="engine")
    )
    scanner: ComponentState = field(
        default_factory=lambda: ComponentState(name="scanner")
    )
    modules: ComponentState = field(
        default_factory=lambda: ComponentState(name="modules")
    )
    plugins: ComponentState = field(
        default_factory=lambda: ComponentState(name="plugins")
    )
    network: ComponentState = field(
        default_factory=lambda: ComponentState(name="network")
    )
    storage: ComponentState = field(
        default_factory=lambda: ComponentState(name="storage")
    )
    configuration: ComponentState = field(
        default_factory=lambda: ComponentState(name="configuration")
    )
    captured_at: Optional[str] = None
    version: str = __version__

    # ── Serialisation ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "captured_at": self.captured_at,
            "engine": self.engine.to_dict(),
            "scanner": self.scanner.to_dict(),
            "modules": self.modules.to_dict(),
            "plugins": self.plugins.to_dict(),
            "network": self.network.to_dict(),
            "storage": self.storage.to_dict(),
            "configuration": self.configuration.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemModel":
        model = cls(
            version=data.get("version", __version__),
            captured_at=data.get("captured_at"),
        )
        for comp_name in ("engine", "scanner", "modules", "plugins", "network", "storage", "configuration"):
            comp_data = data.get(comp_name)
            if isinstance(comp_data, dict):
                setattr(model, comp_name, ComponentState.from_dict(comp_data))
        return model

    # ── Helpers ──────────────────────────────────────────────────────

    def all_components(self) -> Dict[str, ComponentState]:
        """Return a name → ComponentState mapping for every component."""
        return {
            "engine": self.engine,
            "scanner": self.scanner,
            "modules": self.modules,
            "plugins": self.plugins,
            "network": self.network,
            "storage": self.storage,
            "configuration": self.configuration,
        }

    def overall_status(self) -> str:
        """Derive overall status from the worst component status."""
        rank = {"critical": 0, "degraded": 1, "healthy": 2, "unknown": 3, "disabled": 4}
        worst = "unknown"
        for comp in self.all_components().values():
            r = rank.get(comp.status, 3)
            if r < rank.get(worst, 3):
                worst = comp.status
        return worst


# ═══════════════════════════════════════════════════════════════════════════
#  SimulationEngine — what-if scenario runner
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class SimulationResult:
    """Outcome of a what-if simulation."""
    scenario: str
    projected_state: Dict[str, Any]
    risk_level: str  # low | medium | high | critical
    performance_impact: str  # none | minimal | moderate | significant | severe
    affected_components: List[str]
    recommendations: List[str]
    confidence: float  # 0.0 – 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario,
            "projected_state": self.projected_state,
            "risk_level": self.risk_level,
            "performance_impact": self.performance_impact,
            "affected_components": self.affected_components,
            "recommendations": self.recommendations,
            "confidence": round(self.confidence, 2),
        }


class SimulationEngine:
    """Run what-if scenarios against a SystemModel without touching the real system.

    Scenarios supported
    -------------------
    - "add_concurrent_scans:N"   — simulate adding N more concurrent scans
    - "fail_module:<module_id>"  — simulate a module failure
    - "increase_load:N"          — simulate N× load increase
    - "change_timeout:N"         — change default timeout to N seconds
    - "change_concurrency:N"     — change max concurrency to N
    - "disk_full"                — simulate disk full condition
    - "network_degraded"         — simulate degraded network
    - "memory_pressure"          — simulate high memory usage
    - "plugin_load:N"            — simulate loading N additional plugins
    - Custom scenario dict passed via ``what_if()``.
    """

    # ── Scenario handlers ─────────────────────────────────────────────

    def simulate(self, model: SystemModel, scenario: str) -> SimulationResult:
        """Run a named scenario against a snapshot *model*.

        Returns a SimulationResult without mutating the input model.
        """
        sim_model = copy.deepcopy(model)
        affected: List[str] = ["engine", "scanner"]
        recommendations: List[str] = []
        risk = "low"
        perf_impact = "none"
        confidence = 0.7

        try:
            if scenario.startswith("add_concurrent_scans:"):
                n = self._parse_int(scenario, 0)
                risk, perf_impact, recommendations = self._sim_add_concurrent(
                    sim_model, n
                )
                confidence = 0.8

            elif scenario.startswith("fail_module:"):
                module_id = scenario.split(":", 1)[1].strip()
                risk, perf_impact, recommendations = self._sim_fail_module(
                    sim_model, module_id
                )
                confidence = 0.85

            elif scenario.startswith("increase_load:"):
                factor = self._parse_int(scenario, 0)
                risk, perf_impact, recommendations = self._sim_increase_load(
                    sim_model, factor
                )
                confidence = 0.65

            elif scenario.startswith("change_timeout:"):
                new_timeout = self._parse_int(scenario, 0)
                risk, perf_impact, recommendations = self._sim_change_timeout(
                    sim_model, new_timeout
                )
                confidence = 0.9

            elif scenario.startswith("change_concurrency:"):
                new_conc = self._parse_int(scenario, 0)
                risk, perf_impact, recommendations = self._sim_change_concurrency(
                    sim_model, new_conc
                )
                confidence = 0.85

            elif scenario == "disk_full":
                risk, perf_impact, recommendations = self._sim_disk_full(sim_model)
                confidence = 0.8
                affected.append("storage")

            elif scenario == "network_degraded":
                risk, perf_impact, recommendations = self._sim_network_degraded(sim_model)
                confidence = 0.7
                affected.append("network")

            elif scenario == "memory_pressure":
                risk, perf_impact, recommendations = self._sim_memory_pressure(sim_model)
                confidence = 0.75
                affected.append("storage")

            elif scenario.startswith("plugin_load:"):
                n = self._parse_int(scenario, 0)
                risk, perf_impact, recommendations = self._sim_plugin_load(
                    sim_model, n
                )
                confidence = 0.7
                affected.append("plugins")

            else:
                # Unknown scenario — generic estimate
                risk = "medium"
                perf_impact = "minimal"
                recommendations = [
                    f"Unknown scenario '{scenario}'. "
                    f"Provide a structured dict for custom simulations."
                ]
                confidence = 0.3

        except Exception as exc:
            logger.debug("Simulation error: %s", exc, exc_info=True)
            risk = "medium"
            perf_impact = "unknown"
            recommendations = [f"Simulation failed: {exc}"]
            confidence = 0.1

        return SimulationResult(
            scenario=scenario,
            projected_state=sim_model.to_dict(),
            risk_level=risk,
            performance_impact=perf_impact,
            affected_components=sorted(set(affected)),
            recommendations=recommendations,
            confidence=confidence,
        )

    def simulate_dict(self, model: SystemModel, params: Dict[str, Any]) -> SimulationResult:
        """Run a custom scenario described by a dictionary.

        Keys:
            type        : str   — "fault", "load", "config", "resource"
            component   : str   — target component name
            parameter   : str   — what to change
            value       : Any   — new value
            description : str   — human-readable description
        """
        sim_model = copy.deepcopy(model)
        comp_name = params.get("component", "engine")
        sim_type = params.get("type", "config")
        desc = params.get("description", comp_name)
        value = params.get("value")
        param = params.get("parameter", "unknown")

        affected = [comp_name]
        recommendations: List[str] = []
        risk = "low"
        perf_impact = "none"

        # Apply the change to the simulated model
        comp = sim_model.all_components().get(comp_name)
        if comp is not None:
            comp.metrics[param] = value
            # Simple risk heuristic based on type
            if sim_type == "fault":
                comp.status = "critical"
                risk = "high"
                perf_impact = "significant"
                recommendations.append(
                    f"Component '{comp_name}' is now in CRITICAL state. "
                    f"Consider failover or restart."
                )
            elif sim_type == "load":
                risk = "medium"
                perf_impact = "moderate"
                recommendations.append(
                    f"Load change on '{comp_name}' ({param}={value}). "
                    f"Monitor for degradation."
                )
            elif sim_type == "resource":
                if comp_name == "storage":
                    risk = "medium"
                    perf_impact = "moderate"
                else:
                    risk = "low"
                    perf_impact = "minimal"
                recommendations.append(
                    f"Resource change on '{comp_name}' ({param}={value})."
                )
            else:
                # config change
                risk = "low"
                perf_impact = "minimal"
                recommendations.append(
                    f"Configuration change on '{comp_name}' ({param}={value})."
                )

        return SimulationResult(
            scenario=desc,
            projected_state=sim_model.to_dict(),
            risk_level=risk,
            performance_impact=perf_impact,
            affected_components=affected,
            recommendations=recommendations,
            confidence=0.6,
        )

    # ── Internal scenario implementations ─────────────────────────────

    @staticmethod
    def _parse_int(scenario: str, idx: int) -> int:
        """Extract an integer after the colon at position *idx* (0-based colon count)."""
        parts = scenario.split(":")
        if len(parts) > idx + 1:
            return int(parts[idx + 1].strip())
        raise ValueError(f"Cannot parse integer from scenario: {scenario}")

    def _sim_add_concurrent(
        self, model: SystemModel, n: int
    ) -> Tuple[str, str, List[str]]:
        """Simulate adding *n* more concurrent scans."""
        current = model.engine.metrics.get("active_scans", 0)
        max_conc = model.engine.constraints.get("max_concurrency", DEFAULT_MAX_WORKERS)
        projected = current + n

        model.engine.metrics["active_scans"] = projected

        # Estimate latency impact (rough: linear scaling until thread-bound)
        utilisation = min(projected / max(max_conc, 1), 2.0)
        latency_factor = 1.0 + (utilisation - 0.5) * 0.8
        latency_factor = max(latency_factor, 1.0)

        avg_latency = model.network.metrics.get("avg_latency_ms", _CONNECTION_LATENCY_BASELINE_MS)
        projected_latency = avg_latency * latency_factor
        model.network.metrics["projected_latency_ms"] = round(projected_latency, 1)

        # Memory estimate: ~15 MB per concurrent scan (modules + findings)
        mem_per_scan = 15.0
        extra_mem = n * mem_per_scan
        current_mem = model.storage.metrics.get("rss_mb", 50.0)
        model.storage.metrics["projected_rss_mb"] = round(current_mem + extra_mem, 1)

        # Risk assessment
        recommendations: List[str] = []
        if projected > max_conc:
            risk = "high"
            perf_impact = "significant"
            recommendations.append(
                f"Projected {projected} concurrent scans exceeds limit of {max_conc}. "
                f"Increase max_concurrency or reduce parallel targets."
            )
        elif utilisation > 0.8:
            risk = "medium"
            perf_impact = "moderate"
            recommendations.append(
                f"Utilisation at {utilisation:.0%}. "
                f"Latency may increase by {((latency_factor - 1) * 100):.0f}%. "
                f"Monitor response times."
            )
        else:
            risk = "low"
            perf_impact = "minimal"
            recommendations.append(
                f"Adding {n} scans is within capacity. "
                f"Projected utilisation: {utilisation:.0%}."
            )

        _RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        if current_mem + extra_mem > _MEMORY_WARNING_MB:
            if _RISK_RANK.get(risk, 2) > _RISK_RANK.get("medium", 2):
                risk = "medium"
            recommendations.append(
                f"Memory may reach {current_mem + extra_mem:.0f} MB. "
                f"Consider reducing scan concurrency."
            )

        return risk, perf_impact, recommendations

    def _sim_fail_module(
        self, model: SystemModel, module_id: str
    ) -> Tuple[str, str, List[str]]:
        """Simulate failure of a specific module."""
        # Check if module exists in registry
        module_list: List[str] = model.scanner.metrics.get("module_ids", [])
        broken: List[str] = list(model.scanner.metrics.get("broken_modules", []))

        if module_id not in module_list and module_id not in broken:
            return (
                "low",
                "none",
                [f"Module '{module_id}' not found in registry. No impact."],
            )

        # If already broken, no new impact
        if module_id in broken:
            return "low", "none", [f"Module '{module_id}' already broken. No new impact."]

        # Mark module as broken
        broken.append(module_id)
        model.scanner.metrics["broken_modules"] = broken

        total = len(module_list)
        broken_count = len(broken)
        integrity = "compromised" if broken_count > 0 else "ok"
        model.scanner.metrics["registry_integrity"] = integrity

        # Assess impact
        recommendations: List[str] = []

        broken_pct = broken_count / max(total, 1)
        if broken_pct > 0.5:
            risk = "critical"
            perf_impact = "significant"
            model.scanner.status = "critical"
            recommendations.append(
                f"Over 50% of modules are broken ({broken_count}/{total}). "
                f"System reliability is severely compromised."
            )
        elif broken_pct > 0.2:
            risk = "high"
            perf_impact = "moderate"
            model.scanner.status = "degraded"
            recommendations.append(
                f"{broken_count}/{total} modules broken. "
                f"Scan coverage is significantly reduced."
            )
        else:
            risk = "medium"
            perf_impact = "minimal"
            model.scanner.status = "degraded"
            recommendations.append(
                f"Module '{module_id}' failed. "
                f"{broken_count}/{total} modules broken. "
                f"Remaining modules can compensate."
            )

        return risk, perf_impact, recommendations

    def _sim_increase_load(
        self, model: SystemModel, factor: int
    ) -> Tuple[str, str, List[str]]:
        """Simulate *factor*× load increase."""
        if factor <= 1:
            return "low", "none", ["No load increase (factor ≤ 1)."]

        # Latency scaling (non-linear: queues build up)
        latency = model.network.metrics.get("avg_latency_ms", _CONNECTION_LATENCY_BASELINE_MS)
        projected_latency = latency * (1 + math.log2(factor) * 0.5)
        model.network.metrics["projected_latency_ms"] = round(projected_latency, 1)

        # Memory scaling
        mem = model.storage.metrics.get("rss_mb", 50.0)
        projected_mem = mem * (1 + (factor - 1) * 0.3)
        model.storage.metrics["projected_rss_mb"] = round(projected_mem, 1)

        # Queue depth estimation
        queue = model.engine.metrics.get("scan_queue_depth", 0)
        model.engine.metrics["projected_queue_depth"] = queue * factor

        recommendations: List[str] = []
        if factor >= 5:
            risk = "critical"
            perf_impact = "severe"
            model.engine.status = "critical"
            recommendations.append(
                f"{factor}× load is extreme. System will likely become unresponsive. "
                f"Scale horizontally or reduce load."
            )
        elif factor >= 3:
            risk = "high"
            perf_impact = "significant"
            model.engine.status = "degraded"
            recommendations.append(
                f"{factor}× load will cause significant latency increase. "
                f"Consider rate limiting or load shedding."
            )
        elif factor >= 2:
            risk = "medium"
            perf_impact = "moderate"
            recommendations.append(
                f"{factor}× load is manageable but latency will increase. "
                f"Monitor closely."
            )
        else:
            risk = "low"
            perf_impact = "minimal"
            recommendations.append(
                f"{factor}× load is within normal variance."
            )

        return risk, perf_impact, recommendations

    def _sim_change_timeout(
        self, model: SystemModel, new_timeout: int
    ) -> Tuple[str, str, List[str]]:
        """Simulate changing the default timeout."""
        old_timeout = model.engine.constraints.get("default_timeout", DEFAULT_TIMEOUT)
        model.engine.constraints["default_timeout"] = new_timeout
        model.engine.metrics["previous_timeout"] = old_timeout

        recommendations: List[str] = []
        if new_timeout < 3:
            risk = "high"
            perf_impact = "moderate"
            recommendations.append(
                f"Timeout of {new_timeout}s is very aggressive. "
                f"Expect increased false-negative findings on slow targets."
            )
        elif new_timeout < old_timeout:
            risk = "medium"
            perf_impact = "minimal"
            recommendations.append(
                f"Reducing timeout from {old_timeout}s to {new_timeout}s. "
                f"Scans will complete faster but may miss slow responses."
            )
        elif new_timeout > 30:
            risk = "medium"
            perf_impact = "significant"
            recommendations.append(
                f"Timeout of {new_timeout}s is very long. "
                f"Scans may take excessively long on unresponsive targets."
            )
        else:
            risk = "low"
            perf_impact = "minimal"
            recommendations.append(
                f"Timeout change to {new_timeout}s is reasonable."
            )

        return risk, perf_impact, recommendations

    def _sim_change_concurrency(
        self, model: SystemModel, new_conc: int
    ) -> Tuple[str, str, List[str]]:
        """Simulate changing max concurrency."""
        old_conc = model.engine.constraints.get("max_concurrency", DEFAULT_MAX_WORKERS)
        model.engine.constraints["max_concurrency"] = new_conc
        model.engine.metrics["previous_concurrency"] = old_conc

        recommendations: List[str] = []
        # Estimate memory impact per worker: ~10 MB
        mem_delta = (new_conc - old_conc) * 10.0
        current_mem = model.storage.metrics.get("rss_mb", 50.0)
        model.storage.metrics["projected_rss_mb"] = round(current_mem + mem_delta, 1)

        if new_conc <= 0:
            risk = "critical"
            perf_impact = "severe"
            recommendations.append("Concurrency of 0 will prevent any scans from running.")
        elif new_conc > 20:
            risk = "high"
            perf_impact = "significant"
            recommendations.append(
                f"Concurrency of {new_conc} may overwhelm the system. "
                f"Projected memory increase: ~{mem_delta:.0f} MB. "
                f"Risk of thread starvation and connection exhaustion."
            )
        elif new_conc > 10:
            risk = "medium"
            perf_impact = "moderate"
            recommendations.append(
                f"Concurrency of {new_conc} is elevated. "
                f"Monitor for resource contention."
            )
        elif new_conc < 2:
            risk = "low"
            perf_impact = "minimal"
            recommendations.append(
                f"Concurrency of {new_conc} will serialise scans. "
                f"Safe but slow."
            )
        else:
            risk = "low"
            perf_impact = "none"
            recommendations.append(
                f"Concurrency of {new_conc} is within normal range."
            )

        return risk, perf_impact, recommendations

    @staticmethod
    def _sim_disk_full(model: SystemModel) -> Tuple[str, str, List[str]]:
        """Simulate a disk-full condition."""
        model.storage.status = "critical"
        model.storage.metrics["usage_percent"] = 99.0
        model.storage.metrics["free_mb"] = 0.0

        recommendations = [
            "Disk is effectively full. Scan results cannot be saved. "
            "Knowledge graph updates will fail. Clear scan history or free disk space."
        ]
        return "critical", "significant", recommendations

    @staticmethod
    def _sim_network_degraded(model: SystemModel) -> Tuple[str, str, List[str]]:
        """Simulate a degraded network."""
        model.network.status = "degraded"
        latency = model.network.metrics.get("avg_latency_ms", _CONNECTION_LATENCY_BASELINE_MS)
        model.network.metrics["avg_latency_ms"] = latency * 3
        model.network.metrics["dns_resolve_ms"] = model.network.metrics.get("dns_resolve_ms", 50) * 4

        recommendations = [
            "Network is degraded. Latency increased ~3×. DNS resolution slow. "
            "Scans will take significantly longer. Consider reducing concurrency."
        ]
        return "high", "significant", recommendations

    @staticmethod
    def _sim_memory_pressure(model: SystemModel) -> Tuple[str, str, List[str]]:
        """Simulate high memory usage."""
        model.storage.status = "degraded"
        model.storage.metrics["rss_mb"] = _MEMORY_CRITICAL_MB + 50

        recommendations = [
            f"Memory pressure detected (>{_MEMORY_CRITICAL_MB} MB). "
            f"Reduce concurrent scans or clear cached data. "
            f"Risk of OOM kills."
        ]
        return "high", "moderate", recommendations

    @staticmethod
    def _sim_plugin_load(
        model: SystemModel, n: int
    ) -> Tuple[str, str, List[str]]:
        """Simulate loading N additional plugins."""
        current = model.plugins.metrics.get("plugin_count", 0)
        model.plugins.metrics["plugin_count"] = current + n
        model.plugins.metrics["loaded_plugins"] = model.plugins.metrics.get(
            "loaded_plugins", []
        ) + [f"sim_plugin_{i}" for i in range(n)]

        # Memory impact: ~2 MB per plugin
        mem_per_plugin = 2.0
        current_mem = model.storage.metrics.get("rss_mb", 50.0)
        model.storage.metrics["projected_rss_mb"] = round(
            current_mem + n * mem_per_plugin, 1
        )

        if n > 20:
            return (
                "high",
                "moderate",
                [
                    f"Loading {n} plugins is excessive. "
                    f"Hook execution overhead will slow every scan. "
                    f"Projected memory: ~{current_mem + n * mem_per_plugin:.0f} MB."
                ],
            )
        elif n > 10:
            return (
                "medium",
                "minimal",
                [
                    f"Loading {n} plugins adds moderate overhead. "
                    f"Verify plugin quality and hook compatibility."
                ],
            )
        else:
            return (
                "low",
                "none",
                [f"Loading {n} plugins is within normal range."],
            )


# ═══════════════════════════════════════════════════════════════════════════
#  TwinSync — keep twin in sync with the live system
# ═══════════════════════════════════════════════════════════════════════════


class TwinSync:
    """Periodically refresh the digital twin from the live system.

    Detects drift between the twin model and reality by comparing
    successive snapshots.
    """

    def __init__(
        self,
        twin: "DigitalTwin",
        refresh_interval: float = 30.0,
        auto_start: bool = False,
    ) -> None:
        self._twin = twin
        self._refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._drift_history: List[Dict[str, Any]] = []
        self._last_model: Optional[SystemModel] = None
        self._sync_count = 0

        if auto_start:
            self.start()

    # ── Lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        """Start background sync loop."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._sync_loop,
                name="twin-sync",
                daemon=True,
            )
            self._thread.start()
            logger.debug("TwinSync started (interval=%.1fs)", self._refresh_interval)

    def stop(self) -> None:
        """Stop background sync loop."""
        with self._lock:
            self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self._refresh_interval * 2)
            self._thread = None
            logger.debug("TwinSync stopped")

    def sync_once(self) -> Dict[str, Any]:
        """Perform a single sync cycle. Returns drift report."""
        new_model = self._twin.capture_state()
        drift = self._compute_drift(self._last_model, new_model)

        with self._lock:
            self._last_model = new_model
            self._sync_count += 1
            if drift["has_drift"]:
                self._drift_history.append(drift)
                # Keep bounded: trim to last 50 when exceeding 100
                while len(self._drift_history) > 100:
                    self._drift_history = self._drift_history[-50:]

        return drift

    # ── Drift detection ───────────────────────────────────────────────

    def get_drift_history(self) -> List[Dict[str, Any]]:
        """Return accumulated drift reports."""
        with self._lock:
            return list(self._drift_history)

    def get_sync_stats(self) -> Dict[str, Any]:
        """Return sync statistics."""
        with self._lock:
            return {
                "sync_count": self._sync_count,
                "running": self._running,
                "refresh_interval": self._refresh_interval,
                "drift_events": len(self._drift_history),
            }

    def _compute_drift(
        self, old: Optional[SystemModel], new: SystemModel
    ) -> Dict[str, Any]:
        """Compare two system models and report differences."""
        if old is None:
            return {
                "has_drift": False,
                "message": "No previous model to compare against (first snapshot).",
                "changes": [],
                "timestamp": new.captured_at,
            }

        changes: List[Dict[str, Any]] = []
        for comp_name, new_comp in new.all_components().items():
            old_comp = old.all_components().get(comp_name)
            if old_comp is None:
                changes.append({
                    "component": comp_name,
                    "type": "added",
                    "detail": f"Component '{comp_name}' appeared.",
                })
                continue

            # Status change
            if old_comp.status != new_comp.status:
                changes.append({
                    "component": comp_name,
                    "type": "status_change",
                    "from": old_comp.status,
                    "to": new_comp.status,
                    "detail": f"{comp_name}: {old_comp.status} → {new_comp.status}",
                })

            # Metric changes
            old_metrics = old_comp.metrics
            new_metrics = new_comp.metrics
            for key in set(list(old_metrics.keys()) + list(new_metrics.keys())):
                old_val = old_metrics.get(key)
                new_val = new_metrics.get(key)
                if old_val != new_val:
                    # Skip noisy counters (counters always change)
                    if key.endswith("_count") or key in ("rss_mb", "free_mb"):
                        # Only flag if change is significant
                        if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
                            pct = abs(new_val - old_val) / max(abs(old_val), 0.001)
                            if pct < 0.1:  # less than 10% change
                                continue
                    changes.append({
                        "component": comp_name,
                        "type": "metric_change",
                        "metric": key,
                        "from": old_val,
                        "to": new_val,
                        "detail": (
                            f"{comp_name}.{key}: {old_val} → {new_val}"
                        ),
                    })

            # Constraint changes
            old_constraints = old_comp.constraints
            new_constraints = new_comp.constraints
            for key in set(list(old_constraints.keys()) + list(new_constraints.keys())):
                if old_constraints.get(key) != new_constraints.get(key):
                    changes.append({
                        "component": comp_name,
                        "type": "constraint_change",
                        "metric": key,
                        "from": old_constraints.get(key),
                        "to": new_constraints.get(key),
                        "detail": (
                            f"{comp_name} constraint {key}: "
                            f"{old_constraints.get(key)} → {new_constraints.get(key)}"
                        ),
                    })

        # Filter to status changes and significant metric changes
        significant = [
            c for c in changes
            if c["type"] in ("status_change", "constraint_change")
            or c.get("type") == "metric_change"
        ]

        return {
            "has_drift": len(significant) > 0,
            "message": (
                f"{len(significant)} change(s) detected."
                if significant
                else "No significant drift."
            ),
            "changes": changes,
            "significant_changes": significant,
            "timestamp": new.captured_at,
        }

    # ── Background loop ───────────────────────────────────────────────

    def _sync_loop(self) -> None:
        """Background sync loop (runs in daemon thread)."""
        while self._running:
            try:
                self.sync_once()
            except Exception as exc:
                logger.debug("TwinSync error: %s", exc, exc_info=True)
            # Sleep in small increments so we can stop promptly
            for _ in range(int(self._refresh_interval * 10)):
                if not self._running:
                    break
                time.sleep(0.1)


# ═══════════════════════════════════════════════════════════════════════════
#  DigitalTwin — main facade
# ═══════════════════════════════════════════════════════════════════════════


class DigitalTwin:
    """Virtual model of the running ReconPro system.

    Provides meta-level operations:
    - ``capture_state()`` — snapshot current system state
    - ``predict_impact(change)`` — simulate a change before applying
    - ``detect_anomaly()`` — compare current state vs expected model
    - ``what_if(scenario)`` — run hypothetical scenarios
    - ``get_system_topology()`` — return component graph with health
    - ``get_capacity_model()`` — current capacity vs limits

    Usage
    -----
        twin = DigitalTwin()
        state = twin.capture_state()
        print(state.overall_status())

        result = twin.what_if("add_concurrent_scans:5")
        print(result.risk_level, result.recommendations)

        anomalies = twin.detect_anomaly()
        print(anomalies)
    """

    def __init__(self, persist: bool = True) -> None:
        self._persist = persist
        self._model: Optional[SystemModel] = None
        self._lock = threading.Lock()
        self._simulation = SimulationEngine()
        self._sync: Optional[TwinSync] = None
        self._baseline: Optional[SystemModel] = None

    # ── State capture ─────────────────────────────────────────────────

    def capture_state(self) -> SystemModel:
        """Snapshot the current system state from live diagnostics and observability.

        Gathers data from:
        - diagnostics.py (health_check, module_status, validate_config)
        - observability.py (HealthMonitor, MetricsCollector via TelemetryManager)
        - connection_pool.py (stats — if pool instance is reachable)
        - registry.py (module counts, broken modules)
        - filesystem (disk, memory, directory existence)

        Returns a SystemModel suitable for simulation and anomaly detection.
        """
        model = SystemModel(captured_at=_utc_iso())

        self._capture_engine(model)
        self._capture_scanner(model)
        self._capture_modules(model)
        self._capture_plugins(model)
        self._capture_network(model)
        self._capture_storage(model)
        self._capture_configuration(model)

        with self._lock:
            self._model = model
            if self._baseline is None:
                self._baseline = copy.deepcopy(model)

        if self._persist:
            self._save(model)

        return model

    # ── Predict impact ─────────────────────────────────────────────────

    def predict_impact(self, change: str) -> SimulationResult:
        """Simulate a named change against the current (or last captured) state.

        Args:
            change: A scenario string (e.g. "add_concurrent_scans:5")
                   or a dict for custom simulations.

        Returns:
            SimulationResult with projected state, risk, and recommendations.
        """
        model = self._get_or_capture()
        if isinstance(change, dict):
            return self._simulation.simulate_dict(model, change)
        return self._simulation.simulate(model, change)

    # ── What-if ───────────────────────────────────────────────────────

    def what_if(self, scenario: str) -> SimulationResult:
        """Run a hypothetical scenario. Alias for ``predict_impact``."""
        return self.predict_impact(scenario)

    # ── Anomaly detection ──────────────────────────────────────────────

    def detect_anomaly(self) -> Dict[str, Any]:
        """Compare current state vs the baseline (first captured) model.

        Detects unexpected state deviations:
        - Component status changes (healthy → degraded/critical)
        - Significant metric deviations (> 2× baseline or new critical values)
        - Constraint violations
        - New broken modules
        - Resource exhaustion

        Returns a dict with:
            anomalies: list of detected anomalies
            anomaly_count: int
            severity: str ("none" | "low" | "medium" | "high" | "critical")
        """
        current = self._get_or_capture()
        if self._baseline is None:
            self._baseline = copy.deepcopy(current)
            return {
                "anomalies": [],
                "anomaly_count": 0,
                "severity": "none",
                "message": "Baseline established from current state.",
            }

        anomalies: List[Dict[str, Any]] = []

        for comp_name, curr_comp in current.all_components().items():
            base_comp = self._baseline.all_components().get(comp_name)
            if base_comp is None:
                continue

            # Status regression
            status_rank = {"critical": 0, "degraded": 1, "healthy": 2, "unknown": 3, "disabled": 4}
            curr_rank = status_rank.get(curr_comp.status, 3)
            base_rank = status_rank.get(base_comp.status, 3)
            if curr_rank < base_rank:
                anomalies.append({
                    "component": comp_name,
                    "type": "status_regression",
                    "severity": "high" if curr_rank == 0 else "medium",
                    "baseline": base_comp.status,
                    "current": curr_comp.status,
                    "description": (
                        f"{comp_name} regressed from {base_comp.status} to {curr_comp.status}"
                    ),
                })

            # Broken modules increase
            base_broken = base_comp.metrics.get("broken_modules", [])
            curr_broken = curr_comp.metrics.get("broken_modules", [])
            new_broken = set(curr_broken) - set(base_broken)
            if new_broken:
                anomalies.append({
                    "component": comp_name,
                    "type": "new_broken_modules",
                    "severity": "high",
                    "new_broken": sorted(new_broken),
                    "description": (
                        f"New broken module(s) detected: {sorted(new_broken)}"
                    ),
                })

            # Metric anomalies — compare numeric metrics
            for metric_key, curr_val in curr_comp.metrics.items():
                if not isinstance(curr_val, (int, float)):
                    continue
                base_val = base_comp.metrics.get(metric_key)
                if not isinstance(base_val, (int, float)):
                    continue
                if base_val == 0:
                    continue

                ratio = curr_val / base_val if base_val != 0 else float("inf")
                # Flag if metric more than doubled or halved
                if ratio > 2.0 or ratio < 0.5:
                    # Skip known-volatile metrics
                    if metric_key in ("scan_count", "request_count", "total_requests"):
                        continue
                    anomalies.append({
                        "component": comp_name,
                        "type": "metric_anomaly",
                        "severity": "medium",
                        "metric": metric_key,
                        "baseline_value": base_val,
                        "current_value": curr_val,
                        "ratio": round(ratio, 2),
                        "description": (
                            f"{comp_name}.{metric_key}: {base_val} → {curr_val} "
                            f"(ratio: {ratio:.1f}×)"
                        ),
                    })

            # Constraint violations
            for ckey, cval in curr_comp.constraints.items():
                if isinstance(cval, (int, float)) and cval > 0:
                    metric_val = curr_comp.metrics.get(ckey)
                    if isinstance(metric_val, (int, float)) and metric_val > cval:
                        anomalies.append({
                            "component": comp_name,
                            "type": "constraint_violation",
                            "severity": "high",
                            "constraint": ckey,
                            "limit": cval,
                            "actual": metric_val,
                            "description": (
                                f"{comp_name}.{ckey} = {metric_val} "
                                f"exceeds limit {cval}"
                            ),
                        })

        # Determine overall severity
        severity = "none"
        if anomalies:
            sev_ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            worst = min(sev_ranks.get(a["severity"], 3) for a in anomalies)
            severity = ["critical", "high", "medium", "low"][worst]

        return {
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "severity": severity,
            "timestamp": current.captured_at,
        }

    # ── Topology ──────────────────────────────────────────────────────

    def get_system_topology(self) -> Dict[str, Any]:
        """Return the component dependency graph with health status.

        The topology is a static model of how ReconPro components relate:
        - engine depends on scanner, modules, network, plugins
        - scanner depends on modules, registry
        - modules depend on network, plugins
        - plugins depend on storage (for hook files)
        - storage is a leaf node
        - network is a leaf node
        - configuration is a leaf node (read at startup)

        Returns:
            Dict with 'nodes' and 'edges' lists.
        """
        model = self._get_or_capture()

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []

        for comp_name, comp in model.all_components().items():
            nodes.append({
                "id": comp_name,
                "status": comp.status,
                "metrics_count": len(comp.metrics),
            })

        # Dependency edges
        _EDGES = [
            ("engine", "scanner"),
            ("engine", "modules"),
            ("engine", "network"),
            ("engine", "plugins"),
            ("scanner", "modules"),
            ("scanner", "configuration"),
            ("modules", "network"),
            ("modules", "plugins"),
            ("plugins", "storage"),
            ("plugins", "configuration"),
        ]
        for src, dst in _EDGES:
            edges.append({"from": src, "to": dst})

        # Identify impacted paths (if any node is degraded/critical)
        impacted_paths: List[List[str]] = []
        for node in nodes:
            if node["status"] in ("degraded", "critical"):
                # Find all nodes that depend on this one
                dependents = [e["from"] for e in edges if e["to"] == node["id"]]
                for dep in dependents:
                    impacted_paths.append([node["id"], dep])

        return {
            "nodes": nodes,
            "edges": edges,
            "overall_status": model.overall_status(),
            "impacted_paths": impacted_paths,
            "captured_at": model.captured_at,
        }

    # ── Capacity model ─────────────────────────────────────────────────

    def get_capacity_model(self) -> Dict[str, Any]:
        """Return current capacity usage vs known limits.

        Dimensions:
        - concurrency: active / max
        - memory: current MB / warning / critical thresholds
        - disk: usage % / warning / critical thresholds
        - modules: healthy / total
        - network: latency vs baseline
        - plugins: loaded count
        """
        model = self._get_or_capture()

        # Concurrency
        active_scans = model.engine.metrics.get("active_scans", 0)
        max_conc = model.engine.constraints.get("max_concurrency", DEFAULT_MAX_WORKERS)
        conc_pct = (active_scans / max(max_conc, 1)) * 100

        # Memory
        rss_mb = model.storage.metrics.get("rss_mb", 0)
        mem_warning = model.storage.constraints.get("memory_warning_mb", _MEMORY_WARNING_MB)
        mem_critical = model.storage.constraints.get("memory_critical_mb", _MEMORY_CRITICAL_MB)
        mem_pct = (rss_mb / mem_critical * 100) if mem_critical > 0 else 0

        # Disk
        disk_pct = model.storage.metrics.get("usage_percent", 0)
        disk_free = model.storage.metrics.get("free_mb", 0)

        # Modules
        total_modules = model.scanner.metrics.get("total_modules", 0)
        broken_modules = len(model.scanner.metrics.get("broken_modules", []))
        healthy_modules = max(total_modules - broken_modules, 0)

        # Network latency
        avg_latency = model.network.metrics.get("avg_latency_ms", 0)
        latency_baseline = model.network.constraints.get(
            "latency_baseline_ms", _CONNECTION_LATENCY_BASELINE_MS
        )
        latency_ratio = avg_latency / latency_baseline if latency_baseline > 0 else 0

        # Plugins
        plugin_count = model.plugins.metrics.get("plugin_count", 0)

        # Overall capacity score (0-100, 100 = no stress)
        scores: List[float] = []
        scores.append(max(0, 100 - conc_pct))  # concurrency headroom
        scores.append(max(0, 100 - mem_pct))    # memory headroom
        scores.append(max(0, 100 - disk_pct))   # disk headroom
        if total_modules > 0:
            scores.append((healthy_modules / total_modules) * 100)  # module health
        if latency_baseline > 0 and avg_latency > 0:
            scores.append(max(0, 100 - (latency_ratio - 1) * 50))  # latency health

        capacity_score = min(sum(scores) / max(len(scores), 1), 100.0)

        return {
            "capacity_score": round(capacity_score, 1),
            "concurrency": {
                "active": active_scans,
                "max": max_conc,
                "utilisation_pct": round(conc_pct, 1),
                "status": _capacity_status(conc_pct),
            },
            "memory": {
                "rss_mb": round(rss_mb, 1),
                "warning_mb": mem_warning,
                "critical_mb": mem_critical,
                "utilisation_pct": round(mem_pct, 1),
                "status": _capacity_status(mem_pct),
            },
            "disk": {
                "usage_pct": round(disk_pct, 1),
                "free_mb": round(disk_free, 1),
                "warning_pct": _DISK_WARNING_PCT,
                "critical_pct": _DISK_CRITICAL_PCT,
                "status": _capacity_status(disk_pct),
            },
            "modules": {
                "total": total_modules,
                "healthy": healthy_modules,
                "broken": broken_modules,
                "health_pct": round((healthy_modules / max(total_modules, 1)) * 100, 1),
                "status": "healthy" if broken_modules == 0 else ("degraded" if broken_modules <= 3 else "critical"),
            },
            "network": {
                "avg_latency_ms": round(avg_latency, 1),
                "baseline_ms": latency_baseline,
                "ratio": round(latency_ratio, 2),
                "status": "healthy" if latency_ratio < 1.5 else ("degraded" if latency_ratio < 3.0 else "critical"),
            },
            "plugins": {
                "count": plugin_count,
                "status": "healthy",
            },
            "overall_status": model.overall_status(),
            "captured_at": model.captured_at,
        }

    # ── Sync management ───────────────────────────────────────────────

    def start_sync(self, interval: float = 30.0) -> TwinSync:
        """Start background synchronisation. Returns the TwinSync instance."""
        if self._sync is None:
            self._sync = TwinSync(self, refresh_interval=interval, auto_start=True)
        return self._sync

    def stop_sync(self) -> None:
        """Stop background synchronisation."""
        if self._sync is not None:
            self._sync.stop()

    @property
    def sync(self) -> Optional[TwinSync]:
        """Access the TwinSync instance (if any)."""
        return self._sync

    # ── Persistence ────────────────────────────────────────────────────

    def load(self) -> Optional[SystemModel]:
        """Load the last persisted model from disk."""
        try:
            if not DIGITAL_TWIN_FILE.exists():
                return None
            with open(DIGITAL_TWIN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            model = SystemModel.from_dict(data)
            with self._lock:
                self._model = model
                if self._baseline is None:
                    self._baseline = copy.deepcopy(model)
            return model
        except Exception as exc:
            logger.debug("Failed to load digital twin: %s", exc)
            return None

    def _save(self, model: SystemModel) -> None:
        """Persist model to JSON."""
        try:
            MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            with open(DIGITAL_TWIN_FILE, "w", encoding="utf-8") as f:
                json.dump(model.to_dict(), f, indent=2, default=str)
        except Exception as exc:
            logger.debug("Failed to save digital twin: %s", exc)

    def get_last_model(self) -> Optional[SystemModel]:
        """Return the last captured model without re-capturing."""
        with self._lock:
            return self._model

    def reset_baseline(self) -> None:
        """Reset the anomaly detection baseline to the current state."""
        with self._lock:
            if self._model is not None:
                self._baseline = copy.deepcopy(self._model)

    # ── Internal helpers ───────────────────────────────────────────────

    def _get_or_capture(self) -> SystemModel:
        """Return the last model, or capture a new one if none exists."""
        with self._lock:
            if self._model is not None:
                return self._model
        return self.capture_state()

    # ── Component capture implementations ──────────────────────────────

    def _capture_engine(self, model: SystemModel) -> None:
        """Capture ScanEngine / engine state."""
        comp = model.engine
        comp.metrics["version"] = __version__
        comp.metrics["active_scans"] = 0  # not easily observable without engine ref
        comp.constraints["max_concurrency"] = DEFAULT_MAX_WORKERS
        comp.constraints["default_timeout"] = DEFAULT_TIMEOUT
        comp.constraints["default_rate_limit"] = DEFAULT_RATE_LIMIT
        comp.status = "healthy"
        comp.last_updated = _utc_iso()

        # Try to get metrics from TelemetryManager if available
        try:
            from .telemetry import get_metrics_snapshot
            snapshot = get_metrics_snapshot()
            counters = snapshot.get("counters", {})
            gauges = snapshot.get("gauges", {})
            comp.metrics["counters"] = counters
            comp.metrics["gauges"] = gauges
            comp.metrics["active_scans"] = int(gauges.get("active_scans", 0))
            comp.metrics["scan_count"] = int(counters.get("scans_completed", 0))
            comp.metrics["error_count"] = int(counters.get("errors", 0))
            comp.metrics["finding_count"] = int(counters.get("findings", 0))
        except Exception:
            pass

    def _capture_scanner(self, model: SystemModel) -> None:
        """Capture scanner / module registry state."""
        comp = model.scanner
        comp.status = "healthy"
        comp.last_updated = _utc_iso()

        try:
            from .diagnostics import module_status
            modules = module_status()
            comp.metrics["total_modules"] = len(modules)
            comp.metrics["module_ids"] = [m["id"] for m in modules]
            broken = [m["id"] for m in modules if not m["runner_status"]]
            comp.metrics["broken_modules"] = broken
            comp.metrics["registry_integrity"] = (
                "ok" if len(broken) == 0 else "compromised"
            )
            if broken:
                comp.status = "degraded" if len(broken) <= 3 else "critical"
        except Exception as exc:
            comp.metrics["error"] = str(exc)
            comp.status = "unknown"

    def _capture_modules(self, model: SystemModel) -> None:
        """Capture per-module health and performance data."""
        comp = model.modules
        comp.last_updated = _utc_iso()

        try:
            from .registry import ALL_MODULES, MODULE_REGISTRY, LOCAL_MODULES
            remote_count = len(MODULE_REGISTRY)
            local_count = len(LOCAL_MODULES)
            comp.metrics["remote_modules"] = remote_count
            comp.metrics["local_modules"] = local_count
            comp.metrics["total_registered"] = len(ALL_MODULES)
            comp.status = "healthy"
        except Exception as exc:
            comp.metrics["error"] = str(exc)
            comp.status = "unknown"

        # Try to get per-module performance from TelemetryManager
        try:
            from .telemetry import get_telemetry_manager
            tm = get_telemetry_manager()
            if tm.profiling_enabled:
                profiler = tm.create_profiler()
                report = profiler.get_report()
                comp.metrics["performance"] = report
        except Exception:
            pass

    def _capture_plugins(self, model: SystemModel) -> None:
        """Capture plugin directory and hook state."""
        comp = model.plugins
        comp.last_updated = _utc_iso()

        try:
            exists = PLUGIN_DIR.exists()
            comp.metrics["directory_exists"] = exists
            if exists:
                py_files = list(PLUGIN_DIR.glob("*.py"))
                comp.metrics["plugin_count"] = len(py_files)
                comp.metrics["plugin_files"] = [f.name for f in py_files]

                # Check hooks
                from .constants import PLUGIN_HOOKS_FILE
                hooks_exist = PLUGIN_HOOKS_FILE.exists()
                comp.metrics["hooks_file_exists"] = hooks_exist
                if hooks_exist:
                    try:
                        with open(PLUGIN_HOOKS_FILE, "r") as f:
                            import json as _json
                            hooks = _json.load(f)
                        comp.metrics["registered_hooks"] = list(hooks.keys()) if isinstance(hooks, dict) else []
                    except Exception:
                        comp.metrics["registered_hooks"] = []
            else:
                comp.metrics["plugin_count"] = 0
            comp.status = "healthy" if exists else "missing"
        except Exception as exc:
            comp.metrics["error"] = str(exc)
            comp.status = "unknown"

    def _capture_network(self, model: SystemModel) -> None:
        """Capture network state: DNS, SSL, latency."""
        comp = model.network
        comp.constraints["latency_baseline_ms"] = _CONNECTION_LATENCY_BASELINE_MS
        comp.last_updated = _utc_iso()

        # DNS check
        try:
            start = time.perf_counter()
            socket.getaddrinfo("dns.google", 443, socket.AF_INET, socket.SOCK_STREAM)
            dns_ms = (time.perf_counter() - start) * 1000
            comp.metrics["dns_resolve_ms"] = round(dns_ms, 1)
            comp.metrics["dns_reachable"] = True
        except socket.gaierror:
            comp.metrics["dns_resolve_ms"] = None
            comp.metrics["dns_reachable"] = False
            comp.status = "critical"
        except Exception:
            comp.metrics["dns_reachable"] = False
            comp.status = "unknown"

        # Try to get health report from TelemetryManager
        try:
            from .telemetry import check_health as _check_health
            health = _check_health()
            checks = health.get("checks", {})
            net_check = checks.get("network", {})
            if net_check:
                comp.metrics["health_status"] = net_check.get("status", "unknown")
                comp.metrics["avg_latency_ms"] = net_check.get("dns_resolve_ms", 0)
            ssl_check = checks.get("ssl", {})
            if ssl_check:
                comp.metrics["ssl_status"] = ssl_check.get("status", "unknown")
                comp.metrics["ssl_days_until_expiry"] = ssl_check.get("days_until_expiry")
        except Exception:
            pass

        if comp.status == "unknown":
            comp.status = "healthy"

    def _capture_storage(self, model: SystemModel) -> None:
        """Capture disk and memory usage."""
        comp = model.storage
        comp.constraints["memory_warning_mb"] = _MEMORY_WARNING_MB
        comp.constraints["memory_critical_mb"] = _MEMORY_CRITICAL_MB
        comp.constraints["disk_warning_pct"] = _DISK_WARNING_PCT
        comp.constraints["disk_critical_pct"] = _DISK_CRITICAL_PCT
        comp.last_updated = _utc_iso()

        # Memory
        try:
            if os.path.exists("/proc/self/status"):
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            kb = int(line.split()[1])
                            comp.metrics["rss_mb"] = round(kb / 1024, 1)
                            comp.metrics["memory_method"] = "proc"
                            break
            else:
                import resource
                rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                if hasattr(os, "uname") and os.uname().sysname == "Darwin":
                    comp.metrics["rss_mb"] = round(rss / (1024 * 1024), 1)
                else:
                    comp.metrics["rss_mb"] = round(rss / 1024, 1)
                comp.metrics["memory_method"] = "resource"
        except Exception:
            comp.metrics["rss_mb"] = 0
            comp.metrics["memory_method"] = "unavailable"

        # Memory status
        rss = comp.metrics.get("rss_mb", 0)
        if rss > _MEMORY_CRITICAL_MB:
            comp.status = "critical"
        elif rss > _MEMORY_WARNING_MB:
            comp.status = "degraded"
        else:
            comp.status = "healthy"

        # Disk
        try:
            usage = shutil.disk_usage(str(RECONPRO_HOME))
            comp.metrics["total_mb"] = round(usage.total / (1024 * 1024), 1)
            comp.metrics["used_mb"] = round(usage.used / (1024 * 1024), 1)
            comp.metrics["free_mb"] = round(usage.free / (1024 * 1024), 1)
            pct = round(usage.used / usage.total * 100, 1) if usage.total else 0
            comp.metrics["usage_percent"] = pct

            if pct > _DISK_CRITICAL_PCT:
                comp.status = "critical"
            elif pct > _DISK_WARNING_PCT:
                comp.status = "degraded"
            elif comp.status == "healthy":
                pass  # keep memory-derived status if it's worse
            else:
                comp.status = "healthy"
        except Exception:
            comp.metrics["usage_percent"] = 0
            comp.metrics["free_mb"] = 0

        # Scan history
        try:
            if SCAN_HISTORY_DIR.exists():
                scan_count = len(list(SCAN_HISTORY_DIR.glob("*.json")))
                comp.metrics["scan_history_count"] = scan_count
        except Exception:
            pass

    def _capture_configuration(self, model: SystemModel) -> None:
        """Capture configuration state."""
        comp = model.configuration
        comp.last_updated = _utc_iso()

        try:
            from .diagnostics import validate_config
            issues = validate_config()
            comp.metrics["config_issues"] = len(issues)
            comp.metrics["issues"] = [
                {"severity": i["severity"], "category": i["category"], "message": i["message"]}
                for i in issues
            ]

            config_file = RECONPRO_HOME / "config.json"
            comp.metrics["config_exists"] = config_file.exists()

            errors = [i for i in issues if i["severity"] == "error"]
            warnings = [i for i in issues if i["severity"] == "warning"]
            if errors:
                comp.status = "critical"
            elif warnings:
                comp.status = "degraded"
            else:
                comp.status = "healthy"
        except Exception as exc:
            comp.metrics["error"] = str(exc)
            comp.status = "unknown"


# ── Utility functions ─────────────────────────────────────────────────────


def _utc_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _capacity_status(pct: float) -> str:
    """Map utilisation percentage to status string."""
    if pct > 90:
        return "critical"
    elif pct > 75:
        return "degraded"
    else:
        return "healthy"
