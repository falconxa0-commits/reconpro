"""ReconPro Telemetry API.

Quick access to observability features:
    from reconpro.telemetry import get_logger, get_metrics, trace_scan

This module provides convenience wrappers around the TelemetryManager
singleton for ergonomic access to all observability features.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .observability import (
    HealthMonitor,
    MetricsCollector,
    PerformanceProfiler,
    ScanTracer,
    StructuredLogger,
    TelemetryManager,
)


# ── Singleton Access ────────────────────────────────────────────────────


def get_telemetry_manager() -> TelemetryManager:
    """Get the global TelemetryManager singleton.

    Creates one on first call. Subsequent calls return the same instance.
    """
    return TelemetryManager.get_instance()


# DEAD CODE: consider removal
def reset_telemetry() -> None:
    """Reset the global TelemetryManager singleton.

    Useful for testing or reconfiguration.
    """
    TelemetryManager.reset_instance()


# ── Logger Convenience ──────────────────────────────────────────────────


def get_logger(module: str = "root") -> StructuredLogger:
    """Get a StructuredLogger for the given module.

    Args:
        module: Module name for log entries (e.g. "quantum_fingerprint").

    Returns:
        StructuredLogger instance with current telemetry settings.

    Usage:
        from reconpro.telemetry import get_logger
        log = get_logger("recon")
        log.info("scan_start", target="example.com")
    """
    return get_telemetry_manager().get_logger(module)


def log_event(event: str, level: str = "INFO", module: str = "root", **kwargs: Any) -> None:
    """Emit a single structured log event.

    Args:
        event: Event name (e.g. "scan_start", "finding_found").
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        module: Module name for the log entry.
        **kwargs: Additional fields to include in the log entry.

    Usage:
        from reconpro.telemetry import log_event
        log_event("scan_start", target="example.com", module="recon")
    """
    logger = get_logger(module)
    method = getattr(logger, level.lower(), logger.info)
    method(event, **kwargs)


# ── Metrics Convenience ─────────────────────────────────────────────────


def get_metrics() -> MetricsCollector:
    """Get the global MetricsCollector instance.

    Usage:
        from reconpro.telemetry import get_metrics
        metrics = get_metrics()
        metrics.counter_increment("requests")
        metrics.gauge_set("memory_mb", 256)
    """
    return get_telemetry_manager().metrics


def increment_counter(name: str, amount: float = 1) -> None:
    """Increment a counter.

    Args:
        name: Counter name (e.g. "requests", "findings", "errors").
        amount: Amount to increment (default 1).
    """
    get_metrics().counter_increment(name, amount)


def set_gauge(name: str, value: float) -> None:
    """Set a gauge value.

    Args:
        name: Gauge name (e.g. "memory_mb", "connections").
        value: Current value.
    """
    get_metrics().gauge_set(name, value)


def observe_histogram(name: str, value: float) -> None:
    """Record a value in a histogram.

    Args:
        name: Histogram name (e.g. "latency_ms", "response_size").
        value: Observed value.
    """
    get_metrics().histogram_observe(name, value)


def get_metrics_snapshot() -> Dict[str, Any]:
    """Get a snapshot of all current metrics.

    Returns:
        Dictionary with counters, gauges, and histogram summaries.
    """
    return get_metrics().get_snapshot()


# ── Tracing Convenience ─────────────────────────────────────────────────


def trace_scan(target: str) -> ScanTracer:
    """Create a new ScanTracer for a target.

    Args:
        target: The scan target (domain, IP, etc.).

    Returns:
        ScanTracer instance ready to track module execution.

    Usage:
        from reconpro.telemetry import trace_scan
        tracer = trace_scan("example.com")
        tracer.start_scan()
        tracer.start_module("recon")
        # ... run module ...
        tracer.end_module("recon", findings=5)
        receipt = tracer.end_scan(score=85)
    """
    return get_telemetry_manager().create_tracer(target)


# ── Health Convenience ──────────────────────────────────────────────────


def check_health() -> Dict[str, Any]:
    """Run all health checks and return a comprehensive report.

    Returns:
        Health report with overall status and individual check results.
    """
    return get_telemetry_manager().get_health_report()


def check_memory() -> Dict[str, Any]:
    """Run only the memory health check."""
    return get_telemetry_manager().health.check_memory()


def check_disk() -> Dict[str, Any]:
    """Run only the disk health check."""
    return get_telemetry_manager().health.check_disk()


def check_network() -> Dict[str, Any]:
    """Run only the network health check."""
    return get_telemetry_manager().health.check_network()


# ── Profiling Convenience ───────────────────────────────────────────────


def create_profiler() -> PerformanceProfiler:
    """Create a new PerformanceProfiler.

    Returns:
        PerformanceProfiler instance for tracking per-module performance.
    """
    return get_telemetry_manager().create_profiler()


# ── Status Convenience ──────────────────────────────────────────────────


def get_telemetry_status() -> Dict[str, Any]:
    """Get the current telemetry configuration status.

    Returns:
        Dictionary showing which telemetry features are enabled.
    """
    return get_telemetry_manager().get_status()
