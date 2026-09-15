"""ReconPro v11 — Observability Layer.

Structured logging, metrics collection, timing breakdowns,
health monitoring, and execution receipts.

Zero external dependencies. Pure Python. Thread-safe.
Minimal overhead when disabled.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import threading
import time
import traceback
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from .constants import GRADE_THRESHOLDS, MAX_SCORE, MIN_SCORE, RECONPRO_HOME


# ── Helpers ─────────────────────────────────────────────────────────────


def _utc_iso() -> str:
    """Return current UTC time in ISO 8601 format with milliseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _generate_trace_id(length: int = 12) -> str:
    """Generate a short random hex trace ID."""
    return format(time.thread_time_ns() % (16 ** length), 'x').zfill(length)


def _score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade using GRADE_THRESHOLDS."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


# ── A. Structured Logger ────────────────────────────────────────────────


class StructuredLogger:
    """JSON-formatted structured logger for ReconPro.

    Features:
    - Consistent JSON output format
    - Automatic timestamp, trace_id, module fields
    - Configurable log levels
    - Output to stdout (default) or file
    - Scan context propagation

    Log format:
    {
        "ts": "2024-01-15T10:30:00.000Z",
        "level": "INFO",
        "module": "quantum_fingerprint",
        "event": "scan_start",
        "target": "example.com",
        "trace_id": "abc123",
        "duration_ms": 1234,
        "details": {}
    }
    """

    LEVEL_ORDER: Dict[str, int] = {
        "DEBUG": 10,
        "INFO": 20,
        "WARNING": 30,
        "ERROR": 40,
        "CRITICAL": 50,
    }

    def __init__(
        self,
        module: str = "root",
        enabled: bool = True,
        min_level: str = "DEBUG",
        output_file: Optional[str] = None,
    ) -> None:
        self._module = module
        self._enabled = enabled
        self._min_level = self.LEVEL_ORDER.get(min_level.upper(), 10)
        self._output_file = output_file
        self._file_handle: Optional[Any] = None
        self._trace_id: Optional[str] = None
        self._target: Optional[str] = None
        self._lock = threading.Lock()

        if output_file:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            self._file_handle = open(output_file, "a", encoding="utf-8")

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def set_trace_context(self, trace_id: Optional[str], target: Optional[str] = None) -> None:
        """Set scan context for subsequent log entries."""
        self._trace_id = trace_id
        if target is not None:
            self._target = target

    def clear_trace_context(self) -> None:
        """Clear scan context."""
        self._trace_id = None
        self._target = None

    def _should_log(self, level: str) -> bool:
        if not self._enabled:
            return False
        return self.LEVEL_ORDER.get(level, 0) >= self._min_level

    def _emit(self, level: str, event: str, **kwargs: Any) -> None:
        if not self._should_log(level):
            return

        entry: Dict[str, Any] = {
            "ts": _utc_iso(),
            "level": level,
            "module": self._module,
            "event": event,
        }
        if self._trace_id:
            entry["trace_id"] = self._trace_id
        if self._target:
            entry["target"] = self._target
        entry.update(kwargs)

        line = json.dumps(entry, default=str, ensure_ascii=False)

        with self._lock:
            print(line, flush=True)
            if self._file_handle:
                self._file_handle.write(line + "\n")
                self._file_handle.flush()

    def debug(self, event: str, **kwargs: Any) -> None:
        self._emit("DEBUG", event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._emit("INFO", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._emit("WARNING", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._emit("ERROR", event, **kwargs)

    def critical(self, event: str, **kwargs: Any) -> None:
        self._emit("CRITICAL", event, **kwargs)

    def log_exception(self, event: str, exc: Optional[BaseException] = None, **kwargs: Any) -> None:
        """Log an ERROR event with full traceback."""
        tb = traceback.format_exception(type(exc), exc, exc.__traceback__) if exc else traceback.format_stack()
        self._emit("ERROR", event, traceback="".join(tb).strip(), **kwargs)

    def child(self, module: str) -> "StructuredLogger":
        """Create a child logger that inherits trace context."""
        child = StructuredLogger(
            module=module,
            enabled=self._enabled,
            min_level=[k for k, v in self.LEVEL_ORDER.items() if v == self._min_level][0],
            output_file=self._output_file,
        )
        child._trace_id = self._trace_id
        child._target = self._target
        return child

    def close(self) -> None:
        """Close file handle if open."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def __del__(self) -> None:
        self.close()


# ── B. Metrics Collector ───────────────────────────────────────────────


class TimerContext:
    """Context manager for timing a block of code."""

    def __init__(self, collector: "MetricsCollector", name: str) -> None:
        self._collector = collector
        self._name = name
        self._start: Optional[float] = None
        self._elapsed: float = 0.0

    def __enter__(self) -> "TimerContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._start is not None:
            self._elapsed = (time.perf_counter() - self._start) * 1000.0
            self._collector.histogram_observe(f"{self._name}_duration_ms", self._elapsed)

    @property
    def elapsed_ms(self) -> float:
        return self._elapsed


class MetricsCollector:
    """Thread-safe metrics collection.

    Metrics:
    - counters: monotonically increasing values (requests, findings, errors)
    - gauges: point-in-time values (memory, connections, queue_depth)
    - histograms: distribution tracking (latency, response_size)
    - timers: named timers with start/stop

    All methods are O(1) and thread-safe.
    Minimal overhead: disabled metrics cost ~50ns per call.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._active_timers: Dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def counter_increment(self, name: str, amount: float = 1) -> None:
        """Increment a counter by amount (default 1)."""
        if not self._enabled:
            return
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def gauge_set(self, name: str, value: float) -> None:
        """Set a gauge to a specific value."""
        if not self._enabled:
            return
        with self._lock:
            self._gauges[name] = value

    def gauge_increment(self, name: str, amount: float = 1) -> None:
        """Increment (or decrement) a gauge."""
        if not self._enabled:
            return
        with self._lock:
            self._gauges[name] = self._gauges.get(name, 0) + amount

    def histogram_observe(self, name: str, value: float) -> None:
        """Record a value in a histogram."""
        if not self._enabled:
            return
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = []
            self._histograms[name].append(value)

    def timer_start(self, name: str) -> str:
        """Start a named timer. Returns the timer name."""
        if not self._enabled:
            return name
        with self._lock:
            self._active_timers[name] = time.perf_counter()
        return name

    def timer_stop(self, name: str) -> Optional[float]:
        """Stop a named timer and record elapsed ms in histogram. Returns elapsed ms or None."""
        if not self._enabled:
            return None
        with self._lock:
            start = self._active_timers.pop(name, None)
        if start is None:
            return None
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.histogram_observe(f"{name}_duration_ms", elapsed_ms)
        return elapsed_ms

    def timer_context(self, name: str) -> TimerContext:
        """Return a TimerContext for use as a context manager."""
        return TimerContext(self, name)

    def get_snapshot(self) -> Dict[str, Any]:
        """Return all current metrics as a dictionary."""
        with self._lock:
            snapshot: Dict[str, Any] = {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }
            hist_summary: Dict[str, Dict[str, Any]] = {}
            for name, values in self._histograms.items():
                if values:
                    sorted_vals = sorted(values)
                    n = len(sorted_vals)
                    hist_summary[name] = {
                        "count": n,
                        "min": sorted_vals[0],
                        "max": sorted_vals[-1],
                        "avg": sum(sorted_vals) / n,
                        "p50": sorted_vals[n // 2],
                        "p95": sorted_vals[int(n * 0.95)] if n >= 20 else sorted_vals[-1],
                        "p99": sorted_vals[int(n * 0.99)] if n >= 100 else sorted_vals[-1],
                    }
                else:
                    hist_summary[name] = {"count": 0}
            snapshot["histograms"] = hist_summary
            snapshot["active_timers"] = len(self._active_timers)
        return snapshot

    def reset(self) -> None:
        """Clear all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._active_timers.clear()

    def get_counter(self, name: str) -> float:
        """Get current counter value."""
        with self._lock:
            return self._counters.get(name, 0)

    def get_gauge(self, name: str) -> float:
        """Get current gauge value."""
        with self._lock:
            return self._gauges.get(name, 0)


# ── C. Scan Tracer ─────────────────────────────────────────────────────


@dataclass
class ModuleTrace:
    """Timing and result data for a single module within a scan."""
    id: str
    duration_ms: float = 0.0
    findings: int = 0
    status: str = "pending"  # pending | running | ok | error | skipped
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "duration_ms": round(self.duration_ms, 2),
            "findings": self.findings,
            "status": self.status,
            "error": self.error,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class ScanTracer:
    """Trace a scan execution with detailed timing.

    Produces an execution receipt:
    {
        "trace_id": "...",
        "target": "example.com",
        "started_at": "...",
        "completed_at": "...",
        "total_duration_ms": 12345,
        "modules": [
            {"id": "recon", "duration_ms": 1234, "findings": 5, "status": "ok"},
            {"id": "auth", "duration_ms": 567, "findings": 2, "status": "ok"},
        ],
        "errors": [],
        "score": 85,
        "grade": "B"
    }
    """

    def __init__(self, target: str, enabled: bool = True) -> None:
        self._enabled = enabled
        self.trace_id: str = _generate_trace_id()
        self.target: str = target
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self._modules: OrderedDict[str, ModuleTrace] = OrderedDict()
        self._errors: List[str] = []
        self._score: Optional[int] = None
        self._lock = threading.Lock()
        self._start_perf: float = 0.0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def start_scan(self) -> None:
        """Mark the scan as started."""
        self.started_at = _utc_iso()
        self._start_perf = time.perf_counter()

    def end_scan(self, score: Optional[int] = None) -> Dict[str, Any]:
        """Mark the scan as completed and return the execution receipt."""
        self.completed_at = _utc_iso()
        total_ms = (time.perf_counter() - self._start_perf) * 1000.0 if self._start_perf else 0.0
        if score is not None:
            self._score = max(MIN_SCORE, min(MAX_SCORE, score))

        receipt: Dict[str, Any] = {
            "trace_id": self.trace_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_ms": round(total_ms, 2),
            "modules": [m.to_dict() for m in self._modules.values()],
            "errors": list(self._errors),
        }
        if self._score is not None:
            receipt["score"] = self._score
            receipt["grade"] = _score_to_grade(self._score)
        return receipt

    def start_module(self, module_id: str) -> None:
        """Begin timing a module."""
        if not self._enabled:
            return
        with self._lock:
            mt = ModuleTrace(
                id=module_id,
                status="running",
                started_at=_utc_iso(),
            )
            self._modules[module_id] = mt

    def end_module(self, module_id: str, findings: int = 0, status: str = "ok", error: Optional[str] = None) -> None:
        """End timing a module and record results."""
        if not self._enabled:
            return
        with self._lock:
            mt = self._modules.get(module_id)
            if mt is None:
                return
            mt.completed_at = _utc_iso()
            if mt.started_at:
                try:
                    started = datetime.fromisoformat(mt.started_at.replace("Z", "+00:00"))
                    ended = datetime.fromisoformat(mt.completed_at.replace("Z", "+00:00"))
                    mt.duration_ms = (ended - started).total_seconds() * 1000.0
                except (ValueError, OSError):
                    mt.duration_ms = 0.0
            mt.findings = findings
            mt.status = status
            mt.error = error
            if error:
                self._errors.append(f"{module_id}: {error}")

    def add_error(self, message: str) -> None:
        """Add an error to the scan trace."""
        self._errors.append(message)

    def set_module_detail(self, module_id: str, key: str, value: Any) -> None:
        """Set an arbitrary detail on a module trace."""
        if not self._enabled:
            return
        with self._lock:
            mt = self._modules.get(module_id)
            if mt:
                mt.details[key] = value

    def get_receipt(self) -> Dict[str, Any]:
        """Return the current execution receipt without ending the scan."""
        total_ms = 0.0
        if self._start_perf and self.started_at:
            total_ms = (time.perf_counter() - self._start_perf) * 1000.0

        receipt: Dict[str, Any] = {
            "trace_id": self.trace_id,
            "target": self.target,
            "started_at": self.started_at,
            "total_duration_ms": round(total_ms, 2),
            "modules": [m.to_dict() for m in self._modules.values()],
            "errors": list(self._errors),
        }
        if self._score is not None:
            receipt["score"] = self._score
            receipt["grade"] = _score_to_grade(self._score)
        return receipt

    def reset(self) -> None:
        """Reset tracer for reuse."""
        self.trace_id = _generate_trace_id()
        self.started_at = None
        self.completed_at = None
        self._modules.clear()
        self._errors.clear()
        self._score = None
        self._start_perf = 0.0


# ── D. Performance Profiler ────────────────────────────────────────────


@dataclass
class ModuleProfile:
    """Performance profile for a single module."""
    module_id: str
    wall_time_ms: float = 0.0
    http_requests: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    findings: int = 0
    status: str = "ok"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_id": self.module_id,
            "wall_time_ms": round(self.wall_time_ms, 2),
            "http_requests": self.http_requests,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "findings": self.findings,
            "status": self.status,
        }


class PerformanceProfiler:
    """Per-module performance profiling.

    Track per-module:
    - Wall clock time
    - Number of HTTP requests made
    - Bytes sent/received
    - Findings produced

    Generates performance report comparing modules.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled
        self._profiles: OrderedDict[str, ModuleProfile] = OrderedDict()
        self._start_times: Dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def start_module(self, module_id: str) -> None:
        """Begin profiling a module."""
        if not self._enabled:
            return
        with self._lock:
            self._start_times[module_id] = time.perf_counter()
            self._profiles[module_id] = ModuleProfile(module_id=module_id)

    def end_module(self, module_id: str, status: str = "ok") -> None:
        """End profiling a module."""
        if not self._enabled:
            return
        with self._lock:
            start = self._start_times.pop(module_id, None)
            profile = self._profiles.get(module_id)
            if profile and start is not None:
                profile.wall_time_ms = (time.perf_counter() - start) * 1000.0
                profile.status = status

    def record_http_request(self, module_id: str, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Record an HTTP request for a module."""
        if not self._enabled:
            return
        with self._lock:
            profile = self._profiles.get(module_id)
            if profile:
                profile.http_requests += 1
                profile.bytes_sent += bytes_sent
                profile.bytes_received += bytes_received

    def record_findings(self, module_id: str, count: int = 1) -> None:
        """Record findings produced by a module."""
        if not self._enabled:
            return
        with self._lock:
            profile = self._profiles.get(module_id)
            if profile:
                profile.findings += count

    def get_report(self) -> Dict[str, Any]:
        """Generate a performance report comparing all profiled modules."""
        with self._lock:
            profiles = [p.to_dict() for p in self._profiles.values()]

        total_wall_ms = sum(p["wall_time_ms"] for p in profiles)
        total_requests = sum(p["http_requests"] for p in profiles)
        total_bytes_sent = sum(p["bytes_sent"] for p in profiles)
        total_bytes_recv = sum(p["bytes_received"] for p in profiles)
        total_findings = sum(p["findings"] for p in profiles)

        # Sort by wall time descending for ranking
        ranked = sorted(profiles, key=lambda p: p["wall_time_ms"], reverse=True)

        report: Dict[str, Any] = {
            "total_wall_time_ms": round(total_wall_ms, 2),
            "total_http_requests": total_requests,
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_recv,
            "total_findings": total_findings,
            "modules": ranked,
            "slowest_module": ranked[0]["module_id"] if ranked else None,
            "fastest_module": ranked[-1]["module_id"] if ranked else None,
        }
        return report

    def get_module_profile(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get the profile for a specific module."""
        with self._lock:
            profile = self._profiles.get(module_id)
            return profile.to_dict() if profile else None

    def reset(self) -> None:
        """Clear all profiles."""
        with self._lock:
            self._profiles.clear()
            self._start_times.clear()


# ── E. Health Monitor ──────────────────────────────────────────────────


class HealthMonitor:
    """System health monitoring.

    Checks:
    - Memory usage (via resource module or /proc/self/status)
    - Disk usage for ~/.reconpro/
    - Network connectivity
    - SSL certificate expiry

    Returns health report with status: healthy/degraded/critical.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information."""
        result: Dict[str, Any] = {"status": "unknown", "rss_mb": 0, "method": "none"}
        try:
            # Try /proc/self/status first (Linux)
            if os.path.exists("/proc/self/status"):
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            kb = int(line.split()[1])
                            result["rss_mb"] = round(kb / 1024, 1)
                            result["method"] = "proc"
                            break
                # Also get VmSize for context
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("VmSize:"):
                            kb = int(line.split()[1])
                            result["vm_size_mb"] = round(kb / 1024, 1)
                            break
            else:
                # Fallback: try resource module
                import resource
                rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                # On Linux, ru_maxrss is in KB; on macOS, in bytes
                if os.uname().sysname == "Darwin":
                    result["rss_mb"] = round(rss / (1024 * 1024), 1)
                else:
                    result["rss_mb"] = round(rss / 1024, 1)
                result["method"] = "resource"
        except Exception:
            pass
        return result

    def _get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage for ~/.reconpro/."""
        result: Dict[str, Any] = {
            "path": str(RECONPRO_HOME),
            "total_mb": 0,
            "used_mb": 0,
            "free_mb": 0,
            "usage_percent": 0,
            "status": "unknown",
        }
        try:
            usage = shutil.disk_usage(str(RECONPRO_HOME))
            total_mb = round(usage.total / (1024 * 1024), 1)
            used_mb = round(usage.used / (1024 * 1024), 1)
            free_mb = round(usage.free / (1024 * 1024), 1)
            percent = round(usage.used / usage.total * 100, 1) if usage.total else 0
            result["total_mb"] = total_mb
            result["used_mb"] = used_mb
            result["free_mb"] = free_mb
            result["usage_percent"] = percent
            if percent > 90:
                result["status"] = "critical"
            elif percent > 75:
                result["status"] = "degraded"
            else:
                result["status"] = "healthy"
        except Exception:
            pass
        return result

    def _get_network_connectivity(self) -> Dict[str, Any]:
        """Check basic network connectivity via DNS resolution."""
        result: Dict[str, Any] = {"status": "unknown", "dns_resolve_ms": 0}
        try:
            start = time.perf_counter()
            socket.getaddrinfo("example.com", 443, socket.AF_INET, socket.SOCK_STREAM)
            elapsed = (time.perf_counter() - start) * 1000.0
            result["dns_resolve_ms"] = round(elapsed, 1)
            result["status"] = "healthy" if elapsed < 2000 else "degraded"
        except socket.gaierror:
            result["status"] = "critical"
        except Exception:
            result["status"] = "unknown"
        return result

    def _get_ssl_check(self) -> Dict[str, Any]:
        """Check SSL certificate for a known site."""
        result: Dict[str, Any] = {
            "host": "example.com",
            "status": "unknown",
            "days_until_expiry": None,
        }
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="example.com")
            conn.settimeout(3)
            conn.connect(("example.com", 443))
            cert = conn.getpeercert()
            conn.close()

            # Parse notAfter
            import email.utils
            for field in cert.get("notAfter", ""):
                pass  # no-op
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = email.utils.parsedate_to_datetime(not_after_str)
                now = datetime.now(timezone.utc)
                days = (not_after - now).days
                result["days_until_expiry"] = days
                if days <= 0:
                    result["status"] = "critical"
                elif days <= 30:
                    result["status"] = "degraded"
                else:
                    result["status"] = "healthy"
        except Exception:
            pass
        return result

    def check_health(self) -> Dict[str, Any]:
        """Run all health checks and return a comprehensive report."""
        if not self._enabled:
            return {"status": "disabled", "checks": {}}

        memory = self._get_memory_usage()
        disk = self._get_disk_usage()
        network = self._get_network_connectivity()
        ssl = self._get_ssl_check()

        checks = {
            "memory": memory,
            "disk": disk,
            "network": network,
            "ssl": ssl,
        }

        # Determine overall status
        statuses = []
        for check in checks.values():
            s = check.get("status", "unknown")
            if s == "critical":
                statuses.append(0)
            elif s == "degraded":
                statuses.append(1)
            elif s == "healthy":
                statuses.append(2)
            else:
                statuses.append(1)  # unknown -> degraded

        worst = min(statuses)
        overall = ["critical", "degraded", "healthy"][worst]

        return {
            "status": overall,
            "timestamp": _utc_iso(),
            "checks": checks,
        }

    def check_memory(self) -> Dict[str, Any]:
        """Run only the memory check."""
        if not self._enabled:
            return {"status": "disabled"}
        return self._get_memory_usage()

    def check_disk(self) -> Dict[str, Any]:
        """Run only the disk check."""
        if not self._enabled:
            return {"status": "disabled"}
        return self._get_disk_usage()

    def check_network(self) -> Dict[str, Any]:
        """Run only the network check."""
        if not self._enabled:
            return {"status": "disabled"}
        return self._get_network_connectivity()


# ── F. Telemetry Manager ───────────────────────────────────────────────


class TelemetryManager:
    """Central telemetry management.

    Controls all observability features:
    - Enable/disable structured logging
    - Enable/disable metrics collection
    - Enable/disable tracing
    - Set output destination
    - Get health report
    - Get performance snapshot
    """

    _instance: Optional["TelemetryManager"] = None
    _init_lock = threading.Lock()

    def __init__(
        self,
        logging_enabled: bool = True,
        metrics_enabled: bool = True,
        tracing_enabled: bool = True,
        profiling_enabled: bool = True,
        health_enabled: bool = True,
        output_file: Optional[str] = None,
    ) -> None:
        self._logging_enabled = logging_enabled
        self._metrics_enabled = metrics_enabled
        self._tracing_enabled = tracing_enabled
        self._profiling_enabled = profiling_enabled
        self._health_enabled = health_enabled
        self._output_file = output_file

        self._logger = StructuredLogger(
            module="telemetry",
            enabled=logging_enabled,
            output_file=output_file,
        )
        self._metrics = MetricsCollector(enabled=metrics_enabled)
        self._health = HealthMonitor(enabled=health_enabled)

    @classmethod
    def get_instance(cls) -> "TelemetryManager":
        """Get or create the singleton TelemetryManager."""
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (for testing)."""
        with cls._init_lock:
            cls._instance = None

    # ── Logger access ────────────────────────────────────────────────

    @property
    def logger(self) -> StructuredLogger:
        return self._logger

    def get_logger(self, module: str = "root") -> StructuredLogger:
        """Create a new logger for the given module."""
        return StructuredLogger(
            module=module,
            enabled=self._logging_enabled,
            output_file=self._output_file,
        )

    # ── Metrics access ───────────────────────────────────────────────

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics

    # ── Health access ────────────────────────────────────────────────

    @property
    def health(self) -> HealthMonitor:
        return self._health

    # ── Enable/disable controls ──────────────────────────────────────

    @property
    def logging_enabled(self) -> bool:
        return self._logging_enabled

    @logging_enabled.setter
    def logging_enabled(self, value: bool) -> None:
        self._logging_enabled = value
        self._logger.enabled = value

    @property
    def metrics_enabled(self) -> bool:
        return self._metrics_enabled

    @metrics_enabled.setter
    def metrics_enabled(self, value: bool) -> None:
        self._metrics_enabled = value
        self._metrics.enabled = value

    @property
    def tracing_enabled(self) -> bool:
        return self._tracing_enabled

    @tracing_enabled.setter
    def tracing_enabled(self, value: bool) -> None:
        self._tracing_enabled = value

    @property
    def profiling_enabled(self) -> bool:
        return self._profiling_enabled

    @profiling_enabled.setter
    def profiling_enabled(self, value: bool) -> None:
        self._profiling_enabled = value

    @property
    def health_enabled(self) -> bool:
        return self._health_enabled

    @health_enabled.setter
    def health_enabled(self, value: bool) -> None:
        self._health_enabled = value
        self._health.enabled = value

    # ── Convenience methods ──────────────────────────────────────────

    def create_tracer(self, target: str) -> ScanTracer:
        """Create a new ScanTracer for a target."""
        return ScanTracer(target=target, enabled=self._tracing_enabled)

    def create_profiler(self) -> PerformanceProfiler:
        """Create a new PerformanceProfiler."""
        return PerformanceProfiler(enabled=self._profiling_enabled)

    def get_health_report(self) -> Dict[str, Any]:
        """Run health checks and return report."""
        return self._health.check_health()

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        return self._metrics.get_snapshot()

    def get_status(self) -> Dict[str, Any]:
        """Get overall telemetry status."""
        return {
            "logging_enabled": self._logging_enabled,
            "metrics_enabled": self._metrics_enabled,
            "tracing_enabled": self._tracing_enabled,
            "profiling_enabled": self._profiling_enabled,
            "health_enabled": self._health_enabled,
            "output_file": self._output_file,
        }
