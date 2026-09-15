"""Tests for reconpro.observability — Observability Layer.

Covers StructuredLogger, MetricsCollector, ScanTracer,
PerformanceProfiler, HealthMonitor, and TelemetryManager.
Also tests the telemetry.py convenience API.
"""

import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest

# Ensure the reconpro package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.observability import (
    HealthMonitor,
    MetricsCollector,
    ModuleTrace,
    PerformanceProfiler,
    ScanTracer,
    StructuredLogger,
    TelemetryManager,
    TimerContext,
    _score_to_grade,
    _utc_iso,
)
from reconpro.telemetry import (
    check_disk,
    check_health,
    check_memory,
    check_network,
    create_profiler,
    get_logger,
    get_metrics,
    get_metrics_snapshot,
    get_telemetry_manager,
    get_telemetry_status,
    increment_counter,
    observe_histogram,
    reset_telemetry,
    set_gauge,
    trace_scan,
)


# ═══════════════════════════════════════════════════════════════════════
# A. StructuredLogger Tests
# ═══════════════════════════════════════════════════════════════════════


class TestStructuredLoggerInit(unittest.TestCase):
    """Test StructuredLogger initialization."""

    def test_default_module_is_root(self):
        logger = StructuredLogger()
        self.assertEqual(logger._module, "root")

    def test_custom_module(self):
        logger = StructuredLogger(module="quantum_fingerprint")
        self.assertEqual(logger._module, "quantum_fingerprint")

    def test_default_enabled(self):
        logger = StructuredLogger()
        self.assertTrue(logger.enabled)

    def test_disabled_on_init(self):
        logger = StructuredLogger(enabled=False)
        self.assertFalse(logger.enabled)

    def test_enable_disable_toggle(self):
        logger = StructuredLogger(enabled=True)
        logger.enabled = False
        self.assertFalse(logger.enabled)
        logger.enabled = True
        self.assertTrue(logger.enabled)


class TestStructuredLoggerOutput(unittest.TestCase):
    """Test StructuredLogger JSON output format."""

    def _capture_log(self, logger, method, event, **kwargs):
        """Capture stdout from a log call and parse JSON."""
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            getattr(logger, method)(event, **kwargs)
        finally:
            sys.stdout = old_stdout
        return json.loads(buf.getvalue().strip())

    def test_info_produces_json(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "info", "scan_start")
        self.assertIsInstance(entry, dict)

    def test_log_has_ts_field(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "info", "event1")
        self.assertIn("ts", entry)
        self.assertRegex(entry["ts"], r"^\d{4}-\d{2}-\d{2}T")

    def test_log_has_level_field(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "info", "event1")
        self.assertEqual(entry["level"], "INFO")

    def test_log_has_module_field(self):
        logger = StructuredLogger(module="my_module")
        entry = self._capture_log(logger, "info", "event1")
        self.assertEqual(entry["module"], "my_module")

    def test_log_has_event_field(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "info", "custom_event")
        self.assertEqual(entry["event"], "custom_event")

    def test_log_includes_extra_fields(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "info", "scan", target="example.com")
        self.assertEqual(entry["target"], "example.com")

    def test_debug_level(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "debug", "debug_event")
        self.assertEqual(entry["level"], "DEBUG")

    def test_warning_level(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "warning", "warn_event")
        self.assertEqual(entry["level"], "WARNING")

    def test_error_level(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "error", "error_event")
        self.assertEqual(entry["level"], "ERROR")

    def test_critical_level(self):
        logger = StructuredLogger(module="test")
        entry = self._capture_log(logger, "critical", "crit_event")
        self.assertEqual(entry["level"], "CRITICAL")

    def test_disabled_logger_produces_no_output(self):
        logger = StructuredLogger(enabled=False)
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            logger.info("should_not_appear")
        finally:
            sys.stdout = old_stdout
        self.assertEqual(buf.getvalue().strip(), "")

    def test_min_level_filters_lower(self):
        logger = StructuredLogger(min_level="WARNING")
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            logger.debug("should_filter")
            logger.info("should_filter_too")
            logger.warning("should_pass")
        finally:
            sys.stdout = old_stdout
        lines = [l for l in buf.getvalue().strip().split("\n") if l]
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["event"], "should_pass")


class TestStructuredLoggerTraceContext(unittest.TestCase):
    """Test trace_id and target context propagation."""

    def _capture_log(self, logger, method, event, **kwargs):
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            getattr(logger, method)(event, **kwargs)
        finally:
            sys.stdout = old_stdout
        return json.loads(buf.getvalue().strip())

    def test_trace_id_appears_after_set(self):
        logger = StructuredLogger(module="test")
        logger.set_trace_context("abc123")
        entry = self._capture_log(logger, "info", "event")
        self.assertEqual(entry["trace_id"], "abc123")

    def test_target_appears_after_set(self):
        logger = StructuredLogger(module="test")
        logger.set_trace_context(None, target="example.com")
        entry = self._capture_log(logger, "info", "event")
        self.assertEqual(entry["target"], "example.com")

    def test_clear_removes_trace_context(self):
        logger = StructuredLogger(module="test")
        logger.set_trace_context("abc123", "example.com")
        logger.clear_trace_context()
        entry = self._capture_log(logger, "info", "event")
        self.assertNotIn("trace_id", entry)
        self.assertNotIn("target", entry)

    def test_child_inherits_trace_context(self):
        logger = StructuredLogger(module="parent")
        logger.set_trace_context("parent_trace", "example.com")
        child = logger.child("child_mod")
        entry = self._capture_log(child, "info", "event")
        self.assertEqual(entry["trace_id"], "parent_trace")
        self.assertEqual(entry["target"], "example.com")


class TestStructuredLoggerFileOutput(unittest.TestCase):
    """Test file output for StructuredLogger."""

    def test_writes_to_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = StructuredLogger(module="file_test", output_file=path)
            logger.info("file_event", key="value")
            logger.close()
            with open(path, "r") as f:
                line = f.readline().strip()
            entry = json.loads(line)
            self.assertEqual(entry["event"], "file_event")
            self.assertEqual(entry["key"], "value")
        finally:
            os.unlink(path)

    def test_file_output_and_stdout(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            logger = StructuredLogger(module="both_test", output_file=path)
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                logger.info("both_event")
            finally:
                sys.stdout = old_stdout
            logger.close()
            # Stdout captured
            stdout_entry = json.loads(buf.getvalue().strip())
            self.assertEqual(stdout_entry["event"], "both_event")
            # File captured
            with open(path, "r") as f:
                file_entry = json.loads(f.readline().strip())
            self.assertEqual(file_entry["event"], "both_event")
        finally:
            os.unlink(path)


class TestStructuredLoggerLogException(unittest.TestCase):
    """Test log_exception method."""

    def test_log_exception_includes_traceback(self):
        logger = StructuredLogger(module="test")
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            try:
                raise ValueError("test error")
            except ValueError as e:
                logger.log_exception("something_failed", exc=e)
        finally:
            sys.stdout = old_stdout
        entry = json.loads(buf.getvalue().strip())
        self.assertEqual(entry["level"], "ERROR")
        self.assertEqual(entry["event"], "something_failed")
        self.assertIn("traceback", entry)
        self.assertIn("ValueError", entry["traceback"])


# ═══════════════════════════════════════════════════════════════════════
# B. MetricsCollector Tests
# ═══════════════════════════════════════════════════════════════════════


class TestMetricsCounter(unittest.TestCase):
    """Test counter metrics."""

    def test_counter_starts_at_zero(self):
        m = MetricsCollector()
        self.assertEqual(m.get_counter("requests"), 0)

    def test_counter_increment_by_default(self):
        m = MetricsCollector()
        m.counter_increment("requests")
        self.assertEqual(m.get_counter("requests"), 1)

    def test_counter_increment_by_amount(self):
        m = MetricsCollector()
        m.counter_increment("requests", 5)
        self.assertEqual(m.get_counter("requests"), 5)

    def test_counter_multiple_increments(self):
        m = MetricsCollector()
        m.counter_increment("req")
        m.counter_increment("req", 3)
        m.counter_increment("req", 2)
        self.assertEqual(m.get_counter("req"), 6)

    def test_counter_negative_amount(self):
        m = MetricsCollector()
        m.counter_increment("net", -3)
        self.assertEqual(m.get_counter("net"), -3)


class TestMetricsGauge(unittest.TestCase):
    """Test gauge metrics."""

    def test_gauge_set(self):
        m = MetricsCollector()
        m.gauge_set("memory", 256)
        self.assertEqual(m.get_gauge("memory"), 256)

    def test_gauge_overwrites(self):
        m = MetricsCollector()
        m.gauge_set("connections", 10)
        m.gauge_set("connections", 20)
        self.assertEqual(m.get_gauge("connections"), 20)

    def test_gauge_default_zero(self):
        m = MetricsCollector()
        self.assertEqual(m.get_gauge("nonexistent"), 0)

    def test_gauge_increment(self):
        m = MetricsCollector()
        m.gauge_increment("queue")
        m.gauge_increment("queue")
        m.gauge_increment("queue")
        self.assertEqual(m.get_gauge("queue"), 3)

    def test_gauge_decrement(self):
        m = MetricsCollector()
        m.gauge_set("queue", 10)
        m.gauge_increment("queue", -3)
        self.assertEqual(m.get_gauge("queue"), 7)


class TestMetricsHistogram(unittest.TestCase):
    """Test histogram metrics."""

    def test_histogram_single_observe(self):
        m = MetricsCollector()
        m.histogram_observe("latency", 100)
        snap = m.get_snapshot()
        h = snap["histograms"]["latency"]
        self.assertEqual(h["count"], 1)
        self.assertEqual(h["min"], 100)
        self.assertEqual(h["max"], 100)
        self.assertEqual(h["avg"], 100)

    def test_histogram_multiple_observes(self):
        m = MetricsCollector()
        for v in [10, 20, 30, 40, 50]:
            m.histogram_observe("latency", v)
        snap = m.get_snapshot()
        h = snap["histograms"]["latency"]
        self.assertEqual(h["count"], 5)
        self.assertEqual(h["min"], 10)
        self.assertEqual(h["max"], 50)
        self.assertEqual(h["avg"], 30)
        self.assertEqual(h["p50"], 30)

    def test_histogram_empty_not_in_snapshot(self):
        m = MetricsCollector()
        snap = m.get_snapshot()
        self.assertNotIn("latency", snap["histograms"])


class TestMetricsTimer(unittest.TestCase):
    """Test timer metrics."""

    def test_timer_context_records_duration(self):
        m = MetricsCollector()
        with m.timer_context("http_request") as tc:
            time.sleep(0.01)  # 10ms
        self.assertGreater(tc.elapsed_ms, 5)
        snap = m.get_snapshot()
        h = snap["histograms"].get("http_request_duration_ms")
        self.assertIsNotNone(h)
        self.assertEqual(h["count"], 1)
        self.assertGreater(h["min"], 0)

    def test_timer_start_stop(self):
        m = MetricsCollector()
        m.timer_start("operation")
        time.sleep(0.005)
        elapsed = m.timer_stop("operation")
        self.assertIsNotNone(elapsed)
        self.assertGreater(elapsed, 2)
        snap = m.get_snapshot()
        h = snap["histograms"]["operation_duration_ms"]
        self.assertEqual(h["count"], 1)

    def test_timer_stop_nonexistent_returns_none(self):
        m = MetricsCollector()
        result = m.timer_stop("nonexistent")
        self.assertIsNone(result)


class TestMetricsSnapshot(unittest.TestCase):
    """Test get_snapshot."""

    def test_snapshot_has_counters(self):
        m = MetricsCollector()
        m.counter_increment("test")
        snap = m.get_snapshot()
        self.assertIn("counters", snap)
        self.assertEqual(snap["counters"]["test"], 1)

    def test_snapshot_has_gauges(self):
        m = MetricsCollector()
        m.gauge_set("g", 42)
        snap = m.get_snapshot()
        self.assertIn("gauges", snap)
        self.assertEqual(snap["gauges"]["g"], 42)

    def test_snapshot_has_histograms(self):
        m = MetricsCollector()
        m.histogram_observe("h", 10)
        snap = m.get_snapshot()
        self.assertIn("histograms", snap)

    def test_snapshot_has_active_timers(self):
        m = MetricsCollector()
        snap = m.get_snapshot()
        self.assertIn("active_timers", snap)


class TestMetricsReset(unittest.TestCase):
    """Test reset clears all metrics."""

    def test_reset_clears_counters(self):
        m = MetricsCollector()
        m.counter_increment("x")
        m.reset()
        self.assertEqual(m.get_counter("x"), 0)

    def test_reset_clears_gauges(self):
        m = MetricsCollector()
        m.gauge_set("x", 10)
        m.reset()
        self.assertEqual(m.get_gauge("x"), 0)

    def test_reset_clears_histograms(self):
        m = MetricsCollector()
        m.histogram_observe("x", 100)
        m.reset()
        snap = m.get_snapshot()
        self.assertEqual(len(snap["histograms"]), 0)

    def test_reset_clears_timers(self):
        m = MetricsCollector()
        m.timer_start("x")
        m.reset()
        self.assertIsNone(m.timer_stop("x"))


class TestMetricsDisabled(unittest.TestCase):
    """Test that disabled metrics collector has minimal overhead."""

    def test_disabled_counter_no_op(self):
        m = MetricsCollector(enabled=False)
        m.counter_increment("x")
        self.assertEqual(m.get_counter("x"), 0)

    def test_disabled_gauge_no_op(self):
        m = MetricsCollector(enabled=False)
        m.gauge_set("x", 99)
        self.assertEqual(m.get_gauge("x"), 0)

    def test_disabled_histogram_no_op(self):
        m = MetricsCollector(enabled=False)
        m.histogram_observe("x", 100)
        snap = m.get_snapshot()
        self.assertNotIn("x", snap["histograms"])

    def test_disabled_timer_no_op(self):
        m = MetricsCollector(enabled=False)
        m.timer_start("x")
        result = m.timer_stop("x")
        self.assertIsNone(result)


class TestMetricsThreadSafety(unittest.TestCase):
    """Test thread safety of metrics collector."""

    def test_concurrent_counter_increments(self):
        m = MetricsCollector()
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [m.counter_increment("race") for _ in range(100)])
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(m.get_counter("race"), 1000)

    def test_concurrent_gauge_sets(self):
        m = MetricsCollector()
        barrier = threading.Barrier(10)
        def set_gauge(val):
            barrier.wait()
            m.gauge_set("shared", val)
        threads = [threading.Thread(target=set_gauge, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Value should be one of the set values (not corrupted)
        val = m.get_gauge("shared")
        self.assertIn(val, range(10))


# ═══════════════════════════════════════════════════════════════════════
# C. ScanTracer Tests
# ═══════════════════════════════════════════════════════════════════════


class TestScanTracerInit(unittest.TestCase):
    """Test ScanTracer initialization."""

    def test_has_trace_id(self):
        t = ScanTracer(target="example.com")
        self.assertTrue(len(t.trace_id) > 0)

    def test_has_target(self):
        t = ScanTracer(target="example.com")
        self.assertEqual(t.target, "example.com")

    def test_trace_id_is_hex(self):
        t = ScanTracer(target="example.com")
        self.assertRegex(t.trace_id, r'^[0-9a-f]+$')

    def test_unique_trace_ids(self):
        t1 = ScanTracer(target="a.com")
        t2 = ScanTracer(target="b.com")
        self.assertNotEqual(t1.trace_id, t2.trace_id)


class TestScanTracerExecution(unittest.TestCase):
    """Test scan execution flow."""

    def test_start_scan_sets_started_at(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        self.assertIsNotNone(t.started_at)

    def test_end_scan_returns_receipt(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        time.sleep(0.01)
        receipt = t.end_scan(score=85)
        self.assertIsInstance(receipt, dict)
        self.assertEqual(receipt["target"], "example.com")
        self.assertIn("trace_id", receipt)
        self.assertIn("started_at", receipt)
        self.assertIn("completed_at", receipt)
        self.assertGreater(receipt["total_duration_ms"], 0)

    def test_receipt_has_score_and_grade(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        receipt = t.end_scan(score=70)
        self.assertEqual(receipt["score"], 70)
        self.assertEqual(receipt["grade"], "B")

    def test_receipt_score_clamped(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        receipt = t.end_scan(score=150)
        self.assertEqual(receipt["score"], 100)
        self.assertEqual(receipt["grade"], "A+")

    def test_receipt_without_score(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        receipt = t.end_scan()
        self.assertNotIn("score", receipt)
        self.assertNotIn("grade", receipt)


class TestScanTracerModules(unittest.TestCase):
    """Test module tracing within a scan."""

    def test_start_and_end_module(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        t.start_module("recon")
        time.sleep(0.005)
        t.end_module("recon", findings=5)
        receipt = t.end_scan(score=80)
        modules = receipt["modules"]
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["id"], "recon")
        self.assertEqual(modules[0]["findings"], 5)
        self.assertEqual(modules[0]["status"], "ok")
        self.assertGreater(modules[0]["duration_ms"], 0)

    def test_multiple_modules(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        for mod in ["recon", "auth", "chain"]:
            t.start_module(mod)
            t.end_module(mod, findings=2)
        receipt = t.end_scan()
        self.assertEqual(len(receipt["modules"]), 3)

    def test_module_error_tracking(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        t.start_module("recon")
        t.end_module("recon", status="error", error="connection refused")
        receipt = t.end_scan()
        self.assertEqual(len(receipt["errors"]), 1)
        self.assertIn("connection refused", receipt["errors"][0])

    def test_add_error(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        t.add_error("global error")
        receipt = t.end_scan()
        self.assertIn("global error", receipt["errors"])

    def test_module_order_preserved(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        for mod in ["auth", "recon", "chain"]:
            t.start_module(mod)
            t.end_module(mod)
        receipt = t.end_scan()
        ids = [m["id"] for m in receipt["modules"]]
        self.assertEqual(ids, ["auth", "recon", "chain"])


class TestScanTracerDisabled(unittest.TestCase):
    """Test that disabled tracer does not track."""

    def test_disabled_no_modules_tracked(self):
        t = ScanTracer(target="example.com", enabled=False)
        t.start_scan()
        t.start_module("recon")
        t.end_module("recon", findings=5)
        receipt = t.end_scan()
        self.assertEqual(len(receipt["modules"]), 0)


class TestScanTracerGetReceipt(unittest.TestCase):
    """Test get_receipt without ending scan."""

    def test_get_receipt_mid_scan(self):
        t = ScanTracer(target="example.com")
        t.start_scan()
        t.start_module("recon")
        receipt = t.get_receipt()
        self.assertEqual(receipt["target"], "example.com")
        self.assertIsNone(receipt.get("completed_at"))


class TestScanTracerReset(unittest.TestCase):
    """Test reset for reuse."""

    def test_reset_clears_state(self):
        t = ScanTracer(target="a.com")
        t.start_scan()
        t.start_module("recon")
        t.end_module("recon")
        old_id = t.trace_id
        t.reset()
        self.assertNotEqual(t.trace_id, old_id)
        self.assertIsNone(t.started_at)
        self.assertEqual(len(t.get_receipt()["modules"]), 0)


# ═══════════════════════════════════════════════════════════════════════
# D. PerformanceProfiler Tests
# ═══════════════════════════════════════════════════════════════════════


class TestProfilerModuleTiming(unittest.TestCase):
    """Test module timing in PerformanceProfiler."""

    def test_start_end_module(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        time.sleep(0.01)
        p.end_module("recon")
        report = p.get_report()
        self.assertEqual(len(report["modules"]), 1)
        self.assertGreater(report["modules"][0]["wall_time_ms"], 5)

    def test_module_status_recorded(self):
        p = PerformanceProfiler()
        p.start_module("auth")
        p.end_module("auth", status="error")
        profile = p.get_module_profile("auth")
        self.assertEqual(profile["status"], "error")


class TestProfilerHttpRequests(unittest.TestCase):
    """Test HTTP request tracking."""

    def test_record_http_request(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        p.record_http_request("recon", bytes_sent=512, bytes_received=8192)
        p.end_module("recon")
        profile = p.get_module_profile("recon")
        self.assertEqual(profile["http_requests"], 1)
        self.assertEqual(profile["bytes_sent"], 512)
        self.assertEqual(profile["bytes_received"], 8192)

    def test_multiple_requests(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        for _ in range(5):
            p.record_http_request("recon", bytes_sent=100, bytes_received=500)
        p.end_module("recon")
        profile = p.get_module_profile("recon")
        self.assertEqual(profile["http_requests"], 5)
        self.assertEqual(profile["bytes_sent"], 500)
        self.assertEqual(profile["bytes_received"], 2500)


class TestProfilerFindings(unittest.TestCase):
    """Test findings tracking."""

    def test_record_findings(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        p.record_findings("recon", 3)
        p.end_module("recon")
        profile = p.get_module_profile("recon")
        self.assertEqual(profile["findings"], 3)

    def test_findings_accumulate(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        p.record_findings("recon", 2)
        p.record_findings("recon", 3)
        p.end_module("recon")
        profile = p.get_module_profile("recon")
        self.assertEqual(profile["findings"], 5)


class TestProfilerReport(unittest.TestCase):
    """Test performance report generation."""

    def test_report_has_totals(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        p.record_http_request("recon", 100, 500)
        p.record_findings("recon", 2)
        p.end_module("recon")
        p.start_module("auth")
        p.record_http_request("auth", 200, 800)
        p.record_findings("auth", 1)
        p.end_module("auth")
        report = p.get_report()
        self.assertEqual(report["total_http_requests"], 2)
        self.assertEqual(report["total_bytes_sent"], 300)
        self.assertEqual(report["total_bytes_received"], 1300)
        self.assertEqual(report["total_findings"], 3)

    def test_report_identifies_slowest(self):
        p = PerformanceProfiler()
        p.start_module("fast")
        p.end_module("fast")
        p.start_module("slow")
        time.sleep(0.02)
        p.end_module("slow")
        report = p.get_report()
        self.assertEqual(report["slowest_module"], "slow")
        self.assertEqual(report["fastest_module"], "fast")

    def test_empty_report(self):
        p = PerformanceProfiler()
        report = p.get_report()
        self.assertEqual(report["total_http_requests"], 0)
        self.assertIsNone(report["slowest_module"])
        self.assertIsNone(report["fastest_module"])

    def test_report_modules_sorted_by_time(self):
        p = PerformanceProfiler()
        p.start_module("a")
        p.end_module("a")
        p.start_module("b")
        time.sleep(0.01)
        p.end_module("b")
        report = p.get_report()
        self.assertEqual(report["modules"][0]["module_id"], "b")


class TestProfilerDisabled(unittest.TestCase):
    """Test disabled profiler."""

    def test_disabled_no_tracking(self):
        p = PerformanceProfiler(enabled=False)
        p.start_module("recon")
        p.record_http_request("recon")
        p.record_findings("recon")
        p.end_module("recon")
        self.assertIsNone(p.get_module_profile("recon"))
        report = p.get_report()
        self.assertEqual(len(report["modules"]), 0)


class TestProfilerReset(unittest.TestCase):
    """Test profiler reset."""

    def test_reset_clears_profiles(self):
        p = PerformanceProfiler()
        p.start_module("recon")
        p.end_module("recon")
        p.reset()
        report = p.get_report()
        self.assertEqual(len(report["modules"]), 0)


# ═══════════════════════════════════════════════════════════════════════
# E. HealthMonitor Tests
# ═══════════════════════════════════════════════════════════════════════


class TestHealthMonitorFormat(unittest.TestCase):
    """Test that health check returns valid format."""

    def test_check_health_returns_dict(self):
        h = HealthMonitor()
        result = h.check_health()
        self.assertIsInstance(result, dict)

    def test_check_health_has_status_field(self):
        h = HealthMonitor()
        result = h.check_health()
        self.assertIn("status", result)
        self.assertIn(result["status"], ["healthy", "degraded", "critical", "disabled"])

    def test_check_health_has_timestamp(self):
        h = HealthMonitor()
        result = h.check_health()
        self.assertIn("timestamp", result)

    def test_check_health_has_checks(self):
        h = HealthMonitor()
        result = h.check_health()
        self.assertIn("checks", result)
        checks = result["checks"]
        self.assertIn("memory", checks)
        self.assertIn("disk", checks)
        self.assertIn("network", checks)
        self.assertIn("ssl", checks)

    def test_disabled_returns_disabled_status(self):
        h = HealthMonitor(enabled=False)
        result = h.check_health()
        self.assertEqual(result["status"], "disabled")


class TestHealthMonitorIndividual(unittest.TestCase):
    """Test individual health checks."""

    def test_memory_check_returns_dict(self):
        h = HealthMonitor()
        result = h.check_memory()
        self.assertIsInstance(result, dict)

    def test_memory_check_has_rss_mb(self):
        h = HealthMonitor()
        result = h.check_memory()
        self.assertIn("rss_mb", result)

    def test_disk_check_returns_dict(self):
        h = HealthMonitor()
        result = h.check_disk()
        self.assertIsInstance(result, dict)

    def test_disk_check_has_usage_percent(self):
        h = HealthMonitor()
        result = h.check_disk()
        self.assertIn("usage_percent", result)

    def test_network_check_returns_dict(self):
        h = HealthMonitor()
        result = h.check_network()
        self.assertIsInstance(result, dict)

    def test_network_check_has_status(self):
        h = HealthMonitor()
        result = h.check_network()
        self.assertIn("status", result)

    def test_individual_checks_respect_disabled(self):
        h = HealthMonitor(enabled=False)
        self.assertEqual(h.check_memory()["status"], "disabled")
        self.assertEqual(h.check_disk()["status"], "disabled")
        self.assertEqual(h.check_network()["status"], "disabled")


# ═══════════════════════════════════════════════════════════════════════
# F. TelemetryManager Tests
# ═══════════════════════════════════════════════════════════════════════


class TestTelemetryManagerInit(unittest.TestCase):
    """Test TelemetryManager initialization."""

    def setUp(self):
        TelemetryManager.reset_instance()

    def tearDown(self):
        TelemetryManager.reset_instance()

    def test_get_instance_returns_same(self):
        m1 = TelemetryManager.get_instance()
        m2 = TelemetryManager.get_instance()
        self.assertIs(m1, m2)

    def test_reset_creates_new(self):
        m1 = TelemetryManager.get_instance()
        TelemetryManager.reset_instance()
        m2 = TelemetryManager.get_instance()
        self.assertIsNot(m1, m2)


class TestTelemetryManagerFeatures(unittest.TestCase):
    """Test enable/disable of individual features."""

    def setUp(self):
        TelemetryManager.reset_instance()

    def tearDown(self):
        TelemetryManager.reset_instance()

    def test_default_all_enabled(self):
        m = TelemetryManager()
        status = m.get_status()
        self.assertTrue(status["logging_enabled"])
        self.assertTrue(status["metrics_enabled"])
        self.assertTrue(status["tracing_enabled"])
        self.assertTrue(status["profiling_enabled"])
        self.assertTrue(status["health_enabled"])

    def test_disable_logging(self):
        m = TelemetryManager(logging_enabled=False)
        self.assertFalse(m.logging_enabled)
        self.assertFalse(m.logger.enabled)

    def test_disable_metrics(self):
        m = TelemetryManager(metrics_enabled=False)
        self.assertFalse(m.metrics_enabled)
        self.assertFalse(m.metrics.enabled)

    def test_toggle_logging(self):
        m = TelemetryManager()
        m.logging_enabled = False
        self.assertFalse(m.logger.enabled)
        m.logging_enabled = True
        self.assertTrue(m.logger.enabled)

    def test_toggle_metrics(self):
        m = TelemetryManager()
        m.metrics_enabled = False
        self.assertFalse(m.metrics.enabled)

    def test_create_tracer_respects_setting(self):
        m = TelemetryManager(tracing_enabled=False)
        t = m.create_tracer("example.com")
        self.assertFalse(t.enabled)

    def test_create_profiler_respects_setting(self):
        m = TelemetryManager(profiling_enabled=False)
        p = m.create_profiler()
        self.assertFalse(p.enabled)

    def test_get_logger_returns_logger(self):
        m = TelemetryManager()
        logger = m.get_logger("test")
        self.assertIsInstance(logger, StructuredLogger)
        self.assertEqual(logger._module, "test")

    def test_get_health_report(self):
        m = TelemetryManager()
        report = m.get_health_report()
        self.assertIn("status", report)

    def test_get_metrics_snapshot(self):
        m = TelemetryManager()
        m.metrics.counter_increment("test")
        snap = m.get_metrics_snapshot()
        self.assertEqual(snap["counters"]["test"], 1)

    def test_get_status_format(self):
        m = TelemetryManager()
        status = m.get_status()
        expected_keys = {"logging_enabled", "metrics_enabled", "tracing_enabled",
                         "profiling_enabled", "health_enabled", "output_file"}
        self.assertEqual(set(status.keys()), expected_keys)


class TestTelemetryManagerGlobalState(unittest.TestCase):
    """Test that singleton manages global state."""

    def setUp(self):
        TelemetryManager.reset_instance()

    def tearDown(self):
        TelemetryManager.reset_instance()

    def test_singleton_metrics_shared(self):
        m = TelemetryManager.get_instance()
        m.metrics.counter_increment("global_counter")
        m2 = TelemetryManager.get_instance()
        self.assertEqual(m2.metrics.get_counter("global_counter"), 1)


# ═══════════════════════════════════════════════════════════════════════
# G. Telemetry Convenience API Tests
# ═══════════════════════════════════════════════════════════════════════


class TestTelemetryConvenienceAPI(unittest.TestCase):
    """Test the telemetry.py convenience functions."""

    def setUp(self):
        TelemetryManager.reset_instance()

    def tearDown(self):
        TelemetryManager.reset_instance()

    def test_get_logger_returns_logger(self):
        logger = get_logger("test_mod")
        self.assertIsInstance(logger, StructuredLogger)

    def test_get_metrics_returns_collector(self):
        metrics = get_metrics()
        self.assertIsInstance(metrics, MetricsCollector)

    def test_trace_scan_returns_tracer(self):
        tracer = trace_scan("example.com")
        self.assertIsInstance(tracer, ScanTracer)
        self.assertEqual(tracer.target, "example.com")

    def test_increment_counter(self):
        increment_counter("conv_test")
        self.assertEqual(get_metrics().get_counter("conv_test"), 1)

    def test_set_gauge(self):
        set_gauge("conv_gauge", 77)
        self.assertEqual(get_metrics().get_gauge("conv_gauge"), 77)

    def test_observe_histogram(self):
        observe_histogram("conv_hist", 42)
        snap = get_metrics_snapshot()
        self.assertEqual(snap["histograms"]["conv_hist"]["count"], 1)

    def test_get_metrics_snapshot(self):
        increment_counter("snap_test")
        snap = get_metrics_snapshot()
        self.assertIn("counters", snap)
        self.assertEqual(snap["counters"]["snap_test"], 1)

    def test_check_health(self):
        result = check_health()
        self.assertIn("status", result)

    def test_check_memory(self):
        result = check_memory()
        self.assertIsInstance(result, dict)

    def test_check_disk(self):
        result = check_disk()
        self.assertIsInstance(result, dict)

    def test_check_network(self):
        result = check_network()
        self.assertIsInstance(result, dict)

    def test_create_profiler(self):
        p = create_profiler()
        self.assertIsInstance(p, PerformanceProfiler)

    def test_get_telemetry_status(self):
        status = get_telemetry_status()
        self.assertIn("logging_enabled", status)

    def test_reset_telemetry(self):
        m1 = TelemetryManager.get_instance()
        reset_telemetry()
        m2 = TelemetryManager.get_instance()
        self.assertIsNot(m1, m2)

    def test_get_telemetry_manager(self):
        m = get_telemetry_manager()
        self.assertIsInstance(m, TelemetryManager)


# ═══════════════════════════════════════════════════════════════════════
# H. Helper Function Tests
# ═══════════════════════════════════════════════════════════════════════


class TestHelperFunctions(unittest.TestCase):
    """Test internal helper functions."""

    def test_utc_iso_format(self):
        ts = _utc_iso()
        self.assertRegex(ts, r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')

    def test_score_to_grade_boundaries(self):
        self.assertEqual(_score_to_grade(95), "A+")
        self.assertEqual(_score_to_grade(90), "A+")
        self.assertEqual(_score_to_grade(85), "A")
        self.assertEqual(_score_to_grade(80), "A")
        self.assertEqual(_score_to_grade(70), "B")
        self.assertEqual(_score_to_grade(65), "B")
        self.assertEqual(_score_to_grade(55), "C")
        self.assertEqual(_score_to_grade(40), "D")
        self.assertEqual(_score_to_grade(20), "F")
        self.assertEqual(_score_to_grade(0), "F")

    def test_score_to_grade_clamped(self):
        self.assertEqual(_score_to_grade(200), "A+")
        self.assertEqual(_score_to_grade(-10), "F")


class TestModuleTraceDataclass(unittest.TestCase):
    """Test ModuleTrace dataclass."""

    def test_default_values(self):
        mt = ModuleTrace(id="test")
        self.assertEqual(mt.id, "test")
        self.assertEqual(mt.duration_ms, 0.0)
        self.assertEqual(mt.findings, 0)
        self.assertEqual(mt.status, "pending")
        self.assertIsNone(mt.error)

    def test_to_dict(self):
        mt = ModuleTrace(id="recon", duration_ms=100.5, findings=3, status="ok")
        d = mt.to_dict()
        self.assertEqual(d["id"], "recon")
        self.assertEqual(d["duration_ms"], 100.5)
        self.assertEqual(d["findings"], 3)
        self.assertEqual(d["status"], "ok")

    def test_to_dict_rounds_duration(self):
        mt = ModuleTrace(id="test", duration_ms=123.456)
        d = mt.to_dict()
        self.assertEqual(d["duration_ms"], 123.46)


class TestTimerContext(unittest.TestCase):
    """Test TimerContext."""

    def test_initial_elapsed_is_zero(self):
        m = MetricsCollector()
        tc = TimerContext(m, "test")
        self.assertEqual(tc.elapsed_ms, 0.0)

    def test_elapsed_after_context(self):
        m = MetricsCollector()
        with TimerContext(m, "test") as tc:
            time.sleep(0.01)
        self.assertGreater(tc.elapsed_ms, 5)


if __name__ == "__main__":
    unittest.main()
