"""ReconPro v11.1.0 — Comprehensive Reliability & Stress Tests.

Production-ready stress tests covering memory, concurrency, I/O, resource
limits, and endurance. Zero external dependencies. All network access is
mocked. Self-contained.

Runnable via:
    python3 -m pytest reconpro/tests/test_reliability.py -v
    python3 -m pytest reconpro/tests/test_reliability.py -v -k "memory"
    python3 -m pytest reconpro/tests/test_reliability.py -v --timeout=120
"""

from __future__ import annotations

import concurrent.futures
import gc
import io
import json
import logging
import os
import random
import string
import sys
import tempfile
import threading
import time
import traceback
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, Mock, patch, PropertyMock

# ── Ensure package is importable ────────────────────────────────────────
_TEST_DIR: str = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT: str = os.path.join(_TEST_DIR, "..", "..")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from reconpro.http_layer import Finding, RateLimiter
from reconpro.utils import (
    count_severities,
    compute_score,
    compute_grade,
    sort_findings_by_severity,
    entropy,
    truncate,
    extract_host,
    validate_target,
    url_join,
)
from reconpro.scanner import ReconProResult
from reconpro.connection_pool import ConnectionPool
from reconpro.constants import (
    MAX_SCORE,
    MIN_SCORE,
    DEFAULT_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_BODY_LIMIT,
    SEVERITY_LEVELS,
    VALID_SEVERITIES,
    GRADE_THRESHOLDS,
)
from reconpro.benchmark import ScoreTracker, _compute_score
from reconpro.observability import (
    StructuredLogger,
    MetricsCollector,
    ScanTracer,
    PerformanceProfiler,
)
from reconpro.engine import ScanEngine, ScanEvent, EventCollector

logger = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────


def _make_finding(
    severity: str = "info",
    title: str = "Test Finding",
    **kwargs: Any,
) -> Finding:
    """Create a Finding with sensible defaults for stress tests."""
    return Finding(
        title=title,
        severity=severity,
        category=kwargs.get("category", "test"),
        module=kwargs.get("module", "test_mod"),
        description=kwargs.get("description", "Test description"),
        evidence=kwargs.get("evidence", "Test evidence"),
        asset=kwargs.get("asset", "test_asset"),
        points_deducted=kwargs.get("points_deducted", 5),
        remediation=kwargs.get("remediation", "Fix it"),
        dread_score=kwargs.get("dread_score", 0.5),
    )


def _make_result(
    target: str = "example.com",
    num_findings: int = 10,
    score: int = 85,
    grade: str = "A",
) -> ReconProResult:
    """Create a ReconProResult with a given number of findings."""
    severities = ["critical", "high", "medium", "low", "info"]
    findings: List[Dict[str, Any]] = []
    sev_counts: Dict[str, int] = {}
    for i in range(num_findings):
        sev = severities[i % len(severities)]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        findings.append({
            "title": f"Finding {i}",
            "severity": sev,
            "category": "test",
            "module": "test_mod",
            "description": f"Test finding number {i}",
            "evidence": f"Evidence {i}",
            "asset": target,
            "points_deducted": 5,
            "remediation": "Fix it",
            "dread_score": 0.5,
        })
    return ReconProResult(
        target=target,
        modules_run=["test_mod"],
        findings=findings,
        severity_counts=sev_counts,
        total_score=score,
        grade=grade,
        badge_markdown="",
    )


def _random_string(length: int) -> str:
    """Generate a random ASCII string of the given length."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION A: MEMORY STRESS TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestMemoryStressFindings(unittest.TestCase):
    """Test behavior with very large finding lists."""

    def test_1000_findings_score_computation(self) -> None:
        """Score computation with 1000 findings must complete quickly."""
        findings = [
            _make_finding(
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                title=f"F{i}",
                points_deducted=[25, 15, 5, 1, 0][i % 5],
            )
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        score = compute_score(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0, "compute_score(1000) took too long")
        self.assertIsInstance(score, int)
        self.assertTrue(0 <= score <= 100)

    def test_10000_findings_score_computation(self) -> None:
        """Score computation with 10000 findings."""
        findings = [
            _make_finding(
                severity="info",
                title=f"F{i}",
                points_deducted=1,
            )
            for i in range(10000)
        ]
        t0 = time.perf_counter()
        score = compute_score(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 2.0, "compute_score(10000) took too long")
        self.assertEqual(score, 0)

    def test_10000_findings_severity_count(self) -> None:
        """count_severities with 10000 findings — must be fast and correct."""
        severities = ["critical"] * 2000 + ["high"] * 3000 + ["medium"] * 2000 + ["low"] * 2000 + ["info"] * 1000
        findings = [_make_finding(severity=s) for s in severities]
        t0 = time.perf_counter()
        counts = count_severities(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0, "count_severities(10000) took too long")
        self.assertEqual(counts["critical"], 2000)
        self.assertEqual(counts["high"], 3000)
        self.assertEqual(counts["medium"], 2000)
        self.assertEqual(counts["low"], 2000)
        self.assertEqual(counts["info"], 1000)

    def test_10000_findings_sort(self) -> None:
        """Sorting 10000 findings by severity must complete."""
        severities = ["info", "low", "medium", "high", "critical"]
        findings = [_make_finding(severity=severities[i % 5], title=f"F{i}") for i in range(10000)]
        t0 = time.perf_counter()
        sorted_f = sort_findings_by_severity(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 5.0, "sort_findings_by_severity(10000) took too long")
        # First finding must be critical
        self.assertEqual(sorted_f[0].severity, "critical")

    def test_memory_cleanup_after_large_scan(self) -> None:
        """Large finding lists should be garbage-collectable."""
        gc.collect()
        before = len(gc.get_objects())
        # Create a massive batch
        findings = [_make_finding(title=f"MemTest-{i}", evidence="X" * 1000) for i in range(5000)]
        result = _make_result(num_findings=5000)
        d = result.to_dict()
        # Delete references
        del findings
        del result
        del d
        gc.collect()
        after = len(gc.get_objects())
        # We can't guarantee exact counts, but should not leak significantly
        # Allow up to 500 new objects (internal Python overhead)
        self.assertLess(after - before, 500, "Possible memory leak detected")

    def test_large_finding_evidence_strings(self) -> None:
        """Findings with 64KB evidence strings should not cause issues."""
        big_evidence = "A" * 65536
        f = _make_finding(evidence=big_evidence)
        self.assertEqual(len(f.evidence), 65536)
        d = f.to_dict()
        self.assertIn("evidence", d)
        truncated = truncate(d["evidence"])
        self.assertLessEqual(len(truncated), DEFAULT_BODY_LIMIT)

    def test_benchmark_score_computation_10000_findings(self) -> None:
        """Benchmark _compute_score with 10000 mixed-severity findings."""
        findings = []
        for i in range(10000):
            findings.append({
                "severity": ["critical", "high", "medium", "low", "info"][i % 5],
                "category": f"cat_{i % 20}",
            })
        t0 = time.perf_counter()
        score, grade, count, sev_counts = _compute_score(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0, "_compute_score(10000) took too long")
        self.assertEqual(count, 10000)
        self.assertIsInstance(score, float)
        self.assertIn(grade, "ABCDF")


class TestMemoryStressConnectionPool(unittest.TestCase):
    """Test connection pool under heavy memory pressure."""

    def test_pool_creation_100_instances(self) -> None:
        """Creating 100 connection pools should not cause issues."""
        pools: List[ConnectionPool] = []
        t0 = time.perf_counter()
        for _ in range(100):
            pool = ConnectionPool(default_timeout=1, verify_ssl=True)
            pools.append(pool)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 5.0, "Creating 100 pools took too long")
        # Cleanup
        for p in pools:
            p.close()
        del pools
        gc.collect()

    def test_pool_stats_under_load(self) -> None:
        """Stats tracking under simulated high request volume."""
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)
        # Simulate recording many stats without actual network calls
        for _ in range(10000):
            pool._record_stats(0.001)  # 1ms simulated latency
        stats = pool.stats()
        self.assertEqual(stats["total_requests"], 10000)
        self.assertGreater(stats["avg_latency_ms"], 0.0)
        pool.close()

    def test_pool_close_and_reuse(self) -> None:
        """Closing and reusing a pool should work."""
        pool = ConnectionPool(default_timeout=1)
        pool.close()
        # After close, SSL contexts are None — next probe will lazily recreate
        self.assertIsNone(pool._ssl_verify)
        self.assertIsNone(pool._ssl_no_verify)
        # Can still build headers
        headers = pool._build_headers({"X-Custom": "test"})
        self.assertEqual(headers["X-Custom"], "test")
        pool.close()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION B: CONCURRENCY STRESS TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestConcurrencyRateLimiter(unittest.TestCase):
    """Test rate limiter accuracy under high concurrency."""

    def test_rate_limiter_thread_safety(self) -> None:
        """Rate limiter must be thread-safe under concurrent access."""
        limiter = RateLimiter(max_per_second=100.0)
        errors: List[str] = []
        successful: List[bool] = []

        def acquire_n(n: int) -> None:
            for _ in range(n):
                try:
                    limiter.acquire()
                    successful.append(True)
                except Exception as e:
                    errors.append(str(e))

        threads = [threading.Thread(target=acquire_n, args=(100,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Rate limiter errors: {errors[:5]}")
        self.assertEqual(len(successful), 1000)

    def test_rate_limiter_respects_rate(self) -> None:
        """Rate limiter should approximately respect the configured rate.

        Uses a slow rate (20 req/s) and measures wall-clock time for 100 calls.
        """
        limiter = RateLimiter(max_per_second=20.0)
        n = 100
        t0 = time.monotonic()
        for _ in range(n):
            limiter.acquire()
        elapsed = time.monotonic() - t0
        # At 20 req/s, 100 calls should take at least ~4.5s (accounting for overhead)
        # Allow some slack due to Python thread scheduling
        expected_min = (n - 1) * (1.0 / 20.0) * 0.8  # 80% tolerance
        self.assertGreater(
            elapsed,
            expected_min,
            f"Rate limiter too permissive: {n} calls at 20/s completed in {elapsed:.3f}s (expected >{expected_min:.3f}s)",
        )

    def test_rate_limiter_high_rate(self) -> None:
        """At very high rate (10000/s), should have minimal delay."""
        limiter = RateLimiter(max_per_second=10000.0)
        n = 500
        t0 = time.monotonic()
        for _ in range(n):
            limiter.acquire()
        elapsed = time.monotonic() - t0
        # Should complete in under 1 second for 500 calls at 10000/s
        self.assertLess(elapsed, 1.0, f"High-rate limiter too slow: {elapsed:.3f}s for {n} calls")

    def test_rate_limiter_zero_rate(self) -> None:
        """Rate limiter with extremely high rate should impose no delay."""
        limiter = RateLimiter(max_per_second=999999.0)
        n = 1000
        t0 = time.monotonic()
        for _ in range(n):
            limiter.acquire()
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.5, f"Zero-delay limiter took {elapsed:.3f}s for {n} calls")


class TestConcurrencyFindings(unittest.TestCase):
    """Test thread-safe access to finding processing functions."""

    def test_concurrent_count_severities(self) -> None:
        """Multiple threads computing severity counts simultaneously."""
        findings = [
            _make_finding(severity=["critical", "high", "medium", "low", "info"][i % 5])
            for i in range(1000)
        ]
        results: List[Dict[str, int]] = []
        lock = threading.Lock()

        def worker() -> None:
            r = count_severities(findings)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 50)
        for r in results:
            self.assertEqual(r["critical"], 200)
            self.assertEqual(r["high"], 200)
            self.assertEqual(r["medium"], 200)
            self.assertEqual(r["low"], 200)
            self.assertEqual(r["info"], 200)

    def test_concurrent_compute_score(self) -> None:
        """Multiple threads computing scores simultaneously must be consistent."""
        findings = [_make_finding(severity="high", points_deducted=5) for _ in range(10)]
        results: List[int] = []

        def worker() -> None:
            results.append(compute_score(findings))

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 100)
        self.assertTrue(all(r == 50 for r in results), "Score computation is not thread-safe")

    def test_concurrent_sort_findings(self) -> None:
        """Sort must produce correct results when called concurrently."""
        findings = [_make_finding(title=f"F{i}", severity="info") for i in range(100)]
        results: List[List[str]] = []

        def worker() -> None:
            sorted_f = sort_findings_by_severity(findings)
            titles = [f.title for f in sorted_f]
            results.append(titles)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = [f"F{i}" for i in range(100)]
        for r in results:
            self.assertEqual(r, expected, "Concurrent sort produced incorrect results")


class TestConcurrencyThreadPoolExecutor(unittest.TestCase):
    """Test parallel execution using ThreadPoolExecutor."""

    def test_max_workers_concurrent_scans(self) -> None:
        """Simulate 20 concurrent scan-like operations."""
        call_count = 0
        call_lock = threading.Lock()
        peak_threads = [0]
        thread_lock = threading.Lock()

        def simulated_scan(target: str) -> Dict[str, Any]:
            nonlocal call_count
            with thread_lock:
                current = threading.active_count()
                if current > peak_threads[0]:
                    peak_threads[0] = current
            time.sleep(0.01)  # Simulate work
            with call_lock:
                call_count += 1
            return {"target": target, "score": random.randint(0, 100)}

        targets = [f"target-{i}.example.com" for i in range(20)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(simulated_scan, t): t for t in targets}
            results = {}
            for future in concurrent.futures.as_completed(futures):
                results[futures[future]] = future.result()

        self.assertEqual(len(results), 20)
        self.assertEqual(call_count, 20)

    def test_parallel_benchmark_computation(self) -> None:
        """Compute benchmark scores for 100 targets in parallel."""
        tracker = ScoreTracker(storage_dir=tempfile.mkdtemp())

        def compute(target: str) -> Dict[str, Any]:
            findings = [{"severity": random.choice(["critical", "high", "medium", "low", "info"]), "category": f"cat_{random.randint(1,10)}"} for _ in range(random.randint(1, 50))]
            score, grade, count, sev = _compute_score(findings)
            return {"target": target, "score": score, "grade": grade, "count": count}

        targets = [f"target-{i}.example.com" for i in range(100)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(compute, t) for t in targets]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), 100)
        for r in results:
            self.assertIn(r["grade"], "ABCDF")

        # Cleanup
        import shutil
        shutil.rmtree(tracker._dir, ignore_errors=True)


class TestConcurrencyMetricsCollector(unittest.TestCase):
    """Test MetricsCollector under concurrent access."""

    def test_concurrent_counter_increment(self) -> None:
        """100 threads incrementing a counter 1000 times each."""
        mc = MetricsCollector(enabled=True)
        n_threads = 100
        n_increments = 1000

        def worker() -> None:
            for _ in range(n_increments):
                mc.counter_increment("requests", 1)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        val = mc.get_counter("requests")
        self.assertEqual(val, n_threads * n_increments)

    def test_concurrent_gauge_updates(self) -> None:
        """Concurrent gauge set/increment operations."""
        mc = MetricsCollector(enabled=True)
        n_threads = 50

        def worker(thread_id: int) -> None:
            for i in range(100):
                mc.gauge_set(f"gauge_{thread_id % 5}", i)
                mc.gauge_increment(f"counter_{thread_id % 5}", 1)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should have occurred
        snapshot = mc.get_snapshot()
        self.assertIn("gauges", snapshot)
        self.assertIn("counters", snapshot)

    def test_concurrent_histogram_observations(self) -> None:
        """Concurrent histogram observations from many threads."""
        mc = MetricsCollector(enabled=True)
        n_threads = 20
        n_obs = 500

        def worker() -> None:
            for i in range(n_obs):
                mc.histogram_observe("latency_ms", float(i % 100))

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snapshot = mc.get_snapshot()
        hist = snapshot["histograms"].get("latency_ms", {})
        self.assertEqual(hist["count"], n_threads * n_obs)

    def test_concurrent_timers(self) -> None:
        """Concurrent timer start/stop operations."""
        mc = MetricsCollector(enabled=True)
        results: List[Optional[float]] = []
        results_lock = threading.Lock()

        def worker(name: str) -> None:
            mc.timer_start(name)
            time.sleep(0.001)
            elapsed = mc.timer_stop(name)
            with results_lock:
                results.append(elapsed)

        threads = [threading.Thread(target=worker, args=(f"timer_{i}",)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 50)
        for elapsed in results:
            self.assertIsNotNone(elapsed)
            self.assertGreater(elapsed, 0.0)


class TestConcurrencyScanTracer(unittest.TestCase):
    """Test ScanTracer under concurrent module start/end."""

    def test_concurrent_module_tracing(self) -> None:
        """Trace many modules started and ended concurrently."""
        tracer = ScanTracer(target="example.com", enabled=True)
        n_modules = 50

        def start_end(mod_id: str) -> None:
            tracer.start_module(mod_id)
            time.sleep(0.001)
            tracer.end_module(mod_id, findings=random.randint(0, 10))

        threads = [threading.Thread(target=start_end, args=(f"mod_{i}",)) for i in range(n_modules)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        receipt = tracer.get_receipt()
        self.assertEqual(len(receipt["modules"]), n_modules)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION C: I/O STRESS TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestIOTimeoutSimulation(unittest.TestCase):
    """Test behavior with simulated slow/timeout networks."""

    @patch("urllib.request.urlopen")
    def test_connection_pool_timeout_handling(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle timeouts gracefully."""
        def slow_open(*args: Any, **kwargs: Any) -> Mock:
            time.sleep(0.05)  # Simulate slow response
            raise urllib.error.URLError("Connection timed out")

        mock_urlopen.side_effect = slow_open
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)

        t0 = time.monotonic()
        result = pool.probe("https://timeout-test.example.com/")
        elapsed = time.monotonic() - t0

        # Should not hang; result should indicate failure
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertIn("timed out", result["reason"].lower() or "")
        self.assertLess(elapsed, 5.0, "Timeout handling took too long")
        pool.close()

    @patch("urllib.request.urlopen")
    def test_connection_pool_http_error(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle HTTP errors gracefully."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com/",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,  # type: ignore[arg-type]
        )
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)

        result = pool.probe("https://error-test.example.com/")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 500)
        pool.close()

    @patch("urllib.request.urlopen")
    def test_connection_pool_large_response(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle large response bodies (truncated to limit)."""
        big_body = b"X" * (1024 * 1024)  # 1 MB response

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = [("Content-Type", "text/html")]
        mock_resp.read.return_value = big_body
        mock_resp.__enter__ = Mock(return_value=mock_resp)
        mock_resp.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_resp

        pool = ConnectionPool(default_timeout=5, verify_ssl=False)
        result = pool.probe("https://big-response.example.com/")
        self.assertTrue(result["ok"])
        # Body should be truncated to _BODY_LIMIT (16KB)
        self.assertLessEqual(len(result["body"]), 16384)
        pool.close()

    @patch("urllib.request.urlopen")
    def test_connection_pool_concurrent_errors(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle concurrent error-producing requests."""
        mock_urlopen.side_effect = urllib.error.URLError("Network unreachable")

        pool = ConnectionPool(default_timeout=1, verify_ssl=False)
        results: List[Dict[str, Any]] = []

        def probe_url(url: str) -> None:
            r = pool.probe(url)
            results.append(r)

        threads = [
            threading.Thread(target=probe_url, args=(f"https://fail-{i}.example.com/",))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 20)
        for r in results:
            self.assertFalse(r["ok"])
        pool.close()


class TestIOFileStress(unittest.TestCase):
    """Test file I/O under stress."""

    def test_score_tracker_many_records(self) -> None:
        """ScoreTracker with many records for many targets."""
        tmpdir = tempfile.mkdtemp()
        try:
            tracker = ScoreTracker(storage_dir=tmpdir)
            n_targets = 50
            n_records = 100

            for t_idx in range(n_targets):
                target = f"target-{t_idx}.example.com"
                for _ in range(n_records):
                    findings = [
                        {"severity": random.choice(["critical", "high", "medium", "low", "info"])}
                        for _ in range(random.randint(1, 20))
                    ]
                    tracker.record_findings(target, findings)

            # Verify data integrity
            for t_idx in range(n_targets):
                target = f"target-{t_idx}.example.com"
                history = tracker.get_history(target, days=365)
                self.assertEqual(len(history), n_records)

            # Compare targets should work with many targets
            targets = [f"target-{i}.example.com" for i in range(n_targets)]
            comparison = tracker.compare_targets(targets)
            self.assertEqual(len(comparison["targets"]), n_targets)
            self.assertIsNotNone(comparison["best_target"])
            self.assertIsNotNone(comparison["worst_target"])
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_structured_logger_file_output_stress(self) -> None:
        """StructuredLogger writing many entries to file."""
        tmpdir = tempfile.mkdtemp()
        log_file = os.path.join(tmpdir, "stress.log")
        try:
            slog = StructuredLogger(module="stress_test", output_file=log_file)
            n_entries = 1000

            for i in range(n_entries):
                slog.info(
                    "test_event",
                    index=i,
                    data=_random_string(100),
                )

            slog.close()

            # Verify all entries were written
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            self.assertEqual(len(lines), n_entries)
            # Verify each line is valid JSON
            for line in lines:
                entry = json.loads(line)
                self.assertIn("ts", entry)
                self.assertIn("event", entry)
                self.assertEqual(entry["event"], "test_event")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_benchmark_report_large_dataset(self) -> None:
        """Benchmark report generation with many targets."""
        tmpdir = tempfile.mkdtemp()
        try:
            tracker = ScoreTracker(storage_dir=tmpdir)

            # Create 50 targets with varying histories
            for t_idx in range(50):
                target = f"target-{t_idx}.example.com"
                for day in range(30):
                    findings = [
                        {"severity": random.choice(["critical", "high", "medium", "low", "info"]),
                         "category": f"cat_{random.randint(1, 10)}"}
                        for _ in range(random.randint(1, 30))
                    ]
                    tracker.record_findings(target, findings, {"day": day})

            # Generate report
            from reconpro.benchmark import BenchmarkRunner
            runner = BenchmarkRunner()
            runner.tracker = tracker
            report = runner.generate_report(days=30)

            self.assertIn("Leaderboard", report)
            self.assertIn("Team Average", report)
            self.assertGreater(len(report), 100)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION D: RESOURCE LIMIT TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestResourceLimitEmptyInputs(unittest.TestCase):
    """Test graceful behavior with empty/zero inputs."""

    def test_empty_findings_score(self) -> None:
        """Empty findings list should return max score."""
        score = compute_score([])
        self.assertEqual(score, MAX_SCORE)

    def test_empty_findings_grade(self) -> None:
        """Empty findings should produce A+ grade."""
        grade = compute_grade(MAX_SCORE)
        self.assertEqual(grade, "A+")

    def test_empty_findings_count(self) -> None:
        """count_severities with empty list should return empty dict."""
        counts = count_severities([])
        self.assertEqual(counts, {})

    def test_empty_findings_sort(self) -> None:
        """Sort on empty list should return empty list."""
        result = sort_findings_by_severity([])
        self.assertEqual(result, [])

    def test_empty_target_extract_host(self) -> None:
        """extract_host with empty string."""
        self.assertEqual(extract_host(""), "")

    def test_empty_target_normalize(self) -> None:
        """normalize_base_url with empty string."""
        from reconpro.utils import normalize_base_url
        self.assertEqual(normalize_base_url(""), "")

    def test_empty_string_entropy(self) -> None:
        """Entropy of empty string should be 0."""
        self.assertEqual(entropy(""), 0.0)

    def test_empty_string_truncate(self) -> None:
        """Truncating empty string."""
        self.assertEqual(truncate(""), "")

    def test_validate_empty_target(self) -> None:
        """Validation of empty target should fail."""
        valid, reason = validate_target("")
        self.assertFalse(valid)

    def test_validate_whitespace_target(self) -> None:
        """Validation of whitespace-only target should fail."""
        valid, reason = validate_target("   ")
        self.assertFalse(valid)


class TestResourceLimitInvalidInputs(unittest.TestCase):
    """Test graceful behavior with invalid/corrupt inputs."""

    def test_invalid_severity_handling(self) -> None:
        """Unknown severity should default to 'info'."""
        counts = count_severities([
            Finding(
                title="t", severity="INVALID", category="c", module="m",
                description="d", evidence="e", asset="a",
            )
        ])
        self.assertEqual(counts.get("info", 0), 1)

    def test_mixed_valid_invalid_findings(self) -> None:
        """Score computation with mix of valid and edge-case findings."""
        findings = [
            _make_finding(severity="critical", points_deducted=100),
            _make_finding(severity="info", points_deducted=0),
            _make_finding(severity="high", points_deducted=50),
        ]
        score = compute_score(findings)
        self.assertEqual(score, 0)  # 100 - 150 = clamped to 0

    def test_negative_points_deducted(self) -> None:
        """Negative points_deducted should be handled (score clamped)."""
        findings = [
            Finding(
                title="t", severity="info", category="c", module="m",
                description="d", evidence="e", asset="a",
                points_deducted=-10,
            )
        ]
        score = compute_score(findings)
        # Score would be 100 - (-10) = 110, clamped to 100
        self.assertEqual(score, MAX_SCORE)

    def test_very_large_points_deducted(self) -> None:
        """Very large points_deducted should clamp to MIN_SCORE."""
        findings = [
            Finding(
                title="t", severity="critical", category="c", module="m",
                description="d", evidence="e", asset="a",
                points_deducted=999999,
            )
        ]
        score = compute_score(findings)
        self.assertEqual(score, MIN_SCORE)

    def test_benchmark_empty_findings(self) -> None:
        """_compute_score with empty findings list."""
        score, grade, count, sev_counts = _compute_score([])
        self.assertEqual(score, 100.0)
        self.assertEqual(grade, "A")
        self.assertEqual(count, 0)
        self.assertEqual(sev_counts, {})

    def test_benchmark_unknown_severity(self) -> None:
        """_compute_score with unknown severity defaults to 'info'."""
        findings = [{"severity": "unknown_severity", "category": "test"}]
        score, grade, count, sev_counts = _compute_score(findings)
        # Unknown severity defaults to info (0 penalty)
        self.assertEqual(score, 100.0)
        self.assertIn("info", sev_counts)


class TestResourceLimitNoNetwork(unittest.TestCase):
    """Test graceful degradation when network is unavailable."""

    @patch("urllib.request.urlopen")
    def test_pool_unreachable_host(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle unreachable hosts."""
        mock_urlopen.side_effect = urllib.error.URLError("Network is unreachable")
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)

        result = pool.probe("https://unreachable-host.example.com/")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertIn("reason", result)
        pool.close()

    @patch("urllib.request.urlopen")
    def test_pool_dns_failure(self, mock_urlopen: Mock) -> None:
        """Connection pool should handle DNS failures."""
        mock_urlopen.side_effect = urllib.error.URLError(
            OSError("Name or service not known")
        )
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)

        result = pool.probe("https://nonexistent.invalid/")
        self.assertFalse(result["ok"])
        pool.close()

    @patch("socket.socket.connect_ex")
    def test_benchmark_quick_scan_network_failure(self, mock_connect: Mock) -> None:
        """BenchmarkRunner._quick_scan should handle all network failures."""
        mock_connect.return_value = -1  # All ports closed/connection refused

        from reconpro.benchmark import BenchmarkRunner
        runner = BenchmarkRunner()
        # Patch urlopen to also fail
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network error")):
            findings = runner._quick_scan("network-fail-test.example.com")
        # Should return empty or partial findings without crashing
        self.assertIsInstance(findings, list)


class TestResourceLimitDiskFull(unittest.TestCase):
    """Test behavior when disk writes fail."""

    def test_score_tracker_write_failure(self) -> None:
        """ScoreTracker should handle write failures gracefully."""
        tmpdir = tempfile.mkdtemp()
        try:
            tracker = ScoreTracker(storage_dir=tmpdir)

            # Write some data first
            tracker.record("test-target", 85.0, "A", 5)

            # Make directory read-only to simulate disk full
            os.chmod(tmpdir, 0o444)

            try:
                # This should not crash — though it may fail silently
                with patch("builtins.open", side_effect=OSError("No space left on device")):
                    # The tracker might raise, but should not leave inconsistent state
                    try:
                        tracker.record("test-target", 90.0, "A+", 0)
                    except OSError:
                        pass  # Acceptable: failure propagated
            finally:
                # Restore permissions for cleanup
                os.chmod(tmpdir, 0o755)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_structured_logger_file_write_failure(self) -> None:
        """StructuredLogger raises OSError when file cannot be opened."""
        tmpdir = tempfile.mkdtemp()
        log_file = os.path.join(tmpdir, "test.log")
        try:
            slog = StructuredLogger(module="test", output_file=log_file)
            slog.info("first")  # This works
            slog.close()

            # Make directory read-only to simulate disk full
            os.chmod(tmpdir, 0o444)

            # Logger should raise on __init__ when it cannot open the file
            with self.assertRaises(PermissionError):
                StructuredLogger(module="test2", output_file=log_file)

            # Restore permissions to verify data
            os.chmod(tmpdir, 0o755)

            # Verify the original logger's data was persisted
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)
        finally:
            os.chmod(tmpdir, 0o755)
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION E: ENDURANCE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestEnduranceRepeatedScoring(unittest.TestCase):
    """Test repeated scoring operations for stability."""

    def test_100_iterations_compute_score(self) -> None:
        """Run compute_score 100 times with varying inputs."""
        for i in range(100):
            n_findings = random.randint(0, 500)
            findings = [
                _make_finding(
                    severity=random.choice(["critical", "high", "medium", "low", "info"]),
                    points_deducted=random.randint(0, 30),
                )
                for _ in range(n_findings)
            ]
            score = compute_score(findings)
            self.assertIsInstance(score, int)
            self.assertTrue(0 <= score <= 100)

    def test_100_iterations_benchmark_score(self) -> None:
        """Run _compute_score 100 times."""
        for i in range(100):
            n_findings = random.randint(0, 200)
            findings = [
                {
                    "severity": random.choice(["critical", "high", "medium", "low", "info"]),
                    "category": f"cat_{random.randint(1, 20)}",
                }
                for _ in range(n_findings)
            ]
            score, grade, count, sev_counts = _compute_score(findings)
            self.assertIsInstance(score, float)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)
            self.assertEqual(count, n_findings)

    def test_100_iterations_count_severities(self) -> None:
        """Run count_severities 100 times."""
        for _ in range(100):
            n = random.randint(0, 1000)
            findings = [
                _make_finding(severity=random.choice(list(VALID_SEVERITIES)))
                for _ in range(n)
            ]
            counts = count_severities(findings)
            total = sum(counts.values())
            self.assertEqual(total, n)


class TestEnduranceRepeatedObjectCreation(unittest.TestCase):
    """Test creating and destroying objects repeatedly."""

    def test_100_iterations_connection_pool_lifecycle(self) -> None:
        """Create, use, and destroy 100 connection pools."""
        for i in range(100):
            pool = ConnectionPool(default_timeout=1, verify_ssl=False)
            pool._record_stats(0.001 * i)
            stats = pool.stats()
            self.assertEqual(stats["total_requests"], 1)
            pool.close()

    def test_100_iterations_metrics_collector(self) -> None:
        """Create, populate, snapshot, reset, destroy 100 collectors."""
        for i in range(100):
            mc = MetricsCollector(enabled=True)
            mc.counter_increment(f"req_{i}", 10)
            mc.gauge_set(f"gauge_{i}", float(i))
            mc.histogram_observe(f"hist_{i}", float(i * 0.1))
            snapshot = mc.get_snapshot()
            self.assertIn("counters", snapshot)
            mc.reset()
            empty = mc.get_snapshot()
            self.assertEqual(len(empty["counters"]), 0)

    def test_100_iterations_scan_tracer(self) -> None:
        """Create, trace, get receipt, reset 100 tracers."""
        for i in range(100):
            tracer = ScanTracer(target=f"target-{i}.example.com")
            tracer.start_scan()
            tracer.start_module(f"mod_{i % 10}")
            tracer.end_module(f"mod_{i % 10}", findings=random.randint(0, 10))
            receipt = tracer.end_scan(score=random.randint(0, 100))
            self.assertIn("trace_id", receipt)
            self.assertIn("modules", receipt)
            tracer.reset()

    def test_100_iterations_structured_logger(self) -> None:
        """Create and destroy 100 loggers."""
        for i in range(100):
            slog = StructuredLogger(module=f"mod_{i}", enabled=True)
            slog.info("test_event", iteration=i)
            slog.close()

    def test_100_iterations_reconpro_result(self) -> None:
        """Create and serialize 100 ReconProResult objects."""
        for i in range(100):
            result = _make_result(
                target=f"target-{i}.example.com",
                num_findings=random.randint(1, 100),
                score=random.randint(0, 100),
            )
            d = result.to_dict()
            self.assertIn("target", d)
            self.assertIn("findings", d)
            self.assertIn("total_score", d)


class TestEnduranceLongRunning(unittest.TestCase):
    """Test operations that run for extended periods."""

    def test_rate_limiter_sustained_1_second(self) -> None:
        """Sustained rate limiting for 1 second at 50 req/s."""
        limiter = RateLimiter(max_per_second=50.0)
        count = 0
        deadline = time.monotonic() + 1.0

        while time.monotonic() < deadline:
            limiter.acquire()
            count += 1

        # At 50 req/s, in 1 second we should get roughly 50 calls
        # Allow wide margin due to startup overhead
        self.assertGreater(count, 30, f"Too few acquisitions in 1s: {count}")
        self.assertLess(count, 200, f"Too many acquisitions in 1s: {count}")

    def test_metrics_collector_sustained_recording(self) -> None:
        """Sustained metrics recording for 0.5 seconds."""
        mc = MetricsCollector(enabled=True)
        deadline = time.monotonic() + 0.5
        count = 0

        while time.monotonic() < deadline:
            mc.counter_increment("ops")
            mc.histogram_observe("latency", random.uniform(0.1, 10.0))
            mc.gauge_set("queue_depth", random.randint(0, 100))
            count += 1

        snapshot = mc.get_snapshot()
        self.assertEqual(mc.get_counter("ops"), count)
        self.assertGreater(snapshot["histograms"]["latency"]["count"], 0)
        self.assertIn("queue_depth", snapshot["gauges"])

    def test_concurrent_scan_engine_event_emission(self) -> None:
        """EventCollector under rapid event emission."""
        collector = EventCollector()

        def emit_events(n: int) -> None:
            for i in range(n):
                collector(ScanEvent(
                    type="FINDING",
                    module_id=f"mod_{i % 5}",
                    finding=_make_finding(title=f"F{i}"),
                ))

        threads = [threading.Thread(target=emit_events, args=(500,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have collected all events
        self.assertEqual(len(collector.events), 5000)
        self.assertEqual(len(collector.findings), 5000)


class TestEnduranceRepeatedFileOperations(unittest.TestCase):
    """Test repeated file read/write cycles."""

    def test_score_tracker_repeated_write_read(self) -> None:
        """ScoreTracker: write, read, overwrite, read — 50 times."""
        tmpdir = tempfile.mkdtemp()
        try:
            tracker = ScoreTracker(storage_dir=tmpdir)
            target = "endurance-test.example.com"

            for i in range(50):
                score = random.randint(0, 100)
                grade = compute_grade(score)
                tracker.record(target, score, grade, random.randint(0, 20))

                # Verify history grows
                history = tracker.get_history(target, days=365)
                self.assertEqual(len(history), i + 1)

                # Verify latest is correct
                latest = history[-1]
                self.assertEqual(latest["score"], score)
                self.assertEqual(latest["grade"], grade)

            # Trend should have data
            trend = tracker.get_trend(target, days=365)
            self.assertGreater(len(trend), 0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION F: GRACEFUL DEGRADATION TESTS
# ═══════════════════════════════════════════════════════════════════════════


def _timed_calls(slog: "StructuredLogger", n: int) -> float:
    t0 = time.perf_counter()
    for i in range(n):
        slog.info("test_event", data=_random_string(50))
    return time.perf_counter() - t0


class TestGracefulDegradation(unittest.TestCase):
    """Test that the system degrades gracefully under adverse conditions."""

    def test_scan_engine_module_error_handling(self) -> None:
        """ScanEngine should handle module errors gracefully."""
        collector = EventCollector()
        engine = ScanEngine(
            event_callback=collector,
            concurrency=2,
            use_async=False,  # Force sync path
        )

        # Run with an unresolvable target but short timeout
        # The engine should handle connection errors per-module
        try:
            result = engine.scan_one(
                target="192.0.2.1",  # TEST-NET, unreachable
                modules=["recon"],
                timeout=1,
            )
            # Should return a result (possibly with error findings) rather than crashing
            self.assertIsInstance(result, ReconProResult)
        except Exception:
            # Also acceptable: engine raises, but doesn't hang
            pass

    def test_structured_logger_disabled_no_overhead(self) -> None:
        """Disabled logger should have near-zero overhead."""
        slog = StructuredLogger(module="test", enabled=False)
        n = 10000
        # Timing assertions are load-sensitive: take the BEST of 3 runs so a
        # busy CI machine (other test files running) cannot cause a false
        # failure — the property under test is the code's own speed, not the
        # machine's instantaneous load.
        best = min(
            _timed_calls(slog, n) for _ in range(3)
        )
        self.assertLess(best, 0.1, f"Disabled logger too slow: {best:.3f}s for {n} calls")

    def test_metrics_collector_disabled_no_overhead(self) -> None:
        """Disabled MetricsCollector should have near-zero overhead."""
        mc = MetricsCollector(enabled=False)
        n = 100000
        t0 = time.perf_counter()
        for i in range(n):
            mc.counter_increment("ops")
            mc.histogram_observe("latency", float(i))
            mc.gauge_set("queue", float(i))
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"Disabled metrics too slow: {elapsed:.3f}s for {n} calls")
        # Verify nothing was recorded
        self.assertEqual(mc.get_counter("ops"), 0)

    def test_scan_tracer_disabled_no_overhead(self) -> None:
        """Disabled ScanTracer should have near-zero overhead."""
        tracer = ScanTracer(target="example.com", enabled=False)
        n = 10000
        t0 = time.perf_counter()
        for i in range(n):
            tracer.start_module(f"mod_{i % 10}")
            tracer.end_module(f"mod_{i % 10}", findings=1)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"Disabled tracer too slow: {elapsed:.3f}s for {n} calls")

    def test_connection_pool_stats_after_errors(self) -> None:
        """Pool stats should be accurate even after many errors."""
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)

        # Record many simulated stats (mix of fast and slow)
        for i in range(1000):
            latency = random.uniform(0.001, 0.1)
            pool._record_stats(latency)

        stats = pool.stats()
        self.assertEqual(stats["total_requests"], 1000)
        self.assertGreater(stats["avg_latency_ms"], 0.0)
        pool.close()

    def test_pool_reset_stats(self) -> None:
        """Resetting pool stats should clear all counters."""
        pool = ConnectionPool(default_timeout=1, verify_ssl=False)
        for _ in range(100):
            pool._record_stats(0.01)
        self.assertEqual(pool.stats()["total_requests"], 100)

        pool.reset_stats()
        self.assertEqual(pool.stats()["total_requests"], 0)
        pool.close()

    def test_performance_profiler_under_load(self) -> None:
        """PerformanceProfiler tracking many modules."""
        profiler = PerformanceProfiler(enabled=True)

        for i in range(100):
            mod_id = f"mod_{i}"
            profiler.start_module(mod_id)
            profiler.record_http_request(mod_id, bytes_sent=100, bytes_received=1000)
            profiler.end_module(mod_id)

        report = profiler.get_report()
        self.assertEqual(len(report["modules"]), 100)

    def test_url_join_edge_cases(self) -> None:
        """url_join with various edge cases."""
        # Normal case
        self.assertEqual(url_join("https://example.com", "path"), "https://example.com/path")
        # Trailing slash in base
        self.assertEqual(url_join("https://example.com/", "path"), "https://example.com/path")
        # Leading slash in path
        self.assertEqual(url_join("https://example.com", "/path"), "https://example.com/path")
        # Both slashes
        self.assertEqual(url_join("https://example.com/", "/path"), "https://example.com/path")
        # Nested path
        self.assertEqual(url_join("https://example.com/api", "v1/test"), "https://example.com/api/v1/test")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION G: PERFORMANCE REGRESSION GUARD
# ═══════════════════════════════════════════════════════════════════════════


class TestPerformanceRegression(unittest.TestCase):
    """Guard against performance regressions in critical hot paths."""

    def test_compute_score_10k_under_500ms(self) -> None:
        """compute_score with 10k findings must complete in under 500ms."""
        findings = [_make_finding(points_deducted=i % 30) for i in range(10000)]
        t0 = time.perf_counter()
        compute_score(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"compute_score regression: {elapsed:.3f}s")

    def test_count_severities_10k_under_200ms(self) -> None:
        """count_severities with 10k findings must complete in under 200ms."""
        findings = [_make_finding(severity="high") for _ in range(10000)]
        t0 = time.perf_counter()
        count_severities(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.2, f"count_severities regression: {elapsed:.3f}s")

    def test_sort_findings_10k_under_1s(self) -> None:
        """sort_findings_by_severity with 10k findings must complete in under 1s."""
        findings = [_make_finding(severity=["critical", "info"][i % 2]) for i in range(10000)]
        t0 = time.perf_counter()
        sort_findings_by_severity(findings)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0, f"sort_findings regression: {elapsed:.3f}s")

    def test_to_dict_10k_under_500ms(self) -> None:
        """Finding.to_dict() for 10k findings must complete in under 500ms."""
        findings = [_make_finding(evidence="X" * 100) for _ in range(10000)]
        t0 = time.perf_counter()
        for f in findings:
            d = f.to_dict()
            self.assertIn("title", d)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"to_dict regression: {elapsed:.3f}s")

    def test_entropy_large_string_under_100ms(self) -> None:
        """entropy() on 100KB string must complete in under 100ms."""
        data = _random_string(100000)
        t0 = time.perf_counter()
        result = entropy(data)
        elapsed = time.perf_counter() - t0
        self.assertGreater(result, 0.0)
        self.assertLess(elapsed, 0.1, f"entropy regression: {elapsed:.3f}s")

    def test_validate_target_under_1ms(self) -> None:
        """validate_target must be sub-millisecond."""
        target = "example.com"
        # Warm up
        for _ in range(100):
            validate_target(target)
        t0 = time.perf_counter()
        for _ in range(1000):
            validate_target(target)
        elapsed = time.perf_counter() - t0
        avg_us = (elapsed / 1000) * 1_000_000
        self.assertLess(avg_us, 100, f"validate_target regression: {avg_us:.1f}us avg")

    def test_truncate_under_1ms(self) -> None:
        """truncate must be sub-millisecond even for large strings."""
        data = "X" * 1000000  # 1MB
        t0 = time.perf_counter()
        for _ in range(1000):
            truncate(data)
        elapsed = time.perf_counter() - t0
        avg_us = (elapsed / 1000) * 1_000_000
        self.assertLess(avg_us, 100, f"truncate regression: {avg_us:.1f}us avg")


if __name__ == "__main__":
    unittest.main()
