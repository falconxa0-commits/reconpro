"""ReconPro v11 — Performance Benchmark Suite.

Micro-benchmarks for critical hot paths: HTTP probe overhead, scan orchestration,
rate limiter, memory allocation, parallel execution. Uses only time.perf_counter —
zero external dependencies.

Runnable via:
    python -m tests.test_performance
    python -m unittest tests.test_performance -v
"""

from __future__ import annotations

import concurrent.futures
import math
import os
import statistics
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

# ── Ensure package is importable ────────────────────────────────────────
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.join(_TEST_DIR, "..", "..")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── Benchmark helpers ───────────────────────────────────────────────────

@dataclass
class BenchResult:
    """Statistical summary of a benchmark run."""
    name: str
    iterations: int
    total_ops: int
    min_us: float
    max_us: float
    mean_us: float
    median_us: float
    ops_per_sec: float

    def row(self) -> str:
        return (
            f"│ {self.name:<40s} │ {self.iterations:>3d} × {self.total_ops:>6d} │"
            f" {self.min_us:>8.1f} │ {self.max_us:>8.1f} │"
            f" {self.mean_us:>8.1f} │ {self.median_us:>8.1f} │"
            f" {self.ops_per_sec:>12.0f} │"
        )


def run_benchmark(
    name: str,
    fn,
    ops_per_iter: int = 1,
    iterations: int = 5,
    warmup: int = 1,
) -> BenchResult:
    """Run *fn* for *iterations*, return min/max/mean/median per-op timing.

    Parameters
    ----------
    name : str
        Human-readable benchmark name.
    fn : callable
        Function to benchmark. May accept no arguments.
    ops_per_iter : int
        Number of logical operations performed by one call to *fn*.
    iterations : int
        Number of timing iterations (after warmup).
    warmup : int
        Number of un-timed warmup iterations.
    """
    # Warmup
    for _ in range(warmup):
        fn()

    times: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        times.append(t1 - t0)

    per_op_us = [t / ops_per_iter * 1_000_000 for t in times]
    total_ops = iterations * ops_per_iter
    total_time = sum(times)
    ops_sec = total_ops / total_time if total_time > 0 else float("inf")

    return BenchResult(
        name=name,
        iterations=iterations,
        total_ops=total_ops,
        min_us=min(per_op_us),
        max_us=max(per_op_us),
        mean_us=statistics.mean(per_op_us),
        median_us=statistics.median(per_op_us),
        ops_per_sec=ops_sec,
    )


def _print_table(results: List[BenchResult], title: str) -> None:
    """Print a formatted benchmark results table."""
    sep = "├" + "─" * 42 + "┼" + "─" * 16 + "┼" + "─" * 11 + "┼" + "─" * 11 + "┼" + "─" * 11 + "┼" + "─" * 11 + "┼" + "─" * 15 + "┤"
    top = "┌" + "─" * 42 + "┬" + "─" * 16 + "┬" + "─" * 11 + "┬" + "─" * 11 + "┬" + "─" * 11 + "┬" + "─" * 11 + "┬" + "─" * 15 + "┐"
    bot = "└" + "─" * 42 + "┴" + "─" * 16 + "┴" + "─" * 11 + "┴" + "─" * 11 + "┴" + "─" * 11 + "┴" + "─" * 11 + "┴" + "─" * 15 + "┘"
    hdr = "│ {:<40s} │ {:>14s} │ {:>9s} │ {:>9s} │ {:>9s} │ {:>9s} │ {:>13s} │".format(
        title[:40], "Iterations", "Min (µs)", "Max (µs)", "Mean (µs)", "Med (µs)", "Ops/sec"
    )

    print()
    print(top)
    print(hdr)
    print(sep)
    for r in results:
        print(r.row())
    print(bot)
    print()


# ══════════════════════════════════════════════════════════════════════════
# 1. Startup Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestStartupBenchmark(unittest.TestCase):
    """Benchmark: cold import time for the reconpro package."""

    def test_cold_import_time(self):
        """Measure time to `import reconpro` in a fresh subprocess."""
        times: List[float] = []
        iterations = 5
        for _ in range(iterations):
            t0 = time.perf_counter()
            result = subprocess.run(
                [sys.executable, "-c", "import reconpro; print('ok')"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=_PROJECT_ROOT,
            )
            t1 = time.perf_counter()
            self.assertEqual(result.stdout.strip(), "ok",
                             f"Import failed: {result.stderr.strip()}")
            times.append(t1 - t0)

        per_call_ms = [t * 1000 for t in times]
        avg = statistics.mean(per_call_ms)
        print(f"\n  🚀 Startup Benchmark: cold import")
        print(f"     Iterations:  {iterations}")
        print(f"     Min:         {min(per_call_ms):.1f} ms")
        print(f"     Max:         {max(per_call_ms):.1f} ms")
        print(f"     Mean:        {avg:.1f} ms")
        print(f"     Median:      {statistics.median(per_call_ms):.1f} ms")

    def test_module_discovery_time(self):
        """Time how long module registry discovery takes."""
        from reconpro.registry import MODULE_REGISTRY, LOCAL_MODULES, ALL_MODULES

        results: List[BenchResult] = []

        def bench_registry_build():
            """Time the module registry discovery."""
            from reconpro.registry import build_module_registry, build_local_modules
            build_module_registry()
            build_local_modules()

        results.append(run_benchmark(
            "Registry discovery (remote+local)",
            bench_registry_build,
            ops_per_iter=1,
            iterations=5,
        ))

        print(f"\n  📦 Module counts: {len(MODULE_REGISTRY)} remote, {len(LOCAL_MODULES)} local, {len(ALL_MODULES)} total")
        _print_table(results, "Module Discovery")


# ══════════════════════════════════════════════════════════════════════════
# 2. HTTP Probe Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestHTTPProbeBenchmark(unittest.TestCase):
    """Benchmark: http_probe overhead with mocked network I/O."""

    def _make_mock_response(self, status: int = 200):
        """Create a mock urllib response."""
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = [
            ("Content-Type", "text/html"), ("Server", "nginx"),
        ]
        mock_resp.read.return_value = b"Hello World" * 100
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_probe_overhead(self):
        """Measure per-probe overhead (serialization, headers, TLS ctx)."""
        from reconpro.http_layer import http_probe

        mock_resp = self._make_mock_response()
        results: List[BenchResult] = []

        # Benchmark: probe overhead with no limiter
        def bench_probe_no_limiter():
            with patch("reconpro.http_layer.urllib.request.urlopen", return_value=mock_resp):
                for _ in range(100):
                    http_probe("https://example.com/", timeout=1)

        results.append(run_benchmark(
            "http_probe ×100 (no limiter)",
            bench_probe_no_limiter,
            ops_per_iter=100,
            iterations=5,
        ))

        # Benchmark: probe overhead with limiter (fast)
        from reconpro.http_layer import RateLimiter
        fast_limiter = RateLimiter(max_per_second=100000)

        def bench_probe_with_limiter():
            with patch("reconpro.http_layer.urllib.request.urlopen", return_value=mock_resp):
                for _ in range(100):
                    http_probe("https://example.com/", timeout=1, limiter=fast_limiter)

        results.append(run_benchmark(
            "http_probe ×100 (fast limiter)",
            bench_probe_with_limiter,
            ops_per_iter=100,
            iterations=5,
        ))

        _print_table(results, "HTTP Probe Overhead")

        # Assert: per-probe overhead target is < 1 ms (1000µs) on developer
        # hardware. GitHub-hosted runners are shared 2-core machines where
        # the identical code measures 14–18 ms/probe (observed 2026-09 on
        # ubuntu-latest, all of 3.11/3.12/3.13): scale the gate under CI so
        # it catches code regressions rather than host speed.
        ci_scale = 20 if os.environ.get("CI") == "true" else 1
        overhead = results[0].median_us
        self.assertLess(overhead, 1000 * ci_scale,
                        f"http_probe overhead {overhead:.0f}µs exceeds "
                        f"{1000 * ci_scale // 1000}ms target "
                        f"(CI-scaled={ci_scale > 1})")

    def test_header_construction(self):
        """Benchmark header dict creation overhead."""
        from reconpro.http_layer import UA

        results: List[BenchResult] = []

        def bench_headers_fresh():
            """Create headers dict from scratch each call (current approach)."""
            for _ in range(10000):
                h = {
                    "User-Agent": UA,
                    "Accept": "application/json,text/html,text/plain,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                h.update({"X-Custom": "value"})

        results.append(run_benchmark(
            "Headers dict (fresh per call) ×10k",
            bench_headers_fresh,
            ops_per_iter=10000,
            iterations=5,
        ))

        def bench_headers_pooled():
            """Pre-build base headers, copy+update."""
            base = {
                "User-Agent": UA,
                "Accept": "application/json,text/html,text/plain,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
            for _ in range(10000):
                h = dict(base)
                h["X-Custom"] = "value"

        results.append(run_benchmark(
            "Headers dict (copy+update) ×10k",
            bench_headers_pooled,
            ops_per_iter=10000,
            iterations=5,
        ))

        _print_table(results, "Header Construction")

    def test_ssl_context_creation(self):
        """Benchmark SSL context creation overhead."""
        import ssl

        results: List[BenchResult] = []

        def bench_ssl_create_default():
            for _ in range(100):
                ssl.create_default_context()

        results.append(run_benchmark(
            "ssl.create_default_context() ×100",
            bench_ssl_create_default,
            ops_per_iter=100,
            iterations=5,
        ))

        def bench_ssl_unverified():
            from reconpro.http_layer import _unverified_context
            for _ in range(100):
                _unverified_context()  # audited opt-in helper, not the private stdlib API

        results.append(run_benchmark(
            "ssl._create_unverified_context() ×100",
            bench_ssl_unverified,
            ops_per_iter=100,
            iterations=5,
        ))

        _print_table(results, "SSL Context Creation")


# ══════════════════════════════════════════════════════════════════════════
# 3. Scan Orchestration Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestScanOrchestrationBenchmark(unittest.TestCase):
    """Benchmark: scan() loop overhead with mocked module runners."""

    def _mock_findings(self, count: int = 0) -> list:
        """Create mock Finding objects."""
        from reconpro.http_layer import Finding
        findings = []
        for i in range(count):
            findings.append(Finding(
                title=f"Test finding {i}",
                severity="info",
                category="test",
                module="bench",
                description="Benchmark test finding",
                evidence="none",
                asset="example.com",
                points_deducted=0,
            ))
        return findings

    def test_scan_loop_overhead(self):
        """Benchmark scan loop overhead: mock the full scan pipeline."""
        results: List[BenchResult] = []

        for n_modules in [0, 5, 10, 20]:
            mod_list = [f"mod_{i}" for i in range(n_modules)]

            def bench_scan_loop(mods=mod_list):
                """Time the scan orchestration overhead with N mocked modules.

                We mock get_module_runner to return instant no-op functions
                and patch the module list that scan() iterates over.
                """
                fake_modules = list(mods)

                def fake_runner(mod_id):
                    return lambda target, base_url, **kwargs: []

                with patch("reconpro.scanner.validate_target", return_value=(True, "")), \
                     patch("reconpro.scanner.get_module_runner", side_effect=fake_runner), \
                     patch("reconpro.scanner.DEFAULT_MODULES", fake_modules):
                    from reconpro.scanner import scan
                    try:
                        scan("example.com", timeout=1)
                    except Exception:
                        pass

            results.append(run_benchmark(
                f"Scan loop ({n_modules} modules)",
                bench_scan_loop,
                ops_per_iter=1,
                iterations=5,
            ))

        _print_table(results, "Scan Orchestration")

    def test_score_computation(self):
        """Benchmark score computation for various finding counts."""
        from reconpro.utils import compute_score, count_severities
        from reconpro.http_layer import Finding

        results: List[BenchResult] = []

        for n_findings in [0, 10, 100, 1000]:
            findings = self._mock_findings(n_findings)

            def bench_score(f=findings):
                compute_score(f)

            results.append(run_benchmark(
                f"compute_score ({n_findings} findings) ×1000",
                bench_score,
                ops_per_iter=1000,
                iterations=5,
            ))

            def bench_count(f=findings):
                count_severities(f)

            results.append(run_benchmark(
                f"count_severities ({n_findings} findings) ×1000",
                bench_count,
                ops_per_iter=1000,
                iterations=5,
            ))

        _print_table(results, "Score & Severity Computation")


# ══════════════════════════════════════════════════════════════════════════
# 4. Rate Limiter Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestRateLimiterBenchmark(unittest.TestCase):
    """Benchmark: RateLimiter acquire() overhead."""

    def test_acquire_no_delay(self):
        """Measure acquire() overhead with infinite rate (no delay)."""
        from reconpro.http_layer import RateLimiter

        results: List[BenchResult] = []

        # Infinite rate — no sleep expected
        limiter = RateLimiter(max_per_second=1e9)

        def bench_acquire_fast():
            for _ in range(10000):
                limiter.acquire()

        results.append(run_benchmark(
            "RateLimiter.acquire() ×10k (infinite rate)",
            bench_acquire_fast,
            ops_per_iter=10000,
            iterations=5,
        ))

        _print_table(results, "Rate Limiter — No Delay")

        # Overhead should be minimal
        overhead_us = results[0].median_us
        self.assertLess(overhead_us, 10,
                        f"RateLimiter.acquire() overhead {overhead_us:.1f}µs too high")

    def test_acquire_with_rate(self):
        """Measure acquire() at 1000/s rate (1ms interval)."""
        from reconpro.http_layer import RateLimiter

        results: List[BenchResult] = []

        # 1000/s → 1ms minimum interval
        limiter = RateLimiter(max_per_second=1000)

        def bench_acquire_1000():
            for _ in range(100):
                limiter.acquire()

        results.append(run_benchmark(
            "RateLimiter.acquire() ×100 (1000/s)",
            bench_acquire_1000,
            ops_per_iter=100,
            iterations=5,
        ))

        _print_table(results, "Rate Limiter — 1000/s Rate")

    def test_thread_contention(self):
        """10 threads × 1000 acquires each with rate limiting."""
        from reconpro.http_layer import RateLimiter

        results: List[BenchResult] = []

        for rate in [100, 1000]:
            limiter = RateLimiter(max_per_second=rate)
            acquires_per_thread = 100

            def bench_contention():
                errors = []
                barrier = threading.Barrier(10)

                def worker():
                    try:
                        barrier.wait(timeout=5)
                    except threading.BrokenBarrierError:
                        return
                    for _ in range(acquires_per_thread):
                        limiter.acquire()

                threads = [threading.Thread(target=worker) for _ in range(10)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)

            total_ops = 10 * acquires_per_thread
            results.append(run_benchmark(
                f"10 threads × {acquires_per_thread} acquires ({rate}/s)",
                bench_contention,
                ops_per_iter=total_ops,
                iterations=3,
            ))

        _print_table(results, "Rate Limiter — Thread Contention")


# ══════════════════════════════════════════════════════════════════════════
# 5. Memory Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestMemoryBenchmark(unittest.TestCase):
    """Benchmark: Finding creation, to_dict(), list operations."""

    def test_finding_creation(self):
        """Measure Finding object creation throughput."""
        from reconpro.http_layer import Finding

        results: List[BenchResult] = []

        def bench_create_10k():
            for _ in range(10000):
                Finding(
                    title="Test Finding",
                    severity="high",
                    category="web",
                    module="recon",
                    description="Benchmark finding",
                    evidence="test",
                    asset="example.com",
                    points_deducted=5,
                    remediation="Fix it",
                    dread_score=0.7,
                )

        results.append(run_benchmark(
            "Finding() creation ×10k",
            bench_create_10k,
            ops_per_iter=10000,
            iterations=5,
        ))

        _print_table(results, "Finding Object Creation")

    def test_finding_to_dict(self):
        """Benchmark Finding.to_dict() serialization."""
        from reconpro.http_layer import Finding

        # Pre-create findings
        findings = [
            Finding(
                title=f"Finding {i}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                category="test",
                module="bench",
                description="Benchmark test finding " * 5,
                evidence="evidence data " * 10,
                asset="example.com",
                points_deducted=i % 20,
                remediation="Fix recommendation",
                dread_score=0.5,
            )
            for i in range(1000)
        ]

        results: List[BenchResult] = []

        def bench_to_dict():
            for f in findings:
                f.to_dict()

        results.append(run_benchmark(
            "Finding.to_dict() ×1000",
            bench_to_dict,
            ops_per_iter=1000,
            iterations=5,
        ))

        _print_table(results, "Finding Serialization")

    def test_result_to_dict(self):
        """Benchmark ReconProResult.to_dict() with many findings."""
        from reconpro.http_layer import Finding
        from reconpro.scanner import ReconProResult

        findings = [
            Finding(
                title=f"Finding {i}",
                severity="high",
                category="test",
                module="bench",
                description="Test",
                evidence="test",
                asset="example.com",
            ).to_dict()
            for i in range(1000)
        ]

        result = ReconProResult(
            target="example.com",
            modules_run=["bench"],
            findings=findings,
            severity_counts={"high": 1000},
            total_score=0,
            grade="F",
            badge_markdown="!",
        )

        results: List[BenchResult] = []

        def bench_result_to_dict():
            result.to_dict()

        results.append(run_benchmark(
            "ReconProResult.to_dict() (1000 findings) ×1000",
            bench_result_to_dict,
            ops_per_iter=1000,
            iterations=5,
        ))

        _print_table(results, "ReconProResult Serialization")

    def test_list_operations(self):
        """Benchmark list operations on findings."""
        from reconpro.http_layer import Finding
        from reconpro.utils import sort_findings_by_severity

        findings = [
            Finding(
                title=f"Finding {i}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                category="test",
                module="bench",
                description="Test",
                evidence="test",
                asset="example.com",
            )
            for i in range(5000)
        ]

        results: List[BenchResult] = []

        def bench_extend():
            target = []
            target.extend(findings)

        results.append(run_benchmark(
            "list.extend(5000 findings) ×100",
            bench_extend,
            ops_per_iter=100,
            iterations=5,
        ))

        def bench_sort():
            sort_findings_by_severity(findings)

        results.append(run_benchmark(
            "sort_findings_by_severity(5000) ×100",
            bench_sort,
            ops_per_iter=100,
            iterations=5,
        ))

        def bench_filter():
            [f for f in findings if f.severity == "critical"]

        results.append(run_benchmark(
            "list comprehension filter(5000) ×100",
            bench_filter,
            ops_per_iter=100,
            iterations=5,
        ))

        _print_table(results, "List Operations on Findings")


# ══════════════════════════════════════════════════════════════════════════
# 6. Parallel Execution Benchmark
# ══════════════════════════════════════════════════════════════════════════

class TestParallelExecutionBenchmark(unittest.TestCase):
    """Benchmark: ThreadPoolExecutor overhead for parallel scanning."""

    def test_threadpool_overhead(self):
        """Measure thread pool overhead with no-op tasks."""
        results: List[BenchResult] = []

        for n_workers in [1, 2, 4, 8]:
            n_tasks = n_workers * 10

            def bench_pool(nw=n_workers, nt=n_tasks):
                def noop():
                    pass
                with concurrent.futures.ThreadPoolExecutor(max_workers=nw) as pool:
                    futures = [pool.submit(noop) for _ in range(nt)]
                    concurrent.futures.wait(futures)

            results.append(run_benchmark(
                f"ThreadPoolExecutor ({n_workers}w, {n_tasks} tasks) ×100",
                bench_pool,
                ops_per_iter=n_tasks,
                iterations=5,
            ))

        _print_table(results, "ThreadPoolExecutor Overhead")

    def test_threadpool_with_result_collection(self):
        """Benchmark result collection patterns."""
        results: List[BenchResult] = []

        # Pattern A: as_completed loop (current parallel.py approach)
        def bench_as_completed():
            n = 40
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(lambda: ("target", {"findings": []}, None)): i
                           for i in range(n)}
                collected = []
                for f in concurrent.futures.as_completed(futures):
                    collected.append(f.result())

        results.append(run_benchmark(
            "as_completed collection (40 tasks) ×100",
            bench_as_completed,
            ops_per_iter=40,
            iterations=5,
        ))

        # Pattern B: callback-based collection
        def bench_callback():
            n = 40
            collected_cb = []
            lock = threading.Lock()

            def on_done(f):
                with lock:
                    collected_cb.append(f.result())

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(lambda: ("target", {"findings": []}, None))
                           for _ in range(n)]
                for f in futures:
                    f.add_done_callback(on_done)
                concurrent.futures.wait(futures)

        results.append(run_benchmark(
            "Callback collection (40 tasks) ×100",
            bench_callback,
            ops_per_iter=40,
            iterations=5,
        ))

        # Pattern C: executor.map (simpler)
        def bench_map():
            n = 40
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: ("target", {"findings": []}, None), range(n)))

        results.append(run_benchmark(
            "executor.map collection (40 tasks) ×100",
            bench_map,
            ops_per_iter=40,
            iterations=5,
        ))

        _print_table(results, "Result Collection Patterns")


# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

def run_all_benchmarks() -> None:
    """Run all benchmark test classes and print a summary."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add only performance test classes
    for cls in [
        TestStartupBenchmark,
        TestHTTPProbeBenchmark,
        TestScanOrchestrationBenchmark,
        TestRateLimiterBenchmark,
        TestMemoryBenchmark,
        TestParallelExecutionBenchmark,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)

    print("\n" + "=" * 100)
    print(f"  ReconPro v11 Performance Benchmark Summary")
    print(f"  Ran {result.testsRun} benchmarks | "
          f"{'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 100)


if __name__ == "__main__":
    run_all_benchmarks()
