"""ReconPro v11.0 — Benchmark Automation System.

Automates continuous performance benchmarking across all ReconPro subsystems.
Provides suite-based benchmarking, historical baseline management, regression
detection, and scheduled execution.

Builds ON TOP of ``benchmark.py`` (ScoreTracker, BenchmarkRunner) and
re-uses ``constants.py`` paths (RECONPRO_HOME, MEMORY_DIR).

Exports:
    BenchmarkResult       – single benchmark measurement with comparison helpers
    BenchmarkSuite        – named collection of related benchmarks
    BenchmarkBaseline     – historical baseline storage and trend tracking
    BenchmarkAutomation   – top-level orchestrator for all automation features

Pure Python. Zero external dependencies. Uses only stdlib.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import sys
import tempfile
import threading
import time
import tracemalloc
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .constants import RECONPRO_HOME, MEMORY_DIR

__all__ = [
    "BenchmarkResult",
    "BenchmarkSuite",
    "BenchmarkBaseline",
    "BenchmarkAutomation",
]

logger = logging.getLogger("reconpro.benchmark_automation")


# ── Helpers ──────────────────────────────────────────────────────────────

def _ensure_dir(path: Path) -> Path:
    """Create directory if it does not exist and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _sparkline(values: list) -> str:
    """Create a tiny ASCII sparkline from numeric *values*."""
    if not values:
        return ""
    blocks = ["\u2581", "\u2582", "\u2583", "\u2584", "\u2585", "\u2586", "\u2587", "\u2588"]
    mn, mx = min(values), max(values)
    rng = mx - mn if mx != mn else 1
    return "".join(
        blocks[min(len(blocks) - 1, int((v - mn) / rng * (len(blocks) - 1)))]
        for v in values
    )


def _safe_serialize(obj: Any) -> Any:
    """Make an object JSON-serializable."""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [_safe_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    return str(obj)


# ── BenchmarkResult ─────────────────────────────────────────────────────


@dataclass
class BenchmarkResult:
    """Single benchmark measurement with comparison helpers.

    Attributes:
        name:       Human-readable benchmark name (e.g. "dict_create_1000")
        category:   Suite category (memory, cpu, io, scanner, module, startup)
        value:      Measured value (time in seconds, memory in bytes, etc.)
        unit:       Unit of measurement ("s", "ms", "bytes", "KB", "ops/s")
        timestamp:  When the benchmark was taken
        iterations: Number of iterations run for this measurement
        context:    Arbitrary extra metadata dict (platform, python version, etc.)
        extra:      Additional numeric measurements (min, max, median, etc.)
    """

    name: str
    category: str
    value: float
    unit: str = "ms"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    iterations: int = 1
    context: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "iterations": self.iterations,
            "context": _safe_serialize(self.context),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BenchmarkResult":
        """Deserialize from a dictionary."""
        ts = data.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        elif not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        return cls(
            name=data["name"],
            category=data.get("category", "unknown"),
            value=float(data["value"]),
            unit=data.get("unit", "ms"),
            timestamp=ts,
            iterations=data.get("iterations", 1),
            context=data.get("context", {}),
            extra=data.get("extra", {}),
        )

    def vs_baseline(self, baseline_value: float) -> Dict[str, Any]:
        """Compare this result against a baseline value.

        Returns a dict with:
            baseline_value, current_value, delta, delta_pct, direction.
        Direction is "improvement", "regression", or "neutral".
        For timing benchmarks, lower is better (regression = increase).
        For throughput, higher is better (regression = decrease).
        """
        if baseline_value == 0:
            delta_pct = 0.0 if self.value == 0 else float("inf")
        else:
            delta_pct = ((self.value - baseline_value) / baseline_value) * 100

        delta = self.value - baseline_value

        # Determine direction based on unit conventions.
        # Timing units (s, ms, us, ns): lower is better.
        # Throughput units (ops/s, req/s): higher is better.
        # Memory units (bytes, KB, MB): lower is better.
        throughput_units = {"ops/s", "req/s", "items/s"}
        lower_is_better = self.unit not in throughput_units

        if lower_is_better:
            if delta > 0:
                direction = "regression"
            elif delta < 0:
                direction = "improvement"
            else:
                direction = "neutral"
        else:
            if delta > 0:
                direction = "improvement"
            elif delta < 0:
                direction = "regression"
            else:
                direction = "neutral"

        return {
            "name": self.name,
            "category": self.category,
            "baseline_value": baseline_value,
            "current_value": self.value,
            "delta": round(delta, 6),
            "delta_pct": round(delta_pct, 2) if abs(delta_pct) != float("inf") else delta_pct,
            "direction": direction,
            "unit": self.unit,
        }

    def vs_previous(self, previous: "BenchmarkResult") -> Optional[Dict[str, Any]]:
        """Compare this result against a previous BenchmarkResult.

        Returns None if the names or units do not match.
        """
        if self.name != previous.name or self.unit != previous.unit:
            return None
        return self.vs_baseline(previous.value)


# ── BenchmarkSuite ──────────────────────────────────────────────────────


@dataclass
class BenchmarkCase:
    """A single callable benchmark within a suite."""
    name: str
    fn: Callable[..., float]
    category: str = "generic"
    unit: str = "ms"
    iterations: int = 5
    warmup: int = 1


class BenchmarkSuite:
    """A named collection of related benchmarks.

    Parameters:
        name:        Suite identifier (e.g. "memory", "cpu")
        description: Human-readable description of what the suite measures
    """

    def __init__(self, name: str, description: str = "") -> None:
        self.name: str = name
        self.description: str = description
        self._cases: List[BenchmarkCase] = []

    def add(
        self,
        name: str,
        fn: Callable[..., float],
        category: str = "",
        unit: str = "ms",
        iterations: int = 5,
        warmup: int = 1,
    ) -> "BenchmarkSuite":
        """Add a benchmark case. Returns self for chaining."""
        self._cases.append(BenchmarkCase(
            name=name,
            fn=fn,
            category=category or self.name,
            unit=unit,
            iterations=iterations,
            warmup=warmup,
        ))
        return self

    def run(self) -> List[BenchmarkResult]:
        """Execute all benchmark cases and return results.

        Each case runs ``warmup`` iterations (discarded) followed by
        ``iterations`` measured iterations. Returns the median value.
        Memory is tracked via tracemalloc for the measured iterations.
        """
        results: List[BenchmarkResult] = []
        for case in self._cases:
            result = self._run_case(case)
            if result is not None:
                results.append(result)
        return results

    def _run_case(self, case: BenchmarkCase) -> Optional[BenchmarkResult]:
        """Run a single benchmark case with warmup and memory tracking."""
        try:
            # Warmup
            for _ in range(case.warmup):
                try:
                    case.fn()
                except Exception:
                    pass  # warmup errors are silently ignored

            # Measured iterations
            times: List[float] = []
            peak_memory = 0

            tracemalloc.start()
            for _ in range(case.iterations):
                t0 = time.perf_counter()
                case.fn()
                t1 = time.perf_counter()
                times.append(t1 - t0)
                _, current_peak = tracemalloc.get_traced_memory()
                peak_memory = max(peak_memory, current_peak)
            tracemalloc.stop()

            times.sort()
            median = times[len(times) // 2]
            mean = sum(times) / len(times)

            # Convert to appropriate unit
            value, unit = self._convert_unit(median, case.unit)
            extra = {
                "min_s": round(min(times), 9),
                "max_s": round(max(times), 9),
                "mean_s": round(mean, 9),
                "median_s": round(median, 9),
                "peak_memory_bytes": peak_memory,
            }

            return BenchmarkResult(
                name=case.name,
                category=case.category,
                value=value,
                unit=unit,
                iterations=case.iterations,
                context={
                    "suite": self.name,
                    "python": sys.version.split()[0],
                    "platform": sys.platform,
                },
                extra=extra,
            )
        except Exception as exc:
            logger.warning("Benchmark case '%s' failed: %s", case.name, exc)
            return None

    @staticmethod
    def _convert_unit(seconds: float, preferred_unit: str) -> Tuple[float, str]:
        """Convert seconds to the preferred unit."""
        if preferred_unit == "ns":
            return round(seconds * 1e9, 2), "ns"
        elif preferred_unit == "us":
            return round(seconds * 1e6, 2), "us"
        elif preferred_unit == "ms":
            return round(seconds * 1000, 4), "ms"
        elif preferred_unit == "s":
            return round(seconds, 6), "s"
        elif preferred_unit == "bytes":
            return round(seconds, 2), "bytes"  # pass-through for memory
        elif preferred_unit == "KB":
            return round(seconds / 1024, 2), "KB"
        else:
            return round(seconds * 1000, 4), "ms"

    def __len__(self) -> int:
        return len(self._cases)

    def __repr__(self) -> str:
        return f"BenchmarkSuite(name={self.name!r}, cases={len(self._cases)})"


# ── BenchmarkBaseline ───────────────────────────────────────────────────


class BenchmarkBaseline:
    """Historical baseline storage and trend tracking.

    Stores baselines at ``RECONPRO_HOME / "memory" / "benchmark_baselines.json"``.
    Each benchmark name has a list of historical values with timestamps.

    Features:
    - Create/update baselines from BenchmarkResult lists
    - Compare results against stored baselines
    - Track trends over time
    - Prune old entries to keep storage bounded
    """

    MAX_HISTORY_PER_BENCHMARK: int = 100
    DEFAULT_BASELINE_FILE: str = "benchmark_baselines.json"

    def __init__(self, storage_dir: Optional[Path] = None) -> None:
        if storage_dir is None:
            storage_dir = MEMORY_DIR
        self._dir = _ensure_dir(storage_dir)
        self._file: Path = self._dir / self.DEFAULT_BASELINE_FILE
        self._data: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        """Load baselines from disk."""
        if self._file.exists():
            try:
                with open(self._file, "r", encoding="utf-8") as fh:
                    self._data = json.load(fh)
                # Validate structure
                if not isinstance(self._data, dict):
                    self._data = {}
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Failed to load baselines from %s: %s", self._file, exc)
                self._data = {}

    def _save(self) -> None:
        """Persist baselines to disk."""
        try:
            _ensure_dir(self._dir)
            with open(self._file, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, default=str)
        except OSError as exc:
            logger.error("Failed to save baselines to %s: %s", self._file, exc)

    def record(self, result: BenchmarkResult) -> None:
        """Record a single benchmark result as a data point.

        If the benchmark name already has history, the new value is appended.
        Old entries beyond MAX_HISTORY_PER_BENCHMARK are pruned.
        """
        with self._lock:
            entry: Dict[str, Any] = {
                "value": result.value,
                "unit": result.unit,
                "timestamp": result.timestamp.isoformat(),
                "epoch": result.timestamp.timestamp(),
                "iterations": result.iterations,
                "extra": result.extra,
            }
            key = f"{result.category}:{result.name}"
            history = self._data.setdefault(key, [])
            history.append(entry)
            # Prune old entries
            if len(history) > self.MAX_HISTORY_PER_BENCHMARK:
                self._data[key] = history[-self.MAX_HISTORY_PER_BENCHMARK:]
            self._save()

    def record_batch(self, results: List[BenchmarkResult]) -> None:
        """Record multiple benchmark results at once."""
        for r in results:
            self.record(r)

    def get_baseline(self, name: str, category: str = "") -> Optional[float]:
        """Get the most recent baseline value for a benchmark.

        Returns the value of the most recent entry, or None if not found.
        """
        key = f"{category}:{name}" if category else name
        with self._lock:
            history = self._data.get(key, [])
            if not history:
                # Try searching by name alone
                for k, v in self._data.items():
                    if k.endswith(f":{name}") or k == name:
                        return v[-1]["value"] if v else None
                return None
            return history[-1]["value"]

    def get_history(
        self, name: str, category: str = "", days: int = 90
    ) -> List[Dict[str, Any]]:
        """Get historical values for a benchmark within the last N days."""
        key = f"{category}:{name}" if category else name
        cutoff = time.time() - days * 86400
        with self._lock:
            history = self._data.get(key, [])
            return [h for h in history if h.get("epoch", 0) >= cutoff]

    def get_trend(
        self, name: str, category: str = "", days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get daily-average trend for a benchmark.

        Each entry has ``date`` (YYYY-MM-DD) and ``avg_value``.
        """
        history = self.get_history(name, category, days)
        if not history:
            return []
        daily: Dict[str, List[float]] = {}
        for h in history:
            ts = h.get("timestamp", "")
            date_str = ts[:10] if len(ts) >= 10 else ts
            daily.setdefault(date_str, []).append(h["value"])
        trend = []
        for date_str in sorted(daily):
            values = daily[date_str]
            avg = sum(values) / len(values)
            trend.append({
                "date": date_str,
                "avg_value": round(avg, 4),
                "samples": len(values),
            })
        return trend

    def get_all_baseline_values(self) -> Dict[str, float]:
        """Get the latest baseline value for every recorded benchmark.

        Returns a dict mapping ``category:name`` -> latest value.
        """
        with self._lock:
            result = {}
            for key, history in self._data.items():
                if history:
                    result[key] = history[-1]["value"]
            return result

    def compare(self, results: List[BenchmarkResult]) -> List[Dict[str, Any]]:
        """Compare a list of results against stored baselines.

        Returns a list of comparison dicts (one per result that has a baseline).
        """
        comparisons = []
        for r in results:
            baseline_value = self.get_baseline(r.name, r.category)
            if baseline_value is not None:
                comparisons.append(r.vs_baseline(baseline_value))
        return comparisons

    def prune(self, days: int = 365) -> int:
        """Remove entries older than *days*.

        Returns the number of entries removed.
        """
        cutoff = time.time() - days * 86400
        removed = 0
        with self._lock:
            for key in list(self._data.keys()):
                original_len = len(self._data[key])
                self._data[key] = [
                    h for h in self._data[key]
                    if h.get("epoch", 0) >= cutoff
                ]
                removed += original_len - len(self._data[key])
                # Remove empty keys
                if not self._data[key]:
                    del self._data[key]
            if removed > 0:
                self._save()
        return removed

    def set_baseline(
        self, name: str, category: str, value: float, unit: str = "ms"
    ) -> None:
        """Manually set a baseline value for a benchmark."""
        result = BenchmarkResult(
            name=name, category=category, value=value, unit=unit
        )
        self.record(result)

    def clear(self) -> None:
        """Remove all baseline data."""
        with self._lock:
            self._data = {}
            self._save()


# ── BenchmarkAutomation ─────────────────────────────────────────────────


class BenchmarkAutomation:
    """Automated benchmark runner for continuous performance tracking.

    Orchestrates benchmark suites, manages baselines, detects regressions,
    and generates reports. Stores results at ``MEMORY_DIR / "benchmarks"``.

    Parameters:
        results_dir:  Override directory for benchmark result files
        baseline_dir: Override directory for baseline storage
    """

    # Regression threshold: percentage change considered a regression
    REGRESSION_THRESHOLD: float = 20.0
    # Default quick-benchmark iteration counts (smaller for speed)
    QUICK_ITERATIONS: int = 3
    # Default full-benchmark iteration counts
    FULL_ITERATIONS: int = 5

    def __init__(
        self,
        results_dir: Optional[Path] = None,
        baseline_dir: Optional[Path] = None,
    ) -> None:
        self._results_dir = _ensure_dir(results_dir or (MEMORY_DIR / "benchmarks"))
        self._baseline = BenchmarkBaseline(baseline_dir)
        self._suites: Dict[str, BenchmarkSuite] = {}
        self._scheduler_timer: Optional[threading.Timer] = None
        self._scheduler_stop = threading.Event()
        self._register_default_suites()

    # ── Suite Registration ────────────────────────────────────────────

    def _register_default_suites(self) -> None:
        """Register the six predefined benchmark suites."""
        self._suites["memory"] = self._build_memory_suite()
        self._suites["cpu"] = self._build_cpu_suite()
        self._suites["io"] = self._build_io_suite()
        self._suites["scanner"] = self._build_scanner_suite()
        self._suites["module"] = self._build_module_suite()
        self._suites["startup"] = self._build_startup_suite()

    @staticmethod
    def _build_memory_suite() -> BenchmarkSuite:
        """Memory allocation and usage patterns."""
        suite = BenchmarkSuite("memory", "Memory allocation and usage patterns")

        # Dict allocation
        for n in (100, 1000, 10000):
            def _bench_dict_alloc(_n=n):
                d = {str(i): i for i in range(_n)}
                return sys.getsizeof(d)
            suite.add(
                f"dict_alloc_{n}",
                _bench_dict_alloc,
                unit="bytes",
                iterations=5,
            )

        # List allocation
        for n in (100, 1000, 10000):
            def _bench_list_alloc(_n=n):
                lst = [i for i in range(_n)]
                return sys.getsizeof(lst)
            suite.add(
                f"list_alloc_{n}",
                _bench_list_alloc,
                unit="bytes",
                iterations=5,
            )

        # String allocation
        for n in (100, 1000, 10000):
            def _bench_str_alloc(_n=n):
                s = "x" * _n
                return sys.getsizeof(s)
            suite.add(
                f"str_alloc_{n}",
                _bench_str_alloc,
                unit="bytes",
                iterations=5,
            )

        # Set allocation
        for n in (100, 1000, 5000):
            def _bench_set_alloc(_n=n):
                s = set(range(_n))
                return sys.getsizeof(s)
            suite.add(
                f"set_alloc_{n}",
                _bench_set_alloc,
                unit="bytes",
                iterations=5,
            )

        # Dict comprehension
        def _bench_dict_comp():
            d = {i: str(i) for i in range(1000)}
            return sys.getsizeof(d)
        suite.add("dict_comprehension_1000", _bench_dict_comp, unit="bytes", iterations=5)

        return suite

    @staticmethod
    def _build_cpu_suite() -> BenchmarkSuite:
        """CPU-bound operation timing."""
        suite = BenchmarkSuite("cpu", "CPU-bound operation timing")

        # String operations
        def _bench_str_concat():
            parts = ["hello"] * 1000
            return len("".join(parts))
        suite.add("str_concat_1000", _bench_str_concat, iterations=10)

        def _bench_str_format():
            return len(f"{'hello' * 100} {42:0.6f} {3.14:.2e}")
        suite.add("str_format", _bench_str_format, iterations=10)

        # Dict operations
        def _bench_dict_lookup():
            d = {str(i): i for i in range(10000)}
            total = 0
            for i in range(10000):
                total += d.get(str(i % 10000), 0)
            return total
        suite.add("dict_lookup_10k", _bench_dict_lookup, iterations=5)

        def _bench_dict_insert():
            d = {}
            for i in range(10000):
                d[str(i)] = i
            return len(d)
        suite.add("dict_insert_10k", _bench_dict_insert, iterations=5)

        # List operations
        def _bench_list_sort():
            lst = list(range(10000, 0, -1))
            lst.sort()
            return lst[0]
        suite.add("list_sort_10k", _bench_list_sort, iterations=5)

        def _bench_list_comp():
            return len([x * 2 for x in range(10000) if x % 3 == 0])
        suite.add("list_comp_10k", _bench_list_comp, iterations=10)

        # JSON serialization
        def _bench_json_encode():
            data = {"key" + str(i): [1, 2, 3] for i in range(1000)}
            return len(json.dumps(data))
        suite.add("json_encode_1k", _bench_json_encode, iterations=5)

        def _bench_json_decode():
            data = json.dumps({"key" + str(i): [1, 2, 3] for i in range(1000)})
            return len(json.loads(data))
        suite.add("json_decode_1k", _bench_json_decode, iterations=5)

        # Regex
        import re
        pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        text = "contact us at test@example.com or admin@corp.org for info"

        def _bench_regex_match():
            return len(pattern.findall(text * 100))
        suite.add("regex_email_find", _bench_regex_match, iterations=10)

        # Math
        def _bench_math_operations():
            total = 0.0
            for i in range(100000):
                total += (i ** 0.5) * 1.1
            return total
        suite.add("math_sqrt_100k", _bench_math_operations, iterations=3)

        return suite

    @staticmethod
    def _build_io_suite() -> BenchmarkSuite:
        """Network and disk I/O timing (local disk operations only for zero-dependency)."""
        suite = BenchmarkSuite("io", "Disk I/O timing")

        # File write
        def _bench_file_write():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".tmp", delete=False
            ) as f:
                f.write("x" * 100000)
                tmp_path = f.name
            os.unlink(tmp_path)
            return 100000
        suite.add("file_write_100KB", _bench_file_write, iterations=5)

        # File read
        def _bench_file_read():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".tmp", delete=False
            ) as f:
                f.write("x" * 100000)
                tmp_path = f.name
            with open(tmp_path, "r") as f:
                _ = f.read()
            os.unlink(tmp_path)
            return 100000
        suite.add("file_read_100KB", _bench_file_read, iterations=5)

        # JSON file round-trip
        def _bench_json_file_roundtrip():
            data = {"key" + str(i): i for i in range(1000)}
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                json.dump(data, f)
                tmp_path = f.name
            with open(tmp_path, "r") as f:
                loaded = json.load(f)
            os.unlink(tmp_path)
            return len(loaded)
        suite.add("json_file_roundtrip_1k", _bench_json_file_roundtrip, iterations=5)

        # Temp directory creation
        def _bench_mkdir_rmdir():
            d = tempfile.mkdtemp()
            os.rmdir(d)
            return 1
        suite.add("mkdir_rmdir", _bench_mkdir_rmdir, iterations=20)

        # Path operations
        def _bench_path_operations():
            p = Path("/some/nested/path/to/file.txt")
            _ = p.parent, p.stem, p.suffix, p.name
            return 1
        suite.add("path_operations", _bench_path_operations, iterations=50)

        return suite

    @staticmethod
    def _build_scanner_suite() -> BenchmarkSuite:
        """Scanner component performance (in-process, no network)."""
        suite = BenchmarkSuite("scanner", "Scanner component performance")

        # Finding creation overhead
        def _bench_finding_dict_create():
            for i in range(100):
                _ = {
                    "title": f"Finding {i}",
                    "severity": "high",
                    "category": "injection",
                    "description": "x" * 200,
                    "evidence": "y" * 100,
                }
            return 100
        suite.add("finding_dict_create_100", _bench_finding_dict_create, iterations=10)

        # URL parsing
        def _bench_url_parsing():
            from urllib.parse import urlparse
            urls = [
                "https://example.com/path?q=1&r=2",
                "http://sub.domain.org:8080/api/v1/endpoint",
                "https://cdn.example.co.uk/static/img.png?v=123",
            ] * 1000
            total = 0
            for u in urls:
                p = urlparse(u)
                total += len(p.hostname or "")
            return total
        suite.add("url_parse_3000", _bench_url_parsing, iterations=5)

        # Header dict construction
        def _bench_header_construction():
            for _ in range(1000):
                h = {
                    "User-Agent": "ReconPro/11.0",
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "keep-alive",
                    "Cache-Control": "no-cache",
                }
            return len(h)
        suite.add("header_construction_1k", _bench_header_construction, iterations=10)

        # Severity sorting
        def _bench_severity_sort():
            import random
            severities = ["critical", "high", "medium", "low", "info"]
            items = [random.choice(severities) for _ in range(10000)]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            items.sort(key=lambda x: order.get(x, 99))
            return len(items)
        suite.add("severity_sort_10k", _bench_severity_sort, iterations=5)

        # Score computation
        def _bench_score_compute():
            for _ in range(100):
                score = max(0, 100 - 5 * 3 - 10 * 2 - 15 * 1 + 3.5)
            return score
        suite.add("score_compute_100", _bench_score_compute, iterations=20)

        return suite

    @staticmethod
    def _build_module_suite() -> BenchmarkSuite:
        """Module load and execution timing (imports that exist)."""
        suite = BenchmarkSuite("module", "Module load and execution timing")

        # JSON module operations
        def _bench_json_module():
            data = {"a": [1, 2, 3], "b": {"c": 4}}
            for _ in range(100):
                s = json.dumps(data)
                _ = json.loads(s)
            return len(s)
        suite.add("json_roundtrip_100", _bench_json_module, iterations=5)

        # Re module operations
        def _bench_re_module():
            import re
            pat = re.compile(r"\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", re.IGNORECASE)
            text = "Email: user@example.com, admin@test.org" * 500
            for _ in range(10):
                _ = pat.findall(text)
            return 1
        suite.add("re_findall_5k_emails", _bench_re_module, iterations=5)

        # Collections module
        def _bench_collections():
            from collections import defaultdict, Counter
            d = defaultdict(int)
            for i in range(10000):
                d[i % 100] += 1
            c = Counter(range(1000))
            return len(d) + len(c)
        suite.add("collections_ops_10k", _bench_collections, iterations=5)

        # Dataclass creation
        def _bench_dataclass():
            from dataclasses import dataclass
            @dataclass
            class Item:
                name: str
                value: int
                flags: list
            items = [Item(f"item_{i}", i, [True, False]) for i in range(1000)]
            return len(items)
        suite.add("dataclass_create_1k", _bench_dataclass, iterations=5)

        # Copy module
        def _bench_copy_deepcopy():
            import copy
            data = {"a": [1, 2, {"b": 3}], "c": [4, 5, 6]}
            for _ in range(100):
                _ = copy.deepcopy(data)
            return 1
        suite.add("deepcopy_100", _bench_copy_deepcopy, iterations=5)

        return suite

    @staticmethod
    def _build_startup_suite() -> BenchmarkSuite:
        """Import time and startup latency."""
        suite = BenchmarkSuite("startup", "Import time and startup latency")

        # Stdlib import timing
        def _bench_import_json():
            import importlib
            mod = importlib.import_module("json")
            return len(dir(mod))
        suite.add("import_json", _bench_import_json, iterations=10)

        def _bench_import_os():
            import importlib
            mod = importlib.import_module("os")
            return len(dir(mod))
        suite.add("import_os", _bench_import_os, iterations=10)

        def _bench_import_re():
            import importlib
            mod = importlib.import_module("re")
            return len(dir(mod))
        suite.add("import_re", _bench_import_re, iterations=10)

        def _bench_import_collections():
            import importlib
            mod = importlib.import_module("collections")
            return len(dir(mod))
        suite.add("import_collections", _bench_import_collections, iterations=10)

        def _bench_import_threading():
            import importlib
            mod = importlib.import_module("threading")
            return len(dir(mod))
        suite.add("import_threading", _bench_import_threading, iterations=10)

        # Constants import
        def _bench_import_constants():
            import importlib
            mod = importlib.import_module("reconpro.constants")
            return len(dir(mod))
        suite.add("import_reconpro_constants", _bench_import_constants, iterations=5)

        return suite

    # ── Run Methods ───────────────────────────────────────────────────

    def run_full_benchmark(self) -> Dict[str, Any]:
        """Execute all registered benchmark suites.

        Returns a comprehensive results dict with per-suite results,
        comparisons against baselines, and regression detection.
        """
        logger.info("Starting full benchmark run")
        all_results: List[BenchmarkResult] = []
        suite_summaries: List[Dict[str, Any]] = []
        errors: List[str] = []
        start_time = time.perf_counter()

        for suite_name, suite in self._suites.items():
            logger.debug("Running suite: %s", suite_name)
            try:
                suite_results = suite.run()
                all_results.extend(suite_results)
                suite_summaries.append({
                    "suite": suite_name,
                    "description": suite.description,
                    "benchmarks_run": len(suite_results),
                    "results": [r.to_dict() for r in suite_results],
                })
            except Exception as exc:
                msg = f"Suite '{suite_name}' failed: {exc}"
                logger.error(msg)
                errors.append(msg)

        elapsed = time.perf_counter() - start_time

        # Record results as baselines
        self._baseline.record_batch(all_results)

        # Compare against previous baselines
        comparisons = self._baseline.compare(all_results)
        regressions = [c for c in comparisons if c.get("direction") == "regression"]

        # Save results file
        results_file = self._save_results(all_results, "full")

        summary = {
            "type": "full",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "total_benchmarks": len(all_results),
            "regressions_detected": len(regressions),
            "results_file": str(results_file),
            "suites": suite_summaries,
            "comparisons": comparisons,
            "regressions": regressions,
            "errors": errors,
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
        }

        logger.info(
            "Full benchmark complete: %d benchmarks, %d regressions, %.2fs",
            len(all_results), len(regressions), elapsed,
        )
        return summary

    def run_quick_benchmark(self) -> Dict[str, Any]:
        """Run a fast subset of critical benchmarks.

        Uses fewer iterations and only the most important benchmarks
        from memory, cpu, and scanner suites.
        """
        logger.info("Starting quick benchmark run")
        all_results: List[BenchmarkResult] = []
        start_time = time.perf_counter()

        # Quick suite: subset of critical benchmarks with fewer iterations
        quick_suite = BenchmarkSuite("quick", "Quick benchmark subset")

        # Memory: only 1k allocations
        def _q_dict_alloc():
            d = {str(i): i for i in range(1000)}
            return sys.getsizeof(d)
        quick_suite.add("dict_alloc_1000", _q_dict_alloc, unit="bytes", iterations=3)

        # CPU: key operations
        def _q_json_encode():
            data = {"key" + str(i): [1, 2, 3] for i in range(1000)}
            return len(json.dumps(data))
        quick_suite.add("json_encode_1k", _q_json_encode, iterations=3)

        def _q_dict_lookup():
            d = {str(i): i for i in range(10000)}
            total = 0
            for i in range(10000):
                total += d.get(str(i % 10000), 0)
            return total
        quick_suite.add("dict_lookup_10k", _q_dict_lookup, iterations=3)

        def _q_list_sort():
            lst = list(range(10000, 0, -1))
            lst.sort()
            return lst[0]
        quick_suite.add("list_sort_10k", _q_list_sort, iterations=3)

        # Scanner: finding creation
        def _q_finding_create():
            for i in range(100):
                _ = {
                    "title": f"Finding {i}",
                    "severity": "high",
                    "category": "injection",
                    "description": "x" * 200,
                }
            return 100
        quick_suite.add("finding_dict_create_100", _q_finding_create, iterations=3)

        # IO: file write
        def _q_file_write():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".tmp", delete=False
            ) as f:
                f.write("x" * 100000)
                tmp_path = f.name
            os.unlink(tmp_path)
            return 100000
        quick_suite.add("file_write_100KB", _q_file_write, iterations=3)

        try:
            all_results = quick_suite.run()
        except Exception as exc:
            logger.error("Quick benchmark failed: %s", exc)

        elapsed = time.perf_counter() - start_time

        # Record and compare
        self._baseline.record_batch(all_results)
        comparisons = self._baseline.compare(all_results)
        regressions = [c for c in comparisons if c.get("direction") == "regression"]

        results_file = self._save_results(all_results, "quick")

        summary = {
            "type": "quick",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "total_benchmarks": len(all_results),
            "regressions_detected": len(regressions),
            "results_file": str(results_file),
            "results": [r.to_dict() for r in all_results],
            "comparisons": comparisons,
            "regressions": regressions,
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
        }

        logger.info(
            "Quick benchmark complete: %d benchmarks, %.2fs",
            len(all_results), elapsed,
        )
        return summary

    def run_component_benchmark(self, component: str) -> Dict[str, Any]:
        """Benchmark a specific component/suite by name.

        Parameters:
            component: Name of a registered suite (memory, cpu, io,
                       scanner, module, startup) or "all".

        Returns:
            Results dict for the requested component.

        Raises:
            ValueError: If the component name is not recognized.
        """
        component_lower = component.lower().strip()

        if component_lower == "all":
            return self.run_full_benchmark()

        if component_lower not in self._suites:
            available = ", ".join(sorted(self._suites.keys()))
            raise ValueError(
                f"Unknown component '{component}'. "
                f"Available: {available}"
            )

        suite = self._suites[component_lower]
        logger.info("Running component benchmark: %s", component_lower)
        start_time = time.perf_counter()

        results = suite.run()
        elapsed = time.perf_counter() - start_time

        self._baseline.record_batch(results)
        comparisons = self._baseline.compare(results)
        regressions = [c for c in comparisons if c.get("direction") == "regression"]

        results_file = self._save_results(results, component_lower)

        return {
            "type": "component",
            "component": component_lower,
            "description": suite.description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "total_benchmarks": len(results),
            "regressions_detected": len(regressions),
            "results_file": str(results_file),
            "results": [r.to_dict() for r in results],
            "comparisons": comparisons,
            "regressions": regressions,
        }

    # ── Comparison & Regression ───────────────────────────────────────

    def compare_with_baseline(self, results: List[BenchmarkResult]) -> List[Dict[str, Any]]:
        """Compare a list of results against stored historical baselines.

        Each comparison includes the baseline value, current value, delta,
        percentage change, and direction (improvement/regression/neutral).
        """
        return self._baseline.compare(results)

    def detect_regression(
        self,
        results: List[BenchmarkResult],
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Detect performance regressions in results.

        A regression is detected when a timing/memory benchmark increases
        by more than *threshold* percent compared to its baseline, or when
        a throughput benchmark decreases by more than *threshold* percent.

        Parameters:
            results:   Benchmark results to check
            threshold: Percentage change threshold (default: REGRESSION_THRESHOLD)

        Returns:
            List of regression details, sorted by severity (worst first).
        """
        if threshold is None:
            threshold = self.REGRESSION_THRESHOLD

        comparisons = self.compare_with_baseline(results)
        regressions = []

        for comp in comparisons:
            pct = comp.get("delta_pct", 0)
            if pct == float("inf") or pct == float("-inf"):
                regressions.append({**comp, "threshold": threshold, "severity": "critical"})
            elif abs(pct) >= threshold and comp["direction"] == "regression":
                severity = "critical" if abs(pct) >= threshold * 2 else "high"
                regressions.append({**comp, "threshold": threshold, "severity": severity})

        # Sort by delta_pct descending (worst regression first)
        regressions.sort(key=lambda r: abs(r.get("delta_pct", 0)), reverse=True)
        return regressions

    # ── Report Generation ─────────────────────────────────────────────

    def generate_benchmark_report(
        self, results: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a comprehensive benchmark report as Markdown.

        If *results* is None, runs a quick benchmark first.

        Returns a markdown-formatted string.
        """
        if results is None:
            results = self.run_quick_benchmark()

        lines: List[str] = []
        lines.append("# ReconPro Benchmark Report")
        lines.append(f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")
        lines.append(f"*Platform: {results.get('platform', sys.platform)}*")
        lines.append(f"*Python: {results.get('python_version', sys.version.split()[0])}*")
        lines.append(f"*Type: {results.get('type', 'unknown')}*")
        lines.append(f"*Duration: {results.get('elapsed_seconds', 0):.2f}s*")
        lines.append("")

        # Summary stats
        total = results.get("total_benchmarks", 0)
        reg_count = results.get("regressions_detected", 0)
        status = "PASS" if reg_count == 0 else "FAIL"
        lines.append(f"## Summary")
        lines.append(f"- **Benchmarks**: {total}")
        lines.append(f"- **Regressions**: {reg_count}")
        lines.append(f"- **Status**: **{status}**")
        lines.append("")

        # Results table
        lines.append("## Results")
        lines.append("")
        lines.append(f"| {'Name':<40} | {'Value':>12} | {'Unit':>8} | {'Memory (peak)':>14} |")
        lines.append(f"|{'─' * 41}|{'─' * 13}|{'─' * 9}|{'─' * 15}|")

        benchmark_results = results.get("results", [])
        # If full benchmark with suites, flatten
        if not benchmark_results and "suites" in results:
            for suite in results["suites"]:
                benchmark_results.extend(suite.get("results", []))

        for r in benchmark_results:
            name = r.get("name", "?")[:40]
            value = r.get("value", 0)
            unit = r.get("unit", "?")
            mem_bytes = r.get("extra", {}).get("peak_memory_bytes", 0)
            mem_str = f"{mem_bytes / 1024:.1f} KB" if mem_bytes > 0 else "N/A"
            lines.append(
                f"| {name:<40} | {value:>12.4f} | {unit:>8} | {mem_str:>14} |"
            )
        lines.append("")

        # Comparisons
        comparisons = results.get("comparisons", [])
        if comparisons:
            lines.append("## Comparison vs Baseline")
            lines.append("")
            lines.append(f"| {'Benchmark':<40} | {'Baseline':>10} | {'Current':>10} | {'Delta':>8} | {'Direction':>12} |")
            lines.append(f"|{'─' * 41}|{'─' * 11}|{'─' * 11}|{'─' * 9}|{'─' * 13}|")
            for c in comparisons:
                name = c.get("name", "?")[:40]
                baseline = c.get("baseline_value", 0)
                current = c.get("current_value", 0)
                pct = c.get("delta_pct", 0)
                direction = c.get("direction", "?")
                pct_str = f"{pct:+.1f}%" if isinstance(pct, (int, float)) else str(pct)
                lines.append(
                    f"| {name:<40} | {baseline:>10.4f} | {current:>10.4f} | {pct_str:>8} | {direction:>12} |"
                )
            lines.append("")

        # Regressions
        regressions = results.get("regressions", [])
        if regressions:
            lines.append("## Regressions Detected")
            lines.append("")
            for r in regressions:
                severity = r.get("severity", "high")
                name = r.get("name", "?")
                pct = r.get("delta_pct", 0)
                pct_str = f"{pct:+.1f}%" if isinstance(pct, (int, float)) else str(pct)
                icon = "CRITICAL" if severity == "critical" else "HIGH"
                lines.append(
                    f"- [{icon}] **{name}**: {pct_str} change "
                    f"(baseline={r.get('baseline_value', '?')}, "
                    f"current={r.get('current_value', '?')})"
                )
            lines.append("")

        # Trend data
        lines.append("## Historical Trends")
        lines.append("")
        all_baselines = self._baseline.get_all_baseline_values()
        if all_baselines:
            lines.append(f"| {'Benchmark':<50} | {'Latest':>12} | {'Samples':>8} |")
            lines.append(f"|{'─' * 51}|{'─' * 13}|{'─' * 9}|")
            for key, value in sorted(all_baselines.items()):
                name = key[:50]
                history = self._baseline.get_history(
                    key.split(":", 1)[1] if ":" in key else key,
                    key.split(":", 1)[0] if ":" in key else "",
                    days=365,
                )
                lines.append(
                    f"| {name:<50} | {value:>12.4f} | {len(history):>8} |"
                )
        else:
            lines.append("No historical baseline data available yet.")
        lines.append("")

        lines.append("---")
        lines.append("*ReconPro Benchmark Automation System*")
        return "\n".join(lines)

    # ── Scheduling ────────────────────────────────────────────────────

    def schedule_benchmarks(
        self,
        interval: float = 3600.0,
        benchmark_type: str = "quick",
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> threading.Timer:
        """Schedule periodic benchmark runs.

        Parameters:
            interval:       Seconds between benchmark runs (default: 1 hour)
            benchmark_type: "quick", "full", or a component name
            callback:       Optional callback invoked with results after each run

        Returns:
            The Timer object (call .cancel() to stop).
        """
        self._scheduler_stop.clear()
        logger.info(
            "Scheduling %s benchmarks every %.0f seconds",
            benchmark_type, interval,
        )

        def _run_and_reschedule() -> None:
            if self._scheduler_stop.is_set():
                return
            try:
                if benchmark_type == "quick":
                    results = self.run_quick_benchmark()
                elif benchmark_type == "full":
                    results = self.run_full_benchmark()
                else:
                    results = self.run_component_benchmark(benchmark_type)
                if callback is not None:
                    try:
                        callback(results)
                    except Exception as cb_err:
                        logger.error("Benchmark callback error: %s", cb_err)
            except Exception as exc:
                logger.error("Scheduled benchmark error: %s", exc)
                logger.debug("Traceback: %s", traceback.format_exc())
            # Reschedule if not stopped
            if not self._scheduler_stop.is_set():
                self._scheduler_timer = threading.Timer(interval, _run_and_reschedule)
                self._scheduler_timer.daemon = True
                self._scheduler_timer.start()

        timer = threading.Timer(interval, _run_and_reschedule)
        timer.daemon = True
        self._scheduler_timer = timer
        timer.start()
        return timer

    def stop_scheduled_benchmarks(self) -> None:
        """Stop any running scheduled benchmark timer."""
        self._scheduler_stop.set()
        if self._scheduler_timer is not None:
            self._scheduler_timer.cancel()
            self._scheduler_timer = None
        logger.info("Scheduled benchmarks stopped")

    # ── Persistence ────────────────────────────────────────────────────

    def _save_results(
        self, results: List[BenchmarkResult], label: str
    ) -> Path:
        """Save benchmark results to a JSON file.

        File is saved to ``self._results_dir / "benchmark_<label>_<timestamp>.json``.
        """
        _ensure_dir(self._results_dir)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_{label}_{ts}.json"
        filepath = self._results_dir / filename

        data = {
            "label": label,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": sys.platform,
            "python_version": sys.version.split()[0],
            "total_results": len(results),
            "results": [r.to_dict() for r in results],
        }

        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
            logger.debug("Results saved to %s", filepath)
        except OSError as exc:
            logger.error("Failed to save results to %s: %s", filepath, exc)

        return filepath

    def load_results(self, filepath: Path) -> List[BenchmarkResult]:
        """Load benchmark results from a previously saved JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            results_data = data.get("results", [])
            return [BenchmarkResult.from_dict(r) for r in results_data]
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.error("Failed to load results from %s: %s", filepath, exc)
            return []

    def list_saved_results(self) -> List[Dict[str, Any]]:
        """List all saved benchmark result files with metadata."""
        files = []
        if not self._results_dir.exists():
            return files
        for path in sorted(self._results_dir.glob("benchmark_*.json")):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                files.append({
                    "path": str(path),
                    "label": data.get("label", "unknown"),
                    "timestamp": data.get("timestamp", ""),
                    "total_results": data.get("total_results", 0),
                })
            except (json.JSONDecodeError, OSError):
                files.append({"path": str(path), "error": "unreadable"})
        return files

    # ── Properties ────────────────────────────────────────────────────

    @property
    def baseline(self) -> BenchmarkBaseline:
        """Access the underlying BenchmarkBaseline instance."""
        return self._baseline

    @property
    def suites(self) -> Dict[str, BenchmarkSuite]:
        """Access the registered benchmark suites."""
        return dict(self._suites)

    @property
    def results_dir(self) -> Path:
        """Access the results storage directory."""
        return self._results_dir

    def add_suite(self, suite: BenchmarkSuite) -> None:
        """Register a custom benchmark suite."""
        self._suites[suite.name] = suite

    def get_suite(self, name: str) -> Optional[BenchmarkSuite]:
        """Get a registered suite by name."""
        return self._suites.get(name)
