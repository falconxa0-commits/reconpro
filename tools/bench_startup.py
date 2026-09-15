#!/usr/bin/env python3
"""Cold-start startup benchmark for the ReconPro CLI.

Measures the wall-clock time of a SUBPROCESS cold import of
`reconpro.cli` followed by execution of `main(['--version'])`, i.e. the
true "user runs the CLI" path including interpreter startup.

N runs (default 7), reporting min / median / avg / p95 / max in
milliseconds. Exit code 1 if the MEDIAN exceeds the threshold
(default 100 ms — the target after the lazy-import performance work
lands; see tools/ci_local.sh STARTUP_BUDGET_MS for the temporary,
honest, higher gate).
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BENCH_CMD = "from reconpro.cli import main; main(['--version'])"


def percentile_nearest(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in [0,1])."""
    if not sorted_values:
        return float("nan")
    n = len(sorted_values)
    k = max(1, min(n, int(round(q * n))))
    return sorted_values[k - 1]


def measure_once(python: str, cwd: Path) -> tuple[float, int, str]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [python, "-c", BENCH_CMD],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return elapsed_ms, proc.returncode, (proc.stdout + proc.stderr).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="ReconPro CLI cold-start benchmark")
    ap.add_argument("--threshold-ms", type=float, default=100.0,
                    help="fail if median startup exceeds this (default 100)")
    ap.add_argument("--runs", type=int, default=7, help="number of runs (default 7)")
    ap.add_argument("--json-out", type=str, default=None,
                    help="write full JSON report to this path")
    ap.add_argument("--python", type=str, default=sys.executable,
                    help="interpreter to benchmark (default: current)")
    args = ap.parse_args()

    measurements: list[float] = []
    failures: list[str] = []
    # one untimed warmup run to stabilise filesystem/page caches so the N
    # timed runs measure steady-state cold-start, not cold-cache noise
    warm_ms, warm_code, _ = measure_once(args.python, REPO)
    print(f"[bench] warmup (untimed, discarded): {warm_ms:.2f} ms"
          + ("" if warm_code == 0 else f"  (EXIT {warm_code})"), flush=True)
    for i in range(args.runs):
        ms, code, out = measure_once(args.python, REPO)
        if code != 0:
            failures.append(f"run {i + 1}: exit {code}: {out[:200]}")
        measurements.append(round(ms, 2))
        print(f"[bench] run {i + 1}/{args.runs}: {ms:8.2f} ms"
              + ("" if code == 0 else f"  (EXIT {code}: {out[:120]})"), flush=True)

    if not measurements:
        print("[bench] FATAL: no measurements")
        return 1

    s = sorted(measurements)
    stats = {
        "min_ms": s[0],
        "median_ms": round(statistics.median(measurements), 2),
        "avg_ms": round(statistics.fmean(measurements), 2),
        "p95_ms": round(percentile_nearest(s, 0.95), 2),
        "max_ms": s[-1],
    }
    passed = stats["median_ms"] <= args.threshold_ms and not failures
    report = {
        "tool": "tools/bench_startup.py",
        "target": "subprocess cold import of reconpro.cli + --version execution",
        "python": args.python,
        "python_version": subprocess.run(
            [args.python, "--version"], capture_output=True, text=True
        ).stdout.strip(),
        "runs": args.runs,
        "threshold_ms": args.threshold_ms,
        "measurements_ms": measurements,
        "stats_ms": stats,
        "failures": failures,
        "passed": passed,
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    print("[bench] " + json.dumps(stats))
    print(f"[bench] threshold (median) = {args.threshold_ms} ms -> "
          f"{'PASS' if passed else 'FAIL'}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2) + "\n")
        print(f"[bench] JSON report written to {args.json_out}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
