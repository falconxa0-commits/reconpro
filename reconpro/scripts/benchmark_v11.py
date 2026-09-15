"""ReconPro v11 — Comprehensive Performance Benchmark Suite.

Benchmarks all performance-critical subsystems at multiple scales.
Pure Python. Zero external dependencies (except tracemalloc from stdlib).
"""
from __future__ import annotations

import json
import os
import random
import string
import sys
import time
import tracemalloc
from collections import defaultdict
from datetime import datetime, timezone

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# ═══════════════════════════════════════════════════════════════════════════
# Synthetic Data Generators
# ═══════════════════════════════════════════════════════════════════════════

CATEGORIES = [
    "information_disclosure", "misconfiguration", "injection", "auth_bypass",
    "broken_access_control", "ssrf", "xss", "csrf", "security_headers",
    "tls", "dns", "port_scan", "certificate", "api_security",
    "business_logic", "data_exposure", "privilege_escalation",
]
MODULES = [
    "recon", "auth", "chain", "bot", "gorgon", "oblivion", "vibesec",
    "nhi", "pegasus", "cloud_recon", "quantum_fingerprint",
    "dark_web_monitor", "steganography_detector", "zero_day_hunter",
    "honeypot_dance", "signal_intelligence", "covert_channel",
]
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def random_id(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def make_finding(idx: int, target: str = "example.com") -> dict:
    """Generate a realistic synthetic finding."""
    sev_weights = [0.05, 0.15, 0.30, 0.30, 0.20]
    severity = random.choices(SEVERITIES, weights=sev_weights, k=1)[0]
    pts_map = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
    cat = random.choice(CATEGORIES)
    mod = random.choice(MODULES)
    return {
        "title": f"[{severity.upper()}] {cat.replace('_', ' ').title()} detected on {target}",
        "severity": severity,
        "category": cat,
        "module": mod,
        "description": f"Detailed analysis of {cat} vulnerability on asset {target}/{random_id()}. "
                      f"This finding indicates a potential security weakness that could be exploited.",
        "evidence": f"Response code 200, headers: {{'x-powered-by': 'Express', 'server': 'nginx/1.18'}}",
        "asset": f"{random_id()}.{target}",
        "points_deducted": pts_map.get(severity, 0),
        "remediation": f"Fix the {cat} issue by implementing proper security controls and validation.",
        "dread_score": round(random.uniform(0.1, 1.0), 2),
        "cwe": f"CWE-{random.choice([79, 89, 352, 22, 287, 306, 502, 918, 400, 401])}",
        "cvss_score": round(random.uniform(1.0, 10.0), 1),
        "id": f"RP-{idx:06d}",
    }


def make_scan_result(num_findings: int, target: str = "example.com") -> dict:
    """Generate a complete scan result with N findings."""
    findings = [make_finding(i, target) for i in range(num_findings)]
    total_pts = sum(f["points_deducted"] for f in findings)
    score = max(0, 100 - total_pts)
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f["severity"]] += 1
    if score >= 90: grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else: grade = "F"
    return {
        "target": target,
        "findings": findings,
        "total_score": score,
        "grade": grade,
        "severity_counts": dict(sev_counts),
        "modules_run": list(set(f["module"] for f in findings)),
        "scan_duration": round(random.uniform(0.5, 30.0), 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Benchmark Runner
# ═══════════════════════════════════════════════════════════════════════════

results: dict = {"benchmarks": {}, "meta": {
    "version": "v11.0.0", "timestamp": datetime.now(timezone.utc).isoformat(),
    "platform": sys.platform, "python_version": sys.version,
}}


def bench(label: str, fn, iterations: int = 3) -> dict:
    """Run a function multiple times and return timing/memory stats."""
    times = []
    peak_mem = 0
    for _ in range(iterations):
        tracemalloc.start()
        t0 = time.perf_counter()
        result = fn()
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append(t1 - t0)
        peak_mem = max(peak_mem, peak)
    return {
        "mean_ms": round(sum(times) / len(times) * 1000, 2),
        "min_ms": round(min(times) * 1000, 2),
        "max_ms": round(max(times) * 1000, 2),
        "peak_memory_bytes": peak_mem,
        "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
        "iterations": iterations,
    }


def run_all_benchmarks():
    """Execute all benchmark suites."""
    print("=" * 70)
    print("ReconPro v11 Performance Benchmark Suite")
    print("=" * 70)

    # ── 1. JSON Export ──────────────────────────────────────────────────
    print("\n[1/9] JSON Export Benchmark...")
    import reconpro.formats as fmt
    for n in [100, 1000, 10000]:
        data = make_scan_result(n)
        tmp = f"/tmp/rp_bench_{n}.json"
        r = bench(f"json_export_{n}", lambda: fmt.export_json(data, tmp))
        results["benchmarks"][f"json_export_{n}"] = r
        print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
        os.unlink(tmp)

    # ── 2. SARIF Export ─────────────────────────────────────────────────
    print("\n[2/9] SARIF Export Benchmark...")
    for n in [100, 1000, 10000]:
        data = make_scan_result(n)
        tmp = f"/tmp/rp_bench_{n}.sarif.json"
        r = bench(f"sarif_export_{n}", lambda: fmt.export_sarif(data, tmp))
        results["benchmarks"][f"sarif_export_{n}"] = r
        print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
        os.unlink(tmp)

    # ── 3. Markdown Export ───────────────────────────────────────────────
    print("\n[3/9] Markdown Export Benchmark...")
    for n in [100, 1000, 10000]:
        data = make_scan_result(n)
        tmp = f"/tmp/rp_bench_{n}.md"
        r = bench(f"markdown_export_{n}", lambda: fmt.export_markdown(data, tmp))
        results["benchmarks"][f"markdown_export_{n}"] = r
        print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
        os.unlink(tmp)

    # ── 4. PDF (Print-ready HTML) Export ───────────────────────────────
    print("\n[4/9] PDF Export Benchmark...")
    for n in [100, 1000, 10000]:
        data = make_scan_result(n)
        tmp = f"/tmp/rp_bench_{n}.pdf.html"
        r = bench(f"pdf_export_{n}", lambda: fmt.export_pdf(data, tmp))
        results["benchmarks"][f"pdf_export_{n}"] = r
        print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
        os.unlink(tmp)

    # ── 5. Attack Graph Engine ───────────────────────────────────────────
    print("\n[5/9] Attack Graph Engine Benchmark...")
    try:
        import reconpro.attack_graph as ag
        for n_nodes in [50, 200, 500, 1000]:
            findings = [make_finding(i) for i in range(n_nodes)]

            def build_graph(fds=findings):
                eng = ag.AttackGraphEngine()
                for f in fds:
                    eng.add_finding(f)
                eng.build_graph()
                return eng.find_attack_paths()

            r = bench(f"attack_graph_{n_nodes}", build_graph, iterations=2)
            results["benchmarks"][f"attack_graph_{n_nodes}"] = r
            print(f"  {n_nodes:6d} nodes: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
    except Exception as e:
        print(f"  ERROR: {e}")

    # ── 6. Threat Intelligence Correlation ──────────────────────────────
    print("\n[6/9] Threat Intelligence Benchmark...")
    try:
        import reconpro.threat_intel as ti_mod
        for n in [100, 500, 1000, 5000]:
            findings = [make_finding(i) for i in range(n)]

            def enrich(fds=findings, _n=n):
                ti = ti_mod.ThreatIntelCenter()
                results_list = []
                for f in fds[:_n]:
                    r = ti.enrich_finding(f)
                    results_list.append(r)
                return results_list

            r = bench(f"threat_intel_{n}", enrich, iterations=2)
            results["benchmarks"][f"threat_intel_{n}"] = r
            print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
    except Exception as e:
        print(f"  ERROR: {e}")

    # ── 7. AI Analyst Classification ──────────────────────────────────
    print("\n[7/9] AI Analyst Benchmark...")
    try:
        import reconpro.ai_analyst as aa
        for n in [100, 500, 1000]:
            findings = [make_finding(i) for i in range(n)]

            def classify(fds=findings, _n=n):
                analyst = aa.AIAnalyst()
                results_list = []
                for f in fds[:_n]:
                    r = analyst.classify(f)
                    results_list.append(r)
                return results_list

            r = bench(f"ai_analyst_{n}", classify, iterations=2)
            results["benchmarks"][f"ai_analyst_{n}"] = r
            print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
    except Exception as e:
        print(f"  ERROR: {e}")

    # ── 8. Intelligence Pipeline (End-to-End) ──────────────────────────
    print("\n[8/9] Intelligence Pipeline End-to-End Benchmark...")
    try:
        import reconpro.intelligence_pipeline as ip
        for n in [50, 200, 500]:
            findings = [make_finding(i) for i in range(n)]

            def pipeline(fds=findings):
                return ip.run_intelligence_pipeline(fds)

            r = bench(f"intelligence_pipeline_{n}", pipeline, iterations=2)
            results["benchmarks"][f"intelligence_pipeline_{n}"] = r
            print(f"  {n:6d} findings: {r['mean_ms']:>10.2f} ms | {r['peak_memory_mb']:>8.2f} MB")
    except Exception as e:
        print(f"  ERROR: {e}")

    # ── 9. Concurrent Execution Scaling ────────────────────────────────
    print("\n[9/9] Concurrent Execution Scaling...")
    try:
        from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

        def workload(_):
            data = make_scan_result(100)
            tmp = f"/tmp/rp_concurrent_{os.getpid()}_{random_id()}.json"
            export_json(data, tmp)
            os.unlink(tmp)
            return True

        for workers in [1, 2, 4, 8]:
            tasks = 32
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(workload, range(tasks)))
            elapsed = time.perf_counter() - t0
            key = f"concurrent_threads_{workers}w"
            results["benchmarks"][key] = {
                "workers": workers,
                "tasks": tasks,
                "total_ms": round(elapsed * 1000, 2),
                "throughput_per_sec": round(tasks / elapsed, 2),
            }
            print(f"  {workers} workers, {tasks} tasks: {elapsed*1000:.0f} ms total, "
                  f"{tasks/elapsed:.1f} tasks/sec")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n" + "=" * 70)
    print("Benchmark complete. Results saved.")
    print("=" * 70)


if __name__ == "__main__":
    run_all_benchmarks()
    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "team2_benchmark_data.json"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Data saved to {out_path}")
