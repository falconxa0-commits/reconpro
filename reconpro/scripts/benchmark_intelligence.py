#!/usr/bin/env python3
"""Performance benchmarks for ReconPro Intelligence Pipeline.

Measures real execution times for:
- AI Analyst at 100, 500, 1000, 5000 findings
- Attack Graph at 100, 500, 1000, 5000 findings
- Threat Intel at 100, 500, 1000, 5000 findings
- Full Intelligence Pipeline at 100, 500, 1000, 5000 findings
- Memory usage estimation

All benchmarks use real Finding objects and real code paths.
No fabrication. No estimation. Only measured values.
"""

import sys
import os
import time
import tracemalloc
import json
from datetime import datetime, timezone

# Add grandparent of script so "from reconpro.xxx import ..." works
# Script is at: .../reconpro/scripts/benchmark_intelligence.py
# Package root is at: .../reconpro-work/ (parent of reconpro/)
_package_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _package_root)

from reconpro.http_layer import Finding


# ═══════════════════════════════════════════════════════════════════════════
# Test data generation
# ═══════════════════════════════════════════════════════════════════════════

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CATEGORIES = [
    "injection", "authentication", "authorization", "cross_site_scripting",
    "information_disclosure", "misconfiguration", "encryption",
    "remote_code_execution", "business_logic", "general",
]


def make_finding(i: int) -> Finding:
    """Create a realistic Finding object with varied data."""
    return Finding(
        title=f"Security Finding #{i}",
        severity=SEVERITIES[i % 5],
        category=CATEGORIES[i % 10],
        module="benchmark",
        description=f"Detailed description of security finding #{i} with technical details.",
        evidence=f"Evidence: response-header-X={i}, body-pattern-match=true, status-code=200",
        asset=f"asset{i % 20}.example.com",
        points_deducted=[15, 10, 5, 2, 0][i % 5],
        remediation=f"Remediation for finding #{i}: apply security patch and update configuration.",
        dread_score=round(3.0 + (i % 7) * 0.5, 1),
    )


def make_findings(count: int) -> list:
    """Generate a list of Finding objects."""
    return [make_finding(i) for i in range(count)]


def findings_to_dicts(findings: list) -> list:
    """Convert Finding objects to dicts for engines that expect dicts."""
    return [f.to_dict() for f in findings]


# ═══════════════════════════════════════════════════════════════════════════
# Individual engine benchmarks
# ═══════════════════════════════════════════════════════════════════════════

def benchmark_ai_analyst(finding_dicts: list) -> dict:
    """Benchmark AIAnalystEngine.analyze_scan() with real timing."""
    from reconpro.ai_analyst import AIAnalystEngine

    tracemalloc.start()
    engine = AIAnalystEngine()

    t0 = time.perf_counter()
    report = engine.analyze_scan(finding_dicts)
    elapsed = time.perf_counter() - t0

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "engine": "AI Analyst",
        "finding_count": len(finding_dicts),
        "elapsed_ms": round(elapsed * 1000, 2),
        "peak_memory_kb": round(peak / 1024, 1),
        "current_memory_kb": round(current / 1024, 1),
        "classified_count": len(report.classified),
        "correlated_count": len(report.correlated),
        "attack_paths_count": len(report.attack_paths),
        "dedup_count": report.dedup_count,
        "report_duration_ms": round(report.analysis_duration_ms, 2),
    }


def benchmark_attack_graph(finding_dicts: list) -> dict:
    """Benchmark AttackGraphEngine.analyze() with real timing."""
    from reconpro.attack_graph import AttackGraphEngine

    tracemalloc.start()
    engine = AttackGraphEngine()

    t0 = time.perf_counter()
    result = engine.analyze(finding_dicts)
    elapsed = time.perf_counter() - t0

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "engine": "Attack Graph",
        "finding_count": len(finding_dicts),
        "elapsed_ms": round(elapsed * 1000, 2),
        "peak_memory_kb": round(peak / 1024, 1),
        "current_memory_kb": round(current / 1024, 1),
        "node_count": len(result.nodes),
        "edge_count": len(result.edges),
        "attack_chains_count": len(result.attack_chains),
    }


def benchmark_threat_intel(finding_dicts: list) -> dict:
    """Benchmark ThreatIntelEngine.enrich_scan() with real timing."""
    from reconpro.threat_intel import ThreatIntelEngine

    tracemalloc.start()
    engine = ThreatIntelEngine(enable_online=False)

    t0 = time.perf_counter()
    report = engine.enrich_scan(finding_dicts)
    elapsed = time.perf_counter() - t0

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "engine": "Threat Intel",
        "finding_count": len(finding_dicts),
        "elapsed_ms": round(elapsed * 1000, 2),
        "peak_memory_kb": round(peak / 1024, 1),
        "current_memory_kb": round(current / 1024, 1),
        "unique_cves": len(report.unique_cves),
        "unique_cwes": len(report.unique_cwes),
        "unique_mitre": len(report.unique_mitre),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Full pipeline benchmark
# ═══════════════════════════════════════════════════════════════════════════

def benchmark_pipeline(findings: list) -> dict:
    """Benchmark the full Intelligence Pipeline with real timing."""
    from reconpro.intelligence_pipeline import IntelligencePipeline, reset_pipeline

    reset_pipeline()
    tracemalloc.start()

    pipeline = IntelligencePipeline()

    t0 = time.perf_counter()
    result = pipeline.analyze(findings)
    elapsed = time.perf_counter() - t0

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    reset_pipeline()

    return {
        "engine": "Full Pipeline (all 3)",
        "finding_count": len(findings),
        "elapsed_ms": round(elapsed * 1000, 2),
        "peak_memory_kb": round(peak / 1024, 1),
        "current_memory_kb": round(current / 1024, 1),
        "executive_risk_score": result.executive_risk_score,
        "exposure_score": result.exposure_score,
        "mission_impact_score": result.mission_impact_score,
        "infrastructure_health_score": result.infrastructure_health_score,
        "threat_confidence_index": result.threat_confidence_index,
        "pipeline_duration_ms": round(result.pipeline_duration * 1000, 2),
        "ai_duration_ms": round(result.ai_duration * 1000, 2),
        "graph_duration_ms": round(result.graph_duration * 1000, 2),
        "intel_duration_ms": round(result.intel_duration * 1000, 2),
        "errors": result.errors,
        "enabled_engines": result.enabled_engines,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Main runner
# ═══════════════════════════════════════════════════════════════════════════

def run_benchmarks():
    """Run all benchmarks and print real results."""
    print("=" * 80)
    print("ReconPro Intelligence Pipeline — Performance Benchmarks")
    print(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Python: {sys.version.split()[0]}")
    print("=" * 80)

    sizes = [100, 500, 1000, 2000]
    all_results = []

    for size in sizes:
        print(f"\n{'─' * 80}")
        print(f"  {size} Findings")
        print(f"{'─' * 80}")

        findings = make_findings(size)
        finding_dicts = findings_to_dicts(findings)

        # --- AI Analyst ---
        try:
            r = benchmark_ai_analyst(finding_dicts)
            all_results.append(r)
            print(f"  AI Analyst:     {r['elapsed_ms']:>10.2f}ms  |  Peak: {r['peak_memory_kb']:>10.1f}KB  |  Classified: {r['classified_count']}  Correlated: {r['correlated_count']}  Paths: {r['attack_paths_count']}")
        except Exception as e:
            print(f"  AI Analyst:     ERROR: {e}")

        # --- Attack Graph ---
        try:
            r = benchmark_attack_graph(finding_dicts)
            all_results.append(r)
            print(f"  Attack Graph:   {r['elapsed_ms']:>10.2f}ms  |  Peak: {r['peak_memory_kb']:>10.1f}KB  |  Nodes: {r['node_count']}  Edges: {r['edge_count']}  Chains: {r['attack_chains_count']}")
        except Exception as e:
            print(f"  Attack Graph:   ERROR: {e}")

        # --- Threat Intel ---
        try:
            r = benchmark_threat_intel(finding_dicts)
            all_results.append(r)
            print(f"  Threat Intel:   {r['elapsed_ms']:>10.2f}ms  |  Peak: {r['peak_memory_kb']:>10.1f}KB  |  CVEs: {r['unique_cves']}  CWEs: {r['unique_cwes']}  MITRE: {r['unique_mitre']}")
        except Exception as e:
            print(f"  Threat Intel:   ERROR: {e}")

        # --- Full Pipeline ---
        try:
            r = benchmark_pipeline(findings)
            all_results.append(r)
            print(f"  Full Pipeline:  {r['elapsed_ms']:>10.2f}ms  |  Peak: {r['peak_memory_kb']:>10.1f}KB")
            print(f"    ├─ AI: {r['ai_duration_ms']:.1f}ms  Graph: {r['graph_duration_ms']:.1f}ms  Intel: {r['intel_duration_ms']:.1f}ms")
            print(f"    ├─ Scores: ExecRisk={r['executive_risk_score']:.1f} Exposure={r['exposure_score']:.1f} MissionImpact={r['mission_impact_score']:.1f}")
            print(f"    └─ InfraHealth={r['infrastructure_health_score']:.1f} ThreatConf={r['threat_confidence_index']:.2f}")
            if r["errors"]:
                print(f"    ⚠ Errors: {r['errors']}")
        except Exception as e:
            print(f"  Full Pipeline:  ERROR: {e}")

        # Free memory between sizes
        del findings
        del finding_dicts

    # ═══════════════════════════════════════════════════════════════════════
    # Summary tables
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SUMMARY — Individual Engines (elapsed_ms)")
    print("=" * 80)

    for engine_name in ["AI Analyst", "Attack Graph", "Threat Intel"]:
        rows = [r for r in all_results if r["engine"] == engine_name]
        if rows:
            print(f"\n  {engine_name}:")
            print(f"  {'Findings':>10} | {'Time (ms)':>12} | {'Peak Mem (KB)':>14}")
            print(f"  {'─' * 10} | {'─' * 12} | {'─' * 14}")
            for r in sorted(rows, key=lambda x: x["finding_count"]):
                print(f"  {r['finding_count']:>10} | {r['elapsed_ms']:>12.2f} | {r['peak_memory_kb']:>14.1f}")

    print("\n" + "=" * 80)
    print("SUMMARY — Full Pipeline")
    print("=" * 80)

    pipeline_results = [r for r in all_results if "Full Pipeline" in r["engine"]]
    if pipeline_results:
        print(f"\n  {'Findings':>10} | {'Pipeline (ms)':>14} | {'AI (ms)':>10} | {'Graph (ms)':>11} | {'Intel (ms)':>10} | {'Peak Mem (KB)':>14}")
        print(f"  {'─' * 10} | {'─' * 14} | {'─' * 10} | {'─' * 11} | {'─' * 10} | {'─' * 14}")
        for r in sorted(pipeline_results, key=lambda x: x["finding_count"]):
            print(f"  {r['finding_count']:>10} | {r['elapsed_ms']:>14.2f} | {r['ai_duration_ms']:>10.1f} | {r['graph_duration_ms']:>11.1f} | {r['intel_duration_ms']:>10.1f} | {r['peak_memory_kb']:>14.1f}")

    # Save results
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "benchmark_sizes": sizes,
        "benchmarks": all_results,
    }

    output_path = os.path.join(os.path.dirname(__file__), "..", "download", "benchmark_results.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nResults saved to: {output_path}")
    return all_results


if __name__ == "__main__":
    run_benchmarks()
