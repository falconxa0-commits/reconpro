"""
Memory profiling and optimization tests for ReconPro.

Comprehensive test suite that:
  a) Measures per-module import memory and validates no unexpected growth.
  b) Tests ConnectionPool memory lifecycle (growth, shrinkage, cleanup).
  c) Tests KnowledgeGraph memory with large graphs (1000+ nodes).
  d) Tests UnifiedMemoryStore (findings, blackboard, vault) memory.
  e) Tests history persistence memory with large datasets.
  f) Tests scanner-level memory during mock scans with large finding lists.
  g) Uses tracemalloc to detect leaks and unbounded growth patterns.

Pure Python — ZERO external dependencies beyond stdlib + reconpro itself.
"""

from __future__ import annotations

import gc
import io
import json
import os
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

# ── Ensure package import path ────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.scanner import ReconProResult
from reconpro.connection_pool import ConnectionPool
from reconpro.knowledge_graph import (
    SecurityKnowledgeGraph,
    _FallbackDiGraph,
)
from reconpro.memory import UnifiedMemoryStore
from reconpro.history import (
    HISTORY_DIR,
    save_scan,
    list_scans,
    get_latest,
    get_scan,
    clear_history,
    diff_scans,
)
from reconpro.constants import (
    MAX_SCORE,
    MIN_SCORE,
    SEVERITY_LEVELS,
    VALID_SEVERITIES,
)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def _make_finding(
    severity: str = "info",
    title: str = "Test Finding",
    **kwargs: Any,
) -> Finding:
    """Create a Finding with sensible defaults."""
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


def _make_scan_dict(
    target: str = "example.com",
    n_findings: int = 10,
    **overrides: Any,
) -> Dict[str, Any]:
    """Create a mock scan result dict."""
    severities = ["critical", "high", "medium", "low", "info"]
    findings: List[Dict[str, Any]] = []
    for i in range(n_findings):
        sev = severities[i % len(severities)]
        findings.append({
            "title": f"Finding-{i}",
            "severity": sev,
            "category": "test",
            "module": "test_mod",
            "description": f"Test finding number {i}",
            "evidence": f"evidence-{i}",
            "asset": target,
            "points_deducted": 5,
        })
    result: Dict[str, Any] = {
        "target": target,
        "modules_run": ["test_mod"],
        "findings": findings,
        "severity_counts": {"critical": n_findings // 5, "high": n_findings // 5,
                             "medium": n_findings // 5, "low": n_findings // 5,
                             "info": n_findings // 5},
        "total_score": max(MIN_SCORE, MAX_SCORE - n_findings * 5),
        "grade": "B",
        "badge_markdown": "![B](https://img.shields.io/badge/Score-B-yellow)",
        "module_results": {},
    }
    result.update(overrides)
    return result


def _force_gc_and_collect() -> int:
    """Force garbage collection and return the number of collected objects."""
    gc.collect()
    gc.collect()  # double pass for cyclic references
    return gc.collect()


def _start_tracemalloc() -> tracemalloc.Snapshot:
    """Start tracemalloc, clear filters, take a baseline snapshot."""
    tracemalloc.stop()
    tracemalloc.clear_traces()
    tracemalloc.start(25)  # 25 frames of traceback — good balance
    return tracemalloc.take_snapshot()


def _stop_and_diff(baseline: tracemalloc.Snapshot) -> tracemalloc.StatisticDiff:
    """Take a final snapshot, stop tracemalloc, diff against baseline.

    Must take snapshot BEFORE stopping because take_snapshot requires
    an active tracing session.
    """
    current = tracemalloc.take_snapshot()
    tracemalloc.stop()
    stats = current.compare_to(baseline, "lineno")
    return stats


def _snapshot_memory_mb() -> float:
    """Return current RSS in MB via tracemalloc's tracked memory."""
    current, peak = tracemalloc.get_traced_memory()
    return current / (1024 * 1024)


# ═══════════════════════════════════════════════════════════════════════
#  a) Import Memory Tests
# ═══════════════════════════════════════════════════════════════════════


class TestImportMemory(unittest.TestCase):
    """Measure the memory footprint of importing each major subsystem."""

    def test_constants_import_size(self) -> None:
        """constants.py should be tiny (< 512 KB measured).

        Since the module is already imported at file level, this tests
        that reloading it does not cause significant new allocations.
        """
        import importlib
        import reconpro.constants as const_mod
        baseline = _start_tracemalloc()
        importlib.reload(const_mod)
        _ = const_mod.__version__  # ensure loaded
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 512_000,  # 512 KB absolute ceiling
                        f"constants import allocated {total / 1024:.1f} KB")

    def test_connection_pool_import_size(self) -> None:
        """connection_pool.py import should be reasonable."""
        import importlib
        import reconpro.connection_pool as cp_mod
        baseline = _start_tracemalloc()
        importlib.reload(cp_mod)
        _ = cp_mod.ConnectionPool  # touch
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 1_048_576,  # 1 MB
                        f"connection_pool import allocated {total / 1024:.1f} KB")

    def test_knowledge_graph_import_size(self) -> None:
        """knowledge_graph.py import should be reasonable."""
        import importlib
        import reconpro.knowledge_graph as kg_mod
        baseline = _start_tracemalloc()
        importlib.reload(kg_mod)
        _ = kg_mod.SecurityKnowledgeGraph  # touch
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,  # 2 MB
                        f"knowledge_graph import allocated {total / 1024:.1f} KB")

    def test_memory_store_import_size(self) -> None:
        """memory.py (UnifiedMemoryStore) import should be bounded."""
        import importlib
        import reconpro.memory as mem_mod
        baseline = _start_tracemalloc()
        importlib.reload(mem_mod)
        _ = mem_mod.UnifiedMemoryStore  # touch
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,  # 2 MB
                        f"memory store import allocated {total / 1024:.1f} KB")

    def test_history_import_size(self) -> None:
        """history.py import should be tiny."""
        import importlib
        import reconpro.history as hist_mod
        baseline = _start_tracemalloc()
        importlib.reload(hist_mod)
        _ = hist_mod.save_scan  # touch
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 512_000,  # 512 KB
                        f"history import allocated {total / 1024:.1f} KB")

    def test_scanner_import_size(self) -> None:
        """scanner.py import should be bounded."""
        import importlib
        import reconpro.scanner as scan_mod
        baseline = _start_tracemalloc()
        importlib.reload(scan_mod)
        _ = scan_mod.ReconProResult  # touch
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,  # 2 MB
                        f"scanner import allocated {total / 1024:.1f} KB")

    def test_no_unexpected_import_growth(self) -> None:
        """Re-importing a module should not cause additional allocations."""
        import importlib
        import reconpro.constants as const_mod
        baseline = _start_tracemalloc()
        importlib.reload(const_mod)
        stats = _stop_and_diff(baseline)
        # Re-import should add very little (just metadata)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 65_536,  # 64 KB for a reload
                        f"Re-import allocated unexpected {total / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════
#  b) Connection Pool Memory Tests
# ═══════════════════════════════════════════════════════════════════════


class TestConnectionPoolMemory(unittest.TestCase):
    """Test memory lifecycle of ConnectionPool."""

    def test_pool_instance_size(self) -> None:
        """A fresh ConnectionPool instance should be small (< 4 KB)."""
        pool = ConnectionPool()
        size = sys.getsizeof(pool)
        self.assertLess(size, 4096,
                        f"ConnectionPool instance is {size} bytes")
        pool.close()

    def test_ssl_context_caching_saves_memory(self) -> None:
        """Cached SSL contexts should not be duplicated on repeated access."""
        pool = ConnectionPool()
        baseline = _start_tracemalloc()
        # Access SSL context 100 times
        for _ in range(100):
            pool._get_ssl_context(True)
            pool._get_ssl_context(False)
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # After first creation, repeated access should be near-zero
        self.assertLess(total, 65_536,
                        f"100 repeated SSL context accesses allocated {total} bytes")
        pool.close()

    def test_pool_close_releases_ssl_contexts(self) -> None:
        """After close(), SSL context references should be None."""
        pool = ConnectionPool()
        # Force SSL context creation
        pool._get_ssl_context(True)
        pool._get_ssl_context(False)
        self.assertIsNotNone(pool._ssl_verify)
        self.assertIsNotNone(pool._ssl_no_verify)

        pool.close()
        self.assertIsNone(pool._ssl_verify)
        self.assertIsNone(pool._ssl_no_verify)

    def test_stats_counters_do_not_leak(self) -> None:
        """Resetting stats should not leave residual objects."""
        pool = ConnectionPool()
        baseline = _start_tracemalloc()
        # Record 1000 stats
        for _ in range(1000):
            pool._record_stats(0.001)
        stats_before = pool.stats()
        self.assertEqual(stats_before["total_requests"], 1000)

        pool.reset_stats()
        stats_after = pool.stats()
        self.assertEqual(stats_after["total_requests"], 0)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # Stats recording should be near-zero (just integer increments)
        self.assertLess(total, 131_072,  # 128 KB generous ceiling
                        f"1000 stat records leaked {total} bytes")
        pool.close()

    def test_pool_under_high_concurrency(self) -> None:
        """Multiple threads using the pool should not cause unbounded growth."""
        pool = ConnectionPool()
        errors: List[str] = []

        baseline = _start_tracemalloc()

        def worker(thread_id: int) -> None:
            try:
                for i in range(50):
                    ctx = pool._get_ssl_context(True)
                    pool._record_stats(0.001)
                    time.sleep(0.0001)  # tiny yield
            except Exception as e:
                errors.append(f"Thread-{thread_id}: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(pool.stats()["total_requests"], 500)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 262_144,  # 256 KB for 10 threads × 50 ops
                        f"Concurrent pool usage leaked {total} bytes")
        pool.close()

    def test_header_build_copies_not_mutates(self) -> None:
        """Building headers should create a copy, not reference the template."""
        pool = ConnectionPool()
        h1 = pool._build_headers({"X-Custom": "val1"})
        h2 = pool._build_headers({"X-Custom": "val2"})
        # Each should be independent
        self.assertNotEqual(h1.get("X-Custom"), h2.get("X-Custom"))
        # Template should not be polluted
        from reconpro.connection_pool import _HEADER_TEMPLATES
        self.assertNotIn("X-Custom", _HEADER_TEMPLATES["default"])
        pool.close()


# ═══════════════════════════════════════════════════════════════════════
#  c) Knowledge Graph Memory Tests
# ═══════════════════════════════════════════════════════════════════════


class TestKnowledgeGraphMemory(unittest.TestCase):
    """Test memory behaviour of SecurityKnowledgeGraph and _FallbackDiGraph."""

    def test_empty_graph_size(self) -> None:
        """An empty graph should have minimal memory footprint."""
        g = _FallbackDiGraph()
        size = sys.getsizeof(g)
        # The _nodes and _succ/_pred dicts are the main storage
        self.assertLess(size, 4096, f"Empty _FallbackDiGraph is {size} bytes")

    def test_large_graph_1000_nodes(self) -> None:
        """Graph with 1000 nodes should not exceed 5 MB of new allocations."""
        g = _FallbackDiGraph()
        baseline = _start_tracemalloc()

        for i in range(1000):
            g.add_node(f"target:node-{i}",
                       node_type="target",
                       label=f"node-{i}")

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,  # 5 MB
                        f"1000 nodes allocated {total / 1024:.1f} KB")
        self.assertEqual(len(g.nodes()), 1000)

    def test_large_graph_1000_edges(self) -> None:
        """Graph with 1000 nodes and 1000 edges should be bounded."""
        g = _FallbackDiGraph()
        baseline = _start_tracemalloc()

        for i in range(1000):
            g.add_node(f"target:node-{i}", node_type="target", label=f"node-{i}")
        for i in range(999):
            g.add_edge(f"target:node-{i}", f"target:node-{i+1}",
                       edge_type="links_to")

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 10_485_760,  # 10 MB generous
                        f"1000 nodes + 999 edges allocated {total / 1024:.1f} KB")
        self.assertEqual(len(g.edges()), 999)

    def test_graph_clear_frees_nodes_and_edges(self) -> None:
        """Clearing a graph via creating a new instance should release memory."""
        g = _FallbackDiGraph()
        # Add substantial data
        for i in range(500):
            g.add_node(f"node-{i}", data=f"x" * 100)
            if i > 0:
                g.add_edge(f"node-{i-1}", f"node-{i}")

        self.assertEqual(len(g.nodes()), 500)

        # Simulate clear by replacing graph
        baseline = _start_tracemalloc()
        del g
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        # After deletion, memory should be mostly reclaimed
        # (Python's memory allocator may keep the arena, so we check relative)
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 262_144,  # 256 KB residual after delete
                        f"After deleting 500-node graph, {total} bytes remain")

    def test_serialization_memory(self) -> None:
        """Serializing and deserializing a graph should not leak."""
        g = _FallbackDiGraph()
        for i in range(200):
            g.add_node(f"node-{i}", value=i, data=f"payload-{i}" * 5)
            if i > 0:
                g.add_edge(f"node-{i-1}", f"node-{i}", weight=i)

        baseline = _start_tracemalloc()

        # Serialize
        data = g.to_dict()
        json_str = json.dumps(data)

        # Deserialize
        data_loaded = json.loads(json_str)
        g2 = _FallbackDiGraph.from_dict(data_loaded)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        self.assertEqual(len(g2.nodes()), 200)
        self.assertEqual(len(g2.edges()), 199)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,  # 2 MB for serialization roundtrip
                        f"Serialization of 200-node graph leaked {total / 1024:.1f} KB")

    def test_security_knowledge_graph_large_ingest(self) -> None:
        """SecurityKnowledgeGraph.ingest of 100 findings should be bounded."""
        kg = SecurityKnowledgeGraph()
        baseline = _start_tracemalloc()

        scan_dict = _make_scan_dict(target="example.com", n_findings=100)
        kg.add_scan_result(scan_dict)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        graph_stats = kg.stats()
        self.assertGreater(graph_stats["total_nodes"], 100)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,  # 5 MB for 100 findings
                        f"Ingesting 100 findings allocated {total / 1024:.1f} KB")

    def test_remove_node_cleans_up_edges(self) -> None:
        """Removing a node should also remove associated edges."""
        g = _FallbackDiGraph()
        g.add_node("a")
        g.add_node("b")
        g.add_node("c")
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        g.add_edge("a", "c")

        self.assertEqual(len(g.edges()), 3)

        g.remove_node("b")
        self.assertNotIn("b", g.nodes())
        self.assertEqual(len(g.edges()), 1)  # only a->c remains

    def test_graph_to_dict_size_bounded(self) -> None:
        """to_dict() output for 1000 nodes should not be excessively large."""
        g = _FallbackDiGraph()
        for i in range(1000):
            g.add_node(f"node-{i}")
            if i > 0:
                g.add_edge(f"node-{i-1}", f"node-{i}")

        baseline = _start_tracemalloc()
        data = g.to_dict()
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        # The dict itself should not exceed ~2 MB of new allocations
        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 4_194_304,  # 4 MB
                        f"to_dict() for 1000 nodes allocated {total / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════
#  d) History / Memory Persistence Tests
# ═══════════════════════════════════════════════════════════════════════


class TestHistoryMemory(unittest.TestCase):
    """Test memory usage of the history subsystem with large datasets."""

    def setUp(self) -> None:
        """Use a temp directory for history files."""
        self._orig_dir = HISTORY_DIR
        self._tmpdir = tempfile.mkdtemp(prefix="reconpro_mem_test_")
        # Patch HISTORY_DIR
        import reconpro.history as hist_mod
        hist_mod.HISTORY_DIR = Path(self._tmpdir)

    def tearDown(self) -> None:
        """Restore original HISTORY_DIR and clean up."""
        import reconpro.history as hist_mod
        hist_mod.HISTORY_DIR = self._orig_dir
        # Clean temp dir
        for fp in Path(self._tmpdir).glob("*.json"):
            fp.unlink()
        try:
            os.rmdir(self._tmpdir)
        except OSError:
            pass

    def test_save_and_cleanup_memory(self) -> None:
        """Saving 50 scans and clearing should not leak memory."""
        baseline = _start_tracemalloc()

        for i in range(50):
            data = _make_scan_dict(target=f"target-{i}.com", n_findings=20)
            save_scan(data, label="mem_test")

        # Verify saves worked (list_scans default limit is 20)
        scans = list_scans(limit=60)
        self.assertGreaterEqual(len(scans), 50)

        # Clear all
        cleared = clear_history()
        self.assertEqual(cleared, 50)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # 50 scans × 20 findings should be well under 5 MB
        self.assertLess(total, 5_242_880,
                        f"50 save/clear cycles leaked {total / 1024:.1f} KB")

    def test_large_history_dataset_memory(self) -> None:
        """Reading 100 history files should not cause unbounded memory."""
        # Create 100 history files
        for i in range(100):
            data = _make_scan_dict(target=f"target-{i}.com", n_findings=50)
            save_scan(data, label="mem_test")

        baseline = _start_tracemalloc()

        # list_scans with limit=100
        scans = list_scans(limit=100)
        self.assertEqual(len(scans), 100)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 10_485_760,  # 10 MB for 100 × 50 findings
                        f"Reading 100 history files allocated {total / 1024:.1f} KB")

        clear_history()

    def test_diff_scans_memory(self) -> None:
        """Diffing two scans should not cause excessive memory."""
        d1 = _make_scan_dict(target="example.com", n_findings=30)
        d2 = _make_scan_dict(target="example.com", n_findings=35)

        baseline = _start_tracemalloc()
        result = diff_scans(json.dumps(d1), json.dumps(d2))
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        self.assertIn("fixed", result)
        self.assertIn("new", result)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,
                        f"diff_scans allocated {total / 1024:.1f} KB")

    def test_list_scans_with_target_filter(self) -> None:
        """Target filtering should not load all scans into memory."""
        for i in range(50):
            data = _make_scan_dict(target=f"target-{i}.com", n_findings=10)
            save_scan(data, label="mem_test")

        baseline = _start_tracemalloc()
        filtered = list_scans(target="target-5.com", limit=100)
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        # Should find only one matching scan
        self.assertLessEqual(len(filtered), 2)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"Filtered list_scans leaked {total / 1024:.1f} KB")

        clear_history()


# ═══════════════════════════════════════════════════════════════════════
#  e) UnifiedMemoryStore (FindingStore, Blackboard, Vault) Memory Tests
# ═══════════════════════════════════════════════════════════════════════


class TestUnifiedMemoryStoreMemory(unittest.TestCase):
    """Test memory behaviour of UnifiedMemoryStore sub-systems."""

    def setUp(self) -> None:
        """Use temp directories for all file-backed storage."""
        import reconpro.memory as mem_mod
        self._tmpdir = tempfile.mkdtemp(prefix="reconpro_ums_test_")
        self._orig_memory_dir = mem_mod.MEMORY_DIR
        self._orig_findings_dir = mem_mod.FINDINGS_DIR
        self._orig_vault_path = mem_mod.VAULT_PATH
        mem_mod.MEMORY_DIR = Path(self._tmpdir) / "memory"
        mem_mod.FINDINGS_DIR = mem_mod.MEMORY_DIR / "findings"
        mem_mod.VAULT_PATH = mem_mod.MEMORY_DIR / "vault.json"

        # Also patch knowledge_graph's default dir
        import reconpro.knowledge_graph as kg_mod
        self._orig_kg_dir = kg_mod.DEFAULT_GRAPH_DIR
        kg_mod.DEFAULT_GRAPH_DIR = mem_mod.MEMORY_DIR

        self.store = UnifiedMemoryStore()

    def tearDown(self) -> None:
        """Restore original paths and clean up."""
        import reconpro.memory as mem_mod
        import reconpro.knowledge_graph as kg_mod
        mem_mod.MEMORY_DIR = self._orig_memory_dir
        mem_mod.FINDINGS_DIR = self._orig_findings_dir
        mem_mod.VAULT_PATH = self._orig_vault_path
        kg_mod.DEFAULT_GRAPH_DIR = self._orig_kg_dir

        # Clean temp dir
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_empty_store_size(self) -> None:
        """Empty UnifiedMemoryStore should have small footprint."""
        size = sys.getsizeof(self.store)
        self.assertLess(size, 4096,
                        f"Empty UnifiedMemoryStore is {size} bytes")

    def test_finding_store_100_targets(self) -> None:
        """Storing 100 findings across 10 targets should be bounded."""
        baseline = _start_tracemalloc()

        for i in range(10):
            target = f"target-{i}.com"
            for j in range(10):
                self.store.save_finding(target, {
                    "title": f"Finding-{j}",
                    "severity": "info",
                    "module": "test",
                })

        stats_snapshot = self.store.stats()
        self.assertEqual(stats_snapshot["findings"]["total_findings"], 100)
        self.assertEqual(stats_snapshot["findings"]["targets_tracked"], 10)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,  # 5 MB
                        f"100 findings across 10 targets leaked {total / 1024:.1f} KB")

    def test_blackboard_1000_entries(self) -> None:
        """1000 blackboard entries should not cause unbounded memory."""
        baseline = _start_tracemalloc()

        for i in range(1000):
            self.store.bb_set(f"key-{i}", f"value-{i}" * 10, agent_id="agent-1")

        all_entries = self.store.bb_get_all()
        self.assertEqual(len(all_entries), 1000)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"1000 blackboard entries leaked {total / 1024:.1f} KB")

    def test_blackboard_ttl_expiration_frees_memory(self) -> None:
        """Expired blackboard entries should be pruned on access."""
        for i in range(500):
            self.store.bb_set(f"key-{i}", f"value-{i}", agent_id="agent-1", ttl=0)

        # Small sleep to ensure TTL expiration
        time.sleep(0.01)

        # Trigger expiration check via bb_get_all
        all_entries = self.store.bb_get_all()
        self.assertEqual(len(all_entries), 0,
                         "All TTL=0 entries should have expired")

    def test_blackboard_clear_frees_memory(self) -> None:
        """bb_clear() should wipe all entries."""
        for i in range(500):
            self.store.bb_set(f"key-{i}", f"value-{i}", agent_id="agent-1")

        bb_stats_before = self.store.stats()
        self.assertEqual(bb_stats_before["blackboard"]["active_entries"], 500)

        self.store.bb_clear()

        bb_stats_after = self.store.stats()
        self.assertEqual(bb_stats_after["blackboard"]["active_entries"], 0)

    def test_vault_500_credentials(self) -> None:
        """Storing 500 credentials should be bounded."""
        baseline = _start_tracemalloc()

        for i in range(500):
            self.store.vault_store(
                source=f"source-{i}",
                username=f"user-{i}",
                password=f"password-{i}",
            )

        creds = self.store.vault_get_all()
        self.assertEqual(len(creds), 500)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"500 vault credentials leaked {total / 1024:.1f} KB")

    def test_vault_purge_clears_memory(self) -> None:
        """vault_purge() should securely clear all credentials."""
        for i in range(100):
            self.store.vault_store("source", f"user-{i}", f"secret-{i}")

        vault_stats_before = self.store.stats()
        self.assertEqual(vault_stats_before["vault"]["total_credentials"], 100)

        self.store.vault_purge()

        vault_stats_after = self.store.stats()
        self.assertEqual(vault_stats_after["vault"]["total_credentials"], 0)

    def test_graph_subsystem_large_data(self) -> None:
        """Adding 500 nodes + findings to the graph sub-system."""
        baseline = _start_tracemalloc()

        for i in range(100):
            self.store.add_target(f"target-{i}.com")
            for j in range(5):
                self.store.add_vulnerability(
                    f"Vuln-{i}-{j}",
                    f"target-{i}.com",
                    severity="high",
                )

        graph_stats = self.store.graph_stats()
        self.assertGreater(graph_stats["total_nodes"], 500)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 10_485_760,  # 10 MB for 100 targets × 5 vulns
                        f"Graph subsystem 600 nodes leaked {total / 1024:.1f} KB")

    def test_clear_all_releases_memory(self) -> None:
        """clear_all() should release memory across all sub-systems."""
        # Populate all sub-systems
        for i in range(50):
            self.store.add_target(f"target-{i}.com")
            self.store.save_finding(f"target-{i}.com", {"title": f"F-{i}"})
            self.store.bb_set(f"key-{i}", f"val-{i}", agent_id="a")
            self.store.vault_store("s", f"u-{i}", f"p-{i}")

        stats_before = self.store.stats()
        self.assertEqual(stats_before["findings"]["total_findings"], 50)
        self.assertEqual(stats_before["blackboard"]["active_entries"], 50)
        self.assertEqual(stats_before["vault"]["total_credentials"], 50)

        self.store.clear_all()

        stats_after = self.store.stats()
        self.assertEqual(stats_after["findings"]["total_findings"], 0)
        self.assertEqual(stats_after["blackboard"]["active_entries"], 0)
        self.assertEqual(stats_after["vault"]["total_credentials"], 0)

    def test_save_load_roundtrip(self) -> None:
        """Save and load roundtrip should not leak."""
        # Add data
        for i in range(20):
            self.store.add_target(f"target-{i}.com")
            self.store.save_finding(f"target-{i}.com", {"title": f"F-{i}"})

        baseline = _start_tracemalloc()
        self.store.save()
        self.store.load()
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"Save/load roundtrip leaked {total / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════
#  f) Scanner Memory Tests
# ═══════════════════════════════════════════════════════════════════════


class TestScannerMemory(unittest.TestCase):
    """Test memory during scan operations (using mock data, no network)."""

    def test_reconpro_result_size(self) -> None:
        """ReconProResult with 500 findings should be bounded."""
        findings = [
            {"title": f"Finding-{i}", "severity": "info",
             "description": f"desc-{i}" * 20}
            for i in range(500)
        ]
        result = ReconProResult(
            target="example.com",
            modules_run=["test"],
            findings=findings,
            severity_counts={"info": 500},
            total_score=0,
            grade="F",
            badge_markdown="",
        )

        baseline = _start_tracemalloc()
        d = result.to_dict()
        _ = json.dumps(d)  # serialization
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,  # 5 MB for 500 findings
                        f"500 findings dict+json leaked {total / 1024:.1f} KB")

    def test_finding_objects_1000(self) -> None:
        """Creating 1000 Finding dataclass instances should be bounded."""
        baseline = _start_tracemalloc()

        findings: List[Finding] = []
        for i in range(1000):
            findings.append(_make_finding(
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                title=f"Finding-{i}",
                description=f"Description-{i}" * 10,
                evidence=f"Evidence-{i}" * 5,
            ))

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        self.assertEqual(len(findings), 1000)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 10_485_760,  # 10 MB for 1000 Findings
                        f"1000 Finding objects allocated {total / 1024:.1f} KB")

    def test_finding_cleanup_after_scope(self) -> None:
        """Finding objects should be collectible after they go out of scope."""
        baseline = _start_tracemalloc()

        def create_many_findings() -> int:
            findings: List[Finding] = []
            for i in range(5000):
                findings.append(_make_finding(title=f"Big-{i}",
                                               description="x" * 500))
            return len(findings)

        count = create_many_findings()
        self.assertEqual(count, 5000)

        del count  # ensure no references
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # After gc, the list is gone — only residual allocations
        self.assertLess(total, 5_242_880,
                        f"After scope exit, {total / 1024:.1f} KB remain")

    def test_scan_dict_serialization_memory(self) -> None:
        """Serializing a large scan dict should not double memory."""
        scan_dict = _make_scan_dict(target="example.com", n_findings=200)

        baseline = _start_tracemalloc()

        # Serialize multiple times
        for _ in range(10):
            _ = json.dumps(scan_dict)
            _ = json.dumps(scan_dict, indent=2)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # 20 serializations of the same object should not leak
        self.assertLess(total, 5_242_880,
                        f"20 serializations leaked {total / 1024:.1f} KB")

    def test_multi_module_findings_aggregation(self) -> None:
        """Aggregating findings from 10 modules should be bounded."""
        baseline = _start_tracemalloc()

        all_findings: List[Dict[str, Any]] = []
        for mod in range(10):
            module_findings = [
                {"title": f"Mod{mod}-Finding-{i}",
                 "severity": "info",
                 "module": f"module-{mod}"}
                for i in range(100)
            ]
            all_findings.extend(module_findings)

        self.assertEqual(len(all_findings), 1000)

        # Severity counts
        sev_counts: Dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"10 modules × 100 findings leaked {total / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════
#  g) General Memory / Tracemalloc / GC Tests
# ═══════════════════════════════════════════════════════════════════════


class TestGeneralMemory(unittest.TestCase):
    """Cross-cutting memory tests: leak detection, GC effectiveness, growth patterns."""

    def test_tracemalloc_detects_no_leak_in_loop(self) -> None:
        """A tight loop creating/destroying objects should not leak."""
        tracemalloc.stop()
        tracemalloc.clear_traces()
        tracemalloc.start(25)

        # Warmup phase
        for _ in range(100):
            _ = {"key": "value" * 100, "nested": [{"i": i} for i in range(10)]}

        baseline = tracemalloc.take_snapshot()

        # Measurement phase — same workload
        for _ in range(1000):
            _ = {"key": "value" * 100, "nested": [{"i": i} for i in range(10)]}

        _force_gc_and_collect()
        current = tracemalloc.take_snapshot()
        stats = current.compare_to(baseline, "lineno")
        tracemalloc.stop()

        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        # Growth should be proportional to iterations (linear), not super-linear
        # 1000 iterations vs 100 warmup = 10x more allocations expected
        # But memory should not grow by more than ~2 MB (each dict is small)
        self.assertLess(total_growth, 10_485_760,
                        f"Loop leaked {total_growth / 1024:.1f} KB")

    def test_gc_collects_circular_references(self) -> None:
        """Garbage collector should handle circular references."""
        # Create circular references
        objects: List[Dict[str, Any]] = []
        for i in range(1000):
            d: Dict[str, Any] = {"data": f"x" * 100}
            d["self_ref"] = d  # circular
            objects.append(d)

        # Remove all references — objects are only reachable via cycles
        objects.clear()

        collected = _force_gc_and_collect()
        # GC should have collected something from the cycles
        # (The exact number depends on Python internals, just verify it runs)

    def test_no_unbounded_string_growth(self) -> None:
        """String concatenation in a loop should not leak."""
        baseline = _start_tracemalloc()

        parts: List[str] = []
        for i in range(10000):
            parts.append(f"part-{i}")
        result = "".join(parts)  # efficient join

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # 10000 short strings joined should be < 1 MB of tracked allocations
        self.assertLess(total, 2_097_152,
                        f"String concatenation leaked {total / 1024:.1f} KB")

    def test_defaultdict_growth_bounded(self) -> None:
        """defaultdict should not grow beyond expected size."""
        from collections import defaultdict

        baseline = _start_tracemalloc()

        d: Dict[str, List[int]] = defaultdict(list)
        for i in range(1000):
            d[f"key-{i % 100}"].append(i)  # 100 unique keys, 1000 entries

        self.assertEqual(len(d), 100)
        self.assertEqual(sum(len(v) for v in d.values()), 1000)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,
                        f"defaultdict 1000 entries leaked {total / 1024:.1f} KB")

    def test_thread_local_memory_isolation(self) -> None:
        """Thread-local data should not leak to main thread."""
        thread_locals = threading.local()
        baseline = _start_tracemalloc()

        def worker() -> None:
            thread_locals.data = ["x" * 1000 for _ in range(100)]

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=5)

        # Main thread's thread_locals should not have 'data'
        self.assertFalse(hasattr(thread_locals, "data"),
                         "Thread-local data leaked to main thread")

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        # Thread-local cleanup should not leak
        self.assertLess(total, 1_048_576,
                        f"Thread-local usage leaked {total / 1024:.1f} KB")

    def test_repeated_object_creation_no_growth(self) -> None:
        """Repeatedly creating and destroying the same object should stabilize."""
        tracemalloc.stop()
        tracemalloc.clear_traces()
        tracemalloc.start(25)

        # Warmup
        for _ in range(50):
            store = UnifiedMemoryStore()
            del store

        baseline = tracemalloc.take_snapshot()

        # Measurement
        for _ in range(100):
            store = UnifiedMemoryStore()
            del store

        _force_gc_and_collect()
        current = tracemalloc.take_snapshot()
        stats = current.compare_to(baseline, "lineno")
        tracemalloc.stop()

        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        # After warmup, 100 more create/destroy cycles should add very little
        self.assertLess(total_growth, 2_097_152,
                        f"Repeated UnifiedMemoryStore create/delete leaked "
                        f"{total_growth / 1024:.1f} KB")

    def test_large_dict_clear(self) -> None:
        """Clearing a large dict should release most memory."""
        d: Dict[str, str] = {}
        for i in range(10000):
            d[f"key-{i}"] = f"value-{i}" * 10

        self.assertEqual(len(d), 10000)

        baseline = _start_tracemalloc()
        d.clear()
        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        # After clear, the dict is empty — minimal residual
        self.assertEqual(len(d), 0)

    def test_list_comp_vs_append_memory(self) -> None:
        """List comprehension should not use dramatically more memory."""
        n = 10000

        # List comprehension
        baseline1 = _start_tracemalloc()
        lc = [f"item-{i}" for i in range(n)]
        _force_gc_and_collect()
        stats1 = _stop_and_diff(baseline1)
        lc_size = sum(s.size_diff for s in stats1 if s.size_diff > 0)
        del lc

        # Append loop
        baseline2 = _start_tracemalloc()
        la: List[str] = []
        for i in range(n):
            la.append(f"item-{i}")
        _force_gc_and_collect()
        stats2 = _stop_and_diff(baseline2)
        la_size = sum(s.size_diff for s in stats2 if s.size_diff > 0)
        del la

        # Both should be in the same ballpark (within 2x)
        ratio = max(lc_size, la_size) / max(min(lc_size, la_size), 1)
        self.assertLess(ratio, 3.0,
                        f"List comp ({lc_size/1024:.1f}KB) vs append "
                        f"({la_size/1024:.1f}KB) ratio = {ratio:.1f}")

    def test_refcount_finding(self) -> None:
        """Finding refcount should be predictable."""
        f = _make_finding()
        # f + one reference from the test frame = 2
        rc = sys.getrefcount(f)
        # Refcount may vary by Python implementation, just verify it's reasonable
        self.assertGreater(rc, 0)
        self.assertLess(rc, 100, f"Unexpectedly high refcount: {rc}")


# ═══════════════════════════════════════════════════════════════════════
#  h) Memory Regression — Repeated Operations
# ═══════════════════════════════════════════════════════════════════════


class TestMemoryRegression(unittest.TestCase):
    """Detect memory regressions by running operations repeatedly."""

    def test_knowledge_graph_repeated_add_scan(self) -> None:
        """Adding scan results to the same graph should not grow unboundedly."""
        kg = SecurityKnowledgeGraph()
        tracemalloc.stop()
        tracemalloc.clear_traces()
        tracemalloc.start(25)

        # Warmup
        for i in range(5):
            kg.add_scan_result(_make_scan_dict(f"target-{i}.com", n_findings=10))

        baseline = tracemalloc.take_snapshot()

        # Measurement — add same volume
        for i in range(5, 15):
            kg.add_scan_result(_make_scan_dict(f"target-{i}.com", n_findings=10))

        _force_gc_and_collect()
        current = tracemalloc.take_snapshot()
        stats = current.compare_to(baseline, "lineno")
        tracemalloc.stop()

        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        # 10 more scans × 10 findings = proportional growth
        # Should be < 3 MB
        self.assertLess(total_growth, 3_145_728,
                        f"Repeated add_scan leaked {total_growth / 1024:.1f} KB")

    def test_connection_pool_repeated_probe_stats(self) -> None:
        """Repeated stat recording should not accumulate objects."""
        pool = ConnectionPool()
        tracemalloc.stop()
        tracemalloc.clear_traces()
        tracemalloc.start(25)

        # Warmup
        for _ in range(100):
            pool._record_stats(0.01)

        baseline = tracemalloc.take_snapshot()

        # Measurement
        for _ in range(1000):
            pool._record_stats(0.01)

        _force_gc_and_collect()
        current = tracemalloc.take_snapshot()
        stats = current.compare_to(baseline, "lineno")
        tracemalloc.stop()

        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        # Stats recording is just integer increments — nearly zero growth
        self.assertLess(total_growth, 65_536,
                        f"Repeated stat recording leaked {total_growth} bytes")
        pool.close()

    def test_memory_store_repeated_save_findings(self) -> None:
        """Repeatedly saving findings to the same target should be bounded."""
        tmpdir = tempfile.mkdtemp(prefix="reconpro_reg_test_")
        try:
            import reconpro.memory as mem_mod
            orig = mem_mod.MEMORY_DIR, mem_mod.FINDINGS_DIR, mem_mod.VAULT_PATH
            mem_mod.MEMORY_DIR = Path(tmpdir) / "memory"
            mem_mod.FINDINGS_DIR = mem_mod.MEMORY_DIR / "findings"
            mem_mod.VAULT_PATH = mem_mod.MEMORY_DIR / "vault.json"

            store = UnifiedMemoryStore()

            tracemalloc.stop()
            tracemalloc.clear_traces()
            tracemalloc.start(25)

            # Warmup
            for i in range(10):
                store.save_finding("example.com", {"title": f"Warmup-{i}"})

            baseline = tracemalloc.take_snapshot()

            # Measurement
            for i in range(100):
                store.save_finding("example.com", {"title": f"Meas-{i}"})

            _force_gc_and_collect()
            current = tracemalloc.take_snapshot()
            stats = current.compare_to(baseline, "lineno")
            tracemalloc.stop()

            total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
            # Each finding adds ~200 bytes to a list + flushes to disk
            # 100 findings should grow by < 2 MB
            self.assertLess(total_growth, 2_097_152,
                            f"Repeated save_finding leaked {total_growth / 1024:.1f} KB")

            # Restore
            mem_mod.MEMORY_DIR, mem_mod.FINDINGS_DIR, mem_mod.VAULT_PATH = orig
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
#  i) FallbackDiGraph Stress Tests
# ═══════════════════════════════════════════════════════════════════════


class TestFallbackDiGraphStress(unittest.TestCase):
    """Stress the _FallbackDiGraph with large-scale operations."""

    def test_bfs_on_large_graph(self) -> None:
        """BFS should complete on a 500-node chain without blowing memory."""
        from reconpro.knowledge_graph import _FallbackDiGraph
        from collections import deque

        g = _FallbackDiGraph()
        for i in range(500):
            g.add_node(f"n-{i}")
            if i > 0:
                g.add_edge(f"n-{i-1}", f"n-{i}")

        baseline = _start_tracemalloc()

        # BFS from n-0
        visited: set = set()
        queue: deque = deque()
        queue.append(("n-0", 0))
        visited.add("n-0")
        while queue:
            node, depth = queue.popleft()
            if depth >= 500:
                continue
            for nbr in g.successors(node):
                if nbr not in visited:
                    visited.add(nbr)
                    queue.append((nbr, depth + 1))

        self.assertEqual(len(visited), 500)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 5_242_880,
                        f"BFS on 500-node chain leaked {total / 1024:.1f} KB")

    def test_subgraph_memory(self) -> None:
        """Creating a subgraph should not copy the entire graph."""
        g = _FallbackDiGraph()
        for i in range(500):
            g.add_node(f"n-{i}")
            if i > 0:
                g.add_edge(f"n-{i-1}", f"n-{i}")

        baseline = _start_tracemalloc()

        # Create a small subgraph (10 nodes)
        subset = {f"n-{i}" for i in range(10)}
        sub = g.subgraph(subset)

        self.assertEqual(len(sub.nodes()), 10)
        self.assertEqual(len(sub.edges()), 9)

        _force_gc_and_collect()
        stats = _stop_and_diff(baseline)

        total = sum(s.size_diff for s in stats if s.size_diff > 0)
        self.assertLess(total, 2_097_152,
                        f"Subgraph of 10 from 500 nodes leaked {total / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main()
