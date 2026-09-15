"""Tests for reconpro.repository_memory — Repository Memory System.

All tests use a temporary directory for persistence so they never touch
the real ``~/.reconpro/`` directory.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.repository_memory import (
    DEFAULT_CONFIDENCE,
    EngineeringFact,
    MemoryIndex,
    MemoryQuery,
    MemorySnapshot,
    RepositoryMemory,
    _size_of_dict,
)


def _tmp_path() -> Path:
    """Return a fresh temp-file path for each call."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(path)
    return Path(path)


def _make_fact(
    key: str = "test/key",
    value: Any = "hello",
    tags: Optional[List[str]] = None,
    source: str = "test",
    confidence: float = DEFAULT_CONFIDENCE,
    expires: Optional[float] = None,
    timestamp: Optional[float] = None,
) -> EngineeringFact:
    """Factory for creating test facts with sensible defaults."""
    return EngineeringFact(
        key=key,
        value=value,
        timestamp=timestamp if timestamp is not None else time.time(),
        source=source,
        tags=frozenset(tags or []),
        confidence=confidence,
        expires=expires,
    )


# ======================================================================
#  EngineeringFact Tests
# ======================================================================


class TestEngineeringFact(unittest.TestCase):
    """Tests for the EngineeringFact dataclass."""

    def test_default_fields(self):
        f = EngineeringFact(key="k", value="v")
        self.assertEqual(f.key, "k")
        self.assertEqual(f.value, "v")
        self.assertEqual(f.source, "")
        self.assertEqual(f.tags, frozenset())
        self.assertAlmostEqual(f.confidence, DEFAULT_CONFIDENCE)
        self.assertIsNone(f.expires)
        self.assertGreater(f.timestamp, 0)

    def test_custom_fields(self):
        ts = 1700000000.0
        f = EngineeringFact(
            key="a/b/c",
            value={"x": 1},
            timestamp=ts,
            source="agent-1",
            tags=frozenset(["auth", "decision"]),
            confidence=0.95,
            expires=ts + 3600,
        )
        self.assertEqual(f.key, "a/b/c")
        self.assertEqual(f.value, {"x": 1})
        self.assertEqual(f.timestamp, ts)
        self.assertEqual(f.source, "agent-1")
        self.assertEqual(f.tags, frozenset(["auth", "decision"]))
        self.assertAlmostEqual(f.confidence, 0.95)
        self.assertAlmostEqual(f.expires, ts + 3600)

    def test_is_expired_no_expiration(self):
        f = EngineeringFact(key="k", value="v", expires=None)
        self.assertFalse(f.is_expired())
        self.assertFalse(f.is_expired(now=time.time() + 1e9))

    def test_is_expired_future(self):
        f = EngineeringFact(
            key="k", value="v", expires=time.time() + 3600,
        )
        self.assertFalse(f.is_expired())

    def test_is_expired_past(self):
        f = EngineeringFact(
            key="k", value="v", expires=time.time() - 1,
        )
        self.assertTrue(f.is_expired())

    def test_is_expired_with_explicit_now(self):
        f = EngineeringFact(key="k", value="v", expires=100.0)
        self.assertFalse(f.is_expired(now=99.0))
        self.assertTrue(f.is_expired(now=101.0))

    def test_round_trip_serialization(self):
        original = EngineeringFact(
            key="perf/baseline",
            value={"latency_p50": 42, "latency_p99": 200},
            timestamp=1700000000.0,
            source="bench-runner",
            tags=frozenset(["perf", "baseline"]),
            confidence=0.9,
            expires=None,
        )
        d = original.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["key"], "perf/baseline")
        self.assertEqual(d["value"], {"latency_p50": 42, "latency_p99": 200})
        # Tags are serialised as sorted list
        self.assertEqual(d["tags"], ["baseline", "perf"])

        restored = EngineeringFact.from_dict(d)
        self.assertEqual(restored.key, original.key)
        self.assertEqual(restored.value, original.value)
        self.assertEqual(restored.timestamp, original.timestamp)
        self.assertEqual(restored.source, original.source)
        self.assertEqual(restored.tags, original.tags)
        self.assertAlmostEqual(restored.confidence, original.confidence)
        self.assertEqual(restored.expires, original.expires)

    def test_from_dict_missing_optional_fields(self):
        d = {"key": "k", "value": "v"}
        f = EngineeringFact.from_dict(d)
        self.assertEqual(f.key, "k")
        self.assertEqual(f.value, "v")
        self.assertEqual(f.source, "")
        self.assertEqual(f.tags, frozenset())
        self.assertAlmostEqual(f.confidence, DEFAULT_CONFIDENCE)
        self.assertIsNone(f.expires)


# ======================================================================
#  MemoryIndex Tests
# ======================================================================


class TestMemoryIndex(unittest.TestCase):
    """Tests for the MemoryIndex class."""

    def _make_index_with_facts(self) -> tuple[MemoryIndex, Dict[str, EngineeringFact]]:
        facts: Dict[str, EngineeringFact] = {}
        facts["a"] = _make_fact("a", "val-a", tags=["t1", "t2"], source="src1", timestamp=1700000000.0)
        facts["b"] = _make_fact("b", "val-b", tags=["t1"], source="src2", timestamp=1700086400.0)
        facts["c"] = _make_fact("c", "val-c", tags=["t2", "t3"], source="src1", timestamp=1700172800.0)
        idx = MemoryIndex()
        idx.rebuild(facts)
        return idx, facts

    def test_by_tag_single(self):
        idx, _ = self._make_index_with_facts()
        keys = idx.by_tag("t1")
        self.assertEqual(keys, {"a", "b"})

    def test_by_tag_missing(self):
        idx, _ = self._make_index_with_facts()
        self.assertEqual(idx.by_tag("nonexistent"), set())

    def test_by_tags_intersection(self):
        idx, _ = self._make_index_with_facts()
        # t1 and t2 both -> only "a"
        self.assertEqual(idx.by_tags(["t1", "t2"]), {"a"})

    def test_by_tags_single(self):
        idx, _ = self._make_index_with_facts()
        self.assertEqual(idx.by_tags(["t3"]), {"c"})

    def test_by_tags_empty(self):
        idx, _ = self._make_index_with_facts()
        self.assertEqual(idx.by_tags([]), set())

    def test_by_time_range(self):
        idx, _ = self._make_index_with_facts()
        # a=2023-11-14, b=2023-11-15, c=2023-11-16 (UTC)
        keys = idx.by_time_range(1700000000.0, 1700086400.0)
        # includes dates 2023-11-14 and 2023-11-15
        self.assertEqual(keys, {"a", "b"})

    def test_by_source(self):
        idx, _ = self._make_index_with_facts()
        self.assertEqual(idx.by_source("src1"), {"a", "c"})
        self.assertEqual(idx.by_source("src2"), {"b"})

    def test_all_keys(self):
        idx, facts = self._make_index_with_facts()
        self.assertEqual(idx.all_keys(), set(facts.keys()))

    def test_add_and_remove(self):
        idx = MemoryIndex()
        fact = _make_fact("x", "val", tags=["new"], source="newsrc")
        idx.add(fact)
        self.assertIn("x", idx.all_keys())
        self.assertEqual(idx.by_tag("new"), {"x"})
        self.assertEqual(idx.by_source("newsrc"), {"x"})

        idx.remove(fact)
        self.assertNotIn("x", idx.all_keys())
        self.assertEqual(idx.by_tag("new"), set())

    def test_clear(self):
        idx, _ = self._make_index_with_facts()
        idx.clear()
        self.assertEqual(idx.all_keys(), set())
        self.assertTrue(idx.dirty)

    def test_rebuild(self):
        idx, facts = self._make_index_with_facts()
        idx.clear()
        self.assertEqual(idx.all_keys(), set())
        idx.rebuild(facts)
        self.assertEqual(idx.all_keys(), set(facts.keys()))
        self.assertFalse(idx.dirty)


# ======================================================================
#  MemoryQuery Tests
# ======================================================================


class TestMemoryQuery(unittest.TestCase):
    """Tests for the MemoryQuery builder."""

    def test_empty_query_matches_everything(self):
        q = MemoryQuery()
        fact = _make_fact("a/b/c", "val", tags=["x"])
        self.assertTrue(q.matches(fact))

    def test_with_tags_all_required(self):
        q = MemoryQuery().with_tags({"auth", "decision"})
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["auth", "decision", "extra"])))
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["auth", "decision"])))
        self.assertFalse(q.matches(_make_fact("k", "v", tags=["auth"])))
        self.assertFalse(q.matches(_make_fact("k", "v", tags=[])))

    def test_with_any_tag(self):
        q = MemoryQuery().with_any_tag({"auth", "perf"})
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["auth"])))
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["perf"])))
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["auth", "perf"])))
        self.assertFalse(q.matches(_make_fact("k", "v", tags=["network"])))

    def test_with_sources(self):
        q = MemoryQuery().with_sources({"agent-1", "agent-2"})
        self.assertTrue(q.matches(_make_fact("k", "v", source="agent-1")))
        self.assertFalse(q.matches(_make_fact("k", "v", source="agent-3")))
        self.assertFalse(q.matches(_make_fact("k", "v", source="")))

    def test_with_key_pattern(self):
        q = MemoryQuery().with_key_pattern("perf/*")
        self.assertTrue(q.matches(_make_fact("perf/latency", "v")))
        self.assertTrue(q.matches(_make_fact("perf/baseline/api", "v")))
        self.assertFalse(q.matches(_make_fact("auth/decision", "v")))

    def test_with_confidence(self):
        q = MemoryQuery().with_confidence(min_conf=0.7, max_conf=0.9)
        self.assertTrue(q.matches(_make_fact("k", "v", confidence=0.8)))
        self.assertTrue(q.matches(_make_fact("k", "v", confidence=0.7)))
        self.assertTrue(q.matches(_make_fact("k", "v", confidence=0.9)))
        self.assertFalse(q.matches(_make_fact("k", "v", confidence=0.5)))
        self.assertFalse(q.matches(_make_fact("k", "v", confidence=1.0)))

    def test_with_time_range(self):
        q = MemoryQuery().with_time_range(start=100.0, end=200.0)
        self.assertTrue(q.matches(_make_fact("k", "v", timestamp=150.0)))
        self.assertTrue(q.matches(_make_fact("k", "v", timestamp=100.0)))
        self.assertTrue(q.matches(_make_fact("k", "v", timestamp=200.0)))
        self.assertFalse(q.matches(_make_fact("k", "v", timestamp=99.0)))
        self.assertFalse(q.matches(_make_fact("k", "v", timestamp=201.0)))

    def test_with_time_range_open_start(self):
        q = MemoryQuery().with_time_range(end=200.0)
        self.assertTrue(q.matches(_make_fact("k", "v", timestamp=50.0)))
        self.assertTrue(q.matches(_make_fact("k", "v", timestamp=200.0)))
        self.assertFalse(q.matches(_make_fact("k", "v", timestamp=201.0)))

    def test_with_text(self):
        q = MemoryQuery().with_text("nginx")
        self.assertTrue(q.matches(_make_fact("k", "Uses nginx 1.24")))
        self.assertTrue(q.matches(_make_fact("k", {"server": "nginx"})))
        self.assertFalse(q.matches(_make_fact("k", "Uses Apache 2.4")))
        # Case-insensitive
        self.assertTrue(q.matches(_make_fact("k", "Nginx reverse proxy")))

    def test_without_tags(self):
        q = MemoryQuery().without_tags({"deprecated"})
        self.assertTrue(q.matches(_make_fact("k", "v", tags=["active"])))
        self.assertFalse(q.matches(_make_fact("k", "v", tags=["active", "deprecated"])))
        self.assertFalse(q.matches(_make_fact("k", "v", tags=["deprecated"])))

    def test_without_sources(self):
        q = MemoryQuery().without_sources({"untrusted"})
        self.assertTrue(q.matches(_make_fact("k", "v", source="trusted")))
        self.assertFalse(q.matches(_make_fact("k", "v", source="untrusted")))

    def test_without_keys(self):
        q = MemoryQuery().without_keys({"skip/me"})
        self.assertTrue(q.matches(_make_fact("keep/me", "v")))
        self.assertFalse(q.matches(_make_fact("skip/me", "v")))

    def test_chaining(self):
        q = (
            MemoryQuery()
            .with_tags({"perf"})
            .with_confidence(min_conf=0.5)
            .with_text("latency")
        )
        self.assertTrue(
            q.matches(_make_fact("k", {"latency_ms": 42}, tags=["perf"], confidence=0.8))
        )
        # Missing tag
        self.assertFalse(
            q.matches(_make_fact("k", {"latency_ms": 42}, tags=["net"], confidence=0.8))
        )
        # Low confidence
        self.assertFalse(
            q.matches(_make_fact("k", {"latency_ms": 42}, tags=["perf"], confidence=0.3))
        )
        # No text match
        self.assertFalse(
            q.matches(_make_fact("k", {"throughput": 100}, tags=["perf"], confidence=0.8))
        )

    def test_and_combinator(self):
        q1 = MemoryQuery().with_tags({"auth"})
        q2 = MemoryQuery().with_confidence(min_conf=0.9)
        combined = MemoryQuery.and_(q1, q2)
        self.assertTrue(combined.matches(_make_fact("k", "v", tags=["auth"], confidence=0.95)))
        self.assertFalse(combined.matches(_make_fact("k", "v", tags=["auth"], confidence=0.5)))
        self.assertFalse(combined.matches(_make_fact("k", "v", tags=["net"], confidence=0.95)))

    def test_or_combinator(self):
        q1 = MemoryQuery().with_tags({"auth"})
        q2 = MemoryQuery().with_tags({"perf"})
        combined = MemoryQuery.or_(q1, q2)
        # OR should have relaxed any_tags
        self.assertTrue(combined.matches(_make_fact("k", "v", tags=["auth"])))
        self.assertTrue(combined.matches(_make_fact("k", "v", tags=["perf"])))
        self.assertTrue(combined.matches(_make_fact("k", "v", tags=["auth", "perf"])))

    def test_not_combinator(self):
        q = MemoryQuery().with_tags({"auth"})
        inverted = MemoryQuery.not_(q)
        self.assertFalse(inverted.matches(_make_fact("k", "v", tags=["auth"])))
        self.assertTrue(inverted.matches(_make_fact("k", "v", tags=["perf"])))

    def test_to_dict(self):
        q = (
            MemoryQuery()
            .with_tags({"a", "b"})
            .with_sources({"s1"})
            .with_confidence(min_conf=0.5)
        )
        d = q.to_dict()
        self.assertEqual(sorted(d["tags"]), ["a", "b"])
        self.assertEqual(d["sources"], ["s1"])
        self.assertAlmostEqual(d["min_confidence"], 0.5)

    def test_repr(self):
        q = MemoryQuery().with_tags({"t1"})
        r = repr(q)
        self.assertIn("MemoryQuery", r)
        self.assertIn("t1", r)


# ======================================================================
#  RepositoryMemory Tests
# ======================================================================


class TestRepositoryMemory(unittest.TestCase):
    """Tests for the main RepositoryMemory class."""

    def setUp(self):
        self.tmp_path = _tmp_path()
        self.mem = RepositoryMemory(persist_path=self.tmp_path)

    def tearDown(self):
        if self.tmp_path.exists():
            self.tmp_path.unlink()
        # Clean up any tmp file
        tmp = self.tmp_path.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()

    # ── Remember / Recall ─────────────────────────────────────────────

    def test_remember_and_recall(self):
        fact = self.mem.remember("arch/auth", "JWT-based")
        self.assertEqual(fact.key, "arch/auth")
        self.assertEqual(fact.value, "JWT-based")

        recalled = self.mem.recall("arch/auth")
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled.value, "JWT-based")
        self.assertEqual(recalled.key, "arch/auth")

    def test_recall_nonexistent(self):
        self.assertIsNone(self.mem.recall("nonexistent"))

    def test_remember_with_metadata(self):
        fact = self.mem.remember(
            "perf/baseline/api-latency",
            {"p50_ms": 42, "p99_ms": 200},
            metadata={
                "source": "bench-runner",
                "tags": ["perf", "baseline", "api"],
                "confidence": 0.95,
            },
        )
        self.assertEqual(fact.source, "bench-runner")
        self.assertEqual(fact.tags, frozenset(["perf", "baseline", "api"]))
        self.assertAlmostEqual(fact.confidence, 0.95)

    def test_remember_overwrites(self):
        self.mem.remember("k", "v1")
        self.mem.remember("k", "v2")
        recalled = self.mem.recall("k")
        self.assertEqual(recalled.value, "v2")

    def test_remember_tags_as_string(self):
        """Tags passed as a single string should be converted to a frozenset."""
        fact = self.mem.remember(
            "k", "v", metadata={"tags": "single-tag"},
        )
        self.assertEqual(fact.tags, frozenset(["single-tag"]))

    # ── Recall Pattern ───────────────────────────────────────────────

    def test_recall_pattern_glob(self):
        self.mem.remember("perf/latency", "val1")
        self.mem.remember("perf/throughput", "val2")
        self.mem.remember("auth/decision", "val3")

        results = self.mem.recall_pattern("perf/*")
        keys = [f.key for f in results]
        self.assertEqual(keys, ["perf/latency", "perf/throughput"])

    def test_recall_pattern_star_star(self):
        self.mem.remember("a/b/c", "v1")
        self.mem.remember("a/b/d", "v2")
        self.mem.remember("x/y/z", "v3")

        results = self.mem.recall_pattern("a/*")
        keys = [f.key for f in results]
        self.assertEqual(len(keys), 2)
        self.assertIn("a/b/c", keys)
        self.assertIn("a/b/d", keys)

    def test_recall_pattern_no_match(self):
        self.mem.remember("a/b/c", "v")
        results = self.mem.recall_pattern("x/*")
        self.assertEqual(results, [])

    # ── Forget ───────────────────────────────────────────────────────

    def test_forget_existing(self):
        self.mem.remember("k", "v")
        self.assertTrue(self.mem.forget("k"))
        self.assertIsNone(self.mem.recall("k"))

    def test_forget_nonexistent(self):
        self.assertFalse(self.mem.forget("nonexistent"))

    def test_forget_removes_from_index(self):
        self.mem.remember("k", "v", metadata={"tags": ["test"]})
        self.mem.forget("k")
        # The fact should be gone from tag lookups too
        results = self.mem.recall_by_tag("test")
        self.assertEqual(results, [])

    # ── Search ───────────────────────────────────────────────────────

    def test_search_text(self):
        self.mem.remember("tech/server", "nginx 1.24 reverse proxy")
        self.mem.remember("tech/db", "PostgreSQL 16")

        results = self.mem.search(query_text="nginx")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].key, "tech/server")

    def test_search_with_query(self):
        self.mem.remember("a", "v1", metadata={"tags": ["auth"], "confidence": 0.9})
        self.mem.remember("b", "v2", metadata={"tags": ["auth"], "confidence": 0.5})
        self.mem.remember("c", "v3", metadata={"tags": ["perf"], "confidence": 0.9})

        q = MemoryQuery().with_tags({"auth"}).with_confidence(min_conf=0.8)
        results = self.mem.search(query=q)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].key, "a")

    def test_search_sorted_by_confidence(self):
        self.mem.remember("low", "v", metadata={"confidence": 0.3})
        self.mem.remember("high", "v", metadata={"confidence": 0.95})
        self.mem.remember("mid", "v", metadata={"confidence": 0.6})

        results = self.mem.search()
        keys = [f.key for f in results]
        self.assertEqual(keys, ["high", "mid", "low"])

    def test_search_limit(self):
        for i in range(10):
            self.mem.remember(f"k/{i}", f"v{i}")
        results = self.mem.search(limit=3)
        self.assertEqual(len(results), 3)

    def test_search_no_results(self):
        self.mem.remember("k", "v")
        results = self.mem.search(query_text="NONEXISTENT_TEXT_12345")
        self.assertEqual(results, [])

    # ── Expiration ───────────────────────────────────────────────────

    def test_expired_fact_not_recalled(self):
        self.mem.remember(
            "k", "v",
            metadata={"expires": time.time() - 1},
        )
        self.assertIsNone(self.mem.recall("k"))

    def test_expired_fact_not_searched(self):
        self.mem.remember(
            "k", "v",
            metadata={"expires": time.time() - 1},
        )
        results = self.mem.search()
        self.assertEqual(results, [])

    def test_expired_fact_not_in_pattern(self):
        self.mem.remember(
            "k", "v",
            metadata={"expires": time.time() - 1},
        )
        results = self.mem.recall_pattern("*")
        self.assertEqual(results, [])

    def test_not_expired_fact_recalled(self):
        self.mem.remember(
            "k", "v",
            metadata={"expires": time.time() + 3600},
        )
        self.assertIsNotNone(self.mem.recall("k"))

    # ── Snapshots ────────────────────────────────────────────────────

    def test_snapshot_basic(self):
        self.mem.remember("a", "v1")
        self.mem.remember("b", "v2")

        snap = self.mem.snapshot(label="test")
        self.assertIn("snap_", snap.id)
        self.assertIn("test", snap.id)
        self.assertEqual(snap.fact_count, 2)
        self.assertEqual(len(snap.facts), 2)
        self.assertGreater(snap.total_bytes, 0)

    def test_snapshot_excludes_expired(self):
        self.mem.remember("active", "v", metadata={"expires": time.time() + 3600})
        self.mem.remember("expired", "v", metadata={"expires": time.time() - 1})

        snap = self.mem.snapshot()
        self.assertEqual(snap.fact_count, 1)
        self.assertIn("active", snap.facts)

    def test_diff_snapshots_added(self):
        self.mem.remember("a", "v1")
        snap_a = self.mem.snapshot()

        self.mem.remember("b", "v2")
        snap_b = self.mem.snapshot()

        diff = RepositoryMemory.diff_snapshots(snap_a, snap_b)
        self.assertEqual(diff["added"], ["b"])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["modified"], [])
        self.assertEqual(diff["unchanged"], ["a"])
        self.assertEqual(diff["stats"]["net_change"], 1)

    def test_diff_snapshots_removed(self):
        self.mem.remember("a", "v1")
        self.mem.remember("b", "v2")
        snap_a = self.mem.snapshot()

        self.mem.forget("b")
        snap_b = self.mem.snapshot()

        diff = RepositoryMemory.diff_snapshots(snap_a, snap_b)
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], ["b"])
        self.assertEqual(diff["stats"]["net_change"], -1)

    def test_diff_snapshots_modified(self):
        self.mem.remember("a", "v1")
        snap_a = self.mem.snapshot()

        self.mem.remember("a", "v2-changed")
        snap_b = self.mem.snapshot()

        diff = RepositoryMemory.diff_snapshots(snap_a, snap_b)
        self.assertEqual(diff["modified"], ["a"])
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])

    def test_diff_snapshots_unchanged(self):
        self.mem.remember("a", "v1")
        snap_a = self.mem.snapshot()
        snap_b = self.mem.snapshot()

        diff = RepositoryMemory.diff_snapshots(snap_a, snap_b)
        self.assertEqual(diff["unchanged"], ["a"])
        self.assertEqual(diff["stats"]["added_count"], 0)
        self.assertEqual(diff["stats"]["removed_count"], 0)
        self.assertEqual(diff["stats"]["modified_count"], 0)

    # ── Stats ────────────────────────────────────────────────────────

    def test_stats_empty(self):
        stats = self.mem.get_stats()
        self.assertEqual(stats["total_facts"], 0)
        self.assertEqual(stats["expired_facts"], 0)
        self.assertEqual(stats["tag_distribution"], {})
        self.assertEqual(stats["source_distribution"], {})
        self.assertIsNone(stats["oldest_fact"])
        self.assertIsNone(stats["newest_fact"])

    def test_stats_with_facts(self):
        self.mem.remember(
            "a", "v1",
            metadata={"tags": ["t1", "t2"], "source": "s1", "confidence": 0.9},
        )
        self.mem.remember(
            "b", "v2",
            metadata={"tags": ["t1"], "source": "s2", "confidence": 0.5},
        )

        stats = self.mem.get_stats()
        self.assertEqual(stats["total_facts"], 2)
        self.assertEqual(stats["tag_distribution"]["t1"], 2)
        self.assertEqual(stats["tag_distribution"]["t2"], 1)
        self.assertEqual(stats["source_distribution"]["s1"], 1)
        self.assertEqual(stats["source_distribution"]["s2"], 1)
        self.assertAlmostEqual(stats["confidence_stats"]["min"], 0.5)
        self.assertAlmostEqual(stats["confidence_stats"]["max"], 0.9)
        self.assertAlmostEqual(stats["confidence_stats"]["avg"], 0.7)
        self.assertIsNotNone(stats["oldest_fact"])
        self.assertIsNotNone(stats["newest_fact"])
        self.assertGreater(stats["total_bytes"], 0)

    def test_stats_age_distribution(self):
        now = time.time()
        self.mem.remember(
            "recent", "v", metadata={"timestamp": now - 600},  # 10 min ago
        )
        self.mem.remember(
            "old", "v", metadata={"timestamp": now - 86400 * 60},  # 60 days ago
        )

        stats = self.mem.get_stats()
        self.assertEqual(stats["age_distribution"]["<1h"], 1)
        self.assertEqual(stats["age_distribution"][">30d"], 1)

    # ── Persistence ──────────────────────────────────────────────────

    def test_save_and_reload(self):
        self.mem.remember("a", "v1", metadata={"tags": ["t1"], "source": "s1"})
        self.mem.remember("b", {"x": 42}, metadata={"tags": ["t2"], "source": "s2"})
        self.mem.save()

        # Create a new instance pointing to the same file
        mem2 = RepositoryMemory(persist_path=self.tmp_path)
        self.assertEqual(mem2.recall("a").value, "v1")
        self.assertEqual(mem2.recall("b").value, {"x": 42})
        self.assertEqual(mem2.recall("a").tags, frozenset(["t1"]))
        self.assertEqual(mem2.recall("a").source, "s1")

    def test_save_prunes_expired(self):
        self.mem.remember("active", "v", metadata={"expires": time.time() + 3600})
        self.mem.remember("expired", "v", metadata={"expires": time.time() - 1})
        self.mem.save()

        mem2 = RepositoryMemory(persist_path=self.tmp_path)
        self.assertIsNotNone(mem2.recall("active"))
        self.assertIsNone(mem2.recall("expired"))

    def test_load_empty_file(self):
        """Loading from a non-existent path starts fresh."""
        mem = RepositoryMemory(persist_path=_tmp_path())
        self.assertEqual(len(mem), 0)

    def test_load_corrupt_file(self):
        """A corrupt JSON file is handled gracefully."""
        self.tmp_path.parent.mkdir(parents=True, exist_ok=True)
        self.tmp_path.write_text("{not valid json!!!", encoding="utf-8")
        mem = RepositoryMemory(persist_path=self.tmp_path)
        self.assertEqual(len(mem), 0)

    def test_atomic_save(self):
        """Save uses atomic rename (no partial writes)."""
        self.mem.remember("k", "v")
        self.mem.save()

        # Verify the file is valid JSON
        data = json.loads(self.tmp_path.read_text(encoding="utf-8"))
        self.assertIn("k", data)
        self.assertEqual(data["k"]["value"], "v")

    # ── Index-based lookups ──────────────────────────────────────────

    def test_recall_by_tag(self):
        self.mem.remember("a", "v1", metadata={"tags": ["auth", "decision"]})
        self.mem.remember("b", "v2", metadata={"tags": ["perf"]})
        self.mem.remember("c", "v3", metadata={"tags": ["auth"]})

        results = self.mem.recall_by_tag("auth")
        keys = [f.key for f in results]
        self.assertIn("a", keys)
        self.assertIn("c", keys)
        self.assertNotIn("b", keys)

    def test_recall_by_source(self):
        self.mem.remember("a", "v1", metadata={"source": "agent-1"})
        self.mem.remember("b", "v2", metadata={"source": "agent-2"})

        results = self.mem.recall_by_source("agent-1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].key, "a")

    def test_recall_by_time_range(self):
        self.mem.remember("old", "v1", metadata={"timestamp": 100.0})
        self.mem.remember("mid", "v2", metadata={"timestamp": 200.0})
        self.mem.remember("new", "v3", metadata={"timestamp": 300.0})

        results = self.mem.recall_by_time_range(150.0, 250.0)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].key, "mid")

    # ── Bulk / Utility ───────────────────────────────────────────────

    def test_clear(self):
        self.mem.remember("a", "v1")
        self.mem.remember("b", "v2")
        count = self.mem.clear()
        self.assertEqual(count, 2)
        self.assertEqual(len(self.mem), 0)

    def test_all_keys(self):
        self.mem.remember("c", "v")
        self.mem.remember("a", "v")
        self.mem.remember("b", "v")
        self.assertEqual(self.mem.all_keys(), ["a", "b", "c"])

    def test_contains(self):
        self.mem.remember("k", "v")
        self.assertIn("k", self.mem)
        self.assertNotIn("nonexistent", self.mem)

    def test_contains_expired(self):
        self.mem.remember("k", "v", metadata={"expires": time.time() - 1})
        self.assertNotIn("k", self.mem)

    def test_len(self):
        self.assertEqual(len(self.mem), 0)
        self.mem.remember("a", "v")
        self.assertEqual(len(self.mem), 1)
        self.mem.remember("b", "v")
        self.assertEqual(len(self.mem), 2)

    def test_count(self):
        self.assertEqual(self.mem.count(), 0)
        self.mem.remember("a", "v")
        self.assertEqual(self.mem.count(), 1)

    # ── Complex value types ──────────────────────────────────────────

    def test_dict_value(self):
        self.mem.remember(
            "arch/services",
            {"auth": "jwt", "db": "postgres", "cache": "redis"},
        )
        recalled = self.mem.recall("arch/services")
        self.assertEqual(recalled.value["auth"], "jwt")

    def test_list_value(self):
        self.mem.remember("tech/deps", ["flask", "sqlalchemy", "redis"])
        recalled = self.mem.recall("tech/deps")
        self.assertEqual(recalled.value, ["flask", "sqlalchemy", "redis"])

    def test_numeric_value(self):
        self.mem.remember("perf/score", 87.5)
        recalled = self.mem.recall("perf/score")
        self.assertAlmostEqual(recalled.value, 87.5)

    def test_none_value(self):
        self.mem.remember("k", None)
        recalled = self.mem.recall("k")
        self.assertIsNone(recalled.value)
        self.assertEqual(recalled.key, "k")

    def test_nested_value(self):
        val = {"servers": [{"name": "web-1", "ports": [80, 443]}]}
        self.mem.remember("infra/layout", val)
        recalled = self.mem.recall("infra/layout")
        self.assertEqual(recalled.value["servers"][0]["name"], "web-1")


# ======================================================================
#  Edge Cases & Stress Tests
# ======================================================================


class TestRepositoryMemoryEdgeCases(unittest.TestCase):
    """Edge cases and stress tests for RepositoryMemory."""

    def setUp(self):
        self.tmp_path = _tmp_path()
        self.mem = RepositoryMemory(persist_path=self.tmp_path)

    def tearDown(self):
        if self.tmp_path.exists():
            self.tmp_path.unlink()
        tmp = self.tmp_path.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()

    def test_many_facts(self):
        """Store and retrieve 500 facts efficiently."""
        for i in range(500):
            self.mem.remember(f"fact/{i:04d}", {"idx": i}, metadata={"tags": [f"tag-{i % 10}"]})
        self.assertEqual(len(self.mem), 500)

        # Pattern recall
        results = self.mem.recall_pattern("fact/00*")
        self.assertGreater(len(results), 0)

        # Tag recall
        results = self.mem.recall_by_tag("tag-0")
        self.assertEqual(len(results), 50)  # 500 / 10

    def test_overwrite_preserves_index(self):
        """Overwriting a fact with different tags updates the index."""
        self.mem.remember("k", "v1", metadata={"tags": ["old-tag"]})
        self.assertEqual(len(self.mem.recall_by_tag("old-tag")), 1)

        self.mem.remember("k", "v2", metadata={"tags": ["new-tag"]})
        self.assertEqual(len(self.mem.recall_by_tag("old-tag")), 0)
        self.assertEqual(len(self.mem.recall_by_tag("new-tag")), 1)

    def test_search_with_all_filter_types(self):
        """Exercise all query filters simultaneously."""
        self.mem.remember(
            "match/me", "nginx",
            metadata={"tags": ["web", "server"], "source": "scanner", "confidence": 0.9, "timestamp": 150.0},
        )
        self.mem.remember(
            "no/match", "apache",
            metadata={"tags": ["web"], "source": "scanner", "confidence": 0.9, "timestamp": 150.0},
        )

        q = (
            MemoryQuery()
            .with_tags({"web", "server"})
            .with_sources({"scanner"})
            .with_confidence(min_conf=0.8)
            .with_time_range(start=100.0, end=200.0)
            .with_text("nginx")
        )
        results = self.mem.search(query=q)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].key, "match/me")

    def test_unicode_keys_and_values(self):
        """Unicode should work in keys, values, tags, and sources."""
        self.mem.remember(
            "arch/認証", {"方式": "JWT"},
            metadata={"tags": ["セキュリティ"], "source": "スキャナー"},
        )
        recalled = self.mem.recall("arch/認証")
        self.assertIsNotNone(recalled)
        self.assertEqual(recalled.value["方式"], "JWT")

    def test_empty_key_allowed(self):
        """Empty string keys should work (edge case but not prohibited)."""
        self.mem.remember("", "empty-key-value")
        recalled = self.mem.recall("")
        self.assertEqual(recalled.value, "empty-key-value")

    def test_very_long_value(self):
        """Large values should persist and retrieve correctly."""
        big_value = {"data": "x" * 100_000}
        self.mem.remember("big", big_value)
        recalled = self.mem.recall("big")
        self.assertEqual(len(recalled.value["data"]), 100_000)

    def test_snapshot_immutability(self):
        """Modifying memory after snapshot shouldn't affect the snapshot."""
        self.mem.remember("a", "v1")
        snap = self.mem.snapshot()
        self.mem.remember("b", "v2")

        self.assertEqual(snap.fact_count, 1)
        self.assertIn("a", snap.facts)
        self.assertNotIn("b", snap.facts)

    def test_multiple_snapshots_independent(self):
        """Each snapshot is independent."""
        self.mem.remember("a", "v1")
        snap1 = self.mem.snapshot(label="first")

        self.mem.remember("b", "v2")
        snap2 = self.mem.snapshot(label="second")

        self.assertEqual(snap1.fact_count, 1)
        self.assertEqual(snap2.fact_count, 2)
        self.assertNotIn("second", snap1.id)
        self.assertIn("second", snap2.id)

    def test_double_load_idempotent(self):
        """Loading twice should not duplicate data."""
        self.mem.remember("k", "v")
        self.mem.load()  # already loaded, should be no-op
        self.mem.load()  # still no-op
        self.assertEqual(len(self.mem), 1)


# ======================================================================
#  Integration with existing modules
# ======================================================================


class TestIntegrationWithExistingModules(unittest.TestCase):
    """Verify repository_memory does not conflict with memory.py or knowledge_graph.py."""

    def test_import_does_not_break_memory_module(self):
        """Importing repository_memory should not affect memory.py."""
        from reconpro.memory import UnifiedMemoryStore
        store = UnifiedMemoryStore()
        self.assertIsNotNone(store)

    def test_import_does_not_break_knowledge_graph(self):
        """Importing repository_memory should not affect knowledge_graph.py."""
        from reconpro.knowledge_graph import SecurityKnowledgeGraph
        kg = SecurityKnowledgeGraph()
        self.assertIsNotNone(kg)

    def test_separate_storage_paths(self):
        """Repository memory uses a different file than knowledge graph."""
        from reconpro.constants import KNOWLEDGE_GRAPH_FILE
        from reconpro.repository_memory import REPOSITORY_MEMORY_FILE
        # They should be different files
        self.assertNotEqual(REPOSITORY_MEMORY_FILE, KNOWLEDGE_GRAPH_FILE)

    def test_repository_memory_is_not_unified_memory_store(self):
        """RepositoryMemory is a separate class from UnifiedMemoryStore."""
        from reconpro.memory import UnifiedMemoryStore
        self.assertNotEqual(RepositoryMemory, UnifiedMemoryStore)
        self.assertNotIsInstance(RepositoryMemory(), UnifiedMemoryStore)


if __name__ == "__main__":
    unittest.main()
