"""ReconPro v11 — Tests for engineering_recommendations.py.

Covers:
- Recommendation dataclass: creation, serialisation, normalisation, priority scoring
- RecommendationStore: CRUD, persistence, filtering, search, pruning
- RecommendationEngine: rule generation from all 5 input types
- RecommendationEngine: deduplication via Jaccard similarity
- RecommendationEngine: aging / severity escalation
- EngineeringRecommender: facade API (recommend_from_*, dismiss, stats)
- Module-level convenience functions
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure parent package is importable
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

from reconpro.engineering_recommendations import (
    EngineeringRecommender,
    Recommendation,
    RecommendationEngine,
    RecommendationStore,
    _DEDUP_THRESHOLD,
    _EFFORT_SCORE,
    _SEVERITY_SCORE,
    _STALE_DAYS,
    _VERY_STALE_DAYS,
    get_recommender,
    reset_recommender,
)


# ═══════════════════════════════════════════════════════════════════════════
# Test Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _tmp_store() -> tuple[RecommendationStore, Path]:
    """Create a RecommendationStore backed by a temp file."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    path.unlink(missing_ok=True)  # Ensure clean slate
    store = RecommendationStore(path=path)
    return store, path


def _make_rec(**overrides) -> Recommendation:
    """Create a test Recommendation with sensible defaults."""
    defaults = dict(
        title="Test recommendation",
        description="A test recommendation for validation.",
        severity="medium",
        category="testing",
        effort_estimate="small",
        affected_files=["test_module.py"],
        suggested_fix="Fix the thing.",
        evidence="Evidence here.",
        confidence=0.8,
        source="unit_test",
    )
    defaults.update(overrides)
    return Recommendation(**defaults)


# ═══════════════════════════════════════════════════════════════════════════
# Recommendation Dataclass Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRecommendation(unittest.TestCase):
    """Tests for the Recommendation dataclass."""

    def test_creation_with_defaults(self):
        rec = Recommendation(title="Test", description="Desc")
        self.assertTrue(len(rec.id) > 0)
        self.assertEqual(rec.title, "Test")
        self.assertEqual(rec.description, "Desc")
        self.assertEqual(rec.severity, "medium")
        self.assertFalse(rec.dismissed)
        self.assertGreater(rec.created_at, "")

    def test_id_is_deterministic(self):
        rec1 = Recommendation(title="A", category="x", source="y", affected_files=["f1"])
        rec2 = Recommendation(title="A", category="x", source="y", affected_files=["f1"])
        self.assertEqual(rec1.id, rec2.id)

    def test_id_differs_for_different_content(self):
        rec1 = Recommendation(title="A", category="x", source="y", affected_files=[])
        rec2 = Recommendation(title="B", category="x", source="y", affected_files=[])
        self.assertNotEqual(rec1.id, rec2.id)

    def test_severity_normalised(self):
        rec = Recommendation(title="T", severity="CRITICAL")
        self.assertEqual(rec.severity, "critical")

    def test_invalid_severity_falls_back_to_medium(self):
        rec = Recommendation(title="T", severity="INVALID")
        self.assertEqual(rec.severity, "medium")

    def test_confidence_clamped_high(self):
        rec = Recommendation(title="T", confidence=1.5)
        self.assertEqual(rec.confidence, 1.0)

    def test_confidence_clamped_low(self):
        rec = Recommendation(title="T", confidence=-0.5)
        self.assertEqual(rec.confidence, 0.0)

    def test_effort_normalised(self):
        rec = Recommendation(title="T", effort_estimate="LARGE")
        self.assertEqual(rec.effort_estimate, "large")

    def test_invalid_effort_falls_back_to_small(self):
        rec = Recommendation(title="T", effort_estimate="massive")
        self.assertEqual(rec.effort_estimate, "small")

    def test_priority_score_computed(self):
        rec = Recommendation(title="T", severity="high", confidence=0.9, effort_estimate="small")
        # high=8.0 * 10 + 0.9 * 10 - 2.0 * 2 = 80 + 9 - 4 = 85
        self.assertAlmostEqual(rec.priority_score, 85.0, places=1)

    def test_priority_score_critical_trivial(self):
        rec = Recommendation(title="T", severity="critical", confidence=1.0, effort_estimate="trivial")
        # critical=10 * 10 + 1.0 * 10 - 1.0 * 2 = 100 + 10 - 2 = 108
        self.assertAlmostEqual(rec.priority_score, 108.0, places=1)

    def test_to_dict_roundtrip(self):
        rec = _make_rec(title="Roundtrip test", severity="high", effort_estimate="large")
        d = rec.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["title"], "Roundtrip test")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["category"], "testing")
        self.assertEqual(d["effort_estimate"], "large")
        self.assertAlmostEqual(d["confidence"], 0.8)
        self.assertIsInstance(d["affected_files"], list)

    def test_from_dict(self):
        data = {
            "id": "abc123",
            "title": "From dict",
            "description": "Desc",
            "severity": "low",
            "category": "performance",
            "effort_estimate": "medium",
            "affected_files": ["a.py", "b.py"],
            "suggested_fix": "Do X.",
            "evidence": "Because.",
            "confidence": 0.6,
            "created_at": "2025-01-01T00:00:00+00:00",
            "dismissed": True,
            "dismissed_reason": "Not needed",
            "priority_score": 42.0,
            "source": "test",
        }
        rec = Recommendation.from_dict(data)
        self.assertEqual(rec.id, "abc123")
        self.assertEqual(rec.title, "From dict")
        self.assertEqual(rec.severity, "low")
        self.assertTrue(rec.dismissed)
        self.assertEqual(rec.dismissed_reason, "Not needed")

    def test_from_dict_defaults(self):
        rec = Recommendation.from_dict({})
        self.assertEqual(rec.severity, "medium")
        self.assertEqual(rec.effort_estimate, "small")
        self.assertFalse(rec.dismissed)


# ═══════════════════════════════════════════════════════════════════════════
# RecommendationStore Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRecommendationStore(unittest.TestCase):
    """Tests for the RecommendationStore persistence layer."""

    def setUp(self):
        self.store, self.path = _tmp_store()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_empty_store(self):
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.active_count(), 0)

    def test_add_and_get(self):
        rec = _make_rec(title="Store test")
        self.assertTrue(self.store.add(rec))
        fetched = self.store.get(rec.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.title, "Store test")

    def test_add_duplicate_not_overwritten(self):
        rec1 = _make_rec(title="Dupe test")
        self.assertTrue(self.store.add(rec1))
        # Adding same recommendation again should return False.
        self.assertFalse(self.store.add(rec1))
        self.assertEqual(self.store.count(), 1)

    def test_add_without_id_returns_false(self):
        rec = Recommendation.__new__(Recommendation)
        rec.id = ""
        rec.title = ""
        rec.description = ""
        rec.severity = "medium"
        rec.category = "test"
        rec.effort_estimate = "small"
        rec.affected_files = []
        rec.suggested_fix = ""
        rec.evidence = ""
        rec.confidence = 0.5
        rec.created_at = ""
        rec.dismissed = False
        rec.dismissed_reason = ""
        rec.priority_score = 0.0
        rec.source = ""
        self.assertFalse(self.store.add(rec))

    def test_dismiss(self):
        rec = _make_rec()
        self.store.add(rec)
        self.assertTrue(self.store.dismiss(rec.id, "Test dismissal"))
        fetched = self.store.get(rec.id)
        self.assertTrue(fetched.dismissed)
        self.assertEqual(fetched.dismissed_reason, "Test dismissal")

    def test_dismiss_nonexistent(self):
        self.assertFalse(self.store.dismiss("nonexistent"))

    def test_restore(self):
        rec = _make_rec()
        self.store.add(rec)
        self.store.dismiss(rec.id, "reason")
        self.assertTrue(self.store.restore(rec.id))
        fetched = self.store.get(rec.id)
        self.assertFalse(fetched.dismissed)
        self.assertEqual(fetched.dismissed_reason, "")

    def test_restore_nonexistent(self):
        self.assertFalse(self.store.restore("nonexistent"))

    def test_remove(self):
        rec = _make_rec()
        self.store.add(rec)
        self.assertTrue(self.store.remove(rec.id))
        self.assertIsNone(self.store.get(rec.id))
        self.assertEqual(self.store.count(), 0)

    def test_remove_nonexistent(self):
        self.assertFalse(self.store.remove("nonexistent"))

    def test_get_all(self):
        for i in range(5):
            self.store.add(_make_rec(title=f"Rec {i}", source=f"src{i}"))
        all_recs = self.store.get_all()
        self.assertEqual(len(all_recs), 5)

    def test_get_active(self):
        r1 = _make_rec(title="Active 1")
        r2 = _make_rec(title="Active 2")
        r3 = _make_rec(title="Dismissed")
        self.store.add(r1)
        self.store.add(r2)
        self.store.add(r3)
        self.store.dismiss(r3.id)
        active = self.store.get_active()
        self.assertEqual(len(active), 2)
        # Should be sorted by priority descending
        titles = [r.title for r in active]
        self.assertIn("Active 1", titles)
        self.assertIn("Active 2", titles)

    def test_get_dismissed(self):
        r1 = _make_rec(title="Keep")
        r2 = _make_rec(title="Gone")
        self.store.add(r1)
        self.store.add(r2)
        self.store.dismiss(r2.id)
        dismissed = self.store.get_dismissed()
        self.assertEqual(len(dismissed), 1)
        self.assertEqual(dismissed[0].title, "Gone")

    def test_active_count(self):
        for i in range(3):
            self.store.add(_make_rec(title=f"R{i}"))
        self.store.dismiss(self.store.get_all()[0].id)
        self.assertEqual(self.store.active_count(), 2)

    def test_clear_dismissed(self):
        r1 = _make_rec(title="Keep")
        r2 = _make_rec(title="Gone 1")
        r3 = _make_rec(title="Gone 2")
        self.store.add(r1)
        self.store.add(r2)
        self.store.add(r3)
        self.store.dismiss(r2.id)
        self.store.dismiss(r3.id)
        removed = self.store.clear_dismissed()
        self.assertEqual(removed, 2)
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.active_count(), 1)

    def test_filter_by_severity(self):
        self.store.add(_make_rec(title="High", severity="high"))
        self.store.add(_make_rec(title="Low", severity="low"))
        self.store.add(_make_rec(title="Med", severity="medium"))
        high = self.store.filter_by_severity("high")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].title, "High")

    def test_filter_by_category(self):
        self.store.add(_make_rec(title="D1", category="diagnostics"))
        self.store.add(_make_rec(title="D2", category="diagnostics"))
        self.store.add(_make_rec(title="T1", category="testing"))
        diag = self.store.filter_by_category("diagnostics")
        self.assertEqual(len(diag), 2)

    def test_filter_by_source(self):
        self.store.add(_make_rec(title="S1", source="drift"))
        self.store.add(_make_rec(title="S2", source="diagnostics"))
        result = self.store.filter_by_source("drift")
        self.assertEqual(len(result), 1)

    def test_search(self):
        self.store.add(_make_rec(title="Fix memory leak in scanner module"))
        self.store.add(_make_rec(title="Update TLS certificate handling"))
        results = self.store.search("memory")
        self.assertEqual(len(results), 1)
        self.assertIn("memory", results[0].title.lower())

    def test_search_case_insensitive(self):
        self.store.add(_make_rec(title="Fix Memory Leak"))
        results = self.store.search("memory")
        self.assertEqual(len(results), 1)

    def test_search_in_description(self):
        self.store.add(_make_rec(title="X", description="This is about performance optimization"))
        results = self.store.search("performance")
        self.assertEqual(len(results), 1)

    def test_search_no_results(self):
        self.store.add(_make_rec(title="Completely unrelated"))
        results = self.store.search("quantum entanglement")
        self.assertEqual(len(results), 0)

    def test_persistence(self):
        """Recommendations survive store reload."""
        rec = _make_rec(title="Persistent")
        self.store.add(rec)
        # Reload from same file
        new_store = RecommendationStore(path=self.path)
        fetched = new_store.get(rec.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.title, "Persistent")

    def test_loads_from_existing_file(self):
        """Store can load from a pre-existing JSON file."""
        data = {
            "abc123": {
                "id": "abc123",
                "title": "Pre-loaded",
                "description": "From file",
                "severity": "high",
                "category": "testing",
                "effort_estimate": "small",
                "affected_files": [],
                "suggested_fix": "Fix it.",
                "evidence": "Evident.",
                "confidence": 0.9,
                "created_at": "2025-06-01T00:00:00+00:00",
                "dismissed": False,
                "dismissed_reason": "",
                "priority_score": 86.0,
                "source": "test",
            }
        }
        with open(self.path, "w") as f:
            json.dump(data, f)
        store = RecommendationStore(path=self.path)
        self.assertEqual(store.count(), 1)
        self.assertEqual(store.get("abc123").title, "Pre-loaded")

    def test_loads_from_corrupt_file(self):
        """Store gracefully handles corrupt JSON."""
        with open(self.path, "w") as f:
            f.write("{invalid json}")
        store = RecommendationStore(path=self.path)
        self.assertEqual(store.count(), 0)

    def test_loads_from_non_dict_file(self):
        """Store gracefully handles non-dict JSON."""
        with open(self.path, "w") as f:
            json.dump([1, 2, 3], f)
        store = RecommendationStore(path=self.path)
        self.assertEqual(store.count(), 0)

    def test_add_dismissed_allows_re_add(self):
        """A dismissed recommendation can be re-added (overwritten)."""
        rec = _make_rec(title="Re-add")
        self.store.add(rec)
        self.store.dismiss(rec.id, "old reason")
        # Re-add with updated info
        new_rec = _make_rec(title="Re-add updated", severity="high")
        new_rec.id = rec.id  # Force same ID
        self.assertTrue(self.store.add(new_rec))
        fetched = self.store.get(rec.id)
        self.assertEqual(fetched.title, "Re-add updated")
        self.assertFalse(fetched.dismissed)


# ═══════════════════════════════════════════════════════════════════════════
# RecommendationEngine Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRecommendationEngineDedup(unittest.TestCase):
    """Tests for deduplication logic."""

    def test_jaccard_identical(self):
        engine = RecommendationEngine()
        sim = engine._jaccard("hello world", "hello world")
        self.assertEqual(sim, 1.0)

    def test_jaccard_disjoint(self):
        engine = RecommendationEngine()
        sim = engine._jaccard("abc def", "xyz uvw")
        self.assertEqual(sim, 0.0)

    def test_jaccard_partial(self):
        engine = RecommendationEngine()
        sim = engine._jaccard("fix memory leak", "fix memory issue")
        # tokens: {fix, memory, leak} vs {fix, memory, issue}
        # intersection = {fix, memory}, union = {fix, memory, leak, issue}
        self.assertAlmostEqual(sim, 2 / 4, places=2)

    def test_jaccard_empty(self):
        engine = RecommendationEngine()
        self.assertEqual(engine._jaccard("", "test"), 0.0)
        self.assertEqual(engine._jaccard("test", ""), 0.0)

    def test_is_duplicate_true(self):
        engine = RecommendationEngine()
        existing = [_make_rec(title="Fix memory leak in scanner", category="performance")]
        candidate = _make_rec(title="Fix memory leak in scanner module", category="performance")
        candidate.id = "different_id_12345678"  # Force unique ID
        self.assertTrue(engine._is_duplicate(candidate, existing))

    def test_is_duplicate_false_different_category(self):
        engine = RecommendationEngine()
        existing = [_make_rec(title="Fix memory leak", category="performance")]
        candidate = _make_rec(title="Fix memory leak", category="testing")
        candidate.id = "different_id_12345678"
        self.assertFalse(engine._is_duplicate(candidate, existing))

    def test_is_duplicate_false_different_title(self):
        engine = RecommendationEngine()
        existing = [_make_rec(title="Fix memory leak in scanner", category="performance")]
        candidate = _make_rec(title="Update TLS configuration", category="performance")
        candidate.id = "different_id_12345678"
        self.assertFalse(engine._is_duplicate(candidate, existing))

    def test_is_duplicate_false_dismissed(self):
        """Dismissed recommendations don't count as duplicates."""
        engine = RecommendationEngine()
        rec = _make_rec(title="Fix memory leak", category="performance")
        rec.dismissed = True
        existing = [rec]
        candidate = _make_rec(title="Fix memory leak", category="performance")
        candidate.id = "different_id_12345678"
        self.assertFalse(engine._is_duplicate(candidate, existing))

    def test_is_duplicate_shared_files(self):
        """High file overlap + moderate title similarity = duplicate."""
        engine = RecommendationEngine()
        existing = [_make_rec(
            title="Scanner memory issues",
            category="performance",
            affected_files=["scanner.py", "utils.py"],
        )]
        candidate = _make_rec(
            title="Scanner has memory problems",
            category="performance",
            affected_files=["scanner.py", "utils.py"],
        )
        candidate.id = "different_id_12345678"
        self.assertTrue(engine._is_duplicate(candidate, existing))


class TestRecommendationEngineAging(unittest.TestCase):
    """Tests for recommendation aging / severity escalation."""

    def test_fresh_recommendation_unchanged(self):
        rec = _make_rec(severity="low")
        # created_at defaults to now, so it should be fresh.
        aged = RecommendationEngine._age_recommendation(rec)
        self.assertEqual(aged.severity, "low")

    def test_stale_recommendation_escalated(self):
        rec = _make_rec(severity="low")
        # Set created_at to _STALE_DAYS + 1 days ago.
        from datetime import datetime, timezone, timedelta
        old_time = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS + 1)
        rec.created_at = old_time.isoformat()
        aged = RecommendationEngine._age_recommendation(rec)
        self.assertEqual(aged.severity, "medium")

    def test_very_stale_recommendation_escalated_twice(self):
        rec = _make_rec(severity="low")
        from datetime import datetime, timezone, timedelta
        old_time = datetime.now(timezone.utc) - timedelta(days=_VERY_STALE_DAYS + 1)
        rec.created_at = old_time.isoformat()
        aged = RecommendationEngine._age_recommendation(rec)
        self.assertEqual(aged.severity, "high")

    def test_critical_does_not_escalate_beyond(self):
        rec = _make_rec(severity="critical")
        from datetime import datetime, timezone, timedelta
        old_time = datetime.now(timezone.utc) - timedelta(days=_VERY_STALE_DAYS + 1)
        rec.created_at = old_time.isoformat()
        aged = RecommendationEngine._age_recommendation(rec)
        self.assertEqual(aged.severity, "critical")

    def test_escalate_severity_steps(self):
        self.assertEqual(RecommendationEngine._escalate_severity("info", 1), "low")
        self.assertEqual(RecommendationEngine._escalate_severity("info", 2), "medium")
        self.assertEqual(RecommendationEngine._escalate_severity("medium", 1), "high")
        self.assertEqual(RecommendationEngine._escalate_severity("high", 1), "critical")
        self.assertEqual(RecommendationEngine._escalate_severity("critical", 1), "critical")
        self.assertEqual(RecommendationEngine._escalate_severity("critical", 10), "critical")

    def test_escalate_severity_invalid(self):
        self.assertEqual(RecommendationEngine._escalate_severity("INVALID", 1), "invalid")

    def test_escalate_severity_zero_steps(self):
        self.assertEqual(RecommendationEngine._escalate_severity("low", 0), "low")

    def test_bad_created_at_unchanged(self):
        rec = _make_rec(severity="low")
        rec.created_at = "not-a-date"
        aged = RecommendationEngine._age_recommendation(rec)
        self.assertEqual(aged.severity, "low")


# ═══════════════════════════════════════════════════════════════════════════
# Diagnostic Recommendation Generation
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateFromDiagnostics(unittest.TestCase):
    """Tests for generate_from_diagnostics()."""

    def setUp(self):
        self.store, self.path = _tmp_store()
        self.engine = RecommendationEngine(store=self.store)

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_all_passing_no_recommendations(self):
        diag = {
            "timestamp": "2025-01-01T00:00:00+00:00",
            "total_checks": 10,
            "passed": 10,
            "failed": 0,
            "checks": [
                {"label": f"check_{i}", "status": "ok", "value": None}
                for i in range(10)
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertEqual(len(recs), 0)

    def test_empty_input(self):
        recs = self.engine.generate_from_diagnostics({})
        self.assertEqual(len(recs), 0)

    def test_none_input(self):
        recs = self.engine.generate_from_diagnostics(None)  # type: ignore
        self.assertEqual(len(recs), 0)

    def test_broken_modules_generates_recommendation(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 9,
            "failed": 1,
            "checks": [
                {"label": "module_registry", "status": "error",
                 "error": "broken runners", "value": {"broken": ["mod_a", "mod_b"]}},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertGreater(len(recs), 0)
        titles = [r.title for r in recs]
        self.assertTrue(any("broken" in t.lower() and "module" in t.lower() for t in titles))

    def test_disk_space_failure(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 9,
            "failed": 1,
            "checks": [
                {"label": "disk_space", "status": "error", "error": "no space"},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("disk" in r.title.lower() for r in recs))

    def test_network_failure(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 9,
            "failed": 1,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "unreachable"},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("network" in r.title.lower() for r in recs))

    def test_ssl_failure(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 9,
            "failed": 1,
            "checks": [
                {"label": "ssl_certificate", "status": "error", "error": "verify failed"},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("ssl" in r.title.lower() for r in recs))

    def test_multiple_failures(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 4,
            "failed": 6,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "dns fail"},
                {"label": "disk_space", "status": "error", "error": "no space"},
                {"label": "ssl_certificate", "status": "error", "error": "ssl fail"},
                {"label": "plugin_directory", "status": "error", "error": "missing"},
                {"label": "scan_history", "status": "error", "error": "missing"},
                {"label": "memory", "status": "error", "error": "unavailable"},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        self.assertGreaterEqual(len(recs), 5)

    def test_recommendations_have_required_fields(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 9,
            "failed": 1,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
            ],
        }
        recs = self.engine.generate_from_diagnostics(diag)
        for r in recs:
            self.assertTrue(len(r.id) > 0)
            self.assertTrue(len(r.title) > 0)
            self.assertTrue(len(r.description) > 0)
            self.assertTrue(len(r.suggested_fix) > 0)
            self.assertTrue(len(r.evidence) > 0)
            self.assertGreater(r.confidence, 0.0)
            self.assertEqual(r.source, "diagnostics")


# ═══════════════════════════════════════════════════════════════════════════
# Drift Recommendation Generation
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateFromDrift(unittest.TestCase):
    """Tests for generate_from_drift()."""

    def setUp(self):
        self.store, self.path = _tmp_store()
        self.engine = RecommendationEngine(store=self.store)

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_no_drift_no_recommendations(self):
        report = {"target": "example.com", "drift_detected": False, "drift_events": []}
        recs = self.engine.generate_from_drift(report)
        self.assertEqual(len(recs), 0)

    def test_empty_input(self):
        recs = self.engine.generate_from_drift({})
        self.assertEqual(len(recs), 0)

    def test_security_header_removal(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 2,
            "risk_score": 85.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02T00:00:00+00:00",
                    "field_changed": "security_header_removed:strict-transport-security",
                    "old_value": "present",
                    "new_value": "removed",
                    "severity": "critical",
                    "risk_impact": "HSTS header removed",
                },
                {
                    "timestamp": "2025-01-02T00:00:00+00:00",
                    "field_changed": "security_header_removed:content-security-policy",
                    "old_value": "present",
                    "new_value": "removed",
                    "severity": "high",
                    "risk_impact": "CSP header removed",
                },
            ],
        }
        recs = self.engine.generate_from_drift(report)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("security header" in r.title.lower() for r in recs))

    def test_new_ports(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 3,
            "risk_score": 70.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "PORT_CHANGE",
                    "old_value": "",
                    "new_value": "8080",
                    "severity": "high",
                    "risk_impact": "New port 8080 added",
                },
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "PORT_CHANGE",
                    "old_value": "",
                    "new_value": "3306",
                    "severity": "high",
                    "risk_impact": "New port 3306 added",
                },
            ],
        }
        recs = self.engine.generate_from_drift(report)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("port" in r.title.lower() for r in recs))

    def test_tech_stack_change(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 1,
            "risk_score": 40.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "TECH_CHANGE",
                    "old_value": "",
                    "new_value": "React",
                    "severity": "medium",
                    "risk_impact": "New technology React added",
                },
            ],
        }
        recs = self.engine.generate_from_drift(report)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("technology" in r.title.lower() or "tech" in r.title.lower() for r in recs))

    def test_dns_change(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 1,
            "risk_score": 50.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "DNS_CHANGE",
                    "old_value": "1.2.3.4",
                    "new_value": "5.6.7.8",
                    "severity": "high",
                    "risk_impact": "A record changed",
                },
            ],
        }
        recs = self.engine.generate_from_drift(report)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("dns" in r.title.lower() for r in recs))

    def test_high_volume_drift(self):
        events = [
            {
                "timestamp": "2025-01-02",
                "field_changed": "HEADER_CHANGE",
                "old_value": "old",
                "new_value": "new",
                "severity": "low",
                "risk_impact": "Header changed",
            }
            for _ in range(12)
        ]
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 12,
            "risk_score": 60.0,
            "drift_events": events,
        }
        recs = self.engine.generate_from_drift(report)
        self.assertTrue(any("high volume" in r.title.lower() for r in recs))

    def test_5xx_status_change(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 1,
            "risk_score": 80.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "STATUS_CHANGE",
                    "old_value": "200",
                    "new_value": "502",
                    "severity": "high",
                    "risk_impact": "Status changed",
                },
            ],
        }
        recs = self.engine.generate_from_drift(report)
        self.assertTrue(any("5xx" in r.title.lower() or "error" in r.title.lower() for r in recs))


# ═══════════════════════════════════════════════════════════════════════════
# Test Results Recommendation Generation
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateFromTestResults(unittest.TestCase):
    """Tests for generate_from_test_results()."""

    def setUp(self):
        self.store, self.path = _tmp_store()
        self.engine = RecommendationEngine(store=self.store)

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_perfect_pass_no_recommendations(self):
        results = {"total": 100, "passed": 100, "failed": 0, "errors": 0, "skipped": 0, "duration_s": 5.0, "failures": []}
        recs = self.engine.generate_from_test_results(results)
        self.assertEqual(len(recs), 0)

    def test_empty_input(self):
        recs = self.engine.generate_from_test_results({})
        self.assertEqual(len(recs), 0)

    def test_zero_total(self):
        recs = self.engine.generate_from_test_results({"total": 0})
        self.assertEqual(len(recs), 0)

    def test_low_pass_rate(self):
        results = {
            "total": 50, "passed": 30, "failed": 15, "errors": 5,
            "skipped": 0, "duration_s": 10.0,
            "failures": [
                {"test_name": "test_a", "error_message": "assertion failed", "file": "a.py"},
                {"test_name": "test_b", "error_message": "assertion failed", "file": "b.py"},
            ],
        }
        recs = self.engine.generate_from_test_results(results)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("pass rate" in r.title.lower() for r in recs))

    def test_test_errors(self):
        results = {
            "total": 20, "passed": 15, "failed": 2, "errors": 3,
            "skipped": 0, "duration_s": 5.0,
            "failures": [
                {"test_name": "test_err", "error_message": "ImportError: no module", "file": "err.py"},
            ],
        }
        recs = self.engine.generate_from_test_results(results)
        self.assertTrue(any("error" in r.title.lower() for r in recs))

    def test_high_skip_rate(self):
        results = {
            "total": 100, "passed": 60, "failed": 0, "errors": 0,
            "skipped": 30, "duration_s": 5.0, "failures": [],
        }
        recs = self.engine.generate_from_test_results(results)
        self.assertTrue(any("skip" in r.title.lower() for r in recs))

    def test_slow_suite(self):
        results = {
            "total": 50, "passed": 50, "failed": 0, "errors": 0,
            "skipped": 0, "duration_s": 45.0, "failures": [],
        }
        recs = self.engine.generate_from_test_results(results)
        self.assertTrue(any("slow" in r.title.lower() for r in recs))

    def test_repeated_failures_in_file(self):
        results = {
            "total": 20, "passed": 10, "failed": 5, "errors": 0,
            "skipped": 5, "duration_s": 5.0,
            "failures": [
                {"test_name": f"test_{i}", "error_message": "fail", "file": "bad_module.py"}
                for i in range(5)
            ],
        }
        recs = self.engine.generate_from_test_results(results)
        self.assertTrue(any("bad_module.py" in str(r.affected_files) for r in recs))

    def test_source_is_testing(self):
        results = {
            "total": 10, "passed": 3, "failed": 5, "errors": 2,
            "skipped": 0, "duration_s": 5.0,
            "failures": [{"test_name": "t", "error_message": "e", "file": "f"}],
        }
        recs = self.engine.generate_from_test_results(results)
        for r in recs:
            self.assertEqual(r.source, "testing")


# ═══════════════════════════════════════════════════════════════════════════
# Performance Recommendation Generation
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateFromPerformance(unittest.TestCase):
    """Tests for generate_from_performance()."""

    def setUp(self):
        self.store, self.path = _tmp_store()
        self.engine = RecommendationEngine(store=self.store)

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_healthy_no_recommendations(self):
        perf = {
            "scan_duration_s": 5.0,
            "module_timings": {"recon": {"duration_s": 3.0, "findings_count": 10}},
            "memory_peak_mb": 50.0,
            "request_count": 100,
            "error_count": 0,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertEqual(len(recs), 0)

    def test_empty_input(self):
        recs = self.engine.generate_from_performance({})
        self.assertEqual(len(recs), 0)

    def test_high_error_rate(self):
        perf = {
            "scan_duration_s": 10.0,
            "module_timings": {},
            "memory_peak_mb": 50.0,
            "request_count": 100,
            "error_count": 15,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertTrue(any("error rate" in r.title.lower() for r in recs))

    def test_high_timeout_rate(self):
        perf = {
            "scan_duration_s": 10.0,
            "module_timings": {},
            "memory_peak_mb": 50.0,
            "request_count": 100,
            "error_count": 2,
            "timeout_count": 8,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertTrue(any("timeout" in r.title.lower() for r in recs))

    def test_slow_module(self):
        perf = {
            "scan_duration_s": 60.0,
            "module_timings": {
                "slow_mod": {"duration_s": 35.0, "findings_count": 2},
            },
            "memory_peak_mb": 50.0,
            "request_count": 200,
            "error_count": 0,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertTrue(any("slow_mod" in r.title for r in recs))

    def test_high_memory(self):
        perf = {
            "scan_duration_s": 10.0,
            "module_timings": {},
            "memory_peak_mb": 800.0,
            "request_count": 50,
            "error_count": 0,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertTrue(any("memory" in r.title.lower() for r in recs))

    def test_long_scan_duration(self):
        perf = {
            "scan_duration_s": 400.0,
            "module_timings": {},
            "memory_peak_mb": 100.0,
            "request_count": 500,
            "error_count": 0,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        self.assertTrue(any("duration" in r.title.lower() or "long" in r.title.lower() for r in recs))

    def test_source_is_performance(self):
        perf = {
            "scan_duration_s": 10.0,
            "module_timings": {},
            "memory_peak_mb": 600.0,
            "request_count": 100,
            "error_count": 20,
            "timeout_count": 0,
        }
        recs = self.engine.generate_from_performance(perf)
        for r in recs:
            self.assertEqual(r.source, "performance")


# ═══════════════════════════════════════════════════════════════════════════
# Security (Engineering) Recommendation Generation
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateFromSecurity(unittest.TestCase):
    """Tests for generate_from_security() — engineering recommendations about scan quality."""

    def setUp(self):
        self.store, self.path = _tmp_store()
        self.engine = RecommendationEngine(store=self.store)

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_empty_input(self):
        recs = self.engine.generate_from_security({})
        self.assertEqual(len(recs), 0)

    def test_healthy_scan_no_recommendations(self):
        sec = {
            "total_findings": 50,
            "false_positive_rate": 0.05,
            "scan_coverage_pct": 95.0,
            "modules_run": ["recon", "host", "headers", "tls", "ports", "auth", "dns"],
            "findings_by_severity": {"critical": 2, "high": 5, "medium": 15, "low": 20, "info": 8},
            "cross_validation_rate": 92.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertEqual(len(recs), 0)

    def test_high_fp_rate(self):
        sec = {
            "total_findings": 50,
            "false_positive_rate": 0.4,
            "scan_coverage_pct": 90.0,
            "modules_run": ["recon", "host"],
            "findings_by_severity": {},
            "cross_validation_rate": 80.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertTrue(any("false positive" in r.title.lower() for r in recs))

    def test_low_cross_validation(self):
        sec = {
            "total_findings": 30,
            "false_positive_rate": 0.1,
            "scan_coverage_pct": 80.0,
            "modules_run": ["recon", "host"],
            "findings_by_severity": {},
            "cross_validation_rate": 55.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertTrue(any("cross-validation" in r.title.lower() for r in recs))

    def test_limited_modules(self):
        sec = {
            "total_findings": 5,
            "false_positive_rate": 0.0,
            "scan_coverage_pct": 30.0,
            "modules_run": ["recon"],
            "findings_by_severity": {},
            "cross_validation_rate": 100.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertTrue(any("coverage" in r.title.lower() or "module" in r.title.lower() for r in recs))

    def test_no_critical_with_low_coverage(self):
        sec = {
            "total_findings": 8,
            "false_positive_rate": 0.0,
            "scan_coverage_pct": 40.0,
            "modules_run": ["recon", "host"],
            "findings_by_severity": {"medium": 5, "low": 3},
            "cross_validation_rate": 90.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertTrue(any("coverage" in r.title.lower() for r in recs))

    def test_high_noise_findings(self):
        sec = {
            "total_findings": 50,
            "false_positive_rate": 0.1,
            "scan_coverage_pct": 80.0,
            "modules_run": ["recon", "host", "headers"],
            "findings_by_severity": {"info": 35, "low": 10, "medium": 5},
            "cross_validation_rate": 90.0,
        }
        recs = self.engine.generate_from_security(sec)
        self.assertTrue(any("low-value" in r.title.lower() or "noise" in r.title.lower() for r in recs))

    def test_source_is_security(self):
        sec = {
            "total_findings": 50,
            "false_positive_rate": 0.4,
            "scan_coverage_pct": 80.0,
            "modules_run": ["recon"],
            "findings_by_severity": {},
            "cross_validation_rate": 60.0,
        }
        recs = self.engine.generate_from_security(sec)
        for r in recs:
            self.assertEqual(r.source, "security")


# ═══════════════════════════════════════════════════════════════════════════
# EngineeringRecommender Facade Tests
# ═══════════════════════════════════════════════════════════════════════════


class TestEngineeringRecommender(unittest.TestCase):
    """Tests for the EngineeringRecommender facade."""

    def setUp(self):
        self.recommender = EngineeringRecommender()

    def test_recommend_from_diagnostics(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
                {"label": "disk_space", "status": "error", "error": "low"},
            ],
        }
        recs = self.recommender.recommend_from_diagnostics(diag)
        self.assertGreater(len(recs), 0)

    def test_recommend_from_drift(self):
        report = {
            "target": "example.com",
            "drift_detected": True,
            "drift_event_count": 2,
            "risk_score": 70.0,
            "drift_events": [
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "PORT_CHANGE",
                    "old_value": "",
                    "new_value": "8080",
                    "severity": "high",
                    "risk_impact": "New port 8080 added",
                },
                {
                    "timestamp": "2025-01-02",
                    "field_changed": "DNS_CHANGE",
                    "old_value": "1.1.1.1",
                    "new_value": "2.2.2.2",
                    "severity": "high",
                    "risk_impact": "A record changed",
                },
            ],
        }
        recs = self.recommender.recommend_from_drift(report)
        self.assertGreater(len(recs), 0)

    def test_recommend_from_test_results(self):
        results = {
            "total": 50, "passed": 25, "failed": 20, "errors": 5,
            "skipped": 0, "duration_s": 60.0,
            "failures": [{"test_name": "t", "error_message": "e", "file": "f"}],
        }
        recs = self.recommender.recommend_from_test_results(results)
        self.assertGreater(len(recs), 0)

    def test_recommend_from_performance(self):
        perf = {
            "scan_duration_s": 400.0,
            "module_timings": {"slow": {"duration_s": 50.0, "findings_count": 1}},
            "memory_peak_mb": 800.0,
            "request_count": 200,
            "error_count": 30,
            "timeout_count": 10,
        }
        recs = self.recommender.recommend_from_performance(perf)
        self.assertGreater(len(recs), 0)

    def test_recommend_from_security(self):
        sec = {
            "total_findings": 40,
            "false_positive_rate": 0.45,
            "scan_coverage_pct": 80.0,
            "modules_run": ["recon"],
            "findings_by_severity": {},
            "cross_validation_rate": 55.0,
        }
        recs = self.recommender.recommend_from_security(sec)
        self.assertGreater(len(recs), 0)

    def test_get_all_recommendations(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
                {"label": "disk_space", "status": "error", "error": "low"},
            ],
        }
        self.recommender.recommend_from_diagnostics(diag)
        all_recs = self.recommender.get_all_recommendations()
        self.assertGreater(len(all_recs), 0)
        # Should be sorted by priority descending
        for i in range(len(all_recs) - 1):
            self.assertGreaterEqual(all_recs[i].priority_score, all_recs[i + 1].priority_score)

    def test_dismiss_recommendation(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
                {"label": "disk_space", "status": "error", "error": "low"},
            ],
        }
        self.recommender.recommend_from_diagnostics(diag)
        active = self.recommender.get_all_recommendations()
        self.assertGreater(len(active), 0)
        rec_id = active[0].id
        self.assertTrue(self.recommender.dismiss_recommendation(rec_id, "Test dismiss"))
        # Should no longer be in active
        new_active = self.recommender.get_all_recommendations()
        self.assertFalse(any(r.id == rec_id for r in new_active))

    def test_dismiss_nonexistent(self):
        self.assertFalse(self.recommender.dismiss_recommendation("nonexistent_id"))

    def test_get_recommendation_stats(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
                {"label": "disk_space", "status": "error", "error": "low"},
            ],
        }
        self.recommender.recommend_from_diagnostics(diag)
        stats = self.recommender.get_recommendation_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn("total", stats)
        self.assertIn("active", stats)
        self.assertIn("dismissed", stats)
        self.assertIn("by_severity", stats)
        self.assertIn("by_category", stats)
        self.assertIn("by_source", stats)
        self.assertIn("by_effort", stats)
        self.assertIn("age_distribution", stats)
        self.assertIn("average_confidence", stats)
        self.assertIn("average_priority", stats)
        self.assertGreater(stats["active"], 0)
        self.assertEqual(stats["dismissed"], 0)

    def test_stats_with_dismissed(self):
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "fail"},
                {"label": "disk_space", "status": "error", "error": "low"},
            ],
        }
        self.recommender.recommend_from_diagnostics(diag)
        active = self.recommender.get_all_recommendations()
        if active:
            self.recommender.dismiss_recommendation(active[0].id, "test")
        stats = self.recommender.get_recommendation_stats()
        self.assertGreater(stats["dismissed"], 0)

    def test_stats_empty(self):
        # Use a fresh recommender with no data backed by a temp file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = Path(f.name)
        tmp_path.unlink(missing_ok=True)
        try:
            fresh = EngineeringRecommender(store_path=tmp_path)
            stats = fresh.get_recommendation_stats()
            self.assertEqual(stats["active"], 0)
            self.assertEqual(stats["dismissed"], 0)
            self.assertEqual(stats["total"], 0)
            self.assertEqual(stats["highest_priority"], 0.0)
            self.assertEqual(stats["highest_priority_title"], "")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_dedup_across_calls(self):
        """Calling recommend_from_diagnostics twice with similar data doesn't double-store."""
        diag = {
            "timestamp": "2025-01-01",
            "total_checks": 10,
            "passed": 8,
            "failed": 2,
            "checks": [
                {"label": "network_dns", "status": "error", "error": "dns resolution failed"},
                {"label": "disk_space", "status": "error", "error": "low disk"},
            ],
        }
        self.recommender.recommend_from_diagnostics(diag)
        count_before = self.recommender.get_all_recommendations().__len__()
        self.recommender.recommend_from_diagnostics(diag)
        count_after = self.recommender.get_all_recommendations().__len__()
        self.assertEqual(count_before, count_after)


# ═══════════════════════════════════════════════════════════════════════════
# Module-Level Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for get_recommender() and reset_recommender()."""

    def test_get_recommender_returns_instance(self):
        rec = get_recommender()
        self.assertIsInstance(rec, EngineeringRecommender)

    def test_get_recommender_is_singleton(self):
        r1 = get_recommender()
        r2 = get_recommender()
        self.assertIs(r1, r2)

    def test_reset_creates_new_instance(self):
        r1 = get_recommender()
        reset_recommender()
        r2 = get_recommender()
        self.assertIsNot(r1, r2)


# ═══════════════════════════════════════════════════════════════════════════
# Constants Validation
# ═══════════════════════════════════════════════════════════════════════════


class TestConstants(unittest.TestCase):
    """Validate module-level constants."""

    def test_dedup_threshold_in_range(self):
        self.assertGreater(_DEDUP_THRESHOLD, 0.0)
        self.assertLessEqual(_DEDUP_THRESHOLD, 1.0)

    def test_severity_scores_all_positive(self):
        for sev, score in _SEVERITY_SCORE.items():
            self.assertGreater(score, 0.0, f"Severity {sev} score not positive")

    def test_effort_scores_all_positive(self):
        for eff, score in _EFFORT_SCORE.items():
            self.assertGreater(score, 0.0, f"Effort {eff} score not positive")

    def test_stale_days_positive(self):
        self.assertGreater(_STALE_DAYS, 0)
        self.assertGreater(_VERY_STALE_DAYS, _STALE_DAYS)


if __name__ == "__main__":
    unittest.main()
