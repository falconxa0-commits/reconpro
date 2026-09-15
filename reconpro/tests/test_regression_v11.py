"""Regression tests for ReconPro v11.

Ensures that scoring, severity ordering, grade thresholds, export
file validity, and module registry counts remain correct across
v11 releases. These are NOT duplicated from test_scoring.py or
test_constants.py — they focus on integration-level invariants.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.constants import (
    SEVERITY_LEVELS,
    VALID_SEVERITIES,
    GRADE_THRESHOLDS,
    VALID_GRADES,
    MAX_SCORE,
    MIN_SCORE,
    severity_sort_key,
    __version__,
)
from reconpro.http_layer import Finding
from reconpro.utils import compute_score, compute_grade, count_severities
from reconpro.formats import (
    export_json,
    export_sarif,
    export_markdown,
    export_pdf,
    export,
)
from reconpro.registry import (
    MODULE_REGISTRY,
    LOCAL_MODULES,
    ALL_MODULES,
    DEFAULT_MODULES,
)
from reconpro.intelligence_pipeline import (
    IntelligencePipeline,
    reset_pipeline,
)


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_finding(severity="medium", points=10, **kw):
    defaults = dict(
        title="Test", severity=severity, category="c", module="m",
        description="d", evidence="e", asset="a", points_deducted=points,
    )
    defaults.update(kw)
    return Finding(**defaults)


def _sample_data():
    return {
        "target": "regression.target.com",
        "total_score": 75,
        "grade": "B",
        "findings": [
            {"title": "T1", "severity": "critical", "category": "c", "module": "m",
             "description": "d", "evidence": "e", "asset": "a", "points_deducted": 25},
            {"title": "T2", "severity": "info", "category": "c", "module": "m",
             "description": "d", "evidence": "e", "asset": "a", "points_deducted": 0},
        ],
        "modules_run": ["m"],
        "severity_counts": {"critical": 1, "info": 1},
    }


# ═══════════════════════════════════════════════════════════════════════
# 1. Score Computation Bounds
# ═══════════════════════════════════════════════════════════════════════


class TestScoreBoundsIntegration(unittest.TestCase):
    """Integration-level score bounds: ensure 0 ≤ score ≤ 100 across
    different combinations of findings and point deductions."""

    def test_massive_critical_findings_clamp_to_zero(self):
        """Many high-deduction findings must not produce negative scores."""
        findings = [_make_finding(severity="critical", points=50) for _ in range(20)]
        score = compute_score(findings)
        self.assertGreaterEqual(score, MIN_SCORE)
        self.assertLessEqual(score, MAX_SCORE)

    def test_zero_point_findings_yields_max_score(self):
        """All-zero-deduction findings should yield score 100."""
        findings = [_make_finding(severity="info", points=0) for _ in range(100)]
        score = compute_score(findings)
        self.assertEqual(score, MAX_SCORE)

    def test_negative_points_deduction_ignored(self):
        """Negative points_deducted should not inflate score above 100."""
        findings = [_make_finding(points=-100)]
        score = compute_score(findings)
        self.assertLessEqual(score, MAX_SCORE)

    def test_mixed_severities_score_stays_in_range(self):
        """A realistic mix of all severities stays in [0, 100]."""
        findings = [
            _make_finding(severity="critical", points=25),
            _make_finding(severity="high", points=15),
            _make_finding(severity="medium", points=10),
            _make_finding(severity="low", points=3),
            _make_finding(severity="info", points=0),
        ]
        score = compute_score(findings)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_intelligence_pipeline_scores_bounded(self):
        """Intelligence pipeline composite scores must stay in [0, 100]."""
        reset_pipeline()
        findings = [
            _make_finding(severity="critical", category="injection", asset=f"a{i}.com")
            for i in range(20)
        ]
        p = IntelligencePipeline()
        result = p.analyze(findings)
        self.assertGreaterEqual(result.executive_risk_score, 0)
        self.assertLessEqual(result.executive_risk_score, 100)
        self.assertGreaterEqual(result.exposure_score, 0)
        self.assertLessEqual(result.exposure_score, 100)
        self.assertGreaterEqual(result.mission_impact_score, 0)
        self.assertLessEqual(result.mission_impact_score, 100)
        self.assertGreaterEqual(result.infrastructure_health_score, 0)
        self.assertLessEqual(result.infrastructure_health_score, 100)
        reset_pipeline()

    def test_infrastructure_health_is_inverse_of_risk(self):
        """infrastructure_health_score should equal 100 - executive_risk_score."""
        reset_pipeline()
        findings = [
            _make_finding(severity="critical", category="injection", asset="target.com"),
            _make_finding(severity="high", category="auth", asset="target.com"),
        ]
        p = IntelligencePipeline()
        result = p.analyze(findings)
        if result.executive_risk_score > 0:
            expected_health = 100.0 - result.executive_risk_score
            self.assertAlmostEqual(
                result.infrastructure_health_score, expected_health, places=1,
            )
        reset_pipeline()


# ═══════════════════════════════════════════════════════════════════════
# 2. Severity Ordering
# ═══════════════════════════════════════════════════════════════════════


class TestSeverityOrderingConsistency(unittest.TestCase):
    """Verify that the canonical severity order is correct and consistent."""

    def test_severity_levels_numeric_order(self):
        """critical=0 < high=1 < medium=2 < low=3 < info=4."""
        self.assertLess(SEVERITY_LEVELS["critical"], SEVERITY_LEVELS["high"])
        self.assertLess(SEVERITY_LEVELS["high"], SEVERITY_LEVELS["medium"])
        self.assertLess(SEVERITY_LEVELS["medium"], SEVERITY_LEVELS["low"])
        self.assertLess(SEVERITY_LEVELS["low"], SEVERITY_LEVELS["info"])

    def test_severity_sort_key_function(self):
        """severity_sort_key returns correct numeric ordering."""
        self.assertEqual(severity_sort_key("critical"), 0)
        self.assertEqual(severity_sort_key("high"), 1)
        self.assertEqual(severity_sort_key("medium"), 2)
        self.assertEqual(severity_sort_key("low"), 3)
        self.assertEqual(severity_sort_key("info"), 4)

    def test_severity_sort_key_unknown_high(self):
        """Unknown severities get a high sort key (low priority)."""
        self.assertGreater(severity_sort_key("unknown"), 10)
        self.assertGreater(severity_sort_key(""), 10)

    def test_sorting_findings_by_severity(self):
        """Findings sorted by severity should be in correct order."""
        findings = [
            _make_finding(severity="info"),
            _make_finding(severity="critical"),
            _make_finding(severity="medium"),
            _make_finding(severity="high"),
            _make_finding(severity="low"),
        ]
        sorted_findings = sorted(findings, key=lambda f: severity_sort_key(f.severity))
        severities = [f.severity for f in sorted_findings]
        self.assertEqual(severities, ["critical", "high", "medium", "low", "info"])

    def test_formats_sev_order_matches_constants(self):
        """The _SEV_ORDER in formats.py should match SEVERITY_LEVELS."""
        from reconpro.formats import _SEV_ORDER
        for sev in ["critical", "high", "medium", "low", "info"]:
            self.assertIn(sev, _SEV_ORDER)
        # critical should have lowest value (highest priority)
        self.assertLess(_SEV_ORDER["critical"], _SEV_ORDER["info"])

    def test_valid_severities_frozen_set(self):
        """VALID_SEVERITIES should be a frozenset of exactly 5 items."""
        self.assertIsInstance(VALID_SEVERITIES, frozenset)
        self.assertEqual(len(VALID_SEVERITIES), 5)
        self.assertEqual(VALID_SEVERITIES, frozenset(["critical", "high", "medium", "low", "info"]))


# ═══════════════════════════════════════════════════════════════════════
# 3. Grade Thresholds
# ═══════════════════════════════════════════════════════════════════════


class TestGradeThresholds(unittest.TestCase):
    """Verify grade thresholds match the documented specification."""

    def test_thresholds_order_descending(self):
        """GRADE_THRESHOLDS must be ordered from highest to lowest."""
        for i in range(len(GRADE_THRESHOLDS) - 1):
            self.assertGreater(
                GRADE_THRESHOLDS[i][0],
                GRADE_THRESHOLDS[i + 1][0],
                f"Thresholds not descending at index {i}",
            )

    def test_grade_a_plus_requires_90_plus(self):
        """A+ requires score >= 90."""
        self.assertEqual(GRADE_THRESHOLDS[0], (90, "A+"))

    def test_grade_a_requires_80_plus(self):
        """A requires score >= 80."""
        self.assertEqual(GRADE_THRESHOLDS[1], (80, "A"))

    def test_grade_b_requires_65_plus(self):
        """B requires score >= 65."""
        self.assertEqual(GRADE_THRESHOLDS[2], (65, "B"))

    def test_grade_c_requires_50_plus(self):
        """C requires score >= 50."""
        self.assertEqual(GRADE_THRESHOLDS[3], (50, "C"))

    def test_grade_d_requires_35_plus(self):
        """D requires score >= 35."""
        self.assertEqual(GRADE_THRESHOLDS[4], (35, "D"))

    def test_grade_f_is_floor(self):
        """F is the floor (score >= 0)."""
        self.assertEqual(GRADE_THRESHOLDS[5], (0, "F"))

    def test_valid_grades_match_thresholds(self):
        """VALID_GRADES should contain exactly the grades from thresholds."""
        expected = frozenset(g for _, g in GRADE_THRESHOLDS)
        self.assertEqual(VALID_GRADES, expected)

    def test_boundary_scores_via_compute_grade(self):
        """compute_grade at exact boundaries returns correct grade."""
        self.assertEqual(compute_grade(90), "A+")
        self.assertEqual(compute_grade(89), "A")
        self.assertEqual(compute_grade(80), "A")
        self.assertEqual(compute_grade(79), "B")
        self.assertEqual(compute_grade(65), "B")
        self.assertEqual(compute_grade(64), "C")
        self.assertEqual(compute_grade(50), "C")
        self.assertEqual(compute_grade(49), "D")
        self.assertEqual(compute_grade(35), "D")
        self.assertEqual(compute_grade(34), "F")
        self.assertEqual(compute_grade(0), "F")
        self.assertEqual(compute_grade(100), "A+")


# ═══════════════════════════════════════════════════════════════════════
# 4. Format Export Validity
# ═══════════════════════════════════════════════════════════════════════


class TestFormatExportValidity(unittest.TestCase):
    """All export formats must produce files that exist, are non-empty,
    and parse correctly."""

    def setUp(self):
        self.data = _sample_data()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _assert_file_valid(self, path, min_size=50):
        """Assert file exists and has content."""
        self.assertTrue(os.path.exists(path), f"File not created: {path}")
        size = os.path.getsize(path)
        self.assertGreater(size, min_size, f"File too small ({size} bytes): {path}")

    def test_json_export_file_valid(self):
        path = os.path.join(self.tmpdir, "r.json")
        result = export_json(self.data, path)
        self._assert_file_valid(result)
        with open(result) as f:
            d = json.load(f)
        self.assertIn("findings", d)

    def test_sarif_export_file_valid(self):
        path = os.path.join(self.tmpdir, "r.sarif")
        result = export_sarif(self.data, path)
        self._assert_file_valid(result)
        with open(result) as f:
            d = json.load(f)
        self.assertEqual(d["version"], "2.1.0")

    def test_markdown_export_file_valid(self):
        path = os.path.join(self.tmpdir, "r.md")
        result = export_markdown(self.data, path)
        self._assert_file_valid(result)
        with open(result, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ReconPro", content)

    def test_pdf_export_file_valid(self):
        path = os.path.join(self.tmpdir, "r.pdf")
        result = export_pdf(self.data, path)
        self._assert_file_valid(result)
        with open(result, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("<!DOCTYPE html>", content)

    def test_export_auto_all_formats(self):
        """export() auto-detects and produces valid files for all formats."""
        for ext in [".json", ".sarif", ".md", ".pdf"]:
            path = os.path.join(self.tmpdir, f"auto{ext}")
            result = export(self.data, path)
            self._assert_file_valid(result)

    def test_empty_findings_all_formats(self):
        """Export with zero findings should still produce valid files."""
        empty_data = {
            "target": "clean.target.com",
            "total_score": 100,
            "grade": "A+",
            "findings": [],
            "modules_run": [],
            "severity_counts": {},
        }
        for ext in [".json", ".sarif", ".md", ".pdf"]:
            path = os.path.join(self.tmpdir, f"empty{ext}")
            result = export(empty_data, path)
            self._assert_file_valid(result)

    def test_json_roundtrip_preserves_data(self):
        """JSON export → load → compare preserves core fields."""
        path = os.path.join(self.tmpdir, "rt.json")
        export_json(self.data, path)
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["target"], self.data["target"])
        self.assertEqual(loaded["total_score"], self.data["total_score"])
        self.assertEqual(loaded["grade"], self.data["grade"])
        self.assertEqual(len(loaded["findings"]), len(self.data["findings"]))


# ═══════════════════════════════════════════════════════════════════════
# 5. Module Registry Counts
# ═══════════════════════════════════════════════════════════════════════


class TestModuleRegistryCounts(unittest.TestCase):
    """Regression guard: ensure module counts don't silently change."""

    def test_remote_module_count(self):
        """MODULE_REGISTRY should have 25 remote modules."""
        self.assertEqual(len(MODULE_REGISTRY), 25,
                         f"Expected 25, got {len(MODULE_REGISTRY)}")

    def test_local_module_count(self):
        """LOCAL_MODULES should have 3 local modules."""
        self.assertEqual(len(LOCAL_MODULES), 3)

    def test_all_modules_count(self):
        """ALL_MODULES = remote + local = 28."""
        self.assertEqual(len(ALL_MODULES), 28)

    def test_default_modules_count(self):
        """DEFAULT_MODULES should have 20 entries."""
        self.assertEqual(len(DEFAULT_MODULES), 20)

    def test_no_duplicate_modules(self):
        """ALL_MODULES should have no duplicates."""
        self.assertEqual(len(ALL_MODULES), len(set(ALL_MODULES)))

    def test_all_remote_modules_have_runners(self):
        """Every remote module must have a callable runner."""
        for mod_id, entry in MODULE_REGISTRY.items():
            runner = entry.get("runner")
            self.assertIsNotNone(runner, f"{mod_id} has no runner")
            self.assertTrue(callable(runner), f"{mod_id} runner not callable")

    def test_all_default_modules_exist_in_registry(self):
        """Every DEFAULT_MODULES entry must exist in MODULE_REGISTRY."""
        for mod_id in DEFAULT_MODULES:
            self.assertIn(mod_id, MODULE_REGISTRY,
                          f"{mod_id} in DEFAULT_MODULES but not in MODULE_REGISTRY")

    def test_version_is_v11(self):
        """Version must start with 11. for v11 release."""
        self.assertTrue(__version__.startswith("11."),
                        f"Version should start with '11.', got {__version__}")


if __name__ == "__main__":
    unittest.main()
