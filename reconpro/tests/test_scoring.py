"""Tests for the scoring pipeline (pure logic, no mocking)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.utils import compute_score, compute_grade, count_severities
from reconpro.http_layer import Finding


class TestScoreCalculation(unittest.TestCase):
    """Test pure score calculation from findings."""

    def test_no_findings_score_100(self):
        self.assertEqual(compute_score([]), 100)

    def test_single_info_finding_no_deduction(self):
        f = Finding("t", "info", "c", "m", "d", "e", "a", points_deducted=0)
        self.assertEqual(compute_score([f]), 100)

    def test_single_critical_25_points(self):
        f = Finding("t", "critical", "c", "m", "d", "e", "a", points_deducted=25)
        self.assertEqual(compute_score([f]), 75)

    def test_accumulated_deductions(self):
        findings = [
            Finding("t1", "critical", "c", "m", "d", "e", "a", points_deducted=25),
            Finding("t2", "high", "c", "m", "d", "e", "a", points_deducted=15),
            Finding("t3", "medium", "c", "m", "d", "e", "a", points_deducted=5),
        ]
        self.assertEqual(compute_score(findings), 55)

    def test_dict_findings_deduction(self):
        findings = [
            {"points_deducted": 50},
            {"points_deducted": 20},
        ]
        self.assertEqual(compute_score(findings), 30)


class TestScoreClamping(unittest.TestCase):
    """Test that score never goes below 0 or above 100."""

    def test_clamps_at_zero(self):
        findings = [Finding("t", "c", "c", "m", "d", "e", "a", points_deducted=500)]
        self.assertEqual(compute_score(findings), 0)

    def test_clamps_at_hundred(self):
        self.assertEqual(compute_score([]), 100)

    def test_negative_deductions_clamp(self):
        findings = [{"points_deducted": -10}]
        # -10 deduction from 100 = 110, clamped to 100
        self.assertEqual(compute_score(findings), 100)

    def test_exactly_zero(self):
        findings = [Finding("t", "c", "c", "m", "d", "e", "a", points_deducted=100)]
        self.assertEqual(compute_score(findings), 0)

    def test_one_point_above_zero(self):
        findings = [Finding("t", "c", "c", "m", "d", "e", "a", points_deducted=99)]
        self.assertEqual(compute_score(findings), 1)


class TestEmptyFindingsScore(unittest.TestCase):
    """Test that empty findings list yields score 100."""

    def test_empty_list(self):
        self.assertEqual(compute_score([]), 100)


class TestSeverityCountsMatch(unittest.TestCase):
    """Test severity count accuracy."""

    def test_single_critical(self):
        findings = [Finding("t", "critical", "c", "m", "d", "e", "a")]
        counts = count_severities(findings)
        self.assertEqual(counts.get("critical"), 1)

    def test_mixed_findings(self):
        findings = [
            Finding("t1", "critical", "c", "m", "d", "e", "a"),
            Finding("t2", "critical", "c", "m", "d", "e", "a"),
            Finding("t3", "high", "c", "m", "d", "e", "a"),
            Finding("t4", "high", "c", "m", "d", "e", "a"),
            Finding("t5", "high", "c", "m", "d", "e", "a"),
            Finding("t6", "medium", "c", "m", "d", "e", "a"),
            Finding("t7", "info", "c", "m", "d", "e", "a"),
        ]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 3)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["info"], 1)
        self.assertNotIn("low", counts)

    def test_empty_findings_empty_counts(self):
        self.assertEqual(count_severities([]), {})


class TestScoreGradeIntegration(unittest.TestCase):
    """Test score-to-grade mapping works correctly."""

    def test_score_100_is_a_plus(self):
        self.assertEqual(compute_grade(100), "A+")

    def test_score_90_is_a_plus(self):
        self.assertEqual(compute_grade(90), "A+")

    def test_score_89_is_a(self):
        self.assertEqual(compute_grade(89), "A")

    def test_score_50_is_c(self):
        self.assertEqual(compute_grade(50), "C")

    def test_score_34_is_f(self):
        self.assertEqual(compute_grade(34), "F")

    def test_score_0_is_f(self):
        self.assertEqual(compute_grade(0), "F")


if __name__ == "__main__":
    unittest.main()
