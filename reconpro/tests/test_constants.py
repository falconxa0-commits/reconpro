"""Tests for reconpro.constants — central constants module."""

import sys
import os
import unittest

# Ensure the reconpro package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.constants import (
    SEVERITY_LEVELS,
    VALID_SEVERITIES,
    GRADE_THRESHOLDS,
    DEFAULT_TIMEOUT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_BODY_LIMIT,
    USER_AGENT,
    SEV_COLORS,
    GRADE_COLORS,
    SARIF_LEVEL_MAP,
    BADGE_COLOR_MAP,
    DREAD_SCORE_MAP,
    MAX_SCORE,
    MIN_SCORE,
    VALID_GRADES,
    severity_sort_key,
)


class TestSeverityLevels(unittest.TestCase):
    """Test the SEVERITY_LEVELS constant."""

    def test_has_exactly_five_levels(self):
        self.assertEqual(len(SEVERITY_LEVELS), 5)

    def test_critical_is_zero(self):
        self.assertEqual(SEVERITY_LEVELS["critical"], 0)

    def test_high_is_one(self):
        self.assertEqual(SEVERITY_LEVELS["high"], 1)

    def test_medium_is_two(self):
        self.assertEqual(SEVERITY_LEVELS["medium"], 2)

    def test_low_is_three(self):
        self.assertEqual(SEVERITY_LEVELS["low"], 3)

    def test_info_is_four(self):
        self.assertEqual(SEVERITY_LEVELS["info"], 4)

    def test_ordering_is_correct(self):
        values = list(SEVERITY_LEVELS.values())
        self.assertEqual(values, [0, 1, 2, 3, 4])


class TestValidSeverities(unittest.TestCase):
    """Test the VALID_SEVERITIES frozenset."""

    def test_is_frozenset(self):
        self.assertIsInstance(VALID_SEVERITIES, frozenset)

    def test_has_exactly_five_items(self):
        self.assertEqual(len(VALID_SEVERITIES), 5)

    def test_contains_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertIn(sev, VALID_SEVERITIES)

    def test_matches_severity_levels_keys(self):
        self.assertEqual(set(VALID_SEVERITIES), set(SEVERITY_LEVELS.keys()))


class TestGradeThresholds(unittest.TestCase):
    """Test the GRADE_THRESHOLDS constant."""

    def test_has_six_entries(self):
        self.assertEqual(len(GRADE_THRESHOLDS), 6)

    def test_thresholds_in_descending_order(self):
        thresholds = [t for t, _ in GRADE_THRESHOLDS]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))

    def test_first_threshold_is_a_plus(self):
        self.assertEqual(GRADE_THRESHOLDS[0], (90, "A+"))

    def test_last_threshold_is_f(self):
        self.assertEqual(GRADE_THRESHOLDS[-1], (0, "F"))

    def test_all_grades_unique(self):
        grades = [g for _, g in GRADE_THRESHOLDS]
        self.assertEqual(len(grades), len(set(grades)))


class TestNetworkDefaults(unittest.TestCase):
    """Test network-related constants."""

    def test_default_timeout_is_eight(self):
        self.assertEqual(DEFAULT_TIMEOUT, 8)

    def test_default_rate_limit_is_ten(self):
        self.assertEqual(DEFAULT_RATE_LIMIT, 10.0)

    def test_default_body_limit_is_16384(self):
        self.assertEqual(DEFAULT_BODY_LIMIT, 16384)


class TestUserAgent(unittest.TestCase):
    """Test the USER_AGENT constant."""

    def test_contains_version_11_0_0(self):
        from reconpro import __version__ as _v
        self.assertIn(_v, USER_AGENT)

    def test_contains_reconpro(self):
        self.assertIn("ReconPro", USER_AGENT)

    def test_contains_enterprise(self):
        self.assertIn("Enterprise", USER_AGENT)


class TestSeverityColorMappings(unittest.TestCase):
    """Test SEV_COLORS covers all severities."""

    def test_all_severities_have_colors(self):
        for sev in VALID_SEVERITIES:
            self.assertIn(sev, SEV_COLORS, f"Missing color for {sev}")

    def test_color_count_matches_severity_count(self):
        self.assertEqual(len(SEV_COLORS), len(VALID_SEVERITIES))

    def test_critical_color(self):
        self.assertEqual(SEV_COLORS["critical"], "bright_red")

    def test_info_color(self):
        self.assertEqual(SEV_COLORS["info"], "dim")


class TestGradeColorMappings(unittest.TestCase):
    """Test GRADE_COLORS covers all grades."""

    def test_all_grades_have_colors(self):
        for grade in VALID_GRADES:
            self.assertIn(grade, GRADE_COLORS, f"Missing color for {grade}")

    def test_grade_color_count(self):
        self.assertEqual(len(GRADE_COLORS), 6)


class TestBadgeColorMap(unittest.TestCase):
    """Test BADGE_COLOR_MAP covers all 6 grades."""

    def test_has_six_entries(self):
        self.assertEqual(len(BADGE_COLOR_MAP), 6)

    def test_covers_all_grades(self):
        for grade in VALID_GRADES:
            self.assertIn(grade, BADGE_COLOR_MAP, f"Missing badge color for {grade}")

    def test_a_plus_color(self):
        self.assertEqual(BADGE_COLOR_MAP["A+"], "brightgreen")

    def test_f_color(self):
        self.assertEqual(BADGE_COLOR_MAP["F"], "red")


class TestSarifLevelMap(unittest.TestCase):
    """Test SARIF_LEVEL_MAP."""

    def test_critical_maps_to_error(self):
        self.assertEqual(SARIF_LEVEL_MAP["critical"], "error")

    def test_medium_maps_to_warning(self):
        self.assertEqual(SARIF_LEVEL_MAP["medium"], "warning")

    def test_info_maps_to_note(self):
        self.assertEqual(SARIF_LEVEL_MAP["info"], "note")


class TestDreadScoreMap(unittest.TestCase):
    """Test DREAD_SCORE_MAP."""

    def test_all_severities_have_dread_scores(self):
        for sev in VALID_SEVERITIES:
            self.assertIn(sev, DREAD_SCORE_MAP)

    def test_critical_highest(self):
        self.assertEqual(DREAD_SCORE_MAP["critical"], 0.9)

    def test_info_lowest(self):
        self.assertEqual(DREAD_SCORE_MAP["info"], 0.1)


class TestScoreConstants(unittest.TestCase):
    """Test scoring constants."""

    def test_max_score_is_100(self):
        self.assertEqual(MAX_SCORE, 100)

    def test_min_score_is_0(self):
        self.assertEqual(MIN_SCORE, 0)


class TestSeveritySortKey(unittest.TestCase):
    """Test severity_sort_key function."""

    def test_critical_is_lowest_key(self):
        self.assertEqual(severity_sort_key("critical"), 0)

    def test_info_is_highest_key(self):
        self.assertEqual(severity_sort_key("info"), 4)

    def test_unknown_is_99(self):
        self.assertEqual(severity_sort_key("unknown"), 99)

    def test_case_insensitive(self):
        self.assertEqual(severity_sort_key("CRITICAL"), 0)
        self.assertEqual(severity_sort_key("High"), 1)


if __name__ == "__main__":
    unittest.main()
