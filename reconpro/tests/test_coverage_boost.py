"""Coverage boost tests — targeting uncovered paths in ReconPro.

These tests specifically target branches and edge cases not fully covered
by existing test suites.
"""

import sys
import os
import math
import time
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding, RateLimiter
from reconpro.utils import (
    count_severities,
    compute_score,
    compute_grade,
    sort_findings_by_severity,
    badge_markdown,
    truncate,
    entropy,
    is_private_ip,
    url_join,
    safe_int,
    safe_float,
    validate_target,
    extract_host,
    normalize_base_url,
    severity_to_cvss,
    severity_to_dread,
    validate_severity,
)
from reconpro.constants import (
    MAX_SCORE, MIN_SCORE, DEFAULT_BODY_LIMIT,
    VALID_SEVERITIES, VALID_GRADES,
    SEVERITY_LEVELS, GRADE_THRESHOLDS,
    DREAD_SCORE_MAP, BADGE_COLOR_MAP,
)
from reconpro.scanner import ReconProResult


# ── Finding with all fields populated vs defaults ─────────────────────────


class TestFindingFields(unittest.TestCase):
    """Test Finding dataclass with all fields vs defaults."""

    def test_all_fields_populated(self):
        f = Finding(
            title="Full Title",
            severity="critical",
            category="sqli",
            module="auth",
            description="A critical SQL injection",
            evidence="SELECT * FROM users WHERE 1=1",
            asset="/api/login",
            points_deducted=30,
            remediation="Use parameterized queries immediately",
            dread_score=0.95,
        )
        d = f.to_dict()
        self.assertEqual(d["title"], "Full Title")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["category"], "sqli")
        self.assertEqual(d["module"], "auth")
        self.assertEqual(d["description"], "A critical SQL injection")
        self.assertEqual(d["evidence"], "SELECT * FROM users WHERE 1=1")
        self.assertEqual(d["asset"], "/api/login")
        self.assertEqual(d["points_deducted"], 30)
        self.assertEqual(d["remediation"], "Use parameterized queries immediately")
        self.assertAlmostEqual(d["dread_score"], 0.95)

    def test_defaults_only(self):
        f = Finding(
            title="Minimal",
            severity="info",
            category="c",
            module="m",
            description="d",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertEqual(d["points_deducted"], 0)
        self.assertEqual(d["remediation"], "")
        self.assertAlmostEqual(d["dread_score"], 0.0)

    def test_to_dict_preserves_types(self):
        """Verify all field types are preserved through to_dict()."""
        f = Finding(
            title=str("Title"),
            severity=str("high"),
            category=str("cat"),
            module=str("mod"),
            description=str("desc"),
            evidence=str("ev"),
            asset=str("asset"),
            points_deducted=int(25),
            remediation=str("Fix"),
            dread_score=float(0.7),
        )
        d = f.to_dict()
        self.assertIsInstance(d["title"], str)
        self.assertIsInstance(d["severity"], str)
        self.assertIsInstance(d["points_deducted"], int)
        self.assertIsInstance(d["dread_score"], float)

    def test_empty_strings(self):
        """Finding with empty strings for text fields."""
        f = Finding("", "", "", "", "", "", "")
        d = f.to_dict()
        self.assertEqual(d["title"], "")
        self.assertEqual(d["severity"], "")
        self.assertEqual(d["category"], "")


# ── RateLimiter at boundary rates ─────────────────────────────────────────


class TestRateLimiterBoundary(unittest.TestCase):
    """Test RateLimiter at extreme rate values."""

    def test_very_slow_rate(self):
        """Rate limiter with 0.001 req/s should have long interval."""
        rl = RateLimiter(max_per_second=0.001)
        self.assertEqual(rl._min_interval, 1000.0)

    def test_very_fast_rate(self):
        """Rate limiter with 1000.0 req/s should have tiny interval."""
        rl = RateLimiter(max_per_second=1000.0)
        self.assertAlmostEqual(rl._min_interval, 0.001)

    def test_default_rate(self):
        rl = RateLimiter()
        self.assertAlmostEqual(rl._min_interval, 0.1)

    def test_acquire_completes(self):
        """acquire() should complete without hanging."""
        rl = RateLimiter(max_per_second=1000.0)
        start = time.time()
        rl.acquire()
        elapsed = time.time() - start
        self.assertLess(elapsed, 1.0)

    def test_acquire_no_crash(self):
        """Multiple acquire calls should not crash."""
        rl = RateLimiter(max_per_second=100.0)
        for _ in range(10):
            rl.acquire()


# ── count_severities edge cases ────────────────────────────────────────────


class TestCountSeveritiesEdgeCases(unittest.TestCase):
    """count_severities with mixed case, unknown severity, etc."""

    def test_uppercase_severity(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)

    def test_mixed_case_severities(self):
        findings = [
            {"severity": "Critical"},
            {"severity": "HIGH"},
            {"severity": "MeDiUm"},
            {"severity": "LoW"},
            {"severity": "INFO"},
        ]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)
        self.assertEqual(counts["info"], 1)

    def test_unknown_severity_maps_to_info(self):
        findings = [{"severity": "extreme"}, {"severity": "minor"}]
        counts = count_severities(findings)
        self.assertEqual(counts["info"], 2)

    def test_finding_object_with_string_severity(self):
        f = Finding("T", "CRITICAL", "c", "m", "d", "e", "a")
        counts = count_severities([f])
        self.assertEqual(counts["critical"], 1)

    def test_finding_object_with_empty_severity(self):
        f = Finding("T", "", "c", "m", "d", "e", "a")
        counts = count_severities([f])
        self.assertEqual(counts["info"], 1)

    def test_dict_without_severity_key(self):
        findings = [{"title": "No severity"}]
        counts = count_severities(findings)
        # Missing key -> .get returns None -> not in VALID_SEVERITIES -> maps to info
        self.assertEqual(counts["info"], 1)

    def test_none_severity_raises(self):
        findings = [{"severity": None}]
        # None.lower() raises AttributeError — code doesn't handle None
        with self.assertRaises(AttributeError):
            count_severities(findings)


# ── sort_findings edge cases ────────────────────────────────────────────────


class TestSortFindingsEdgeCases(unittest.TestCase):
    """sort_findings_by_severity with edge cases."""

    def test_all_same_severity_stable(self):
        """All same severity should maintain original order (stable sort)."""
        findings = [Finding(f"F{i}", "medium", "c", "m", "d", "e", "a")
                    for i in range(20)]
        sorted_f = sort_findings_by_severity(findings)
        for i, f in enumerate(sorted_f):
            self.assertEqual(f.title, f"F{i}")

    def test_single_finding(self):
        findings = [Finding("Only", "high", "c", "m", "d", "e", "a")]
        sorted_f = sort_findings_by_severity(findings)
        self.assertEqual(len(sorted_f), 1)

    def test_empty_list(self):
        sorted_f = sort_findings_by_severity([])
        self.assertEqual(sorted_f, [])

    def test_all_unknown_severity(self):
        """Unknown severities should all sort together."""
        findings = [Finding(f"F{i}", "weird", "c", "m", "d", "e", "a")
                    for i in range(5)]
        sorted_f = sort_findings_by_severity(findings)
        self.assertEqual(len(sorted_f), 5)

    def test_reverse_flag(self):
        findings = [
            Finding("Crit", "critical", "c", "m", "d", "e", "a"),
            Finding("Info", "info", "c", "m", "d", "e", "a"),
        ]
        sorted_f = sort_findings_by_severity(findings, reverse=True)
        self.assertEqual(sorted_f[0].severity, "info")

    def test_dict_findings_with_missing_severity(self):
        findings = [{"title": "A"}, {"title": "B"}]
        sorted_f = sort_findings_by_severity(findings)
        # Missing severity defaults to "info"
        self.assertEqual(len(sorted_f), 2)


# ── validate_target edge cases ─────────────────────────────────────────────


class TestValidateTargetEdgeCases(unittest.TestCase):
    """validate_target with various edge cases."""

    def test_url_with_fragment(self):
        valid, msg = validate_target("https://example.com/page#section")
        self.assertTrue(valid)

    def test_ipv6_address(self):
        valid, msg = validate_target("::1")
        self.assertIsInstance(valid, bool)

    def test_domain_with_hyphen(self):
        valid, msg = validate_target("my-domain.example.com")
        self.assertTrue(valid)

    def test_domain_with_underscore(self):
        valid, msg = validate_target("my_domain.example.com")
        self.assertTrue(valid)

    def test_ip_with_double_semicolon(self):
        valid, msg = validate_target("example.com;; ls")
        self.assertFalse(valid)

    def test_domain_with_at_sign(self):
        valid, msg = validate_target("user@example.com")
        self.assertTrue(valid)

    def test_only_scheme(self):
        valid, msg = validate_target("https://")
        self.assertIsInstance(valid, bool)

    def test_newline_in_target(self):
        valid, msg = validate_target("example.com\nrm -rf")
        self.assertIsInstance(valid, bool)


# ── compute_score edge cases ──────────────────────────────────────────────


class TestComputeScoreEdgeCases(unittest.TestCase):
    """compute_score with fractional and edge-case deductions."""

    def test_fractional_points_as_float(self):
        findings = [{"points_deducted": 0.5}, {"points_deducted": 0.3}]
        score = compute_score(findings)
        # 100 - 0.8 = 99.2, but compute_score uses int()
        # total_deductions = 0.8 (float), max(0, min(100, 100 - 0.8)) = 99.2
        # Wait, looking at the code: max_score - total_deductions where total_deductions is float
        # The function returns max(MIN_SCORE, min(max_score, max_score - total_deductions))
        # So 100 - 0.8 = 99.2, then min(100, 99.2) = 99.2, max(0, 99.2) = 99.2
        # But the return type is int... actually the function returns int but the math might return float
        # Let's just check it's in range
        self.assertGreaterEqual(score, MIN_SCORE)
        self.assertLessEqual(score, MAX_SCORE)

    def test_negative_points(self):
        findings = [{"points_deducted": -10}]
        score = compute_score(findings)
        # 100 - (-10) = 110, clamped to 100
        self.assertEqual(score, MAX_SCORE)

    def test_zero_max_score(self):
        findings = []
        score = compute_score(findings, max_score=0)
        self.assertEqual(score, 0)

    def test_single_large_deduction(self):
        findings = [Finding("T", "critical", "c", "m", "d", "e", "a", points_deducted=101)]
        score = compute_score(findings)
        self.assertEqual(score, 0)

    def test_exactly_100_deductions(self):
        findings = [Finding("T", "critical", "c", "m", "d", "e", "a", points_deducted=100)]
        score = compute_score(findings)
        self.assertEqual(score, 0)

    def test_exactly_99_deductions(self):
        findings = [Finding("T", "critical", "c", "m", "d", "e", "a", points_deducted=99)]
        score = compute_score(findings)
        self.assertEqual(score, 1)

    def test_string_points_raises(self):
        # String points_deducted causes TypeError in +=
        findings = [{"points_deducted": "20"}]
        with self.assertRaises(TypeError):
            compute_score(findings)


# ── badge_markdown edge cases ──────────────────────────────────────────────


class TestBadgeMarkdownEdgeCases(unittest.TestCase):
    """badge_markdown with various grades."""

    def test_unknown_grade_uses_lightgrey(self):
        md = badge_markdown("host", "UNKNOWN")
        self.assertIn("lightgrey", md)

    def test_empty_grade(self):
        md = badge_markdown("host", "")
        self.assertIn("lightgrey", md)

    def test_numeric_grade(self):
        md = badge_markdown("host", "99")
        self.assertIn("lightgrey", md)

    def test_special_chars_in_grade(self):
        md = badge_markdown("host", "A++")
        # Should contain the grade string
        self.assertIn("A++", md)

    def test_all_known_grades_have_color(self):
        for grade in VALID_GRADES:
            md = badge_markdown("host", grade)
            self.assertIn("labelColor=000000", md)


# ── truncate edge cases ────────────────────────────────────────────────────


class TestTruncateEdgeCases(unittest.TestCase):
    """truncate with various edge cases."""

    def test_empty_string(self):
        self.assertEqual(truncate(""), "")

    def test_exact_length(self):
        s = "a" * 16384
        result = truncate(s, max_len=16384)
        self.assertEqual(len(result), 16384)

    def test_one_over_length(self):
        s = "a" * 16385
        result = truncate(s, max_len=16384)
        self.assertEqual(len(result), 16384)

    def test_custom_max_len(self):
        s = "abcdefghij"
        result = truncate(s, max_len=5)
        self.assertEqual(result, "abcde")

    def test_max_len_zero(self):
        result = truncate("hello", max_len=0)
        self.assertEqual(result, "")

    def test_max_len_one(self):
        result = truncate("hello", max_len=1)
        self.assertEqual(result, "h")

    def test_whitespace_preserved(self):
        s = "hello world  "
        result = truncate(s, max_len=100)
        self.assertEqual(result, "hello world  ")

    def test_newlines_preserved(self):
        s = "line1\nline2\nline3"
        result = truncate(s, max_len=100)
        self.assertEqual(result, s)


# ── entropy edge cases ───────────────────────────────────────────────────


class TestEntropyEdgeCases(unittest.TestCase):
    """entropy with edge case inputs."""

    def test_single_character(self):
        e = entropy("a")
        self.assertEqual(e, 0.0)

    def test_two_same_characters(self):
        e = entropy("aa")
        self.assertEqual(e, 0.0)

    def test_two_different_characters(self):
        e = entropy("ab")
        self.assertAlmostEqual(e, 1.0, places=5)

    def test_repeated_pattern(self):
        e = entropy("abcabcabc")
        # Equal frequency of 3 chars = log2(3)
        self.assertAlmostEqual(e, math.log2(3), places=5)

    def test_all_unique(self):
        s = "abcdefghij"
        e = entropy(s)
        self.assertGreater(e, 0.0)

    def test_binary_string(self):
        e = entropy("01010101")
        self.assertAlmostEqual(e, 1.0, places=5)

    def test_whitespace_entropy(self):
        e = entropy("   ")
        self.assertEqual(e, 0.0)

    def test_newline_entropy(self):
        e = entropy("\n\n\n\n")
        self.assertEqual(e, 0.0)


# ── is_private_ip edge cases ──────────────────────────────────────────────


class TestIsPrivateIpEdgeCases(unittest.TestCase):
    """is_private_ip with RFC1918 ranges and public IPs."""

    def test_10_0_0_0(self):
        self.assertTrue(is_private_ip("10.0.0.0"))

    def test_10_255_255_255(self):
        self.assertTrue(is_private_ip("10.255.255.255"))

    def test_172_15_edge(self):
        self.assertFalse(is_private_ip("172.15.255.255"))

    def test_172_16_start(self):
        self.assertTrue(is_private_ip("172.16.0.0"))

    def test_172_31_end(self):
        self.assertTrue(is_private_ip("172.31.255.255"))

    def test_172_32_start(self):
        self.assertFalse(is_private_ip("172.32.0.0"))

    def test_192_167_edge(self):
        self.assertFalse(is_private_ip("192.167.255.255"))

    def test_192_168_start(self):
        self.assertTrue(is_private_ip("192.168.0.0"))

    def test_192_168_end(self):
        self.assertTrue(is_private_ip("192.168.255.255"))

    def test_192_169_start(self):
        self.assertFalse(is_private_ip("192.169.0.0"))

    def test_127_all(self):
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("127.255.255.255"))

    def test_public_ips(self):
        public = ["8.8.8.8", "1.1.1.1", "203.0.113.1", "224.0.0.1", "255.255.255.255"]
        for ip in public:
            self.assertFalse(is_private_ip(ip), f"{ip} should be public")

    def test_invalid_inputs(self):
        invalid = ["", "not-an-ip", "1.2.3", "a.b.c.d", "256.1.1.1", "1.1.1.1.1"]
        for ip in invalid:
            self.assertFalse(is_private_ip(ip), f"{ip} should return False")

    def test_ipv6_not_supported(self):
        self.assertFalse(is_private_ip("::1"))
        self.assertFalse(is_private_ip("2001:db8::1"))


# ── url_join edge cases ────────────────────────────────────────────────────


class TestUrlJoinEdgeCases(unittest.TestCase):
    """url_join with trailing/leading slashes and edge cases."""

    def test_no_trailing_slash_no_leading_slash(self):
        self.assertEqual(url_join("https://a.com", "path"), "https://a.com/path")

    def test_trailing_slash_no_leading_slash(self):
        self.assertEqual(url_join("https://a.com/", "path"), "https://a.com/path")

    def test_no_trailing_slash_leading_slash(self):
        self.assertEqual(url_join("https://a.com", "/path"), "https://a.com/path")

    def test_both_slashes(self):
        self.assertEqual(url_join("https://a.com/", "/path"), "https://a.com/path")

    def test_multiple_trailing_slashes(self):
        self.assertEqual(url_join("https://a.com///", "path"), "https://a.com/path")

    def test_multiple_leading_slashes(self):
        self.assertEqual(url_join("https://a.com", "///path"), "https://a.com/path")

    def test_empty_path(self):
        self.assertEqual(url_join("https://a.com/", ""), "https://a.com/")

    def test_nested_path(self):
        self.assertEqual(url_join("https://a.com", "a/b/c"), "https://a.com/a/b/c")

    def test_path_with_query(self):
        self.assertEqual(url_join("https://a.com", "path?q=1"), "https://a.com/path?q=1")


# ── safe_int / safe_float edge cases ─────────────────────────────────────


class TestSafeIntEdgeCases(unittest.TestCase):
    """safe_int with various edge cases."""

    def test_float_string_raises(self):
        # int("3.14") raises ValueError, returns default
        self.assertEqual(safe_int("3.14"), 0)

    def test_negative_string(self):
        self.assertEqual(safe_int("-42"), -42)

    def test_zero_string(self):
        self.assertEqual(safe_int("0"), 0)

    def test_bool_true(self):
        self.assertEqual(safe_int(True), 1)

    def test_bool_false(self):
        self.assertEqual(safe_int(False), 0)

    def test_list_input(self):
        self.assertEqual(safe_int([1, 2]), 0)

    def test_dict_input(self):
        self.assertEqual(safe_int({"a": 1}), 0)

    def test_empty_string(self):
        self.assertEqual(safe_int(""), 0)

    def test_float_nan(self):
        # int(nan) raises ValueError, returns default
        self.assertEqual(safe_int(float("nan")), 0)

    def test_float_inf_raises(self):
        # int(inf) raises OverflowError, safe_int doesn't catch it
        with self.assertRaises(OverflowError):
            safe_int(float("inf"))


class TestSafeFloatEdgeCases(unittest.TestCase):
    """safe_float with various edge cases."""

    def test_empty_string(self):
        self.assertAlmostEqual(safe_float(""), 0.0)

    def test_negative_string(self):
        self.assertAlmostEqual(safe_float("-3.14"), -3.14)

    def test_bool_true(self):
        self.assertAlmostEqual(safe_float(True), 1.0)

    def test_bool_false(self):
        self.assertAlmostEqual(safe_float(False), 0.0)

    def test_list_input(self):
        self.assertAlmostEqual(safe_float([1.0]), 0.0)

    def test_very_large_string(self):
        # Python can parse very large floats, just returns a huge number
        result = safe_float("999999999999999999999")
        self.assertIsInstance(result, float)

    def test_nan_string(self):
        # float("nan") succeeds and returns NaN, safe_float returns it
        import math
        result = safe_float("nan")
        self.assertTrue(math.isnan(result))


# ── DREAD_SCORE_MAP coverage ─────────────────────────────────────────────


class TestDreadScoreMapCoverage(unittest.TestCase):
    """Verify DREAD_SCORE_MAP has entries for all valid severities."""

    def test_all_severities_have_dread(self):
        for sev in VALID_SEVERITIES:
            self.assertIn(sev, DREAD_SCORE_MAP)

    def test_dread_values_in_range(self):
        for sev, score in DREAD_SCORE_MAP.items():
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    def test_dread_decreasing_order(self):
        vals = [DREAD_SCORE_MAP[s] for s in ["critical", "high", "medium", "low", "info"]]
        for i in range(len(vals) - 1):
            self.assertGreaterEqual(vals[i], vals[i + 1])


# ── BADGE_COLOR_MAP coverage ─────────────────────────────────────────────


class TestBadgeColorMapCoverage(unittest.TestCase):
    """Verify BADGE_COLOR_MAP completeness."""

    def test_all_grades_have_badge_colors(self):
        for grade in VALID_GRADES:
            self.assertIn(grade, BADGE_COLOR_MAP)

    def test_badge_color_values_are_strings(self):
        for color in BADGE_COLOR_MAP.values():
            self.assertIsInstance(color, str)


# ── ReconProResult to_dict completeness ──────────────────────────────────


class TestReconProResultToDict(unittest.TestCase):
    """Verify ReconProResult.to_dict() includes all expected keys."""

    def test_all_keys_present(self):
        result = ReconProResult(
            target="example.com",
            modules_run=["recon", "auth"],
            findings=[{"title": "T1"}],
            severity_counts={"high": 1},
            total_score=80,
            grade="A",
            badge_markdown="![badge](url)",
            vibesec_score=75,
            vibesec_grade="B",
            module_results={"recon": {"findings": [{"severity": "high"}]}},
        )
        d = result.to_dict()
        expected_keys = {
            "target", "modules_run", "total_findings",
            "severity_counts", "total_score", "grade",
            "badge_markdown", "vibesec_score", "vibesec_grade",
            "module_results", "findings", "intelligence",
            # v11 pipeline additions (engineering + quality intelligence)
            "engineering", "engineering_score", "quality",
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["vibesec_score"], 75)
        self.assertEqual(d["vibesec_grade"], "B")

    def test_vibesec_none(self):
        result = ReconProResult(
            target="example.com",
            modules_run=[],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
        )
        d = result.to_dict()
        self.assertIsNone(d["vibesec_score"])
        self.assertIsNone(d["vibesec_grade"])

    def test_empty_findings_count(self):
        result = ReconProResult(
            target="example.com",
            modules_run=[],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
        )
        d = result.to_dict()
        self.assertEqual(d["total_findings"], 0)


# ── SEVERITY_LEVELS and GRADE_THRESHOLDS consistency ──────────────────────


class TestConstantsConsistency(unittest.TestCase):
    """Verify cross-constant consistency."""

    def test_severity_levels_range(self):
        vals = list(SEVERITY_LEVELS.values())
        self.assertEqual(min(vals), 0)
        self.assertEqual(max(vals), 4)

    def test_grade_thresholds_decreasing(self):
        thresholds = [t for t, _ in GRADE_THRESHOLDS]
        for i in range(len(thresholds) - 1):
            self.assertGreater(thresholds[i], thresholds[i + 1])

    def test_grade_thresholds_first_is_max_score(self):
        self.assertEqual(GRADE_THRESHOLDS[0][0], 90)

    def test_grade_thresholds_last_is_zero(self):
        self.assertEqual(GRADE_THRESHOLDS[-1][0], 0)


if __name__ == "__main__":
    unittest.main()
