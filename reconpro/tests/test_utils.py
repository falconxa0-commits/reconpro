"""Tests for reconpro.utils — shared utility functions."""

import sys
import os
import math
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.utils import (
    extract_host,
    normalize_base_url,
    validate_target,
    count_severities,
    sort_findings_by_severity,
    severity_to_cvss,
    severity_to_dread,
    validate_severity,
    compute_score,
    compute_grade,
    badge_markdown,
    safe_int,
    safe_float,
    truncate,
    entropy,
    is_private_ip,
    url_join,
)
from reconpro.http_layer import Finding


# ── extract_host ─────────────────────────────────────────────────────────

class TestExtractHost(unittest.TestCase):
    """Test extract_host with various inputs."""

    def test_https_url(self):
        self.assertEqual(extract_host("https://example.com/path"), "example.com")

    def test_http_url(self):
        self.assertEqual(extract_host("http://example.com/path"), "example.com")

    def test_url_with_port(self):
        self.assertEqual(extract_host("http://example.com:8080/"), "example.com:8080")

    def test_https_url_with_port(self):
        self.assertEqual(extract_host("https://example.com:443/api"), "example.com:443")

    def test_bare_domain(self):
        self.assertEqual(extract_host("example.com"), "example.com")

    def test_ip_address(self):
        self.assertEqual(extract_host("192.168.1.1"), "192.168.1.1")

    def test_ip_with_port(self):
        self.assertEqual(extract_host("192.168.1.1:443"), "192.168.1.1:443")

    def test_empty_string(self):
        self.assertEqual(extract_host(""), "")

    def test_whitespace_only(self):
        self.assertEqual(extract_host("   "), "")

    def test_url_with_query_params(self):
        self.assertEqual(extract_host("https://example.com/path?q=1"), "example.com")

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(extract_host("  example.com  "), "example.com")

    def test_case_insensitive_scheme(self):
        self.assertEqual(extract_host("HTTPS://Example.COM/path"), "Example.COM")


# ── normalize_base_url ───────────────────────────────────────────────────

class TestNormalizeBaseUrl(unittest.TestCase):
    """Test normalize_base_url."""

    def test_bare_domain_gets_https(self):
        self.assertEqual(normalize_base_url("example.com"), "https://example.com")

    def test_http_preserved(self):
        self.assertEqual(normalize_base_url("http://example.com"), "http://example.com")

    def test_https_preserved(self):
        self.assertEqual(normalize_base_url("https://example.com/path"), "https://example.com/path")

    def test_empty_string(self):
        self.assertEqual(normalize_base_url(""), "")

    def test_whitespace_stripped(self):
        self.assertEqual(normalize_base_url("  example.com  "), "https://example.com")


# ── validate_target ──────────────────────────────────────────────────────

class TestValidateTarget(unittest.TestCase):
    """Test validate_target."""

    def test_empty_string_rejected(self):
        valid, msg = validate_target("")
        self.assertFalse(valid)
        self.assertIn("empty", msg.lower())

    def test_whitespace_only_rejected(self):
        valid, msg = validate_target("   ")
        self.assertFalse(valid)

    def test_semicolon_rejected(self):
        valid, msg = validate_target("example.com; ls")
        self.assertFalse(valid)
        self.assertIn("invalid characters", msg)

    def test_pipe_rejected(self):
        valid, msg = validate_target("example.com | cat")
        self.assertFalse(valid)

    def test_backtick_rejected(self):
        valid, msg = validate_target("example.com`whoami`")
        self.assertFalse(valid)

    def test_dollar_sign_rejected(self):
        valid, msg = validate_target("example.com$HOME")
        self.assertFalse(valid)

    def test_ampersand_rejected(self):
        valid, msg = validate_target("example.com&echo")
        self.assertFalse(valid)

    def test_valid_domain_accepted(self):
        valid, msg = validate_target("example.com")
        self.assertTrue(valid)

    def test_valid_url_accepted(self):
        valid, msg = validate_target("https://example.com")
        self.assertTrue(valid)

    def test_private_ip_returns_local_flag(self):
        valid, msg = validate_target("127.0.0.1")
        self.assertTrue(valid)
        self.assertEqual(msg, "LOCAL")

    def test_10_range_returns_local_flag(self):
        valid, msg = validate_target("10.0.0.1")
        self.assertTrue(valid)
        self.assertEqual(msg, "LOCAL")

    def test_192_168_range_returns_local_flag(self):
        valid, msg = validate_target("192.168.1.1")
        self.assertTrue(valid)
        self.assertEqual(msg, "LOCAL")

    def test_localhost_returns_local_flag(self):
        valid, msg = validate_target("localhost")
        self.assertTrue(valid)
        self.assertEqual(msg, "LOCAL")

    def test_long_hostname_rejected(self):
        long_host = "a" * 254 + ".com"
        valid, msg = validate_target(long_host)
        self.assertFalse(valid)
        self.assertIn("253", msg)


# ── count_severities ─────────────────────────────────────────────────────

class TestCountSeverities(unittest.TestCase):
    """Test count_severities."""

    def test_empty_list(self):
        self.assertEqual(count_severities([]), {})

    def test_finding_objects(self):
        findings = [
            Finding("t1", "critical", "c", "m", "d", "e", "a", points_deducted=10),
            Finding("t2", "critical", "c", "m", "d", "e", "a", points_deducted=10),
            Finding("t3", "high", "c", "m", "d", "e", "a", points_deducted=5),
        ]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 1)

    def test_dict_findings(self):
        findings = [
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
        counts = count_severities(findings)
        self.assertEqual(counts["medium"], 2)
        self.assertEqual(counts["low"], 1)

    def test_unknown_severity_maps_to_info(self):
        findings = [{"severity": "weird"}]
        counts = count_severities(findings)
        self.assertEqual(counts["info"], 1)

    def test_case_insensitive(self):
        findings = [{"severity": "CRITICAL"}]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 1)


# ── sort_findings_by_severity ────────────────────────────────────────────

class TestSortFindingsBySeverity(unittest.TestCase):
    """Test sort_findings_by_severity."""

    def test_critical_first(self):
        findings = [
            Finding("t1", "info", "c", "m", "d", "e", "a"),
            Finding("t2", "critical", "c", "m", "d", "e", "a"),
            Finding("t3", "high", "c", "m", "d", "e", "a"),
        ]
        sorted_f = sort_findings_by_severity(findings)
        self.assertEqual(sorted_f[0].severity, "critical")
        self.assertEqual(sorted_f[1].severity, "high")
        self.assertEqual(sorted_f[2].severity, "info")

    def test_reverse_order(self):
        findings = [
            Finding("t1", "critical", "c", "m", "d", "e", "a"),
            Finding("t2", "info", "c", "m", "d", "e", "a"),
        ]
        sorted_f = sort_findings_by_severity(findings, reverse=True)
        self.assertEqual(sorted_f[0].severity, "info")
        self.assertEqual(sorted_f[1].severity, "critical")

    def test_stable_sort(self):
        f1 = Finding("a", "high", "c", "m", "d", "e", "a")
        f2 = Finding("b", "high", "c", "m", "d", "e", "a")
        findings = [f2, f1]
        sorted_f = sort_findings_by_severity(findings)
        self.assertIs(sorted_f[0], f2)
        self.assertIs(sorted_f[1], f1)

    def test_dict_findings_sorted(self):
        findings = [
            {"severity": "low"},
            {"severity": "critical"},
        ]
        sorted_f = sort_findings_by_severity(findings)
        self.assertEqual(sorted_f[0]["severity"], "critical")


# ── severity_to_cvss / severity_to_dread ─────────────────────────────────

class TestSeverityMappings(unittest.TestCase):
    """Test severity-to-CVSS and severity-to-DREAD mappings."""

    def test_cvss_critical(self):
        self.assertEqual(severity_to_cvss("critical"), "CRITICAL")

    def test_cvss_high(self):
        self.assertEqual(severity_to_cvss("high"), "HIGH")

    def test_cvss_medium(self):
        self.assertEqual(severity_to_cvss("medium"), "MEDIUM")

    def test_cvss_low(self):
        self.assertEqual(severity_to_cvss("low"), "LOW")

    def test_cvss_info(self):
        self.assertEqual(severity_to_cvss("info"), "INFO")

    def test_cvss_unknown_falls_back_to_info(self):
        self.assertEqual(severity_to_cvss("unknown"), "INFO")

    def test_cvss_case_insensitive(self):
        self.assertEqual(severity_to_cvss("CRITICAL"), "CRITICAL")

    def test_dread_critical(self):
        self.assertEqual(severity_to_dread("critical"), 0.9)

    def test_dread_high(self):
        self.assertEqual(severity_to_dread("high"), 0.7)

    def test_dread_medium(self):
        self.assertEqual(severity_to_dread("medium"), 0.5)

    def test_dread_low(self):
        self.assertEqual(severity_to_dread("low"), 0.3)

    def test_dread_info(self):
        self.assertEqual(severity_to_dread("info"), 0.1)

    def test_dread_unknown_falls_back(self):
        self.assertEqual(severity_to_dread("unknown"), 0.1)


# ── validate_severity ────────────────────────────────────────────────────

class TestValidateSeverity(unittest.TestCase):
    """Test validate_severity."""

    def test_valid_critical(self):
        self.assertEqual(validate_severity("critical"), "critical")

    def test_valid_high(self):
        self.assertEqual(validate_severity("high"), "high")

    def test_case_normalization(self):
        self.assertEqual(validate_severity("CRITICAL"), "critical")

    def test_whitespace_stripped(self):
        self.assertEqual(validate_severity("  medium  "), "medium")

    def test_unknown_returns_info(self):
        self.assertEqual(validate_severity("weird"), "info")

    def test_empty_string_returns_info(self):
        self.assertEqual(validate_severity(""), "info")


# ── compute_score ────────────────────────────────────────────────────────

class TestComputeScore(unittest.TestCase):
    """Test compute_score."""

    def test_empty_findings_returns_100(self):
        self.assertEqual(compute_score([]), 100)

    def test_no_deductions_returns_100(self):
        findings = [Finding("t", "info", "c", "m", "d", "e", "a")]
        self.assertEqual(compute_score(findings), 100)

    def test_max_deductions_clamps_to_zero(self):
        findings = [Finding("t", "critical", "c", "m", "d", "e", "a", points_deducted=150)]
        self.assertEqual(compute_score(findings), 0)

    def test_partial_deductions(self):
        findings = [Finding("t", "high", "c", "m", "d", "e", "a", points_deducted=25)]
        self.assertEqual(compute_score(findings), 75)

    def test_multiple_findings(self):
        findings = [
            Finding("t1", "critical", "c", "m", "d", "e", "a", points_deducted=30),
            Finding("t2", "high", "c", "m", "d", "e", "a", points_deducted=20),
        ]
        self.assertEqual(compute_score(findings), 50)

    def test_dict_findings(self):
        findings = [{"points_deducted": 10}, {"points_deducted": 5}]
        self.assertEqual(compute_score(findings), 85)

    def test_custom_max_score(self):
        findings = [Finding("t", "high", "c", "m", "d", "e", "a", points_deducted=30)]
        self.assertEqual(compute_score(findings, max_score=200), 170)


# ── compute_grade ────────────────────────────────────────────────────────

class TestComputeGrade(unittest.TestCase):
    """Test compute_grade."""

    def test_95_is_a_plus(self):
        self.assertEqual(compute_grade(95), "A+")

    def test_90_is_a_plus(self):
        self.assertEqual(compute_grade(90), "A+")

    def test_85_is_a(self):
        self.assertEqual(compute_grade(85), "A")

    def test_80_is_a(self):
        self.assertEqual(compute_grade(80), "A")

    def test_70_is_b(self):
        self.assertEqual(compute_grade(70), "B")

    def test_65_is_b(self):
        self.assertEqual(compute_grade(65), "B")

    def test_55_is_c(self):
        self.assertEqual(compute_grade(55), "C")

    def test_40_is_d(self):
        self.assertEqual(compute_grade(40), "D")

    def test_20_is_f(self):
        self.assertEqual(compute_grade(20), "F")

    def test_zero_is_f(self):
        self.assertEqual(compute_grade(0), "F")

    def test_100_is_a_plus(self):
        self.assertEqual(compute_grade(100), "A+")


# ── badge_markdown ───────────────────────────────────────────────────────

class TestBadgeMarkdown(unittest.TestCase):
    """Test badge_markdown."""

    def test_output_format(self):
        md = badge_markdown("example.com", "A+")
        self.assertIn("![ReconPro A+]", md)
        self.assertIn("img.shields.io", md)
        self.assertIn("A+", md)
        self.assertIn("brightgreen", md)

    def test_style_for_the_badge(self):
        md = badge_markdown("example.com", "B")
        self.assertIn("for-the-badge", md)

    def test_label_color_black(self):
        md = badge_markdown("example.com", "C")
        self.assertIn("labelColor=000000", md)

    def test_unknown_grade_uses_lightgrey(self):
        md = badge_markdown("example.com", "Z")
        self.assertIn("lightgrey", md)


# ── safe_int / safe_float ───────────────────────────────────────────────

class TestSafeInt(unittest.TestCase):
    """Test safe_int."""

    def test_valid_integer(self):
        self.assertEqual(safe_int("42"), 42)

    def test_valid_integer_from_int(self):
        self.assertEqual(safe_int(42), 42)

    def test_valid_float_truncates(self):
        self.assertEqual(safe_int(3.7), 3)

    def test_none_returns_default(self):
        self.assertEqual(safe_int(None), 0)

    def test_invalid_string_returns_default(self):
        self.assertEqual(safe_int("abc"), 0)

    def test_custom_default(self):
        self.assertEqual(safe_int("bad", default=-1), -1)


class TestSafeFloat(unittest.TestCase):
    """Test safe_float."""

    def test_valid_float(self):
        self.assertAlmostEqual(safe_float("3.14"), 3.14)

    def test_valid_int(self):
        self.assertAlmostEqual(safe_float(42), 42.0)

    def test_none_returns_default(self):
        self.assertAlmostEqual(safe_float(None), 0.0)

    def test_invalid_string_returns_default(self):
        self.assertAlmostEqual(safe_float("not a number"), 0.0)

    def test_custom_default(self):
        self.assertAlmostEqual(safe_float("bad", default=-1.5), -1.5)


# ── truncate ─────────────────────────────────────────────────────────────

class TestTruncate(unittest.TestCase):
    """Test truncate."""

    def test_short_string_unchanged(self):
        self.assertEqual(truncate("hello"), "hello")

    def test_long_string_truncated(self):
        s = "a" * 20000
        result = truncate(s)
        self.assertEqual(len(result), 16384)

    def test_empty_string(self):
        self.assertEqual(truncate(""), "")

    def test_none_input(self):
        self.assertEqual(truncate(None), "")  # type: ignore[arg-type]

    def test_custom_max_len(self):
        s = "abcdefghij"
        self.assertEqual(truncate(s, max_len=5), "abcde")

    def test_exact_length_unchanged(self):
        s = "a" * 16384
        self.assertEqual(len(truncate(s)), 16384)


# ── entropy ──────────────────────────────────────────────────────────────

class TestEntropy(unittest.TestCase):
    """Test entropy function."""

    def test_empty_string_zero(self):
        self.assertEqual(entropy(""), 0.0)

    def test_single_char_zero(self):
        self.assertEqual(entropy("aaaa"), 0.0)

    def test_uniform_distribution(self):
        # Two characters with equal frequency: entropy = 1.0
        self.assertAlmostEqual(entropy("ab"), 1.0, places=5)

    def test_skewed_distribution(self):
        # Mostly 'a' with one 'b': low entropy
        e = entropy("aaaaab")
        self.assertLess(e, 1.0)
        self.assertGreater(e, 0.0)

    def test_high_entropy(self):
        # All unique characters in base64 range
        import string
        data = string.ascii_letters + string.digits
        e = entropy(data)
        # Shannon entropy for 62 unique chars is log2(62) ≈ 5.95
        self.assertAlmostEqual(e, math.log2(62), places=1)

    def test_deterministic(self):
        self.assertEqual(entropy("hello"), entropy("hello"))


# ── is_private_ip ───────────────────────────────────────────────────────

class TestIsPrivateIp(unittest.TestCase):
    """Test is_private_ip."""

    def test_10_range(self):
        self.assertTrue(is_private_ip("10.0.0.1"))

    def test_172_16_range(self):
        self.assertTrue(is_private_ip("172.16.0.1"))

    def test_172_31_range(self):
        self.assertTrue(is_private_ip("172.31.255.255"))

    def test_192_168_range(self):
        self.assertTrue(is_private_ip("192.168.1.1"))

    def test_127_loopback(self):
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_public_ip(self):
        self.assertFalse(is_private_ip("8.8.8.8"))

    def test_public_ip_2(self):
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_invalid_format(self):
        self.assertFalse(is_private_ip("not-an-ip"))

    def test_missing_octet(self):
        self.assertFalse(is_private_ip("192.168.1"))

    def test_non_numeric_octet(self):
        self.assertFalse(is_private_ip("192.168.abc.1"))


# ── url_join ─────────────────────────────────────────────────────────────

class TestUrlJoin(unittest.TestCase):
    """Test url_join."""

    def test_basic_join(self):
        self.assertEqual(url_join("https://example.com", "api/v1"),
                         "https://example.com/api/v1")

    def test_trailing_slash_stripped(self):
        self.assertEqual(url_join("https://example.com/", "path"),
                         "https://example.com/path")

    def test_leading_slash_stripped(self):
        self.assertEqual(url_join("https://example.com", "/path"),
                         "https://example.com/path")

    def test_both_slashes(self):
        self.assertEqual(url_join("https://example.com/", "/path"),
                         "https://example.com/path")


if __name__ == "__main__":
    unittest.main()
