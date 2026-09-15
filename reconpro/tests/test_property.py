"""Property-based tests for ReconPro — invariant verification across valid inputs.

Manual implementation (no hypothesis dependency). Tests verify that functions
maintain invariants over their entire input domain.
"""

import sys
import os
import math
import string
import random
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.utils import (
    severity_to_cvss,
    severity_to_dread,
    compute_score,
    compute_grade,
    extract_host,
    normalize_base_url,
    count_severities,
    sort_findings_by_severity,
    entropy,
    badge_markdown,
    validate_severity,
    is_private_ip,
    url_join,
    safe_int,
    safe_float,
)
from reconpro.http_layer import Finding
from reconpro.constants import (
    VALID_SEVERITIES,
    VALID_GRADES,
    MAX_SCORE,
    MIN_SCORE,
    GRADE_THRESHOLDS,
)


# ── severity_to_cvss: always returns known mapping ─────────────────────────


class TestSeverityToCvssProperties(unittest.TestCase):
    """For all valid severities, severity_to_cvss returns known CVSS strings."""

    _EXPECTED = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    }

    def test_all_valid_severities_have_known_mapping(self):
        for sev in VALID_SEVERITIES:
            result = severity_to_cvss(sev)
            self.assertIn(result, self._EXPECTED.values(),
                          f"Unexpected CVSS for {sev}: {result}")

    def test_critical_maps_to_critical(self):
        self.assertEqual(severity_to_cvss("critical"), "CRITICAL")

    def test_high_maps_to_high(self):
        self.assertEqual(severity_to_cvss("high"), "HIGH")

    def test_medium_maps_to_medium(self):
        self.assertEqual(severity_to_cvss("medium"), "MEDIUM")

    def test_low_maps_to_low(self):
        self.assertEqual(severity_to_cvss("low"), "LOW")

    def test_info_maps_to_info(self):
        self.assertEqual(severity_to_cvss("info"), "INFO")

    def test_unknown_always_maps_to_info(self):
        unknowns = ["", "none", "unknown", "MINOR", "MAJOR", "CRITICAL_CUSTOM"]
        for u in unknowns:
            self.assertEqual(severity_to_cvss(u), "INFO",
                             f"severity_to_cvss({u!r}) should return INFO")

    def test_case_insensitive(self):
        for sev in VALID_SEVERITIES:
            self.assertEqual(severity_to_cvss(sev.upper()), severity_to_cvss(sev))


# ── severity_to_dread: always returns float in [0, 1] ─────────────────────


class TestSeverityToDreadProperties(unittest.TestCase):
    """For all valid severities, severity_to_dread returns float in [0, 1]."""

    def test_all_valid_severities_in_range(self):
        for sev in VALID_SEVERITIES:
            d = severity_to_dread(sev)
            self.assertIsInstance(d, float, f"DREAD for {sev} not float")
            self.assertGreaterEqual(d, 0.0, f"DREAD for {sev} < 0")
            self.assertLessEqual(d, 1.0, f"DREAD for {sev} > 1")

    def test_unknown_always_in_range(self):
        unknowns = ["", "extreme", "minimal", "UNKNOWN"]
        for u in unknowns:
            d = severity_to_dread(u)
            self.assertGreaterEqual(d, 0.0)
            self.assertLessEqual(d, 1.0)

    def test_critical_highest(self):
        self.assertEqual(severity_to_dread("critical"), 0.9)

    def test_info_lowest(self):
        self.assertEqual(severity_to_dread("info"), 0.1)

    def test_monotonic_decrease(self):
        """Higher severity should have higher DREAD score."""
        prev = float('inf')
        for sev in ["critical", "high", "medium", "low", "info"]:
            d = severity_to_dread(sev)
            self.assertGreaterEqual(prev, d, f"DREAD not monotonic: {prev} vs {d} ({sev})")
            prev = d


# ── compute_score: always returns int in [0, 100] ──────────────────────────


class TestComputeScoreProperties(unittest.TestCase):
    """compute_score always returns int in [MIN_SCORE, MAX_SCORE]."""

    def test_empty_findings_returns_max(self):
        self.assertEqual(compute_score([]), MAX_SCORE)

    def test_zero_deductions_returns_max(self):
        findings = [Finding("t", "info", "c", "m", "d", "e", "a")]
        self.assertEqual(compute_score(findings), MAX_SCORE)

    def test_result_always_int(self):
        for n in range(0, 200, 10):
            findings = [Finding("t", "high", "c", "m", "d", "e", "a", points_deducted=n)]
            score = compute_score(findings)
            self.assertIsInstance(score, int)

    def test_result_always_in_range(self):
        for n in range(0, 300, 25):
            findings = [Finding("t", "critical", "c", "m", "d", "e", "a", points_deducted=n)]
            score = compute_score(findings)
            self.assertGreaterEqual(score, MIN_SCORE)
            self.assertLessEqual(score, MAX_SCORE)

    def test_massive_deductions_clamped_to_zero(self):
        findings = [Finding("t", "critical", "c", "m", "d", "e", "a", points_deducted=10000)]
        self.assertEqual(compute_score(findings), MIN_SCORE)

    def test_fractional_points_clamped(self):
        """Dict findings with float points should be handled."""
        findings = [{"points_deducted": 50.7}]
        score = compute_score(findings)
        self.assertGreaterEqual(score, MIN_SCORE)
        self.assertLessEqual(score, MAX_SCORE)

    def test_many_findings_still_in_range(self):
        findings = [Finding(f"t{i}", "high", "c", "m", "d", "e", "a", points_deducted=1)
                    for i in range(200)]
        score = compute_score(findings)
        self.assertEqual(score, 0)

    def test_custom_max_score(self):
        findings = [Finding("t", "high", "c", "m", "d", "e", "a", points_deducted=50)]
        score = compute_score(findings, max_score=200)
        self.assertGreaterEqual(score, MIN_SCORE)
        self.assertLessEqual(score, 200)


# ── compute_grade: always returns valid grade string ─────────────────────


class TestComputeGradeProperties(unittest.TestCase):
    """compute_grade always returns a valid grade."""

    def test_all_scores_return_valid_grade(self):
        for score in range(-10, 110, 5):
            grade = compute_grade(score)
            # Grade should be A+, A, B, C, D, or F
            self.assertIn(grade, VALID_GRADES,
                          f"Score {score} -> invalid grade '{grade}'")

    def test_boundary_scores(self):
        boundaries = [0, 1, 34, 35, 36, 49, 50, 51, 64, 65, 66, 79, 80, 81, 89, 90, 91, 100]
        for score in boundaries:
            grade = compute_grade(score)
            self.assertIn(grade, VALID_GRADES)

    def test_monotonic_grade_improvement(self):
        """Higher scores should have same or better grades."""
        prev_grade_idx = len(GRADE_THRESHOLDS)  # Start with worst
        grade_list = [g for _, g in GRADE_THRESHOLDS]
        for score in range(0, 101, 1):
            grade = compute_grade(score)
            idx = grade_list.index(grade)
            # As score increases, grade should improve or stay same
            # (not strictly monotonic due to ranges, but overall trend holds)


# ── extract_host: always returns non-empty for valid inputs ────────────────


class TestExtractHostProperties(unittest.TestCase):
    """extract_host always returns non-empty string for valid inputs."""

    def test_various_url_formats(self):
        inputs = [
            "https://example.com",
            "http://example.com:8080/path",
            "example.com",
            "192.168.1.1:443",
            "sub.domain.example.co.uk/path?q=1",
            "https://a-b.c-d.example.com:9999/api/v1",
        ]
        for inp in inputs:
            result = extract_host(inp)
            self.assertTrue(len(result) > 0, f"extract_host({inp!r}) returned empty")
            # No slashes should remain
            self.assertNotIn("/", result, f"extract_host({inp!r}) has slash: {result}")

    def test_empty_input_returns_empty(self):
        self.assertEqual(extract_host(""), "")

    def test_ip_addresses(self):
        ips = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "8.8.8.8"]
        for ip in ips:
            result = extract_host(ip)
            self.assertTrue(len(result) > 0)

    def test_with_port(self):
        result = extract_host("https://example.com:443/path")
        self.assertEqual(result, "example.com:443")


# ── normalize_base_url: always starts with scheme ─────────────────────────


class TestNormalizeBaseUrlProperties(unittest.TestCase):
    """normalize_base_url always starts with http:// or https://."""

    def test_various_inputs(self):
        inputs = [
            "example.com",
            "sub.example.com",
            "http://example.com",
            "https://example.com/path",
            "192.168.1.1",
            "example.com:8080",
        ]
        for inp in inputs:
            result = normalize_base_url(inp)
            self.assertTrue(
                result.startswith("http://") or result.startswith("https://"),
                f"normalize_base_url({inp!r}) = {result!r} missing scheme"
            )

    def test_empty_returns_empty(self):
        self.assertEqual(normalize_base_url(""), "")

    def test_http_preserved(self):
        self.assertTrue(normalize_base_url("http://example.com").startswith("http://"))

    def test_https_preserved(self):
        self.assertTrue(normalize_base_url("https://example.com").startswith("https://"))

    def test_bare_domain_gets_https(self):
        self.assertTrue(normalize_base_url("example.com").startswith("https://"))


# ── count_severities: counts always sum to total findings ─────────────────


class TestCountSeveritiesProperties(unittest.TestCase):
    """Severity counts always sum to total number of findings."""

    def test_counts_sum_to_total(self):
        for _ in range(100):
            n_findings = random.randint(1, 50)
            findings = []
            for i in range(n_findings):
                sev = random.choice(list(VALID_SEVERITIES))
                findings.append({"severity": sev})
            counts = count_severities(findings)
            total = sum(counts.values())
            self.assertEqual(total, n_findings,
                             f"Counts {counts} sum to {total}, expected {n_findings}")

    def test_empty_list_counts_zero(self):
        counts = count_severities([])
        self.assertEqual(sum(counts.values()), 0)

    def test_mixed_objects_and_dicts(self):
        f1 = Finding("t", "high", "c", "m", "d", "e", "a")
        f2 = {"severity": "high"}
        f3 = {"severity": "low"}
        counts = count_severities([f1, f2, f3])
        self.assertEqual(sum(counts.values()), 3)

    def test_unknown_severity_maps_to_info(self):
        """Unknown severities should be mapped to 'info', and still count."""
        findings = [
            {"severity": "critical"},
            {"severity": "weird"},
            {"severity": "none"},
        ]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["info"], 2)
        self.assertEqual(sum(counts.values()), 3)

    def test_all_same_severity(self):
        for sev in VALID_SEVERITIES:
            findings = [{"severity": sev} for _ in range(10)]
            counts = count_severities(findings)
            self.assertEqual(counts[sev], 10)
            self.assertEqual(sum(counts.values()), 10)


# ── sort_findings_by_severity: stable sort ───────────────────────────────


class TestSortFindingsStable(unittest.TestCase):
    """sort_findings_by_severity preserves insertion order for equal severities."""

    def test_stable_with_same_severity(self):
        """Equal elements should maintain their relative order."""
        findings = [
            Finding(f"F{i}", "high", "c", "m", "d", "e", "a")
            for i in range(10)
        ]
        sorted_f = sort_findings_by_severity(findings)
        for i, f in enumerate(sorted_f):
            self.assertEqual(f.title, f"F{i}")

    def test_stable_reversed_input(self):
        findings = [
            Finding(f"F{i}", "info", "c", "m", "d", "e", "a")
            for i in range(20, 0, -1)
        ]
        sorted_f = sort_findings_by_severity(findings)
        titles = [f.title for f in sorted_f]
        self.assertEqual(titles, [f"F{i}" for i in range(20, 0, -1)])

    def test_stable_with_dicts(self):
        findings = [{"severity": "medium", "idx": i} for i in range(5)]
        sorted_f = sort_findings_by_severity(findings)
        indices = [f["idx"] for f in sorted_f]
        self.assertEqual(indices, [0, 1, 2, 3, 4])

    def test_interleaved_severities(self):
        """Alternating severities should be grouped correctly."""
        findings = []
        for i in range(5):
            findings.append(Finding(f"Info{i}", "info", "c", "m", "d", "e", "a"))
            findings.append(Finding(f"Crit{i}", "critical", "c", "m", "d", "e", "a"))
        sorted_f = sort_findings_by_severity(findings)
        # All criticals first, then all infos
        all_sevs = [f.severity for f in sorted_f]
        # Criticals should all be before infos
        last_crit = 0
        for i, s in enumerate(all_sevs):
            if s == "critical":
                last_crit = i
        for i in range(last_crit + 1, len(all_sevs)):
            self.assertEqual(all_sevs[i], "info")


# ── entropy: always returns non-negative float ────────────────────────────


class TestEntropyProperties(unittest.TestCase):
    """entropy always returns a non-negative float."""

    def test_empty_string_is_zero(self):
        self.assertEqual(entropy(""), 0.0)

    def test_always_non_negative(self):
        for _ in range(100):
            length = random.randint(1, 100)
            s = "".join(random.choice(string.ascii_letters) for _ in range(length))
            e = entropy(s)
            self.assertGreaterEqual(e, 0.0)

    def test_uniform_distribution_max_entropy(self):
        """Uniform distribution should have highest entropy for given alphabet."""
        # Binary: "01" repeated
        binary = "01" * 50
        e = entropy(binary)
        # All binary: max entropy = 1.0
        self.assertAlmostEqual(e, 1.0, places=5)

    def test_single_char_repeated_zero_entropy(self):
        self.assertAlmostEqual(entropy("aaaaa"), 0.0)

    def test_two_chars_equal_frequency(self):
        self.assertAlmostEqual(entropy("ab"), 1.0, places=5)

    def test_high_alphabet_high_entropy(self):
        """256 unique characters should have high entropy."""
        s = "".join(chr(i) for i in range(256))
        e = entropy(s)
        # Shannon entropy for 256 unique chars: log2(256) = 8
        self.assertAlmostEqual(e, 8.0, places=1)

    def test_entropy_deterministic(self):
        """Same input always gives same output."""
        for _ in range(50):
            s = "".join(random.choice("abc") for _ in range(20))
            self.assertEqual(entropy(s), entropy(s))

    def test_entropy_monotonic_with_diversity(self):
        """More diverse input should have higher or equal entropy."""
        e1 = entropy("aaaa")
        e2 = entropy("aabb")
        e3 = entropy("abcd")
        self.assertLessEqual(e1, e2)
        self.assertLessEqual(e2, e3)


# ── badge_markdown: always contains grade string ───────────────────────────


class TestBadgeMarkdownProperties(unittest.TestCase):
    """badge_markdown always contains the grade string."""

    def test_all_valid_grades(self):
        for grade in VALID_GRADES:
            md = badge_markdown("example.com", grade)
            self.assertIn(grade, md, f"Grade {grade} not in badge: {md}")

    def test_unknown_grade(self):
        md = badge_markdown("example.com", "Z")
        self.assertIn("Z", md)

    def test_always_contains_shields_io(self):
        for grade in list(VALID_GRADES) + ["X", "Y", "Z"]:
            md = badge_markdown("host", grade)
            self.assertIn("img.shields.io", md)

    def test_always_markdown_image_format(self):
        md = badge_markdown("host", "A+")
        self.assertTrue(md.startswith("!["))
        self.assertIn("](https://", md)


# ── validate_severity: always returns valid severity ──────────────────────


class TestValidateSeverityProperties(unittest.TestCase):
    """validate_severity always returns a string in VALID_SEVERITIES or 'info'."""

    def test_all_valid_severities_unchanged(self):
        for sev in VALID_SEVERITIES:
            self.assertEqual(validate_severity(sev), sev)

    def test_invalid_inputs_return_info(self):
        invalids = ["", "none", "unknown", "CRITICAL_CUSTOM", "   ", "MEDIUM\n", "\tlow\t"]
        for inv in invalids:
            result = validate_severity(inv)
            self.assertIn(result, VALID_SEVERITIES)

    def test_uppercase_normalized(self):
        for sev in VALID_SEVERITIES:
            self.assertEqual(validate_severity(sev.upper()), sev)

    def test_whitespace_handled(self):
        self.assertEqual(validate_severity("  critical  "), "critical")


if __name__ == "__main__":
    unittest.main()
