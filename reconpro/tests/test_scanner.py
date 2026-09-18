"""Tests for reconpro.scanner — scan orchestration."""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.scanner import scan, audit_scan, ReconProResult


class TestScanEmptyTarget(unittest.TestCase):
    """Test scan() raises ValueError for empty target."""

    def test_empty_string_raises(self):
        with self.assertRaises(ValueError) as ctx:
            scan("")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_whitespace_target_raises(self):
        with self.assertRaises(ValueError):
            scan("   ")


class TestScanInvalidChars(unittest.TestCase):
    """Test scan() raises ValueError for target with invalid chars."""

    def test_semicolon_raises(self):
        with self.assertRaises(ValueError) as ctx:
            scan("example.com; ls")
        self.assertIn("invalid", str(ctx.exception).lower())

    def test_pipe_raises(self):
        with self.assertRaises(ValueError):
            scan("example.com | cat")

    def test_backtick_raises(self):
        with self.assertRaises(ValueError):
            scan("example.com`id`")

    def test_dollar_raises(self):
        with self.assertRaises(ValueError):
            scan("example.com$HOME")

    def test_ampersand_raises(self):
        with self.assertRaises(ValueError):
            scan("example.com && echo")


class TestScanWithNoWorkingModules(unittest.TestCase):
    """Test scan() with no working modules returns score 100 (mocked)."""

    @patch('reconpro.scanner.get_module_runner', return_value=None)
    def test_no_runners_score_100(self, mock_runner):
        result = scan("example.com", modules=["nonexistent"])
        self.assertEqual(result.total_score, 100)
        self.assertEqual(result.grade, "A+")
        self.assertEqual(result.findings, [])

    @patch('reconpro.scanner.get_module_runner', return_value=None)
    def test_no_runners_modules_run_empty(self, mock_runner):
        result = scan("example.com", modules=["fake"])
        self.assertEqual(result.modules_run, [])


class TestScanWithMockedModules(unittest.TestCase):
    """Test scan() with mocked module runners."""

    @patch('reconpro.scanner.get_module_runner')
    def test_scan_with_empty_findings_module(self, mock_get_runner):
        mock_get_runner.return_value = lambda target, base_url, **kwargs: []
        result = scan("example.com", modules=["recon"])
        self.assertEqual(result.total_score, 100)
        self.assertEqual(len(result.findings), 0)

    @patch('reconpro.scanner.get_module_runner')
    def test_scan_with_finding_module(self, mock_get_runner):
        from reconpro.http_layer import Finding

        def fake_runner(target, base_url, **kwargs):
            return [Finding(
                title="Test Finding",
                severity="high",
                category="test",
                module="recon",
                description="test",
                evidence="test",
                asset="example.com",
                points_deducted=20,
            )]

        mock_get_runner.return_value = fake_runner
        result = scan("example.com", modules=["recon"])
        self.assertEqual(result.total_score, 80)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.severity_counts.get("high"), 1)


class TestAuditScan(unittest.TestCase):
    """Test audit_scan returns ReconProResult."""

    @patch('reconpro.scanner.get_module_runner', return_value=lambda **kwargs: [])
    def test_audit_returns_result(self, mock_runner):
        result = audit_scan()
        self.assertIsInstance(result, ReconProResult)

    @patch('reconpro.scanner.get_module_runner', return_value=lambda **kwargs: [])
    def test_audit_target_local_audit(self, mock_runner):
        result = audit_scan()
        self.assertEqual(result.target, "local-audit")

    @patch('reconpro.scanner.get_module_runner', return_value=lambda **kwargs: [])
    def test_audit_modules_run(self, mock_runner):
        result = audit_scan()
        self.assertIn("host", result.modules_run)
        self.assertIn("dev", result.modules_run)
        self.assertIn("doctor", result.modules_run)

    @patch('reconpro.scanner.get_module_runner', return_value=lambda **kwargs: [])
    def test_audit_score_100_no_findings(self, mock_runner):
        result = audit_scan()
        self.assertEqual(result.total_score, 100)


class TestReconProResultToDict(unittest.TestCase):
    """Test ReconProResult.to_dict() has correct keys."""

    def test_to_dict_keys(self):
        result = ReconProResult(
            target="example.com",
            modules_run=["recon"],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="![badge](...)",
        )
        d = result.to_dict()
        expected_keys = {
            "target", "modules_run", "total_findings",
            "severity_counts", "total_score", "grade",
            "badge_markdown", "vibesec_score", "vibesec_grade",
            "module_results", "findings", "intelligence", "engineering",
            "quality", "engineering_score",
            "target_validation", "scan_metadata",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_total_findings(self):
        result = ReconProResult(
            target="example.com",
            modules_run=["recon"],
            findings=[{"title": "t1"}, {"title": "t2"}],
            severity_counts={},
            total_score=80,
            grade="A",
            badge_markdown="",
        )
        d = result.to_dict()
        self.assertEqual(d["total_findings"], 2)

    def test_to_dict_optional_fields_none(self):
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


if __name__ == "__main__":
    unittest.main()
