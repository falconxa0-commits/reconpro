"""Tests for reconpro.http_layer.Finding dataclass."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding


class TestFindingCreation(unittest.TestCase):
    """Test Finding dataclass creation."""

    def test_create_with_all_fields(self):
        f = Finding(
            title="XSS in login form",
            severity="high",
            category="injection",
            module="recon",
            description="Reflected XSS found",
            evidence="<script>alert(1)</script>",
            asset="example.com/login",
            points_deducted=15,
            remediation="Sanitize user input",
            dread_score=0.7,
        )
        self.assertEqual(f.title, "XSS in login form")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.category, "injection")
        self.assertEqual(f.module, "recon")
        self.assertEqual(f.description, "Reflected XSS found")
        self.assertEqual(f.evidence, "<script>alert(1)</script>")
        self.assertEqual(f.asset, "example.com/login")
        self.assertEqual(f.points_deducted, 15)
        self.assertEqual(f.remediation, "Sanitize user input")
        self.assertAlmostEqual(f.dread_score, 0.7)

    def test_minimal_creation(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="test",
            description="desc",
            evidence="ev",
            asset="a.com",
        )
        self.assertEqual(f.title, "Test")


class TestFindingDefaults(unittest.TestCase):
    """Test Finding default field values."""

    def test_points_deducted_default_zero(self):
        f = Finding("t", "info", "c", "m", "d", "e", "a")
        self.assertEqual(f.points_deducted, 0)

    def test_remediation_default_empty(self):
        f = Finding("t", "info", "c", "m", "d", "e", "a")
        self.assertEqual(f.remediation, "")

    def test_dread_score_default_zero(self):
        f = Finding("t", "info", "c", "m", "d", "e", "a")
        self.assertAlmostEqual(f.dread_score, 0.0)


class TestFindingToDict(unittest.TestCase):
    """Test Finding.to_dict()."""

    def setUp(self):
        self.finding = Finding(
            title="SQL Injection",
            severity="critical",
            category="injection",
            module="auth",
            description="SQLi in search",
            evidence="' OR 1=1--",
            asset="example.com/search",
            points_deducted=25,
            remediation="Use parameterized queries",
            dread_score=0.9,
        )

    def test_to_dict_returns_dict(self):
        self.assertIsInstance(self.finding.to_dict(), dict)

    def test_to_dict_has_all_keys(self):
        d = self.finding.to_dict()
        expected_keys = {
            "title", "severity", "category", "module",
            "description", "evidence", "asset",
            "points_deducted", "remediation", "dread_score",
            "confidence", "verification_state",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_values_match_constructor(self):
        d = self.finding.to_dict()
        self.assertEqual(d["title"], "SQL Injection")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["category"], "injection")
        self.assertEqual(d["module"], "auth")
        self.assertEqual(d["description"], "SQLi in search")
        self.assertEqual(d["evidence"], "' OR 1=1--")
        self.assertEqual(d["asset"], "example.com/search")
        self.assertEqual(d["points_deducted"], 25)
        self.assertEqual(d["remediation"], "Use parameterized queries")
        self.assertAlmostEqual(d["dread_score"], 0.9)

    def test_to_dict_with_defaults(self):
        f = Finding("t", "low", "c", "m", "d", "e", "a")
        d = f.to_dict()
        self.assertEqual(d["points_deducted"], 0)
        self.assertEqual(d["remediation"], "")
        self.assertAlmostEqual(d["dread_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
