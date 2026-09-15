"""Stress tests for ReconPro — large inputs, boundary conditions, memory."""

import sys
import os
import time
import gc
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.utils import (
    count_severities,
    compute_score,
    compute_grade,
    sort_findings_by_severity,
    entropy,
    truncate,
    extract_host,
    validate_target,
)
from reconpro.scanner import ReconProResult
from reconpro.formats import export_sarif, export_markdown, export_json
from reconpro.constants import MAX_SCORE, MIN_SCORE


def _make_finding(severity="info", title="Test Finding", **kwargs):
    """Create a Finding with defaults."""
    return Finding(
        title=title,
        severity=severity,
        category=kwargs.get("category", "test"),
        module=kwargs.get("module", "test_mod"),
        description=kwargs.get("description", "Test description"),
        evidence=kwargs.get("evidence", "Test evidence"),
        asset=kwargs.get("asset", "test_asset"),
        points_deducted=kwargs.get("points_deducted", 5),
        remediation=kwargs.get("remediation", "Fix it"),
        dread_score=kwargs.get("dread_score", 0.5),
    )


# ── Large finding lists ───────────────────────────────────────────────────


class TestLargeFindingLists(unittest.TestCase):
    """Test score computation and severity counting with large datasets."""

    def test_1000_findings_score(self):
        findings = [_make_finding(severity="info", points_deducted=1) for _ in range(1000)]
        score = compute_score(findings)
        # 100 - 1000 = clamped to 0
        self.assertEqual(score, 0)

    def test_1000_findings_severity_count(self):
        severities = ["critical"] * 200 + ["high"] * 300 + ["medium"] * 200 + ["low"] * 200 + ["info"] * 100
        findings = [_make_finding(severity=s) for s in severities]
        counts = count_severities(findings)
        self.assertEqual(counts["critical"], 200)
        self.assertEqual(counts["high"], 300)
        self.assertEqual(counts["medium"], 200)
        self.assertEqual(counts["low"], 200)
        self.assertEqual(counts["info"], 100)

    def test_5000_findings_sort(self):
        """Sorting 5000 findings should complete and be correct."""
        severities = ["info", "low", "medium", "high", "critical"]
        findings = [_make_finding(severity=severities[i % 5], title=f"F{i}")
                    for i in range(5000)]
        start = time.time()
        sorted_f = sort_findings_by_severity(findings)
        elapsed = time.time() - start
        self.assertLess(elapsed, 10.0, "Sorting 5000 findings took too long")
        # First finding should be critical
        self.assertEqual(sorted_f[0].severity, "critical")

    def test_10000_findings_count(self):
        """count_severities with 10000 findings."""
        findings = [_make_finding(severity="medium") for _ in range(10000)]
        counts = count_severities(findings)
        self.assertEqual(counts["medium"], 10000)

    def test_10000_findings_grade(self):
        """Grade computation with massive deductions."""
        findings = [_make_finding(severity="critical", points_deducted=1) for _ in range(10000)]
        score = compute_score(findings)
        grade = compute_grade(score)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")

    def test_1000_findings_to_dict(self):
        """Convert 1000 findings to dict and back."""
        findings = [_make_finding(title=f"F{i}", severity="info") for i in range(1000)]
        dicts = [f.to_dict() for f in findings]
        self.assertEqual(len(dicts), 1000)
        self.assertEqual(dicts[500]["title"], "F500")


# ── Long target strings ──────────────────────────────────────────────────


class TestLongTargetStrings(unittest.TestCase):
    """Test with very long target strings."""

    def test_near_max_length_host(self):
        # 250 chars + ".com" (4) = 254 chars; 254 > 253, so rejected
        host = "a" * 250 + ".com"
        valid, msg = validate_target(host)
        self.assertFalse(valid)

    def test_at_max_length_host(self):
        # 249 chars + ".com" (4) = 253 chars; exactly at limit
        host = "a" * 249 + ".com"
        valid, msg = validate_target(host)
        self.assertTrue(valid)

    def test_over_max_length_host(self):
        host = "a" * 260 + ".com"  # 264 chars
        valid, msg = validate_target(host)
        self.assertFalse(valid)
        self.assertIn("253", msg)

    def test_extract_host_long(self):
        long_host = "a" * 200 + ".example.com"
        result = extract_host(long_host)
        self.assertEqual(result, long_host)

    def test_normalize_long_url(self):
        long_domain = "a" * 100 + ".example.com"
        result = extract_host(f"https://{long_domain}/path/to/resource")
        self.assertEqual(result, long_domain)


# ── Many modules ─────────────────────────────────────────────────────────


class TestManyModules(unittest.TestCase):
    """Test with many modules in scan result."""

    def test_26_modules_in_result(self):
        """ReconProResult with 26 module entries."""
        module_results = {}
        modules_run = []
        findings = []
        for i in range(26):
            mod_name = f"module_{i}"
            modules_run.append(mod_name)
            module_results[mod_name] = {
                "findings": [
                    {"severity": "info", "title": f"F{j}"} for j in range(3)
                ]
            }
            for f_dict in module_results[mod_name]["findings"]:
                f_dict["module"] = mod_name
                findings.append(f_dict)
        result = ReconProResult(
            target="example.com",
            modules_run=modules_run,
            findings=findings,
            severity_counts={"info": 78},
            total_score=50,
            grade="C",
            badge_markdown="",
            module_results=module_results,
        )
        self.assertEqual(len(result.modules_run), 26)
        self.assertEqual(len(result.module_results), 26)
        d = result.to_dict()
        self.assertEqual(len(d["modules_run"]), 26)


# ── Deep nesting ──────────────────────────────────────────────────────────


class TestDeepNesting(unittest.TestCase):
    """Test deep nesting in to_dict() calls."""

    def test_finding_to_dict_preserves_types(self):
        f = _make_finding(
            severity="critical",
            title="Test",
            dread_score=0.95,
            points_deducted=30,
        )
        d = f.to_dict()
        self.assertIsInstance(d["title"], str)
        self.assertIsInstance(d["severity"], str)
        self.assertIsInstance(d["points_deducted"], int)
        self.assertIsInstance(d["dread_score"], float)

    def test_result_to_dict_deep(self):
        findings = [
            {
                "title": "Nested",
                "severity": "high",
                "category": "c",
                "module": "m",
                "description": "desc",
                "evidence": {"nested": {"deep": {"value": "test"}}},
                "asset": "a",
                "points_deducted": 20,
                "remediation": "Fix",
            }
        ]
        result = ReconProResult(
            target="test.com",
            modules_run=["recon"],
            findings=findings,
            severity_counts={"high": 1},
            total_score=80,
            grade="A",
            badge_markdown="",
        )
        d = result.to_dict()
        self.assertIsInstance(d["findings"], list)
        self.assertEqual(len(d["findings"]), 1)
        # Evidence is a nested dict — should be preserved
        ev = d["findings"][0].get("evidence", {})
        self.assertIsInstance(ev, dict)

    def test_nested_module_results(self):
        module_results = {
            "recon": {
                "findings": [{"severity": "info"}],
                "stats": {"requests": 100, "time": 2.5},
                "metadata": {"version": "1.0", "options": {"deep": True}},
            }
        }
        result = ReconProResult(
            target="test.com",
            modules_run=["recon"],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
            module_results=module_results,
        )
        d = result.to_dict()
        self.assertIn("stats", d["module_results"]["recon"])
        self.assertIn("metadata", d["module_results"]["recon"])


# ── Memory: large object creation ────────────────────────────────────────


class TestMemoryStress(unittest.TestCase):
    """Test creating large numbers of objects doesn't cause issues."""

    def test_create_10000_finding_objects(self):
        """Create 10000 Finding objects, verify they're valid."""
        findings = []
        for i in range(10000):
            f = _make_finding(title=f"F{i}", severity="info")
            findings.append(f)
        self.assertEqual(len(findings), 10000)
        # Verify first and last are correct
        self.assertEqual(findings[0].title, "F0")
        self.assertEqual(findings[-1].title, "F9999")
        # Force GC to verify no crashes
        gc.collect()

    def test_10000_finding_objects_to_dict(self):
        """Convert 10000 Finding objects to dicts, verify no leaks."""
        findings = [_make_finding(title=f"F{i}") for i in range(10000)]
        dicts = [f.to_dict() for f in findings]
        self.assertEqual(len(dicts), 10000)
        total_mem_approx = sum(len(str(d)) for d in dicts[:100])
        # Each dict should be non-empty
        for d in dicts[:10]:
            self.assertIn("title", d)
            self.assertIn("severity", d)
        gc.collect()


# ── Large evidence strings ────────────────────────────────────────────────


class TestLargeEvidenceStrings(unittest.TestCase):
    """Test handling of large evidence/body strings."""

    def test_evidence_16kb(self):
        """16KB evidence string should be handled by truncate."""
        evidence = "A" * 16384
        truncated = truncate(evidence)
        self.assertEqual(len(truncated), 16384)

    def test_evidence_32kb(self):
        """32KB evidence string should be truncated to 16KB."""
        evidence = "B" * 32768
        truncated = truncate(evidence)
        self.assertEqual(len(truncated), 16384)
        self.assertTrue(truncated.endswith("B"))

    def test_evidence_over_16kb_in_finding(self):
        """Finding with 16KB+ evidence should be stored."""
        evidence = "X" * 20000
        f = _make_finding(evidence=evidence)
        # Finding stores full evidence
        self.assertEqual(len(f.evidence), 20000)
        # But truncate should handle it
        self.assertEqual(len(truncate(f.evidence)), 16384)

    def test_export_sarif_with_large_evidence(self):
        """SARIF export with large evidence should truncate."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 50,
                "grade": "C",
                "findings": [
                    {
                        "title": "Large evidence",
                        "severity": "info",
                        "category": "c",
                        "module": "m",
                        "description": "d",
                        "evidence": "E" * 10000,
                        "asset": "a",
                        "points_deducted": 0,
                    }
                ],
                "modules_run": ["m"],
                "severity_counts": {"info": 1},
            }
            path = export_sarif(data, tmppath)
            import json
            with open(tmppath) as f:
                sarif = json.load(f)
            ev = sarif["runs"][0]["results"][0]["properties"]["evidence"]
            self.assertLessEqual(len(ev), 200)
        finally:
            os.unlink(tmppath)


# ── Concurrent-like access ──────────────────────────────────────────────


class TestConcurrentAccess(unittest.TestCase):
    """Test thread-safe patterns (mocked)."""

    def test_multiple_count_severities_calls(self):
        """Multiple concurrent-like calls to count_severities."""
        findings = [_make_finding(severity=["critical", "high", "medium", "low", "info"][i % 5])
                    for i in range(1000)]
        results = [count_severities(findings) for _ in range(100)]
        for r in results:
            self.assertEqual(r["critical"], 200)
            self.assertEqual(r["high"], 200)
            self.assertEqual(r["medium"], 200)
            self.assertEqual(r["low"], 200)
            self.assertEqual(r["info"], 200)

    def test_multiple_compute_score_calls(self):
        """Multiple compute_score calls should be consistent."""
        findings = [_make_finding(severity="high", points_deducted=5) for _ in range(10)]
        results = [compute_score(findings) for _ in range(100)]
        self.assertTrue(all(r == results[0] for r in results))
        self.assertEqual(results[0], 50)

    def test_multiple_sort_calls_stable(self):
        """Multiple sort calls should produce same results."""
        findings = [_make_finding(title=f"F{i}", severity="info") for i in range(100)]
        results = [sort_findings_by_severity(findings) for _ in range(10)]
        for r in results:
            titles = [f.title for f in r]
            self.assertEqual(titles, [f"F{i}" for i in range(100)])


if __name__ == "__main__":
    unittest.main()
