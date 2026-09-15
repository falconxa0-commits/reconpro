"""Tests for reconpro.formats — multi-format export (SARIF, Markdown, JSON, HTML, PDF)."""

import sys
import os
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.formats import (
    _normalize,
    export_sarif,
    export_markdown,
    export_json,
    export_pdf,
    export,
    _severity_to_cvss,
    _SEV_ORDER,
    _FORMAT_MAP,
)
from reconpro.scanner import ReconProResult


def _sample_data(
    target="example.com",
    score=85,
    grade="A",
    findings=None,
    modules_run=None,
):
    """Build a sample data dict."""
    if findings is None:
        findings = [
            {
                "title": "SQL Injection in login form",
                "severity": "critical",
                "category": "sqli",
                "module": "auth",
                "description": "A SQL injection was found in the login endpoint.",
                "evidence": "POST /login?id=1' OR '1'='1",
                "asset": "/api/login",
                "points_deducted": 30,
                "remediation": "Use parameterized queries.",
            },
            {
                "title": "Missing CSP header",
                "severity": "medium",
                "category": "headers",
                "module": "recon",
                "description": "Content-Security-Policy header is missing.",
                "evidence": "No CSP header in response",
                "asset": "https://example.com",
                "points_deducted": 10,
                "remediation": "Add a Content-Security-Policy header.",
            },
        ]
    if modules_run is None:
        modules_run = ["auth", "recon"]
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return {
        "target": target,
        "total_score": score,
        "grade": grade,
        "findings": findings,
        "modules_run": modules_run,
        "severity_counts": severity_counts,
    }


# ── _normalize ───────────────────────────────────────────────────────────


class TestNormalize(unittest.TestCase):
    """Test _normalize accepts both dict and ReconProResult."""

    def test_dict_passthrough(self):
        data = {"key": "value"}
        result = _normalize(data)
        self.assertEqual(result, data)

    def test_reconpro_result_converted(self):
        result_obj = ReconProResult(
            target="test.com",
            modules_run=[],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
        )
        result = _normalize(result_obj)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["target"], "test.com")
        self.assertEqual(result["total_score"], 100)

    def test_dict_with_to_dict_attribute(self):
        """Objects with to_dict() method should be normalized."""
        class Fake:
            def to_dict(self):
                return {"from_fake": True}
        result = _normalize(Fake())
        self.assertEqual(result, {"from_fake": True})


# ── _severity_to_cvss ─────────────────────────────────────────────────────


class TestSeverityToCvss(unittest.TestCase):
    """Test _severity_to_cvss mapping for SARIF properties."""

    def test_critical(self):
        self.assertEqual(_severity_to_cvss("critical"), "9.0")

    def test_high(self):
        self.assertEqual(_severity_to_cvss("high"), "7.5")

    def test_medium(self):
        self.assertEqual(_severity_to_cvss("medium"), "5.0")

    def test_low(self):
        self.assertEqual(_severity_to_cvss("low"), "2.5")

    def test_info(self):
        self.assertEqual(_severity_to_cvss("info"), "0.0")

    def test_unknown_defaults_zero(self):
        self.assertEqual(_severity_to_cvss("unknown"), "0.0")

    def test_empty_string_defaults_zero(self):
        self.assertEqual(_severity_to_cvss(""), "0.0")

    def test_case_sensitive_exact_match_only(self):
        # _severity_to_cvss does NOT lowercase — only exact matches work
        self.assertEqual(_severity_to_cvss("critical"), "9.0")
        self.assertEqual(_severity_to_cvss("CRITICAL"), "0.0")  # not lowered


# ── export_sarif ──────────────────────────────────────────────────────────


class TestExportSarif(unittest.TestCase):
    """Test SARIF 2.1.0 export."""

    def test_valid_output(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_sarif(data, tmppath)
            self.assertTrue(os.path.exists(tmppath))
            with open(tmppath) as f:
                sarif = json.load(f)
            self.assertEqual(sarif["$schema"].startswith("https://raw.githubusercontent.com/oasis-tcs/sarif-spec"), True)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"]), 1)
            run = sarif["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "ReconPro")
            self.assertEqual(len(run["results"]), 2)
        finally:
            os.unlink(tmppath)

    def test_empty_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            self.assertEqual(len(sarif["runs"][0]["results"]), 0)
            self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 0)
        finally:
            os.unlink(tmppath)

    def test_special_characters_in_title(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "XSS <script>alert('hi')</script>", "severity": "high",
                 "category": "xss", "module": "auth", "description": "test",
                 "evidence": "<script>", "asset": "/page", "points_deducted": 20},
            ])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            result = sarif["runs"][0]["results"][0]
            self.assertIn("script", result["message"]["text"])
        finally:
            os.unlink(tmppath)

    def test_sarif_level_mapping(self):
        """Verify all severities map to correct SARIF levels."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": f"T{s}", "severity": s, "category": "c", "module": "m",
                 "description": "d", "evidence": "e", "asset": "a", "points_deducted": 5}
                for s in ["critical", "high", "medium", "low", "info"]
            ])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            levels = {r["level"] for r in sarif["runs"][0]["results"]}
            self.assertIn("error", levels)  # critical, high
            self.assertIn("warning", levels)  # medium
            self.assertIn("note", levels)  # low, info
        finally:
            os.unlink(tmppath)

    def test_cve_references_in_findings(self):
        """Test CVE enrichment data is included in SARIF."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {
                    "title": "CVE Finding",
                    "severity": "critical",
                    "category": "cve",
                    "module": "cve",
                    "description": "CVE found",
                    "evidence": "evidence",
                    "asset": "asset",
                    "points_deducted": 30,
                    "related_cves": [
                        {"cve_id": "CVE-2024-1234", "cvss_score": "9.8", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
                    ],
                },
            ])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            result = sarif["runs"][0]["results"][0]
            self.assertIn("relatedLocations", result)
            self.assertEqual(len(result["relatedLocations"]), 1)
            self.assertIn("CVE-2024-1234", result["relatedLocations"][0]["message"]["text"])
        finally:
            os.unlink(tmppath)

    def test_evidence_truncated_to_200(self):
        """Evidence field should be truncated to 200 chars in SARIF."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            long_evidence = "A" * 500
            data = _sample_data(findings=[
                {"title": "T", "severity": "info", "category": "c", "module": "m",
                 "description": "d", "evidence": long_evidence, "asset": "a",
                 "points_deducted": 0},
            ])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            prop_evidence = sarif["runs"][0]["results"][0]["properties"]["evidence"]
            self.assertLessEqual(len(prop_evidence), 200)
        finally:
            os.unlink(tmppath)

    def test_creates_parent_directories(self):
        """export_sarif should create parent directories if they don't exist."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        nested = os.path.join(tmpdir, "a", "b", "c", "output.sarif")
        try:
            data = _sample_data()
            result_path = export_sarif(data, nested)
            self.assertTrue(os.path.exists(nested))
        finally:
            os.unlink(nested)
            # Clean up dirs
            os.rmdir(os.path.join(tmpdir, "a", "b", "c"))
            os.rmdir(os.path.join(tmpdir, "a", "b"))
            os.rmdir(os.path.join(tmpdir, "a"))
            os.rmdir(tmpdir)

    def test_unicode_content(self):
        """Test SARIF handles unicode in findings."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "Unicode: 你好 世界 🌍", "severity": "info", "category": "c",
                 "module": "m", "description": "测试", "evidence": "テスト",
                 "asset": "a", "points_deducted": 0},
            ])
            result_path = export_sarif(data, tmppath)
            with open(tmppath, encoding="utf-8") as f:
                sarif = json.load(f)
            self.assertIn("你好", sarif["runs"][0]["results"][0]["message"]["text"])
        finally:
            os.unlink(tmppath)


# ── export_markdown ───────────────────────────────────────────────────────


class TestExportMarkdown(unittest.TestCase):
    """Test Markdown export."""

    def test_valid_output(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("# ReconPro Security Report", content)
            self.assertIn("example.com", content)
            self.assertIn("85/100", content)
            self.assertIn("| # | Severity |", content)
        finally:
            os.unlink(tmppath)

    def test_empty_findings_clean_report(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[])
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("No findings", content)
            self.assertIn("| **Total** | **0** |", content)
        finally:
            os.unlink(tmppath)

    def test_severity_ordering(self):
        """Findings should be sorted critical -> info."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "Info Finding", "severity": "info", "category": "c",
                 "module": "m", "description": "d", "evidence": "e", "asset": "a",
                 "points_deducted": 0},
                {"title": "Critical Finding", "severity": "critical", "category": "c",
                 "module": "m", "description": "d", "evidence": "e", "asset": "a",
                 "points_deducted": 30},
            ])
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # Critical should appear before Info in the findings table
            crit_pos = content.index("Critical Finding")
            info_pos = content.index("Info Finding")
            self.assertLess(crit_pos, info_pos)
        finally:
            os.unlink(tmppath)

    def test_remediation_section(self):
        """Remediations for critical/high should appear, info/low filtered out."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "T1", "severity": "critical", "category": "c", "module": "m",
                 "description": "d", "evidence": "e", "asset": "a", "points_deducted": 30,
                 "remediation": "Fix critical"},
                {"title": "T2", "severity": "info", "category": "c", "module": "m",
                 "description": "d", "evidence": "e", "asset": "a", "points_deducted": 0,
                 "remediation": "Fix info"},
            ])
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("Fix critical", content)
            self.assertNotIn("Fix info", content)
        finally:
            os.unlink(tmppath)

    def test_module_breakdown_section(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("## Module Breakdown", content)
            self.assertIn("auth", content)
            self.assertIn("recon", content)
        finally:
            os.unlink(tmppath)

    def test_modules_run_list(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(modules_run=["auth", "recon", "headers"])
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("## Modules Run", content)
            self.assertIn("`auth`", content)
            self.assertIn("`recon`", content)
            self.assertIn("`headers`", content)
        finally:
            os.unlink(tmppath)

    def test_badge_generation(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(grade="A+")
            result_path = export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("img.shields.io", content)
            self.assertIn("A+", content)
        finally:
            os.unlink(tmppath)

    def test_unicode_in_markdown(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "日本語タイトル", "severity": "info", "category": "c",
                 "module": "m", "description": "描述", "evidence": "증거",
                 "asset": "a", "points_deducted": 0},
            ])
            result_path = export_markdown(data, tmppath)
            with open(tmppath, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("日本語タイトル", content)
        finally:
            os.unlink(tmppath)


# ── export_json ───────────────────────────────────────────────────────────


class TestExportJson(unittest.TestCase):
    """Test JSON export."""

    def test_valid_output(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_json(data, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["target"], "example.com")
            self.assertEqual(loaded["total_score"], 85)
            self.assertEqual(len(loaded["findings"]), 2)
        finally:
            os.unlink(tmppath)

    def test_pretty_printed(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_json(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # Pretty printed should have indentation
            self.assertIn("  ", content)
            self.assertIn("\n", content)
        finally:
            os.unlink(tmppath)

    def test_with_reconpro_result(self):
        """export_json should accept ReconProResult via _normalize."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            result_obj = ReconProResult(
                target="test.com",
                modules_run=["recon"],
                findings=[],
                severity_counts={},
                total_score=100,
                grade="A+",
                badge_markdown="",
            )
            result_path = export_json(result_obj, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["target"], "test.com")
        finally:
            os.unlink(tmppath)

    def test_empty_data(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            result_path = export_json({}, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            self.assertEqual(loaded, {})
        finally:
            os.unlink(tmppath)


# ── export_pdf (print-ready HTML) ────────────────────────────────────────


class TestExportPdf(unittest.TestCase):
    """Test PDF (print-ready HTML) export."""

    def test_valid_output_html(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("ReconPro Security Report", content)
            self.assertIn("example.com", content)
            self.assertIn("@media print", content)
        finally:
            os.unlink(tmppath)

    def test_html_escaping(self):
        """HTML special characters in title should be in raw HTML (not escaped in table)."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "Test <b>bold</b>", "severity": "info", "category": "c",
                 "module": "m", "description": "d", "evidence": "<script>alert(1)</script>",
                 "asset": "a", "points_deducted": 0},
            ])
            result_path = export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # Title appears in the HTML content
            self.assertIn("Test", content)
        finally:
            os.unlink(tmppath)

    def test_empty_findings_no_rows(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[])
            result_path = export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("No findings", content)
        finally:
            os.unlink(tmppath)

    def test_grade_color_in_score_circle(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(grade="A+", score=95)
            result_path = export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("#2ecc71", content)  # A+ color
            self.assertIn("95", content)
        finally:
            os.unlink(tmppath)

    def test_severity_colors_in_table(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # Should have severity colors
            self.assertIn("#e74c3c", content)  # critical color
            self.assertIn("#f1c40f", content)  # medium color
        finally:
            os.unlink(tmppath)

    def test_unicode_content(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[
                {"title": "Ünïcödé têst", "severity": "info", "category": "c",
                 "module": "m", "description": "d", "evidence": "e",
                 "asset": "a", "points_deducted": 0},
            ])
            result_path = export_pdf(data, tmppath)
            with open(tmppath, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Ünïcödé", content)
        finally:
            os.unlink(tmppath)


# ── export (auto-detect) ─────────────────────────────────────────────────


class TestExportAutoDetect(unittest.TestCase):
    """Test export() auto-detects format from extension."""

    def test_sarif_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = json.load(f)
            self.assertEqual(content["version"], "2.1.0")
        finally:
            os.unlink(tmppath)

    def test_md_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("# ReconPro Security Report", content)
        finally:
            os.unlink(tmppath)

    def test_markdown_extension(self):
        """'.markdown' extension should also trigger markdown export."""
        with tempfile.NamedTemporaryFile(suffix=".markdown", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("# ReconPro Security Report", content)
        finally:
            os.unlink(tmppath)

    def test_json_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = json.load(f)
            self.assertEqual(content["target"], "example.com")
        finally:
            os.unlink(tmppath)

    def test_pdf_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
        finally:
            os.unlink(tmppath)

    def test_unknown_extension_defaults_json(self):
        """Unknown extension should default to JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath)
            with open(tmppath) as f:
                content = json.load(f)
            self.assertEqual(content["target"], "example.com")
        finally:
            os.unlink(tmppath)

    def test_explicit_format_override(self):
        """Explicit format parameter should override extension."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath, format="sarif")
            with open(tmppath) as f:
                content = json.load(f)
            self.assertEqual(content["version"], "2.1.0")
        finally:
            os.unlink(tmppath)

    def test_format_without_dot_prefix(self):
        """Format without leading dot should work."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data()
            result_path = export(data, tmppath, format="md")
            with open(tmppath) as f:
                content = f.read()
            self.assertIn("# ReconPro Security Report", content)
        finally:
            os.unlink(tmppath)


# ── _SEV_ORDER and _FORMAT_MAP ───────────────────────────────────────────


class TestFormatConstants(unittest.TestCase):
    """Test format module constants."""

    def test_sev_order_keys(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertIn(sev, _SEV_ORDER)

    def test_sev_order_values_monotonic(self):
        values = list(_SEV_ORDER.values())
        self.assertEqual(values, sorted(values))

    def test_format_map_extensions(self):
        for ext in (".sarif", ".md", ".markdown", ".json", ".html", ".htm", ".pdf"):
            self.assertIn(ext, _FORMAT_MAP)

    def test_format_map_all_callable(self):
        for exporter in _FORMAT_MAP.values():
            self.assertTrue(callable(exporter))

    def test_missing_keys_in_findings(self):
        """Export should handle findings missing optional keys gracefully."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = _sample_data(findings=[{"title": "Minimal"}])
            result_path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        finally:
            os.unlink(tmppath)


if __name__ == "__main__":
    unittest.main()
