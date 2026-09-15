"""End-to-end pipeline tests: Scan → Intelligence → Engineering.

Verifies the full data flow from scan findings through intelligence
pipeline analysis and engineering field integration. All tests use
unittest.mock to avoid network calls.
"""

import unittest
from unittest.mock import patch, MagicMock

from reconpro.scanner import ReconProResult
from reconpro.intelligence_pipeline import IntelligencePipeline, IntelligenceResult


class TestIntelligencePipelineEndToEnd(unittest.TestCase):
    """Verify intelligence pipeline processes findings correctly."""

    def test_empty_findings_returns_zero_result(self):
        pipeline = IntelligencePipeline()
        result = pipeline.analyze([])
        self.assertIsInstance(result, IntelligenceResult)
        self.assertEqual(result.executive_risk_score, 0.0)
        self.assertFalse(result.has_intelligence)

    def test_valid_findings_produce_intelligence(self):
        pipeline = IntelligencePipeline()
        findings = [
            {
                "title": "SQL Injection",
                "severity": "critical",
                "category": "injection",
                "module": "test",
                "description": "SQL injection found",
                "evidence": "SELECT * FROM",
                "asset": "example.com/api",
                "points_deducted": 20,
            },
            {
                "title": "XSS",
                "severity": "high",
                "category": "xss",
                "module": "test",
                "description": "Cross-site scripting",
                "evidence": "<script>",
                "asset": "example.com/page",
                "points_deducted": 15,
            },
        ]
        result = pipeline.analyze(findings)
        self.assertTrue(result.has_intelligence)
        self.assertGreater(result.executive_risk_score, 0.0)
        self.assertIn("ai_analyst", result.enabled_engines)

    def test_result_serialization(self):
        pipeline = IntelligencePipeline()
        result = pipeline.analyze([{
            "title": "Test",
            "severity": "medium",
            "category": "test",
            "module": "test",
            "description": "Test finding",
            "evidence": "",
            "asset": "test.com",
            "points_deducted": 5,
        }])
        d = result.to_dict()
        self.assertIn("executive_risk_score", d)
        self.assertIn("risk_level", d)
        self.assertIn("enabled_engines", d)
        self.assertIn("attack_graph", d)
        self.assertIn("cve_matches", d)

    def test_attack_graph_engine_enabled(self):
        """Verify the attack_graph engine is reported when enabled."""
        pipeline = IntelligencePipeline(enable_attack_graph=True)
        findings = [{
            "title": "Open Port",
            "severity": "high",
            "category": "network",
            "module": "test",
            "description": "Port 22 open",
            "evidence": "22/tcp",
            "asset": "example.com",
            "points_deducted": 10,
        }]
        result = pipeline.analyze(findings)
        self.assertIn("attack_graph", result.enabled_engines)

    def test_attack_graph_disabled(self):
        """Verify the attack_graph engine is omitted when disabled."""
        pipeline = IntelligencePipeline(enable_attack_graph=False)
        result = pipeline.analyze([{
            "title": "Test",
            "severity": "low",
            "category": "test",
            "module": "test",
            "description": "Test",
            "evidence": "",
            "asset": "test",
            "points_deducted": 2,
        }])
        self.assertNotIn("attack_graph", result.enabled_engines)

    def test_pipeline_with_all_engines(self):
        pipeline = IntelligencePipeline(
            enable_ai_analyst=True,
            enable_attack_graph=True,
            enable_threat_intel=True,
        )
        findings = [{
            "title": "Critical Vuln",
            "severity": "critical",
            "category": "vulnerability",
            "module": "test",
            "description": "Critical vulnerability",
            "evidence": "CVE-2024-0001",
            "asset": "target.com",
            "points_deducted": 25,
        }]
        result = pipeline.analyze(findings)
        self.assertTrue(result.has_intelligence)
        self.assertGreater(len(result.enabled_engines), 0)

    def test_global_pipeline_function(self):
        from reconpro.intelligence_pipeline import run_intelligence_pipeline, reset_pipeline
        reset_pipeline()
        result = run_intelligence_pipeline([{
            "title": "Test",
            "severity": "medium",
            "category": "test",
            "module": "test",
            "description": "Test",
            "evidence": "",
            "asset": "test",
            "points_deducted": 5,
        }])
        self.assertIsInstance(result, IntelligenceResult)
        reset_pipeline()


class TestReconProResultEngineering(unittest.TestCase):
    """Verify ReconProResult supports engineering field."""

    def test_engineering_field_default_none(self):
        result = ReconProResult(
            target="test.com",
            modules_run=[],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
        )
        self.assertIsNone(result.engineering)

    def test_engineering_field_in_to_dict(self):
        result = ReconProResult(
            target="test.com",
            modules_run=[],
            findings=[],
            severity_counts={},
            total_score=100,
            grade="A+",
            badge_markdown="",
        )
        result.engineering = {"overall_status": "pass", "stages_run": 14}
        d = result.to_dict()
        self.assertIn("engineering", d)
        self.assertEqual(d["engineering"]["overall_status"], "pass")


class TestScannerExceptionIsolation(unittest.TestCase):
    """Verify one failed module doesn't stop the scan."""

    @patch("reconpro.scanner.get_module_runner")
    @patch("reconpro.scanner.validate_target")
    @patch("reconpro.scanner.normalize_base_url")
    @patch("reconpro.scanner.extract_host")
    def test_failed_module_doesnt_stop_scan(self, mock_host, mock_url, mock_validate, mock_runner):
        mock_validate.return_value = (True, "")
        mock_host.return_value = "example.com"
        mock_url.return_value = "https://example.com"

        from reconpro.http_layer import Finding

        # First module succeeds
        def good_runner(*args, **kwargs):
            return [Finding(
                title="Good finding", severity="info", category="test",
                module="good", description="", evidence="", asset="test", points_deducted=0,
            )]

        # Second module fails
        def bad_runner(*args, **kwargs):
            raise RuntimeError("Module crashed!")

        mock_runner.side_effect = [good_runner, bad_runner, good_runner]

        # Inject fake modules into the registry so scan() accepts them
        fake_registry = {
            "good":  {"name": "GOOD",  "runner": good_runner,  "color": "white"},
            "bad":   {"name": "BAD",   "runner": bad_runner,   "color": "white"},
            "good2": {"name": "GOOD2", "runner": good_runner,  "color": "white"},
        }

        with patch("reconpro.scanner.MODULE_REGISTRY", fake_registry):
            from reconpro.scanner import scan as scan_func
            result = scan_func("example.com", modules=["good", "bad", "good2"])

        # Should still have findings from good modules
        self.assertGreater(len(result.findings), 0)
        # Bad module should have error recorded
        self.assertIn("bad", result.module_results)
        self.assertIn("error", result.module_results["bad"])


if __name__ == "__main__":
    unittest.main()
