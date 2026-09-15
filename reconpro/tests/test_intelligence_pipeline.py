"""Tests for the Intelligence Pipeline — the post-scan orchestration layer."""

import sys
import os
import unittest
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.intelligence_pipeline import (
    IntelligencePipeline,
    IntelligenceResult,
    run_intelligence_pipeline,
    reset_pipeline,
)


def _make_finding(
    title="Test Finding",
    severity="medium",
    category="general",
    module="test",
    description="A test finding",
    evidence="evidence here",
    asset="test_asset",
    points_deducted=5,
    remediation="Fix it",
    dread_score=5.0,
):
    return Finding(
        title=title, severity=severity, category=category, module=module,
        description=description, evidence=evidence, asset=asset,
        points_deducted=points_deducted, remediation=remediation,
        dread_score=dread_score,
    )


class TestIntelligenceResult(unittest.TestCase):
    """Tests for IntelligenceResult dataclass."""

    def test_default_values(self):
        r = IntelligenceResult()
        self.assertEqual(r.executive_risk_score, 0.0)
        self.assertEqual(r.exposure_score, 0.0)
        self.assertEqual(r.pipeline_duration, 0.0)
        self.assertEqual(r.errors, [])
        self.assertEqual(r.enabled_engines, [])
        self.assertFalse(r.has_intelligence)

    def test_has_intelligence_with_attack_paths(self):
        r = IntelligenceResult(attack_paths=[{"id": "test"}])
        self.assertTrue(r.has_intelligence)

    def test_has_intelligence_with_cve_matches(self):
        r = IntelligenceResult(cve_matches=["CVE-2024-0001"])
        self.assertTrue(r.has_intelligence)

    def test_has_intelligence_with_mitre(self):
        r = IntelligenceResult(mitre_techniques=[{"technique": "T1059"}])
        self.assertTrue(r.has_intelligence)

    def test_risk_levels(self):
        r_critical = IntelligenceResult(executive_risk_score=85)
        self.assertEqual(r_critical.risk_level, "CRITICAL")
        r_high = IntelligenceResult(executive_risk_score=65)
        self.assertEqual(r_high.risk_level, "HIGH")
        r_medium = IntelligenceResult(executive_risk_score=45)
        self.assertEqual(r_medium.risk_level, "MEDIUM")
        r_low = IntelligenceResult(executive_risk_score=25)
        self.assertEqual(r_low.risk_level, "LOW")
        r_minimal = IntelligenceResult(executive_risk_score=10)
        self.assertEqual(r_minimal.risk_level, "MINIMAL")

    def test_to_dict_keys(self):
        r = IntelligenceResult(
            executive_risk_score=42.5,
            attack_paths=[{"id": "p1"}],
            cve_matches=["CVE-2024-1234"],
        )
        d = r.to_dict()
        self.assertIn("executive_risk_score", d)
        self.assertIn("attack_paths", d)
        self.assertIn("cve_matches", d)
        self.assertIn("risk_level", d)
        self.assertEqual(d["executive_risk_score"], 42.5)
        self.assertIn("pipeline_duration_ms", d)
        self.assertIn("enabled_engines", d)

    def test_to_dict_rounds_scores(self):
        r = IntelligenceResult(executive_risk_score=42.56789)
        d = r.to_dict()
        self.assertEqual(d["executive_risk_score"], 42.6)


class TestIntelligencePipelineEmpty(unittest.TestCase):
    """Pipeline behavior with empty/null inputs."""

    def setUp(self):
        reset_pipeline()

    def test_empty_findings(self):
        p = IntelligencePipeline()
        result = p.analyze([])
        self.assertIsInstance(result, IntelligenceResult)
        self.assertFalse(result.has_intelligence)
        self.assertEqual(result.executive_risk_score, 0.0)
        self.assertEqual(result.pipeline_duration, 0.0)

    def test_none_scan_data(self):
        p = IntelligencePipeline()
        findings = [_make_finding()]
        result = p.analyze(findings, scan_data=None)
        self.assertIsInstance(result, IntelligenceResult)

    def test_disabled_all_engines(self):
        p = IntelligencePipeline(
            enable_ai_analyst=False,
            enable_attack_graph=False,
            enable_threat_intel=False,
            enable_knowledge_graph=False,
            enable_regression=False,
            enable_recommendations=False,
        )
        findings = [_make_finding()]
        result = p.analyze(findings)
        self.assertEqual(result.enabled_engines, [])
        self.assertFalse(result.has_intelligence)

    def test_non_dict_non_finding_items(self):
        p = IntelligencePipeline()
        # Strings and ints should be skipped gracefully
        result = p.analyze(["string", 42, None])
        self.assertIsInstance(result, IntelligenceResult)


class TestIntelligencePipelineAIAnalyst(unittest.TestCase):
    """AI Analyst integration through pipeline."""

    def setUp(self):
        reset_pipeline()

    def test_single_finding_classification(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        findings = [_make_finding(title="SQL Injection", severity="critical", category="injection")]
        result = p.analyze(findings)
        self.assertIn("ai_analyst", result.enabled_engines)
        self.assertIsInstance(result.ai_analysis, dict)
        # Should classify the finding
        self.assertIsInstance(result.classification_summary, dict)

    def test_multiple_findings_correlation(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        findings = [
            _make_finding(title="SQLi", severity="critical", category="injection", asset="api.example.com"),
            _make_finding(title="Broken Auth", severity="high", category="authentication", asset="api.example.com"),
            _make_finding(title="XSS", severity="medium", category="cross_site_scripting", asset="web.example.com"),
        ]
        result = p.analyze(findings)
        self.assertGreater(len(result.extended_findings), 0)

    def test_attack_path_detection(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        findings = [
            _make_finding(title="Info Disclosure", severity="low", category="information_disclosure", asset="target.com"),
            _make_finding(title="SQL Injection", severity="critical", category="injection", asset="target.com"),
            _make_finding(title="Privilege Escalation", severity="high", category="authorization", asset="target.com"),
        ]
        result = p.analyze(findings)
        # Attack paths should be detected for chained vulnerabilities
        self.assertIsInstance(result.attack_paths, list)

    def test_composite_scores_populated(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        findings = [
            _make_finding(severity="critical", category="injection", asset="api.test.com"),
            _make_finding(severity="high", category="authentication", asset="web.test.com"),
        ]
        result = p.analyze(findings)
        self.assertGreater(result.executive_risk_score, 0)
        self.assertGreater(result.exposure_score, 0)
        self.assertGreater(result.mission_impact_score, 0)
        self.assertGreater(result.infrastructure_health_score, 0)

    def test_composite_scores_bounded(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        # Many critical findings
        findings = [_make_finding(severity="critical", category="injection", asset=f"a{i}.com") for i in range(50)]
        result = p.analyze(findings)
        self.assertLessEqual(result.executive_risk_score, 100)
        self.assertLessEqual(result.exposure_score, 100)
        self.assertLessEqual(result.mission_impact_score, 100)

    def test_ai_duration_measured(self):
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        findings = [_make_finding()]
        result = p.analyze(findings)
        self.assertGreater(result.ai_duration, 0)
        self.assertEqual(result.graph_duration, 0)
        self.assertEqual(result.intel_duration, 0)


class TestIntelligencePipelineAttackGraph(unittest.TestCase):
    """Attack Graph integration through pipeline."""

    def setUp(self):
        reset_pipeline()

    def test_graph_built(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_threat_intel=False)
        findings = [
            _make_finding(title="Vuln1", severity="critical", asset="server1"),
            _make_finding(title="Vuln2", severity="high", asset="server2"),
        ]
        result = p.analyze(findings)
        self.assertIn("attack_graph", result.enabled_engines)
        self.assertIsInstance(result.attack_graph, dict)

    def test_attack_chains_detected(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_threat_intel=False)
        findings = [
            _make_finding(title="Info Leak", severity="low", category="information_disclosure", asset="target.com"),
            _make_finding(title="RCE", severity="critical", category="remote_code_execution", asset="target.com"),
            _make_finding(title="Privesc", severity="high", category="authorization", asset="target.com"),
        ]
        result = p.analyze(findings)
        self.assertIsInstance(result.attack_chains, list)

    def test_graph_duration_measured(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_threat_intel=False)
        findings = [_make_finding()]
        result = p.analyze(findings)
        self.assertGreater(result.graph_duration, 0)
        self.assertEqual(result.ai_duration, 0)

    def test_kill_chain_mapping(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_threat_intel=False)
        findings = [_make_finding(severity="critical", category="injection")]
        result = p.analyze(findings)
        self.assertIsInstance(result.kill_chain_mapping, dict)


class TestIntelligencePipelineThreatIntel(unittest.TestCase):
    """Threat Intelligence integration through pipeline."""

    def setUp(self):
        reset_pipeline()

    def test_enrichment_runs(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_attack_graph=False)
        findings = [_make_finding(title="XSS Vulnerability", category="cross_site_scripting")]
        result = p.analyze(findings)
        self.assertIn("threat_intel", result.enabled_engines)

    def test_cwe_matches(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_attack_graph=False)
        findings = [_make_finding(title="SQL Injection", category="injection")]
        result = p.analyze(findings)
        self.assertIsInstance(result.cwe_matches, list)

    def test_mitre_techniques(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_attack_graph=False)
        findings = [_make_finding(title="Command Injection", category="injection")]
        result = p.analyze(findings)
        self.assertIsInstance(result.mitre_techniques, list)

    def test_intel_duration_measured(self):
        p = IntelligencePipeline(enable_ai_analyst=False, enable_attack_graph=False)
        findings = [_make_finding()]
        result = p.analyze(findings)
        self.assertGreater(result.intel_duration, 0)
        self.assertEqual(result.ai_duration, 0)
        self.assertEqual(result.graph_duration, 0)


class TestIntelligencePipelineFull(unittest.TestCase):
    """Full pipeline with all three engines enabled."""

    def setUp(self):
        reset_pipeline()

    def test_all_engines_enabled(self):
        p = IntelligencePipeline()
        findings = [
            _make_finding(title="SQLi", severity="critical", category="injection", asset="api.target.com"),
            _make_finding(title="XSS", severity="high", category="cross_site_scripting", asset="web.target.com"),
            _make_finding(title="Broken Auth", severity="medium", category="authentication", asset="api.target.com"),
        ]
        result = p.analyze(findings)
        self.assertIn("ai_analyst", result.enabled_engines)
        self.assertIn("attack_graph", result.enabled_engines)
        self.assertIn("threat_intel", result.enabled_engines)
        self.assertGreater(result.pipeline_duration, 0)
        # At least some intelligence should be produced
        self.assertTrue(result.has_intelligence)

    def test_pipeline_duration_exceeds_individual(self):
        p = IntelligencePipeline()
        findings = [_make_finding()] * 10
        result = p.analyze(findings)
        # Pipeline duration should be >= sum of individual durations
        individual_sum = result.ai_duration + result.graph_duration + result.intel_duration
        self.assertGreaterEqual(result.pipeline_duration, individual_sum * 0.9)  # 90% tolerance for timing

    def test_to_dict_complete(self):
        p = IntelligencePipeline()
        findings = [_make_finding(severity="critical")]
        result = p.analyze(findings)
        d = result.to_dict()
        # Verify all expected keys exist
        expected_keys = [
            "executive_risk_score", "exposure_score", "mission_impact_score",
            "infrastructure_health_score", "threat_confidence_index",
            "pipeline_duration_ms", "enabled_engines", "errors",
            "ai_analysis", "attack_paths", "attack_chains",
            "cve_matches", "cwe_matches", "mitre_techniques",
        ]
        for key in expected_keys:
            self.assertIn(key, d, f"Missing key: {key}")

    def test_large_finding_set(self):
        """Test with 100 findings to check performance."""
        p = IntelligencePipeline()
        findings = [
            _make_finding(
                title=f"Finding {i}",
                severity=["critical", "high", "medium", "low"][i % 4],
                category=["injection", "authentication", "xss", "info_disclosure"][i % 4],
                asset=f"asset{i}.example.com",
            )
            for i in range(100)
        ]
        t0 = time.monotonic()
        result = p.analyze(findings)
        elapsed = time.monotonic() - t0
        # Should complete in reasonable time (< 10 seconds for 100 findings)
        self.assertLess(elapsed, 10.0, f"Pipeline took {elapsed:.2f}s for 100 findings")
        self.assertTrue(result.has_intelligence)


class TestConvenienceFunction(unittest.TestCase):
    """Tests for the module-level convenience function."""

    def setUp(self):
        reset_pipeline()

    def test_run_intelligence_pipeline(self):
        findings = [_make_finding(severity="critical")]
        result = run_intelligence_pipeline(findings)
        self.assertIsInstance(result, IntelligenceResult)

    def test_reset_pipeline(self):
        findings = [_make_finding()]
        r1 = run_intelligence_pipeline(findings)
        reset_pipeline()
        r2 = run_intelligence_pipeline(findings, enable_ai_analyst=False)
        self.assertNotIn("ai_analyst", r2.enabled_engines)
        reset_pipeline()

    def test_global_state_reuse(self):
        """Verify that the global pipeline instance is reused."""
        findings = [_make_finding()]
        r1 = run_intelligence_pipeline(findings)
        r2 = run_intelligence_pipeline(findings)
        # Same settings should produce same engine list
        self.assertEqual(r1.enabled_engines, r2.enabled_engines)


if __name__ == "__main__":
    unittest.main()
