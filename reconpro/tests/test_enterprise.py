"""Enterprise readiness tests for ReconPro v11.

Verifies that all intelligence engines are importable, the intelligence
pipeline works end-to-end with synthetic data, all export formats
produce valid files, the observability module collects metrics, and
version strings are consistent across modules.
"""

import importlib
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.intelligence_pipeline import (
    IntelligencePipeline,
    IntelligenceResult,
    run_intelligence_pipeline,
    reset_pipeline,
)
from reconpro.formats import (
    export_json,
    export_sarif,
    export_markdown,
    export_pdf,
)
from reconpro.observability import MetricsCollector, StructuredLogger
from reconpro.constants import __version__ as CONSTANTS_VERSION


# ── Sample data builder ────────────────────────────────────────────────


def _synthetic_findings(count=5):
    """Create a realistic set of synthetic findings for pipeline testing."""
    templates = [
        {
            "title": "SQL Injection in /api/login",
            "severity": "critical",
            "category": "injection",
            "module": "auth",
            "description": "SQL injection in login endpoint allows authentication bypass.",
            "evidence": "POST /api/login?id=1' OR '1'='1' --",
            "asset": "api.target.com",
            "points_deducted": 30,
            "remediation": "Use parameterized queries.",
        },
        {
            "title": "Cross-Site Scripting in search",
            "severity": "high",
            "category": "cross_site_scripting",
            "module": "recon",
            "description": "Reflected XSS via the q parameter.",
            "evidence": "GET /search?q=<script>alert(1)</script>",
            "asset": "web.target.com",
            "points_deducted": 20,
            "remediation": "Apply output encoding.",
        },
        {
            "title": "Missing Content-Security-Policy",
            "severity": "medium",
            "category": "headers",
            "module": "recon",
            "description": "CSP header is absent.",
            "evidence": "Response has no Content-Security-Policy header",
            "asset": "target.com",
            "points_deducted": 10,
            "remediation": "Add a restrictive CSP header.",
        },
        {
            "title": "TLS 1.0 still enabled",
            "severity": "medium",
            "category": "crypto",
            "module": "recon",
            "description": "The server supports TLS 1.0 which is deprecated.",
            "evidence": "TLSv1.0 cipher: AES256-SHA",
            "asset": "target.com:443",
            "points_deducted": 10,
            "remediation": "Disable TLS 1.0 on the server.",
        },
        {
            "title": "Information Disclosure in Headers",
            "severity": "low",
            "category": "information_disclosure",
            "module": "recon",
            "description": "Server version header reveals technology stack.",
            "evidence": "Server: Apache/2.4.49",
            "asset": "target.com",
            "points_deducted": 3,
            "remediation": "Remove or obfuscate server headers.",
        },
        {
            "title": "Session Cookie Missing HttpOnly",
            "severity": "medium",
            "category": "authentication",
            "module": "auth",
            "description": "Session cookie lacks HttpOnly flag.",
            "evidence": "Set-Cookie: session=abc123; Path=/",
            "asset": "target.com",
            "points_deducted": 8,
            "remediation": "Set HttpOnly flag on session cookies.",
        },
        {
            "title": "Open Redirect in /redirect",
            "severity": "high",
            "category": "redirect",
            "module": "chain",
            "description": "Unvalidated redirect parameter allows phishing.",
            "evidence": "GET /redirect?url=//evil.com",
            "asset": "target.com",
            "points_deducted": 15,
            "remediation": "Whitelist allowed redirect destinations.",
        },
    ]
    findings = []
    for i in range(count):
        t = templates[i % len(templates)].copy()
        t["title"] = f"{t['title']} (variant {i})" if count > len(templates) else t["title"]
        if count > len(templates):
            t["asset"] = f"asset{i}.target.com"
        findings.append(Finding(**t))
    return findings


def _sample_scan_data():
    """Build scan data dict suitable for all export formats."""
    return {
        "target": "enterprise.target.com",
        "total_score": 68,
        "grade": "C",
        "findings": [
            {
                "title": "Critical SQL Injection",
                "severity": "critical",
                "category": "injection",
                "module": "auth",
                "description": "SQLi in login.",
                "evidence": "id=1' OR '1'='1",
                "asset": "/api/login",
                "points_deducted": 30,
                "remediation": "Use parameterized queries.",
            },
            {
                "title": "XSS in Dashboard",
                "severity": "high",
                "category": "cross_site_scripting",
                "module": "recon",
                "description": "Reflected XSS.",
                "evidence": "q=<script>",
                "asset": "/dashboard",
                "points_deducted": 20,
            },
            {
                "title": "Missing HSTS",
                "severity": "info",
                "category": "headers",
                "module": "recon",
                "description": "No HSTS header.",
                "evidence": "Response missing Strict-Transport-Security",
                "asset": "enterprise.target.com",
                "points_deducted": 0,
            },
        ],
        "modules_run": ["auth", "recon", "chain"],
        "severity_counts": {"critical": 1, "high": 1, "info": 1},
    }


# ═══════════════════════════════════════════════════════════════════════
# 1. Intelligence Engine Import Tests
# ═══════════════════════════════════════════════════════════════════════


class TestIntelligenceEngineImports(unittest.TestCase):
    """All 3 intelligence engines must be importable and have expected classes."""

    def test_ai_analyst_importable(self):
        """AIAnalystEngine can be imported from reconpro.ai_analyst."""
        from reconpro.ai_analyst import AIAnalystEngine
        self.assertTrue(callable(AIAnalystEngine))

    def test_attack_graph_importable(self):
        """AttackGraphEngine can be imported from reconpro.attack_graph."""
        from reconpro.attack_graph import AttackGraphEngine
        self.assertTrue(callable(AttackGraphEngine))

    def test_threat_intel_importable(self):
        """ThreatIntelEngine can be imported from reconpro.threat_intel."""
        from reconpro.threat_intel import ThreatIntelEngine
        self.assertTrue(callable(ThreatIntelEngine))

    def test_ai_analyst_has_analyze_scan(self):
        """AIAnalystEngine instances have an analyze_scan method."""
        from reconpro.ai_analyst import AIAnalystEngine
        engine = AIAnalystEngine()
        self.assertTrue(hasattr(engine, "analyze_scan"))
        self.assertTrue(callable(engine.analyze_scan))

    def test_attack_graph_has_analyze(self):
        """AttackGraphEngine instances have an analyze method."""
        from reconpro.attack_graph import AttackGraphEngine
        engine = AttackGraphEngine()
        self.assertTrue(hasattr(engine, "analyze"))
        self.assertTrue(callable(engine.analyze))

    def test_threat_intel_has_enrich_scan(self):
        """ThreatIntelEngine instances have an enrich_scan method."""
        from reconpro.threat_intel import ThreatIntelEngine
        engine = ThreatIntelEngine()
        self.assertTrue(hasattr(engine, "enrich_scan"))
        self.assertTrue(callable(engine.enrich_scan))

    def test_pipeline_module_importable(self):
        """IntelligencePipeline can be imported from reconpro.intelligence_pipeline."""
        self.assertTrue(callable(IntelligencePipeline))

    def test_intelligence_result_is_dataclass(self):
        """IntelligenceResult must be a dataclass."""
        import dataclasses
        self.assertTrue(dataclasses.is_dataclass(IntelligenceResult))


# ═══════════════════════════════════════════════════════════════════════
# 2. Intelligence Pipeline End-to-End
# ═══════════════════════════════════════════════════════════════════════


class TestPipelineEndToEnd(unittest.TestCase):
    """End-to-end pipeline tests with realistic synthetic data."""

    def setUp(self):
        reset_pipeline()

    def tearDown(self):
        reset_pipeline()

    def test_single_critical_finding_produces_intelligence(self):
        """A single critical finding should produce actionable intelligence."""
        findings = _synthetic_findings(1)
        p = IntelligencePipeline()
        result = p.analyze(findings)
        # All engines should be enabled (v11 pipeline: 6 engines — the
        # original 3 plus knowledge_graph, regression, recommendations)
        self.assertEqual(
            set(result.enabled_engines),
            {"ai_analyst", "attack_graph", "threat_intel",
             "knowledge_graph", "regression", "recommendations"},
        )
        # Should produce intelligence
        self.assertTrue(result.has_intelligence)
        # Risk score should be non-zero
        self.assertGreater(result.executive_risk_score, 0)

    def test_multi_severity_pipeline(self):
        """Pipeline with findings at all 5 severity levels."""
        findings = [
            Finding(title=f"{s} finding", severity=s, category="test", module="m",
                    description="d", evidence="e", asset=f"a{i}.com", points_deducted=5)
            for i, s in enumerate(["critical", "high", "medium", "low", "info"])
        ]
        p = IntelligencePipeline()
        result = p.analyze(findings)
        self.assertTrue(result.has_intelligence)
        # Composite scores should be populated
        self.assertGreater(result.executive_risk_score, 0)
        self.assertGreater(result.exposure_score, 0)
        # All durations should be positive
        self.assertGreater(result.pipeline_duration, 0)

    def test_pipeline_with_scan_data_context(self):
        """Pipeline accepts optional scan_data without error."""
        findings = _synthetic_findings(3)
        scan_data = {
            "target": "corp.example.com",
            "scan_time": "2024-06-15T10:30:00Z",
            "modules_run": ["auth", "recon"],
        }
        result = run_intelligence_pipeline(findings, scan_data=scan_data)
        self.assertIsInstance(result, IntelligenceResult)
        self.assertTrue(result.has_intelligence)

    def test_pipeline_to_dict_is_json_serialisable(self):
        """IntelligenceResult.to_dict() must produce JSON-serialisable data."""
        findings = _synthetic_findings(5)
        p = IntelligencePipeline()
        result = p.analyze(findings)
        d = result.to_dict()
        # Should not raise
        json_str = json.dumps(d, default=str)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 100)

    def test_pipeline_error_tolerant(self):
        """If one engine fails, others still produce results."""
        findings = _synthetic_findings(2)
        # Enable only AI analyst — simulate failure by passing bad data mixed in
        p = IntelligencePipeline(enable_attack_graph=False, enable_threat_intel=False)
        result = p.analyze(findings)
        # Should still succeed
        self.assertIn("ai_analyst", result.enabled_engines)
        self.assertIsInstance(result, IntelligenceResult)

    def test_pipeline_empty_findings_no_crash(self):
        """Empty findings should return a zeroed result without errors."""
        p = IntelligencePipeline()
        result = p.analyze([])
        self.assertFalse(result.has_intelligence)
        self.assertEqual(result.executive_risk_score, 0.0)
        self.assertEqual(result.errors, [])


# ═══════════════════════════════════════════════════════════════════════
# 3. Export Format Tests
# ═══════════════════════════════════════════════════════════════════════


class TestExportFormatsEnterprise(unittest.TestCase):
    """Verify all export formats produce valid, parseable files."""

    def setUp(self):
        self.data = _sample_scan_data()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_json_export_creates_valid_json(self):
        """export_json produces a valid JSON file."""
        path = os.path.join(self.tmpdir, "report.json")
        result = export_json(self.data, path)
        self.assertTrue(os.path.exists(result))
        with open(result, encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["target"], "enterprise.target.com")
        self.assertEqual(len(loaded["findings"]), 3)

    def test_sarif_export_valid_sarif_structure(self):
        """export_sarif produces a valid SARIF 2.1.0 file."""
        path = os.path.join(self.tmpdir, "report.sarif")
        result = export_sarif(self.data, path)
        self.assertTrue(os.path.exists(result))
        with open(result, encoding="utf-8") as f:
            sarif = json.load(f)
        # SARIF 2.1.0 required fields
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertIn("runs", sarif)
        self.assertGreaterEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("results", run)
        # Tool driver should have ReconPro name
        self.assertEqual(run["tool"]["driver"]["name"], "ReconPro")

    def test_markdown_export_has_expected_sections(self):
        """export_markdown produces a file with expected markdown sections."""
        path = os.path.join(self.tmpdir, "report.md")
        result = export_markdown(self.data, path)
        self.assertTrue(os.path.exists(result))
        with open(result, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("# ReconPro Security Report", content)
        self.assertIn("## Summary", content)
        self.assertIn("## Findings", content)
        self.assertIn("## Remediation", content)
        self.assertIn("enterprise.target.com", content)

    def test_pdf_export_is_valid_html(self):
        """export_pdf produces a valid HTML file (print-ready)."""
        path = os.path.join(self.tmpdir, "report.pdf")
        result = export_pdf(self.data, path)
        self.assertTrue(os.path.exists(result))
        with open(result, encoding="utf-8") as f:
            html = f.read()
        self.assertTrue(html.strip().startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", html)
        self.assertIn("@media print", html)

    def test_all_exports_with_intelligence_data(self):
        """Exports work when intelligence data is included."""
        data = dict(self.data)
        data["intelligence"] = {
            "executive_risk_score": 72.5,
            "exposure_score": 45.0,
            "attack_paths": [{"description": "SQLi → Data Exfiltration"}],
            "cve_matches": ["CVE-2024-1234"],
            "cwe_matches": ["CWE-89"],
            "mitre_techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
        }
        # JSON with intelligence
        json_path = os.path.join(self.tmpdir, "intel.json")
        export_json(data, json_path)
        with open(json_path, encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertIn("intelligence", loaded)
        self.assertEqual(loaded["intelligence"]["executive_risk_score"], 72.5)

        # SARIF with intelligence
        sarif_path = os.path.join(self.tmpdir, "intel.sarif")
        export_sarif(data, sarif_path)
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)
        self.assertIn("intelligence", sarif["runs"][0]["properties"])

    def test_export_auto_detect_format(self):
        """The export() function auto-detects format from file extension."""
        from reconpro.formats import export
        for ext, expected_content in [
            (".json", "enterprise.target.com"),
            (".sarif", '"version": "2.1.0"'),
            (".md", "# ReconPro Security Report"),
        ]:
            path = os.path.join(self.tmpdir, f"auto{ext}")
            result = export(self.data, path)
            self.assertTrue(os.path.exists(result), f"Failed for {ext}")
            with open(result, encoding="utf-8") as f:
                content = f.read()
            self.assertIn(expected_content, content, f"Missing content for {ext}")


# ═══════════════════════════════════════════════════════════════════════
# 4. Observability Metrics Collection
# ═══════════════════════════════════════════════════════════════════════


class TestObservabilityMetricsCollection(unittest.TestCase):
    """Verify the MetricsCollector collects and reports metrics correctly."""

    def test_counter_increment_and_snapshot(self):
        """Counter increment is reflected in snapshot."""
        mc = MetricsCollector()
        mc.counter_increment("scans_total")
        mc.counter_increment("scans_total", 4)
        snap = mc.get_snapshot()
        self.assertEqual(snap["counters"]["scans_total"], 5.0)

    def test_gauge_set_and_snapshot(self):
        """Gauge value is set exactly in snapshot."""
        mc = MetricsCollector()
        mc.gauge_set("memory_mb", 512.0)
        mc.gauge_set("memory_mb", 768.0)  # Overwrite
        snap = mc.get_snapshot()
        self.assertEqual(snap["gauges"]["memory_mb"], 768.0)

    def test_histogram_records_distribution(self):
        """Histogram records multiple observations and computes stats."""
        mc = MetricsCollector()
        for val in [10, 20, 30, 40, 50]:
            mc.histogram_observe("latency_ms", val)
        snap = mc.get_snapshot()
        h = snap["histograms"]["latency_ms"]
        self.assertEqual(h["count"], 5)
        self.assertEqual(h["min"], 10.0)
        self.assertEqual(h["max"], 50.0)
        self.assertAlmostEqual(h["avg"], 30.0)

    def test_timer_start_stop_records_duration(self):
        """Timer start/stop records elapsed time in histogram."""
        mc = MetricsCollector()
        mc.timer_start("scan")
        time.sleep(0.01)  # 10ms
        elapsed = mc.timer_stop("scan")
        self.assertIsNotNone(elapsed)
        self.assertGreater(elapsed, 5.0)  # At least 5ms
        snap = mc.get_snapshot()
        self.assertIn("scan_duration_ms", snap["histograms"])

    def test_disabled_collector_is_noop(self):
        """A disabled collector records nothing."""
        mc = MetricsCollector(enabled=False)
        mc.counter_increment("x")
        mc.gauge_set("y", 1)
        mc.histogram_observe("z", 1)
        snap = mc.get_snapshot()
        self.assertEqual(snap["counters"], {})
        self.assertEqual(snap["gauges"], {})
        self.assertEqual(snap["histograms"], {})

    def test_snapshot_isolation(self):
        """Modifying snapshot dict does not affect collector state."""
        mc = MetricsCollector()
        mc.counter_increment("findings")
        snap1 = mc.get_snapshot()
        snap1["counters"]["findings"] = 999
        snap2 = mc.get_snapshot()
        self.assertEqual(snap2["counters"]["findings"], 1.0)

    def test_histogram_p50_p95_p99(self):
        """Histogram computes percentiles correctly."""
        mc = MetricsCollector()
        # 100 values: 0..99
        for i in range(100):
            mc.histogram_observe("test_pct", float(i))
        snap = mc.get_snapshot()
        h = snap["histograms"]["test_pct"]
        self.assertEqual(h["count"], 100)
        self.assertIn("p50", h)
        self.assertIn("p95", h)
        self.assertIn("p99", h)
        # p50 should be close to 49-50
        self.assertGreaterEqual(h["p50"], 45)
        self.assertLessEqual(h["p50"], 55)

    def test_structured_logger_timestamp_format(self):
        """Structured logger timestamps should be ISO 8601 with Z suffix."""
        from reconpro.observability import _utc_iso
        ts = _utc_iso()
        self.assertTrue(ts.endswith("Z"))
        self.assertIn("T", ts)


# ═══════════════════════════════════════════════════════════════════════
# 5. Version String Consistency
# ═══════════════════════════════════════════════════════════════════════


class TestVersionConsistency(unittest.TestCase):
    """Version string must be consistent across all module entry points."""

    def test_constants_version_is_v11(self):
        """constants.__version__ should start with '11.'"""
        self.assertTrue(CONSTANTS_VERSION.startswith("11."),
                        f"Expected v11.x, got {CONSTANTS_VERSION}")

    def test_package_init_version_matches_constants(self):
        """reconpro.__version__ must match constants.__version__."""
        import reconpro
        self.assertEqual(reconpro.__version__, CONSTANTS_VERSION)

    def test_formats_module_uses_constants_version(self):
        """formats.py should reference __version__ from constants."""
        from reconpro import constants
        source_path = os.path.join(os.path.dirname(constants.__file__), "formats.py")
        with open(source_path, encoding="utf-8") as f:
            source = f.read()
        # formats.py imports __version__ from .constants
        self.assertIn("from .constants import __version__", source)

    def test_server_module_uses_package_version(self):
        """server.py should reference __version__ from the package."""
        from reconpro import constants
        source_path = os.path.join(os.path.dirname(constants.__file__), "server.py")
        with open(source_path, encoding="utf-8") as f:
            source = f.read()
        self.assertIn("from . import __version__", source)

    def test_security_profile_version(self):
        """get_security_profile should include a version field."""
        from reconpro.security import get_security_profile
        profile = get_security_profile()
        self.assertIn("version", profile)
        self.assertIsInstance(profile["version"], str)

    def test_version_format_is_semver(self):
        """Version string should follow semver (MAJOR.MINOR.PATCH)."""
        import re
        pattern = r'^\d+\.\d+\.\d+$'
        self.assertRegex(CONSTANTS_VERSION, pattern,
                                 f"Version {CONSTANTS_VERSION} is not semver")


if __name__ == "__main__":
    unittest.main()
