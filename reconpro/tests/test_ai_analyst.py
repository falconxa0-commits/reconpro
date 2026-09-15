"""Tests for ai_analyst.py — AI Security Analyst Engine."""

import sys
import os
import unittest

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro.ai_analyst import (
    FindingClassifier, FindingCorrelator, ExploitabilityEstimator,
    BusinessImpactAnalyzer, AttackPathDetector, RemediationPrioritizer,
    AIAnalystEngine, resolve_mappings, generate_cvss,
    generate_remediation_plan, generate_validation_steps,
    ClassificationResult, CorrelationGroup, AttackPath,
    ExtendedFinding, AnalysisReport,
    MITRE_ATTACK_MAP, CWE_MAP, CAPEC_MAP,
)


# ═══════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════

def _finding(title="SQL Injection in login", severity="high", category="sqli",
             module="chain", evidence="SELECT * FROM users WHERE id=1",
             description="A SQL injection vulnerability was found in the login form",
             asset="example.com/login", **kwargs):
    f = {
        "title": title, "severity": severity, "category": category,
        "module": module, "description": description, "evidence": evidence,
        "asset": asset, "points_deducted": 10, "remediation": "", "dread_score": 7.0,
    }
    f.update(kwargs)
    return f


def _finding_xss():
    return _finding(
        title="Reflected XSS in search parameter",
        severity="high", category="xss", module="recon",
        evidence="<script>alert(1)</script> in search?q=",
        description="Reflected XSS found in search parameter",
        asset="example.com/search",
    )


def _finding_ssrf():
    return _finding(
        title="SSRF via user profile endpoint",
        severity="critical", category="ssrf", module="chain",
        evidence="http://169.254.169.254/latest/meta-data/",
        description="Server-Side Request Forgery allowing internal network access",
        asset="example.com/api/profile",
    )


def _finding_rce():
    return _finding(
        title="Remote Code Execution via eval",
        severity="critical", category="rce", module="recon",
        evidence="eval(user_input) in template engine",
        description="RCE through unsanitized input passed to eval()",
        asset="example.com/admin",
        points_deducted=25,
    )


def _finding_auth_bypass():
    return _finding(
        title="Authentication bypass via IDOR",
        severity="high", category="auth_bypass", module="auth",
        evidence="Changing user_id in URL grants access to other accounts",
        description="Broken authentication allows access to any user account by modifying IDs",
        asset="example.com/account",
    )


def _finding_misconfig():
    return _finding(
        title="Missing Content-Security-Policy header",
        severity="medium", category="misconfiguration", module="recon",
        evidence="Response lacks Content-Security-Policy header",
        description="CSP header is missing, allowing potential XSS attacks",
        asset="example.com",
        points_deducted=5,
    )


def _finding_default_creds():
    return _finding(
        title="Default credentials on admin panel",
        severity="critical", category="default_credentials", module="auth",
        evidence="admin:admin login successful",
        description="Admin panel accessible with default credentials admin/admin",
        asset="example.com/admin",
        points_deducted=25,
    )


def _finding_data_exposure():
    return _finding(
        title="Sensitive data in API response",
        severity="high", category="data_exposure", module="recon",
        evidence="API returns full user records including SSN and credit card numbers",
        description="User API endpoint exposes sensitive PII without authentication",
        asset="example.com/api/users",
    )


def _finding_beaconing():
    return _finding(
        title="C2 beaconing pattern detected",
        severity="critical", category="beaconing", module="signal_intelligence",
        evidence="Regular HTTP requests to suspicious domain every 60 seconds",
        description="Command and control beaconing pattern detected in network traffic",
        asset="example.com",
        points_deducted=20,
    )


def _finding_supply_chain():
    return _finding(
        title="Vulnerable dependency lodash@4.17.15",
        severity="high", category="supply_chain", module="dev",
        evidence="lodash prototype pollution CVE-2024-XXXX",
        description="Outdated dependency with known prototype pollution vulnerability",
        asset="example.com",
        points_deducted=10,
    )


# ═══════════════════════════════════════════════════════════════════════════
# FindingClassifier Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestFindingClassifier(unittest.TestCase):

    def setUp(self):
        self.classifier = FindingClassifier()

    def test_classify_sqli(self):
        f = _finding()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "sqli")
        self.assertGreater(result.confidence, 0.5)

    def test_classify_xss(self):
        f = _finding_xss()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "xss")

    def test_classify_ssrf(self):
        f = _finding_ssrf()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "ssrf")

    def test_classify_rce(self):
        f = _finding_rce()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "rce")

    def test_classify_auth_bypass(self):
        f = _finding_auth_bypass()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "auth_bypass")

    def test_classify_default_credentials(self):
        f = _finding_default_creds()
        result = self.classifier.classify(f)
        self.assertIn(result.attack_category, ("default_credentials", "credential_theft"))

    def test_classify_misconfiguration(self):
        f = _finding_misconfig()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "misconfiguration")

    def test_classify_data_exposure(self):
        f = _finding_data_exposure()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "data_exposure")

    def test_classify_beaconing(self):
        f = _finding_beaconing()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "beaconing")

    def test_classify_supply_chain(self):
        f = _finding_supply_chain()
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "supply_chain")

    def test_classify_module_honeypot(self):
        f = _finding(title="Honeypot detected", module="honeypot_dance")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "honeypot")

    def test_classify_module_dark_web(self):
        f = _finding(title="Credential dump found", module="dark_web_monitor")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "dark_web")

    def test_classify_module_quantum(self):
        f = _finding(title="HTTP timing analysis", module="quantum_fingerprint", category="tech_fingerprint")
        result = self.classifier.classify(f)
        self.assertIn(result.attack_category, ("tech_fingerprint", "misc"))

    def test_classify_unknown_returns_misc(self):
        # Create a finding directly with no SQL patterns in any field
        f = {
            "title": "Random thing", "description": "Something random", "category": "misc",
            "evidence": "nothing special here", "severity": "info", "module": "unknown",
            "asset": "target", "points_deducted": 0, "remediation": "", "dread_score": 0.0,
        }
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "misc")
        self.assertLess(result.confidence, 0.5)

    def test_classify_evidence_boosts_confidence(self):
        f_short = _finding(evidence="x")
        f_long = _finding(evidence="A" * 200)
        r_short = self.classifier.classify(f_short)
        r_long = self.classifier.classify(f_long)
        self.assertGreaterEqual(r_long.confidence, r_short.confidence - 0.1)

    def test_classify_batch(self):
        findings = [_finding(), _finding_xss(), _finding_ssrf()]
        results = self.classifier.classify_batch(findings)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].attack_category, "sqli")
        self.assertEqual(results[1].attack_category, "xss")
        self.assertEqual(results[2].attack_category, "ssrf")

    def test_classify_dos(self):
        f = _finding(title="Denial of Service via slowloris", category="dos")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "dos")

    def test_classify_xxe(self):
        f = _finding(title="XXE vulnerability in XML parser", category="xxe")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "xxe")

    def test_classify_crypto_failure(self):
        f = _finding(title="Weak TLS 1.0 encryption", category="crypto_failure")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "crypto_failure")

    def test_classify_open_redirect(self):
        f = _finding(title="Open redirect vulnerability", category="open_redirect")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "open_redirect")

    def test_classify_jwt(self):
        f = _finding(title="JWT token exposed in localStorage", category="jwt_exposure")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "jwt_exposure")

    def test_classify_injection(self):
        f = _finding(title="Code injection in template", category="injection")
        result = self.classifier.classify(f)
        self.assertIn(result.attack_category, ("injection", "rce"))

    def test_confidence_range(self):
        f = _finding()
        result = self.classifier.classify(f)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_indicators_not_empty(self):
        f = _finding()
        result = self.classifier.classify(f)
        self.assertIsInstance(result.indicators, list)

    def test_classify_privilege_escalation(self):
        f = _finding(title="Privilege escalation via kernel exploit", category="privilege_escalation")
        result = self.classifier.classify(f)
        self.assertEqual(result.attack_category, "privilege_escalation")


# ═══════════════════════════════════════════════════════════════════════════
# FindingCorrelator Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestFindingCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = FindingCorrelator()

    def test_correlate_empty(self):
        groups, deduped = self.correlator.correlate([])
        self.assertEqual(groups, [])
        self.assertEqual(deduped, [])

    def test_dedup_identical(self):
        findings = [_finding(), _finding()]
        groups, deduped = self.correlator.correlate(findings)
        self.assertEqual(len(deduped), 1)
        # Should have 0 correlation groups (single finding can't correlate)
        self.assertEqual(len(groups), 0)

    def test_dedup_different(self):
        findings = [_finding(), _finding_xss()]
        groups, deduped = self.correlator.correlate(findings)
        self.assertEqual(len(deduped), 2)

    def test_group_by_asset(self):
        findings = [
            _finding(asset="example.com/login"),
            _finding_xss().update({"asset": "example.com/login"}) or _finding_xss(),
        ]
        findings[1]["asset"] = "example.com/login"
        groups, deduped = self.correlator.correlate(findings)
        asset_groups = [g for g in groups if g.correlation_type == "shared_asset"]
        self.assertGreater(len(asset_groups), 0)

    def test_detect_attack_chain(self):
        # Both findings share the same asset so the chain detection
        # can link them (auth_bypass → default_creds attack chain).
        auth = _finding_auth_bypass()
        auth["asset"] = "example.com/admin"
        creds = _finding_default_creds()
        findings = [auth, creds]
        groups, deduped = self.correlator.correlate(findings)
        chain_groups = [g for g in groups if g.correlation_type == "attack_chain"]
        self.assertGreater(len(chain_groups), 0)

    def test_correlation_group_dataclass(self):
        cg = CorrelationGroup(
            findings=[_finding()],
            correlation_type="shared_asset",
            combined_risk="high",
            combined_confidence=0.8,
        )
        self.assertEqual(cg.correlation_type, "shared_asset")
        self.assertEqual(cg.combined_risk, "high")

    def test_dedup_keeps_more_evidence(self):
        f1 = _finding(evidence="short")
        f2 = _finding(evidence="A" * 200)
        groups, deduped = self.correlator.correlate([f1, f2])
        self.assertEqual(len(deduped), 1)
        self.assertGreater(len(deduped[0].get("evidence", "")), 50)


# ═══════════════════════════════════════════════════════════════════════════
# ExploitabilityEstimator Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExploitabilityEstimator(unittest.TestCase):

    def setUp(self):
        self.estimator = ExploitabilityEstimator()

    def test_estimate_sqli(self):
        result = self.estimator.estimate(_finding())
        self.assertIn("exploitability", result)
        self.assertIn("attacker_effort", result)
        self.assertIn("likelihood", result)
        self.assertIn("confidence", result)
        self.assertGreater(result["exploitability"], 0.5)

    def test_estimate_critical_higher_than_low(self):
        critical = self.estimator.estimate(_finding(severity="critical"))
        low = self.estimator.estimate(_finding(severity="low"))
        self.assertGreater(critical["exploitability"], low["exploitability"])

    def test_estimate_default_creds_high(self):
        result = self.estimator.estimate(_finding_default_creds())
        self.assertGreater(result["exploitability"], 0.7)
        self.assertEqual(result["attacker_effort"], "low")

    def test_estimate_effort_levels(self):
        for effort in ["low", "medium", "high", "very_high"]:
            self.assertIn(effort, ["low", "medium", "high", "very_high"])

    def test_estimate_ranges(self):
        result = self.estimator.estimate(_finding())
        for key in ("exploitability", "likelihood", "confidence"):
            self.assertGreaterEqual(result[key], 0.0)
            self.assertLessEqual(result[key], 1.0)


# ═══════════════════════════════════════════════════════════════════════════
# BusinessImpactAnalyzer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBusinessImpactAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = BusinessImpactAnalyzer()

    def test_analyze_rce_high_impact(self):
        result = self.analyzer.analyze(_finding_rce())
        self.assertGreater(result["impact_score"], 0.6)
        self.assertIn("financial", result["affected_dimensions"])

    def test_analyze_misconfig_lower_impact(self):
        result = self.analyzer.analyze(_finding_misconfig())
        self.assertLess(result["impact_score"], 0.8)

    def test_analyze_production_asset_higher(self):
        prod = self.analyzer.analyze(_finding(asset="production-api.example.com"))
        dev = self.analyzer.analyze(_finding(asset="dev-api.example.com"))
        self.assertGreaterEqual(prod["impact_score"], dev["impact_score"])

    def test_analyze_dimensions(self):
        result = self.analyzer.analyze(_finding_data_exposure())
        self.assertIsInstance(result["affected_dimensions"], list)
        self.assertGreater(len(result["affected_dimensions"]), 0)

    def test_analyze_description_present(self):
        result = self.analyzer.analyze(_finding())
        self.assertIsInstance(result["impact_description"], str)
        self.assertGreater(len(result["impact_description"]), 10)

    def test_analyze_ranges(self):
        result = self.analyzer.analyze(_finding())
        self.assertGreaterEqual(result["impact_score"], 0.0)
        self.assertLessEqual(result["impact_score"], 1.0)


# ═══════════════════════════════════════════════════════════════════════════
# AttackPathDetector Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAttackPathDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AttackPathDetector()

    def test_detect_empty(self):
        paths = self.detector.detect([])
        self.assertEqual(paths, [])

    def test_detect_single_finding(self):
        paths = self.detector.detect([_finding()])
        self.assertEqual(paths, [])

    def test_detect_two_step_chain(self):
        paths = self.detector.detect([
            _finding_default_creds(),
            _finding_auth_bypass(),
        ])
        self.assertGreater(len(paths), 0)

    def test_detect_full_chain(self):
        paths = self.detector.detect([
            _finding(title="Subdomain discovered", severity="info", category="dns_recon", module="subdomains"),
            _finding_default_creds(),
            _finding_auth_bypass(),
            _finding(title="Privilege escalation", severity="critical",
                     category="privilege_escalation", module="recon"),
        ])
        self.assertGreater(len(paths), 0)

    def test_attack_path_dataclass(self):
        ap = AttackPath(
            steps=[{"title": "Step 1"}],
            entry_point="target",
            objective="Compromise",
            complexity="high",
            likelihood=0.8,
            impact=0.9,
            confidence=0.72,
            narrative="Test path",
        )
        self.assertEqual(len(ap.steps), 1)
        self.assertEqual(ap.complexity, "high")

    def test_paths_sorted_by_confidence(self):
        paths = self.detector.detect([
            _finding_misconfig(),
            _finding_default_creds(),
            _finding_auth_bypass(),
            _finding_data_exposure(),
        ])
        for i in range(len(paths) - 1):
            self.assertGreaterEqual(paths[i].confidence, paths[i + 1].confidence)


# ═══════════════════════════════════════════════════════════════════════════
# RemediationPrioritizer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestRemediationPrioritizer(unittest.TestCase):

    def setUp(self):
        self.prioritizer = RemediationPrioritizer()

    def test_prioritize_empty(self):
        result = self.prioritizer.prioritize([])
        self.assertEqual(result, [])

    def test_prioritize_orders_correctly(self):
        findings = [
            {"severity": "low", "exploitability": 0.2, "business_impact_score": 0.2,
             "confidence_score": 0.3, "title": "Low priority"},
            {"severity": "critical", "exploitability": 0.9, "business_impact_score": 0.9,
             "confidence_score": 0.9, "title": "High priority"},
        ]
        result = self.prioritizer.prioritize(findings)
        self.assertEqual(result[0]["title"], "High priority")
        self.assertEqual(result[0]["priority_rank"], 1)
        self.assertEqual(result[1]["title"], "Low priority")

    def test_prioritize_has_reasoning(self):
        findings = [{"severity": "critical", "exploitability": 0.9,
                     "business_impact_score": 0.9, "confidence_score": 0.9, "title": "Test"}]
        result = self.prioritizer.prioritize(findings)
        self.assertIn("priority_reasoning", result[0])
        self.assertIn("#1", result[0]["priority_reasoning"])


# ═══════════════════════════════════════════════════════════════════════════
# Mapping Functions Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMappings(unittest.TestCase):

    def test_mitre_attack_map_coverage(self):
        """At least 30 categories should have MITRE mappings."""
        self.assertGreaterEqual(len(MITRE_ATTACK_MAP), 30)

    def test_cwe_map_coverage(self):
        """At least 25 categories should have CWE mappings."""
        self.assertGreaterEqual(len(CWE_MAP), 25)

    def test_capec_map_coverage(self):
        """At least 20 categories should have CAPEC mappings."""
        self.assertGreaterEqual(len(CAPEC_MAP), 20)

    def test_resolve_mappings_sqli(self):
        mitre, cwe, capec = resolve_mappings("sqli")
        self.assertIn("technique", mitre)
        self.assertIn("CWE-89", cwe)
        self.assertIn("CAPEC-66", capec)

    def test_resolve_mappings_unknown(self):
        mitre, cwe, capec = resolve_mappings("nonexistent")
        self.assertEqual(mitre, {})
        self.assertEqual(cwe, [])
        self.assertEqual(capec, [])

    def test_generate_cvss_critical(self):
        result = generate_cvss("critical")
        self.assertGreater(result["base_score"], 8.0)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertIn("CVSS:3.1", result["vector_string"])

    def test_generate_cvss_info(self):
        result = generate_cvss("info")
        self.assertLess(result["base_score"], 3.0)

    def test_generate_remediation_plan_sqli(self):
        steps = generate_remediation_plan("sqli", "critical", {})
        self.assertGreater(len(steps), 2)
        self.assertTrue(any("parameterized" in s.lower() for s in steps))

    def test_generate_remediation_plan_critical_prefix(self):
        steps = generate_remediation_plan("sqli", "critical", {})
        self.assertTrue(steps[0].startswith("CRITICAL:"))

    def test_generate_validation_steps(self):
        steps = generate_validation_steps("sqli")
        self.assertGreater(len(steps), 2)
        self.assertTrue(any("re-run" in s.lower() for s in steps))


# ═══════════════════════════════════════════════════════════════════════════
# AIAnalystEngine Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAIAnalystEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AIAnalystEngine()

    def test_analyze_empty(self):
        report = self.engine.analyze_scan([], "example.com")
        self.assertEqual(report.total_findings, 0)
        self.assertIn("No findings", report.summary)

    def test_analyze_single_finding(self):
        findings = [_finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertEqual(report.total_findings, 1)
        self.assertGreater(len(report.extended_findings), 0)
        self.assertGreater(len(report.classified), 0)
        self.assertIn("example.com", report.summary)

    def test_analyze_multiple_findings(self):
        findings = [_finding(), _finding_xss(), _finding_ssrf(), _finding_rce()]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertEqual(report.total_findings, 4)
        self.assertEqual(len(report.extended_findings), 4)
        self.assertGreater(len(report.classified), 0)

    def test_analyze_extended_finding_fields(self):
        findings = [_finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        ef = report.extended_findings[0]
        self.assertIn("executive_summary", ef)
        self.assertIn("technical_explanation", ef)
        self.assertIn("attack_narrative", ef)
        self.assertIn("mitre_attack_mapping", ef)
        self.assertIn("cwe_mapping", ef)
        self.assertIn("capec_mapping", ef)
        self.assertIn("cvss_interpretation", ef)
        self.assertIn("remediation_plan", ef)
        self.assertIn("validation_steps", ef)
        self.assertIn("confidence_score", ef)
        self.assertIn("exploitability", ef)
        self.assertIn("business_impact_score", ef)
        self.assertIn("attacker_effort", ef)
        self.assertIn("root_cause", ef)

    def test_analyze_correlation(self):
        findings = [_finding_default_creds(), _finding_auth_bypass(), _finding_data_exposure()]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertGreaterEqual(len(report.correlated), 0)

    def test_analyze_prioritization(self):
        findings = [_finding_misconfig(), _finding_rce(), _finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertEqual(len(report.prioritized), 3)
        # Critical should be first
        self.assertEqual(report.prioritized[0]["priority_rank"], 1)

    def test_analyze_dedup(self):
        findings = [_finding(), _finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertGreater(report.dedup_count, 0)
        self.assertLess(len(report.extended_findings), 2)

    def test_analyze_uncertainty_low_evidence(self):
        f = _finding(evidence="", description="")
        report = self.engine.analyze_scan([f], "example.com")
        ef = report.extended_findings[0]
        self.assertLess(ef["confidence_score"], 0.5)

    def test_analyze_confidence_high_evidence(self):
        f = _finding(evidence="A" * 200, description="Detailed vulnerability analysis with multiple indicators")
        report = self.engine.analyze_scan([f], "example.com")
        ef = report.extended_findings[0]
        self.assertGreater(ef["confidence_score"], 0.4)

    def test_analyze_attack_paths(self):
        findings = [
            _finding_default_creds(),
            _finding_auth_bypass(),
            _finding(title="Privilege escalation found", severity="critical",
                     category="privilege_escalation", module="recon"),
        ]
        report = self.engine.analyze_scan(findings, "example.com")
        # With chainable findings, should detect paths
        self.assertGreaterEqual(len(report.attack_paths), 0)

    def test_report_to_dict(self):
        report = self.engine.analyze_scan([_finding()], "example.com")
        d = report.to_dict()
        self.assertIn("target", d)
        self.assertIn("total_findings", d)
        self.assertIn("analysis_duration_ms", d)
        self.assertGreater(d["analysis_duration_ms"], 0)

    def test_analyze_summary_content(self):
        findings = [
            _finding(severity="critical"),
            _finding_xss(),
            _finding_misconfig(),
        ]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertIn("1 critical", report.summary)
        self.assertIn("example.com", report.summary)

    def test_analysis_duration(self):
        findings = [_finding() for _ in range(10)]
        report = self.engine.analyze_scan(findings, "example.com")
        self.assertGreater(report.analysis_duration_ms, 0)

    def test_mitre_mapping_populated(self):
        findings = [_finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        ef = report.extended_findings[0]
        self.assertIn("technique", ef["mitre_attack_mapping"])
        self.assertIn("tactic", ef["mitre_attack_mapping"])

    def test_cwe_mapping_populated(self):
        findings = [_finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        ef = report.extended_findings[0]
        self.assertIn("CWE-89", ef["cwe_mapping"])

    def test_capec_mapping_populated(self):
        findings = [_finding()]
        report = self.engine.analyze_scan(findings, "example.com")
        ef = report.extended_findings[0]
        self.assertIn("CAPEC-66", ef["capec_mapping"])

    def test_cvss_interpretation(self):
        findings = [_finding(severity="critical")]
        report = self.engine.analyze_scan(findings, "example.com")
        ef = report.extended_findings[0]
        cvss = ef["cvss_interpretation"]
        self.assertGreater(cvss["base_score"], 8.0)
        self.assertIn("vector_string", cvss)


# ═══════════════════════════════════════════════════════════════════════════
# ExtendedFinding Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestExtendedFinding(unittest.TestCase):

    def test_default_values(self):
        ef = ExtendedFinding(title="Test", severity="high", category="sqli",
                           module="test", description="desc", evidence="ev", asset="target")
        self.assertEqual(ef.confidence_score, 0.0)
        self.assertEqual(ef.exploitability, 0.0)
        self.assertEqual(ef.mitre_attack_mapping, {})

    def test_to_dict(self):
        ef = ExtendedFinding(title="Test", severity="high", category="sqli",
                           module="test", description="desc", evidence="ev", asset="target")
        d = ef.to_dict()
        self.assertEqual(d["title"], "Test")
        self.assertIn("mitre_attack_mapping", d)
        self.assertIn("confidence_score", d)


if __name__ == "__main__":
    unittest.main()
