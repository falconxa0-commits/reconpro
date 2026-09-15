"""Tests for threat_intel.py — Threat Intelligence Center."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro.threat_intel import (
    ThreatIntelEngine, ThreatRecord, EnrichedFinding, ThreatIntelReport,
    _CVE_KNOWN_PATTERNS, _CISA_KEV_CVE_LIST, _CWE_DATABASE, _CAPEC_DATABASE,
    _MITRE_TECHNIQUES, _OWASP_TOP10, _CATEGORY_TO_CWE, _CATEGORY_TO_CAPEC,
    _CATEGORY_TO_MITRE, _quick_classify,
)


def _finding(title="SQL Injection", severity="high", category="sqli",
             evidence="SELECT * FROM users WHERE id=1", description="Vulnerability found",
             asset="example.com", **kw):
    f = {"title": title, "severity": severity, "category": category,
         "description": description, "evidence": evidence, "asset": asset,
         "points_deducted": 10, "dread_score": 7.0}
    f.update(kw)
    return f


class TestThreatIntelDatabases(unittest.TestCase):

    def test_cve_database_not_empty(self):
        self.assertGreater(len(_CVE_KNOWN_PATTERNS), 0)

    def test_cisa_kev_not_empty(self):
        self.assertGreater(len(_CISA_KEV_CVE_LIST), 0)

    def test_cwe_database_not_empty(self):
        self.assertGreater(len(_CWE_DATABASE), 25)

    def test_capec_database_not_empty(self):
        self.assertGreater(len(_CAPEC_DATABASE), 20)

    def test_mitre_database_not_empty(self):
        self.assertGreater(len(_MITRE_TECHNIQUES), 30)

    def test_owasp_top10(self):
        self.assertEqual(len(_OWASP_TOP10), 10)

    def test_category_to_cwe(self):
        self.assertGreater(len(_CATEGORY_TO_CWE), 10)

    def test_category_to_capec(self):
        self.assertGreater(len(_CATEGORY_TO_CAPEC), 10)

    def test_category_to_mitre(self):
        self.assertGreater(len(_CATEGORY_TO_MITRE), 10)

    def test_cve_log4shell(self):
        entry = _CVE_KNOWN_PATTERNS.get("CVE-2021-44228")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["severity"], "critical")
        self.assertTrue(entry["known_exploited"])

    def test_cve_in_cisa_kev(self):
        self.assertIn("CVE-2021-44228", _CISA_KEV_CVE_LIST)

    def test_cwe_89(self):
        entry = _CWE_DATABASE.get("CWE-89")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["name"], "SQL Injection")

    def test_capec_66(self):
        entry = _CAPEC_DATABASE.get("CAPEC-66")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["name"], "SQL Injection")

    def test_mitre_t1190(self):
        entry = _MITRE_TECHNIQUES.get("T1190")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["name"], "Exploit Public-Facing Application")

    def test_owasp_ids(self):
        ids = {item["id"] for item in _OWASP_TOP10}
        self.assertIn("A01", ids)
        self.assertIn("A10", ids)


class TestQuickClassify(unittest.TestCase):

    def test_sqli(self):
        self.assertEqual(_quick_classify(_finding()), "sqli")

    def test_xss(self):
        f = _finding(title="XSS found", category="xss", evidence="<script>alert(1)</script>")
        self.assertEqual(_quick_classify(f), "xss")

    def test_rce(self):
        f = _finding(title="RCE detected", category="rce")
        self.assertEqual(_quick_classify(f), "rce")

    def test_cve(self):
        f = _finding(title="CVE-2024-3094 detected", category="cve")
        self.assertEqual(_quick_classify(f), "cve")

    def test_supply_chain(self):
        f = _finding(title="Supply chain vulnerability", category="supply_chain")
        self.assertEqual(_quick_classify(f), "supply_chain")

    def test_default_creds(self):
        f = _finding(title="Default credentials", category="default_credentials", evidence="admin:admin")
        # credential_theft has higher weight for "credential" pattern
        self.assertIn(_quick_classify(f), ("default_credentials", "credential_theft"))

    def test_unknown(self):
        f = _finding(title="Random finding", category="misc", evidence="nothing special")
        self.assertEqual(_quick_classify(f), "misc")


class TestThreatIntelEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ThreatIntelEngine(enable_online=False)

    def test_lookup_cve_known(self):
        result = self.engine.lookup_cve("CVE-2021-44228")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "Log4Shell")
        self.assertTrue(result["known_exploited"])

    def test_lookup_cve_unknown(self):
        result = self.engine.lookup_cve("CVE-9999-9999")
        self.assertIsNone(result)

    def test_lookup_cwe(self):
        result = self.engine.lookup_cwe("CWE-89")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "SQL Injection")

    def test_lookup_cwe_unknown(self):
        result = self.engine.lookup_cwe("CWE-99999")
        self.assertIsNone(result)

    def test_lookup_capec(self):
        result = self.engine.lookup_capec("CAPEC-66")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "SQL Injection")

    def test_lookup_mitre(self):
        result = self.engine.lookup_mitre("T1190")
        self.assertIsNotNone(result)
        self.assertIn("tactic", result)

    def test_get_owasp_mapping_sqli(self):
        result = self.engine.get_owasp_mapping("sqli")
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["owasp_id"], "A03")

    def test_get_owasp_mapping_empty(self):
        result = self.engine.get_owasp_mapping("nonexistent")
        self.assertEqual(result, [])

    def test_cache_hit(self):
        self.engine.lookup_cve("CVE-2021-44228")
        self.engine.lookup_cve("CVE-2021-44228")
        stats = self.engine.cache_stats
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)

    def test_cache_miss(self):
        self.engine.lookup_cve("CVE-9999-9999")
        stats = self.engine.cache_stats
        self.assertEqual(stats["misses"], 1)

    def test_clear_cache(self):
        self.engine.lookup_cve("CVE-2021-44228")
        self.engine.clear_cache()
        self.assertEqual(self.engine.cache_stats["size"], 0)


class TestEnrichScan(unittest.TestCase):

    def setUp(self):
        self.engine = ThreatIntelEngine(enable_online=False)

    def test_enrich_empty(self):
        report = self.engine.enrich_scan([], "example.com")
        self.assertEqual(len(report.enriched_findings), 0)
        self.assertIn("No findings", report.threat_summary)

    def test_enrich_single_sqli(self):
        findings = [_finding()]
        report = self.engine.enrich_scan(findings, "example.com")
        self.assertEqual(len(report.enriched_findings), 1)
        ef = report.enriched_findings[0]
        self.assertIn("CWE-89", ef["cwe_matches"])
        self.assertIn("CAPEC-66", ef["capec_matches"])
        self.assertGreater(len(ef["mitre_techniques"]), 0)

    def test_enrich_cve_reference(self):
        findings = [_finding(
            title="Log4Shell vulnerability CVE-2021-44228",
            evidence="CVE-2021-44228 detected in application logs",
            category="cve",
        )]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        self.assertIn("CVE-2021-44228", ef["cve_matches"])
        self.assertTrue(ef["known_exploitation"])

    def test_enrich_multiple_findings(self):
        findings = [
            _finding(severity="critical", category="sqli"),
            _finding(title="XSS", severity="high", category="xss", evidence="<script>alert(1)</script>"),
            _finding(title="SSRF", severity="critical", category="ssrf", evidence="http://169.254.169.254"),
        ]
        report = self.engine.enrich_scan(findings, "example.com")
        self.assertEqual(len(report.enriched_findings), 3)
        self.assertGreater(len(report.unique_cwes), 0)
        self.assertGreater(len(report.unique_capecs), 0)
        self.assertGreater(len(report.unique_mitre), 0)

    def test_enrich_technology_detection(self):
        findings = [_finding(
            evidence="Found in Apache Tomcat application using Java and Spring Framework",
        )]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        self.assertIn("Apache", ef["affected_technologies"])
        self.assertIn("Java", ef["affected_technologies"])

    def test_enrich_threat_records_populated(self):
        findings = [_finding()]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        self.assertGreater(ef["record_count"], 0)
        self.assertGreater(len(ef["threat_records"]), 0)

    def test_enrich_report_to_dict(self):
        findings = [_finding()]
        report = self.engine.enrich_scan(findings, "example.com")
        d = report.to_dict()
        self.assertIn("target", d)
        self.assertIn("unique_cves", d)
        self.assertIn("enriched_count", d)

    def test_enrich_summary_content(self):
        findings = [
            _finding(title="CVE-2021-44228 detected", category="cve",
                    evidence="CVE-2021-44228"),
        ]
        report = self.engine.enrich_scan(findings, "example.com")
        self.assertIn("CVE", report.threat_summary)
        self.assertGreater(report.known_exploited_count, 0)

    def test_enrich_xss_mappings(self):
        findings = [_finding(title="XSS", category="xss", severity="high", evidence="<script>alert(1)</script>")]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        self.assertIn("CWE-79", ef["cwe_matches"])
        self.assertIn("CAPEC-86", ef["capec_matches"])

    def test_enrich_ssrf_mappings(self):
        findings = [_finding(title="SSRF", category="ssrf", severity="critical", evidence="http://169.254.169.254")]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        self.assertIn("CWE-918", ef["cwe_matches"])

    def test_enrich_misconfiguration_owasp(self):
        findings = [_finding(title="Missing security headers misconfiguration", category="misconfiguration", severity="medium")]
        report = self.engine.enrich_scan(findings, "example.com")
        ef = report.enriched_findings[0]
        # Should have OWASP records
        sources = {r.get("source") for r in ef["threat_records"]}
        self.assertIn("OWASP", sources)

    def test_enrich_duration(self):
        findings = [_finding() for _ in range(10)]
        report = self.engine.enrich_scan(findings, "example.com")
        self.assertGreater(report.analysis_duration_ms, 0)


class TestThreatRecord(unittest.TestCase):

    def test_to_dict(self):
        tr = ThreatRecord(source="CVE", source_id="CVE-2021-44228",
                        name="Log4Shell", severity="critical", confidence=0.9)
        d = tr.to_dict()
        self.assertEqual(d["source"], "CVE")
        self.assertEqual(d["source_id"], "CVE-2021-44228")


class TestEnrichedFinding(unittest.TestCase):

    def test_default_values(self):
        ef = EnrichedFinding(original=_finding())
        self.assertFalse(ef.known_exploitation)
        self.assertEqual(ef.severity_evolution, "stable")

    def test_to_dict(self):
        ef = EnrichedFinding(original=_finding(), cve_matches=["CVE-2021-44228"],
                            cwe_matches=["CWE-89"])
        d = ef.to_dict()
        self.assertIn("CVE-2021-44228", d["cve_matches"])
        self.assertIn("CWE-89", d["cwe_matches"])


if __name__ == "__main__":
    unittest.main()
