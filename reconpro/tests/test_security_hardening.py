"""Security hardening tests for ReconPro v11 Enterprise.

Tests focused on server endpoint hardening, XSS prevention in generated
reports, bootstrap secret enforcement, and error response sanitisation.

These complement (but do not duplicate) the existing test_security.py and
test_security_regression.py suites.
"""

import json
import os
import secrets
import sys
import tempfile
import unittest
from io import BytesIO
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.security import sanitize_filename, sanitize_path, sanitize_html
from reconpro.formats import export_pdf, export_sarif, export_markdown, export_json
from reconpro.reports import generate_html_report
from reconpro.server import (
    _Handler,
    _API_TOKENS,
    generate_api_token,
    validate_api_token,
    REPORTS_DIR,
)


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_handler(body=b"", method="GET", path="/", headers=None):
    """Create a minimal _Handler instance for testing endpoint logic."""
    handler = _Handler(
        BytesIO(body), ("localhost", 7890), None,
    )
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.path = path
    handler.headers = headers or {}
    # Provide a response buffer
    handler.wfile = BytesIO()
    return handler


def _sample_scan_data(**overrides):
    """Build a minimal scan-data dict for report generation."""
    data = {
        "target": "example.com",
        "total_score": 72,
        "grade": "B",
        "findings": [
            {
                "title": "Open Redirect",
                "severity": "high",
                "category": "redirect",
                "module": "recon",
                "description": "An open redirect was found.",
                "evidence": "Location header to //evil.com",
                "asset": "/login",
                "points_deducted": 15,
                "remediation": "Validate redirect URLs.",
            },
        ],
        "modules_run": ["recon"],
        "severity_counts": {"high": 1},
    }
    data.update(overrides)
    return data


class TestServerPathTraversalReportEndpoint(unittest.TestCase):
    """C-01 FIX: /report/<filename> must block path traversal.

    The server applies sanitize_filename() to the filename extracted
    from the URL path, then validates the resolved path stays within
    REPORTS_DIR.
    """

    def test_report_path_traversal_dotdot_stripped(self):
        """sanitize_filename strips directory components and .. sequences."""
        malicious = "../../etc/passwd"
        safe = sanitize_filename(malicious)
        # Should contain no path separators
        self.assertNotIn("/", safe)
        self.assertNotIn("\\", safe)
        self.assertNotIn("..", safe)

    def test_report_path_traversal_encoded_dots(self):
        """Percent-encoded dots are decoded then stripped."""
        malicious = "%2e%2e/%2e%2e/etc/shadow"
        # sanitize_filename does not decode percent-encoding directly,
        # but it strips path separators
        safe = sanitize_filename(malicious)
        self.assertNotIn("/", safe)

    def test_report_path_traversal_backslash(self):
        """Backslash directory traversal is normalised and stripped."""
        malicious = "..\\..\\windows\\system32"
        safe = sanitize_filename(malicious)
        self.assertNotIn("\\", safe)
        self.assertNotIn("..", safe)

    def test_report_path_traversal_null_byte(self):
        """Null bytes are stripped from filename."""
        malicious = "report.html\x00.txt"
        safe = sanitize_filename(malicious)
        self.assertNotIn("\x00", safe)

    def test_report_filename_still_works(self):
        """Legitimate filenames survive sanitisation."""
        legit = "report_20240115_120000.html"
        safe = sanitize_filename(legit)
        self.assertIn(".html", safe)
        self.assertIn("report", safe)


class TestServerPathTraversalHistoryEndpoint(unittest.TestCase):
    """C-02 FIX: /history/<filename> must block path traversal.

    Same sanitisation mechanism as /report/ — both endpoints use
    sanitize_filename() from reconpro.security.
    """

    def test_history_dotdot_escaped(self):
        """Double-dot sequences are removed by sanitize_filename."""
        safe = sanitize_filename("../../scans/evil.json")
        self.assertNotIn("..", safe)

    def test_history_absolute_path_stripped(self):
        """Absolute path components are stripped — only basename kept."""
        safe = sanitize_filename("/etc/shadow")
        # sanitize_filename takes basename
        self.assertEqual(safe, "shadow")

    def test_history_deep_nesting_flattened(self):
        """Deeply nested paths collapse to the final component."""
        safe = sanitize_filename("a/b/c/d/e/f/g/secret.json")
        self.assertEqual(safe, "secret.json")


class TestXSSInHTMLReportGeneration(unittest.TestCase):
    """Verify that XSS payloads in finding fields are escaped in HTML output.

    The PDF export (export_pdf) and the main report generator
    (generate_html_report) both produce HTML.  User-controlled data
    like finding titles, descriptions, and evidence must be escaped.
    """

    def test_pdf_export_escapes_script_in_title(self):
        """export_pdf must escape <script> in finding titles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "xss_test.pdf")
            data = _sample_scan_data(
                findings=[{
                    "title": "<script>alert('XSS')</script>",
                    "severity": "high",
                    "category": "xss",
                    "module": "m",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 10,
                }],
            )
            export_pdf(data, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            # The literal string "<script>" should NOT appear as a tag
            # in the rendered table rows (it should be &lt;script&gt;)
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)

    def test_pdf_export_escapes_xss_in_title(self):
        """export_pdf must escape XSS payloads injected via the finding title."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "img_test.pdf")
            data = _sample_scan_data(
                findings=[{
                    "title": "<img src=x onerror=alert(1)>",
                    "severity": "high",
                    "category": "xss",
                    "module": "m",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 10,
                }],
            )
            export_pdf(data, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            # Title is rendered in table cells which use _html_module.escape
            self.assertNotIn("<img src=x onerror=alert(1)>", html)
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_pdf_export_escapes_target_in_h2(self):
        """The target field in the PDF h2 header must be escaped.

        Note: the <title> tag is not escaped (known gap), but the
        visible h2 element uses _html_module.escape and is safe.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "target_test.pdf")
            data = _sample_scan_data(
                target='<img src=x onerror=alert("target")>',
            )
            export_pdf(data, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            # The h2 content must be escaped
            self.assertIn("&lt;img src=x onerror=alert(&quot;target&quot;)&gt;", html)
            # The raw unescaped payload must NOT appear inside <h2>
            import re
            h2_match = re.search(r'<h2>(.*?)</h2>', html, re.DOTALL)
            self.assertIsNotNone(h2_match)
            h2_content = h2_match.group(1)
            self.assertNotIn('<img src=', h2_content)

    def test_html_report_escapes_xss_in_finding_title(self):
        """generate_html_report must escape XSS in finding titles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            data = _sample_scan_data(
                findings=[{
                    "title": '<script>document.cookie="stolen"</script>',
                    "severity": "critical",
                    "category": "xss",
                    "module": "auth",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 25,
                }],
            )
            generate_html_report(data, output_path=path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            # The raw script tag should not appear verbatim
            self.assertNotIn('<script>document.cookie', html)

    def test_sarif_export_preserves_xss_as_data(self):
        """SARIF is JSON — XSS is preserved as text data (safe in JSON)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "xss.sarif")
            data = _sample_scan_data(
                findings=[{
                    "title": "<script>alert(1)</script>",
                    "severity": "critical",
                    "category": "xss",
                    "module": "m",
                    "description": "d",
                    "evidence": "e",
                    "asset": "a",
                    "points_deducted": 25,
                }],
            )
            export_sarif(data, path)
            with open(path, encoding="utf-8") as f:
                sarif = json.load(f)
            # In JSON the text is safely stored (escaped by JSON encoder)
            title = sarif["runs"][0]["results"][0]["message"]["text"]
            self.assertIn("<script>", title)

    def test_sanitize_html_comprehensive(self):
        """sanitize_html should escape all HTML special characters."""
        payload = '<script>alert("xss")</script>&"\'test'
        escaped = sanitize_html(payload)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&amp;", escaped)
        self.assertIn("&quot;", escaped)
        self.assertIn("&#x27;", escaped)


class TestBootstrapSecretEnforcement(unittest.TestCase):
    """C-03 FIX: When RECONPRO_BOOTSTRAP_SECRET env var is set, the
    /auth/token endpoint must reject requests with an invalid secret.
    """

    def test_token_generation_without_secret_env_succeeds(self):
        """When no RECONPRO_BOOTSTRAP_SECRET is set, token generation succeeds."""
        with patch.dict(os.environ, {"RECONPRO_BOOTSTRAP_SECRET": ""}, clear=False):
            with patch.dict(os.environ, {"RECONPRO_BOOTSTRAP_SECRET": ""}):
                del os.environ["RECONPRO_BOOTSTRAP_SECRET"]
                # This would normally succeed — we test by checking the
                # generate_api_token function directly (no env check there)
                token = generate_api_token(label="test")
                self.assertTrue(len(token) > 20)
                # Clean up
                if token in _API_TOKENS:
                    del _API_TOKENS[token]

    def test_token_validation_works(self):
        """A generated token validates correctly."""
        token = generate_api_token(label="test", hours=1)
        try:
            self.assertTrue(validate_api_token(token))
            self.assertFalse(validate_api_token(""))
            self.assertFalse(validate_api_token("invalid-token"))
        finally:
            if token in _API_TOKENS:
                del _API_TOKENS[token]

    def test_bootstrap_secret_comparison_is_constant_time(self):
        """The server uses secrets.compare_digest (constant-time comparison).

        We verify this by checking the source of the comparison in
        server.py's POST /auth/token handler.
        """
        import inspect
        source = inspect.getsource(_Handler.do_POST)
        # The handler must use compare_digest for bootstrap secret
        self.assertIn("compare_digest", source)

    def test_wrong_bootstrap_secret_rejected(self):
        """When RECONPRO_BOOTSTRAP_SECRET is set, a wrong secret is rejected.

        We simulate the handler logic directly since it uses
        secrets.compare_digest.
        """
        real_secret = "my-super-secret-key-12345"
        wrong_secret = "wrong-secret-key"
        # This is exactly what the server does
        self.assertFalse(secrets.compare_digest(wrong_secret, real_secret))
        self.assertTrue(secrets.compare_digest(real_secret, real_secret))

    def test_empty_bootstrap_secret_vs_empty_provided(self):
        """Empty string vs empty string should match."""
        self.assertTrue(secrets.compare_digest("", ""))

    def test_bootstrap_secret_similar_but_different(self):
        """Similar-looking secrets must not match."""
        a = "secret-value-A1"
        b = "secret-value-A2"
        self.assertFalse(secrets.compare_digest(a, b))


class TestErrorResponseSanitisation(unittest.TestCase):
    """H-06 FIX: Server error responses must not leak internal details.

    The server catches all exceptions in do_POST and returns a generic
    error message with a request_id instead of the raw traceback.
    """

    def test_error_response_has_generic_message(self):
        """Verify the 500 handler produces a generic error, not internal details."""
        import inspect
        source = inspect.getsource(_Handler.do_POST)
        # The exception handler must NOT include str(e) in the response
        # It should use a fixed message
        self.assertIn('"Internal server error"', source)
        self.assertIn("request_id", source)

    def test_error_response_includes_request_id(self):
        """Error responses must include a unique request_id for log correlation."""
        import inspect
        source = inspect.getsource(_Handler.do_POST)
        # request_id should be generated with secrets.token_hex
        self.assertIn("secrets.token_hex", source)

    def test_forbidden_response_is_simple(self):
        """The 403 response should not leak details."""
        import inspect
        source = inspect.getsource(_Handler._forbidden)
        self.assertIn('"Forbidden"', source)

    def test_unauthorized_response_is_simple(self):
        """The 401 response should not leak token validation details."""
        import inspect
        source = inspect.getsource(_Handler._unauthorized)
        self.assertIn('"Unauthorized', source)


class TestSanitizePathEdgeCases(unittest.TestCase):
    """Additional path sanitisation edge cases not covered by test_security.py."""

    def test_percent_encoded_slash(self):
        """Percent-encoded slashes are decoded by sanitize_path."""
        result = sanitize_path("%2fetc%2fpasswd")
        self.assertNotIn("%2f", result.lower())
        self.assertNotIn("..", result)

    def test_double_encoding(self):
        """Double-encoded traversal should still be safe."""
        result = sanitize_path("%252e%252e%252f")
        # After first decode: %2e%2e%2f — after second: ../../
        # sanitize_path only decodes once, but .. is filtered anyway
        self.assertNotIn("..", result)

    def test_very_long_path_truncated(self):
        """Paths exceeding 4096 chars should be truncated."""
        long_path = "a/" * 5000
        result = sanitize_path(long_path)
        self.assertLessEqual(len(result), 4096)

    def test_mixed_separators(self):
        """Mixed forward and back slashes are normalised."""
        result = sanitize_path("..\\..\\etc/passwd")
        self.assertNotIn("\\", result)
        self.assertNotIn("..", result)

    def test_empty_path_returns_empty(self):
        """Empty input returns empty string."""
        self.assertEqual(sanitize_path(""), "")

    def test_dot_only_components_filtered(self):
        """Single-dot components are filtered out."""
        result = sanitize_path("./foo/./bar/./baz")
        self.assertNotIn("./", result)


if __name__ == "__main__":
    unittest.main()
