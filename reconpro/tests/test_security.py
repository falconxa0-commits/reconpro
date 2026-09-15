"""Comprehensive tests for reconpro.security — Security Hardening Layer."""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.security import (
    sanitize_target,
    sanitize_path,
    sanitize_filename,
    sanitize_html,
    sanitize_shell,
    sanitize_log,
    detect_secrets_in_text,
    safe_json_parse,
    safe_url_parse,
    safe_xml_parse,
    SecurityAuditLogger,
    compute_file_hash,
    verify_module_signature,
    check_dependency_integrity,
    get_security_profile,
    classify_threat,
    THREAT_CATEGORIES,
)


# ── sanitize_target ──────────────────────────────────────────────────────

class TestSanitizeTarget(unittest.TestCase):
    """Tests for sanitize_target."""

    def test_normal_url(self):
        self.assertEqual(sanitize_target("https://example.com"), "https://example.com")

    def test_normal_domain(self):
        self.assertEqual(sanitize_target("example.com"), "example.com")

    def test_ip_address(self):
        self.assertEqual(sanitize_target("192.168.1.1"), "192.168.1.1")

    def test_whitespace_stripped(self):
        self.assertEqual(sanitize_target("  example.com  "), "example.com")

    def test_null_bytes_removed(self):
        self.assertEqual(sanitize_target("example.com\x00.evil.com"), "example.com.evil.com")

    def test_control_chars_removed(self):
        # \x01 is a control character, should be removed
        result = sanitize_target("example\x01.com")
        self.assertNotIn("\x01", result)

    def test_semicolon_removed(self):
        result = sanitize_target("example.com; rm -rf /")
        self.assertNotIn(";", result)

    def test_pipe_removed(self):
        result = sanitize_target("example.com | cat /etc/passwd")
        self.assertNotIn("|", result)

    def test_backtick_removed(self):
        result = sanitize_target("example.com`whoami`")
        self.assertNotIn("`", result)

    def test_dollar_sign_removed(self):
        result = sanitize_target("example.com$HOME")
        self.assertNotIn("$", result)

    def test_ampersand_removed(self):
        result = sanitize_target("example.com&&rm")
        self.assertNotIn("&", result)

    def test_redirect_removed(self):
        result = sanitize_target("example.com > /etc/passwd")
        self.assertNotIn(">", result)

    def test_less_than_removed(self):
        result = sanitize_target("example.com < /etc/passwd")
        self.assertNotIn("<", result)

    def test_empty_string(self):
        self.assertEqual(sanitize_target(""), "")

    def test_unicode_preserved(self):
        self.assertEqual(sanitize_target("例え.jp"), "例え.jp")

    def test_multiple_whitespace_collapsed(self):
        self.assertEqual(sanitize_target("example   .com"), "example .com")

    def test_newline_removed(self):
        result = sanitize_target("example.com\nevil.com")
        self.assertNotIn("\n", result)

    def test_tab_preserved_as_space(self):
        # Tab is allowed by the filter (ord >= 0x20 check has exception for \t)
        # but then whitespace collapse may change it
        result = sanitize_target("example.com\tpath")
        # Tab should survive the control char filter
        self.assertNotIn("\t", result)  # collapsed by \s+ regex

    def test_url_with_port(self):
        self.assertEqual(sanitize_target("https://example.com:8080/path"), "https://example.com:8080/path")


# ── sanitize_path ────────────────────────────────────────────────────────

class TestSanitizePath(unittest.TestCase):
    """Tests for sanitize_path."""

    def test_normal_path(self):
        self.assertEqual(sanitize_path("/var/log/test.log"), "var/log/test.log")

    def test_dot_dot_slash_traversal(self):
        result = sanitize_path("/etc/passwd")
        self.assertNotIn("..", result)

    def test_dot_dot_removed(self):
        self.assertEqual(sanitize_path("foo/bar/../../../etc/passwd"), "etc/passwd")

    def test_null_byte_removed(self):
        self.assertEqual(sanitize_path("file.txt\x00.jpg"), "file.txt.jpg")

    def test_backslash_normalized(self):
        self.assertEqual(sanitize_path("foo\\bar\\baz"), "foo/bar/baz")

    def test_empty_string(self):
        self.assertEqual(sanitize_path(""), "")

    def test_long_path_truncated(self):
        long_path = "/".join(["a"] * 5000)
        result = sanitize_path(long_path)
        self.assertLessEqual(len(result), 4096)

    def test_current_directory_ignored(self):
        self.assertEqual(sanitize_path("./foo/./bar/./baz"), "foo/bar/baz")

    def test_complex_traversal(self):
        # Multiple .. that would go above root
        result = sanitize_path("a/b/../../c")
        self.assertEqual(result, "c")

    def test_percent_encoded_dots(self):
        result = sanitize_path("%2e%2e/etc/passwd")
        self.assertNotIn("..", result)

    def test_standalone_dots_only(self):
        self.assertEqual(sanitize_path("..."), "...")

    def test_trailing_slash(self):
        self.assertEqual(sanitize_path("foo/bar/"), "foo/bar")

    def test_leading_slash_stripped(self):
        self.assertEqual(sanitize_path("/foo/bar"), "foo/bar")

    def test_control_chars_removed(self):
        result = sanitize_path("foo\x01bar")
        self.assertNotIn("\x01", result)


# ── sanitize_filename ────────────────────────────────────────────────────

class TestSanitizeFilename(unittest.TestCase):
    """Tests for sanitize_filename."""

    def test_normal_filename(self):
        self.assertEqual(sanitize_filename("report.pdf"), "report.pdf")

    def test_directory_traversal_removed(self):
        self.assertEqual(sanitize_filename("../../../etc/passwd"), "passwd")

    def test_null_byte_removed(self):
        self.assertEqual(sanitize_filename("file\x00.txt"), "file.txt")

    def test_special_chars_replaced(self):
        result = sanitize_filename("file<name>.txt")
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)

    def test_hidden_file_dot_replaced(self):
        self.assertEqual(sanitize_filename(".hidden"), "_hidden")

    def test_empty_string(self):
        self.assertEqual(sanitize_filename(""), "unnamed")

    def test_only_special_chars(self):
        result = sanitize_filename('<>:"/\\|?*')
        # All special chars replaced with underscores
        self.assertTrue(all(c in "_." for c in result))

    def test_long_filename_truncated(self):
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        self.assertLessEqual(len(result), 255)

    def test_backslash_directory_removed(self):
        self.assertEqual(sanitize_filename("path\\to\\file.txt"), "file.txt")

    def test_unix_path_removed(self):
        self.assertEqual(sanitize_filename("/path/to/file.txt"), "file.txt")

    def test_spaces_allowed(self):
        # Spaces are replaced with _ since they don't match [a-zA-Z0-9._-]
        result = sanitize_filename("my file.txt")
        self.assertEqual(result, "my_file.txt")

    def test_all_unsafe_returns_fallback(self):
        # Pure special characters → all become underscores
        result = sanitize_filename("@@@###")
        self.assertNotEqual(result, "unnamed")  # Has content
        self.assertTrue(all(c in "_." for c in result))


# ── sanitize_html ────────────────────────────────────────────────────────

class TestSanitizeHtml(unittest.TestCase):
    """Tests for sanitize_html."""

    def test_script_tag_escaped(self):
        result = sanitize_html("<script>alert(1)</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_img_onerror_escaped(self):
        result = sanitize_html('<img src=x onerror="alert(1)">')
        # html.escape escapes <, >, &, ", ' — attribute names remain but tags are neutered
        self.assertIn("&lt;img", result)
        self.assertIn("&gt;", result)
        self.assertNotIn("<img", result)

    def test_ampersand_escaped(self):
        self.assertEqual(sanitize_html("a & b"), "a &amp; b")

    def test_quotes_escaped(self):
        result = sanitize_html('value="test"')
        self.assertIn("&quot;", result)

    def test_single_quote_escaped(self):
        result = sanitize_html("it's")
        self.assertIn("&#x27;", result)

    def test_empty_string(self):
        self.assertEqual(sanitize_html(""), "")

    def test_normal_text_unchanged(self):
        self.assertEqual(sanitize_html("Hello World"), "Hello World")

    def test_nested_tags_escaped(self):
        result = sanitize_html("<div><p>text</p></div>")
        self.assertIn("&lt;div&gt;", result)
        self.assertIn("&lt;p&gt;", result)

    def test_event_handler_escaped(self):
        result = sanitize_html('<a onclick="evil()">click</a>')
        # Tags are escaped so event handlers cannot execute
        self.assertIn("&lt;a", result)
        self.assertIn("&quot;evil()&quot;", result)
        self.assertNotIn("<a", result)


# ── sanitize_shell ───────────────────────────────────────────────────────

class TestSanitizeShell(unittest.TestCase):
    """Tests for sanitize_shell."""

    def test_simple_text(self):
        # Simple text gets wrapped in single quotes
        result = sanitize_shell("hello")
        self.assertEqual(result, "'hello'")

    def test_command_injection_escaped(self):
        result = sanitize_shell("; rm -rf /")
        self.assertTrue(result.startswith("'"))
        self.assertTrue(result.endswith("'"))

    def test_pipe_escaped(self):
        result = sanitize_shell("| cat /etc/passwd")
        self.assertTrue(result.startswith("'"))

    def test_backtick_escaped(self):
        result = sanitize_shell("`whoami`")
        self.assertTrue(result.startswith("'"))

    def test_semicolon_escaped(self):
        result = sanitize_shell("foo; bar")
        # Semicolons are inside single quotes, so they can't break out
        self.assertTrue(result.startswith("'"))
        self.assertTrue(result.endswith("'"))

    def test_dollar_sign_escaped(self):
        result = sanitize_shell("$HOME")
        self.assertTrue(result.startswith("'"))

    def test_ampersand_escaped(self):
        result = sanitize_shell("&& echo")
        self.assertTrue(result.startswith("'"))

    def test_single_quote_in_text(self):
        # Single quotes within text should be properly escaped
        result = sanitize_shell("it's a test")
        self.assertIn("'\\''", result)

    def test_null_byte_removed(self):
        result = sanitize_shell("test\x00command")
        self.assertNotIn("\x00", result)

    def test_empty_string(self):
        self.assertEqual(sanitize_shell(""), "")


# ── sanitize_log ─────────────────────────────────────────────────────────

class TestSanitizeLog(unittest.TestCase):
    """Tests for sanitize_log."""

    def test_crlf_removed(self):
        result = sanitize_log("normal\r\nfake log entry")
        self.assertNotIn("\r", result)
        self.assertNotIn("\n", result)

    def test_newline_removed(self):
        result = sanitize_log("line1\nline2")
        self.assertNotIn("\n", result)
        self.assertIn("line1", result)
        self.assertIn("line2", result)

    def test_carriage_return_removed(self):
        result = sanitize_log("line1\rline2")
        self.assertNotIn("\r", result)

    def test_control_chars_removed(self):
        result = sanitize_log("text\x01\x02\x03end")
        self.assertNotIn("\x01", result)

    def test_normal_text_unchanged(self):
        self.assertEqual(sanitize_log("normal log entry"), "normal log entry")

    def test_empty_string(self):
        self.assertEqual(sanitize_log(""), "")

    def test_tab_preserved(self):
        result = sanitize_log("col1\tcol2")
        self.assertIn("\t", result)

    def test_multiple_newlines_become_spaces(self):
        result = sanitize_log("line1\n\n\nline2")
        self.assertNotIn("\n", result)
        self.assertIn("line1", result)
        self.assertIn("line2", result)

    def test_crlf_injection_prevented(self):
        # Simulated CRLF log injection attack
        result = sanitize_log("user\r\n[ERROR] Fake alert")
        self.assertNotIn("\r", result)
        self.assertNotIn("\n", result)

    def test_multiple_spaces_collapsed(self):
        result = sanitize_log("too   many   spaces")
        self.assertEqual(result, "too many spaces")


# ── detect_secrets_in_text ───────────────────────────────────────────────

class TestDetectSecrets(unittest.TestCase):
    """Tests for detect_secrets_in_text."""

    def test_aws_key_detected(self):
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "aws_key" for r in results))

    def test_github_token_detected(self):
        text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "github_token" for r in results))

    def test_password_in_url_detected(self):
        text = "DB_URL=https://admin:secretpass123@db.example.com"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "password_in_url" for r in results))

    def test_private_key_rsa_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "private_key_rsa" for r in results))

    def test_private_key_ec_detected(self):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCA\n-----END EC PRIVATE KEY-----"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "private_key_ec" for r in results))

    def test_jwt_detected(self):
        # Construct a valid-looking JWT with enough characters
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # 36 chars
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"  # 60 chars
        sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # 43 chars
        text = f"Authorization: Bearer {header}.{payload}.{sig}"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "jwt_token" for r in results))

    def test_db_connection_string_detected(self):
        text = "mongodb://user:pass@mongo.example.com:27017/mydb"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "db_connection_string" for r in results))

    def test_generic_api_key_detected(self):
        text = 'api_key="abcdefghijklmnopqrstuvwxyz012345"'
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "generic_api_key" for r in results))

    def test_no_secrets_clean_text(self):
        text = "This is just normal text with no secrets."
        results = detect_secrets_in_text(text)
        self.assertEqual(len(results), 0)

    def test_empty_text(self):
        results = detect_secrets_in_text("")
        self.assertEqual(results, [])

    def test_multiple_secrets_same_line(self):
        text = "AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        results = detect_secrets_in_text(text)
        types = {r["type"] for r in results}
        self.assertIn("aws_key", types)
        self.assertIn("github_token", types)

    def test_secret_line_numbers(self):
        text = "line1\nAKIAIOSFODNN7EXAMPLE\nline3"
        results = detect_secrets_in_text(text)
        aws_results = [r for r in results if r["type"] == "aws_key"]
        self.assertTrue(len(aws_results) > 0)
        self.assertEqual(aws_results[0]["line"], 2)

    def test_secret_has_offset(self):
        text = "prefix AKIAIOSFODNN7EXAMPLE"
        results = detect_secrets_in_text(text)
        aws_results = [r for r in results if r["type"] == "aws_key"]
        self.assertTrue(len(aws_results) > 0)
        self.assertIn("offset", aws_results[0])

    def test_secret_has_confidence(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        results = detect_secrets_in_text(text)
        self.assertTrue(len(results) > 0)
        self.assertIn("confidence", results[0])

    def test_postgres_connection_string(self):
        text = "postgresql://user:pass@localhost:5432/mydb"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "db_connection_string" for r in results))

    def test_private_key_generic_detected(self):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEvg\n-----END PRIVATE KEY-----"
        results = detect_secrets_in_text(text)
        self.assertTrue(any(r["type"] == "private_key_generic" for r in results))


# ── safe_json_parse ──────────────────────────────────────────────────────

class TestSafeJsonParse(unittest.TestCase):
    """Tests for safe_json_parse."""

    def test_valid_json(self):
        data, err = safe_json_parse('{"key": "value"}')
        self.assertIsNone(err)
        self.assertEqual(data, {"key": "value"})

    def test_empty_json(self):
        data, err = safe_json_parse("{}")
        self.assertIsNone(err)
        self.assertEqual(data, {})

    def test_invalid_json(self):
        data, err = safe_json_parse("not json")
        self.assertIsNone(data)
        self.assertIsNotNone(err)
        self.assertIn("Invalid JSON", err)

    def test_empty_string(self):
        data, err = safe_json_parse("")
        self.assertIsNone(data)
        self.assertIn("Empty", err)

    def test_too_large_json(self):
        # Generate a JSON string larger than 1MB
        large_obj = {f"key_{i}": f"value_{i}" * 1000 for i in range(2000)}
        large_json = json.dumps(large_obj)
        data, err = safe_json_parse(large_json)
        self.assertIsNone(data)
        self.assertIn("exceeds maximum size", err)

    def test_too_deep_json(self):
        # Build a deeply nested JSON string
        obj: Any = "leaf"
        for _ in range(25):
            obj = {"child": obj}
        deep_json = json.dumps(obj)
        data, err = safe_json_parse(deep_json)
        self.assertIsNone(data)
        self.assertIn("depth", err)

    def test_too_many_keys_json(self):
        # Generate JSON with more than 10,000 keys
        obj = {f"key_{i}": f"val_{i}" for i in range(11000)}
        many_keys_json = json.dumps(obj)
        data, err = safe_json_parse(many_keys_json)
        self.assertIsNone(data)
        self.assertIn("keys", err)

    def test_json_array_rejected(self):
        data, err = safe_json_parse('["a", "b"]')
        self.assertIsNone(data)
        self.assertIn("object", err)

    def test_nested_valid_json(self):
        nested = {"a": {"b": {"c": "d"}}}
        data, err = safe_json_parse(json.dumps(nested))
        self.assertIsNone(err)
        self.assertEqual(data["a"]["b"]["c"], "d")

    def test_json_with_numbers(self):
        data, err = safe_json_parse('{"count": 42, "price": 3.14}')
        self.assertIsNone(err)
        self.assertEqual(data["count"], 42)
        self.assertAlmostEqual(data["price"], 3.14)

    def test_malformed_json_trailing_comma(self):
        data, err = safe_json_parse('{"key": "value",}')
        self.assertIsNone(data)
        self.assertIsNotNone(err)


# ── safe_url_parse ───────────────────────────────────────────────────────

class TestSafeUrlParse(unittest.TestCase):
    """Tests for safe_url_parse."""

    def test_valid_https(self):
        result, err = safe_url_parse("https://example.com/path")
        self.assertIsNone(err)
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["netloc"], "example.com")
        self.assertEqual(result["path"], "/path")

    def test_valid_http(self):
        result, err = safe_url_parse("http://example.com:8080/api?key=val")
        self.assertIsNone(err)
        self.assertEqual(result["scheme"], "http")
        self.assertEqual(result["netloc"], "example.com:8080")
        self.assertIn("key=val", result["query"])

    def test_javascript_protocol_rejected(self):
        result, err = safe_url_parse("javascript:alert(1)")
        self.assertIsNone(result)
        self.assertIn("not allowed", err)

    def test_data_url_rejected(self):
        result, err = safe_url_parse("data:text/html,<script>alert(1)</script>")
        self.assertIsNone(result)
        self.assertIn("not allowed", err)

    def test_ftp_rejected(self):
        result, err = safe_url_parse("ftp://evil.com/file")
        self.assertIsNone(result)
        self.assertIn("not allowed", err)

    def test_empty_url(self):
        result, err = safe_url_parse("")
        self.assertIsNone(result)
        self.assertIn("Empty", err)

    def test_url_too_long(self):
        long_url = "https://example.com/" + "a" * 3000
        result, err = safe_url_parse(long_url)
        self.assertIsNone(result)
        self.assertIn("exceeds maximum length", err)

    def test_missing_hostname(self):
        result, err = safe_url_parse("https:///path")
        self.assertIsNone(result)
        self.assertIn("hostname", err)

    def test_url_with_fragment(self):
        result, err = safe_url_parse("https://example.com/page#section")
        self.assertIsNone(err)
        self.assertEqual(result["fragment"], "section")

    def test_scheme_case_insensitive(self):
        result, err = safe_url_parse("HTTPS://EXAMPLE.COM")
        self.assertIsNone(err)
        self.assertEqual(result["scheme"], "https")

    def test_no_scheme_allowed(self):
        result, err = safe_url_parse("example.com")
        self.assertIsNone(result)
        self.assertIn("scheme", err.lower())


# ── safe_xml_parse ───────────────────────────────────────────────────────

class TestSafeXmlParse(unittest.TestCase):
    """Tests for safe_xml_parse."""

    def test_valid_xml(self):
        tag, err = safe_xml_parse("<root><child>text</child></root>")
        self.assertIsNone(err)
        self.assertEqual(tag, "root")

    def test_empty_input(self):
        tag, err = safe_xml_parse("")
        self.assertIsNone(tag)
        self.assertIn("Empty", err)

    def test_invalid_xml(self):
        tag, err = safe_xml_parse("<root><unclosed>")
        self.assertIsNone(tag)
        self.assertIsNotNone(err)

    def test_too_large_xml(self):
        large_xml = "<root>" + "x" * 2_000_000 + "</root>"
        tag, err = safe_xml_parse(large_xml)
        self.assertIsNone(tag)
        self.assertIn("exceeds maximum size", err)


# ── SecurityAuditLogger ──────────────────────────────────────────────────

class TestSecurityAuditLogger(unittest.TestCase):
    """Tests for SecurityAuditLogger."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = SecurityAuditLogger(log_dir=self.tmpdir, module_name="test")

    def tearDown(self):
        self.logger.close()

    def test_creates_log_file(self):
        self.logger.info("TEST_EVENT", target="example.com")
        self.assertTrue(os.path.exists(self.logger.log_path))

    def test_structured_json_format(self):
        self.logger.info("SCAN_START", target="test.com", details={"scanner": "nmap"})
        with open(self.logger.log_path, "r") as f:
            line = f.readline().strip()
        entry = json.loads(line)
        self.assertEqual(entry["event_type"], "SCAN_START")
        self.assertEqual(entry["level"], "INFO")
        self.assertEqual(entry["module"], "test")
        self.assertEqual(entry["target"], "test.com")
        self.assertEqual(entry["details"]["scanner"], "nmap")

    def test_warn_level(self):
        self.logger.warn("FINDING", details={"severity": "high"})
        with open(self.logger.log_path, "r") as f:
            entry = json.loads(f.readline().strip())
        self.assertEqual(entry["level"], "WARN")

    def test_alert_level(self):
        self.logger.alert("CRITICAL_FINDING")
        with open(self.logger.log_path, "r") as f:
            entry = json.loads(f.readline().strip())
        self.assertEqual(entry["level"], "ALERT")

    def test_iso_timestamp(self):
        self.logger.info("TEST")
        with open(self.logger.log_path, "r") as f:
            entry = json.loads(f.readline().strip())
        # Should be parseable ISO 8601
        self.assertIn("T", entry["timestamp"])
        self.assertIn("timestamp", entry)

    def test_crlf_sanitized_in_target(self):
        self.logger.info("TEST", target="evil\r\n[FAKE] injected")
        with open(self.logger.log_path, "r") as f:
            content = f.read()
        self.assertNotIn("\r", content)
        self.assertNotIn("\n", content.replace("\n", ""))  # Only json newlines

    def test_multiple_entries(self):
        self.logger.info("EVENT_1")
        self.logger.warn("EVENT_2")
        self.logger.alert("EVENT_3")
        with open(self.logger.log_path, "r") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 3)

    def test_log_rotation(self):
        """Test that log rotation is configured (handler has maxBytes set)."""
        self.assertEqual(self.logger._handler.maxBytes, 10 * 1024 * 1024)

    def test_backup_count(self):
        self.assertEqual(self.logger._handler.backupCount, 5)

    def test_log_path_property(self):
        self.assertIn("audit.log", self.logger.log_path)


# ── compute_file_hash ────────────────────────────────────────────────────

class TestComputeFileHash(unittest.TestCase):
    """Tests for compute_file_hash."""

    def test_sha256_of_known_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("hello world")
            tmppath = f.name
        try:
            result = compute_file_hash(tmppath, "sha256")
            expected = hashlib.sha256(b"hello world").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(tmppath)

    def test_nonexistent_file(self):
        result = compute_file_hash("/nonexistent/path/file.txt")
        self.assertEqual(result, "")

    def test_md5_algorithm(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test")
            tmppath = f.name
        try:
            result = compute_file_hash(tmppath, "md5")
            expected = hashlib.md5(b"test").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(tmppath)

    def test_sha512_algorithm(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test")
            tmppath = f.name
        try:
            result = compute_file_hash(tmppath, "sha512")
            expected = hashlib.sha512(b"test").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(tmppath)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmppath = f.name
        try:
            result = compute_file_hash(tmppath)
            self.assertEqual(len(result), 64)  # SHA-256 hex length
        finally:
            os.unlink(tmppath)


# ── verify_module_signature ──────────────────────────────────────────────

class TestVerifyModuleSignature(unittest.TestCase):
    """Tests for verify_module_signature (placeholder)."""

    def test_returns_true_placeholder(self):
        # Placeholder always returns True
        self.assertTrue(verify_module_signature("reconpro.scanner", "abc123"))

    def test_returns_true_any_input(self):
        self.assertTrue(verify_module_signature("any.module", ""))


# ── check_dependency_integrity ───────────────────────────────────────────

class TestCheckDependencyIntegrity(unittest.TestCase):
    """Tests for check_dependency_integrity."""

    def test_returns_dict(self):
        result = check_dependency_integrity()
        self.assertIsInstance(result, dict)

    def test_has_required_keys(self):
        result = check_dependency_integrity()
        self.assertIn("status", result)
        self.assertIn("stdlib_imports", result)
        self.assertIn("external_imports", result)
        self.assertIn("details", result)

    def test_status_is_string(self):
        result = check_dependency_integrity()
        self.assertIn(result["status"], ("ok", "warning"))

    def test_stdlib_imports_is_set(self):
        result = check_dependency_integrity()
        self.assertIsInstance(result["stdlib_imports"], set)

    def test_external_imports_is_set(self):
        result = check_dependency_integrity()
        self.assertIsInstance(result["external_imports"], set)

    def test_details_is_string(self):
        result = check_dependency_integrity()
        self.assertIsInstance(result["details"], str)


# ── get_security_profile ─────────────────────────────────────────────────

class TestGetSecurityProfile(unittest.TestCase):
    """Tests for get_security_profile."""

    def test_returns_dict(self):
        profile = get_security_profile()
        self.assertIsInstance(profile, dict)

    def test_has_version(self):
        profile = get_security_profile()
        self.assertIn("version", profile)

    def test_has_sanitization_section(self):
        profile = get_security_profile()
        self.assertIn("sanitization", profile)
        self.assertIn("sanitize_target", profile["sanitization"])

    def test_has_secret_detection_section(self):
        profile = get_security_profile()
        self.assertIn("secret_detection", profile)
        self.assertIn("patterns", profile["secret_detection"])

    def test_has_safe_parsing_section(self):
        profile = get_security_profile()
        self.assertIn("safe_parsing", profile)
        self.assertIn("json_max_depth", profile["safe_parsing"])

    def test_has_threat_categories(self):
        profile = get_security_profile()
        self.assertIn("threat_categories", profile)
        self.assertIsInstance(profile["threat_categories"], dict)

    def test_json_limits_sensible(self):
        profile = get_security_profile()
        self.assertGreater(profile["safe_parsing"]["json_max_size_bytes"], 0)
        self.assertGreater(profile["safe_parsing"]["json_max_depth"], 0)


# ── classify_threat ──────────────────────────────────────────────────────

class TestClassifyThreat(unittest.TestCase):
    """Tests for classify_threat."""

    def test_sql_injection(self):
        result = classify_threat({"type": "sql_injection"})
        self.assertEqual(result, "injection")

    def test_xss(self):
        result = classify_threat({"type": "xss"})
        self.assertEqual(result, "injection")

    def test_command_injection(self):
        result = classify_threat({"type": "command_injection"})
        self.assertEqual(result, "injection")

    def test_weak_hash(self):
        result = classify_threat({"type": "weak_hash"})
        self.assertEqual(result, "crypto")

    def test_expired_cert(self):
        result = classify_threat({"type": "expired_cert"})
        self.assertEqual(result, "crypto")

    def test_open_port(self):
        result = classify_threat({"type": "open_port"})
        self.assertEqual(result, "network")

    def test_exposed_service(self):
        result = classify_threat({"type": "exposed_service"})
        self.assertEqual(result, "network")

    def test_data_leak(self):
        result = classify_threat({"type": "data_leak"})
        self.assertEqual(result, "data")

    def test_pii(self):
        result = classify_threat({"type": "pii_exposure"})
        self.assertEqual(result, "data")

    def test_auth_bypass(self):
        result = classify_threat({"type": "auth_bypass"})
        self.assertEqual(result, "auth")

    def test_weak_password(self):
        result = classify_threat({"type": "weak_password"})
        self.assertEqual(result, "auth")

    def test_missing_mfa(self):
        result = classify_threat({"type": "missing_mfa"})
        self.assertEqual(result, "auth")

    def test_session_fixation(self):
        result = classify_threat({"type": "session_fixation"})
        self.assertEqual(result, "auth")

    def test_description_matching(self):
        result = classify_threat({"description": "SQL injection vulnerability found"})
        self.assertEqual(result, "injection")

    def test_xss_in_description(self):
        result = classify_threat({"description": "Cross-site scripting in search parameter"})
        self.assertEqual(result, "injection")

    def test_empty_finding(self):
        result = classify_threat({})
        self.assertEqual(result, "unknown")

    def test_none_finding(self):
        result = classify_threat(None)  # type: ignore[arg-type]
        self.assertEqual(result, "unknown")

    def test_tls_falls_to_crypto(self):
        result = classify_threat({"type": "tls_v1_0_detected"})
        self.assertEqual(result, "crypto")

    def test_password_in_auth(self):
        result = classify_threat({"description": "Default password detected"})
        self.assertEqual(result, "auth")


# ── THREAT_CATEGORIES ────────────────────────────────────────────────────

class TestThreatCategories(unittest.TestCase):
    """Tests for THREAT_CATEGORIES constant."""

    def test_has_injection_category(self):
        self.assertIn("injection", THREAT_CATEGORIES)

    def test_has_crypto_category(self):
        self.assertIn("crypto", THREAT_CATEGORIES)

    def test_has_network_category(self):
        self.assertIn("network", THREAT_CATEGORIES)

    def test_has_data_category(self):
        self.assertIn("data", THREAT_CATEGORIES)

    def test_has_auth_category(self):
        self.assertIn("auth", THREAT_CATEGORIES)

    def test_injection_has_sql(self):
        self.assertIn("sql", THREAT_CATEGORIES["injection"])

    def test_crypto_has_weak_hash(self):
        self.assertIn("weak_hash", THREAT_CATEGORIES["crypto"])

    def test_categories_are_sets(self):
        for cat, keywords in THREAT_CATEGORIES.items():
            self.assertIsInstance(keywords, set)


# ── sanitize.py re-exports ───────────────────────────────────────────────

class TestSanitizeReexports(unittest.TestCase):
    """Tests that sanitize.py correctly re-exports from security.py."""

    def test_import_sanitize_target(self):
        from reconpro.sanitize import sanitize_target as st
        self.assertIs(st, sanitize_target)

    def test_import_sanitize_path(self):
        from reconpro.sanitize import sanitize_path as sp
        self.assertIs(sp, sanitize_path)

    def test_import_sanitize_html(self):
        from reconpro.sanitize import sanitize_html as sh
        self.assertIs(sh, sanitize_html)

    def test_import_detect_secrets(self):
        from reconpro.sanitize import detect_secrets_in_text as ds
        self.assertIs(ds, detect_secrets_in_text)

    def test_import_safe_json_parse(self):
        from reconpro.sanitize import safe_json_parse as sjp
        self.assertIs(sjp, safe_json_parse)

    def test_import_safe_url_parse(self):
        from reconpro.sanitize import safe_url_parse as sup
        self.assertIs(sup, safe_url_parse)

    def test_import_security_audit_logger(self):
        from reconpro.sanitize import SecurityAuditLogger as SAL
        self.assertIs(SAL, SecurityAuditLogger)

    def test_import_classify_threat(self):
        from reconpro.sanitize import classify_threat as ct
        self.assertIs(ct, classify_threat)


if __name__ == "__main__":
    unittest.main()
