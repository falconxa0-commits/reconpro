"""Tests for reconpro.http_layer.http_probe with mocked connections."""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from reconpro.http_layer import http_probe, RateLimiter


@patch('reconpro.http_layer.urllib.request.urlopen')
class TestHttpProbeStructure(unittest.TestCase):
    """Test http_probe returns correct dict structure."""

    def test_return_type_is_dict(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = [("Content-Type", "text/html")]
        mock_resp.read.return_value = b"hello"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_probe("https://example.com")
        self.assertIsInstance(result, dict)

    def test_dict_has_required_keys(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = []
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_probe("https://example.com")
        required_keys = {"ok", "status", "reason", "headers", "body"}
        self.assertTrue(required_keys.issubset(set(result.keys())))

    def test_values_are_correct_types(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = []
        mock_resp.read.return_value = b"body content"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_probe("https://example.com")
        self.assertIsInstance(result["ok"], bool)
        self.assertIsInstance(result["status"], int)
        self.assertIsInstance(result["reason"], str)
        self.assertIsInstance(result["headers"], dict)
        self.assertIsInstance(result["body"], str)


@patch('reconpro.http_layer.urllib.request.urlopen')
class TestHttpProbeSuccess(unittest.TestCase):
    """Test http_probe with mocked success response."""

    def test_success_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = [("Server", "nginx")]
        mock_resp.read.return_value = b"<html>hello</html>"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_probe("https://example.com")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["reason"], "OK")
        self.assertEqual(result["body"], "<html>hello</html>")
        self.assertEqual(result["headers"], {"Server": "nginx"})

    def test_body_truncated_to_16384(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = []
        mock_resp.read.return_value = b"x" * 20000
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = http_probe("https://example.com")
        self.assertLessEqual(len(result["body"]), 16384)


@patch('reconpro.http_layer.urllib.request.urlopen')
class TestHttpProbeHTTPError(unittest.TestCase):
    """Test http_probe with mocked HTTPError."""

    def test_404_response(self, mock_urlopen):
        import urllib.error
        mock_err = urllib.error.HTTPError(
            url="https://example.com/notfound",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )
        mock_urlopen.side_effect = mock_err

        result = http_probe("https://example.com/notfound")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 404)

    def test_500_response(self, mock_urlopen):
        import urllib.error
        mock_err = urllib.error.HTTPError(
            url="https://example.com/error",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None,
        )
        mock_urlopen.side_effect = mock_err

        result = http_probe("https://example.com/error")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 500)


@patch('reconpro.http_layer.urllib.request.urlopen')
class TestHttpProbeNetworkError(unittest.TestCase):
    """Test http_probe with mocked timeout/network error."""

    def test_timeout_error(self, mock_urlopen):
        import socket
        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        result = http_probe("https://slow.example.com")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertIn("timed out", result["reason"].lower())
        self.assertEqual(result["body"], "")

    def test_connection_refused(self, mock_urlopen):
        import socket
        mock_urlopen.side_effect = ConnectionRefusedError("Connection refused")

        result = http_probe("https://offline.example.com")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertIn("refused", result["reason"].lower())

    def test_generic_exception(self, mock_urlopen):
        mock_urlopen.side_effect = RuntimeError("Unexpected error")

        result = http_probe("https://broken.example.com")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], 0)
        self.assertEqual(result["body"], "")


class TestHttpProbeLimiter(unittest.TestCase):
    """Test that limiter is called when provided."""

    @patch('reconpro.http_layer.urllib.request.urlopen')
    def test_limiter_acquire_called(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = []
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        limiter = MagicMock(spec=RateLimiter)
        http_probe("https://example.com", limiter=limiter)
        limiter.acquire.assert_called_once()

    @patch('reconpro.http_layer.urllib.request.urlopen')
    def test_no_limiter_no_call(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.reason = "OK"
        mock_resp.headers.items.return_value = []
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        # Should not raise even without limiter
        result = http_probe("https://example.com")
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
