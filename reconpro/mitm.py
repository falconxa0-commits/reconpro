"""
ReconPro v8.5 — Live Traffic Interception

MITM proxy using stdlib http.server, with traffic replay and
session analysis for discovering exposed tokens, missing auth,
and sensitive data leakage.

Exports:
    ProxyInterceptor  – MITM HTTP proxy server
    TrafficReplay     – replay requests with modifications
    SessionAnalysis   – analyze captured traffic for security issues
"""

from __future__ import annotations

import base64
import json
import re
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Sensitive data patterns ─────────────────────────────────────────

TOKEN_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "high"),
    ("API Key", re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-]{20,})[\'\"]?", re.I), "high"),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?"), "critical"),
    ("GitHub Token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"), "high"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "medium"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9A-Za-z]{24,}"), "high"),
    ("Stripe Key", re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"), "critical"),
    ("Session ID", re.compile(r"(?:sessionid|session_id|sid|jsessionid)\s*[=:]\s*[\'\"]?([A-Za-z0-9\-]{20,})", re.I), "medium"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "high"),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("Auth Basic", re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"), "medium"),
    ("Cookie Auth", re.compile(r"(?:auth|token|session)\s*=[A-Za-z0-9\-._~%/+]{20,}", re.I), "medium"),
]

SENSITIVE_QUERY_PARAMS = {
    "api_key", "apikey", "key", "token", "secret", "password", "passwd",
    "access_token", "auth_token", "session_token", "private_key",
    "client_secret", "refresh_token", "id_token",
}

MAX_BODY_SIZE = 10240  # 10KB


# ══════════════════════════════════════════════════════════════════════
# ProxyInterceptor
# ══════════════════════════════════════════════════════════════════════

class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler that proxies and logs all traffic."""

    _captured: List[Dict[str, Any]] = []
    _api_endpoints: List[str] = []
    _lock = threading.Lock()
    _on_request: Optional[Callable] = None
    _on_response: Optional[Callable] = None

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging
        pass

    def _relay(self) -> None:
        """Read the full request, forward it, capture and relay the response."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(min(content_length, MAX_BODY_SIZE)) if content_length > 0 else b""

        # Build the target URL
        host = self.headers.get("Host", "")
        scheme = "https"
        if hasattr(self, "_proxy_scheme"):
            scheme = self._proxy_scheme
        target_url = f"{scheme}://{host}{self.path}"

        # Capture request
        req_headers = {k: v for k, v in self.headers.items()}
        body_str = body.decode("utf-8", errors="replace")[:MAX_BODY_SIZE]

        # Auto-discover API endpoints
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith(("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
            with _ProxyHandler._lock:
                if target_url not in _ProxyHandler._api_endpoints:
                    _ProxyHandler._api_endpoints.append(target_url)

        # Forward the request
        resp_status = 0
        resp_headers: Dict[str, str] = {}
        resp_body = b""

        try:
            req = urllib.request.Request(target_url, data=body if body else None, method=self.command)
            for k, v in self.headers.items():
                if k.lower() not in ("host", "connection", "proxy-connection", "proxy-authorization"):
                    try:
                        req.add_header(k, v)
                    except Exception:
                        pass

            try:
                response = urllib.request.urlopen(req, timeout=30)
                resp_status = response.status
                resp_headers = dict(response.headers)
                resp_body = response.read(MAX_BODY_SIZE)
            except urllib.error.HTTPError as e:
                resp_status = e.code
                resp_headers = dict(e.headers) if e.headers else {}
                try:
                    resp_body = e.read(MAX_BODY_SIZE)
                except Exception:
                    resp_body = b""
        except Exception:
            resp_status = 502
            resp_body = b"Bad Gateway"

        resp_body_str = resp_body.decode("utf-8", errors="replace")[:MAX_BODY_SIZE]

        # Store captured data
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "url": target_url,
            "path": self.path,
            "query": parsed.query,
            "request_headers": req_headers,
            "request_body": body_str,
            "response_status": resp_status,
            "response_headers": resp_headers,
            "response_body": resp_body_str,
            "content_type": resp_headers.get("Content-Type", ""),
        }
        with _ProxyHandler._lock:
            _ProxyHandler._captured.append(entry)

        if _ProxyHandler._on_request:
            _ProxyHandler._on_request(entry)
        if _ProxyHandler._on_response:
            _ProxyHandler._on_response(entry)

        # Send response back to client
        self.send_response(resp_status)
        for k, v in resp_headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "proxy-connection"):
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self) -> None:
        self._relay()

    def do_POST(self) -> None:
        self._relay()

    def do_PUT(self) -> None:
        self._relay()

    def do_PATCH(self) -> None:
        self._relay()

    def do_DELETE(self) -> None:
        self._relay()

    def do_HEAD(self) -> None:
        self._relay()

    def do_OPTIONS(self) -> None:
        self._relay()


class ProxyInterceptor:
    """Man-in-the-middle HTTP proxy server.

    Intercepts all HTTP traffic, logs requests/responses, and
    auto-discovers API endpoints, auth tokens, and session cookies.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8888) -> None:
        self._host = host
        self._port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"

    def start(self, background: bool = True, on_request: Optional[Callable] = None, on_response: Optional[Callable] = None) -> None:
        """Start the MITM proxy server.

        Parameters
        ----------
        background : bool
            If True, runs in a daemon thread.
        on_request, on_response : callable | None
            Callbacks invoked for each captured request/response.
        """
        _ProxyHandler._on_request = on_request
        _ProxyHandler._on_response = on_response

        class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = ThreadedHTTPServer((self._host, self._port), _ProxyHandler)
        self._running = True

        if background:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        else:
            self._server.serve_forever()

    def stop(self) -> None:
        """Stop the proxy server."""
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def get_captured(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return captured request/response entries.

        If *limit* is set, returns the most recent *limit* entries.
        """
        with _ProxyHandler._lock:
            data = list(_ProxyHandler._captured)
        if limit:
            return data[-limit:]
        return data

    def clear_captured(self) -> int:
        """Clear all captured data and return the count of cleared entries."""
        with _ProxyHandler._lock:
            count = len(_ProxyHandler._captured)
            _ProxyHandler._captured.clear()
            return count

    def get_discovered_endpoints(self) -> List[str]:
        """Return auto-discovered API endpoints."""
        with _ProxyHandler._lock:
            return list(_ProxyHandler._api_endpoints)

    def get_tokens(self) -> List[Dict[str, Any]]:
        """Extract all detected auth tokens from captured traffic.

        Returns list of {"type", "value", "source", "severity", "url"}.
        """
        tokens: List[Dict[str, Any]] = []
        seen: set = set()
        for entry in self.get_captured():
            # Check headers
            headers_str = json.dumps(entry.get("request_headers", {}))
            for name, pattern, severity in TOKEN_PATTERNS:
                for match in pattern.finditer(headers_str):
                    value = match.group(0)
                    key = (name, value[:40])
                    if key not in seen:
                        seen.add(key)
                        tokens.append({
                            "type": name,
                            "value": value[:100],
                            "source": "header",
                            "severity": severity,
                            "url": entry.get("url", ""),
                        })

            # Check URL query string
            query = entry.get("query", "")
            for param in SENSITIVE_QUERY_PARAMS:
                if param in query.lower():
                    parsed_qs = urllib.parse.parse_qs(query)
                    for p_name, p_values in parsed_qs.items():
                        if p_name.lower() in SENSITIVE_QUERY_PARAMS and p_values:
                            val = p_values[0][:80]
                            key = ("Query Param", f"{p_name}={val[:20]}")
                            if key not in seen:
                                seen.add(key)
                                tokens.append({
                                    "type": f"Query Param: {p_name}",
                                    "value": val,
                                    "source": "url",
                                    "severity": "high",
                                    "url": entry.get("url", ""),
                                })
        return tokens


# ══════════════════════════════════════════════════════════════════════
# TrafficReplay
# ══════════════════════════════════════════════════════════════════════

class TrafficReplay:
    """Replay captured HTTP requests with modifications.

    Used to test authorization by replaying requests with auth
    headers removed, or to test IDOR by changing parameters.
    """

    def replay_request(
        self,
        original_request: Dict[str, Any],
        modifications: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Replay a captured request with optional modifications.

        Parameters
        ----------
        original_request : dict
            A captured request entry from ProxyInterceptor.
        modifications : dict | None
            Supported keys:
            - "remove_auth" (bool): strip Authorization header
            - "remove_cookies" (bool): strip Cookie header
            - "change_method" (str): override HTTP method
            - "add_headers" (dict): extra headers to add
            - "replace_path" (str): swap the path
            - "replace_params" (dict): replace query parameters

        Returns dict with "original_status", "replay_status", "replay_headers",
        "replay_body", "diff", and "is_different".
        """
        if modifications is None:
            modifications = {}

        url = original_request.get("url", "")
        method = modifications.get("change_method", original_request.get("method", "GET"))
        headers = dict(original_request.get("request_headers", {}))
        body = original_request.get("request_body", "")
        original_status = original_request.get("response_status", 0)

        # Apply modifications
        if modifications.get("remove_auth"):
            headers.pop("Authorization", None)
            headers.pop("authorization", None)

        if modifications.get("remove_cookies"):
            headers.pop("Cookie", None)
            headers.pop("cookie", None)

        if modifications.get("add_headers"):
            headers.update(modifications["add_headers"])

        if modifications.get("replace_path"):
            parsed = urllib.parse.urlparse(url)
            url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, modifications["replace_path"],
                 parsed.params, parsed.query, parsed.fragment)
            )

        if modifications.get("replace_params"):
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs.update(modifications["replace_params"])
            new_query = urllib.parse.urlencode(qs, doseq=True)
            url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path,
                 parsed.params, new_query, parsed.fragment)
            )

        # Execute replay
        replay_status = 0
        replay_headers: Dict[str, str] = {}
        replay_body = ""

        try:
            req = urllib.request.Request(url, data=body.encode() if body else None, method=method)
            for k, v in headers.items():
                if k.lower() not in ("host", "connection", "content-length"):
                    try:
                        req.add_header(k, v)
                    except Exception:
                        pass

            try:
                resp = urllib.request.urlopen(req, timeout=15)
                replay_status = resp.status
                replay_headers = dict(resp.headers)
                replay_body = resp.read(MAX_BODY_SIZE).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                replay_status = e.code
                replay_headers = dict(e.headers) if e.headers else {}
                try:
                    replay_body = e.read(MAX_BODY_SIZE).decode("utf-8", errors="replace")
                except Exception:
                    replay_body = ""
        except Exception as exc:
            replay_status = 0
            replay_body = str(exc)

        is_different = (replay_status != original_status)

        # Build diff summary
        diff_parts = []
        if is_different:
            diff_parts.append(f"Status changed: {original_status} → {replay_status}")
        if modifications.get("remove_auth") and replay_status < 400:
            diff_parts.append(f"ACCESS WITHOUT AUTH: Status {replay_status} (should be 401/403)")

        orig_body = original_request.get("response_body", "")
        if replay_body and orig_body and replay_body != orig_body:
            diff_parts.append("Response body differs")

        return {
            "url": url,
            "method": method,
            "original_status": original_status,
            "replay_status": replay_status,
            "replay_headers": replay_headers,
            "replay_body": replay_body[:MAX_BODY_SIZE],
            "diff": "; ".join(diff_parts) if diff_parts else "No differences",
            "is_different": is_different,
            "modifications_applied": modifications,
        }

    def test_authorization(self, captured: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test all captured requests for missing authorization enforcement.

        Replays each request without auth headers and checks if the
        server still returns a success (2xx) status.

        Returns list of replay results where auth bypass was detected.
        """
        bypasses: List[Dict[str, Any]] = []
        for entry in captured:
            if entry.get("response_status", 0) < 400:
                result = self.replay_request(entry, {"remove_auth": True})
                if result["replay_status"] < 400:
                    result["title"] = f"Auth bypass: {entry.get('method', '')} {entry.get('path', '')}"
                    result["severity"] = "critical" if entry.get("path", "").startswith(("/api/", "/admin/")) else "high"
                    result["category"] = "access_control"
                    result["description"] = (
                        f"Request to {entry.get('path', '')} succeeded ({result['replay_status']}) "
                        f"even after removing Authorization header. "
                        f"Original status: {entry.get('response_status', 0)}."
                    )
                    bypasses.append(result)
        return bypasses


# ══════════════════════════════════════════════════════════════════════
# SessionAnalysis
# ══════════════════════════════════════════════════════════════════════

class SessionAnalysis:
    """Analyze captured HTTP traffic for security issues.

    Detects exposed tokens, missing auth on API calls, sensitive
    data in URLs, and other common web security issues.
    """

    def analyze_session(self, captured_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run full session analysis on captured traffic.

        Returns list of findings, each a dict with at least
        ``title``, ``severity``, ``category``, ``description``, ``url``.
        """
        findings: List[Dict[str, Any]] = []
        seen: set = set()

        for entry in captured_requests:
            url = entry.get("url", "")
            path = entry.get("path", "")
            method = entry.get("method", "GET")
            headers = entry.get("request_headers", {})
            query = entry.get("query", "")
            resp_status = entry.get("response_status", 0)
            resp_body = entry.get("response_body", "")
            req_body = entry.get("request_body", "")

            # 1. Check for tokens in headers
            headers_str = json.dumps(headers)
            for token_name, pattern, severity in TOKEN_PATTERNS:
                for match in pattern.finditer(headers_str):
                    value = match.group(0)[:60]
                    key = ("token_in_header", token_name, value[:20])
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title": f"{token_name} exposed in request header",
                            "severity": severity,
                            "category": "data_protection",
                            "description": (
                                f"A {token_name} was found in the {method} request to {path}. "
                                f"Value (truncated): {value}..."
                            ),
                            "url": url,
                            "remediation": "Use environment variables or secure vaults for secrets. Never log or transmit tokens in plaintext headers in non-HTTPS contexts.",
                        })

            # 2. Check for sensitive data in URLs (query params)
            parsed_qs = urllib.parse.parse_qs(query)
            for param_name, param_values in parsed_qs.items():
                if param_name.lower() in SENSITIVE_QUERY_PARAMS and param_values:
                    key = ("sensitive_query", param_name, path)
                    if key not in seen:
                        seen.add(key)
                        val_preview = param_values[0][:30]
                        findings.append({
                            "title": f"Sensitive parameter '{param_name}' in URL",
                            "severity": "high",
                            "category": "data_protection",
                            "description": (
                                f"The parameter '{param_name}' with a sensitive value was found "
                                f"in the query string of {url}. URLs are logged in server access logs, "
                                f"browser history, and proxy caches."
                            ),
                            "url": url,
                            "remediation": "Move sensitive parameters to the request body or use POST. Consider encrypting values.",
                        })

            # 3. Check for missing auth on API endpoints
            is_api = path.startswith(("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/admin/"))
            has_auth = any(
                k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token")
                for k in headers
            )
            if is_api and not has_auth and resp_status < 400:
                key = ("missing_auth", path)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"API endpoint without authentication: {method} {path}",
                        "severity": "high" if "/admin/" in path else "medium",
                        "category": "access_control",
                        "description": (
                            f"{method} {path} returned {resp_status} without any authentication headers. "
                            f"API endpoints should require authentication."
                        ),
                        "url": url,
                        "remediation": "Implement authentication for all API endpoints. Use token-based auth (Bearer/JWT) with proper validation.",
                    })

            # 4. Check for tokens in response body
            for token_name, pattern, severity in TOKEN_PATTERNS:
                for match in pattern.finditer(resp_body[:5000]):
                    value = match.group(0)[:60]
                    key = ("token_in_response", token_name, value[:20])
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title": f"{token_name} leaked in response body",
                            "severity": severity,
                            "category": "data_protection",
                            "description": (
                                f"A {token_name} was found in the response body of {method} {path}. "
                                f"Tokens should not be embedded in response payloads."
                            ),
                            "url": url,
                            "remediation": "Use HttpOnly, Secure cookies for session tokens. Avoid returning API keys or secrets in response bodies.",
                        })

            # 5. Check for PII in response (email, SSN patterns)
            email_matches = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", resp_body[:10000])
            if len(email_matches) > 5:
                key = ("pii_emails", path)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "title": f"Bulk email addresses in response: {method} {path}",
                        "severity": "medium",
                        "category": "data_protection",
                        "description": f"Response contains {len(email_matches)} email addresses. Verify this is intended and data is properly protected.",
                        "url": url,
                        "remediation": "Ensure PII is only returned when necessary, with proper access controls and audit logging.",
                    })

            # 6. Missing security headers
            resp_headers = entry.get("response_headers", {})
            if path.startswith(("/api/", "/")) and resp_status < 400:
                missing_headers = []
                resp_header_lower = {k.lower(): v for k, v in resp_headers.items()}
                if "x-content-type-options" not in resp_header_lower:
                    missing_headers.append("X-Content-Type-Options")
                if "x-frame-options" not in resp_header_lower:
                    missing_headers.append("X-Frame-Options")
                if "strict-transport-security" not in resp_header_lower and url.startswith("https"):
                    missing_headers.append("Strict-Transport-Security")
                if "content-security-policy" not in resp_header_lower:
                    missing_headers.append("Content-Security-Policy")
                if missing_headers:
                    key = ("missing_headers", tuple(sorted(missing_headers)), path)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "title": f"Missing security headers on {method} {path}",
                            "severity": "low",
                            "category": "configuration",
                            "description": f"Missing headers: {', '.join(missing_headers)}",
                            "url": url,
                            "remediation": f"Add the following security headers: {', '.join(missing_headers)}.",
                        })

        return findings


# Module-level convenience exports
proxy = ProxyInterceptor()
replay = TrafficReplay()
analyzer = SessionAnalysis()
