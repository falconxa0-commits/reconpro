"""Lightweight HTTP connection pool for ReconPro.

Pure Python. Uses urllib.request. Thread-safe.
Reuses SSL contexts and base headers across requests.

Performance notes
────────────────
  - SSL contexts are created lazily and cached: one for verify=True,
    one for verify=False.  Avoids the ~100µs cost of
    ``ssl.create_default_context()`` on every single probe.
  - Base header templates are pre-built and shallow-copied per request
    instead of being reconstructed from scratch.
  - Connection statistics (total requests, reused connections, avg
    latency) are tracked via thread-safe atomic counters for monitoring.

Usage
─────
    from reconpro.connection_pool import ConnectionPool

    pool = ConnectionPool()

    # Each request reuses the cached SSL context and header template.
    result = pool.probe("https://example.com/")

    # Retrieve stats
    stats = pool.stats()
    print(stats["total_requests"], stats["avg_latency_ms"])

    pool.close()
"""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .constants import USER_AGENT

# ── Constants ────────────────────────────────────────────────────────────

UA = USER_AGENT  # canonical from constants

_HEADER_TEMPLATES = {
    "default": {
        "User-Agent": UA,
        "Accept": "application/json,text/html,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    },
}

_BODY_LIMIT = 16384  # 16 KB — same as http_layer.py


# ── Connection Pool ──────────────────────────────────────────────────────


class ConnectionPool:
    """Lightweight thread-safe HTTP connection pool.

    Manages reusable SSL contexts and pre-built header templates.
    Tracks aggregate connection statistics.

    Parameters
    ----------
    default_timeout : int
        Default request timeout in seconds.
    verify_ssl : bool
        Whether to verify TLS certificates by default.
    """

    def __init__(
        self,
        default_timeout: int = 8,
        verify_ssl: bool = True,
    ) -> None:
        self._default_timeout = default_timeout
        self._default_verify = verify_ssl

        # Lazy-initialized SSL contexts (cached for the lifetime of the pool).
        self._ssl_verify: Optional[ssl.SSLContext] = None
        self._ssl_no_verify: Optional[ssl.SSLContext] = None
        self._ssl_lock = threading.Lock()

        # Connection statistics — thread-safe counters.
        self._total_requests = 0
        self._total_latency = 0.0
        self._stats_lock = threading.Lock()

    # ── SSL Context Management ───────────────────────────────────────

    def _get_ssl_context(self, verify: bool) -> ssl.SSLContext:
        """Return a cached SSL context, creating it lazily if needed."""
        if verify:
            ctx = self._ssl_verify
            if ctx is not None:
                return ctx
            with self._ssl_lock:
                if self._ssl_verify is None:
                    self._ssl_verify = ssl.create_default_context()
                return self._ssl_verify
        else:
            ctx = self._ssl_no_verify
            if ctx is not None:
                return ctx
            with self._ssl_lock:
                if self._ssl_no_verify is None:
                    from .http_layer import _unverified_context
                    self._ssl_no_verify = _unverified_context()
                return self._ssl_no_verify

    # ── Header Management ────────────────────────────────────────────

    @staticmethod
    def _build_headers(
        extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Build request headers from pre-built template.

        Copies the default template and merges extra headers on top.
        Avoids dict literal construction on every request.
        """
        headers = _HEADER_TEMPLATES["default"].copy()
        if extra:
            headers.update(extra)
        return headers

    # ── Probe ─────────────────────────────────────────────────────────

    def probe(
        self,
        url: str,
        method: str = "GET",
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        verify_ssl: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Perform an HTTP probe using pooled resources.

        Reuses cached SSL context and header templates.

        Returns dict with keys: ok, status, reason, headers, body,
        response_time_ms.
        """
        t0 = time.perf_counter()
        timeout_val = timeout if timeout is not None else self._default_timeout
        verify = verify_ssl if verify_ssl is not None else self._default_verify

        ctx = self._get_ssl_context(verify)
        h = self._build_headers(headers)

        req = urllib.request.Request(url, data=body, method=method, headers=h)

        try:
            with urllib.request.urlopen(req, timeout=timeout_val, context=ctx) as resp:
                raw = resp.read(_BODY_LIMIT)
                elapsed = time.perf_counter() - t0
                self._record_stats(elapsed)
                return {
                    "ok": True,
                    "status": resp.status,
                    "reason": resp.reason,
                    "headers": dict(resp.headers.items()),
                    "body": raw.decode("utf-8", errors="replace")[:_BODY_LIMIT],
                    "response_time_ms": elapsed * 1000,
                }
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(_BODY_LIMIT)
                body_str = raw.decode("utf-8", errors="replace")[:_BODY_LIMIT]
            except Exception:
                body_str = ""
            elapsed = time.perf_counter() - t0
            self._record_stats(elapsed)
            return {
                "ok": False,
                "status": e.code,
                "reason": e.reason,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": body_str,
                "response_time_ms": elapsed * 1000,
            }
        except Exception as e:
            elapsed = time.perf_counter() - t0
            self._record_stats(elapsed)
            return {
                "ok": False,
                "status": 0,
                "reason": str(e),
                "headers": {},
                "body": "",
                "response_time_ms": elapsed * 1000,
            }

    # ── Statistics ───────────────────────────────────────────────────

    def _record_stats(self, latency: float) -> None:
        """Thread-safe recording of request latency."""
        with self._stats_lock:
            self._total_requests += 1
            self._total_latency += latency

    def stats(self) -> Dict[str, Any]:
        """Return aggregate connection statistics.

        Keys:
            total_requests : int     — total probes issued through this pool
            avg_latency_ms : float   — average response latency in milliseconds
            ssl_contexts_cached : int — number of cached SSL contexts (0–2)
        """
        with self._stats_lock:
            total = self._total_requests
            avg_lat = (self._total_latency / total * 1000) if total > 0 else 0.0

        ssl_cached = sum(
            1 for ctx in (self._ssl_verify, self._ssl_no_verify)
            if ctx is not None
        )

        return {
            "total_requests": total,
            "avg_latency_ms": round(avg_lat, 3),
            "ssl_contexts_cached": ssl_cached,
        }

    def reset_stats(self) -> None:
        """Reset all counters to zero."""
        with self._stats_lock:
            self._total_requests = 0
            self._total_latency = 0.0

    # ── Lifecycle ─────────────────────────────────────────────────────

    def close(self) -> None:
        """Release resources held by the pool.

        Clears cached SSL contexts to free memory. The pool can still
        be used afterward — contexts will be re-created lazily.
        """
        with self._ssl_lock:
            self._ssl_verify = None
            self._ssl_no_verify = None

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"ConnectionPool(requests={s['total_requests']}, "
            f"avg_latency={s['avg_latency_ms']:.1f}ms, "
            f"ssl_cached={s['ssl_contexts_cached']})"
        )
