"""Async HTTP engine for ReconPro v11.0.

Architecture
────────────
This module provides a fully async HTTP layer that replaces the synchronous
urllib-based approach in ``http_layer.py`` for high-throughput scanning.  It is
designed as a **drop-in enhancement** — callers that prefer the old sync
API can use :func:`probe_sync` which transparently runs the async path
inside a fresh event loop.

Components
──────────
1. **AsyncSession** — wraps ``aiohttp.ClientSession`` with connection pooling,
   redirect-chain recording, per-target cookie jars, and an automatic sync
   fallback when ``aiohttp`` is not installed.
2. **AdaptiveLimiter** — token-bucket rate limiter with exponential-moving-
   average tracking of response times, error rates, and timeout rates.
   Automatically backs off on 429/503, recovers on fast responses, and
   maintains per-domain state.  Includes hostname cache to avoid
   redundant urlparse calls on repeated URLs.
3. **async_probe()** — async equivalent of ``http_probe()`` returning a
   rich result dict compatible with the existing ``Finding`` dataclass.
4. **probe_sync()** — synchronous wrapper for backward compatibility.
5. **batch_probe()** — concurrent URL probing with ``asyncio.gather`` and
   per-domain rate limiting.

Performance notes (v10.1)
───────────────────────────
  - DEFAULT_HEADERS.copy() used instead of dict(DEFAULT_HEADERS) for
    faster C-level copy path.
  - Hostname cache in AdaptiveLimiter avoids repeated urlparse() on
    the same URLs during high-throughput scanning.
  - Header merge short-circuits when no extra headers are provided.

No direct imports from ``.http`` are used to avoid circular dependencies.
The ``Finding`` dataclass can be imported separately where needed.
"""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import time
import urllib.error
import urllib.request
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .http_layer import _unverified_context

# Optional dependency — gracefully degrade when missing.
try:
    import aiohttp
    from aiohttp import CookieJar
    _HAS_AIOHTTP = True
except ImportError:  # pragma: no cover
    _HAS_AIOHTTP = False

logger = logging.getLogger(__name__)

# Reuse the canonical User-Agent string from constants.
UA = None  # imported below
from .constants import USER_AGENT as UA  # noqa: E402

DEFAULT_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json,text/html,text/plain,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Maximum body size we will capture (same as sync layer).
_BODY_LIMIT = 16384


# ── Adaptive Limiter ────────────────────────────────────────────────────


class _DomainLimiter:
    """Per-domain rate-limit state tracked by AdaptiveLimiter."""

    __slots__ = (
        "tokens",
        "max_tokens",
        "current_rps",
        "last_refill",
        "response_time_ema",
        "error_rate_ema",
        "timeout_count",
        "total_requests",
        "concurrent_limit",
        "last_backoff",
    )

    def __init__(self, rps: float, max_concurrent: int = 50) -> None:
        self.tokens: float = rps
        self.max_tokens: float = rps * 2.0
        self.current_rps: float = rps
        self.last_refill: float = time.monotonic()
        self.response_time_ema: float = 0.0
        self.error_rate_ema: float = 0.0
        self.timeout_count: int = 0
        self.total_requests: int = 0
        self.concurrent_limit: int = max_concurrent
        self.last_backoff: float = 0.0


class AdaptiveLimiter:
    """Token-bucket rate limiter with adaptive back-off and recovery.

    Tracks per-domain response-time EMA, error-rate EMA, and timeout
    frequency to dynamically adjust throughput.  Thread-safe.

    Parameters
    ----------
    min_rps : float
        Minimum allowed requests per second per domain.
    max_rps : float
        Maximum allowed requests per second per domain.
    backoff_factor : float
        Multiplier applied to rate on back-pressure signals (429/503).
    recovery_time : float
        Seconds of calm before the limiter begins ramping back up.
    """

    def __init__(
        self,
        min_rps: float = 1.0,
        max_rps: float = 100.0,
        backoff_factor: float = 0.5,
        recovery_time: float = 5.0,
    ) -> None:
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_factor = backoff_factor
        self.recovery_time = recovery_time
        self._alpha = 0.3  # EMA smoothing factor
        self._lock = Lock()
        self._domains: Dict[str, _DomainLimiter] = {}
        # Hostname cache: avoid repeated urlparse() on the same URLs.
        self._hostname_cache: Dict[str, str] = {}

    # ── public helpers ───────────────────────────────────────────────

    def _get_domain(self, url: str) -> str:
        cached = self._hostname_cache.get(url)
        if cached is not None:
            return cached
        parsed = urlparse(url)
        hostname = parsed.hostname or "unknown"
        self._hostname_cache[url] = hostname
        return hostname

    def _get_or_create(self, domain: str) -> _DomainLimiter:
        if domain not in self._domains:
            self._domains[domain] = _DomainLimiter(rps=self.max_rps)
        return self._domains[domain]

    async def acquire(self, url: str) -> None:
        """Wait until a token is available for *url*."""
        domain = self._get_domain(url)
        with self._lock:
            dl = self._get_or_create(domain)
        await self._wait_for_token(dl)

    def acquire_sync(self, url: str) -> None:
        """Synchronous acquire — blocks until a token is available."""
        domain = self._get_domain(url)
        with self._lock:
            dl = self._get_or_create(domain)
        self._wait_for_token_sync(dl)

    def record_response(
        self,
        url: str,
        status: int,
        response_time: float,
        timed_out: bool = False,
    ) -> None:
        """Update limiter state based on the response outcome."""
        domain = self._get_domain(url)
        with self._lock:
            dl = self._get_or_create(domain)
            dl.total_requests += 1

            # Update response time EMA.
            if dl.response_time_ema == 0.0:
                dl.response_time_ema = response_time
            else:
                dl.response_time_ema = (
                    self._alpha * response_time
                    + (1 - self._alpha) * dl.response_time_ema
                )

            # Update error rate EMA (error = 4xx/5xx excluding 429/503).
            is_error = 400 <= status < 600 and status not in (429, 503)
            if dl.total_requests <= 1:
                dl.error_rate_ema = 1.0 if is_error else 0.0
            else:
                dl.error_rate_ema = (
                    self._alpha * (1.0 if is_error else 0.0)
                    + (1 - self._alpha) * dl.error_rate_ema
                )

            # Handle back-pressure signals: 429 or 503.
            if status in (429, 503):
                dl.current_rps = max(
                    self.min_rps, dl.current_rps * self.backoff_factor
                )
                dl.last_backoff = time.monotonic()
                logger.debug(
                    "AdaptiveLimiter back-off for %s: rate→%.1f rps (status %d)",
                    domain, dl.current_rps, status,
                )

            # Handle timeout — reduce concurrency.
            if timed_out:
                dl.timeout_count += 1
                dl.concurrent_limit = max(
                    1, int(dl.concurrent_limit * 0.75)
                )
                dl.last_backoff = time.monotonic()
                logger.debug(
                    "AdaptiveLimiter timeout for %s: concurrency→%d",
                    domain, dl.concurrent_limit,
                )

            # Recovery: on fast responses, slowly ramp up.
            if response_time < 0.2 and status < 400:
                now = time.monotonic()
                if (now - dl.last_backoff) > self.recovery_time:
                    new_rps = dl.current_rps * 1.1
                    dl.current_rps = min(self.max_rps, new_rps)
                    dl.timeout_count = max(0, dl.timeout_count - 1)
                    dl.concurrent_limit = min(
                        50, dl.concurrent_limit + 1
                    )

            # Refill tokens to reflect new rate.
            dl.max_tokens = dl.current_rps * 2.0
            if dl.tokens > dl.max_tokens:
                dl.tokens = dl.max_tokens

    def get_domain_stats(self, domain: str) -> Dict[str, Any]:
        """Return diagnostic stats for a domain."""
        with self._lock:
            dl = self._domains.get(domain)
            if dl is None:
                return {}
            return {
                "current_rps": round(dl.current_rps, 2),
                "response_time_ema": round(dl.response_time_ema, 4),
                "error_rate_ema": round(dl.error_rate_ema, 4),
                "timeout_count": dl.timeout_count,
                "total_requests": dl.total_requests,
                "concurrent_limit": dl.concurrent_limit,
            }

    # ── internal ─────────────────────────────────────────────────────

    def _refill(self, dl: _DomainLimiter) -> None:
        """Add tokens based on elapsed time and current rate."""
        now = time.monotonic()
        elapsed = now - dl.last_refill
        if elapsed > 0:
            dl.tokens = min(
                dl.max_tokens, dl.tokens + elapsed * dl.current_rps
            )
            dl.last_refill = now

    async def _wait_for_token(self, dl: _DomainLimiter) -> None:
        """Async token wait with jitter on recent back-off."""
        while True:
            with self._lock:
                self._refill(dl)
                if dl.tokens >= 1.0:
                    dl.tokens -= 1.0
                    break
                wait = (1.0 - dl.tokens) / max(dl.current_rps, 0.1)
            # Add jitter if we recently backed off.
            if (time.monotonic() - dl.last_backoff) < self.recovery_time:
                wait += random.uniform(0.1, 0.5)
            await asyncio.sleep(min(wait, 2.0))

    def _wait_for_token_sync(self, dl: _DomainLimiter) -> None:
        """Synchronous token wait with jitter on recent back-off."""
        while True:
            with self._lock:
                self._refill(dl)
                if dl.tokens >= 1.0:
                    dl.tokens -= 1.0
                    break
                wait = (1.0 - dl.tokens) / max(dl.current_rps, 0.1)
            if (time.monotonic() - dl.last_backoff) < self.recovery_time:
                wait += random.uniform(0.1, 0.5)
            time.sleep(min(wait, 2.0))

    def close(self) -> None:
        """Release resources held by the limiter."""


# Module-level default limiter.
default_adaptive_limiter = AdaptiveLimiter()


# ── Async Session ──────────────────────────────────────────────────────


class AsyncSession:
    """Async HTTP session with connection pooling, redirect tracking, and
    an automatic sync fallback when ``aiohttp`` is not installed.

    Parameters
    ----------
    verify_ssl : bool
        Whether to verify TLS certificates.
    timeout : int
        Default request timeout in seconds.
    max_redirects : int
        Maximum number of redirects to follow.
    max_connections : int
        Connection pool size for aiohttp.
    keepalive : int
        TCP keep-alive timeout in seconds.
    """

    def __init__(
        self,
        verify_ssl: bool = True,
        timeout: int = 10,
        max_redirects: int = 10,
        max_connections: int = 1000,
        keepalive: int = 30,
    ) -> None:
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._aio_session: Optional[Any] = None
        self._sync_ssl_ctx: Optional[ssl.SSLContext] = None

        if _HAS_AIOHTTP:
            cookie_jar = CookieJar(unsafe=True)
            connector = aiohttp.TCPConnector(
                limit=max_connections,
                keepalive_timeout=keepalive,
                ssl=False if not verify_ssl else None,
            )
            self._aio_session = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=cookie_jar,
                timeout=aiohttp.ClientTimeout(total=timeout),
            )
        else:
            # Prepare a reusable ssl context for the sync fallback.
            if verify_ssl:
                self._sync_ssl_ctx = ssl.create_default_context()
            else:
                # audited opt-out helper (explicit user choice only)
                self._sync_ssl_ctx = _unverified_context()

    # ── public async methods ─────────────────────────────────────────

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Perform an async GET request."""
        return await self.request("GET", url, headers=headers, **kwargs)

    async def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Perform an async POST request."""
        return await self.request(
            "POST", url, headers=headers, data=body, **kwargs
        )

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Perform an async HEAD request."""
        return await self.request("HEAD", url, headers=headers, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Perform an async HTTP request with redirect-chain tracking.

        Returns an ``AsyncProbeResult`` dict with keys: ok, status,
        reason, headers, body, url, redirect_chain, response_time,
        ssl_info.
        """
        # Short-circuit: use DEFAULT_HEADERS directly when no extras.
        if headers:
            merged = DEFAULT_HEADERS.copy()
            merged.update(headers)
        else:
            merged = DEFAULT_HEADERS

        if _HAS_AIOHTTP and self._aio_session is not None:
            return await self._aio_request(
                method, url, merged, body, **kwargs
            )
        else:
            # Sync fallback — run urllib in a thread to keep the API async.
            return await self._sync_request(method, url, merged, body)

    async def close(self) -> None:
        """Close the underlying aiohttp session (no-op for sync fallback)."""
        if self._aio_session is not None:
            await self._aio_session.close()
            self._aio_session = None

    async def __aenter__(self) -> AsyncSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ── aiohttp path ─────────────────────────────────────────────────

    async def _aio_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute request via aiohttp, following redirects manually."""
        redirect_chain: List[Dict[str, Any]] = []
        current_url = url
        session = self._aio_session
        assert session is not None  # noqa: S101

        for _ in range(self.max_redirects + 1):
            t0 = time.monotonic()
            try:
                # Determine if this is the final hop.
                allow_redirects = False
                async with session.request(
                    method,
                    current_url,
                    headers=headers,
                    data=body if method.upper() != "GET" else None,
                    allow_redirects=allow_redirects,
                    ssl=False if not self.verify_ssl else None,
                    **kwargs,
                ) as resp:
                    elapsed = time.monotonic() - t0
                    ssl_info = self._extract_ssl_info(session, current_url)

                    # Collect response data.
                    resp_body = await resp.read()
                    status = resp.status
                    reason = resp.reason or ""
                    resp_headers = dict(resp.headers.items())
                    body_str = resp_body.decode("utf-8", errors="replace")[
                        :_BODY_LIMIT
                    ]

                    # Handle redirects.
                    if status in (301, 302, 303, 307, 308):
                        location = resp_headers.get("Location", "")
                        if not location:
                            break
                        # Resolve relative URLs.
                        next_url = urljoin(current_url, location)
                        redirect_chain.append({
                            "url": current_url,
                            "status": status,
                            "location": next_url,
                            "response_time": elapsed,
                        })
                        current_url = next_url
                        # For 303, switch to GET.
                        if status == 303:
                            method = "GET"
                            body = None
                        continue

                    return self._build_result(
                        ok=status < 400,
                        status=status,
                        reason=reason,
                        headers=resp_headers,
                        body=body_str,
                        url=current_url,
                        redirect_chain=redirect_chain,
                        response_time=elapsed,
                        ssl_info=ssl_info,
                    )

            except asyncio.TimeoutError:
                elapsed = time.monotonic() - t0
                return self._build_result(
                    ok=False, status=0, reason="Timeout",
                    headers={}, body="", url=current_url,
                    redirect_chain=redirect_chain,
                    response_time=elapsed, ssl_info={},
                )
            except Exception as exc:
                elapsed = time.monotonic() - t0
                return self._build_result(
                    ok=False, status=0, reason=str(exc),
                    headers={}, body="", url=current_url,
                    redirect_chain=redirect_chain,
                    response_time=elapsed, ssl_info={},
                )

        # Exceeded max redirects.
        return self._build_result(
            ok=False, status=0, reason="Too many redirects",
            headers={}, body="", url=current_url,
            redirect_chain=redirect_chain, response_time=0.0, ssl_info={},
        )

    # ── sync fallback path ───────────────────────────────────────────

    async def _sync_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
    ) -> Dict[str, Any]:
        """Run a synchronous urllib request in a thread."""
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            self._sync_request_impl,
            method, url, headers, body,
        )
        return result

    def _sync_request_impl(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
    ) -> Dict[str, Any]:
        """Blocking urllib implementation with manual redirect following."""
        redirect_chain: List[Dict[str, Any]] = []
        current_url = url
        ctx = self._sync_ssl_ctx
        assert ctx is not None  # noqa: S101

        for _ in range(self.max_redirects + 1):
            t0 = time.monotonic()
            req = urllib.request.Request(
                current_url, data=body, method=method, headers=headers,
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.timeout, context=ctx,
                ) as resp:
                    elapsed = time.monotonic() - t0
                    raw = resp.read(_BODY_LIMIT)
                    status = resp.status
                    reason = resp.reason
                    resp_headers = dict(resp.headers.items())
                    body_str = raw.decode("utf-8", errors="replace")
                    return self._build_result(
                        ok=status < 400,
                        status=status,
                        reason=reason or "",
                        headers=resp_headers,
                        body=body_str,
                        url=current_url,
                        redirect_chain=redirect_chain,
                        response_time=elapsed,
                        ssl_info=self._sync_ssl_info(current_url),
                    )
            except urllib.error.HTTPError as exc:
                elapsed = time.monotonic() - t0
                try:
                    raw = exc.read(_BODY_LIMIT)
                    body_str = raw.decode("utf-8", errors="replace")
                except Exception:
                    body_str = ""

                # Handle redirects that urllib exposes as errors.
                if exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get("Location", "") if exc.headers else ""
                    if location:
                        next_url = urljoin(current_url, location)
                        redirect_chain.append({
                            "url": current_url,
                            "status": exc.code,
                            "location": next_url,
                            "response_time": elapsed,
                        })
                        current_url = next_url
                        if exc.code == 303:
                            method = "GET"
                            body = None
                        continue

                resp_headers = (
                    dict(exc.headers.items()) if exc.headers else {}
                )
                return self._build_result(
                    ok=False,
                    status=exc.code,
                    reason=str(exc.reason),
                    headers=resp_headers,
                    body=body_str,
                    url=current_url,
                    redirect_chain=redirect_chain,
                    response_time=elapsed,
                    ssl_info={},
                )
            except Exception as exc:
                elapsed = time.monotonic() - t0
                return self._build_result(
                    ok=False, status=0, reason=str(exc),
                    headers={}, body="", url=current_url,
                    redirect_chain=redirect_chain,
                    response_time=elapsed, ssl_info={},
                )

        return self._build_result(
            ok=False, status=0, reason="Too many redirects",
            headers={}, body="", url=current_url,
            redirect_chain=redirect_chain, response_time=0.0, ssl_info={},
        )

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_result(
        ok: bool,
        status: int,
        reason: str,
        headers: Dict[str, str],
        body: str,
        url: str,
        redirect_chain: List[Dict[str, Any]],
        response_time: float,
        ssl_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Construct a normalised result dict."""
        return {
            "ok": ok,
            "status": status,
            "reason": reason,
            "headers": headers,
            "body": body,
            "url": url,
            "redirect_chain": redirect_chain,
            "response_time": response_time,
            "ssl_info": ssl_info,
        }

    @staticmethod
    def _extract_ssl_info(
        session: Any, url: str,
    ) -> Dict[str, Any]:
        """Pull TLS certificate details from the aiohttp connector."""
        try:
            conn = session.connector
            if conn is None:
                return {}
            # Access the internal connection for certificate info.
            # This is best-effort; many connectors don't expose it.
            return {"version": "TLS", "verified": True}
        except Exception:
            return {}

    @staticmethod
    def _sync_ssl_info(url: str) -> Dict[str, Any]:
        """Return basic SSL info for the sync path (best-effort)."""
        return {"version": "TLS", "verified": True}


# ── async_probe ─────────────────────────────────────────────────────────


# DEAD CODE: consider removal
async def async_probe(
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
    limiter: Optional[AdaptiveLimiter] = None,
    session: Optional[AsyncSession] = None,
) -> Dict[str, Any]:
    """Async equivalent of :func:`http.http_probe`.

    Returns a dict compatible with the ``Finding`` creation pattern::

        {
            "ok": bool,
            "status": int,
            "reason": str,
            "headers": dict,
            "body": str,
            "url": str,
            "redirect_chain": list,
            "response_time": float,
            "ssl_info": dict,
        }

    Parameters
    ----------
    url : str
        Target URL.
    method : str
        HTTP method (GET, POST, HEAD, …).
    body : bytes | None
        Request body.
    headers : dict | None
        Extra headers merged onto the defaults.
    timeout : int
        Timeout in seconds.
    verify_ssl : bool
        Verify TLS certificates.
    limiter : AdaptiveLimiter | None
        Rate limiter instance.  Uses the module default if ``None``.
    session : AsyncSession | None
        Reusable session.  A fresh one is created and closed if ``None``.
    """
    _limiter = limiter or default_adaptive_limiter
    own_session = session is None
    _session = session or AsyncSession(
        verify_ssl=verify_ssl, timeout=timeout,
    )

    try:
        await _limiter.acquire(url)
        result = await _session.request(
            method, url, headers=headers,
            body=body if method.upper() != "GET" else None,
        )
        # Feed response metrics back to the limiter.
        _limiter.record_response(
            url,
            status=result.get("status", 0),
            response_time=result.get("response_time", 0.0),
            timed_out=(result.get("reason") == "Timeout"),
        )
        return result
    except asyncio.TimeoutError:
        timed_out = True
        _limiter.record_response(url, status=0, response_time=float(timeout), timed_out=True)
        return {
            "ok": False, "status": 0, "reason": "Timeout",
            "headers": {}, "body": "", "url": url,
            "redirect_chain": [], "response_time": float(timeout),
            "ssl_info": {},
        }
    except Exception as exc:
        _limiter.record_response(url, status=0, response_time=0.0, timed_out=False)
        return {
            "ok": False, "status": 0, "reason": str(exc),
            "headers": {}, "body": "", "url": url,
            "redirect_chain": [], "response_time": 0.0, "ssl_info": {},
        }
    finally:
        if own_session:
            await _session.close()


# ── probe_sync ──────────────────────────────────────────────────────────


# DEAD CODE: consider removal
def probe_sync(
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
    limiter: Optional[AdaptiveLimiter] = None,
) -> Dict[str, Any]:
    """Synchronous wrapper around :func:`async_probe`.

    Creates (and closes) a fresh event loop for each call, making it
    safe to use from existing synchronous modules without any async
    boilerplate.

    Optimisation: when not already inside an event loop, calls asyncio.run
    directly — the ThreadPoolExecutor fallback is only used when an
    existing loop is detected.
    """
    try:
        asyncio.get_running_loop()
        # Already inside a running loop — fall back to a thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                async_probe(
                    url, method=method, body=body, headers=headers,
                    timeout=timeout, verify_ssl=verify_ssl,
                    limiter=limiter,
                ),
            )
            return future.result()
    except RuntimeError:
        # No running loop — safe to call asyncio.run directly.
        return asyncio.run(
            async_probe(
                url, method=method, body=body, headers=headers,
                timeout=timeout, verify_ssl=verify_ssl,
                limiter=limiter,
            ),
        )


# ── batch_probe ─────────────────────────────────────────────────────────


async def batch_probe(
    urls: List[str],
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
    concurrency: int = 50,
    limiter: Optional[AdaptiveLimiter] = None,
) -> List[Dict[str, Any]]:
    """Probe a list of URLs concurrently with per-domain rate limiting.

    Parameters
    ----------
    urls : list[str]
        URLs to probe.
    method : str
        HTTP method for all requests.
    headers : dict | None
        Extra headers.
    timeout : int
        Per-request timeout in seconds.
    verify_ssl : bool
        Verify TLS certificates.
    concurrency : int
        Maximum number of in-flight requests (semaphore bound).
    limiter : AdaptiveLimiter | None
        Shared rate limiter.  Uses the module default if ``None``.

    Returns
    -------
    list[dict]
        Results in the **same order** as *urls*.
    """
    _limiter = limiter or default_adaptive_limiter
    semaphore = asyncio.Semaphore(concurrency)

    # DEAD CODE: consider removal
    async def _bounded_probe(url: str) -> Dict[str, Any]:
        """Probe a single URL under the concurrency semaphore."""
        async with semaphore:
            return await async_probe(
                url,
                method=method,
                headers=headers,
                timeout=timeout,
                verify_ssl=verify_ssl,
                limiter=_limiter,
            )

    tasks = [_bounded_probe(u) for u in urls]
    return list(await asyncio.gather(*tasks, return_exceptions=False))


def batch_probe_sync(
    urls: List[str],
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    verify_ssl: bool = True,
    concurrency: int = 50,
    limiter: Optional[AdaptiveLimiter] = None,
) -> List[Dict[str, Any]]:
    """Synchronous wrapper around :func:`batch_probe`.

    Runs the full async batch inside a fresh event loop.
    """
    return asyncio.run(
        batch_probe(
            urls, method=method, headers=headers,
            timeout=timeout, verify_ssl=verify_ssl,
            concurrency=concurrency, limiter=limiter,
        ),
    )
