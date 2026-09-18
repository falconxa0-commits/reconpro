"""Shared HTTP layer used by all ReconPro modules.

Thread-safe rate limiter, hardened probe, TLS config.
"""

from __future__ import annotations

import ssl

from .constants import USER_AGENT as UA
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field  # DEAD CODE: consider removal
from typing import Any, Dict, List, Optional, Tuple
from threading import Lock


# ── Rate Limiter ────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter. Default: 10 req/s."""

    def __init__(self, max_per_second: float = 10.0) -> None:
        self._min_interval = 1.0 / max_per_second
        self._lock = Lock()
        self._last = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self._min_interval:
                delay = self._min_interval - elapsed
            else:
                delay = 0.0
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            self._last = time.monotonic()


default_limiter = RateLimiter(max_per_second=10.0)


# ── TLS contexts (audited choke points) ─────────────────────────────────
#
# SECURITY POLICY — read before touching either helper below.
#
# 1. ``_unverified_context()`` must ONLY be reached behind an explicit
#    user opt-in flag (``--insecure`` / ``-k`` → ``verify_tls=False``).
#    TLS verification is the default everywhere in ReconPro.
# 2. ``inspection_context()`` exists solely for *certificate inspection*
#    (reading a peer certificate's fields/ages/issuers), where chain
#    verification is not the purpose of the connection.  It must never be
#    used for regular data transport.
# 3. No other module may construct an unverified context by hand (no
#    private stdlib unverified-context constructors, no CERT_NONE, and no
#    ``check_hostname = False`` outside this file).  The regression suite
#    (tests/test_security_sweep.py) enforces this via AST.


def _unverified_context() -> ssl.SSLContext:
    """SSL context with certificate verification DISABLED.

    AUDITED HELPER — call only when the user explicitly opted out of TLS
    verification (e.g. ``--insecure`` / ``-k``).  Default behaviour in all
    ReconPro modules is a verified context (``ssl.create_default_context``).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def inspection_context() -> ssl.SSLContext:
    """SSL context for *certificate inspection* connections.

    Used by modules whose job is to read and report certificate details
    (issuer, validity dates, SANs).  Chain verification is intentionally
    disabled for these inspection-only connections — an invalid
    certificate must not prevent *reporting on* the certificate.  This
    context must never back ordinary data transport.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── HTTP Probe ──────────────────────────────────────────────────────────


def http_probe(
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[RateLimiter] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    **kwargs: object,
) -> Dict[str, Any]:
    """Hardened HTTP probe. All modules delegate through this.

    Returns dict with keys: ok, status, reason, headers, body.
    """
    if limiter:
        limiter.acquire()

    h = {
        "User-Agent": UA,
        "Accept": "application/json,text/html,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        h.update(headers)

    req = urllib.request.Request(url, data=body, method=method, headers=h)

    try:
        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            # audited opt-out path (user explicitly passed --insecure/-k)
            ctx = _unverified_context()

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(16384)
            return {
                "ok": True,
                "status": resp.status,
                "reason": resp.reason,
                "headers": dict(resp.headers.items()),
                "body": raw.decode("utf-8", errors="replace")[:16384],
            }
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(16384)
            body_str = raw.decode("utf-8", errors="replace")[:16384]
        except Exception:
            body_str = ""
        return {
            "ok": False,
            "status": e.code,
            "reason": e.reason,
            "headers": dict(e.headers.items()) if e.headers else {},
            "body": body_str,
        }
    except Exception as e:
        return {"ok": False, "status": 0, "reason": str(e), "headers": {}, "body": ""}


# ── Finding helper ──────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding."""
    title: str
    severity: str          # critical, high, medium, low, info
    category: str
    module: str
    description: str
    evidence: str
    asset: str
    points_deducted: int = 0
    remediation: str = ""
    dread_score: float = 0.0
    # Truth layer — every finding carries how much it can be trusted:
    #   confidence:          0.0–1.0 estimate of the finding's reliability
    #   verification_state:  VERIFIED_TARGET | PARTIAL_TARGET | UNREACHABLE_TARGET
    #   (set by target_validation.apply_target_truth after the pipeline runs)
    confidence: float = 0.8
    verification_state: str = "UNVERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "asset": self.asset,
            "points_deducted": self.points_deducted,
            "remediation": self.remediation,
            "dread_score": self.dread_score,
            "confidence": self.confidence,
            "verification_state": self.verification_state,
        }


# ── Grade mapping ───────────────────────────────────────────────────────

GRADE_MAP: List[Tuple[int, str]] = [
    (90, "A+"),
    (80, "A"),
    (65, "B"),
    (50, "C"),
    (35, "D"),
    (0,  "F"),
]


def compute_grade(score: int) -> str:
    for threshold, grade in GRADE_MAP:
        if score >= threshold:
            return grade
    return "F"


def badge_markdown(host: str, grade: str) -> str:
    color_map = {
        "A+": "brightgreen", "A": "green", "B": "yellow",
        "C": "red", "D": "orange", "F": "red",
    }
    c = color_map.get(grade, "lightgrey")
    return (
        f"![ReconPro {grade}]"
        f"(https://img.shields.io/badge/ReconPro-{grade}-{c}"
        f"?style=for-the-badge&labelColor=000000)"
    )
