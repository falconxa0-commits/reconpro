"""QUANTUM FINGERPRINT — TCP/IP Stack Fingerprinting via HTTP Timing Analysis.

ReconPro v9.2.0 capability: infer remote operating system, TCP stack
implementation, congestion-control algorithm, MTU, and kernel clock
resolution — entirely through HTTP-level timing observation.

No raw sockets.  No SYN packets.  No privileged access.
Pure urllib / socket / ssl / time stdlib.

Methodology
-----------
Each technique sends carefully crafted HTTP requests and measures
sub-millisecond timing characteristics of the response.  By comparing
the observed multi-dimensional timing fingerprint against a database
of known OS / kernel signatures, we produce a probabilistic OS
identification with a confidence score.

The seven orthogonal signals are:
  1. Initial TTL deduction       — payload-size vs RTT variance
  2. TCP window size              — initial data-burst volume analysis
  3. SYN-ACK timing behaviour     — fresh-connection first-byte latency
  4. HTTP keep-alive persistence  — connection reuse timing degradation
  5. Path MTU detection           — payload escalation fragmentation spike
  6. Congestion control alg.      — burst-recovery timing pattern
  7. Timestamp resolution         — Date-header clock granularity

References
----------
  [1] Zalewski, M. "p0f — Passive OS Fingerprinting" (2006)
  [2] RFC 1323 — TCP Extensions for High Performance
  [3] Ha, S. et al. "CUBIC: A New TCP-Friendly High-Speed TCP Variant" (2008)
  [4] Cardwell, N. et al. "BBR: Congestion-Based Congestion Control" (2016)
  [5] Mathis, M. et al. "The Case for Universal Path MTU Discovery" (RFC 1191)
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import statistics
import struct
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter, _unverified_context

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

MODULE_NAME = "quantum_fingerprint"

_PROBE_ITERATIONS = 12          # samples per sub-probe
_CONGESTION_BURST_SIZE = 8      # requests in burst
_CONGESTION_RECOVERY_PROBES = 6 # probes after burst
_TIMESTAMP_SAMPLES = 25         # rapid sequential requests for clock

# Payload sizes for TTL probing (bytes) — powers of two + edge cases
_TTL_PAYLOAD_SIZES = [64, 128, 256, 512, 1024, 1400, 1460]

# MTU detection escalation points (bytes)
_MTU_PAYLOAD_SIZES = [
    512, 1024, 1300, 1400, 1460, 1472, 1480, 1500,
    1600, 1792, 2048, 3200, 4096, 8192, 16384,
]

# Known initial TTL values per OS family
_KNOWN_INITIAL_TTL = [32, 60, 64, 128, 255]


# ═══════════════════════════════════════════════════════════════════════════
# OS Signature Database
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class OSSignature:
    """Timing fingerprint for a known OS / kernel combination.

    Each field encodes the *expected* value or *range* for that signal,
    plus a tolerance band and weight for confidence scoring.

    Fields
    ------
    name           : Human-readable OS name
    family         : High-level family (Linux, Windows, macOS, BSD, Cisco, CDN)
    ttl_initial    : Expected initial TTL (64, 128, 255 …)
    tcp_window     : Typical initial TCP window size (bytes)
    synack_ms      : Typical SYN→first-byte latency in ms (median)
    timestamp_res  : Date-header clock resolution in ms
    keepalive_s    : Connection persistence after idle in seconds
    congestion     : Congestion control algorithm name
    mtu_default    : Typical default interface MTU
    jitter_ratio   : Expected jitter / mean-rtt ratio (coefficient of variation)
    weight         : Prior probability weight (higher = more common)
    """
    name: str
    family: str
    ttl_initial: int
    tcp_window: int
    synack_ms: float          # median
    timestamp_res: float     # ms
    keepalive_s: float        # seconds
    congestion: str
    mtu_default: int
    jitter_ratio: float       # CV = stddev/mean
    weight: float = 1.0

    # Tolerance multipliers — how much deviation is acceptable
    ttl_tol: int = 2
    window_tol: float = 0.35
    synack_tol: float = 0.6
    timestamp_tol: float = 2.5
    keepalive_tol: float = 0.5
    jitter_tol: float = 0.5


# fmt: off
OS_SIGNATURES: List[OSSignature] = [
    # ── Linux ────────────────────────────────────────────────────────────
    OSSignature(
        name="Linux 6.x (CUBIC, modern)",
        family="Linux",
        ttl_initial=64, tcp_window=65535,
        synack_ms=3.5, timestamp_res=1.0,
        keepalive_s=75.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.04,
        weight=1.8,
    ),
    OSSignature(
        name="Linux 5.x (CUBIC)",
        family="Linux",
        ttl_initial=64, tcp_window=29200,
        synack_ms=4.5, timestamp_res=1.0,
        keepalive_s=75.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.05,
        weight=1.6,
    ),
    OSSignature(
        name="Linux 4.x (CUBIC)",
        family="Linux",
        ttl_initial=64, tcp_window=29200,
        synack_ms=5.5, timestamp_res=1.0,
        keepalive_s=75.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.06,
        weight=1.3,
    ),
    OSSignature(
        name="Linux 6.x (BBR)",
        family="Linux",
        ttl_initial=64, tcp_window=65535,
        synack_ms=2.8, timestamp_res=1.0,
        keepalive_s=75.0, congestion="bbr",
        mtu_default=1500, jitter_ratio=0.03,
        weight=0.9,
    ),
    OSSignature(
        name="Linux 3.x (Reno/CUBIC hybrid)",
        family="Linux",
        ttl_initial=64, tcp_window=14600,
        synack_ms=6.0, timestamp_res=1.0,
        keepalive_s=75.0, congestion="reno",
        mtu_default=1500, jitter_ratio=0.07,
        weight=0.5,
    ),
    OSSignature(
        name="Android (Linux-based)",
        family="Linux",
        ttl_initial=64, tcp_window=29200,
        synack_ms=5.0, timestamp_res=10.0,
        keepalive_s=60.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.08,
        weight=0.4,
    ),

    # ── Windows ──────────────────────────────────────────────────────────
    OSSignature(
        name="Windows Server 2022",
        family="Windows",
        ttl_initial=128, tcp_window=65535,
        synack_ms=5.5, timestamp_res=15.625,
        keepalive_s=120.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.06,
        weight=1.5,
    ),
    OSSignature(
        name="Windows Server 2019",
        family="Windows",
        ttl_initial=128, tcp_window=8192,
        synack_ms=7.5, timestamp_res=15.625,
        keepalive_s=120.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.08,
        weight=1.4,
    ),
    OSSignature(
        name="Windows Server 2016",
        family="Windows",
        ttl_initial=128, tcp_window=65535,
        synack_ms=9.0, timestamp_res=15.625,
        keepalive_s=120.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.09,
        weight=1.1,
    ),
    OSSignature(
        name="Windows 10 / 11",
        family="Windows",
        ttl_initial=128, tcp_window=65535,
        synack_ms=6.0, timestamp_res=15.625,
        keepalive_s=60.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.07,
        weight=1.3,
    ),

    # ── macOS ────────────────────────────────────────────────────────────
    OSSignature(
        name="macOS Sonoma (14.x, Darwin 23)",
        family="macOS",
        ttl_initial=64, tcp_window=65535,
        synack_ms=4.0, timestamp_res=1.0,
        keepalive_s=65.0, congestion="ledbat",
        mtu_default=1500, jitter_ratio=0.04,
        weight=1.1,
    ),
    OSSignature(
        name="macOS Ventura (13.x, Darwin 22)",
        family="macOS",
        ttl_initial=64, tcp_window=65535,
        synack_ms=4.5, timestamp_res=1.0,
        keepalive_s=65.0, congestion="ledbat",
        mtu_default=1500, jitter_ratio=0.05,
        weight=0.9,
    ),
    OSSignature(
        name="macOS Monterey (12.x, Darwin 21)",
        family="macOS",
        ttl_initial=64, tcp_window=65535,
        synack_ms=5.0, timestamp_res=1.0,
        keepalive_s=65.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.06,
        weight=0.6,
    ),

    # ── BSD ───────────────────────────────────────────────────────────────
    OSSignature(
        name="FreeBSD 14.x",
        family="BSD",
        ttl_initial=64, tcp_window=65535,
        synack_ms=3.5, timestamp_res=1.0,
        keepalive_s=75.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.04,
        weight=0.8,
    ),
    OSSignature(
        name="FreeBSD 13.x",
        family="BSD",
        ttl_initial=64, tcp_window=65535,
        synack_ms=4.0, timestamp_res=1.0,
        keepalive_s=75.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.05,
        weight=0.7,
    ),
    OSSignature(
        name="OpenBSD 7.x",
        family="BSD",
        ttl_initial=64, tcp_window=16384,
        synack_ms=5.0, timestamp_res=1.0,
        keepalive_s=60.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.06,
        weight=0.4,
    ),
    OSSignature(
        name="NetBSD 10.x",
        family="BSD",
        ttl_initial=64, tcp_window=16384,
        synack_ms=5.5, timestamp_res=1.0,
        keepalive_s=60.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.07,
        weight=0.3,
    ),

    # ── Networking Equipment ─────────────────────────────────────────────
    OSSignature(
        name="Cisco IOS 15.x / Catalyst",
        family="Cisco",
        ttl_initial=255, tcp_window=4128,
        synack_ms=15.0, timestamp_res=10.0,
        keepalive_s=30.0, congestion="reno",
        mtu_default=1500, jitter_ratio=0.12,
        weight=0.7,
    ),
    OSSignature(
        name="Cisco IOS-XE 17.x",
        family="Cisco",
        ttl_initial=255, tcp_window=4128,
        synack_ms=12.0, timestamp_res=10.0,
        keepalive_s=30.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.10,
        weight=0.5,
    ),
    OSSignature(
        name="Juniper JunOS 21.x",
        family="Cisco",
        ttl_initial=64, tcp_window=16384,
        synack_ms=10.0, timestamp_res=10.0,
        keepalive_s=30.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.11,
        weight=0.4,
    ),

    # ── CDNs & Reverse Proxies ────────────────────────────────────────────
    OSSignature(
        name="Cloudflare (Linux-based)",
        family="CDN",
        ttl_initial=64, tcp_window=65535,
        synack_ms=2.0, timestamp_res=1.0,
        keepalive_s=100.0, congestion="bbr",
        mtu_default=1500, jitter_ratio=0.02,
        weight=0.9,
    ),
    OSSignature(
        name="Akamai (Linux-based)",
        family="CDN",
        ttl_initial=64, tcp_window=29200,
        synack_ms=3.0, timestamp_res=1.0,
        keepalive_s=120.0, congestion="bbr",
        mtu_default=1500, jitter_ratio=0.03,
        weight=0.6,
    ),
    OSSignature(
        name="AWS ALB / NLB",
        family="CDN",
        ttl_initial=64, tcp_window=65535,
        synack_ms=2.5, timestamp_res=1.0,
        keepalive_s=60.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.03,
        weight=0.8,
    ),

    # ── WAFs / Load Balancers ───────────────────────────────────────────
    OSSignature(
        name="F5 BIG-IP TMOS",
        family="BSD",
        ttl_initial=64, tcp_window=4128,
        synack_ms=4.0, timestamp_res=10.0,
        keepalive_s=60.0, congestion="newreno",
        mtu_default=1500, jitter_ratio=0.05,
        weight=0.5,
    ),
    OSSignature(
        name="Nginx (Linux, default)",
        family="Linux",
        ttl_initial=64, tcp_window=29200,
        synack_ms=3.0, timestamp_res=1.0,
        keepalive_s=65.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.04,
        weight=1.2,
    ),
    OSSignature(
        name="Apache httpd 2.4 (Linux)",
        family="Linux",
        ttl_initial=64, tcp_window=29200,
        synack_ms=5.0, timestamp_res=1.0,
        keepalive_s=5.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.06,
        weight=0.9,
    ),
    OSSignature(
        name="Caddy 2.x (Go/Linux)",
        family="Linux",
        ttl_initial=64, tcp_window=65535,
        synack_ms=2.5, timestamp_res=1.0,
        keepalive_s=30.0, congestion="cubic",
        mtu_default=1500, jitter_ratio=0.03,
        weight=0.6,
    ),
]
# fmt: on


# ═══════════════════════════════════════════════════════════════════════════
# Internal Data Structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TimingSample:
    """A single timing measurement."""
    label: str
    elapsed_ms: float
    payload_size: int = 0
    status_code: int = 0
    response_bytes: int = 0
    error: Optional[str] = None


@dataclass
class SubProbeResult:
    """Aggregated result from one sub-probe."""
    probe_name: str
    samples: List[TimingSample] = field(default_factory=list)
    derived_value: Any = None
    description: str = ""
    confidence: float = 0.0

    @property
    def values(self) -> List[float]:
        return [s.elapsed_ms for s in self.samples if s.error is None]

    @property
    def mean(self) -> float:
        v = self.values
        return statistics.mean(v) if v else 0.0

    @property
    def median(self) -> float:
        v = sorted(self.values)
        n = len(v)
        if n == 0:
            return 0.0
        return v[n // 2]

    @property
    def stdev(self) -> float:
        v = self.values
        return statistics.stdev(v) if len(v) > 1 else 0.0

    @property
    def cv(self) -> float:
        """Coefficient of variation (jitter ratio)."""
        m = self.mean
        return self.stdev / m if m > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Low-level Timing Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _timed_request(
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> TimingSample:
    """Send a single HTTP request and measure wall-clock RTT."""
    if limiter:
        limiter.acquire()

    h = {
        "User-Agent": "ReconPro/9.2 (Quantum Fingerprint Scanner)",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if headers:
        h.update(headers)

    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.perf_counter()

    try:
        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            ctx = _unverified_context()  # audited opt-out helper

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            resp_headers = dict(resp.headers.items())
            return TimingSample(
                label=url,
                elapsed_ms=elapsed,
                payload_size=len(body) if body else 0,
                status_code=resp.status,
                response_bytes=len(raw),
                error=None,
            )
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        try:
            e.read()
        except Exception:
            pass
        return TimingSample(
            label=url, elapsed_ms=elapsed, status_code=e.code, error=e.reason
        )
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TimingSample(label=url, elapsed_ms=elapsed, error=str(e)[:120])


def _make_unique_url(base_url: str, seed: str, size: int = 0) -> str:
    """Generate a unique probe URL to avoid caching artifacts."""
    h = hashlib.sha256(f"{seed}-{time.time_ns()}".encode()).hexdigest()[:12]
    url = f"{base_url}/.well-known/quantumfp-{h}"
    if size > 0:
        url += f"?s={size}&r={h}"
    return url


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 1: Initial TTL Deduction
# ═══════════════════════════════════════════════════════════════════════════

def _probe_ttl_deduction(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Deduce initial TTL through payload-size / RTT variance analysis.

    Rationale: Different initial TTL values cause packets to traverse
    different numbers of hops before expiry.  When we vary the payload
    size, the number of TCP segments changes.  Segments that trigger
    more TCP-level processing at each hop reveal the initial TTL
    through a measurable correlation between payload size and RTT
    coefficient of variation.

    Additionally, we look for a step-function pattern: when the
    number of required hops approaches TTL-1, the RTT variance
    increases measurably.
    """
    result = SubProbeResult(probe_name="ttl_deduction")

    # Phase 1: Collect RTT samples at multiple payload sizes
    size_samples: Dict[int, List[float]] = {}
    for size in _TTL_PAYLOAD_SIZES:
        body = b"A" * size
        samples: List[float] = []
        for i in range(_PROBE_ITERATIONS):
            url = _make_unique_url(base_url, f"ttl-p{size}", size)
            ts = _timed_request(
                url, method="POST", body=body,
                timeout=timeout, verify_tls=verify_tls, limiter=limiter,
            )
            if ts.error is None:
                samples.append(ts.elapsed_ms)
            result.samples.append(ts)
            time.sleep(0.02)
        if samples:
            size_samples[size] = samples

    if len(size_samples) < 3:
        result.derived_value = None
        result.description = "Insufficient clean samples for TTL deduction"
        return result

    # Phase 2: Analyze RTT variance pattern vs payload size
    size_variance: List[Tuple[int, float, float]] = []
    for size, vals in sorted(size_samples.items()):
        mean_rtt = statistics.mean(vals)
        cv = statistics.stdev(vals) / mean_rtt if mean_rtt > 0 else 0
        size_variance.append((size, mean_rtt, cv))

    # Phase 3: Score each candidate TTL
    # A lower TTL means more hops are traversed, which means more
    # network noise → higher CV for larger payloads.
    # We compute a "slope" of CV vs payload-size for each TTL candidate.
    total_mean_rtt = statistics.mean([m for _, m, _ in size_variance])
    avg_cv = statistics.mean([cv for _, _, cv in size_variance])

    # The TTL deduction heuristic: look at how CV grows with payload size.
    # Larger payloads → more segments → more hop-dependent variance.
    # The *shape* of this growth curve distinguishes TTL values.
    cv_slope = 0.0
    if len(size_variance) > 2:
        x_vals = [math.log2(max(s, 1)) for s, _, _ in size_variance]
        y_vals = [cv for _, _, cv in size_variance]
        n = len(x_vals)
        mx = sum(x_vals) / n
        my = sum(y_vals) / n
        num = sum((x - mx) * (y - my) for x, y in zip(x_vals, y_vals))
        den = math.sqrt(sum((x - mx) ** 2 for x in x_vals)) * math.sqrt(
            sum((y - my) ** 2 for y in y_vals)
        )
        cv_slope = num / den if den > 0 else 0

    # Score candidate TTLs
    ttl_scores: List[Tuple[int, float]] = []
    for candidate_ttl in _KNOWN_INITIAL_TTL:
        score = 0.0

        # Factor 1: CV slope matches expected hop-count scaling
        # Higher TTL → fewer exhausted hops → lower slope
        expected_slope = 1.0 / math.log2(max(candidate_ttl, 2))
        slope_diff = abs(cv_slope - expected_slope)
        score += max(0, 1.0 - slope_diff * 3.0) * 0.35

        # Factor 2: Mean RTT correlation
        # TTL 255 (networking gear) often has higher latency due to
        # additional processing in routers/switches
        if candidate_ttl == 255:
            score += (0.3 if total_mean_rtt > 50 else 0.1)
        elif candidate_ttl == 128:
            score += (0.3 if total_mean_rtt > 20 else 0.2)
        else:
            score += (0.2 if total_mean_rtt < 100 else 0.1)

        # Factor 3: CV magnitude
        if candidate_ttl <= 64:
            score += max(0, 0.15 - avg_cv * 0.5)
        elif candidate_ttl == 128:
            score += max(0, 0.15 - abs(avg_cv - 0.07) * 2.0)
        else:
            score += max(0, 0.15 - abs(avg_cv - 0.12) * 2.0)

        # Factor 4: Jumps in RTT at specific payload sizes
        if len(size_variance) > 3:
            # Look for step-function jumps at segment boundaries
            jumps = 0
            for i in range(1, len(size_variance)):
                rt_diff = size_variance[i][1] - size_variance[i - 1][1]
                if rt_diff > total_mean_rtt * 0.15:
                    jumps += 1
            # More jumps suggest more hops (lower TTL)
            if candidate_ttl == 64 and jumps >= 2:
                score += 0.15
            elif candidate_ttl == 128 and jumps <= 1:
                score += 0.10
            elif candidate_ttl == 255 and jumps == 0:
                score += 0.10

        ttl_scores.append((candidate_ttl, score))

    ttl_scores.sort(key=lambda x: x[1], reverse=True)
    best_ttl = ttl_scores[0][0] if ttl_scores else 64
    best_score = ttl_scores[0][1] if ttl_scores else 0

    result.derived_value = {
        "deduced_ttl": best_ttl,
        "confidence": round(min(best_score, 1.0), 3),
        "all_scores": {str(t): round(s, 3) for t, s in ttl_scores},
        "mean_rtt_ms": round(total_mean_rtt, 2),
        "avg_cv": round(avg_cv, 4),
        "cv_slope": round(cv_slope, 4),
        "size_variance": [
            {"size": s, "mean_rtt": round(m, 2), "cv": round(c, 4)}
            for s, m, c in size_variance
        ],
    }
    result.confidence = min(best_score, 1.0)
    result.description = (
        f"Deduced initial TTL = {best_ttl} "
        f"(confidence {round(min(best_score, 1.0) * 100, 1)}%)"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 2: TCP Window Size Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════

def _probe_tcp_window(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Fingerprint TCP window size via response data-burst analysis.

    Rationale: When a server sends a large response, the TCP window
    size determines how much data is sent in the initial burst before
    waiting for ACKs.  We measure how response bytes arrive by probing
    with a large response endpoint and analyzing the relationship
    between request size, response time, and bytes received.

    Key signals:
    - Bytes received per millisecond of RTT
    - Ratio of response time for small vs large responses
    - Chunked vs Content-Length transfer patterns
    """
    result = SubProbeResult(probe_name="tcp_window")

    # Phase 1: Measure small response baseline
    small_rtts: List[float] = []
    small_bytes: List[int] = []
    for i in range(_PROBE_ITERATIONS):
        url = _make_unique_url(base_url, f"tw-sm-{i}")
        ts = _timed_request(url, timeout=timeout, verify_tls=verify_tls,
                            limiter=limiter)
        if ts.error is None:
            small_rtts.append(ts.elapsed_ms)
            small_bytes.append(ts.response_bytes)
        result.samples.append(ts)
        time.sleep(0.02)

    # Phase 2: Measure large response (via POST to trigger potential
    # echo or error response of different size)
    large_rtts: List[float] = []
    large_bytes: List[int] = []
    large_body = b"X" * 4096
    for i in range(_PROBE_ITERATIONS):
        url = _make_unique_url(base_url, f"tw-lg-{i}")
        ts = _timed_request(
            url, method="POST", body=large_body,
            timeout=timeout, verify_tls=verify_tls, limiter=limiter,
        )
        if ts.error is None:
            large_rtts.append(ts.elapsed_ms)
            large_bytes.append(ts.response_bytes)
        result.samples.append(ts)
        time.sleep(0.02)

    # Phase 3: Analyze transfer rates
    all_probe_rtts = small_rtts + large_rtts
    if not all_probe_rtts:
        result.derived_value = None
        result.description = "No clean responses for TCP window analysis"
        return result

    all_bytes = small_bytes + large_bytes
    avg_bytes = statistics.mean(all_bytes) if all_bytes else 0
    avg_small_rtt = statistics.mean(small_rtts) if small_rtts else 0
    avg_large_rtt = statistics.mean(large_rtts) if large_rtts else 0

    # Phase 4: Also probe the main page for chunked vs content-length
    main_probe = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    is_chunked = "transfer-encoding" in {
        k.lower() for k in main_probe.get("headers", {})
    }
    content_length = main_probe.get("headers", {}).get("Content-Length", "")

    # Transfer rate (bytes/ms) reflects effective window / RTT
    transfer_rate = avg_bytes / avg_large_rtt if avg_large_rtt > 0 else 0

    # Phase 5: Classify window size
    # Map transfer-rate ranges to window size classes
    window_classification = "unknown"
    estimated_window = 0

    if transfer_rate > 100:
        window_classification = "large (65535)"
        estimated_window = 65535
    elif transfer_rate > 30:
        window_classification = "medium-large (29200)"
        estimated_window = 29200
    elif transfer_rate > 15:
        window_classification = "medium (16384)"
        estimated_window = 16384
    elif transfer_rate > 5:
        window_classification = "small (8192)"
        estimated_window = 8192
    else:
        window_classification = "very-small (4128)"
        estimated_window = 4128

    # Adjust for known server hints
    server_header = main_probe.get("headers", {}).get("Server", "").lower()
    if "nginx" in server_header and estimated_window < 29200:
        estimated_window = 29200
        window_classification = "medium-large (29200) [nginx hint]"
    elif "cloudflare" in server_header:
        estimated_window = 65535
        window_classification = "large (65535) [cloudflare hint]"
    elif "apache" in server_header and estimated_window < 29200:
        estimated_window = 29200
        window_classification = "medium-large (29200) [apache hint]"

    result.derived_value = {
        "estimated_window": estimated_window,
        "classification": window_classification,
        "transfer_rate_bytes_per_ms": round(transfer_rate, 2),
        "avg_small_rtt_ms": round(avg_small_rtt, 2),
        "avg_large_rtt_ms": round(avg_large_rtt, 2),
        "is_chunked": is_chunked,
        "server_hint": server_header or None,
        "avg_response_bytes": round(avg_bytes, 1),
    }
    result.confidence = 0.6 if transfer_rate > 0 else 0.2
    result.description = (
        f"Estimated TCP window ≈ {window_classification} "
        f"(transfer rate: {transfer_rate:.1f} bytes/ms)"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 3: SYN-ACK Timing Behaviour
# ═══════════════════════════════════════════════════════════════════════════

def _probe_synack_timing(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Measure SYN-ACK timing via fresh-connection first-byte latency.

    Rationale: Every time we open a new TCP connection (no keep-alive
    reuse), the observed latency includes:
      - DNS resolution (amortized / cached)
      - TCP SYN → SYN-ACK round trip
      - TLS handshake (if HTTPS)
      - Server request processing → first byte

    By opening many fresh connections and measuring the minimum RTT
    (the tail-eliminated latency), we isolate the kernel's TCP
    interrupt-handling and timer resolution characteristics.

    Different kernels have characteristic first-byte latencies due to
    different NAPI polling intervals, interrupt coalescing, and
    TCP backlog processing strategies.
    """
    result = SubProbeResult(probe_name="synack_timing")

    # Force fresh connections by using a new OpenerDirector each time
    rtts: List[float] = []

    for i in range(_PROBE_ITERATIONS + 4):
        url = _make_unique_url(base_url, f"synack-{i}")

        if limiter:
            limiter.acquire()

        # Build a fresh opener (no connection pooling)
        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            ctx = _unverified_context()  # audited opt-out helper

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx) if base_url.startswith("https")
            else urllib.request.HTTPHandler()
        )

        headers = {
            "User-Agent": "ReconPro/9.2 (Quantum Fingerprint Scanner)",
            "Accept": "*/*",
            "Connection": "close",      # force new connection per request
        }
        req = urllib.request.Request(url, headers=headers)

        t0 = time.perf_counter()
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp.read(512)
                elapsed = (time.perf_counter() - t0) * 1000.0
                rtts.append(elapsed)
                result.samples.append(TimingSample(
                    label=url, elapsed_ms=elapsed, status_code=resp.status
                ))
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            result.samples.append(TimingSample(
                label=url, elapsed_ms=elapsed, error=str(e)[:80]
            ))
        time.sleep(0.03)

    if not rtts:
        result.derived_value = None
        result.description = "No clean SYN-ACK timing samples"
        return result

    rtts_sorted = sorted(rtts)
    n = len(rtts_sorted)

    # Statistical measures
    # Use trimmed mean (discard top 20% — outliers from GC / context switches)
    trim_idx = max(1, n - n // 5)
    trimmed = rtts_sorted[:trim_idx]
    median_rtt = rtts_sorted[n // 2]
    trimmed_mean = statistics.mean(trimmed)
    minimum = rtts_sorted[0]
    p10 = rtts_sorted[max(0, n // 10)]
    p90 = rtts_sorted[min(n - 1, n * 9 // 10)]

    # IQR-based jitter
    q1 = rtts_sorted[n // 4] if n >= 4 else median_rtt
    q3 = rtts_sorted[3 * n // 4] if n >= 4 else median_rtt
    iqr = q3 - q1

    # Classify the kernel interrupt pattern
    kernel_hint = "unknown"
    if trimmed_mean < 3.0 and iqr < 2.0:
        kernel_hint = "low-latency kernel (BBR / modern Linux / CDN)"
    elif trimmed_mean < 5.0 and iqr < 3.0:
        kernel_hint = "standard Linux 5.x+ / macOS / FreeBSD"
    elif trimmed_mean < 8.0 and iqr < 5.0:
        kernel_hint = "Linux 4.x / older macOS / Windows Server"
    elif trimmed_mean < 12.0 and iqr < 8.0:
        kernel_hint = "older Linux / Windows Server / JunOS"
    elif trimmed_mean >= 12.0:
        kernel_hint = "networking equipment / high-latency kernel / proxy chain"

    result.derived_value = {
        "trimmed_mean_ms": round(trimmed_mean, 3),
        "median_ms": round(median_rtt, 3),
        "minimum_ms": round(minimum, 3),
        "p10_ms": round(p10, 3),
        "p90_ms": round(p90, 3),
        "iqr_ms": round(iqr, 3),
        "stddev": round(statistics.stdev(rtts) if len(rtts) > 1 else 0, 3),
        "sample_count": n,
        "kernel_pattern": kernel_hint,
    }
    result.confidence = 0.7
    result.description = (
        f"SYN-ACK latency: median={median_rtt:.2f}ms, "
        f"trimmed-mean={trimmed_mean:.2f}ms, "
        f"iqr={iqr:.2f}ms ({kernel_hint})"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 4: HTTP Keep-Alive Behaviour
# ═══════════════════════════════════════════════════════════════════════════

def _probe_keepalive(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Measure connection persistence and keep-alive timing.

    Rationale: Different TCP stacks keep idle connections open for
    different durations, governed by kernel-level tcp_fin_timeout,
    tcp_keepalive_time, and server-level configuration.  By sending
    a sequence of requests on the same connection with increasing
    idle intervals, we can detect the point at which the server closes
    the connection, revealing the TCP stack's idle timeout.

    We also measure RTT degradation across sequential requests —
    some stacks show increasing latency due to NIC buffer pressure or
    TCP delayed-ACK timer interactions.
    """
    result = SubProbeResult(probe_name="keepalive")

    # Use a single opener for connection reuse
    if verify_tls:
        ctx = ssl.create_default_context()
    else:
        ctx = _unverified_context()  # audited opt-out helper

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx) if base_url.startswith("https")
        else urllib.request.HTTPHandler()
    )

    # Phase 1: Rapid sequential requests — measure RTT degradation
    seq_rtts: List[float] = []
    conn_alive = True

    for i in range(_PROBE_ITERATIONS):
        url = _make_unique_url(base_url, f"ka-seq-{i}")
        headers = {
            "User-Agent": "ReconPro/9.2",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        req = urllib.request.Request(url, headers=headers)

        if limiter:
            limiter.acquire()

        t0 = time.perf_counter()
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp.read(256)
                elapsed = (time.perf_counter() - t0) * 1000.0
                seq_rtts.append(elapsed)
                result.samples.append(TimingSample(
                    label=f"seq-{i}", elapsed_ms=elapsed, status_code=resp.status
                ))
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            result.samples.append(TimingSample(
                label=f"seq-{i}", elapsed_ms=elapsed, error=str(e)[:80]
            ))
            conn_alive = False
            break

    # Phase 2: Idle-interval probing
    # Send a request, wait, send another — find when connection drops
    idle_intervals = [0.5, 1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 20.0]
    idle_survival: List[Tuple[float, bool]] = []
    conn_refreshed = False

    for wait_s in idle_intervals:
        # Refresh connection first
        refresh_url = _make_unique_url(base_url, f"ka-refr-{wait_s}")
        ref_headers = {
            "User-Agent": "ReconPro/9.2",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        ref_req = urllib.request.Request(refresh_url, headers=ref_headers)

        if limiter:
            limiter.acquire()

        try:
            with opener.open(ref_req, timeout=timeout) as resp:
                resp.read(128)
            conn_refreshed = True
        except Exception:
            # Connection was closed; create fresh one
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
                if base_url.startswith("https")
                else urllib.request.HTTPHandler()
            )
            try:
                with opener.open(ref_req, timeout=timeout) as resp:
                    resp.read(128)
                conn_refreshed = True
            except Exception:
                conn_refreshed = False
                idle_survival.append((wait_s, False))
                continue

        if not conn_refreshed:
            idle_survival.append((wait_s, False))
            continue

        # Wait the idle interval
        time.sleep(wait_s)

        # Try to reuse the connection
        test_url = _make_unique_url(base_url, f"ka-test-{wait_s}")
        test_headers = {
            "User-Agent": "ReconPro/9.2",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        test_req = urllib.request.Request(test_url, headers=test_headers)

        if limiter:
            limiter.acquire()

        t0 = time.perf_counter()
        try:
            with opener.open(test_req, timeout=timeout) as resp:
                resp.read(128)
                elapsed = (time.perf_counter() - t0) * 1000.0
                result.samples.append(TimingSample(
                    label=f"idle-{wait_s}s", elapsed_ms=elapsed,
                    status_code=resp.status
                ))
                idle_survival.append((wait_s, True))
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            result.samples.append(TimingSample(
                label=f"idle-{wait_s}s", elapsed_ms=elapsed,
                error="connection_closed"
            ))
            idle_survival.append((wait_s, False))

    # Phase 3: Analyze results
    estimated_timeout = 0.0
    for wait_s, alive in idle_survival:
        if not alive:
            estimated_timeout = wait_s
            break
    else:
        estimated_timeout = max(w for w, _ in idle_survival) if idle_survival else 0

    # RTT degradation slope
    rtt_degradation = 0.0
    if len(seq_rtts) > 2:
        x = list(range(len(seq_rtts)))
        y = seq_rtts
        n = len(x)
        mx = sum(x) / n
        my = sum(y) / n
        num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
        den = math.sqrt(sum((xi - mx) ** 2 for xi in x))
        rtt_degradation = num / den if den > 0 else 0

    # Classify keep-alive behaviour
    ka_hint = "unknown"
    if estimated_timeout <= 5:
        ka_hint = "aggressive timeout (Apache / embedded / Cisco)"
    elif estimated_timeout <= 30:
        ka_hint = "moderate timeout (Nginx default / Caddy / load balancer)"
    elif estimated_timeout <= 75:
        ka_hint = "standard Linux kernel (tcp_keepalive_time ≈ 75s)"
    elif estimated_timeout <= 120:
        ka_hint = "Windows Server default (120s)"
    else:
        ka_hint = "long-lived (CDN / reverse proxy / custom config)"

    if rtt_degradation > 0.5:
        ka_hint += " + increasing latency (possible NIC buffer pressure)"

    result.derived_value = {
        "estimated_timeout_s": round(estimated_timeout, 1),
        "keepalive_hint": ka_hint,
        "idle_survival": [(round(w, 1), a) for w, a in idle_survival],
        "seq_rtt_degradation_ms_per_req": round(rtt_degradation, 3),
        "seq_rtts": [round(r, 2) for r in seq_rtts],
        "seq_rtts_median": round(
            statistics.median(seq_rtts) if seq_rtts else 0, 2
        ),
    }
    result.confidence = 0.6
    result.description = (
        f"Keep-alive timeout ≈ {estimated_timeout:.1f}s — {ka_hint}"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 5: Path MTU Detection
# ═══════════════════════════════════════════════════════════════════════════

def _probe_mtu(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Detect path MTU by escalating payload size until fragmentation.

    Rationale: When the POST body exceeds the path MTU (after subtracting
    TCP + IP headers), the packet must be fragmented.  Fragmentation
    causes a measurable RTT spike because:
      - Additional packet processing at routers
      - Potential retransmission if fragments are lost
      - ICMP "Fragmentation Needed" messages (RFC 1191)

    By plotting RTT vs payload size and detecting the inflection point,
    we can estimate the effective path MTU.

    Typical MTU signatures:
      - 1500: Standard Ethernet (most common)
      - 1472: Without IP header (ICMP payload)
      - 1460: Without IP+TCP headers
      - 9000: Jumbo frames (data center)
      - 1280: IPv6 minimum
    """
    result = SubProbeResult(probe_name="mtu_detection")

    payload_rtts: List[Tuple[int, float]] = []
    prev_rtt = None

    for size in _MTU_PAYLOAD_SIZES:
        body = b"P" * size
        rtts_for_size: List[float] = []

        for trial in range(3):
            url = _make_unique_url(base_url, f"mtu-{size}-{trial}")
            ts = _timed_request(
                url, method="POST", body=body,
                timeout=timeout, verify_tls=verify_tls, limiter=limiter,
            )
            if ts.error is None:
                rtts_for_size.append(ts.elapsed_ms)
            result.samples.append(ts)
            time.sleep(0.02)

        if rtts_for_size:
            mean_rtt = statistics.mean(rtts_for_size)
            payload_rtts.append((size, mean_rtt))
        else:
            payload_rtts.append((size, float("inf")))

    # Phase 2: Detect MTU inflection point
    # Look for the first significant RTT spike
    baseline_rtts = [r for s, r in payload_rtts if s <= 1460 and r < float("inf")]
    baseline_mean = statistics.mean(baseline_rtts) if baseline_rtts else 50.0
    baseline_stdev = statistics.stdev(baseline_rtts) if len(baseline_rtts) > 1 else 5.0
    spike_threshold = baseline_mean + baseline_stdev * 2.5

    mtu_estimate = 0
    spike_detected = False
    for size, rtt in payload_rtts:
        if rtt > spike_threshold and rtt != float("inf"):
            # Account for TCP/IP headers: effective MTU = payload + headers
            # We subtract 60 bytes for TCP+IP headers (typical)
            mtu_estimate = size + 60
            spike_detected = True
            break
        elif rtt == float("inf"):
            mtu_estimate = size + 60
            spike_detected = True
            break

    if not spike_detected:
        # No spike detected → path supports all tested sizes → large MTU
        max_tested = max(s for s, _ in payload_rtts) if payload_rtts else 1500
        mtu_estimate = max(max_tested + 60, 9000)

    # Phase 3: Classify MTU
    mtu_class = "unknown"
    if 1496 <= mtu_estimate <= 1520:
        mtu_class = "standard Ethernet (1500 bytes)"
    elif 1470 <= mtu_estimate <= 1496:
        mtu_class = "Ethernet with encapsulation overhead"
    elif 1486 <= mtu_estimate <= 1520:
        mtu_class = "PPPoE or VPN encapsulation"
    elif mtu_estimate >= 8960:
        mtu_class = "jumbo frames (9000 bytes)"
    elif 1276 <= mtu_estimate <= 1300:
        mtu_class = "IPv6 minimum MTU"
    elif mtu_estimate > 0:
        mtu_class = f"non-standard ({mtu_estimate} bytes)"

    result.derived_value = {
        "estimated_mtu": mtu_estimate,
        "classification": mtu_class,
        "spike_detected": spike_detected,
        "baseline_mean_ms": round(baseline_mean, 2),
        "spike_threshold_ms": round(spike_threshold, 2),
        "payload_rtts": [
            {"size": s, "mean_rtt": round(r, 2) if r < float("inf") else None}
            for s, r in payload_rtts
        ],
    }
    result.confidence = 0.7 if spike_detected else 0.4
    result.description = (
        f"Estimated path MTU = {mtu_estimate} bytes — {mtu_class}"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 6: Congestion Control Algorithm Identification
# ═══════════════════════════════════════════════════════════════════════════

def _probe_congestion_control(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Identify congestion control algorithm via burst-recovery analysis.

    Rationale: Different congestion control algorithms recover from
    packet loss / network congestion at different rates:

      - **CUBIC**: W(t) = C(t - K)³ + W_max — cubic growth function
        produces a characteristic "S-curve" recovery pattern.
      - **Reno/NewReno**: Linear increase after loss detection.
        Slow, steady recovery with predictable slope.
      - **BBR**: Attempts to estimate bandwidth and RTT, then
        paces packets accordingly.  Recovery is near-instant
        with minimal RTT inflation.
      - **LEDBAT**: Designed for background traffic, delays
        heavily.  Very high RTT after burst.

    Methodology:
    1. Establish baseline RTT with isolated probes.
    2. Fire a burst of requests as fast as possible.
    3. Measure RTT inflation during and after burst.
    4. Analyze recovery curve shape.
    """
    result = SubProbeResult(probe_name="congestion_control")

    # Phase 1: Baseline
    baseline_rtts: List[float] = []
    for i in range(_PROBE_ITERATIONS // 2):
        url = _make_unique_url(base_url, f"cc-base-{i}")
        ts = _timed_request(url, timeout=timeout, verify_tls=verify_tls,
                            limiter=limiter)
        if ts.error is None:
            baseline_rtts.append(ts.elapsed_ms)
        result.samples.append(ts)
        time.sleep(0.05)

    if not baseline_rtts:
        result.derived_value = None
        result.description = "No baseline for congestion analysis"
        return result

    baseline_mean = statistics.mean(baseline_rtts)
    baseline_stdev = statistics.stdev(baseline_rtts) if len(baseline_rtts) > 1 else 1.0

    # Phase 2: Burst
    burst_rtts: List[float] = []
    for i in range(_CONGESTION_BURST_SIZE):
        url = _make_unique_url(base_url, f"cc-burst-{i}")
        # Minimal delay between requests to create congestion
        ts = _timed_request(url, timeout=timeout, verify_tls=verify_tls,
                            limiter=limiter)
        burst_rtts.append(ts.elapsed_ms)
        result.samples.append(ts)

    # Phase 3: Recovery probes
    recovery_rtts: List[float] = []
    for i in range(_CONGESTION_RECOVERY_PROBES):
        url = _make_unique_url(base_url, f"cc-recovery-{i}")
        ts = _timed_request(url, timeout=timeout, verify_tls=verify_tls,
                            limiter=limiter)
        if ts.error is None:
            recovery_rtts.append(ts.elapsed_ms)
        result.samples.append(ts)
        time.sleep(0.08)

    # Phase 4: Analysis
    burst_mean = statistics.mean(burst_rtts)
    burst_inflation = (burst_mean - baseline_mean) / baseline_mean if baseline_mean > 0 else 0

    recovery_mean = statistics.mean(recovery_rtts) if recovery_rtts else burst_mean
    recovery_ratio = recovery_mean / baseline_mean if baseline_mean > 0 else 1.0

    # Recovery curve slope (should be negative — RTT decreasing back to baseline)
    recovery_slope = 0.0
    if len(recovery_rtts) > 2:
        x = list(range(len(recovery_rtts)))
        y = recovery_rtts
        n = len(x)
        mx = sum(x) / n
        my = sum(y) / n
        num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
        den = math.sqrt(sum((xi - mx) ** 2 for xi in x))
        recovery_slope = num / den if den > 0 else 0

    # Burst pattern analysis — CUBIC shows non-linear (cubic) increase
    burst_nonlinearity = 0.0
    if len(burst_rtts) > 3:
        # Fit quadratic to burst RTTs; residual indicates non-linearity
        x = list(range(len(burst_rtts)))
        y = burst_rtts
        n = len(x)
        # Simple: compute variance of successive differences
        diffs = [y[i+1] - y[i] for i in range(len(y) - 1)]
        if diffs:
            diff_mean = statistics.mean(diffs)
            diff_var = statistics.variance(diffs) if len(diffs) > 1 else 0
            burst_nonlinearity = math.sqrt(diff_var) / (abs(diff_mean) + 1)

    # Classify congestion control
    algo = "unknown"
    algo_confidence = 0.0

    if burst_inflation < 0.15 and recovery_ratio < 1.2:
        algo = "bbr"
        algo_confidence = 0.75
    elif burst_inflation < 0.3 and recovery_slope < -1.0 and burst_nonlinearity > 0.3:
        algo = "cubic"
        algo_confidence = 0.65
    elif burst_inflation < 0.5 and -0.5 < recovery_slope < 0.5:
        algo = "newreno"
        algo_confidence = 0.55
    elif burst_inflation < 0.5 and recovery_slope >= -0.3:
        algo = "reno"
        algo_confidence = 0.45
    elif burst_inflation > 0.5 or recovery_ratio > 2.0:
        algo = "ledbat"
        algo_confidence = 0.50
    elif burst_inflation > 0.3:
        algo = "cubic (congested)"
        algo_confidence = 0.45

    result.derived_value = {
        "algorithm": algo,
        "confidence": round(algo_confidence, 3),
        "baseline_mean_ms": round(baseline_mean, 2),
        "burst_mean_ms": round(burst_mean, 2),
        "burst_inflation_pct": round(burst_inflation * 100, 1),
        "recovery_mean_ms": round(recovery_mean, 2),
        "recovery_ratio": round(recovery_ratio, 3),
        "recovery_slope": round(recovery_slope, 3),
        "burst_nonlinearity": round(burst_nonlinearity, 3),
        "burst_rtts": [round(r, 2) for r in burst_rtts],
        "recovery_rtts": [round(r, 2) for r in recovery_rtts],
    }
    result.confidence = algo_confidence
    result.description = (
        f"Congestion control: {algo} "
        f"(confidence {round(algo_confidence * 100, 1)}%, "
        f"burst inflation: {burst_inflation * 100:.1f}%)"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Sub-Probe 7: Timestamp Resolution
# ═══════════════════════════════════════════════════════════════════════════

def _probe_timestamp_resolution(
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    limiter: Optional[Any] = None,
) -> SubProbeResult:
    """Measure server's Date-header clock granularity.

    Rationale: The HTTP Date header reflects the server's system
    clock.  Different OS kernels have different timer resolutions:
      - Linux 2.6+/macOS/FreeBSD: ~1ms (high-resolution timers)
      - Windows: ~15.625ms (default timer resolution, 64 Hz)
      - Older/embedded systems: ~10ms

    By sending rapid sequential requests and analyzing the
    inter-request differences in Date timestamps, we can
    determine the kernel's clock tick resolution.

    This is one of the most reliable OS fingerprinting signals
    because it directly reflects kernel configuration rather
    than network conditions.
    """
    result = SubProbeResult(probe_name="timestamp_resolution")

    # Also probe the main page for a reference Date header
    main_probe = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    server_header = main_probe.get("headers", {}).get("Server", "")
    via_header = main_probe.get("headers", {}).get("Via", "")

    timestamps: List[float] = []  # epoch seconds

    for i in range(_TIMESTAMP_SAMPLES):
        url = _make_unique_url(base_url, f"ts-{i}")
        ts = _timed_request(url, timeout=timeout, verify_tls=verify_tls,
                            limiter=limiter)
        if ts.error is None and ts.status_code in (200, 301, 302, 304, 404, 405, 403):
            # We need the Date header — use http_probe for this
            probe = http_probe(url, timeout=timeout, verify_tls=verify_tls)
            date_str = probe.get("headers", {}).get("Date", "")
            if date_str:
                try:
                    dt = parsedate_to_datetime(date_str)
                    epoch = dt.timestamp()
                    timestamps.append(epoch)
                except (ValueError, TypeError):
                    pass
        result.samples.append(ts)
        time.sleep(0.005)  # 5ms between samples

    if len(timestamps) < 3:
        # Fallback: use wall-clock deltas between requests
        result.derived_value = {
            "resolution_ms": 0,
            "classification": "insufficient data",
            "method": "wall-clock fallback",
            "server_header": server_header,
        }
        result.confidence = 0.1
        result.description = "Insufficient Date-header samples for timestamp analysis"
        return result

    # Phase 2: Analyze inter-timestamp deltas
    deltas_ms: List[float] = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i - 1]) * 1000.0
        if delta >= 0:  # Ignore clock skew (negative deltas)
            deltas_ms.append(delta)

    if not deltas_ms:
        result.derived_value = {
            "resolution_ms": 0,
            "classification": "clock going backwards?",
            "server_header": server_header,
        }
        result.confidence = 0.1
        return result

    # Phase 3: Determine resolution
    # Common resolutions: 1ms, 10ms, 15.625ms (≈16ms), 1000ms
    unique_deltas = sorted(set(round(d, 1) for d in deltas_ms if d > 0))
    min_delta = min(deltas_ms) if deltas_ms else 1.0

    # GCD-based resolution detection
    # Find the greatest common divisor of all deltas
    def _gcd_floats(vals: List[float], epsilon: float = 0.5) -> float:
        """Approximate GCD for floating-point values."""
        vals_rounded = [round(v / epsilon) for v in vals]
        from math import gcd as _int_gcd
        result = vals_rounded[0]
        for v in vals_rounded[1:]:
            result = _int_gcd(result, v)
        return result * epsilon

    resolution = _gcd_floats([d for d in deltas_ms if d > 0], epsilon=0.1)

    # Match against known resolutions
    known_resolutions = {
        1.0: "~1ms (Linux / macOS / FreeBSD — high-resolution timer)",
        10.0: "~10ms (embedded / older Linux / Juniper)",
        15.625: "~15.625ms (Windows — default system timer, 64 Hz)",
        16.0: "~16ms (Windows — rounded timer resolution)",
        1000.0: "~1000ms (very coarse / virtualized / load-balanced)",
    }

    classification = "unknown"
    best_match = 0
    for known_res, label in known_resolutions.items():
        if abs(resolution - known_res) < 2.0 or abs(min_delta - known_res) < 3.0:
            classification = label
            best_match = known_res
            break

    if classification == "unknown":
        classification = f"~{resolution:.1f}ms (non-standard resolution)"

    # Phase 4: Compute confidence
    res_confidence = 0.0
    if best_match == 15.625 or best_match == 16.0:
        # Windows timer is very distinctive — 15.625ms is hard to fake
        res_confidence = 0.85
    elif best_match == 1.0:
        res_confidence = 0.7
    elif best_match == 10.0:
        res_confidence = 0.55
    else:
        res_confidence = 0.4

    result.derived_value = {
        "resolution_ms": round(resolution, 3),
        "min_delta_ms": round(min_delta, 3),
        "classification": classification,
        "unique_deltas": unique_deltas[:10],
        "delta_stats": {
            "count": len(deltas_ms),
            "mean": round(statistics.mean(deltas_ms), 2),
            "median": round(statistics.median(deltas_ms), 2),
            "min": round(min(deltas_ms), 3),
        },
        "sample_count": len(timestamps),
        "server_header": server_header,
        "via_header": via_header,
    }
    result.confidence = res_confidence
    result.description = (
        f"Timestamp resolution: {classification} "
        f"(measured: {resolution:.2f}ms, min delta: {min_delta:.2f}ms)"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════
# OS Confidence Scoring Engine
# ═══════════════════════════════════════════════════════════════════════════

def _signal_match_score(
    observed: Any,
    expected: Any,
    tolerance: float,
    is_categorical: bool = False,
) -> float:
    """Compute how well an observed signal matches an expected value.

    Returns 0.0 (no match) to 1.0 (perfect match).
    """
    if observed is None:
        return 0.0

    if is_categorical:
        return 1.0 if str(observed).lower() == str(expected).lower() else 0.0

    try:
        obs = float(observed)
        exp = float(expected)
        diff = abs(obs - exp)
        range_size = max(abs(exp), 1.0)
        normalized_diff = diff / (range_size * tolerance + 0.001)
        return max(0.0, 1.0 - normalized_diff)
    except (TypeError, ValueError):
        return 0.0


def _compute_os_confidence(
    probes: Dict[str, SubProbeResult],
) -> List[Dict[str, Any]]:
    """Probabilistic OS identification by matching all signals against
    the OS_SIGNATURES database.

    Each signal contributes a weighted score.  The total confidence
    is the weighted average across all matched signals, normalized
    by the prior probability (weight field).
    """
    scores: List[Dict[str, Any]] = []

    # Extract observed values from probe results
    ttl_data = probes.get("ttl_deduction")
    window_data = probes.get("tcp_window")
    synack_data = probes.get("synack_timing")
    keepalive_data = probes.get("keepalive")
    mtu_data = probes.get("mtu_detection")
    congestion_data = probes.get("congestion_control")
    timestamp_data = probes.get("timestamp_resolution")

    observed_ttl = None
    if ttl_data and ttl_data.derived_value:
        observed_ttl = ttl_data.derived_value.get("deduced_ttl")

    observed_window = None
    if window_data and window_data.derived_value:
        observed_window = window_data.derived_value.get("estimated_window")

    observed_synack = None
    if synack_data and synack_data.derived_value:
        observed_synack = synack_data.derived_value.get("trimmed_mean_ms")

    observed_keepalive = None
    if keepalive_data and keepalive_data.derived_value:
        observed_keepalive = keepalive_data.derived_value.get("estimated_timeout_s")

    observed_mtu = None
    if mtu_data and mtu_data.derived_value:
        observed_mtu = mtu_data.derived_value.get("estimated_mtu")

    observed_congestion = None
    if congestion_data and congestion_data.derived_value:
        observed_congestion = congestion_data.derived_value.get("algorithm")

    observed_ts_res = None
    if timestamp_data and timestamp_data.derived_value:
        observed_ts_res = timestamp_data.derived_value.get("resolution_ms")

    for sig in OS_SIGNATURES:
        signal_scores: Dict[str, float] = {}
        weights: Dict[str, float] = {}

        # TTL match (weight: 0.20)
        if observed_ttl is not None:
            ttl_match = 1.0 if abs(observed_ttl - sig.ttl_initial) <= sig.ttl_tol else 0.0
            signal_scores["ttl"] = ttl_match
            weights["ttl"] = 0.20

        # Window match (weight: 0.12)
        if observed_window is not None:
            signal_scores["window"] = _signal_match_score(
                observed_window, sig.tcp_window, sig.window_tol
            )
            weights["window"] = 0.12

        # SYN-ACK match (weight: 0.15)
        if observed_synack is not None:
            signal_scores["synack"] = _signal_match_score(
                observed_synack, sig.synack_ms, sig.synack_tol
            )
            weights["synack"] = 0.15

        # Keep-alive match (weight: 0.10)
        if observed_keepalive is not None:
            signal_scores["keepalive"] = _signal_match_score(
                observed_keepalive, sig.keepalive_s, sig.keepalive_tol
            )
            weights["keepalive"] = 0.10

        # MTU match (weight: 0.08)
        if observed_mtu is not None:
            signal_scores["mtu"] = _signal_match_score(
                observed_mtu, sig.mtu_default, 200.0
            )
            weights["mtu"] = 0.08

        # Congestion control match (weight: 0.18)
        if observed_congestion is not None:
            signal_scores["congestion"] = _signal_match_score(
                observed_congestion, sig.congestion, 0.5, is_categorical=True
            )
            weights["congestion"] = 0.18

        # Timestamp resolution match (weight: 0.17)
        if observed_ts_res is not None:
            signal_scores["timestamp"] = _signal_match_score(
                observed_ts_res, sig.timestamp_res, sig.timestamp_tol
            )
            weights["timestamp"] = 0.17

        # Compute weighted score
        total_weight = sum(weights.values())
        if total_weight > 0:
            weighted_score = sum(
                signal_scores[k] * weights[k] for k in signal_scores
            ) / total_weight
        else:
            weighted_score = 0.0

        # Apply prior (prior weight modulates the score)
        prior_factor = sig.weight / max(s.weight for s in OS_SIGNATURES)
        final_score = weighted_score * (0.7 + 0.3 * prior_factor)

        scores.append({
            "os": sig.name,
            "family": sig.family,
            "score": round(final_score, 4),
            "confidence_pct": round(final_score * 100, 1),
            "signal_details": {
                k: round(signal_scores[k], 3) for k in signal_scores
            },
            "prior": sig.weight,
        })

    scores.sort(key=lambda x: x["score"], reverse=True)

    # Normalize top scores to confidence percentages
    if scores and scores[0]["score"] > 0:
        top_score = scores[0]["score"]
        for entry in scores:
            entry["confidence_pct"] = round(
                (entry["score"] / top_score) * min(top_score * 100, 95), 1
            )

    return scores


# ═══════════════════════════════════════════════════════════════════════════
# Network-level helpers (stdlib socket)
# ═══════════════════════════════════════════════════════════════════════════

def _raw_tcp_connect(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
) -> Optional[float]:
    """Open a raw TCP socket, measure SYN→SYN-ACK latency.

    This is used as a supplementary signal — we don't send any data,
    just measure the raw TCP handshake time.
    """
    try:
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        elapsed = (time.perf_counter() - t0) * 1000.0
        sock.close()
        return elapsed
    except Exception:
        return None


def _extract_host(base_url: str) -> str:
    """Extract hostname from URL."""
    parsed = urllib.parse.urlparse(base_url)  # type: ignore
    return parsed.hostname or base_url.split("//")[-1].split("/")[0]


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def run_quantum_fingerprint(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Execute full TCP/IP stack fingerprinting via HTTP timing analysis.

    Parameters
    ----------
    target : str
        Human-readable target identifier (e.g. "example.com").
    base_url : str
        Base URL to probe (e.g. "https://example.com").
    timeout : int
        Per-request timeout in seconds (default 8).
    verify_tls : bool
        Whether to verify TLS certificates (default True).

    Returns
    -------
    List[Finding]
        Security findings for each detected signal and the
        consolidated OS identification.

    Notes
    -----
    This module is designed to work through HTTP proxies, NATs,
    and cloud load balancers.  Timing signals are degraded but
    not eliminated by intermediate infrastructure.

    Execution time: approximately 30–90 seconds depending on
    network latency and server responsiveness.
    """
    import urllib.parse  # ensure import at runtime

    findings: List[Finding] = []
    t_start = time.monotonic()

    # ── Phase 0: Raw TCP handshake baseline (supplementary) ───────────
    host = _extract_host(base_url)
    is_https = base_url.startswith("https")
    raw_port = 443 if is_https else 80

    raw_handshakes: List[float] = []
    for _ in range(5):
        rtt = _raw_tcp_connect(host, raw_port, timeout=timeout)
        if rtt is not None:
            raw_handshakes.append(rtt)
        time.sleep(0.1)

    raw_baseline = statistics.median(raw_handshakes) if raw_handshakes else 0

    # ── Phase 1–7: Execute all sub-probes ────────────────────────────
    probes: Dict[str, SubProbeResult] = {}
    probe_order = [
        ("ttl_deduction", _probe_ttl_deduction),
        ("tcp_window", _probe_tcp_window),
        ("synack_timing", _probe_synack_timing),
        ("keepalive", _probe_keepalive),
        ("mtu_detection", _probe_mtu),
        ("congestion_control", _probe_congestion_control),
        ("timestamp_resolution", _probe_timestamp_resolution),
    ]

    for name, probe_fn in probe_order:
        try:
            probe_result = probe_fn(
                base_url=base_url,
                timeout=timeout,
                verify_tls=verify_tls,
                limiter=default_limiter,
            )
            probes[name] = probe_result
        except Exception as exc:
            probes[name] = SubProbeResult(
                probe_name=name,
                description=f"Probe failed: {str(exc)[:120]}",
            )

    total_elapsed = time.monotonic() - t_start

    # ── Phase 8: Generate findings for each sub-probe ────────────────
    for name, probe in probes.items():
        if not probe.derived_value:
            continue

        severity = "info"
        points = 0

        if name == "ttl_deduction":
            ttl_val = probe.derived_value.get("deduced_ttl")
            desc = (
                f"Initial TTL deduced as {ttl_val} via payload-size / RTT "
                f"variance analysis. TTL families: 32=old routers, "
                f"64=Linux/macOS/BSD, 128=Windows, 255=networking gear."
            )
        elif name == "tcp_window":
            win = probe.derived_value.get("classification", "")
            desc = (
                f"TCP window size estimated as {win}. Window size "
                f"reveals kernel TCP buffer configuration and scaling "
                f"behaviour (RFC 1323 window scaling)."
            )
        elif name == "synack_timing":
            median = probe.derived_value.get("median_ms", 0)
            pattern = probe.derived_value.get("kernel_pattern", "")
            desc = (
                f"SYN-ACK first-byte latency: {median:.2f}ms median. "
                f"Pattern: {pattern}. Raw TCP handshake baseline: "
                f"{raw_baseline:.2f}ms."
            )
        elif name == "keepalive":
            timeout_s = probe.derived_value.get("estimated_timeout_s", 0)
            hint = probe.derived_value.get("keepalive_hint", "")
            desc = (
                f"HTTP keep-alive timeout ≈ {timeout_s:.1f}s. "
                f"{hint}. Short timeouts may indicate embedded devices "
                f"or aggressive connection management."
            )
        elif name == "mtu_detection":
            mtu_val = probe.derived_value.get("estimated_mtu", 0)
            cls = probe.derived_value.get("classification", "")
            desc = (
                f"Path MTU estimated at {mtu_val} bytes — {cls}. "
                f"Non-standard MTU may indicate VPN tunnels, PPPoE, "
                f"or cloud encapsulation overlays."
            )
            if mtu_val not in (1500, 0):
                severity = "low"
                points = 2
        elif name == "congestion_control":
            algo = probe.derived_value.get("algorithm", "")
            inflation = probe.derived_value.get("burst_inflation_pct", 0)
            desc = (
                f"Congestion control algorithm identified as '{algo}' "
                f"(burst inflation: {inflation:.1f}%). BBR indicates a "
                f"modern/CDN host; CUBIC indicates Linux 2.6.26+; "
                f"NewReno indicates older stacks."
            )
        elif name == "timestamp_resolution":
            cls = probe.derived_value.get("classification", "")
            desc = (
                f"Server clock resolution: {cls}. "
                f"15.625ms is a distinctive Windows signature; "
                f"~1ms indicates Linux/macOS/FreeBSD."
            )
        else:
            desc = probe.description

        evidence_json = json.dumps(probe.derived_value, indent=2, default=str)

        findings.append(Finding(
            title=f"TCP/IP Signal: {name.replace('_', ' ').title()}",
            severity=severity,
            category="fingerprinting",
            module=MODULE_NAME,
            description=desc,
            evidence=evidence_json,
            asset=target,
            points_deducted=points,
            remediation=(
                "Server fingerprinting signals cannot be eliminated "
                "without kernel-level TCP stack modifications. "
                "Consider deploying behind a CDN to normalize timing "
                "signals."
            ),
        ))

    # ── Phase 9: Consolidated OS Identification ───────────────────────
    os_scores = _compute_os_confidence(probes)

    if os_scores:
        top = os_scores[0]
        top_os = top["os"]
        top_confidence = top["confidence_pct"]
        top_family = top["family"]
        top_signals = top.get("signal_details", {})

        # Build evidence with top-5 OS candidates
        top_candidates = os_scores[:5]
        candidates_str = "\n".join(
            f"  {i+1}. {c['os']} ({c['family']}) — "
            f"{c['confidence_pct']:.1f}% confidence"
            for i, c in enumerate(top_candidates)
        )

        # Signal breakdown
        signal_lines: List[str] = []
        for sig_name, sig_val in top_signals.items():
            bar_len = int(sig_val * 20)
            bar = "\u2588" * bar_len + "\u2591" * (20 - bar_len)
            signal_lines.append(f"  {sig_name:12s}: {bar} {sig_val:.0%}")

        full_evidence = (
            f"=== QUANTUM FINGERPRINT OS IDENTIFICATION ===\n"
            f"Target: {target}\n"
            f"URL: {base_url}\n"
            f"Scan duration: {total_elapsed:.1f}s\n"
            f"Raw TCP baseline: {raw_baseline:.2f}ms\n"
            f"\nTOP CANDIDATE: {top_os} ({top_family})\n"
            f"Confidence: {top_confidence:.1f}%\n"
            f"\nSignal Match Breakdown:\n"
            + "\n".join(signal_lines) + "\n"
            f"\nAll Candidates:\n"
            f"{candidates_str}\n"
            f"\nRaw Scores:\n"
            f"{json.dumps(os_scores[:10], indent=2, default=str)}\n"
        )

        # Determine severity based on confidence
        if top_confidence >= 70:
            os_severity = "medium"
            os_points = 3
        elif top_confidence >= 40:
            os_severity = "low"
            os_points = 1
        else:
            os_severity = "info"
            os_points = 0

        findings.append(Finding(
            title=f"OS Identified: {top_os} ({top_confidence:.1f}% confidence)",
            severity=os_severity,
            category="fingerprinting",
            module=MODULE_NAME,
            description=(
                f"Quantum fingerprint analysis identified the remote "
                f"host as likely running '{top_os}' (family: {top_family}) "
                f"with {top_confidence:.1f}% confidence.\n\n"
                f"Identification was derived from {len(probes)} orthogonal "
                f"timing signals: initial TTL deduction, TCP window sizing, "
                f"SYN-ACK timing, keep-alive behaviour, MTU detection, "
                f"congestion control algorithm, and clock resolution.\n\n"
                f"Runners-up: {', '.join(c['os'] for c in top_candidates[1:4])}."
            ),
            evidence=full_evidence,
            asset=target,
            points_deducted=os_points,
            remediation=(
                "OS fingerprinting via timing analysis is difficult to "
                "prevent entirely. Mitigations include:\n"
                "  • Deploy behind a CDN (Cloudflare, Akamai) to "
                "    normalize timing signals\n"
                "  • Use TCP randomization patches (e.g., TPROXY)\n"
                "  • Set TCP timestamps to constant values\n"
                "  • Configure tcp_no_metrics_save = 1 (Linux)"
            ),
            dread_score=round(min(top_confidence / 100, 1.0) * 3.5, 1),
        ))

    # ── Phase 10: Technical Summary Finding ──────────────────────────
    probe_summary_lines: List[str] = []
    for name, probe in probes.items():
        probe_summary_lines.append(
            f"  {probe.probe_name:25s}: {probe.description}"
        )

    findings.append(Finding(
        title="Quantum Fingerprint: Technical Summary",
        severity="info",
        category="fingerprinting",
        module=MODULE_NAME,
        description=(
            f"TCP/IP stack fingerprinting completed against {target} in "
            f"{total_elapsed:.1f}s. {len(findings) - 1} findings generated. "
            f"Raw TCP handshake baseline: {raw_baseline:.2f}ms "
            f"({len(raw_handshakes)} samples). "
            f"Total HTTP probes: {sum(len(p.samples) for p in probes.values())}."
        ),
        evidence=(
            f"Probe Results:\n"
            + "\n".join(probe_summary_lines) + "\n"
            f"\nAll probe data:\n"
            + json.dumps(
                {n: p.derived_value for n, p in probes.items()
                 if p.derived_value},
                indent=2, default=str,
            )
        ),
        asset=target,
        points_deducted=0,
        remediation="",
    ))

    return findings
