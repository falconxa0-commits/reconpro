"""SIGNAL_INTELLIGENCE module — Intelligence-community traffic analysis frameworks.

ReconPro v9.2.0

Applies intelligence-community analysis frameworks to HTTP traffic observed from
a target.  Eight analytical capabilities are layered on top of a series of
repeated HTTP probes:

  1. Traffic Pattern Analysis      — request/response timing periodicity & jitter.
  2. Beaconing Detection             — C2 beacon fingerprinting (interval, size, jitter).
  3. C2 Pattern Matching             — known C2 framework fingerprints.
  4. Communication Schedule Extraction — maintenance windows, active hours.
  5. Payload Size Analysis           — encrypted-tunnel size indicators.
  6. User-Agent Fingerprinting       — automation, headless, C2 UA signatures.
  7. DNS-over-HTTP Pattern Analysis  — C2-via-DNS observed through HTTP.
  8. Session Behavior Profiling      — cookie, referrer, navigation chains.

Pure stdlib — zero external dependencies.
"""
from __future__ import annotations

import math
import re
import statistics
import time
import urllib.parse
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# C2_SIGNATURES DATABASE
# ═══════════════════════════════════════════════════════════════════════════

C2_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cobalt_strike": {
        "name": "Cobalt Strike",
        "developer": "HelpSystems / Fortra",
        "description": (
            "Advanced adversary simulation framework. HTTP C2 beacons support "
            "GET/POST check-in with configurable jitter, Malleable C2 profiles "
            "for traffic shaping, and sleep mask obfuscation."
        ),
        "default_beacon_interval": 60,
        "default_jitter_pct": 0.37,
        "known_profiles": [
            "amazon", "azure", "getchelp", "google",
            "maestro", "postman", "safari", "slack",
        ],
        "header_indicators": {
            "Cookie": r"session=[a-f0-9]{32}",
            "User-Agent": r"(Mozilla/5\.0 \(Windows NT.*Trident/7\.0|Mozilla/4\.0 \(compatible; MSIE.*\))",
        },
        "uri_patterns": [
            r"/[a-z]{4,8}\.(asp|aspx|php|js|css)",   # malleable profile URIs
            r"/pixel\.(gif|png|jpg)",
            r"/jquery-[\d.]+\.min\.js",
            r"/favicon\.(ico|png)",
        ],
        "response_size_range": (0, 4096),
        "request_size_range": (0, 8192),
        "dread_score": 9.0,
        "severity": "critical",
        "mitre_attack": ["T1071.001", "T1105", "T1573.001"],
    },
    "metasploit": {
        "name": "Metasploit Framework",
        "developer": "Rapid7 / Offensive Security",
        "description": (
            "Penetration testing framework with multiple HTTP-based payload "
            "stagers (reverse_http, reverse_https). Traffic often includes "
            "Base64-encoded stager URLs and predictable URI patterns."
        ),
        "default_beacon_interval": 5,
        "default_jitter_pct": 0.0,
        "known_payloads": [
            "reverse_http", "reverse_https", "bind_tcp",
            "meterpreter/reverse_tcp", "meterpreter/reverse_https",
        ],
        "header_indicators": {
            "Content-Type": r"application/octet-stream",
            "User-Agent": r"(Mozilla/4\.0|Lynx/|Wget/|curl/)",
        },
        "uri_patterns": [
            r"/[A-Za-z0-9+/]{16,}={0,2}",  # base64 stager URI
            r"/initializ[e]d",                         # meterpreter
            r"/\\x[0-9a-fA-F]{2}",                    # hex-encoded path
            r"/DLL_?\d+",                              # DLL staging
        ],
        "response_size_range": (0, 65536),
        "request_size_range": (0, 4096),
        "dread_score": 8.5,
        "severity": "critical",
        "mitre_attack": ["T1071.001", "T1059.003", "T1132.001"],
    },
    "empire": {
        "name": "Empire / Starkiller",
        "developer": "BC Security",
        "description": (
            "Post-exploitation framework with PowerShell/Python agents. "
            "HTTP C2 uses RESTful-style API calls with JSON payloads. "
            "Common check-in paths: /news.php, /login/process.php."
        ),
        "default_beacon_interval": 5,
        "default_jitter_pct": 0.2,
        "known_profiles": ["default", "redirector", "hop"],
        "header_indicators": {
            "Cookie": r"SESSIONID=[a-f0-9]{32,}",
            "Content-Type": r"application/json",
        },
        "uri_patterns": [
            r"/news\.php$",
            r"/login/process\.php$",
            r"/index\.php\?",
            r"/wp-admin/admin-ajax\.php",
        ],
        "response_size_range": (64, 16384),
        "request_size_range": (32, 8192),
        "dread_score": 8.0,
        "severity": "high",
        "mitre_attack": ["T1059.001", "T1071.001", "T1105"],
    },
    "covenant": {
        "name": "Covenant",
        "developer": "Cobalt Strike (community) / ropnop",
        "description": (
            ".NET C2 framework with HTTP/S listeners. Uses GUID-based "
            "reference IDs in URIs and headers. Grunt agents communicate via "
            "RESTful endpoints with JSON bodies."
        ),
        "default_beacon_interval": 5,
        "default_jitter_pct": 0.2,
        "known_profiles": ["default", "https-profile"],
        "header_indicators": {
            "Cookie": r"covenant=[a-f0-9-]{36}",
            "Content-Type": r"application/json",
        },
        "uri_patterns": [
            r"/api/covenant/[a-f0-9-]{36}",  # GUID-based paths
            r"/api/grunt/[a-f0-9-]{36}",
            r"/covenant/health",
        ],
        "response_size_range": (0, 8192),
        "request_size_range": (0, 8192),
        "dread_score": 7.5,
        "severity": "high",
        "mitre_attack": ["T1071.001", "T1021.007", "T1105"],
    },
    "sliver": {
        "name": "Sliver C2",
        "developer": "Bishop Fox",
        "description": (
            "Open-source C2 framework. HTTP(S) C2 uses mTLS and "
            "WireGuard tunnels. HTTP beacons may use .well-known paths "
            "and content-type sniffing avoidance."
        ),
        "default_beacon_interval": 10,
        "default_jitter_pct": 0.3,
        "known_profiles": ["default", "canary", "wireguard"],
        "header_indicators": {
            "Content-Type": r"application/octet-stream",
            "Sliver": r"[a-f0-9-]{36}",
        },
        "uri_patterns": [
            r"/\.well-known/[a-z]+",
            r"/wp-json/[a-z]+",
        ],
        "response_size_range": (0, 32768),
        "request_size_range": (0, 65536),
        "dread_score": 7.5,
        "severity": "high",
        "mitre_attack": ["T1071.001", "T1090.004", "T1573.001"],
    },
    "brute_ratel": {
        "name": "Brute Ratel",
        "developer": "Pentest Laboratories",
        "description": (
            "Advanced C2 with heavy focus on OPSEC. Uses HTTP/S with "
            "legitimate CDN-fronted domains. Hard to detect via signatures "
            "alone; identified primarily through behavioral analysis."
        ),
        "default_beacon_interval": 30,
        "default_jitter_pct": 0.25,
        "known_profiles": ["badger", "cdn-profile"],
        "header_indicators": {
            "Content-Type": r"application/octet-stream",
        },
        "uri_patterns": [
            r"/js/[a-f0-9]{8}\.js",
            r"/css/[a-f0-9]{8}\.css",
        ],
        "response_size_range": (0, 4096),
        "request_size_range": (0, 4096),
        "dread_score": 8.0,
        "severity": "critical",
        "mitre_attack": ["T1071.001", "T1071.004", "T1105"],
    },
    "havoc": {
        "name": "Havoc Framework",
        "developer": "C5pider",
        "description": (
            "Modern C2 framework with HTTP/S and SMB beacons. Uses "
            "custom binary protocol over HTTP with structured headers. "
            "Demon agents support user-defined profiles."
        ),
        "default_beacon_interval": 10,
        "default_jitter_pct": 0.2,
        "known_profiles": ["default", "stealth"],
        "header_indicators": {
            "Content-Type": r"application/octet-stream",
            "X-Havoc": r"[a-zA-Z0-9+/=]+",
        },
        "uri_patterns": [
            r"/demo/[a-z]+",
            r"/api/v[0-9]+/[a-z]+",
        ],
        "response_size_range": (0, 16384),
        "request_size_range": (0, 8192),
        "dread_score": 7.5,
        "severity": "high",
        "mitre_attack": ["T1071.001", "T1059.001", "T1105"],
    },
    "mythic": {
        "name": "Mythic C2",
        "developer": "ITSecTeam / Community",
        "description": (
            "Extensible C2 framework supporting multiple agent types. "
            "HTTP C2 uses customizable routing with JWT-style tokens "
            "and JSON-based tasking."
        ),
        "default_beacon_interval": 10,
        "default_jitter_pct": 0.3,
        "known_profiles": ["http", "dynamic-http"],
        "header_indicators": {
            "Authorization": r"Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Content-Type": r"application/json",
        },
        "uri_patterns": [
            r"/api/v[0-9]+/",
            r"/mythic/",
        ],
        "response_size_range": (0, 16384),
        "request_size_range": (0, 8192),
        "dread_score": 7.0,
        "severity": "high",
        "mitre_attack": ["T1071.001", "T1132.001", "T1105"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# BEACON_PATTERNS DATABASE
# ═══════════════════════════════════════════════════════════════════════════

BEACON_PATTERNS: Dict[str, Dict[str, Any]] = {
    "regular_interval": {
        "name": "Regular Interval Beacon",
        "description": (
            "Classic beaconing with fixed interval between check-ins. "
            "Common in basic C2 implementations without jitter."" "
            "Indicates unsophisticated or misconfigured C2 agent."
        ),
        "detection_criteria": {
            "cv_threshold": 0.15,        # coefficient of variation
            "min_samples": 4,
            "typical_intervals": [1, 5, 10, 30, 60, 120, 300, 600],
        },
        "dread_score": 7.0,
        "severity": "high",
    },
    "jittered_beacon": {
        "name": "Jittered Beacon",
        "description": (
            "Beacon with randomized timing to evade statistical detection. "
            "Observed intervals cluster around a base with controlled variance. "
            "Common in Cobalt Strike, Sliver, and similar frameworks."
        ),
        "detection_criteria": {
            "cv_min": 0.15,
            "cv_max": 0.60,
            "min_samples": 6,
            "jitter_pct_range": (0.10, 0.50),
        },
        "dread_score": 8.0,
        "severity": "critical",
    },
    "high_jitter_beacon": {
        "name": "High-Jitter Beacon",
        "description": (
            "Beacon with very high jitter (50%+), making it harder to "
            "distinguish from legitimate traffic. Often used by advanced C2 "
            "frameworks with strong OPSEC. Requires behavioral baselining."
        ),
        "detection_criteria": {
            "cv_min": 0.50,
            "cv_max": 1.0,
            "min_samples": 8,
            "jitter_pct_range": (0.50, 0.80),
        },
        "dread_score": 8.5,
        "severity": "critical",
    },
    "small_payload_beacon": {
        "name": "Small Payload Beacon",
        "description": (
            "Beacon characterized by consistently small request/response sizes. "
            "Indicates heartbeat check-ins with minimal data exchange, "
            "typical of idle C2 agents awaiting tasking."
        ),
        "detection_criteria": {
            "max_response_bytes": 512,
            "max_request_bytes": 256,
            "size_cv_threshold": 0.30,
            "min_samples": 4,
        },
        "dread_score": 6.5,
        "severity": "medium",
    },
    "consistent_response_size": {
        "name": "Consistent Response Size Beacon",
        "description": (
            "Beacon where response sizes are nearly identical across "
            "check-ins. Suggests a fixed-format 'no-task' acknowledgment "
            "from the C2 server. Strong indicator of automated communication."
        ),
        "detection_criteria": {
            "response_size_cv_threshold": 0.10,
            "min_samples": 5,
        },
        "dread_score": 7.0,
        "severity": "high",
    },
    "exponential_backoff": {
        "name": "Exponential Backoff Beacon",
        "description": (
            "Beacon that increases interval exponentially after failed "
            "check-ins, then resets. Used for resilience in contested "
            "networks. Pattern: short → medium → long → reset."
        ),
        "detection_criteria": {
            "growth_factor_min": 1.5,
            "growth_factor_max": 4.0,
            "min_sequence_length": 3,
            "tolerance_pct": 0.25,
        },
        "dread_score": 7.5,
        "severity": "high",
    },
    "time_diverse_beacon": {
        "name": "Time-Diverse Beacon",
        "description": (
            "Beacon that varies interval based on time of day or day of week. "
            "Mimics human activity patterns — shorter intervals during "
            "business hours, longer at night. Sophisticated OPSEC measure."
        ),
        "detection_criteria": {
            "min_hour_variance": 0.3,   # stddev of intervals per hour block
            "min_samples_per_hour": 2,
            "active_hours": (8, 20),     # expected human active window
        },
        "dread_score": 8.5,
        "severity": "critical",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# AUTOMATION_UA_SIGNATURES DATABASE
# ═══════════════════════════════════════════════════════════════════════════

AUTOMATION_UA_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "headless_browser": {
        "name": "Headless Browser",
        "category": "automation",
        "indicators": [
            r"HeadlessChrome",
            r"headless",
            r"PhantomJS",
            r"selenium",
            r"Selenium",
            r"webdriver",
            r"WebDriver",
            r"puppeteer",
            r"Puppeteer",
            r"playwright",
            r"Playwright",
        ],
        "stealth_score": 30,      # easily detected
        "dread_score": 5.0,
        "severity": "medium",
        "description": (
            "Headless browsers used for automated web interaction, "
            "scraping, or C2 browsing proxy. Presence indicates automated "
            "tooling rather than human users."
        ),
    },
    "http_library": {
        "name": "HTTP Client Library",
        "category": "automation",
        "indicators": [
            r"^python-requests",
            r"^requests/",
            r"^axios/",
            r"^node-fetch",
            r"^Java/",
            r"^Apache-HttpClient",
            r"^okhttp",
            r"^Go-http-client",
            r"^curl/",
            r"^Wget/",
            r"^libwww",
            r"^http\.client",
            r"^Java\/1\.",
        ],
        "stealth_score": 50,
        "dread_score": 5.5,
        "severity": "medium",
        "description": (
            "Standard HTTP client libraries typically indicate programmatic "
            "access. While common in legitimate APIs, they are unusual for "
            "interactive web browsing and may signal automated reconnaissance."
        ),
    },
    "c2_agent": {
        "name": "C2 Agent User-Agent",
        "category": "malicious",
        "indicators": [
            r"^Mozilla/4\.0 \(compatible; MSIE [67]\.0",
            r"^Mozilla/5\.0 \(Windows NT 6\.1; Trident/7\.0",
            r"^Mozilla/5\.0 \(compatible; MSIE 10\.0",
            r"^Microsoft-CryptoAPI",
            r"^Windows-PowerShell",
            r"^PowerShell",
            r"^WinHTTP",
            r"^Microsoft-WebApplication",
        ],
        "stealth_score": 70,
        "dread_score": 8.0,
        "severity": "high",
        "description": (
            "User-Agent strings commonly associated with C2 agents. These "
            "often mimic legacy Windows software to blend with corporate "
            "traffic, but the specific UA versions and formats are telltale."
        ),
    },
    "scraping_tool": {
        "name": "Web Scraping Tool",
        "category": "automation",
        "indicators": [
            r"^scrapy",
            r"^Scrapy",
            r"^beautifulsoup",
            r"^mechanize",
            r"^HTTrack",
            r"^wget",
            r"^curl",
            r"^lwp-trivial",
            r"^AhrefsBot",
            r"^MJ12bot",
            r"^SemrushBot",
            r"^DotBot",
        ],
        "stealth_score": 20,
        "dread_score": 4.0,
        "severity": "low",
        "description": (
            "Known web scraping and crawling tools. These may indicate "
            "OSINT gathering, competitive intelligence, or data harvesting. "
            "Low individual risk but may contribute to broader attack pattern."
        ),
    },
    "vulnerability_scanner": {
        "name": "Vulnerability Scanner",
        "category": "recon",
        "indicators": [
            r"^Nikto",
            r"^nmap",
            r"^Nessus",
            r"^OpenVAS",
            r"^WPScan",
            r"^sqlmap",
            r"^DirBuster",
            r"^Gobuster",
            r"^ZAP",
            r"^BurpSuite",
            r"^Acunetix",
            r"^Nuclei",
            r"^ReconPro",
        ],
        "stealth_score": 10,
        "dread_score": 6.0,
        "severity": "medium",
        "description": (
            "Known security scanning tools detected in User-Agent. "
            "Indicates active vulnerability assessment or attack "
            "reconnaissance targeting the asset."
        ),
    },
    "suspicious_generic": {
        "name": "Suspicious Generic UA",
        "category": "anomaly",
        "indicators": [
            r"^Mozilla/5\.0$",
            r"^Mozilla/4\.0$",
            r"^$",                                 # empty UA
            r"^-?$",
            r"^\s+$",
            r"^\{.*\}$",                        # JSON in UA
            r"^[a-f0-9]{32,}$",                  # hex hash as UA
            r"^[A-Za-z0-9+/=]{20,}$",            # base64 as UA
        ],
        "stealth_score": 80,
        "dread_score": 7.0,
        "severity": "high",
        "description": (
            "User-Agent strings that are empty, generic, or contain "
            "encoded data. These are strong indicators of custom tools, "
            "malware, or C2 agents that do not properly impersonate browsers."
        ),
    },
    "mobile_automation": {
        "name": "Mobile Automation Framework",
        "category": "automation",
        "indicators": [
            r"^Appium",
            r"^Calabash",
            r"^Dalvik",
            r"^Android.*Dalvik",
            r"^CFNetwork.*Dalvik",
        ],
        "stealth_score": 35,
        "dread_score": 4.5,
        "severity": "low",
        "description": (
            "Mobile automation frameworks that may indicate app security "
            "testing or automated mobile C2 channels."
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

# A single timed probe result.
ProbeSample = Dict[str, Any]

# Paths to probe for traffic observation.
_OBSERVATION_PATHS: List[str] = [
    "/",
    "/index.html",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/health",
    "/api/",
    "/.well-known/",
]

# Number of probe rounds for timing analysis.
_PROBE_ROUNDS: int = 8


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string in bits."""
    if not data:
        return 0.0
    freq: Counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _coefficient_of_variation(values: List[float]) -> Optional[float]:
    """CV = stddev / mean.  Returns None if mean is zero or insufficient data."""
    if len(values) < 2:
        return None
    m = statistics.mean(values)
    if m == 0:
        return None
    return statistics.stdev(values) / m


def _detect_periodicity(values: List[float]) -> Optional[Dict[str, Any]]:
    """Simple autocorrelation-based periodicity detection.

    Returns dict with 'period', 'confidence', 'mean_interval' or None.
    """
    n = len(values)
    if n < 4:
        return None

    mean_val = statistics.mean(values)
    if mean_val == 0:
        return None

    centered = [v - mean_val for v in values]
    variance = sum(c * c for c in centered) / n
    if variance == 0:
        return None

    best_lag = 0
    best_corr = 0.0

    for lag in range(1, n // 2):
        corr_sum = sum(centered[i] * centered[i + lag] for i in range(n - lag))
        corr = corr_sum / ((n - lag) * variance)
        if corr > best_corr:
            best_corr = corr
            best_lag = lag

    if best_corr < 0.4 or best_lag == 0:
        return None

    period_values = [values[i] for i in range(0, n, best_lag) if i < n]
    if len(period_values) < 2:
        return None

    return {
        "period": best_lag,
        "confidence": round(best_corr, 3),
        "mean_interval": round(statistics.mean(values), 4),
        "period_mean": round(statistics.mean(period_values), 4),
    }


def _rounds_to_seconds_estimate(rounds: int) -> float:
    """Estimate the observation window in seconds (rough timing)."""
    # Each round has _PROBE_ROUNDS probes with rate limiter delays.
    return rounds * _PROBE_ROUNDS * 0.15


# ═══════════════════════════════════════════════════════════════════════════
# 1. TRAFFIC PATTERN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_traffic_patterns(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Analyze request/response timing patterns for periodicity, jitter, and
    communication schedules.
    """
    findings: List[Finding] = []

    if len(samples) < 3:
        return findings

    # Extract timing data
    response_times: List[float] = [s["response_time"] for s in samples if s.get("ok")]
    intervals: List[float] = []
    for i in range(1, len(samples)):
        dt = samples[i]["timestamp"] - samples[i - 1]["timestamp"]
        if dt > 0:
            intervals.append(dt)

    if not intervals:
        return findings

    mean_interval = statistics.mean(intervals)
    cv = _coefficient_of_variation(intervals)
    periodicity = _detect_periodicity(intervals)

    # Build evidence
    evidence_parts = [
        f"Samples collected: {len(samples)}",
        f"Successful probes: {len(response_times)}",
        f"Mean interval: {mean_interval:.3f}s",
    ]
    if cv is not None:
        evidence_parts.append(f"Interval CV: {cv:.4f}")
    if response_times:
        evidence_parts.append(
            f"Mean response time: {statistics.mean(response_times):.3f}s"
        )
    if periodicity:
        evidence_parts.append(
            f"Period detected: every {periodicity['period']} samples "
            f"(confidence: {periodicity['confidence']})"
        )

    evidence = "\n".join(evidence_parts)

    # Detect low-jitter pattern (potential beacon)
    if cv is not None and cv < 0.15:
        findings.append(Finding(
            title="Low-Jitter Timing Pattern Detected",
            severity="high",
            category="signal_timing",
            module="signal_intelligence",
            description=(
                f"HTTP responses from {target} show unusually consistent timing "
                f"(CV={cv:.4f}). Low jitter in response intervals can indicate "
                f"automated service endpoints, scheduled tasks, or potential C2 "
                f"beaconing infrastructure. The mean interval of {mean_interval:.3f}s "
                f"suggests {mean_interval:.1f}s periodicity."
            ),
            evidence=evidence,
            asset=base_url,
            points_deducted=5,
            dread_score=6.5,
            remediation=(
                "Investigate the endpoint for scheduled task configuration. "
                "Compare timing patterns against known C2 beacon intervals. "
                "Implement timing-based anomaly detection in network monitoring."
            ),
        ))
    elif cv is not None and cv > 0.8:
        findings.append(Finding(
            title="High-Variance Timing Pattern",
            severity="low",
            category="signal_timing",
            module="signal_intelligence",
            description=(
                f"HTTP response timing from {target} shows high variability "
                f"(CV={cv:.4f}). This could indicate load balancing, caching "
                f"layers, or adaptive rate limiting. While not directly malicious, "
                f"high variance complicates beacon detection and may mask "
                f"underlying periodic communications."
            ),
            evidence=evidence,
            asset=base_url,
            points_deducted=1,
            dread_score=3.0,
            remediation=(
                "Baseline normal timing variance for this service. "
                "Use longer observation windows to detect periodicity "
                f"within high-variance traffic."
            ),
        ))

    # Periodicity finding
    if periodicity and periodicity["confidence"] > 0.6:
        findings.append(Finding(
            title="Significant Communication Periodicity Detected",
            severity="medium",
            category="signal_periodicity",
            module="signal_intelligence",
            description=(
                f"Autocorrelation analysis detected a periodic pattern in HTTP "
                f"traffic to/from {target}. Period: every {periodicity['period']} "
                f"samples (confidence: {periodicity['confidence']}). "
                f"Mean interval: {periodicity['mean_interval']}s. Periodic "
                f"communication patterns are a hallmark of C2 beacons, "
                f"scheduled data exfiltration, and automated reconnaissance."
            ),
            evidence=evidence,
            asset=base_url,
            points_deducted=3,
            dread_score=6.0,
            remediation=(
                "Correlate detected period with known C2 default intervals. "
                "Investigate what service or process triggers periodic HTTP "
                "requests. Deploy behavioral analytics to flag repeated patterns."
            ),
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 2. BEACONING DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_beaconing(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Detect C2 beaconing patterns: regular intervals, small payloads,
    consistent timing with jitter.
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    if len(ok_samples) < BEACON_PATTERNS["regular_interval"]["detection_criteria"]["min_samples"]:
        return findings

    intervals: List[float] = []
    for i in range(1, len(ok_samples)):
        dt = ok_samples[i]["timestamp"] - ok_samples[i - 1]["timestamp"]
        if dt > 0:
            intervals.append(dt)

    if not intervals:
        return findings

    cv = _coefficient_of_variation(intervals)
    mean_interval = statistics.mean(intervals)
    resp_sizes: List[int] = [s["response_size"] for s in ok_samples]
    req_sizes: List[int] = [s["request_size"] for s in ok_samples]

    matched_beacons: List[str] = []
    evidence_parts: List[str] = [
        f"Successful samples: {len(ok_samples)}",
        f"Mean interval: {mean_interval:.3f}s",
    ]
    if cv is not None:
        evidence_parts.append(f"Interval CV: {cv:.4f}")
    evidence_parts.append(
        f"Response sizes: min={min(resp_sizes) if resp_sizes else 0}, "
        f"max={max(resp_sizes) if resp_sizes else 0}, "
        f"mean={statistics.mean(resp_sizes) if resp_sizes else 0:.0f}"
    )

    # Check against beacon patterns
    # Regular interval beacon
    criteria = BEACON_PATTERNS["regular_interval"]["detection_criteria"]
    if cv is not None and cv < criteria["cv_threshold"]:
        # Check if interval matches known beacon intervals
        nearest_known = min(
            criteria["typical_intervals"],
            key=lambda t: abs(t - mean_interval),
        )
        if abs(nearest_known - mean_interval) / max(nearest_known, 1) < 0.30:
            matched_beacons.append("regular_interval")
            evidence_parts.append(
                f"MATCH: Regular interval ~{nearest_known}s beacon "
                f"(actual: {mean_interval:.2f}s, deviation: "
                f"{abs(nearest_known - mean_interval):.2f}s)"
            )

    # Jittered beacon
    criteria_j = BEACON_PATTERNS["jittered_beacon"]["detection_criteria"]
    if (cv is not None
            and criteria_j["cv_min"] <= cv <= criteria_j["cv_max"]):
        matched_beacons.append("jittered_beacon")
        evidence_parts.append(
            f"MATCH: Jittered beacon (CV={cv:.4f} within "
            f"[{criteria_j['cv_min']}, {criteria_j['cv_max']}])"
        )

    # High-jitter beacon
    criteria_hj = BEACON_PATTERNS["high_jitter_beacon"]["detection_criteria"]
    if (cv is not None
            and criteria_hj["cv_min"] <= cv <= criteria_hj["cv_max"]):
        matched_beacons.append("high_jitter_beacon")
        evidence_parts.append(
            f"MATCH: High-jitter beacon (CV={cv:.4f} within "
            f"[{criteria_hj['cv_min']}, {criteria_hj['cv_max']}])"
        )

    # Small payload beacon
    criteria_sp = BEACON_PATTERNS["small_payload_beacon"]["detection_criteria"]
    if (len(resp_sizes) >= criteria_sp["min_samples"]
            and max(resp_sizes) <= criteria_sp["max_response_bytes"]):
        matched_beacons.append("small_payload_beacon")
        evidence_parts.append(
            f"MATCH: Small payload beacon (max response: {max(resp_sizes)}B "
            f"<= {criteria_sp['max_response_bytes']}B)"
        )

    # Consistent response size beacon
    criteria_cr = BEACON_PATTERNS["consistent_response_size"]["detection_criteria"]
    if len(resp_sizes) >= criteria_cr["min_samples"]:
        resp_cv = _coefficient_of_variation([float(s) for s in resp_sizes])
        if resp_cv is not None and resp_cv < criteria_cr["response_size_cv_threshold"]:
            matched_beacons.append("consistent_response_size")
            evidence_parts.append(
                f"MATCH: Consistent response size (CV={resp_cv:.4f})"
            )

    # Generate findings for matched beacons
    for beacon_key in matched_beacons:
        pattern = BEACON_PATTERNS[beacon_key]
        findings.append(Finding(
            title=f"Beacon Pattern Detected: {pattern['name']}",
            severity=pattern["severity"],
            category="beacon_detection",
            module="signal_intelligence",
            description=(
                f"{pattern['description']} Observed on {target} with "
                f"mean interval {mean_interval:.3f}s, CV={cv:.4f if cv else 'N/A'}. "
                f"This pattern is consistent with automated C2 communication."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=8 if pattern["severity"] in ("critical", "high") else 3,
            dread_score=pattern["dread_score"],
            remediation=(
                "Isolate and analyze the communication endpoint. Correlate with "
                "endpoint process information. Implement beacon detection rules in "
                "SIEM. Block or rate-limit the endpoint if confirmed malicious."
            ),
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 3. C2 PATTERN MATCHING
# ═══════════════════════════════════════════════════════════════════════════

def _match_c2_patterns(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Match observed communication patterns against known C2 frameworks.
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    if not ok_samples:
        return findings

    # Collect all observed response headers and body content
    observed_headers: Dict[str, List[str]] = {}
    observed_bodies: List[str] = []
    observed_paths: List[str] = []
    observed_status_codes: List[int] = []

    for s in ok_samples:
        for hdr, val in s.get("response_headers", {}).items():
            observed_headers.setdefault(hdr.lower(), []).append(val)
        if s.get("response_body"):
            observed_bodies.append(s["response_body"])
        if s.get("path"):
            observed_paths.append(s["path"])
        if s.get("status"):
            observed_status_codes.append(s["status"])

    # Also collect request headers from any observed
    request_uas: List[str] = []
    for s in ok_samples:
        ua = s.get("request_headers", {}).get("user-agent", "")
        if ua:
            request_uas.append(ua)

    for c2_key, c2_sig in C2_SIGNATURES.items():
        match_score = 0
        match_evidence: List[str] = []
        max_possible = 0

        # Check header indicators
        for hdr_name, hdr_pattern in c2_sig["header_indicators"].items():
            max_possible += 2
            hdr_values = observed_headers.get(hdr_name.lower(), [])
            for val in hdr_values:
                if re.search(hdr_pattern, val, re.IGNORECASE):
                    match_score += 2
                    match_evidence.append(
                        f"  Header [{hdr_name}] matches: \"{val[:80]}\""
                    )
                    break

        # Check URI patterns against response body / redirect locations
        for uri_pat in c2_sig["uri_patterns"]:
            max_possible += 1
            for path in observed_paths:
                if re.search(uri_pat, path, re.IGNORECASE):
                    match_score += 1
                    match_evidence.append(f"  URI pattern matches: {path}")
                    break
            # Also check body content for references to these patterns
            for body in observed_bodies[:3]:  # limit body scans
                if re.search(uri_pat, body, re.IGNORECASE):
                    match_score += 1
                    match_evidence.append(
                        f"  Body contains URI pattern: {uri_pat[:50]}"
                    )
                    break

        # Check response size range
        resp_sizes = [s["response_size"] for s in ok_samples]
        if resp_sizes:
            max_possible += 1
            rmin, rmax = c2_sig["response_size_range"]
            in_range = sum(1 for sz in resp_sizes if rmin <= sz <= rmax)
            if in_range / len(resp_sizes) > 0.7:
                match_score += 1
                match_evidence.append(
                    f"  {in_range}/{len(resp_sizes)} responses in size range "
                    f"[{rmin}, {rmax}]"
                )

        # Only report if we have meaningful matches
        if match_score > 0 and max_possible > 0:
            confidence = match_score / max_possible
            if confidence >= 0.2:  # 20% minimum match threshold
                mitre_str = ", ".join(c2_sig.get("mitre_attack", []))
                findings.append(Finding(
                    title=f"C2 Framework Pattern Match: {c2_sig['name']}",
                    severity=c2_sig["severity"],
                    category="c2_pattern_match",
                    module="signal_intelligence",
                    description=(
                        f"Observed HTTP traffic from {target} exhibits patterns "
                        f"consistent with {c2_sig['name']} ({c2_sig['developer']}). "
                        f"{c2_sig['description']} Match confidence: "
                        f"{confidence:.1%}. MITRE ATT&CK: {mitre_str}."
                    ),
                    evidence=(
                        f"C2 Framework: {c2_sig['name']}\n"
                        f"Developer: {c2_sig['developer']}\n"
                        f"Match Score: {match_score}/{max_possible} "
                        f"({confidence:.1%})\n"
                        f"Matched Indicators:\n"
                        + ("\n".join(match_evidence) if match_evidence else "  (size range only)")
                        + f"\nMITRE ATT&CK: {mitre_str}"
                    ),
                    asset=base_url,
                    points_deducted=10 if c2_sig["severity"] == "critical" else 6,
                    dread_score=c2_sig["dread_score"] * confidence,
                    remediation=(
                        f"Investigate endpoint for {c2_sig['name']} artifacts: "
                        f"dropped files, persistence mechanisms, lateral movement "
                        f"indicators. Deploy YARA/Sigma rules for {c2_sig['name']}. "
                        f"Review MITRE techniques: {mitre_str}."
                    ),
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 4. COMMUNICATION SCHEDULE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _extract_communication_schedule(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Extract the 'when' of communications — maintenance windows,
    active hours, backup schedules.
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    if len(ok_samples) < 3:
        return findings

    # Analyze response time distribution for patterns
    response_times = [s["response_time"] for s in ok_samples]
    resp_sizes = [s["response_size"] for s in ok_samples]
    status_codes = [s["status"] for s in ok_samples]

    # Bucket by response time (fast / normal / slow)
    fast = [s for s in ok_samples if s["response_time"] < 0.3]
    normal = [s for s in ok_samples if 0.3 <= s["response_time"] < 1.5]
    slow = [s for s in ok_samples if s["response_time"] >= 1.5]

    # Look for error rate patterns
    error_count = sum(1 for sc in status_codes if sc >= 400)
    error_rate = error_count / len(status_codes) if status_codes else 0

    evidence_parts = [
        f"Total probes: {len(ok_samples)}",
        f"Fast (<0.3s): {len(fast)}",
        f"Normal (0.3-1.5s): {len(normal)}",
        f"Slow (>=1.5s): {len(slow)}",
        f"Error rate: {error_rate:.1%}",
        f"Status codes: {dict(Counter(str(sc) for sc in status_codes))}",
    ]

    if resp_sizes:
        evidence_parts.append(
            f"Response size range: {min(resp_sizes)} - {max(resp_sizes)} bytes"
        )

    # Check for high error rate (possible maintenance window / rate limiting)
    if error_rate > 0.4:
        findings.append(Finding(
            title="High Error Rate Pattern — Possible Rate Limiting or Maintenance",
            severity="medium",
            category="comm_schedule",
            module="signal_intelligence",
            description=(
                f"{error_rate:.1%} of HTTP requests to {target} returned errors. "
                f"This may indicate: (1) Active rate limiting being triggered by "
                f"the observation probes, (2) A maintenance window or degraded "
                f"service period, (3) Defensive WAF/IPS blocking, or "
                f"(4) Intentional service degradation as a defense mechanism."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=3,
            dread_score=5.0,
            remediation=(
                "Distinguish between rate limiting and genuine errors. "
                "If rate limited, adjust probe cadence. If maintenance window, "
                "document the schedule for future reference. Check WAF logs."
            ),
        ))

    # Check for bimodal timing (e.g., cached vs uncached responses)
    if len(response_times) >= 6:
        sorted_times = sorted(response_times)
        lower_half = sorted_times[: len(sorted_times) // 2]
        upper_half = sorted_times[len(sorted_times) // 2:]
        lower_mean = statistics.mean(lower_half)
        upper_mean = statistics.mean(upper_half)
        ratio = upper_mean / lower_mean if lower_mean > 0 else float("inf")

        if ratio > 3.0:
            evidence_parts.append(
                f"Bimodal timing: lower mean={lower_mean:.3f}s, "
                f"upper mean={upper_mean:.3f}s, ratio={ratio:.1f}x"
            )
            findings.append(Finding(
                title="Bimodal Response Timing — Cache/Origin Differentiation",
                severity="low",
                category="comm_schedule",
                module="signal_intelligence",
                description=(
                    f"HTTP responses from {target} show bimodal timing distribution. "
                    f"Lower cluster ({lower_mean:.3f}s) likely cache hits; upper cluster "
                    f"({upper_mean:.3f}s) likely origin fetches. This differentiation "
                    f"can be exploited for cache timing attacks or to distinguish "
                    f"frontend infrastructure from backend systems."
                ),
                evidence="\n".join(evidence_parts),
                asset=base_url,
                points_deducted=1,
                dread_score=3.5,
                remediation=(
                    "Implement consistent cache headers. Normalize response "
                    "timing where possible. Monitor for cache timing side-channel "
                    "attacks."
                ),
            ))

    # Check for consistent slow responses (possible indicator of heavy processing / encryption)
    if len(slow) > len(ok_samples) * 0.6 and len(ok_samples) >= 4:
        findings.append(Finding(
            title="Predominantly Slow Responses — Possible Encryption/Processing Overhead",
            severity="low",
            category="comm_schedule",
            module="signal_intelligence",
            description=(
                f"{len(slow)}/{len(ok_samples)} responses from {target} exceeded 1.5s. "
                f"This may indicate server-side encryption/decryption overhead, "
                f"heavy computation, or a congested/restricted endpoint. In a C2 "
                f"context, consistent delays can indicate tunnel decryption or "
                f"data processing before response."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=1,
            dread_score=2.5,
            remediation=(
                "Profile normal response times for this service. Investigate "
                "server-side processing that causes consistent delays."
            ),
        ))

    # General schedule summary
    if response_times:
        schedule_summary = (
            f"Communication Schedule Profile for {target}:\n"
            f"  Mean response: {statistics.mean(response_times):.3f}s\n"
            f"  Median response: {statistics.median(response_times):.3f}s\n"
            f"  Min/Max: {min(response_times):.3f}s / {max(response_times):.3f}s\n"
            f"  StdDev: {statistics.stdev(response_times) if len(response_times) > 1 else 0:.3f}s\n"
            f"  Error rate: {error_rate:.1%}\n"
            f"  Fast/Normal/Slow ratio: {len(fast)}/{len(normal)}/{len(slow)}"
        )
        findings.append(Finding(
            title="Communication Schedule Profile",
            severity="info",
            category="comm_schedule",
            module="signal_intelligence",
            description=(
                f"Extracted communication schedule profile for {target} based on "
                f"{len(ok_samples)} successful probes. This profile captures the "
                f'"when" of the target\'s HTTP communication — response latency '
                f"distribution, error patterns, and timing characteristics that "
                f"form the baseline for anomaly detection."
            ),
            evidence=schedule_summary,
            asset=base_url,
            points_deducted=0,
            dread_score=0.0,
            remediation=(
                "Use this schedule profile as a baseline. Deviations from this "
                "profile may indicate compromise, configuration changes, or "
                "active exploitation. Integrate into SIEM correlation rules."
            ),
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 5. PAYLOAD SIZE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_payload_sizes(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Analyze request/response sizes for encrypted tunnel indicators.
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    if len(ok_samples) < 3:
        return findings

    resp_sizes = [s["response_size"] for s in ok_samples]
    bodies = [s.get("response_body", "") for s in ok_samples]
    body_entropies = [_shannon_entropy(b) for b in bodies if b]

    mean_size = statistics.mean(resp_sizes)
    size_cv = _coefficient_of_variation([float(s) for s in resp_sizes])
    mean_entropy = statistics.mean(body_entropies) if body_entropies else 0.0

    evidence_parts = [
        f"Samples analyzed: {len(ok_samples)}",
        f"Response sizes: min={min(resp_sizes)}, max={max(resp_sizes)}, "
        f"mean={mean_size:.0f}",
    ]
    if size_cv is not None:
        evidence_parts.append(f"Size CV: {size_cv:.4f}")
    if body_entropies:
        evidence_parts.append(
            f"Body entropy: min={min(body_entropies):.2f}, "
            f"max={max(body_entropies):.2f}, mean={mean_entropy:.2f} bits"
        )

    # Check for consistent small responses (tunnel indicator)
    if (len(resp_sizes) >= 4
            and max(resp_sizes) <= 256
            and (size_cv is not None and size_cv < 0.20)):
        findings.append(Finding(
            title="Consistently Small Responses — Potential Encrypted Tunnel Indicator",
            severity="medium",
            category="payload_size",
            module="signal_intelligence",
            description=(
                f"All responses from {target} are small (max {max(resp_sizes)}B) "
                f"with low size variation (CV={size_cv:.4f}). This pattern is "
                f"consistent with encrypted C2 tunnel endpoints where the server "
                f"returns minimal acknowledgment payloads. Legitimate small "
                f"responses include health checks, API heartbeats, and redirects."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=4,
            dread_score=5.5,
            remediation=(
                "Verify the endpoint's intended purpose. Check if small responses "
                "contain meaningful data or are stub acknowledgments. Correlate "
                "with endpoint process and network flow data."
            ),
        ))

    # Check for high-entropy responses (encrypted/compressed data)
    if mean_entropy > 5.5 and body_entropies:
        high_entropy_count = sum(1 for e in body_entropies if e > 5.0)
        findings.append(Finding(
            title="High-Entropy Response Bodies — Encrypted or Compressed Content",
            severity="low",
            category="payload_size",
            module="signal_intelligence",
            description=(
                f"Response bodies from {target} exhibit high Shannon entropy "
                f"(mean={mean_entropy:.2f} bits, {high_entropy_count}/{len(body_entropies)} "
                f"above 5.0 bits). This indicates the content is likely encrypted, "
                f"compressed, or encoded — common in API responses, CDN content, "
                f"and potentially C2 data channels."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=1,
            dread_score=3.0,
            remediation=(
                "Determine if high entropy is expected (TLS, compression). "
                "Compare against known-good baselines. Investigate if "
                "entropy is anomalous for this endpoint type."
            ),
        ))

    # Check for suspiciously uniform response sizes (fixed-block encryption)
    unique_sizes = len(set(resp_sizes))
    if len(resp_sizes) >= 6 and unique_sizes <= 2:
        findings.append(Finding(
            title="Uniform Response Sizes — Possible Fixed-Block Encryption",
            severity="medium",
            category="payload_size",
            module="signal_intelligence",
            description=(
                f"Only {unique_sizes} distinct response size(s) across "
                f"{len(resp_sizes)} responses from {target}. Uniform sizes are "
                f"characteristic of fixed-block encryption (AES-CBC, etc.) or "
                f"templated responses. Distinct sizes: {sorted(set(resp_sizes))}."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=3,
            dread_score=5.0,
            remediation=(
                "Analyze response content structure. Determine if uniformity is "
                f"from encryption padding, templating, or genuine content. "
                f"Unique sizes observed: {sorted(set(resp_sizes))}"
            ),
        ))

    # Size profile summary
    size_histogram: Dict[str, int] = {}
    for sz in resp_sizes:
        bucket = (
            "0-128B" if sz <= 128 else
            "129-512B" if sz <= 512 else
            "513-2KB" if sz <= 2048 else
            "2KB-8KB" if sz <= 8192 else
            "8KB-32KB" if sz <= 32768 else
            ">32KB"
        )
        size_histogram[bucket] = size_histogram.get(bucket, 0) + 1

    evidence_parts.append(
        "Size distribution: "
        + ", ".join(f"{k}:{v}" for k, v in sorted(size_histogram.items()))
    )

    findings.append(Finding(
        title="Payload Size Analysis Profile",
        severity="info",
        category="payload_size",
        module="signal_intelligence",
        description=(
            f"Payload size analysis for {target}. Mean response size: {mean_size:.0f}B. "
            f"Entropy profile: {mean_entropy:.2f} bits. Size consistency: "
            f"CV={size_cv:.4f if size_cv else 'N/A'}. This profile helps identify "
            f"anomalous size patterns that may indicate encrypted tunnels, "
            f"data exfiltration, or C2 communication."
        ),
        evidence="\n".join(evidence_parts),
        asset=base_url,
        points_deducted=0,
        dread_score=0.0,
        remediation=(
            "Establish a baseline size profile. Monitor for deviations — "
            "sudden increases may indicate data exfiltration; consistent "
            "small responses may indicate C2 beaconing."
        ),
    ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 6. USER-AGENT FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════

def _fingerprint_user_agents(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Analyze UA strings for automation patterns, headless browsers, C2 agents.
    """
    findings: List[Finding] = []

    # Collect all observed User-Agent strings
    observed_uas: List[str] = []
    for s in samples:
        ua = s.get("response_headers", {}).get("server", "")
        if ua:
            observed_uas.append(ua)
    # Also check if any observed UAs from other requests
    for s in samples:
        for hdr_val in s.get("response_headers", {}).values():
            if "user-agent" in hdr_val.lower()[:20]:
                observed_uas.append(hdr_val)

    # Analyze response headers for Server, X-Powered-By, etc.
    server_headers: List[str] = []
    powered_by: List[str] = []
    for s in samples:
        srv = s.get("response_headers", {}).get("server", "")
        if srv:
            server_headers.append(srv)
        pb = s.get("response_headers", {}).get("x-powered-by", "")
        if pb:
            powered_by.append(pb)

    # Check Server header for C2 indicators
    server_counter = Counter(server_headers)
    evidence_parts: List[str] = []

    if server_counter:
        evidence_parts.append(
            "Server headers observed: "
            + ", ".join(f"\"{k}\"(x{v})" for k, v in server_counter.most_common(5))
        )

    if powered_by:
        evidence_parts.append(
            "X-Powered-By: " + ", ".join(f"\"{p}\"" for p in set(powered_by))
        )

    # Check observed response headers for automation/C2 UA patterns
    # (Server header sometimes leaks C2 agent info)
    all_header_values: List[str] = []
    for s in samples:
        for val in s.get("response_headers", {}).values():
            all_header_values.append(val)

    matched_ua_sigs: List[str] = []
    for sig_key, sig_data in AUTOMATION_UA_SIGNATURES.items():
        for pattern in sig_data["indicators"]:
            for val in all_header_values:
                if re.search(pattern, val, re.IGNORECASE | re.MULTILINE):
                    if sig_key not in matched_ua_sigs:
                        matched_ua_sigs.append(sig_key)
                        evidence_parts.append(
                            f"MATCH [{sig_data['name']}]: pattern \"{pattern}\" "
                            f"found in header value \"{val[:80]}\""
                        )
                    break

    for sig_key in matched_ua_sigs:
        sig = AUTOMATION_UA_SIGNATURES[sig_key]
        findings.append(Finding(
            title=f"UA/Signature Match: {sig['name']}",
            severity=sig["severity"],
            category="ua_fingerprint",
            module="signal_intelligence",
            description=(
                f"{sig['description']} Detected in HTTP response headers from "
                f"{target}. Category: {sig['category']}. "
                f"Stealth score: {sig['stealth_score']}/100."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=6 if sig["severity"] in ("high", "critical") else 2,
            dread_score=sig["dread_score"],
            remediation=(
                f"Verify if {sig['name']} presence is expected for this service. "
                f"If unexpected, investigate for compromised endpoints or "
                f"unauthorized automation. Implement header sanitization and "
                f"UA validation rules."
            ),
        ))

    # Header diversity analysis
    all_headers_flat: List[str] = []
    for s in samples:
        all_headers_flat.extend(s.get("response_headers", {}).keys())
    header_counter = Counter(h.lower() for h in all_headers_flat)
    unique_headers = len(header_counter)

    # Check for suspiciously minimal headers (C2 often has minimal header sets)
    if unique_headers <= 3 and len(samples) >= 4:
        findings.append(Finding(
            title="Minimal HTTP Header Set — Possible C2 or Minimal Server",
            severity="medium",
            category="ua_fingerprint",
            module="signal_intelligence",
            description=(
                f"HTTP responses from {target} use only {unique_headers} unique "
                f"header names: {', '.join(header_counter.keys())}. Minimal "
                f"header sets are characteristic of custom C2 HTTP listeners, "
                f"embedded HTTP servers, or minimal API backends. Legitimate "
                f"web servers typically expose 8-15+ headers."
            ),
            evidence=(
                f"Unique headers: {unique_headers}\n"
                f"Headers: {dict(header_counter.most_common())}\n"
                + "\n".join(evidence_parts)
            ),
            asset=base_url,
            points_deducted=3,
            dread_score=5.0,
            remediation=(
                "Verify if the minimal header set is expected. Custom/minimal "
                "servers should be inventoried and monitored. Implement header "
                "baseline checks."
            ),
        ))

    # General UA profile
    if evidence_parts:
        findings.append(Finding(
            title="User-Agent / Header Fingerprint Profile",
            severity="info",
            category="ua_fingerprint",
            module="signal_intelligence",
            description=(
                f"HTTP header fingerprint analysis for {target}. Analyzed "
                f"{len(all_header_values)} header values across {len(samples)} "
                f"probes. Found {len(matched_ua_sigs)} signature matches. "
                f"{unique_headers} unique header names observed."
            ),
            evidence="\n".join(evidence_parts),
            asset=base_url,
            points_deducted=0,
            dread_score=0.0,
            remediation=(
                "Use this fingerprint profile for ongoing monitoring. Any changes "
                "in header signatures may indicate server reconfiguration or "
                "compromise."
            ),
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 7. DNS COMMUNICATION PATTERN ANALYSIS (via HTTP observation)
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_dns_comm_patterns(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Detect C2-over-DNS patterns via HTTP observation.

    Since we can only observe HTTP traffic, we look for indirect indicators:
    - Redirect chains to suspicious domains
    - References to DNS-like encoded data in responses
    - Long subdomain-like strings in response bodies or headers
    - High-entropy encoded strings suggesting DNS tunnel data
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    dns_indicators: List[str] = []

    # Patterns suggesting DNS tunneling activity observable via HTTP
    dns_tunnel_patterns = [
        (r"[a-z0-9-]{24,}\.[a-z]{2,}\.[a-z]{2,}", "Long subdomain label"),
        (r"[a-f0-9]{32,}\.", "Hex-encoded subdomain"),
        (r"[A-Za-z0-9+/=]{20,}\.", "Base64-like subdomain"),
        (r"dnscat2|iodine|dns2tcp", "Known DNS tunnel tool reference"),
        (r"TXT|CNAME|NULL record", "DNS record type in HTTP content"),
    ]

    # Check response bodies and headers for DNS tunnel indicators
    for s in ok_samples:
        body = s.get("response_body", "")
        headers_str = " ".join(s.get("response_headers", {}).values())
        combined = f"{body} {headers_str}"

        for pattern, description in dns_tunnel_patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            if matches:
                for m in matches[:3]:  # limit evidence
                    truncated = m[:80] if len(m) > 80 else m
                    dns_indicators.append(
                        f"[{description}] Found: \"{truncated}\" "
                        f"in {s.get('path', 'unknown')}"
                    )

    # Check for .well-known path exploitation (DNS rebinding, etc.)
    wellknown_samples = [
        s for s in ok_samples
        if ".well-known" in s.get("path", "")
    ]
    if wellknown_samples:
        for s in wellknown_samples:
            body = s.get("response_body", "")
            if body:
                entropy = _shannon_entropy(body)
                if entropy > 4.5:
                    dns_indicators.append(
                        f"[.well-known] High-entropy content at {s['path']} "
                        f"(entropy={entropy:.2f})"
                    )

    if dns_indicators:
        severity = "high" if len(dns_indicators) >= 3 else "medium"
        findings.append(Finding(
            title="DNS Communication Pattern Indicators Detected via HTTP",
            severity=severity,
            category="dns_comm_pattern",
            module="signal_intelligence",
            description=(
                f"HTTP observation of {target} revealed {len(dns_indicators)} "
                f"indicators consistent with C2-over-DNS communication patterns. "
                f"These include long encoded subdomain-like strings, hex/base64 "
                f"patterns in response content, and references to DNS tunneling "
                f"tools. C2-over-DNS allows attackers to exfiltrate data and "
                f"receive commands using DNS queries, bypassing many network controls."
            ),
            evidence="\n".join(dns_indicators),
            asset=base_url,
            points_deducted=6 if severity == "high" else 3,
            dread_score=7.0 if severity == "high" else 5.0,
            remediation=(
                "Investigate the source of DNS tunnel indicators. Deploy DNS "
                "monitoring and alerting for anomalous query patterns. Block "
                "known DNS tunneling tools. Implement DNS query logging and "
                "analysis. Consider DNS-over-HTTPS inspection."
            ),
        ))
    else:
        # Info-level finding for completeness
        findings.append(Finding(
            title="DNS Communication Pattern Analysis — No Indicators",
            severity="info",
            category="dns_comm_pattern",
            module="signal_intelligence",
            description=(
                f"HTTP-based DNS communication pattern analysis for {target} "
                f"found no indicators of C2-over-DNS activity. Analysis checked "
                f"response bodies, headers, and .well-known paths for long "
                f"encoded subdomains, hex/base64 patterns, and DNS tunnel tool "
                f"references."
            ),
            evidence=(
                f"Probes analyzed: {len(ok_samples)}\n"
                f"Patterns checked: {len(dns_tunnel_patterns)}\n"
                f".well-known paths probed: {len(wellknown_samples)}"
            ),
            asset=base_url,
            points_deducted=0,
            dread_score=0.0,
            remediation=(
                "Continue monitoring for DNS tunnel indicators. Implement "
                "passive DNS monitoring for long-term trend analysis."
            ),
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 8. SESSION BEHAVIOR PROFILING
# ═══════════════════════════════════════════════════════════════════════════

def _profile_session_behavior(
    samples: List[ProbeSample], target: str, base_url: str
) -> List[Finding]:
    """Build profiles of session behavior — cookie patterns, referrer chains,
    navigation sequences.
    """
    findings: List[Finding] = []
    ok_samples = [s for s in samples if s.get("ok")]

    if len(ok_samples) < 2:
        return findings

    # --- Cookie Analysis ---
    cookie_patterns: List[str] = []
    cookie_names: Counter = Counter()
    set_cookie_values: List[str] = []
    session_cookies_found: List[str] = []

    for s in ok_samples:
        headers = s.get("response_headers", {})
        # Check Set-Cookie
        for hdr_name, hdr_val in headers.items():
            if hdr_name.lower() == "set-cookie":
                set_cookie_values.append(hdr_val)
                # Extract cookie name
                cookie_name = hdr_val.split("=")[0].strip() if "=" in hdr_val else hdr_val
                cookie_names[cookie_name] += 1

                # Check for session-related cookies
                session_indicators = [
                    "session", "sid", "phpsessid", "jsessionid",
                    "asp.net_sessionid", "token", "auth",
                ]
                for si in session_indicators:
                    if si in cookie_name.lower():
                        session_cookies_found.append(cookie_name)

                # Check for suspicious cookie attributes
                if "HttpOnly" not in hdr_val:
                    cookie_patterns.append(
                        f"Cookie \"{cookie_name}\" missing HttpOnly flag"
                    )
                if "Secure" not in hdr_val and "secure" not in hdr_val.lower():
                    cookie_patterns.append(
                        f"Cookie \"{cookie_name}\" missing Secure flag"
                    )
                if "SameSite" not in hdr_val:
                    cookie_patterns.append(
                        f"Cookie \"{cookie_name}\" missing SameSite attribute"
                    )

                # Check for high-entropy cookie values (possible session tokens)
                if "=" in hdr_val:
                    val_part = hdr_val.split("=", 1)[1].split(";")[0].strip()
                    if len(val_part) > 16:
                        ent = _shannon_entropy(val_part)
                        if ent > 4.0:
                            cookie_patterns.append(
                                f"Cookie \"{cookie_name}\" has high-entropy value "
                                f"(entropy={ent:.2f}, len={len(val_part)})"
                            )

    # --- Navigation Sequence Analysis ---
    paths_visited: List[str] = [s.get("path", "") for s in ok_samples]
    path_counter = Counter(paths_visited)
    redirect_chains: List[str] = []

    for s in ok_samples:
        if s.get("status") in (301, 302, 303, 307, 308):
            location = s.get("response_headers", {}).get("location", "")
            if location:
                redirect_chains.append(f"{s['path']} -> {location[:80]}")

    # --- Referrer Analysis ---
    referrer_headers: List[str] = []
    for s in ok_samples:
        ref = s.get("response_headers", {}).get("referrer", "")
        if ref:
            referrer_headers.append(ref)

    # --- Strict-Transport-Security Analysis ---
    hsts_found = any(
        "strict-transport-security" in h.lower()
        for s in ok_samples
        for h in s.get("response_headers", {}).keys()
    )

    # --- Build evidence ---
    evidence_parts: List[str] = [
        f"Paths visited: {len(set(paths_visited))} unique, {len(paths_visited)} total",
        f"Cookie names observed: {dict(cookie_names.most_common(10))}" if cookie_names else "No cookies set",
        f"Set-Cookie headers: {len(set_cookie_values)}",
        f"Redirect chains: {len(redirect_chains)}",
        f"Session cookies: {len(set(session_cookies_found))} "
        f"({', '.join(set(session_cookies_found)[:5])})" if session_cookies_found else "None",
        f"HSTS enabled: {hsts_found}",
    ]

    # --- Cookie security findings ---
    insecure_cookies = [p for p in cookie_patterns if "missing" in p and "HttpOnly" in p]
    no_secure = [p for p in cookie_patterns if "missing Secure" in p]
    no_samesite = [p for p in cookie_patterns if "missing SameSite" in p]

    if insecure_cookies:
        _split_q = '"'
        affected_cookies = ', '.join(c.split(_split_q)[1] for c in insecure_cookies[:5])
        findings.append(Finding(
            title=f"Cookies Missing HttpOnly Flag ({len(insecure_cookies)} found)",
            severity="medium",
            category="session_security",
            module="signal_intelligence",
            description=(
                f"{len(insecure_cookies)} cookie(s) from {target} lack the HttpOnly "
                f"flag, making them accessible to JavaScript and vulnerable to "
                f"XSS-based session theft. Affected: {affected_cookies}."
            ),
            evidence="\n".join(insecure_cookies[:10]),
            asset=base_url,
            points_deducted=3,
            dread_score=5.0,
            remediation=(
                "Set the HttpOnly flag on all session-related cookies. "
                "This prevents client-side JavaScript from accessing cookie values."
            ),
        ))

    if no_secure:
        findings.append(Finding(
            title=f"Cookies Missing Secure Flag ({len(no_secure)} found)",
            severity="medium",
            category="session_security",
            module="signal_intelligence",
            description=(
                f"{len(no_secure)} cookie(s) from {target} lack the Secure flag, "
                f"allowing them to be transmitted over unencrypted HTTP connections. "
                f"This exposes session tokens to network interception."
            ),
            evidence="\n".join(no_secure[:10]),
            asset=base_url,
            points_deducted=3,
            dread_score=5.5,
            remediation=(
                "Set the Secure flag on all cookies when using HTTPS. "
                "Consider HSTS to enforce HTTPS-only connections."
            ),
        ))

    if no_samesite:
        findings.append(Finding(
            title=f"Cookies Missing SameSite Attribute ({len(no_samesite)} found)",
            severity="low",
            category="session_security",
            module="signal_intelligence",
            description=(
                f"{len(no_samesite)} cookie(s) from {target} lack the SameSite "
                f"attribute, making them vulnerable to CSRF attacks. Without "
                f"SameSite, browsers may include these cookies in cross-site requests."
            ),
            evidence="\n".join(no_samesite[:10]),
            asset=base_url,
            points_deducted=2,
            dread_score=4.0,
            remediation=(
                "Set SameSite=Strict or SameSite=Lax on all cookies. "
                "This mitigates cross-site request forgery attacks."
            ),
        ))

    if not hsts_found:
        findings.append(Finding(
            title="HSTS Header Not Detected",
            severity="low",
            category="session_security",
            module="signal_intelligence",
            description=(
                f"{target} does not set the Strict-Transport-Security header. "
                f"Without HSTS, the site is vulnerable to protocol downgrade "
                f"attacks and SSL stripping."
            ),
            evidence="Checked all response headers; HSTS not found.",
            asset=base_url,
            points_deducted=2,
            dread_score=4.0,
            remediation=(
                "Implement HSTS with a minimum max-age of 31536000 (1 year) "
                "and include subdomains. Consider adding to HSTS preload list."
            ),
        ))

    # Redirect chain analysis
    if redirect_chains:
        external_redirects = [
            r for r in redirect_chains
            if target not in r.lower()
        ]
        if external_redirects:
            findings.append(Finding(
                title=f"External Redirect Chains Detected ({len(external_redirects)})",
                severity="medium",
                category="session_behavior",
                module="signal_intelligence",
                description=(
                    f"{target} redirects to external domains in "
                    f"{len(external_redirects)} case(s). Open redirect chains can be "
                    f"exploited for phishing, C2 callback redirection, and session "
                    f"hijacking. External redirects may also indicate third-party "
                    f"service dependencies or CDN usage."
                ),
                evidence="\n".join(redirect_chains[:10]),
                asset=base_url,
                points_deducted=3,
            dread_score=5.5,
            remediation=(
                "Audit all redirect destinations. Implement allowlists for "
                "redirect targets. Use relative redirects where possible. "
                "Sanitize redirect parameters to prevent open redirect."
            ),
        ))

    # Session behavior profile summary
    evidence_parts.append(
        f"Cookie security issues: {len(cookie_patterns)}"
    )
    if cookie_patterns:
        evidence_parts.append(
            "Cookie details:\n" + "\n".join(cookie_patterns[:15])
        )

    findings.append(Finding(
        title="Session Behavior Profile",
        severity="info",
        category="session_behavior",
        module="signal_intelligence",
        description=(
            f"Session behavior profile for {target}. The server sets "
            f"{len(cookie_names)} distinct cookie name(s) across "
            f"{len(set_cookie_values)} Set-Cookie headers. "
            f"{len(set(paths_visited))} unique paths were observed. "
            f"{len(redirect_chains)} redirect(s) detected. "
            f"This profile captures the session management characteristics "
            f"for baseline comparison and anomaly detection."
        ),
        evidence="\n".join(evidence_parts),
        asset=base_url,
        points_deducted=0,
        dread_score=0.0,
        remediation=(
            "Use this session profile as a baseline. Monitor for changes in "
            "cookie behavior, new redirect chains, or navigation pattern "
            "deviations that may indicate session hijacking or C2 activity."
        ),
    ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# PROBE COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def _collect_probe_samples(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[ProbeSample]:
    """Collect timed HTTP probe samples across multiple paths and rounds.

    Returns a list of ProbeSample dicts with timing, size, and header data.
    """
    samples: List[ProbeSample] = []

    parsed = urllib.parse.urlparse(base_url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or target

    for round_idx in range(_PROBE_ROUNDS):
        for path in _OBSERVATION_PATHS:
            url = f"{scheme}://{netloc}{path}"
            t_start = time.monotonic()
            resp = http_probe(
                url,
                timeout=timeout,
                verify_tls=verify_tls,
                limiter=default_limiter,
            )
            t_end = time.monotonic()

            samples.append({
                "round": round_idx,
                "path": path,
                "url": url,
                "ok": resp.get("ok", False),
                "status": resp.get("status", 0),
                "reason": resp.get("reason", ""),
                "response_headers": resp.get("headers", {}),
                "request_headers": {  # our request headers
                    "User-Agent": "ReconPro/2.0 (Enterprise Security Scanner)",
                },
                "response_body": resp.get("body", ""),
                "response_size": len(resp.get("body", "").encode("utf-8", errors="replace")),
                "request_size": 0,  # GET requests, minimal body
                "response_time": round(t_end - t_start, 4),
                "timestamp": round(t_start, 4),
            })

    return samples


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def run_signal_intelligence(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Apply intelligence-community analysis frameworks to HTTP traffic.

    Probes the target across multiple paths and rounds, then applies eight
    analytical capabilities to the collected signal data:

      1. Traffic Pattern Analysis
      2. Beaconing Detection
      3. C2 Pattern Matching
      4. Communication Schedule Extraction
      5. Payload Size Analysis
      6. User-Agent Fingerprinting
      7. DNS Communication Pattern Analysis
      8. Session Behavior Profiling

    Args:
        target: Human-readable target identifier (e.g. 'example.com').
        base_url: Base URL for HTTP probes (e.g. 'https://example.com').
        timeout: Per-request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        List of Finding objects covering all eight analytical dimensions.
    """
    all_findings: List[Finding] = []

    # ── Phase 1: Collect probe samples ──────────────────────────────────
    samples = _collect_probe_samples(target, base_url, timeout, verify_tls)

    ok_count = sum(1 for s in samples if s.get("ok"))

    # ── Phase 2: Run all eight analyzers ───────────────────────────────
    analyzers = [
        (_analyze_traffic_patterns, "Traffic Pattern Analysis"),
        (_detect_beaconing, "Beaconing Detection"),
        (_match_c2_patterns, "C2 Pattern Matching"),
        (_extract_communication_schedule, "Communication Schedule Extraction"),
        (_analyze_payload_sizes, "Payload Size Analysis"),
        (_fingerprint_user_agents, "User-Agent Fingerprinting"),
        (_analyze_dns_comm_patterns, "DNS Communication Pattern Analysis"),
        (_profile_session_behavior, "Session Behavior Profiling"),
    ]

    for analyzer_fn, analyzer_name in analyzers:
        try:
            results = analyzer_fn(samples, target, base_url)
            all_findings.extend(results)
        except Exception:
            continue

    # ── Phase 3: Overall assessment ────────────────────────────────────
    high_sev = sum(1 for f in all_findings if f.severity in ("critical", "high"))
    med_sev = sum(1 for f in all_findings if f.severity == "medium")
    total_dread = sum(f.dread_score for f in all_findings)
    max_dread = 80.0  # theoretical maximum for all analyzers
    risk_pct = min(100, (total_dread / max_dread * 100)) if max_dread > 0 else 0

    risk_level = (
        "CRITICAL" if risk_pct > 60 else
        "HIGH" if risk_pct > 40 else
        "MEDIUM" if risk_pct > 20 else
        "LOW"
    )

    all_findings.append(Finding(
        title=f"Signal Intelligence Assessment: {risk_level} ({risk_pct:.1f}%)",
        severity=(
            "critical" if risk_pct > 60 else
            "high" if risk_pct > 40 else
            "medium" if risk_pct > 20 else
            "low"
        ),
        category="signal_intelligence_assessment",
        module="signal_intelligence",
        description=(
            f"Comprehensive signal intelligence analysis of {target} complete. "
            f"Collected {len(samples)} probe samples across {len(_OBSERVATION_PATHS)} "
            f"paths in {_PROBE_ROUNDS} rounds ({ok_count} successful). "
            f"Applied {len(analyzers)} intelligence-community analytical frameworks. "
            f"Found {high_sev} high-severity and {med_sev} medium-severity findings. "
            f"Aggregate DREAD: {total_dread:.1f}/{max_dread:.0f} ({risk_pct:.1f}%). "
            f"Risk level: {risk_level}."
        ),
        evidence=(
            f"Target: {target}\n"
            f"Base URL: {base_url}\n"
            f"Probe samples: {len(samples)} ({ok_count} successful)\n"
            f"Paths probed: {len(_OBSERVATION_PATHS)}\n"
            f"Rounds: {_PROBE_ROUNDS}\n"
            f"Analyzers: {len(analyzers)}\n"
            f"High-severity findings: {high_sev}\n"
            f"Medium-severity findings: {med_sev}\n"
            f"Total findings: {len(all_findings)}\n"
            f"Aggregate DREAD: {total_dread:.1f}/{max_dread:.0f}\n"
            f"Risk: {risk_level} ({risk_pct:.1f}%)"
        ),
        asset=base_url,
        points_deducted=high_sev * 8 + med_sev * 3,
        dread_score=round(total_dread, 1),
        remediation=(
            "Address high-severity findings first: C2 pattern matches and beacon "
            "detections require immediate investigation. Implement behavioral "
            "baselines from this assessment for ongoing monitoring. Deploy "
            "SIEM correlation rules based on detected patterns. Review session "
            "security configurations (cookie flags, HSTS). Integrate signal "
            "intelligence findings with threat intelligence feeds for "
            "enriched context."
        ),
    ))

    return all_findings
