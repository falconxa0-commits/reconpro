"""ReconPro v11 — Shared Utilities.

Pure functions used across modules. No state, no side effects, no imports
from other reconpro packages (avoids circular deps).

Every duplicated pattern (extract_host, normalize_url, count_severities,
compute_score, sort_findings) is centralized here.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional  # DEAD CODE: consider removal

from .constants import (
    SEVERITY_LEVELS,
    VALID_SEVERITIES,
    MAX_SCORE,
    MIN_SCORE,
    DEFAULT_BODY_LIMIT,
)


# ── Target Normalization ────────────────────────────────────────────────

def extract_host(target: str) -> str:
    """Extract hostname from a URL, domain, or IP string.

    Examples:
        extract_host("https://example.com/path") -> "example.com"
        extract_host("http://example.com:8080/") -> "example.com:8080"
        extract_host("example.com") -> "example.com"
        extract_host("192.168.1.1:443") -> "192.168.1.1:443"
    """
    if not target:
        return ""
    # Strip scheme
    t = target.strip()
    t = re.sub(r'^https?://', '', t, flags=re.IGNORECASE)
    # Extract host:port
    host_port = t.split('/')[0]
    return host_port


def normalize_base_url(target: str) -> str:
    """Ensure target has a scheme prefix for HTTP requests.

    Examples:
        normalize_base_url("example.com") -> "https://example.com"
        normalize_base_url("http://example.com") -> "http://example.com"
        normalize_base_url("https://example.com/path") -> "https://example.com/path"
    """
    if not target:
        return ""
    t = target.strip()
    if t.startswith(('http://', 'https://')):
        return t
    return f"https://{t}"


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a scan target. Returns (is_valid, error_message).

    Checks for:
    - Empty string
    - Only whitespace
    - Invalid characters
    - Reserved/private IPs (informational warning, not blocking)
    """
    if not target or not target.strip():
        return False, "Target cannot be empty."

    cleaned = target.strip()

    # Check for obviously invalid characters
    if any(c in cleaned for c in (';', '|', '`', '$', '&', '&&', '||')):
        return False, f"Target contains invalid characters: {cleaned}"

    # Extract host for validation
    host = extract_host(cleaned)

    # Check host length
    if len(host) > 253:
        return False, f"Hostname exceeds 253 characters: {host[:50]}..."

    # Check for localhost/private ranges (informational)
    private_prefixes = ('127.', '10.', '192.168.', '172.16.', '172.17.',
                        '172.18.', '172.19.', '172.20.', '172.21.',
                        '172.22.', '172.23.', '172.24.', '172.25.',
                        '172.26.', '172.27.', '172.28.', '172.29.',
                        '172.30.', '172.31.')
    if host.startswith(private_prefixes) or host in ('localhost', '::1'):
        return True, "LOCAL"  # Valid but local

    return True, ""


# ── Severity Utilities ──────────────────────────────────────────────────

def count_severities(findings: List[Any]) -> Dict[str, int]:
    """Count findings by severity level.

    Args:
        findings: List of Finding objects or finding dicts (must have 'severity' key).

    Returns:
        Dict mapping severity name to count.
    """
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'info')
        sev = sev.lower()
        if sev in VALID_SEVERITIES:
            counts[sev] = counts.get(sev, 0) + 1
        else:
            counts['info'] = counts.get('info', 0) + 1
    return counts


# DEAD CODE: consider removal
def sort_findings_by_severity(findings: List[Any], reverse: bool = False) -> List[Any]:
    """Sort findings by severity (critical first).

    Args:
        findings: List of Finding objects or finding dicts.
        reverse: If True, info first (least severe first).

    Returns:
        Sorted list (stable sort preserves insertion order within same severity).
    """
    def key(f):
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'info')
        return SEVERITY_LEVELS.get(sev.lower(), 99)

    return sorted(findings, key=key, reverse=reverse)


def severity_to_cvss(severity: str) -> str:
    """Map ReconPro severity to CVSS v3 qualitative rating."""
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    }
    return mapping.get(severity.lower(), "INFO")


def severity_to_dread(severity: str) -> float:
    """Map severity to default DREAD score."""
    from .constants import DREAD_SCORE_MAP
    return DREAD_SCORE_MAP.get(severity.lower(), 0.1)


def validate_severity(severity: str) -> str:
    """Validate and normalize a severity string. Returns 'info' for unknown values."""
    s = severity.lower().strip()
    if s in VALID_SEVERITIES:
        return s
    return "info"


# ── Scoring Utilities ────────────────────────────────────────────────────

def compute_score(findings: List[Any], max_score: int = MAX_SCORE) -> int:
    """Compute overall score from findings based on points deducted.

    Args:
        findings: List of Finding objects or finding dicts.
        max_score: Maximum possible score.

    Returns:
        Integer score clamped to [MIN_SCORE, max_score].
    """
    total_deductions = 0
    for f in findings:
        pts = f.points_deducted if hasattr(f, 'points_deducted') else f.get('points_deducted', 0)
        total_deductions += pts
    if not findings:
        return max_score
    return max(MIN_SCORE, min(max_score, max_score - total_deductions))


def compute_grade(score: int) -> str:
    """Map numeric score to letter grade."""
    from .constants import GRADE_THRESHOLDS
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def badge_markdown(host: str, grade: str) -> str:
    """Generate GitHub-style markdown badge for a scan result."""
    from .constants import BADGE_COLOR_MAP
    c = BADGE_COLOR_MAP.get(grade, "lightgrey")
    return (
        f"![ReconPro {grade}]"
        f"(https://img.shields.io/badge/ReconPro-{grade}-{c}"
        f"?style=for-the-badge&labelColor=000000)"
    )


# ── Data Utilities ──────────────────────────────────────────────────────

def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert to int. Returns default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert to float. Returns default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def truncate(s: str, max_len: int = DEFAULT_BODY_LIMIT) -> str:
    """Truncate string to max_len characters."""
    if not s:
        return ""
    return s[:max_len]


def entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per byte.

    Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0
    import math
    freq: Dict[str, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


# ── Network Utilities ────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if nums[0] == 10:
        return True
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True
    if nums[0] == 192 and nums[1] == 168:
        return True
    if nums[0] == 127:
        return True
    return False


def url_join(base: str, path: str) -> str:
    """Safely join a base URL and path component."""
    base = base.rstrip('/')
    path = path.lstrip('/')
    return f"{base}/{path}"
