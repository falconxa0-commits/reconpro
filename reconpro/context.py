"""ReconPro v11 — Scan Context.

Carries all scan configuration and shared state through the scan pipeline.
Modules CAN use this for cleaner signatures but existing 4-arg calls
continue to work — backward compatible.
"""
from __future__ import annotations

import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Optional  # DEAD CODE: consider removal


@dataclass
class ScanContext:
    """Immutable scan context passed through the pipeline.

    Replaces the 4-argument pattern (target, base_url, timeout, verify_tls)
    with a single object. Existing modules that use 4 args continue to work.
    New modules can accept ScanContext for cleaner APIs.
    """
    target: str
    base_url: str = ""
    timeout: int = 8
    verify_tls: bool = True
    rate_limit: float = 10.0

    # Auto-populated metadata
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)

    # Optional enrichment
    host: str = ""
    scheme: str = ""
    port: int = 0

    def __post_init__(self):
        if not self.host:
            from .utils import extract_host
            self.host = extract_host(self.target)
        if not self.base_url:
            from .utils import normalize_base_url
            self.base_url = normalize_base_url(self.target)
        if not self.scheme:
            parsed = urllib.parse.urlparse(self.base_url)
            self.scheme = parsed.scheme or "https"

    def to_args(self) -> tuple:
        """Convert to legacy 4-arg tuple for backward compat.
        Returns (target, base_url, timeout, verify_tls)
        """
        return (self.target, self.base_url, self.timeout, self.verify_tls)

    # DEAD CODE: consider removal
    def elapsed_ms(self) -> float:
        """Return milliseconds elapsed since scan started."""
        return (time.time() - self.started_at) * 1000


# DEAD CODE: consider removal
def create_context(target: str, **kwargs) -> ScanContext:
    """Factory for creating scan contexts from various input formats.

    Accepts all ScanContext fields as keyword arguments.
    Automatically derives base_url and host from target if not provided.

    Args:
        target: The scan target (URL, domain, or IP).
        **kwargs: Optional overrides for ScanContext fields.

    Returns:
        A fully initialized ScanContext instance.
    """
    return ScanContext(target=target, **kwargs)
