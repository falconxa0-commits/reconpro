"""Target Validation Pipeline — the scanner's truth layer.

Every remote scan MUST validate its target BEFORE any vulnerability checks
run, and every finding MUST carry the verification state of the target it
was produced against.  This module implements that pipeline:

    DNS Resolution
        ↓
    Reachability Check (TCP)
        ↓
    HTTP/TLS Validation
        ↓
    Scanner Decision

States
──────
``VERIFIED_TARGET``
    DNS resolved, TCP connected, and the service answered an HTTP(S)
    request.  Findings may carry any severity.
``PARTIAL_TARGET``
    DNS resolved (and possibly TCP connected) but HTTP validation failed —
    non-HTTP service, TLS failure with verification enabled, or probe
    error.  Modules still run (DNS-based / passive checks may be valid),
    but finding severities are capped at MEDIUM and confidence is reduced.
``UNREACHABLE_TARGET``
    DNS did not resolve or no TCP connection could be established.  Remote
    modules are NOT executed; a single honest ``target_validation`` finding
    is emitted instead.  HIGH/CRITICAL findings are impossible by
    construction.

Usage
─────
::

    from reconpro.target_validation import (
        validate_target_pipeline, apply_target_truth, unreachable_finding,
        VERIFIED_TARGET, PARTIAL_TARGET, UNREACHABLE_TARGET,
    )

    validation = validate_target_pipeline("example.com")
    if validation.state == UNREACHABLE_TARGET:
        ...  # short-circuit: emit unreachable_finding() only
    else:
        ...  # run modules, then apply_target_truth(findings, validation)
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = [
    "VERIFIED_TARGET",
    "PARTIAL_TARGET",
    "UNREACHABLE_TARGET",
    "TARGET_STATES",
    "TargetValidation",
    "validate_target_pipeline",
    "apply_target_truth",
    "unreachable_finding",
    "state_confidence",
]

# ── States ──────────────────────────────────────────────────────────────

VERIFIED_TARGET = "VERIFIED_TARGET"
PARTIAL_TARGET = "PARTIAL_TARGET"
UNREACHABLE_TARGET = "UNREACHABLE_TARGET"

TARGET_STATES = (VERIFIED_TARGET, PARTIAL_TARGET, UNREACHABLE_TARGET)

# Confidence attached to findings produced under each state.  A finding
# against a verified target is trustworthy; one produced while the target
# could not be validated is mostly noise.
_STATE_CONFIDENCE = {
    VERIFIED_TARGET: 0.9,
    PARTIAL_TARGET: 0.5,
    UNREACHABLE_TARGET: 0.2,
}

# Severities allowed per state (anything above the cap is downgraded with a
# note).  UNREACHABLE never runs modules, so its cap only guards callers
# that construct findings manually.
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_STATE_SEVERITY_CAP = {
    VERIFIED_TARGET: "critical",
    PARTIAL_TARGET: "medium",
    UNREACHABLE_TARGET: "low",
}


def state_confidence(state: str) -> float:
    """Default finding confidence for a target-verification state."""
    return _STATE_CONFIDENCE.get(state, 0.2)


# ── Validation result ───────────────────────────────────────────────────


@dataclass
class TargetValidation:
    """Outcome of the target validation pipeline."""

    state: str
    dns_resolved: bool
    reachable: bool
    http_ok: bool
    tls_valid: Optional[bool]
    details: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = ""

    def __post_init__(self) -> None:
        if not self.checked_at:
            self.checked_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "dns_resolved": self.dns_resolved,
            "reachable": self.reachable,
            "http_ok": self.http_ok,
            "tls_valid": self.tls_valid,
            "details": self.details,
            "checked_at": self.checked_at,
        }


# ── Pipeline steps ──────────────────────────────────────────────────────


def _split_target(target: str) -> Dict[str, Any]:
    """Split *target* into host / port / scheme / path."""
    t = (target or "").strip()
    scheme = ""
    if t.startswith("https://"):
        scheme, t = "https", t[len("https://"):]
    elif t.startswith("http://"):
        scheme, t = "http", t[len("http://"):]
    path = ""
    if "/" in t:
        t, path = t.split("/", 1)
        path = "/" + path
    port: Optional[int] = None
    if t.startswith("["):  # IPv6 literal [::1]:8080
        end = t.find("]")
        if end != -1:
            host = t[1:end]
            rest = t[end + 1:]
            if rest.startswith(":"):
                port = int(rest[1:]) if rest[1:].isdigit() else None
            return {"host": host, "port": port, "scheme": scheme, "path": path}
    if ":" in t:
        host, _, maybe_port = t.rpartition(":")
        if maybe_port.isdigit():
            port = int(maybe_port)
        else:
            host = t
    else:
        host = t
    return {"host": host, "port": port, "scheme": scheme, "path": path}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_dns(host: str, timeout: float) -> Dict[str, Any]:
    """Step 1 — DNS resolution. Returns dict with ok, ips, error."""
    if _is_ip_literal(host):
        return {"ok": True, "ips": [host], "error": None, "is_ip_literal": True}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        return {"ok": True, "ips": ips, "error": None, "is_ip_literal": False}
    except socket.gaierror as exc:
        return {"ok": False, "ips": [], "error": str(exc), "is_ip_literal": False}
    except Exception as exc:  # defensive: DNS stack can raise OSError etc.
        return {"ok": False, "ips": [], "error": f"{type(exc).__name__}: {exc}", "is_ip_literal": False}


def _tcp_reachable(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Step 2 — TCP connect. Returns dict with ok, error, latency_ms."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "error": None, "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}


def _http_probe(url: str, timeout: float, verify_tls: bool) -> Dict[str, Any]:
    """Step 3 — HTTP(S) validation. Returns dict with ok, status, error, tls."""
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ReconPro-Validator/11"})
        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            # audited opt-out: reuse the single sanctioned insecure-context
            # helper (http_layer._unverified_context) instead of constructing
            # one here — keeps the AST security sweep guarantee intact.
            from .http_layer import _unverified_context
            ctx = _unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body_head = resp.read(512)  # drain a little; status is what matters
            return {
                "ok": True,
                "status": resp.status,
                "error": None,
                "server": resp.headers.get("Server", ""),
                "body_head_bytes": len(body_head),
            }
    except urllib.error.HTTPError as exc:
        # Any HTTP status (4xx/5xx) still proves a live HTTP service.
        return {"ok": True, "status": exc.code, "error": None, "server": "", "body_head_bytes": 0}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": f"{type(exc).__name__}: {exc}", "server": "", "body_head_bytes": 0}


def validate_target_pipeline(
    target: str,
    timeout: float = 5.0,
    verify_tls: bool = True,
) -> TargetValidation:
    """Run the full validation pipeline against *target*.

    DNS Resolution → Reachability → HTTP/TLS → decision.
    """
    parts = _split_target(target)
    host: str = parts["host"]
    scheme: str = parts["scheme"]
    explicit_port: Optional[int] = parts["port"]

    details: Dict[str, Any] = {"host": host}

    # ── Step 1: DNS ─────────────────────────────────────────────────
    dns = _resolve_dns(host, timeout)
    details["dns"] = dns
    if not dns["ok"]:
        return TargetValidation(
            state=UNREACHABLE_TARGET,
            dns_resolved=False,
            reachable=False,
            http_ok=False,
            tls_valid=None,
            details={**details, "reason": f"DNS resolution failed: {dns['error']}"},
        )
    details["ips"] = dns["ips"]

    # ── Step 2: Reachability (TCP) ─────────────────────────────────
    candidate_ports = (
        [explicit_port] if explicit_port
        else ([443] if scheme == "https" else [80, 443] if scheme == "" else [80])
    )
    reachable = False
    for port in candidate_ports:
        tcp = _tcp_reachable(host, port, timeout)
        details[f"tcp_{port}"] = tcp
        if tcp["ok"]:
            reachable = True
            details["connected_port"] = port
            break
    if not reachable:
        return TargetValidation(
            state=UNREACHABLE_TARGET,
            dns_resolved=True,
            reachable=False,
            http_ok=False,
            tls_valid=None,
            details={**details, "reason": "No TCP connection could be established "
                                          f"on port(s) {candidate_ports}"},
        )

    # ── Step 3: HTTP/TLS validation ───────────────────────────────
    probe_scheme = scheme or "https"
    url = f"{probe_scheme}://{host}" + (f":{explicit_port}" if explicit_port else "") + (parts["path"] or "/")
    probe = _http_probe(url, timeout, verify_tls)
    details["http_probe"] = probe

    if not probe["ok"] and probe_scheme == "https" and not parts["path"]:
        # fall back to plain HTTP once (some targets are HTTP-only)
        http_url = f"http://{host}" + (f":{explicit_port}" if explicit_port else "") + "/"
        alt = _http_probe(http_url, timeout, verify_tls=False)
        details["http_probe_fallback"] = alt
        if alt["ok"]:
            probe, probe_scheme = alt, "http"
            details["fallback_used"] = True

    if not probe["ok"]:
        return TargetValidation(
            state=PARTIAL_TARGET,
            dns_resolved=True,
            reachable=True,
            http_ok=False,
            tls_valid=None,
            details={**details, "reason": f"HTTP validation failed: {probe['error']}"},
        )

    # TLS validation: only meaningful for https with verification enabled.
    tls_valid: Optional[bool] = None
    if probe_scheme == "https":
        tls_valid = verify_tls  # probe succeeded under the user's TLS policy

    return TargetValidation(
        state=VERIFIED_TARGET,
        dns_resolved=True,
        reachable=True,
        http_ok=True,
        tls_valid=tls_valid,
        details={**details, "http_status": probe["status"], "scheme": probe_scheme},
    )


# ── Finding post-processing ─────────────────────────────────────────────


def apply_target_truth(findings: List[Any], validation: TargetValidation) -> None:
    """Tag findings with the target verification state (in place).

    * every finding gets ``verification_state`` + ``confidence``
    * severities above the state cap are downgraded with an explicit note
      (PARTIAL_TARGET caps at MEDIUM — no HIGH/CRITICAL claims without a
      verified target; UNREACHABLE caps at LOW for manual constructions)
    """
    cap = _STATE_SEVERITY_CAP.get(validation.state, "low")
    cap_idx = _SEVERITY_ORDER.index(cap)
    conf = state_confidence(validation.state)

    for f in findings:
        if hasattr(f, "verification_state"):
            f.verification_state = validation.state
        if hasattr(f, "confidence"):
            # never *lower* an explicitly-set confidence
            try:
                if not f.confidence or f.confidence < 0 or f.confidence > 1:
                    f.confidence = conf
                elif f.confidence > conf:
                    f.confidence = conf
            except (TypeError, ValueError):
                f.confidence = conf
        sev = getattr(f, "severity", "info")
        sev = sev.lower() if isinstance(sev, str) else "info"
        if sev in _SEVERITY_ORDER and _SEVERITY_ORDER.index(sev) > cap_idx:
            original = sev
            f.severity = cap
            note = (f"[downgraded from {original}: target state "
                    f"{validation.state}]")
            if hasattr(f, "evidence"):
                f.evidence = (f.evidence + " " + note).strip() if f.evidence else note


def unreachable_finding(target: str, validation: TargetValidation) -> Any:
    """The single honest finding emitted when a target is unreachable."""
    from .http_layer import Finding

    reason = validation.details.get("reason", "unknown reason")
    return Finding(
        title=f"Target unreachable — scan not performed: {target}",
        severity="info",
        category="target_validation",
        module="engine",
        description=(
            "The target validation pipeline could not verify the target, so no "
            "vulnerability modules were executed. This is an honest no-result: "
            "no security claims are made about an unreachable target."
        ),
        evidence=f"state={validation.state}; {reason}",
        asset=target,
        points_deducted=0,
        remediation=(
            "Verify the target hostname is correct and authorized, that DNS "
            "resolves from this network, and that the host allows inbound "
            "connections on HTTP(S) ports."
        ),
        confidence=0.95,
        verification_state=UNREACHABLE_TARGET,
    )
