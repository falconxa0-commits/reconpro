"""Typed result models for the reconpro scan JSON schema (CLI 11.2.0).

Design rules (see sdks/POLICY.md §3):
- Parsing is **additive-tolerant**: unknown JSON keys are ignored (kept in
  ``ScanResult.raw``), and missing optional keys default safely.
- Every finding carries the truth-layer fields ``confidence`` (0..1, or None
  when the CLI did not measure one) and ``verification_state``.
- ``target_validation`` is ``None`` for local scans (``audit``, ``dev``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

# target_validation.state values (the truth layer)
VERIFIED_TARGET = "VERIFIED_TARGET"
PARTIAL_TARGET = "PARTIAL_TARGET"
UNREACHABLE_TARGET = "UNREACHABLE_TARGET"
VALID_TARGET_STATES = (VERIFIED_TARGET, PARTIAL_TARGET, UNREACHABLE_TARGET)

# CLI exit codes (the process contract)
EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_INTERRUPTED = 130


@dataclass(frozen=True)
class Finding:
    """One vulnerability/observation emitted by a reconpro module."""

    title: str = ""
    severity: str = ""
    category: str = ""
    module: str = ""
    description: str = ""
    evidence: str = ""
    asset: str = ""
    points_deducted: float = 0.0
    remediation: str = ""
    dread_score: float = 0.0
    confidence: Optional[float] = None
    verification_state: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        return cls(
            title=data.get("title", ""),
            severity=data.get("severity", ""),
            category=data.get("category", ""),
            module=data.get("module", ""),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            asset=data.get("asset", ""),
            points_deducted=float(data.get("points_deducted") or 0.0),
            remediation=data.get("remediation", ""),
            dread_score=float(data.get("dread_score") or 0.0),
            confidence=(
                float(data["confidence"])
                if data.get("confidence") is not None else None
            ),
            verification_state=data.get("verification_state"),
        )


@dataclass(frozen=True)
class TargetValidation:
    """Truth-layer result for the scanned target (None for local scans)."""

    state: str = ""
    dns_resolved: Optional[bool] = None
    reachable: Optional[bool] = None
    http_ok: Optional[bool] = None
    tls_valid: Optional[bool] = None
    details: Optional[dict] = None
    checked_at: Optional[str] = None

    @property
    def verified(self) -> bool:
        return self.state == VERIFIED_TARGET

    @property
    def unreachable(self) -> bool:
        return self.state == UNREACHABLE_TARGET

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TargetValidation":
        return cls(
            state=data.get("state", ""),
            dns_resolved=data.get("dns_resolved"),
            reachable=data.get("reachable"),
            http_ok=data.get("http_ok"),
            tls_valid=data.get("tls_valid"),
            details=data.get("details"),
            checked_at=data.get("checked_at"),
        )


@dataclass(frozen=True)
class ScanMetadata:
    """When/how the scan ran."""

    scanner: str = "reconpro"
    started_at: Optional[str] = None
    duration_s: Optional[float] = None
    result: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScanMetadata":
        duration = data.get("duration_s")
        return cls(
            scanner=data.get("scanner", "reconpro"),
            started_at=data.get("started_at"),
            duration_s=float(duration) if duration is not None else None,
            result=data.get("result"),
        )


@dataclass(frozen=True)
class ScanResult:
    """Typed view of one reconpro scan (``scan``/``vibesec``/``audit``/``dev``).

    ``raw`` keeps the complete parsed JSON document so fields the CLI adds in
    the future remain accessible without an SDK release.
    """

    target: str = ""
    modules_run: tuple[str, ...] = ()
    total_findings: int = 0
    severity_counts: dict = field(default_factory=dict)
    total_score: float = 0.0
    grade: str = ""
    findings: tuple[Finding, ...] = ()
    target_validation: Optional[TargetValidation] = None
    scan_metadata: Optional[ScanMetadata] = None
    raw: dict = field(default_factory=dict)

    @property
    def unreachable(self) -> bool:
        """True when the truth layer short-circuited an unreachable target."""
        tv = self.target_validation
        return tv is not None and tv.state == UNREACHABLE_TARGET

    def findings_by_severity(self, severity: str) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == severity)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScanResult":
        raw = dict(data)
        tv = raw.get("target_validation")
        sm = raw.get("scan_metadata")
        return cls(
            target=raw.get("target", ""),
            modules_run=tuple(raw.get("modules_run") or ()),
            total_findings=int(raw.get("total_findings") or 0),
            severity_counts=dict(raw.get("severity_counts") or {}),
            total_score=float(raw.get("total_score") or 0.0),
            grade=raw.get("grade", ""),
            findings=tuple(Finding.from_dict(f) for f in raw.get("findings") or ()),
            target_validation=TargetValidation.from_dict(tv) if tv else None,
            scan_metadata=ScanMetadata.from_dict(sm) if sm else None,
            raw=raw,
        )
