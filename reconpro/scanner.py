"""ReconPro v11 — Scan Engine.

Core synchronous scan orchestration. Runs modules against targets,
aggregates findings, computes scores and grades.

All module registries are imported from registry.py (single source of truth).
All shared utilities come from utils.py.
All constants come from constants.py.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from .registry import (
    MODULE_REGISTRY, LOCAL_MODULES, ALL_MODULES,
    DEFAULT_MODULES, DEFAULT_LOCAL_MODULES, get_module_runner,
)
from .http_layer import Finding, RateLimiter
from .utils import (
    extract_host, normalize_base_url, validate_target,
    count_severities, compute_score, compute_grade, badge_markdown,
)
from .target_validation import (
    validate_target_pipeline, apply_target_truth, unreachable_finding,
    UNREACHABLE_TARGET,
)


@dataclass
class ReconProResult:
    """Full result of a ReconPro scan."""
    target: str
    modules_run: List[str]
    findings: List[Dict[str, Any]]
    severity_counts: Dict[str, int]
    total_score: int
    grade: str
    badge_markdown: str
    vibesec_score: Optional[int] = None
    vibesec_grade: Optional[str] = None
    module_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    intelligence: Optional[Dict[str, Any]] = None
    engineering: Optional[Dict[str, Any]] = None
    quality: Optional[Dict[str, Any]] = None
    engineering_score: float = 0.0
    # Truth layer — target validation pipeline outcome (None for local audits)
    target_validation: Optional[Dict[str, Any]] = None
    scan_metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "modules_run": self.modules_run,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "total_score": self.total_score,
            "grade": self.grade,
            "badge_markdown": self.badge_markdown,
            "vibesec_score": self.vibesec_score,
            "vibesec_grade": self.vibesec_grade,
            "module_results": self.module_results,
            "findings": self.findings,
            "intelligence": self.intelligence,
            "engineering": self.engineering,
            "quality": self.quality,
            "engineering_score": round(self.engineering_score, 1),
            "target_validation": self.target_validation,
            "scan_metadata": self.scan_metadata,
        }


def scan(
    target: str,
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 8,
    verify_tls: bool = True,
    rate_limit: float = 10.0,
) -> ReconProResult:
    """Run ReconPro scan against target (remote URL/domain).

    Args:
        target:      Domain or URL to scan.
        modules:     List of module IDs to run. Defaults to DEFAULT_MODULES.
        all_modules: If True, run all remote modules.
        timeout:     Per-request timeout in seconds.
        verify_tls:  Whether to verify TLS certificates.
        rate_limit:  Max requests per second.

    Returns:
        ReconProResult with all findings, scores, and grades.
    """
    # Validate target
    valid, reason = validate_target(target)
    if not valid:
        raise ValueError(f"Invalid scan target: {reason}")

    # ── Truth layer: Target Validation Pipeline ─────────────────────
    # DNS → Reachability → HTTP/TLS → decision.  An unreachable target
    # must NEVER produce module findings (let alone HIGH severity ones).
    from datetime import datetime, timezone as _tz
    _meta_t0 = time.monotonic()
    validation = validate_target_pipeline(target, timeout=min(float(timeout), 5.0), verify_tls=verify_tls)
    if validation.state == UNREACHABLE_TARGET:
        f = unreachable_finding(target, validation)
        return ReconProResult(
            target=extract_host(target),
            modules_run=[],
            findings=[f.to_dict()],
            severity_counts=count_severities([f]),
            total_score=0,
            grade="U",
            badge_markdown=badge_markdown(extract_host(target), "U"),
            target_validation=validation.to_dict(),
            scan_metadata={
                "scanner": "reconpro",
                "started_at": datetime.now(_tz.utc).isoformat(),
                "duration_s": round(time.monotonic() - _meta_t0, 2),
                "result": "unreachable_target_short_circuit",
            },
        )

    # Create dedicated rate limiter (no global mutation)
    limiter = RateLimiter(rate_limit)

    base_url = normalize_base_url(target)
    host = extract_host(target)

    # Resolve module list
    if all_modules:
        mods = [m for m in ALL_MODULES if m in MODULE_REGISTRY]
    elif modules:
        mods = [m.strip().lower() for m in modules
                if m.strip().lower() in MODULE_REGISTRY]
    else:
        mods = list(DEFAULT_MODULES)

    all_findings: List[Finding] = []
    module_results: Dict[str, Dict[str, Any]] = {}
    vibesec_score = None
    vibesec_grade = None
    vibesec_badge = None

    for mod_id in mods:
        runner = get_module_runner(mod_id)
        if runner is None:
            continue

        try:
            # vibesec returns (findings, score, grade, badge_md)
            if mod_id == "vibesec":
                findings, score, grade, badge_md = runner(
                    target, base_url, timeout=timeout, verify_tls=verify_tls,
                    limiter=limiter,
                )
                all_findings.extend(findings)
                vibesec_score = score
                vibesec_grade = grade
                vibesec_badge = badge_md
                module_results["vibesec"] = {
                    "findings": [f.to_dict() for f in findings],
                    "score": score, "grade": grade, "badge": badge_md,
                }
            else:
                findings = runner(target, base_url,
                                  timeout=timeout, verify_tls=verify_tls,
                                  limiter=limiter)
                all_findings.extend(findings)
                module_results[mod_id] = {
                    "findings": [f.to_dict() for f in findings],
                    "count": len(findings),
                }
        except Exception as exc:
            logger.error("Module '%s' failed: %s", mod_id, exc, exc_info=True)
            module_results[mod_id] = {"error": str(exc), "findings": []}
            continue  # One failed module must NEVER stop other modules

    # Calculate overall score using shared utility
    total_score = compute_score(all_findings)
    grade = compute_grade(total_score)
    badge = badge_markdown(host, grade)

    # Count severities using shared utility
    sev_counts = count_severities(all_findings)

    # ── Truth layer: tag every finding with the verification state ──
    # (also caps severity at MEDIUM for PARTIAL_TARGET — no HIGH/CRITICAL
    #  claims against a target we could not fully validate)
    apply_target_truth(all_findings, validation)
    total_score = compute_score(all_findings)
    grade = compute_grade(total_score)
    badge = badge_markdown(host, grade)
    sev_counts = count_severities(all_findings)

    return ReconProResult(
        target=host,
        modules_run=mods,
        findings=[f.to_dict() for f in all_findings],
        severity_counts=sev_counts,
        total_score=total_score,
        grade=grade,
        badge_markdown=badge,
        vibesec_score=vibesec_score,
        vibesec_grade=vibesec_grade,
        module_results=module_results,
        target_validation=validation.to_dict(),
        scan_metadata={
            "scanner": "reconpro",
            "started_at": validation.checked_at,
            "duration_s": round(time.monotonic() - _meta_t0, 2),
            "result": "modules_executed",
        },
    )


def audit_scan(
    target: str = ".",
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
) -> ReconProResult:
    """Run local machine / project audit.

    Args:
        target:      Directory to scan (for dev module) or "localhost" (for host/doctor).
        modules:     List of local module IDs (host, dev, doctor).
        all_modules: If True, run all 3 local modules.

    Returns:
        ReconProResult with all findings, scores, and grades.
    """
    if all_modules:
        mods = list(DEFAULT_LOCAL_MODULES)
    elif modules:
        mods = [m.strip().lower() for m in modules
                if m.strip().lower() in LOCAL_MODULES]
    else:
        mods = list(DEFAULT_LOCAL_MODULES)

    all_findings: List[Finding] = []
    module_results: Dict[str, Dict[str, Any]] = {}

    for mod_id in mods:
        runner = get_module_runner(mod_id)
        if runner is None:
            continue
        try:
            findings = runner(target=target, base_url="", timeout=8, verify_tls=True)
            all_findings.extend(findings)
            module_results[mod_id] = {
                "findings": [f.to_dict() for f in findings],
                "count": len(findings),
            }
        except Exception as exc:
            logger.error("Module '%s' failed: %s", mod_id, exc, exc_info=True)
            module_results[mod_id] = {"error": str(exc), "findings": []}
            continue  # One failed module must NEVER stop other modules

    # Calculate score using shared utility
    total_score = compute_score(all_findings)
    grade = compute_grade(total_score)
    badge = badge_markdown(target if target != "." else "local-audit", grade)

    # Count severities using shared utility
    sev_counts = count_severities(all_findings)

    return ReconProResult(
        target=target if target != "." else "local-audit",
        modules_run=mods,
        findings=[f.to_dict() for f in all_findings],
        severity_counts=sev_counts,
        total_score=total_score,
        grade=grade,
        badge_markdown=badge,
        module_results=module_results,
    )
