"""ReconPro v11 — Engineering Recommendation Engine.

Generates autonomous engineering (non-security) recommendations from diagnostic
data, drift reports, test results, performance metrics, and operational
findings.  This module is complementary to the AI Analyst (which handles
security-specific recommendations) and focuses exclusively on code quality,
testing, performance, and operational engineering improvements.

Pure Python.  Zero external dependencies.

Exports:
    Recommendation           – individual recommendation dataclass
    RecommendationStore      – JSON-backed persistent store
    RecommendationEngine     – core rule-based generation + dedup + aging
    EngineeringRecommender   – high-level facade combining everything
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constants import MEMORY_DIR, RECONPRO_HOME, SEVERITY_LEVELS, VALID_SEVERITIES


logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

RECOMMENDATIONS_FILE: Path = MEMORY_DIR / "recommendations.json"

VALID_CATEGORIES: frozenset[str] = frozenset({
    "diagnostics",
    "drift",
    "testing",
    "performance",
    "engineering",
    "operational",
    "code_quality",
    "reliability",
    "maintainability",
})

VALID_EFFORTS: frozenset[str] = frozenset({
    "trivial",
    "small",
    "medium",
    "large",
    "epic",
})

# Effort estimate numeric mapping for priority scoring.
_EFFORT_SCORE: Dict[str, float] = {
    "trivial": 1.0,
    "small": 2.0,
    "medium": 3.0,
    "large": 5.0,
    "epic": 8.0,
}

# Severity numeric mapping (lower value = higher severity, matches constants.py).
_SEVERITY_SCORE: Dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

# How many days before a recommendation is considered "stale" and gets
# an automatic severity boost.
_STALE_DAYS: int = 14

# How many days before a recommendation is "very stale" and gets a bigger boost.
_VERY_STALE_DAYS: int = 30

# Maximum recommendations to keep (oldest dismissed ones are pruned).
_MAX_STORED: int = 500

# Deduplication similarity threshold (0.0 – 1.0). Two recommendations whose
# titles have a Jaccard similarity above this are considered duplicates.
_DEDUP_THRESHOLD: float = 0.65


# ═══════════════════════════════════════════════════════════════════════════
# Data Model
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Recommendation:
    """A single engineering recommendation.

    Attributes:
        id:              Unique SHA-256 based identifier.
        title:           Short human-readable title.
        description:     Detailed explanation of the recommendation.
        severity:        One of critical/high/medium/low/info.
        category:        Engineering category (diagnostics, testing, etc.).
        effort_estimate: How much work to address (trivial/small/medium/large/epic).
        affected_files:  List of file paths or module names affected.
        suggested_fix:   Concrete action to take.
        evidence:        Why this recommendation was generated.
        confidence:      0.0 – 1.0 confidence in the recommendation.
        created_at:      ISO-8601 UTC timestamp of creation.
        dismissed:       Whether the user has dismissed this recommendation.
        dismissed_reason: Optional reason for dismissal.
        priority_score:  Computed score (severity * 10 + confidence * 10 - effort * 2).
        source:          Which input generated this (diagnostics, drift, etc.).
    """

    id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    category: str = "engineering"
    effort_estimate: str = "small"
    affected_files: List[str] = field(default_factory=list)
    suggested_fix: str = ""
    evidence: str = ""
    confidence: float = 0.7
    created_at: str = ""
    dismissed: bool = False
    dismissed_reason: str = ""
    priority_score: float = 0.0
    source: str = ""

    def __post_init__(self) -> None:
        """Derive the ID if not provided and normalise fields."""
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.id:
            self.id = self._generate_id()
        # Normalise severity
        self.severity = self.severity.lower()
        if self.severity not in VALID_SEVERITIES:
            self.severity = "medium"
        # Normalise category
        self.category = self.category.lower()
        # Clamp confidence
        self.confidence = max(0.0, min(1.0, self.confidence))
        # Clamp effort
        self.effort_estimate = self.effort_estimate.lower()
        if self.effort_estimate not in VALID_EFFORTS:
            self.effort_estimate = "small"
        # Compute priority score
        self.priority_score = self._compute_priority()

    def _generate_id(self) -> str:
        """Generate a deterministic SHA-256 ID from title + category + source."""
        payload = f"{self.title}|{self.category}|{self.source}|{self.affected_files}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _compute_priority(self) -> float:
        """Compute priority score: higher = more urgent.

        Formula: severity_weight * 10 + confidence * 10 - effort_weight * 2
        Range approximately: -14 to +108
        """
        sev = _SEVERITY_SCORE.get(self.severity, 5.0)
        eff = _EFFORT_SCORE.get(self.effort_estimate, 3.0)
        return round(sev * 10.0 + self.confidence * 10.0 - eff * 2.0, 2)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSON persistence."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "effort_estimate": self.effort_estimate,
            "affected_files": list(self.affected_files),
            "suggested_fix": self.suggested_fix,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "dismissed": self.dismissed,
            "dismissed_reason": self.dismissed_reason,
            "priority_score": self.priority_score,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Recommendation:
        """Deserialise from a dict (typically loaded from JSON)."""
        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            category=data.get("category", "engineering"),
            effort_estimate=data.get("effort_estimate", "small"),
            affected_files=data.get("affected_files", []),
            suggested_fix=data.get("suggested_fix", ""),
            evidence=data.get("evidence", ""),
            confidence=data.get("confidence", 0.7),
            created_at=data.get("created_at", ""),
            dismissed=data.get("dismissed", False),
            dismissed_reason=data.get("dismissed_reason", ""),
            priority_score=data.get("priority_score", 0.0),
            source=data.get("source", ""),
        )


# ═══════════════════════════════════════════════════════════════════════════
# RecommendationStore — Persistent JSON Storage
# ═══════════════════════════════════════════════════════════════════════════


class RecommendationStore:
    """Persistent JSON-backed storage for recommendations.

    Stores all recommendations (active and dismissed) in
    ``RECONPRO_HOME/memory/recommendations.json``.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path: Path = path or RECOMMENDATIONS_FILE
        self._recommendations: Dict[str, Recommendation] = {}
        self._load()

    # ── Persistence ─────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load recommendations from the JSON file."""
        if not self._path.exists():
            self._recommendations = {}
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                logger.warning("Recommendation store: expected dict, got %s", type(data).__name__)
                self._recommendations = {}
                return
            for rec_id, rec_data in data.items():
                try:
                    self._recommendations[rec_id] = Recommendation.from_dict(rec_data)
                except Exception as exc:
                    logger.warning("Failed to load recommendation %s: %s", rec_id, exc)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load recommendation store: %s", exc)
            self._recommendations = {}

    def _save(self) -> None:
        """Persist recommendations to the JSON file."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {rid: rec.to_dict() for rid, rec in self._recommendations.items()}
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
        except OSError as exc:
            logger.error("Failed to save recommendation store: %s", exc)

    # ── CRUD ────────────────────────────────────────────────────────────

    def add(self, recommendation: Recommendation) -> bool:
        """Add a recommendation. Returns True if it was newly added."""
        if not recommendation.id:
            return False
        # Don't overwrite existing non-dismissed recommendations.
        existing = self._recommendations.get(recommendation.id)
        if existing is not None and not existing.dismissed:
            return False
        self._recommendations[recommendation.id] = recommendation
        self._prune_if_needed()
        self._save()
        return True

    def get(self, rec_id: str) -> Optional[Recommendation]:
        """Retrieve a recommendation by ID."""
        return self._recommendations.get(rec_id)

    def get_all(self) -> List[Recommendation]:
        """Return all stored recommendations."""
        return list(self._recommendations.values())

    def get_active(self) -> List[Recommendation]:
        """Return only non-dismissed recommendations, sorted by priority desc."""
        active = [r for r in self._recommendations.values() if not r.dismissed]
        active.sort(key=lambda r: r.priority_score, reverse=True)
        return active

    def get_dismissed(self) -> List[Recommendation]:
        """Return only dismissed recommendations."""
        return [r for r in self._recommendations.values() if r.dismissed]

    def dismiss(self, rec_id: str, reason: str = "") -> bool:
        """Mark a recommendation as dismissed."""
        rec = self._recommendations.get(rec_id)
        if rec is None:
            return False
        rec.dismissed = True
        rec.dismissed_reason = reason
        self._save()
        return True

    def restore(self, rec_id: str) -> bool:
        """Un-dismiss a recommendation."""
        rec = self._recommendations.get(rec_id)
        if rec is None:
            return False
        rec.dismissed = False
        rec.dismissed_reason = ""
        self._save()
        return True

    def remove(self, rec_id: str) -> bool:
        """Delete a recommendation entirely from the store."""
        if rec_id in self._recommendations:
            del self._recommendations[rec_id]
            self._save()
            return True
        return False

    def clear_dismissed(self) -> int:
        """Remove all dismissed recommendations. Returns count removed."""
        to_remove = [rid for rid, r in self._recommendations.items() if r.dismissed]
        for rid in to_remove:
            del self._recommendations[rid]
        if to_remove:
            self._save()
        return len(to_remove)

    def count(self) -> int:
        """Total number of stored recommendations."""
        return len(self._recommendations)

    def active_count(self) -> int:
        """Number of non-dismissed recommendations."""
        return sum(1 for r in self._recommendations.values() if not r.dismissed)

    # ── Filtering ───────────────────────────────────────────────────────

    def filter_by_severity(self, severity: str) -> List[Recommendation]:
        """Return active recommendations matching a severity level."""
        sev = severity.lower()
        return [r for r in self.get_active() if r.severity == sev]

    def filter_by_category(self, category: str) -> List[Recommendation]:
        """Return active recommendations matching a category."""
        cat = category.lower()
        return [r for r in self.get_active() if r.category == cat]

    def filter_by_source(self, source: str) -> List[Recommendation]:
        """Return active recommendations from a specific source."""
        return [r for r in self.get_active() if r.source == source]

    def search(self, query: str) -> List[Recommendation]:
        """Full-text search across title, description, and evidence."""
        q = query.lower()
        results: List[Recommendation] = []
        for r in self.get_active():
            if (q in r.title.lower()
                    or q in r.description.lower()
                    or q in r.evidence.lower()
                    or q in r.suggested_fix.lower()):
                results.append(r)
        return results

    # ── Pruning ─────────────────────────────────────────────────────────

    def _prune_if_needed(self) -> None:
        """Remove oldest dismissed entries when store exceeds _MAX_STORED."""
        if len(self._recommendations) <= _MAX_STORED:
            return
        # Sort dismissed by created_at ascending, remove oldest first.
        dismissed = [
            (rid, r) for rid, r in self._recommendations.items() if r.dismissed
        ]
        dismissed.sort(key=lambda pair: pair[1].created_at)
        to_remove = len(self._recommendations) - _MAX_STORED
        for i in range(min(to_remove, len(dismissed))):
            del self._recommendations[dismissed[i][0]]


# ═══════════════════════════════════════════════════════════════════════════
# RecommendationEngine — Core Rule-Based Generation
# ═══════════════════════════════════════════════════════════════════════════


class RecommendationEngine:
    """Core rule-based recommendation generation engine.

    Responsibilities:
    - Rule-based recommendation generation (if X then recommend Y)
    - Priority scoring based on severity + effort + impact
    - Deduplication of similar recommendations via Jaccard similarity
    - Aging: old recommendations get escalated severity
    """

    def __init__(self, store: Optional[RecommendationStore] = None) -> None:
        self.store: RecommendationStore = store or RecommendationStore()

    # ── Jaccard Similarity for Deduplication ────────────────────────────

    @staticmethod
    def _tokenise(text: str) -> Set[str]:
        """Split text into a set of lowercase word tokens."""
        return set(re.findall(r"\b\w+\b", text.lower()))

    def _jaccard(self, a: str, b: str) -> float:
        """Compute Jaccard similarity between two strings."""
        tokens_a = self._tokenise(a)
        tokens_b = self._tokenise(b)
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    def _is_duplicate(
        self, candidate: Recommendation, existing: List[Recommendation]
    ) -> bool:
        """Check if *candidate* duplicates any *existing* recommendation."""
        for ex in existing:
            # Same category is required for a duplicate match.
            if ex.category != candidate.category:
                continue
            if ex.dismissed:
                continue
            # Compare by title similarity and affected files overlap.
            title_sim = self._jaccard(candidate.title, ex.title)
            if title_sim >= _DEDUP_THRESHOLD:
                return True
            # Also check if they affect the same files with similar titles.
            if (candidate.affected_files and ex.affected_files
                    and set(candidate.affected_files) & set(ex.affected_files)
                    and title_sim >= 0.4):
                return True
        return False

    # ── Aging / Escalation ──────────────────────────────────────────────

    @staticmethod
    def _age_recommendation(rec: Recommendation) -> Recommendation:
        """Escalate severity of old recommendations.

        - After _STALE_DAYS: boost severity by one level.
        - After _VERY_STALE_DAYS: boost severity by two levels.
        Returns a *new* Recommendation with updated fields.
        """
        now = datetime.now(timezone.utc)
        try:
            created = datetime.fromisoformat(rec.created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return rec

        age_days = (now - created).total_seconds() / 86400.0

        if age_days >= _VERY_STALE_DAYS:
            new_sev = RecommendationEngine._escalate_severity(rec.severity, steps=2)
        elif age_days >= _STALE_DAYS:
            new_sev = RecommendationEngine._escalate_severity(rec.severity, steps=1)
        else:
            return rec

        if new_sev == rec.severity:
            return rec

        # Build a new Recommendation with the escalated severity.
        updated = Recommendation(
            id=rec.id,
            title=rec.title,
            description=rec.description,
            severity=new_sev,
            category=rec.category,
            effort_estimate=rec.effort_estimate,
            affected_files=rec.affected_files,
            suggested_fix=rec.suggested_fix,
            evidence=rec.evidence,
            confidence=rec.confidence,
            created_at=rec.created_at,
            dismissed=rec.dismissed,
            dismissed_reason=rec.dismissed_reason,
            source=rec.source,
        )
        return updated

    @staticmethod
    def _escalate_severity(current: str, steps: int = 1) -> str:
        """Move severity *steps* levels higher (more severe).

        Order: info -> low -> medium -> high -> critical
        """
        order = ["info", "low", "medium", "high", "critical"]
        current = current.lower()
        try:
            idx = order.index(current)
        except ValueError:
            return current
        new_idx = min(idx + steps, len(order) - 1)
        return order[new_idx]

    # ── Add with Dedup + Persist ────────────────────────────────────────

    def _add_recommendations(self, recommendations: List[Recommendation]) -> int:
        """Add recommendations to the store, skipping duplicates.

        Returns the number of newly added recommendations.
        """
        active = self.store.get_active()
        # Also age existing recommendations while we're here.
        for i, rec in enumerate(active):
            aged = self._age_recommendation(rec)
            if aged.id != rec.id or aged.severity != rec.severity:
                self.store._recommendations[aged.id] = aged

        added = 0
        for rec in recommendations:
            if not self._is_duplicate(rec, active):
                if self.store.add(rec):
                    added += 1
                    active.append(rec)  # Update active list for intra-batch dedup
        return added

    # ═══════════════════════════════════════════════════════════════════
    # Recommendation Generation Rules
    # ═══════════════════════════════════════════════════════════════════

    def generate_from_diagnostics(self, diag_results: Dict[str, Any]) -> List[Recommendation]:
        """Generate engineering recommendations from diagnostic check results.

        Expected input shape (from diagnostics.run_diagnostics):
            {
                "timestamp": str,
                "total_checks": int,
                "passed": int,
                "failed": int,
                "checks": [
                    {"label": str, "status": "ok"|"error", "value": Any, "error": str}
                ]
            }
        """
        recommendations: List[Recommendation] = []
        if not diag_results or "checks" not in diag_results:
            return recommendations

        checks = diag_results.get("checks", [])
        failed_checks = [c for c in checks if c.get("status") == "error"]

        if not failed_checks:
            return recommendations

        # ── Broken module registry ──────────────────────────────────────
        registry_check = next(
            (c for c in failed_checks if c.get("label") == "module_registry"), None
        )
        if registry_check:
            value = registry_check.get("value", {})
            broken = value.get("broken", []) if isinstance(value, dict) else []
            recommendations.append(Recommendation(
                title=f"Fix {len(broken)} broken module runners",
                description=(
                    f"The module registry has {len(broken)} module(s) with broken or "
                    f"non-callable runners: {broken}. This prevents these modules from "
                    f"being executed during scans."
                ),
                severity="high" if len(broken) >= 3 else "medium",
                category="diagnostics",
                effort_estimate="small",
                affected_files=[f"module:{m}" for m in broken],
                suggested_fix=(
                    "Verify that all module files exist and their runner functions are "
                    "properly defined. Reinstall ReconPro if files are missing."
                ),
                evidence=f"module_registry check failed: {registry_check.get('error', '')}",
                confidence=0.95,
                source="diagnostics",
            ))

        # ── Disk space low ─────────────────────────────────────────────
        disk_check = next(
            (c for c in failed_checks if c.get("label") == "disk_space"), None
        )
        if disk_check:
            recommendations.append(Recommendation(
                title="Insufficient disk space for scan data",
                description=(
                    "Disk space is critically low. Scan data storage, history files, "
                    "and drift snapshots may fail to persist. This can cause data loss "
                    "and prevent scan completion."
                ),
                severity="high",
                category="operational",
                effort_estimate="small",
                affected_files=[],
                suggested_fix=(
                    "Free up disk space by cleaning old scan history, pruning drift "
                    "snapshots, or expanding the storage volume."
                ),
                evidence=f"disk_space check failed: {disk_check.get('error', '')}",
                confidence=0.9,
                source="diagnostics",
            ))

        # ── Network unreachable ────────────────────────────────────────
        network_check = next(
            (c for c in failed_checks if c.get("label") == "network_dns"), None
        )
        if network_check:
            recommendations.append(Recommendation(
                title="Network connectivity unavailable",
                description=(
                    "DNS resolution failed, indicating network connectivity issues. "
                    "All remote scanning modules require network access to function."
                ),
                severity="high",
                category="operational",
                effort_estimate="trivial",
                affected_files=[],
                suggested_fix=(
                    "Verify network connectivity, DNS configuration, and firewall rules. "
                    "Check if a proxy is required."
                ),
                evidence=f"network_dns check failed: {network_check.get('error', '')}",
                confidence=0.95,
                source="diagnostics",
            ))

        # ── SSL certificate verification failure ───────────────────────
        ssl_check = next(
            (c for c in failed_checks if c.get("label") == "ssl_certificate"), None
        )
        if ssl_check:
            recommendations.append(Recommendation(
                title="SSL certificate verification broken",
                description=(
                    "The system cannot verify SSL certificates. This may indicate "
                    "missing CA certificates, incorrect system time, or corporate "
                    "proxy interference with TLS."
                ),
                severity="medium",
                category="operational",
                effort_estimate="small",
                affected_files=[],
                suggested_fix=(
                    "Install CA certificate bundles, verify system clock is correct, "
                    "and check if corporate proxy is intercepting HTTPS traffic."
                ),
                evidence=f"ssl_certificate check failed: {ssl_check.get('error', '')}",
                confidence=0.85,
                source="diagnostics",
            ))

        # ── Plugin directory missing ────────────────────────────────────
        plugin_check = next(
            (c for c in failed_checks if c.get("label") == "plugin_directory"), None
        )
        if plugin_check:
            recommendations.append(Recommendation(
                title="Plugin directory is missing or inaccessible",
                description=(
                    "The plugin directory does not exist or is not accessible. "
                    "Custom plugins cannot be loaded until this is resolved."
                ),
                severity="low",
                category="operational",
                effort_estimate="trivial",
                affected_files=[],
                suggested_fix=(
                    "Create the plugin directory at ~/.reconpro/plugins/ and ensure "
                    "appropriate read/write permissions."
                ),
                evidence=f"plugin_directory check failed: {plugin_check.get('error', '')}",
                confidence=0.9,
                source="diagnostics",
            ))

        # ── Scan history missing ────────────────────────────────────────
        history_check = next(
            (c for c in failed_checks if c.get("label") == "scan_history"), None
        )
        if history_check:
            recommendations.append(Recommendation(
                title="Scan history directory is missing",
                description=(
                    "The scan history directory does not exist. Scan results cannot "
                    "be persisted, which means historical comparison and trend "
                    "analysis features will not work."
                ),
                severity="medium",
                category="operational",
                effort_estimate="trivial",
                affected_files=[],
                suggested_fix=(
                    "Create the scan history directory at ~/.reconpro/scans/. "
                    "It will be auto-created on the next scan, but creating it now "
                    "enables immediate functionality."
                ),
                evidence=f"scan_history check failed: {history_check.get('error', '')}",
                confidence=0.9,
                source="diagnostics",
            ))

        # ── Memory check issues ─────────────────────────────────────────
        memory_check = next(
            (c for c in failed_checks if c.get("label") == "memory"), None
        )
        if memory_check:
            recommendations.append(Recommendation(
                title="Memory resource information unavailable",
                description=(
                    "Could not determine system memory availability. This may "
                    "affect the ability to detect resource constraints during "
                    "large-scale scans."
                ),
                severity="low",
                category="operational",
                effort_estimate="trivial",
                affected_files=[],
                suggested_fix=(
                    "Install the 'resource' module (Unix) or 'psutil' package for "
                    "enhanced memory monitoring."
                ),
                evidence=f"memory check failed: {memory_check.get('error', '')}",
                confidence=0.7,
                source="diagnostics",
            ))

        # ── Configuration issues ────────────────────────────────────────
        config_check = next(
            (c for c in failed_checks if c.get("label") == "configuration"), None
        )
        if config_check:
            recommendations.append(Recommendation(
                title="Configuration file issues detected",
                description=(
                    "Problems detected with the ReconPro configuration file. "
                    "Default settings will be used, which may not match your "
                    "operational requirements."
                ),
                severity="medium",
                category="operational",
                effort_estimate="small",
                affected_files=["config.json"],
                suggested_fix=(
                    "Review and fix the configuration file at ~/.reconpro/config.json. "
                    "Ensure valid JSON syntax."
                ),
                evidence=f"configuration check failed: {config_check.get('error', '')}",
                confidence=0.85,
                source="diagnostics",
            ))

        # ── Generic: multiple failures ─────────────────────────────────
        if len(failed_checks) >= 5 and len(recommendations) < 3:
            failed_labels = [c.get("label", "unknown") for c in failed_checks]
            recommendations.append(Recommendation(
                title=f"System health degraded: {len(failed_checks)} checks failed",
                description=(
                    f"A significant number of diagnostic checks are failing: "
                    f"{', '.join(failed_labels)}. This indicates a systemic issue "
                    f"that may affect scan reliability."
                ),
                severity="high",
                category="diagnostics",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Run 'reconpro diagnose' for a full report and address each "
                    "failing check systematically."
                ),
                evidence=f"Failed checks: {', '.join(failed_labels)}",
                confidence=0.95,
                source="diagnostics",
            ))

        return recommendations

    def generate_from_drift(self, drift_report: Dict[str, Any]) -> List[Recommendation]:
        """Generate engineering recommendations from a drift detection report.

        Expected input shape (from drift_monitor.check_for_drift):
            {
                "target": str,
                "drift_detected": bool,
                "drift_event_count": int,
                "previous_timestamp": str,
                "current_timestamp": str,
                "drift_events": [{
                    "timestamp": str,
                    "field_changed": str,
                    "old_value": str,
                    "new_value": str,
                    "severity": str,
                    "risk_impact": str,
                }],
                "risk_score": float,
            }
        """
        recommendations: List[Recommendation] = []
        if not drift_report or not drift_report.get("drift_detected", False):
            return recommendations

        target = drift_report.get("target", "unknown")
        events = drift_report.get("drift_events", [])
        risk_score = drift_report.get("risk_score", 0.0)

        if not events:
            return recommendations

        # Group events by category for aggregate analysis.
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for evt in events:
            cat = evt.get("field_changed", "UNKNOWN")
            by_category.setdefault(cat, []).append(evt)

        # ── Security header removal ─────────────────────────────────────
        security_removals = [
            e for e in events
            if "security_header_removed" in e.get("field_changed", "")
        ]
        if security_removals:
            headers_removed = [
                e.get("field_changed", "").replace("security_header_removed:", "")
                for e in security_removals
            ]
            recommendations.append(Recommendation(
                title=f"Security headers removed on {target}",
                description=(
                    f"{len(headers_removed)} security header(s) were removed from {target}: "
                    f"{', '.join(headers_removed)}. This reduces the security posture "
                    f"and may indicate a deployment regression or misconfiguration."
                ),
                severity="high" if len(headers_removed) >= 2 else "medium",
                category="drift",
                effort_estimate="small",
                affected_files=[target],
                suggested_fix=(
                    f"Verify deployment pipeline for {target}. Ensure security headers "
                    f"are configured in the web server or reverse proxy configuration. "
                    f"Consider adding header enforcement to CI/CD checks."
                ),
                evidence=f"Drift events: {json.dumps([e.get('field_changed', '') for e in security_removals])}",
                confidence=0.9,
                source="drift",
            ))

        # ── Technology stack changes ────────────────────────────────────
        tech_events = by_category.get("TECH_CHANGE", [])
        if tech_events:
            tech_changes = []
            for e in tech_events:
                if "added" in e.get("risk_impact", "").lower():
                    tech_changes.append(f"+{e.get('new_value', '')}")
                elif "removed" in e.get("risk_impact", "").lower():
                    tech_changes.append(f"-{e.get('old_value', '')}")
                else:
                    tech_changes.append(
                        f"{e.get('old_value', '')} -> {e.get('new_value', '')}"
                    )

            recommendations.append(Recommendation(
                title=f"Technology stack changed on {target}",
                description=(
                    f"The technology stack of {target} has changed: "
                    f"{', '.join(tech_changes)}. Technology changes may introduce "
                    f"new attack surfaces or remove existing security controls."
                ),
                severity="medium",
                category="drift",
                effort_estimate="small",
                affected_files=[target],
                suggested_fix=(
                    "Review the technology changes for security implications. Update "
                    "scan profiles and detection signatures if new technologies "
                    "require different testing approaches."
                ),
                evidence=f"Technology drift: {json.dumps(tech_changes)}",
                confidence=0.85,
                source="drift",
            ))

        # ── New open ports ──────────────────────────────────────────────
        port_events = by_category.get("PORT_CHANGE", [])
        new_ports = [
            e for e in port_events
            if "added" in e.get("risk_impact", "").lower()
        ]
        if new_ports:
            port_nums = [e.get("new_value", "") for e in new_ports]
            recommendations.append(Recommendation(
                title=f"New ports opened on {target}",
                description=(
                    f"{len(new_ports)} new port(s) detected on {target}: "
                    f"{', '.join(port_nums)}. New ports increase the attack surface "
                    f"and should be inventoried and assessed."
                ),
                severity="high",
                category="drift",
                effort_estimate="small",
                affected_files=[target],
                suggested_fix=(
                    f"Inventory the new ports on {target}. Verify they are intended "
                    f"and properly firewalled. Run a service scan to identify the "
                    f"applications listening on these ports."
                ),
                evidence=f"New ports: {', '.join(port_nums)}",
                confidence=0.9,
                source="drift",
            ))

        # ── TLS certificate change ─────────────────────────────────────
        cert_events = by_category.get("CERT_CHANGE", [])
        if cert_events:
            recommendations.append(Recommendation(
                title=f"TLS certificate changed on {target}",
                description=(
                    f"The TLS certificate for {target} has changed. This could be "
                    f"a legitimate renewal or could indicate a certificate authority "
                    f"compromise or man-in-the-middle setup."
                ),
                severity="medium",
                category="drift",
                effort_estimate="small",
                affected_files=[target],
                suggested_fix=(
                    f"Verify the new certificate for {target} is from a trusted CA. "
                    f"Check certificate transparency logs and verify with the target's "
                    f"IT team that the change was intentional."
                ),
                evidence=f"Certificate drift events: {len(cert_events)}",
                confidence=0.75,
                source="drift",
            ))

        # ── DNS record changes ──────────────────────────────────────────
        dns_events = by_category.get("DNS_CHANGE", [])
        if dns_events:
            recommendations.append(Recommendation(
                title=f"DNS configuration changed on {target}",
                description=(
                    f"{len(dns_events)} DNS record change(s) detected for {target}. "
                    f"DNS changes can affect service availability, email routing, "
                    f"and content delivery."
                ),
                severity="medium",
                category="drift",
                effort_estimate="small",
                affected_files=[target],
                suggested_fix=(
                    f"Review DNS changes for {target}. Ensure MX records are "
                    f"intentional (affects email delivery). Verify SPF/DKIM/DMARC "
                    f"records are still properly configured."
                ),
                evidence=f"DNS events: {json.dumps([e.get('field_changed', '') for e in dns_events])}",
                confidence=0.85,
                source="drift",
            ))

        # ── High volume drift ───────────────────────────────────────────
        if len(events) >= 10:
            recommendations.append(Recommendation(
                title=f"High volume infrastructure drift on {target} ({len(events)} changes)",
                description=(
                    f"An unusually large number of infrastructure changes ({len(events)}) "
                    f"detected on {target} since the last snapshot. This may indicate "
                    f"a major deployment, infrastructure migration, or potential compromise."
                ),
                severity="high" if risk_score >= 70 else "medium",
                category="drift",
                effort_estimate="medium",
                affected_files=[target],
                suggested_fix=(
                    f"Correlate the drift events with known deployment schedules for "
                    f"{target}. If no deployment is planned, investigate for potential "
                    f"unauthorized infrastructure changes."
                ),
                evidence=f"Drift count: {len(events)}, risk_score: {risk_score}",
                confidence=0.8,
                source="drift",
            ))

        # ── Status code regression ─────────────────────────────────────
        status_events = by_category.get("STATUS_CHANGE", [])
        for evt in status_events:
            old_code = evt.get("old_value", "")
            new_code = evt.get("new_value", "")
            try:
                new_int = int(new_code)
            except (ValueError, TypeError):
                continue
            if new_int >= 500:
                recommendations.append(Recommendation(
                    title=f"HTTP 5xx errors detected on {target}",
                    description=(
                        f"The HTTP status code for {target} changed from {old_code} to "
                        f"{new_code}, indicating a server error. This may be a transient "
                        f"issue or a deployment problem."
                    ),
                    severity="high",
                    category="drift",
                    effort_estimate="trivial",
                    affected_files=[target],
                    suggested_fix=(
                        f"Check the application logs and server health for {target}. "
                        f"Verify recent deployments haven't introduced errors."
                    ),
                    evidence=f"Status change: {old_code} -> {new_code}",
                    confidence=0.9,
                    source="drift",
                ))

        return recommendations

    def generate_from_test_results(self, test_results: Dict[str, Any]) -> List[Recommendation]:
        """Generate engineering recommendations from test suite results.

        Expected input shape:
            {
                "total": int,
                "passed": int,
                "failed": int,
                "skipped": int,
                "errors": int,
                "duration_s": float,
                "failures": [
                    {
                        "test_name": str,
                        "error_message": str,
                        "file": str,
                    }
                ],
            }
        """
        recommendations: List[Recommendation] = []
        if not test_results:
            return recommendations

        total = test_results.get("total", 0)
        passed = test_results.get("passed", 0)
        failed = test_results.get("failed", 0)
        errors = test_results.get("errors", 0)
        skipped = test_results.get("skipped", 0)
        duration = test_results.get("duration_s", 0.0)
        failures = test_results.get("failures", [])

        if total == 0:
            return recommendations

        pass_rate = passed / total

        # ── Low pass rate ───────────────────────────────────────────────
        if pass_rate < 0.8 and total >= 5:
            recommendations.append(Recommendation(
                title=f"Low test pass rate: {pass_rate:.1%} ({passed}/{total})",
                description=(
                    f"The test suite has a pass rate of {pass_rate:.1%}, which is below "
                    f"the 80% threshold. {failed} test(s) failed and {errors} encountered "
                    f"errors. This indicates code quality or test stability issues."
                ),
                severity="high" if pass_rate < 0.5 else "medium",
                category="testing",
                effort_estimate="large",
                affected_files=list({f.get("file", "") for f in failures if f.get("file")}),
                suggested_fix=(
                    "Prioritise fixing failing tests. Categorise failures into: "
                    "(1) genuine code bugs, (2) flaky tests needing stabilisation, "
                    "(3) outdated tests needing updates."
                ),
                evidence=f"pass_rate={pass_rate:.1%}, failed={failed}, errors={errors}",
                confidence=0.95,
                source="testing",
            ))

        # ── Test errors (distinct from failures) ───────────────────────
        if errors > 0:
            recommendations.append(Recommendation(
                title=f"{errors} test error(s) detected in test suite",
                description=(
                    f"{errors} test(s) encountered errors (not assertions failures, but "
                    f"uncaught exceptions). This typically indicates missing fixtures, "
                    f"import errors, or environment configuration issues."
                ),
                severity="medium",
                category="testing",
                effort_estimate="medium",
                affected_files=[
                    f.get("file", "") for f in failures
                    if f.get("file") and "error" in f.get("error_message", "").lower()
                ],
                suggested_fix=(
                    "Investigate test errors for missing imports, fixture issues, or "
                    "environment dependencies. Ensure tests are self-contained."
                ),
                evidence=f"errors={errors}",
                confidence=0.9,
                source="testing",
            ))

        # ── High skip rate ──────────────────────────────────────────────
        if total >= 10 and skipped / total > 0.2:
            recommendations.append(Recommendation(
                title=f"High test skip rate: {skipped}/{total} ({skipped/total:.1%})",
                description=(
                    f"{skipped} out of {total} tests are being skipped. Skipped tests "
                    f"reduce coverage and may mask regressions. Common causes include "
                    f"missing dependencies, platform-specific conditions, or stale tests."
                ),
                severity="low",
                category="testing",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Review skipped tests and either: (1) fix them if they test "
                    "important functionality, (2) remove them if obsolete, or "
                    "(3) document the skip reason if intentional."
                ),
                evidence=f"skipped={skipped}, total={total}",
                confidence=0.8,
                source="testing",
            ))

        # ── Slow test suite ─────────────────────────────────────────────
        if duration > 30.0:
            recommendations.append(Recommendation(
                title=f"Test suite is slow: {duration:.1f}s total runtime",
                description=(
                    f"The test suite took {duration:.1f}s to complete. Slow tests "
                    f"reduce developer productivity and discourage frequent testing. "
                    f"Tests taking more than 30s should be investigated."
                ),
                severity="low",
                category="performance",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Profile the test suite to identify slow tests. Common fixes: "
                    "mock external I/O, reduce sleep/timing waits, parallelise "
                    "independent tests, or move slow integration tests to a "
                    "separate CI pipeline."
                ),
                evidence=f"duration_s={duration:.1f}",
                confidence=0.85,
                source="testing",
            ))

        # ── Repeated failure patterns ───────────────────────────────────
        if failures:
            # Group by file to identify problematic modules.
            file_counts: Dict[str, int] = {}
            for f in failures:
                fname = f.get("file", "unknown")
                file_counts[fname] = file_counts.get(fname, 0) + 1

            for fname, count in file_counts.items():
                if count >= 3 and fname != "unknown":
                    recommendations.append(Recommendation(
                        title=f"Multiple test failures in {fname} ({count} failures)",
                        description=(
                            f"{count} tests failed in {fname}, suggesting a systemic issue "
                            f"in this module. This could be a broken function, missing "
                            f"dependency, or widespread API change."
                        ),
                        severity="high",
                        category="testing",
                        effort_estimate="medium",
                        affected_files=[fname],
                        suggested_fix=(
                            f"Review all failing tests in {fname} for a common root cause. "
                            f"Check if a recent change to the module broke the expected API."
                        ),
                        evidence=f"file={fname}, failure_count={count}",
                        confidence=0.9,
                        source="testing",
                    ))

        return recommendations

    def generate_from_performance(self, perf_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate engineering recommendations from performance metrics.

        Expected input shape:
            {
                "scan_duration_s": float,
                "module_timings": {
                    "module_name": {"duration_s": float, "findings_count": int}
                },
                "memory_peak_mb": float,
                "request_count": int,
                "error_count": int,
                "timeout_count": int,
            }
        """
        recommendations: List[Recommendation] = []
        if not perf_data:
            return recommendations

        total_duration = perf_data.get("scan_duration_s", 0.0)
        module_timings = perf_data.get("module_timings", {})
        memory_peak = perf_data.get("memory_peak_mb", 0.0)
        request_count = perf_data.get("request_count", 0)
        error_count = perf_data.get("error_count", 0)
        timeout_count = perf_data.get("timeout_count", 0)

        # ── High error rate ─────────────────────────────────────────────
        if request_count > 0 and error_count / request_count > 0.1:
            error_rate = error_count / request_count
            recommendations.append(Recommendation(
                title=f"High request error rate: {error_rate:.1%}",
                description=(
                    f"{error_count} out of {request_count} requests failed ({error_rate:.1%}). "
                    f"High error rates degrade scan quality and may indicate "
                    f"target instability, rate limiting, or network issues."
                ),
                severity="high" if error_rate > 0.3 else "medium",
                category="performance",
                effort_estimate="small",
                affected_files=[],
                suggested_fix=(
                    "Check if the target is rate-limiting requests. Consider increasing "
                    "the timeout, reducing concurrency, or adding retry logic with "
                    "exponential backoff."
                ),
                evidence=f"errors={error_count}, requests={request_count}, rate={error_rate:.1%}",
                confidence=0.9,
                source="performance",
            ))

        # ── High timeout rate ───────────────────────────────────────────
        if request_count > 0 and timeout_count / request_count > 0.05:
            timeout_rate = timeout_count / request_count
            recommendations.append(Recommendation(
                title=f"High request timeout rate: {timeout_rate:.1%}",
                description=(
                    f"{timeout_count} out of {request_count} requests timed out "
                    f"({timeout_rate:.1%}). This suggests the target or network is "
                    f"slow to respond, or the timeout is set too aggressively."
                ),
                severity="medium",
                category="performance",
                effort_estimate="small",
                affected_files=[],
                suggested_fix=(
                    "Increase the request timeout from the current value. For slow "
                    f"targets, consider a timeout of 15-30s. Also check if the "
                    f"network path has high latency."
                ),
                evidence=f"timeouts={timeout_count}, requests={request_count}",
                confidence=0.85,
                source="performance",
            ))

        # ── Slow modules ────────────────────────────────────────────────
        if module_timings:
            slow_modules: List[Tuple[str, float]] = []
            for mod_name, mod_data in module_timings.items():
                dur = mod_data.get("duration_s", 0.0) if isinstance(mod_data, dict) else 0.0
                if dur > 10.0:
                    slow_modules.append((mod_name, dur))

            if slow_modules:
                slow_modules.sort(key=lambda x: x[1], reverse=True)
                for mod_name, dur in slow_modules[:3]:  # Top 3 slowest
                    findings = 0
                    if isinstance(module_timings.get(mod_name), dict):
                        findings = module_timings[mod_name].get("findings_count", 0)
                    efficiency = "low" if findings < 5 and dur > 30.0 else "moderate"
                    recommendations.append(Recommendation(
                        title=f"Slow module: {mod_name} took {dur:.1f}s",
                        description=(
                            f"Module '{mod_name}' took {dur:.1f}s and produced "
                            f"{findings} finding(s). Efficiency is {efficiency}. "
                            f"This module dominates scan time."
                        ),
                        severity="medium" if efficiency == "low" else "low",
                        category="performance",
                        effort_estimate="medium",
                        affected_files=[f"module:{mod_name}"],
                        suggested_fix=(
                            f"Profile '{mod_name}' to identify bottlenecks. Consider: "
                            f"(1) reducing the scope of checks, (2) parallelising "
                            f"independent operations, (3) caching repeated lookups."
                        ),
                        evidence=f"module={mod_name}, duration={dur:.1f}s, findings={findings}",
                        confidence=0.8,
                        source="performance",
                    ))

        # ── High memory usage ───────────────────────────────────────────
        if memory_peak > 500.0:
            recommendations.append(Recommendation(
                title=f"High memory usage: {memory_peak:.0f}MB peak",
                description=(
                    f"Peak memory usage reached {memory_peak:.0f}MB during the scan. "
                    f"High memory usage can cause OOM kills on constrained systems "
                    f"and limits the ability to scan large targets."
                ),
                severity="medium" if memory_peak > 1000 else "low",
                category="performance",
                effort_estimate="large",
                affected_files=[],
                suggested_fix=(
                    "Profile memory usage to identify the largest consumers. Common "
                    "fixes: (1) stream large responses instead of buffering, "
                    "(2) limit the number of concurrent requests, (3) release "
                    "references to processed data promptly."
                ),
                evidence=f"memory_peak_mb={memory_peak:.0f}",
                confidence=0.8,
                source="performance",
            ))

        # ── Overall scan duration ───────────────────────────────────────
        if total_duration > 300.0:
            recommendations.append(Recommendation(
                title=f"Long scan duration: {total_duration:.0f}s ({total_duration/60:.1f}min)",
                description=(
                    f"The total scan took {total_duration:.0f}s. Long scan times "
                    f"reduce operational agility and may exceed timeout budgets."
                ),
                severity="medium",
                category="performance",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Consider: (1) running only essential modules, (2) increasing "
                    "worker concurrency, (3) using the 'blitz' mode for faster "
                    "scans, (4) parallelising independent module execution."
                ),
                evidence=f"scan_duration_s={total_duration:.0f}",
                confidence=0.75,
                source="performance",
            ))

        return recommendations

    def generate_from_security(self, sec_findings: Dict[str, Any]) -> List[Recommendation]:
        """Generate engineering recommendations from security findings.

        NOTE: This is NOT about generating security remediation advice (that's
        the AI Analyst's job). This generates ENGINEERING recommendations about
        the scan infrastructure, tooling, and process based on security findings.

        Expected input shape:
            {
                "total_findings": int,
                "false_positive_rate": float,
                "scan_coverage_pct": float,
                "modules_run": [str],
                "findings_by_severity": {"critical": int, "high": int, ...},
                "cross_validation_rate": float,
            }
        """
        recommendations: List[Recommendation] = []
        if not sec_findings:
            return recommendations

        total = sec_findings.get("total_findings", 0)
        fp_rate = sec_findings.get("false_positive_rate", 0.0)
        coverage = sec_findings.get("scan_coverage_pct", 100.0)
        modules_run = sec_findings.get("modules_run", [])
        by_severity = sec_findings.get("findings_by_severity", {})
        cv_rate = sec_findings.get("cross_validation_rate", 100.0)

        # ── High false positive rate ────────────────────────────────────
        if fp_rate > 0.3 and total >= 10:
            recommendations.append(Recommendation(
                title=f"High false positive rate: {fp_rate:.1%}",
                description=(
                    f"{fp_rate:.1%} of findings appear to be false positives. High FP "
                    f"rates waste analyst time, reduce trust in the tool, and may "
                    f"cause real issues to be overlooked."
                ),
                severity="high" if fp_rate > 0.5 else "medium",
                category="code_quality",
                effort_estimate="large",
                affected_files=[],
                suggested_fix=(
                    "Review and improve detection signatures in the modules producing "
                    "false positives. Consider adding confirmation checks, tuning "
                    "thresholds, or implementing Bayesian confidence scoring."
                ),
                evidence=f"fp_rate={fp_rate:.1%}, total_findings={total}",
                confidence=0.8,
                source="security",
            ))

        # ── Low cross-validation rate ──────────────────────────────────
        if cv_rate < 70.0:
            recommendations.append(Recommendation(
                title=f"Low cross-validation rate: {cv_rate:.1%}",
                description=(
                    f"Only {cv_rate:.1%} of findings could be independently verified. "
                    f"Low validation rates suggest detection logic may be producing "
                    f"unverifiable or unreliable results."
                ),
                severity="medium",
                category="code_quality",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Improve detection signatures to produce verifiable evidence. "
                    "Ensure findings include specific, checkable indicators rather "
                    "than vague descriptions."
                ),
                evidence=f"cross_validation_rate={cv_rate:.1%}",
                confidence=0.85,
                source="security",
            ))

        # ── Limited module coverage ─────────────────────────────────────
        if len(modules_run) < 5:
            recommendations.append(Recommendation(
                title=f"Limited scan coverage: only {len(modules_run)} module(s) run",
                description=(
                    f"Only {len(modules_run)} module(s) were executed: "
                    f"{', '.join(modules_run)}. This provides incomplete coverage "
                    f"and may miss important findings."
                ),
                severity="medium",
                category="testing",
                effort_estimate="trivial",
                affected_files=[],
                suggested_fix=(
                    "Run a broader scan using more modules. Consider 'reconpro scan --all' "
                    "or select modules relevant to the target's technology stack."
                ),
                evidence=f"modules_run={modules_run}",
                confidence=0.9,
                source="security",
            ))

        # ── No critical/high findings but low coverage ──────────────────
        critical_count = by_severity.get("critical", 0)
        high_count = by_severity.get("high", 0)
        if critical_count == 0 and high_count == 0 and coverage < 50.0:
            recommendations.append(Recommendation(
                title=f"No critical findings but scan coverage is only {coverage:.0f}%",
                description=(
                    f"No critical or high-severity findings were detected, but scan "
                    f"coverage is only {coverage:.0f}%. The absence of findings may "
                    f"simply reflect incomplete testing rather than a secure target."
                ),
                severity="medium",
                category="testing",
                effort_estimate="small",
                affected_files=[],
                suggested_fix=(
                    "Increase scan coverage before concluding the target is secure. "
                    "Run additional modules and verify all major attack surfaces "
                    "have been tested."
                ),
                evidence=f"coverage={coverage:.0f}%, critical=0, high=0",
                confidence=0.8,
                source="security",
            ))

        # ── Many info/low findings with no actionable ones ──────────────
        info_count = by_severity.get("info", 0)
        low_count = by_severity.get("low", 0)
        if total >= 20 and (info_count + low_count) / total > 0.8:
            recommendations.append(Recommendation(
                title=f"Scan produced mostly low-value findings ({(info_count + low_count)/total:.0%} info/low)",
                description=(
                    f"{info_count + low_count} out of {total} findings are info or low "
                    f"severity. While thoroughness is good, the signal-to-noise ratio "
                    f"is very low, suggesting the scan profile may need tuning."
                ),
                severity="low",
                category="code_quality",
                effort_estimate="medium",
                affected_files=[],
                suggested_fix=(
                    "Adjust detection thresholds to reduce noise. Consider implementing "
                    "finding importance scoring to surface only actionable results. "
                    "Review module sensitivity settings."
                ),
                evidence=(
                    f"info={info_count}, low={low_count}, total={total}, "
                    f"noise_ratio={(info_count + low_count) / total:.1%}"
                ),
                confidence=0.75,
                source="security",
            ))

        return recommendations


# ═══════════════════════════════════════════════════════════════════════════
# EngineeringRecommender — High-Level Facade
# ═══════════════════════════════════════════════════════════════════════════


class EngineeringRecommender:
    """High-level facade for the engineering recommendation system.

    Combines the RecommendationEngine and RecommendationStore into a
    convenient API that matches the interface specified in the task.
    """

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._store = RecommendationStore(path=store_path)
        self._engine = RecommendationEngine(store=self._store)

    def recommend_from_diagnostics(self, diag_results: Dict[str, Any]) -> List[Recommendation]:
        """Generate and store engineering recommendations from diagnostic results.

        Parameters
        ----------
        diag_results : dict
            Output from ``diagnostics.run_diagnostics()``.

        Returns
        -------
        list[Recommendation]
            The newly generated recommendations.
        """
        recs = self._engine.generate_from_diagnostics(diag_results)
        added = self._engine._add_recommendations(recs)
        logger.info(
            "Diagnostics recommendations: %d generated, %d newly added",
            len(recs), added,
        )
        return recs

    def recommend_from_drift(self, drift_report: Dict[str, Any]) -> List[Recommendation]:
        """Generate and store engineering recommendations from a drift report.

        Parameters
        ----------
        drift_report : dict
            Output from ``drift_monitor.check_for_drift()``.

        Returns
        -------
        list[Recommendation]
            The newly generated recommendations.
        """
        recs = self._engine.generate_from_drift(drift_report)
        added = self._engine._add_recommendations(recs)
        logger.info(
            "Drift recommendations: %d generated, %d newly added",
            len(recs), added,
        )
        return recs

    def recommend_from_test_results(self, test_results: Dict[str, Any]) -> List[Recommendation]:
        """Generate and store engineering recommendations from test results.

        Parameters
        ----------
        test_results : dict
            Test suite results with total, passed, failed, etc.

        Returns
        -------
        list[Recommendation]
            The newly generated recommendations.
        """
        recs = self._engine.generate_from_test_results(test_results)
        added = self._engine._add_recommendations(recs)
        logger.info(
            "Test recommendations: %d generated, %d newly added",
            len(recs), added,
        )
        return recs

    def recommend_from_performance(self, perf_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate and store engineering recommendations from performance data.

        Parameters
        ----------
        perf_data : dict
            Performance metrics from a scan run.

        Returns
        -------
        list[Recommendation]
            The newly generated recommendations.
        """
        recs = self._engine.generate_from_performance(perf_data)
        added = self._engine._add_recommendations(recs)
        logger.info(
            "Performance recommendations: %d generated, %d newly added",
            len(recs), added,
        )
        return recs

    def recommend_from_security(self, sec_findings: Dict[str, Any]) -> List[Recommendation]:
        """Generate and store engineering recommendations from security findings.

        NOTE: This generates ENGINEERING recommendations about scan quality
        and tooling, NOT security remediation advice.

        Parameters
        ----------
        sec_findings : dict
            Aggregated security findings metadata.

        Returns
        -------
        list[Recommendation]
            The newly generated recommendations.
        """
        recs = self._engine.generate_from_security(sec_findings)
        added = self._engine._add_recommendations(recs)
        logger.info(
            "Security engineering recommendations: %d generated, %d newly added",
            len(recs), added,
        )
        return recs

    def get_all_recommendations(self) -> List[Recommendation]:
        """Return all active recommendations, sorted by priority (highest first)."""
        return self._store.get_active()

    def dismiss_recommendation(self, rec_id: str, reason: str = "") -> bool:
        """Mark a recommendation as dismissed.

        Parameters
        ----------
        rec_id : str
            The recommendation ID to dismiss.
        reason : str
            Optional reason for dismissal.

        Returns
        -------
        bool
            True if the recommendation was found and dismissed.
        """
        success = self._store.dismiss(rec_id, reason)
        if success:
            logger.info("Dismissed recommendation %s: %s", rec_id, reason or "(no reason)")
        else:
            logger.warning("Cannot dismiss recommendation %s: not found", rec_id)
        return success

    def get_recommendation_stats(self) -> Dict[str, Any]:
        """Return statistics about current recommendations.

        Returns
        -------
        dict
            Statistics including counts by severity, category, source, and age.
        """
        active = self._store.get_active()
        dismissed = self._store.get_dismissed()
        all_recs = self._store.get_all()

        # Count by severity
        by_severity: Dict[str, int] = {}
        for r in active:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

        # Count by category
        by_category: Dict[str, int] = {}
        for r in active:
            by_category[r.category] = by_category.get(r.category, 0) + 1

        # Count by source
        by_source: Dict[str, int] = {}
        for r in active:
            by_source[r.source] = by_source.get(r.source, 0) + 1

        # Count by effort
        by_effort: Dict[str, int] = {}
        for r in active:
            by_effort[r.effort_estimate] = by_effort.get(r.effort_estimate, 0) + 1

        # Age analysis
        now = datetime.now(timezone.utc)
        age_buckets: Dict[str, int] = {"fresh": 0, "stale": 0, "very_stale": 0}
        for r in active:
            try:
                created = datetime.fromisoformat(r.created_at)
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (now - created).total_seconds() / 86400.0
                if age_days >= _VERY_STALE_DAYS:
                    age_buckets["very_stale"] += 1
                elif age_days >= _STALE_DAYS:
                    age_buckets["stale"] += 1
                else:
                    age_buckets["fresh"] += 1
            except (ValueError, TypeError):
                age_buckets["fresh"] += 1

        # Average confidence
        avg_confidence = 0.0
        if active:
            avg_confidence = sum(r.confidence for r in active) / len(active)

        # Average priority
        avg_priority = 0.0
        if active:
            avg_priority = sum(r.priority_score for r in active) / len(active)

        return {
            "total": len(all_recs),
            "active": len(active),
            "dismissed": len(dismissed),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_source": by_source,
            "by_effort": by_effort,
            "age_distribution": age_buckets,
            "average_confidence": round(avg_confidence, 3),
            "average_priority": round(avg_priority, 2),
            "highest_priority": active[0].priority_score if active else 0.0,
            "highest_priority_title": active[0].title if active else "",
        }


# ═══════════════════════════════════════════════════════════════════════════
# Module-Level Convenience API
# ═══════════════════════════════════════════════════════════════════════════

_global_recommender: Optional[EngineeringRecommender] = None


# DEAD CODE: consider removal
def get_recommender() -> EngineeringRecommender:
    """Return the global EngineeringRecommender instance (creates one if needed)."""
    global _global_recommender
    if _global_recommender is None:
        _global_recommender = EngineeringRecommender()
    return _global_recommender


# DEAD CODE: consider removal
def reset_recommender() -> None:
    """Reset the global recommender so the next call creates a fresh one."""
    global _global_recommender
    _global_recommender = None
