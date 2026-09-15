"""ReconPro v11 — Intelligence Pipeline.

Post-scan orchestration layer that composites the AI Analyst,
Attack Graph, Threat Intelligence, and Knowledge Graph engines into
a single unified analysis pass.  Produces an IntelligenceResult with
composite risk scores, attack paths, CVE/CWE/MITRE enrichment,
knowledge-graph entity/relationship data, and executive-ready summaries.

Pure Python.  Zero external dependencies.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# IntelligenceResult
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class IntelligenceResult:
    """Aggregated result from the intelligence pipeline.

    Contains composite risk scores, enriched findings, attack paths,
    threat intelligence matches, and timing metadata.
    """

    # -- Composite scores --------------------------------------------------
    executive_risk_score: float = 0.0
    exposure_score: float = 0.0
    mission_impact_score: float = 0.0
    infrastructure_health_score: float = 0.0
    threat_confidence_index: float = 0.0

    # -- Timing --------------------------------------------------------------
    pipeline_duration: float = 0.0
    ai_duration: float = 0.0
    graph_duration: float = 0.0
    intel_duration: float = 0.0
    regression_duration: float = 0.0
    recommendations_duration: float = 0.0

    # -- Engine metadata -----------------------------------------------------
    enabled_engines: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # -- AI Analyst outputs --------------------------------------------------
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    classification_summary: Dict[str, Any] = field(default_factory=dict)
    extended_findings: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)

    # -- Attack Graph outputs -------------------------------------------------
    attack_graph: Dict[str, Any] = field(default_factory=dict)
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    kill_chain_mapping: Dict[str, Any] = field(default_factory=dict)

    # -- Threat Intel outputs -------------------------------------------------
    cve_matches: List[str] = field(default_factory=list)
    cwe_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = field(default_factory=list)

    # -- Knowledge Graph outputs -------------------------------------------------
    knowledge_graph: Dict[str, Any] = field(default_factory=dict)
    entity_count: int = 0
    relationship_count: int = 0

    # -- Regression Intelligence outputs ----------------------------------------
    regression_data: Dict[str, Any] = field(default_factory=dict)

    # -- Engineering Recommendations outputs -----------------------------------
    recommendations: List[Dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def has_intelligence(self) -> bool:
        """Return True if the result contains any actionable intelligence."""
        return bool(
            self.attack_paths
            or self.cve_matches
            or self.mitre_techniques
            or self.attack_chains
            or self.extended_findings
            or self.classification_summary
            or self.regression_data
            or self.recommendations
        )

    @property
    def risk_level(self) -> str:
        """Map executive_risk_score to a human-readable risk level."""
        s = self.executive_risk_score
        if s >= 75:
            return "CRITICAL"
        if s >= 55:
            return "HIGH"
        if s >= 35:
            return "MEDIUM"
        if s >= 15:
            return "LOW"
        return "MINIMAL"

    # ------------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "executive_risk_score": round(self.executive_risk_score, 1),
            "exposure_score": round(self.exposure_score, 1),
            "mission_impact_score": round(self.mission_impact_score, 1),
            "infrastructure_health_score": round(self.infrastructure_health_score, 1),
            "threat_confidence_index": round(self.threat_confidence_index, 1),
            "pipeline_duration_ms": round(self.pipeline_duration * 1000, 1),
            "ai_duration_ms": round(self.ai_duration * 1000, 1),
            "graph_duration_ms": round(self.graph_duration * 1000, 1),
            "intel_duration_ms": round(self.intel_duration * 1000, 1),
            "enabled_engines": list(self.enabled_engines),
            "errors": list(self.errors),
            "risk_level": self.risk_level,
            "has_intelligence": self.has_intelligence,
            "ai_analysis": self.ai_analysis,
            "classification_summary": self.classification_summary,
            "extended_findings": self.extended_findings,
            "attack_paths": self.attack_paths,
            "attack_graph": self.attack_graph,
            "attack_chains": self.attack_chains,
            "kill_chain_mapping": self.kill_chain_mapping,
            "cve_matches": self.cve_matches,
            "cwe_matches": self.cwe_matches,
            "mitre_techniques": self.mitre_techniques,
            "knowledge_graph": self.knowledge_graph,
            "entity_count": self.entity_count,
            "relationship_count": self.relationship_count,
            "regression_data": self.regression_data,
            "recommendations": self.recommendations,
        }


# ═══════════════════════════════════════════════════════════════════════════
# IntelligencePipeline
# ═══════════════════════════════════════════════════════════════════════════


# Severity weight table (canonical)
_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0, "high": 8.0, "medium": 6.0, "low": 3.0, "info": 1.0,
}


def _sev_val(severity: str) -> float:
    return _SEVERITY_WEIGHTS.get(severity.lower(), 1.0)


def _finding_to_dict(f: Any) -> Dict[str, Any]:
    """Normalise a Finding object or dict into a plain dict."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if isinstance(f, dict):
        return dict(f)
    return {}


class IntelligencePipeline:
    """Post-scan orchestration layer.

    Composites AIAnalystEngine, AttackGraphEngine, ThreatIntelEngine,
    SecurityKnowledgeGraph, RegressionIntelligence, and
    EngineeringRecommendations into a single ``analyze()`` call that
    returns an ``IntelligenceResult``.
    """

    def __init__(
        self,
        *,
        enable_ai_analyst: bool = True,
        enable_attack_graph: bool = True,
        enable_threat_intel: bool = True,
        enable_knowledge_graph: bool = True,
        enable_regression: bool = True,
        enable_recommendations: bool = True,
    ) -> None:
        self.enable_ai_analyst = enable_ai_analyst
        self.enable_attack_graph = enable_attack_graph
        self.enable_threat_intel = enable_threat_intel
        self.enable_knowledge_graph = enable_knowledge_graph
        self.enable_regression = enable_regression
        self.enable_recommendations = enable_recommendations

    def analyze(
        self,
        findings: List[Any],
        scan_data: Optional[Dict[str, Any]] = None,
    ) -> IntelligenceResult:
        """Run all enabled intelligence engines on *findings*.

        Parameters
        ----------
        findings:
            Iterable of Finding objects or dicts.
        scan_data:
            Optional auxiliary scan metadata (unused by current engines
            but reserved for future enrichment).

        Returns
        -------
        IntelligenceResult
        """
        t_start = time.monotonic()
        result = IntelligenceResult()

        # Input validation
        MAX_FINDINGS = 10000  # Prevent memory exhaustion
        if len(findings) > MAX_FINDINGS:
            logger.warning(
                "Intelligence pipeline: truncating %d findings to %d",
                len(findings), MAX_FINDINGS,
            )
            findings = findings[:MAX_FINDINGS]
            result.errors.append(
                f"input_truncated: {MAX_FINDINGS} finding limit applied"
            )

        # Track which engines are active
        if self.enable_ai_analyst:
            result.enabled_engines.append("ai_analyst")
        if self.enable_attack_graph:
            result.enabled_engines.append("attack_graph")
        if self.enable_threat_intel:
            result.enabled_engines.append("threat_intel")
        if self.enable_knowledge_graph:
            result.enabled_engines.append("knowledge_graph")
        if self.enable_regression:
            result.enabled_engines.append("regression")
        if self.enable_recommendations:
            result.enabled_engines.append("recommendations")

        logger.info("Intelligence pipeline starting", extra={"engines": result.enabled_engines, "finding_count": len(findings)})

        # Normalise findings to plain dicts, skipping invalid items
        valid: List[Dict[str, Any]] = []
        for f in findings:
            try:
                d = _finding_to_dict(f)
                if d and "title" in d:
                    valid.append(d)
            except Exception:
                logger.debug("Skipping invalid finding during normalization", exc_info=True)

        if not valid:
            # No valid findings — return zeroed result immediately
            return result

        # ----------------------------------------------------------------
        # 1. AI Analyst
        # ----------------------------------------------------------------
        if self.enable_ai_analyst:
            try:
                from .ai_analyst import AIAnalystEngine

                engine = AIAnalystEngine()
                t_ai = time.monotonic()
                report = engine.analyze_scan(valid)
                result.ai_duration = time.monotonic() - t_ai

                # Classification summary
                classified_categories: Dict[str, int] = {}
                for item in report.classified:
                    cls = item.get("classification", {})
                    cat = cls.get("attack_category", "unknown")
                    classified_categories[cat] = classified_categories.get(cat, 0) + 1
                result.classification_summary = classified_categories

                # Extended findings
                result.extended_findings = report.extended_findings

                # Attack paths (from AI analyst)
                result.attack_paths = report.attack_paths

                # AI analysis summary dict
                result.ai_analysis = report.to_dict()

                duration_ms = result.ai_duration * 1000
                logger.info("Engine '%s' completed in %.1fms", "ai_analyst", duration_ms)

            except Exception as exc:
                logger.exception("ai_analyst engine failed")
                result.errors.append("ai_analyst: internal error")

        # ----------------------------------------------------------------
        # 2. Attack Graph
        # ----------------------------------------------------------------
        if self.enable_attack_graph:
            try:
                from .attack_graph import AttackGraphEngine

                engine = AttackGraphEngine()
                t_graph = time.monotonic()
                graph_result = engine.analyze(valid)
                result.graph_duration = time.monotonic() - t_graph

                result.attack_graph = graph_result.to_dict()
                result.attack_chains = graph_result.attack_chains
                result.kill_chain_mapping = graph_result.kill_chain_mapping

                duration_ms = result.graph_duration * 1000
                logger.info("Engine '%s' completed in %.1fms", "attack_graph", duration_ms)

            except Exception as exc:
                logger.exception("attack_graph engine failed")
                result.errors.append("attack_graph: internal error")

        # ----------------------------------------------------------------
        # 3. Threat Intelligence
        # ----------------------------------------------------------------
        if self.enable_threat_intel:
            try:
                from .threat_intel import ThreatIntelEngine

                engine = ThreatIntelEngine()
                t_intel = time.monotonic()
                intel_report = engine.enrich_scan(valid)
                result.intel_duration = time.monotonic() - t_intel

                result.cve_matches = intel_report.unique_cves
                result.cwe_matches = intel_report.unique_cwes
                result.mitre_techniques = intel_report.unique_mitre

                duration_ms = result.intel_duration * 1000
                logger.info("Engine '%s' completed in %.1fms", "threat_intel", duration_ms)

            except Exception as exc:
                logger.exception("threat_intel engine failed")
                result.errors.append("threat_intel: internal error")

        # ----------------------------------------------------------------
        # 4. Knowledge Graph
        # ----------------------------------------------------------------
        if self.enable_knowledge_graph:
            try:
                from .knowledge_graph import SecurityKnowledgeGraph

                kg = SecurityKnowledgeGraph()
                for f in valid:
                    kg.add_finding(f)
                kg_stats = kg.stats()
                result.knowledge_graph = {
                    "entity_count": kg_stats.get("total_nodes", 0),
                    "relationship_count": kg_stats.get("total_edges", 0),
                    "nodes_by_type": kg_stats.get("nodes_by_type", {}),
                    "edges_by_type": kg_stats.get("edges_by_type", {}),
                    "severity_distribution": kg_stats.get("severity_distribution", {}),
                }
                result.entity_count = kg_stats.get("total_nodes", 0)
                result.relationship_count = kg_stats.get("total_edges", 0)
                # Remove from enabled_engines if nothing was added
                if not result.knowledge_graph.get("entity_count"):
                    result.enabled_engines.remove("knowledge_graph")
            except Exception as exc:
                logger.exception("knowledge_graph engine failed")
                result.errors.append("knowledge_graph: internal error")

        # ----------------------------------------------------------------
        # 5. Regression Intelligence
        # ----------------------------------------------------------------
        if self.enable_regression:
            try:
                from .regression_intelligence import RegressionIntelligence

                ri = RegressionIntelligence()
                t_reg = time.monotonic()
                # Pass scan_data as current_results; gracefully handle no baseline
                try:
                    regressions = ri.detect_regression(scan_data or {})
                except Exception:
                    regressions = []
                result.regression_duration = time.monotonic() - t_reg

                if regressions:
                    result.regression_data = {
                        "regression_count": len(regressions),
                        "regressions": [
                            {
                                "description": getattr(r, "description", str(r)),
                                "severity": getattr(r, "severity", "unknown"),
                            }
                            for r in regressions[:50]
                        ],
                    }
                else:
                    result.regression_data = {"regression_count": 0, "regressions": []}

                duration_ms = result.regression_duration * 1000
                logger.info("Engine '%s' completed in %.1fms", "regression", duration_ms)

            except Exception as exc:
                logger.exception("regression engine failed")
                result.errors.append("regression: internal error")

        # ----------------------------------------------------------------
        # 6. Engineering Recommendations
        # ----------------------------------------------------------------
        if self.enable_recommendations:
            try:
                from .engineering_recommendations import get_recommender

                recommender = get_recommender()
                t_rec = time.monotonic()
                recs = recommender.get_all_recommendations()
                result.recommendations_duration = time.monotonic() - t_rec

                active_recs = [r for r in recs if not getattr(r, "dismissed", False)]
                result.recommendations = [
                    {
                        "id": getattr(r, "id", ""),
                        "title": getattr(r, "title", ""),
                        "severity": getattr(r, "severity", "info"),
                        "category": getattr(r, "category", ""),
                        "affected_files": getattr(r, "affected_files", []),
                    }
                    for r in active_recs[:50]
                ]

                duration_ms = result.recommendations_duration * 1000
                logger.info("Engine '%s' completed in %.1fms (%d active)",
                            "recommendations", duration_ms, len(active_recs))

            except Exception as exc:
                logger.exception("recommendations engine failed")
                result.errors.append("recommendations: internal error")

        # ----------------------------------------------------------------
        # 7. Composite score computation (only when engines are enabled)
        # ----------------------------------------------------------------
        if result.enabled_engines:
            self._compute_composite_scores(result, valid)

        result.pipeline_duration = time.monotonic() - t_start
        logger.info(
            "Intelligence pipeline complete",
            extra={
                "duration_ms": round(result.pipeline_duration * 1000),
                "scores": {
                    "executive_risk": result.executive_risk_score,
                    "exposure": result.exposure_score,
                    "mission_impact": result.mission_impact_score,
                    "infra_health": result.infrastructure_health_score,
                    "threat_confidence": result.threat_confidence_index,
                },
            },
        )
        return result

    # ----------------------------------------------------------------
    # Lightweight mode
    # ----------------------------------------------------------------

    def run_lightweight(
        self,
        findings: List[Any],
        scan_data: Optional[Dict[str, Any]] = None,
    ) -> IntelligenceResult:
        """Run only the AI analyst + threat intel engines (fast scan mode).

        Skips attack graph, knowledge graph, regression, and recommendations
        for maximum speed.  Useful for CI/CD pipelines and quick scans.
        """
        t_start = time.monotonic()
        result = IntelligenceResult()

        # Input validation (same as analyze)
        MAX_FINDINGS = 10000
        if len(findings) > MAX_FINDINGS:
            findings = findings[:MAX_FINDINGS]
            result.errors.append(f"input_truncated: {MAX_FINDINGS} finding limit applied")

        result.enabled_engines = ["ai_analyst", "threat_intel"]

        # Normalise findings
        valid: List[Dict[str, Any]] = []
        for f in findings:
            try:
                d = _finding_to_dict(f)
                if d and "title" in d:
                    valid.append(d)
            except Exception:
                pass

        if not valid:
            return result

        # AI Analyst
        try:
            from .ai_analyst import AIAnalystEngine
            engine = AIAnalystEngine()
            t_ai = time.monotonic()
            report = engine.analyze_scan(valid)
            result.ai_duration = time.monotonic() - t_ai
            classified_categories: Dict[str, int] = {}
            for item in report.classified:
                cls = item.get("classification", {})
                cat = cls.get("attack_category", "unknown")
                classified_categories[cat] = classified_categories.get(cat, 0) + 1
            result.classification_summary = classified_categories
            result.extended_findings = report.extended_findings
            result.attack_paths = report.attack_paths
            result.ai_analysis = report.to_dict()
        except Exception:
            result.errors.append("ai_analyst: internal error")
            result.enabled_engines.remove("ai_analyst")

        # Threat Intelligence
        try:
            from .threat_intel import ThreatIntelEngine
            engine = ThreatIntelEngine()
            t_intel = time.monotonic()
            intel_report = engine.enrich_scan(valid)
            result.intel_duration = time.monotonic() - t_intel
            result.cve_matches = intel_report.unique_cves
            result.cwe_matches = intel_report.unique_cwes
            result.mitre_techniques = intel_report.unique_mitre
        except Exception:
            result.errors.append("threat_intel: internal error")
            result.enabled_engines.remove("threat_intel")

        # Composite scores
        if result.enabled_engines:
            self._compute_composite_scores(result, valid)

        result.pipeline_duration = time.monotonic() - t_start
        return result

    # --------------------------------------------------------------------
    # Composite scoring
    # --------------------------------------------------------------------

    def _compute_composite_scores(
        self, result: IntelligenceResult, findings: List[Dict[str, Any]]
    ) -> None:
        """Derive executive-level composite scores from raw findings + engine outputs."""
        if not findings:
            return

        n = len(findings)

        # --- executive_risk_score ---
        # Weighted average of severity, boosted by count and attack chains
        total_weight = 0.0
        for f in findings:
            total_weight += _sev_val(f.get("severity", "info"))
        avg_sev = total_weight / n
        count_factor = min(n / 10.0, 2.0)  # caps at 2× for 10+ findings
        chain_boost = min(len(result.attack_chains) * 3.0, 15.0)
        raw = avg_sev * 5.0 * count_factor + chain_boost
        result.executive_risk_score = round(min(100.0, raw), 1)

        # --- exposure_score ---
        unique_assets = len({f.get("asset", "") for f in findings})
        asset_factor = min(unique_assets / 3.0, 2.0)
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        raw_exp = (critical_count * 15.0 + high_count * 8.0) * asset_factor
        result.exposure_score = round(min(100.0, raw_exp), 1)

        # --- mission_impact_score ---
        # Based on critical + high findings with exploitability data from AI analyst
        mi = 0.0
        for ef in result.extended_findings:
            sev = _sev_val(ef.get("severity", "info"))
            expl = ef.get("exploitability", 0.5)
            impact = ef.get("business_impact_score", 0.5)
            mi += sev * expl * impact
        if mi > 0:
            result.mission_impact_score = round(min(100.0, mi * 1.5), 1)
        else:
            # Fallback: simple severity-based estimate
            medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
            result.mission_impact_score = round(
                min(100.0, critical_count * 20.0 + high_count * 10.0 + medium_count * 3.0),
                1,
            )

        # --- infrastructure_health_score ---
        # Inverse of risk — higher is better. 100 = perfectly healthy.
        result.infrastructure_health_score = round(
            max(0.0, 100.0 - result.executive_risk_score), 1
        )

        # --- threat_confidence_index ---
        intel_signals = 0
        total_signals = 0
        if result.cve_matches:
            intel_signals += len(result.cve_matches)
        if result.mitre_techniques:
            intel_signals += len(result.mitre_techniques)
        if result.attack_chains:
            intel_signals += len(result.attack_chains) * 2
        total_signals = intel_signals + 1  # avoid div-by-zero
        result.threat_confidence_index = round(
            min(100.0, intel_signals / max(n, 1) * 200.0), 2
        )


# ═══════════════════════════════════════════════════════════════════════════
# Module-level convenience API
# ═══════════════════════════════════════════════════════════════════════════


_global_pipeline: Optional[IntelligencePipeline] = None


# DEAD CODE: consider removal
def run_intelligence_pipeline(
    findings: List[Any],
    *,
    enable_ai_analyst: Optional[bool] = None,
    enable_attack_graph: Optional[bool] = None,
    enable_threat_intel: Optional[bool] = None,
    enable_knowledge_graph: Optional[bool] = None,
    scan_data: Optional[Dict[str, Any]] = None,
) -> IntelligenceResult:
    """Run the global intelligence pipeline (creates one if needed).

    Parameters passed here override the global instance's settings for
    this single call.
    """
    global _global_pipeline

    if _global_pipeline is None:
        _global_pipeline = IntelligencePipeline()

    # Build keyword overrides — only pass flags that the caller specified
    kwargs: Dict[str, Any] = {"scan_data": scan_data}
    if enable_ai_analyst is not None:
        kwargs["enable_ai_analyst"] = enable_ai_analyst
    if enable_attack_graph is not None:
        kwargs["enable_attack_graph"] = enable_attack_graph
    if enable_threat_intel is not None:
        kwargs["enable_threat_intel"] = enable_threat_intel
    if enable_knowledge_graph is not None:
        kwargs["enable_knowledge_graph"] = enable_knowledge_graph

    # If any override was given we need a temporary instance
    if len(kwargs) > 1:  # more than just scan_data
        tmp = IntelligencePipeline(
            enable_ai_analyst=kwargs.get("enable_ai_analyst", _global_pipeline.enable_ai_analyst),
            enable_attack_graph=kwargs.get("enable_attack_graph", _global_pipeline.enable_attack_graph),
            enable_threat_intel=kwargs.get("enable_threat_intel", _global_pipeline.enable_threat_intel),
            enable_knowledge_graph=kwargs.get("enable_knowledge_graph", _global_pipeline.enable_knowledge_graph),
        )
        return tmp.analyze(findings, scan_data=scan_data)

    return _global_pipeline.analyze(findings, scan_data=scan_data)


# DEAD CODE: consider removal
def reset_pipeline() -> None:
    """Reset the global pipeline instance so the next call creates a fresh one."""
    global _global_pipeline
    _global_pipeline = None
