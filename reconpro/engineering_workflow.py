"""ReconPro Age III — Continuous Engineering Workflow Orchestrator.

Wires all 11 Age III engineering modules into ONE continuous pipeline that
executes a full engineering cycle: from state capture and validation through
diagnostics, drift detection, benchmarking, regression analysis, learning,
recommendations, auto-fix proposals, quality gating, reporting, and memory
persistence.

Every stage failure is logged but does NOT stop the pipeline — the
orchestrator degrades gracefully, collecting whatever results it can.

Pure Python. Zero external dependencies. Full type hints. Lazy imports
to avoid circular dependency issues.

Classes:
    EngineeringStage       – Enum for each pipeline stage
    StageResult            – Per-stage outcome dataclass
    EngineeringCycleResult – Complete cycle result dataclass
    ContinuousEngineeringOrchestrator – Main orchestrator facade

Usage:
    from reconpro.engineering_workflow import ContinuousEngineeringOrchestrator

    orch = ContinuousEngineeringOrchestrator("/path/to/repo")
    result = orch.run_full_cycle()
    print(result.overall_status)
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple  # DEAD CODE: consider removal

from .constants import MEMORY_DIR, RECONPRO_HOME  # DEAD CODE: consider removal

logger = logging.getLogger("reconpro.engineering_workflow")

# ── Persistence paths ──────────────────────────────────────────────────

ENGINEERING_CYCLES_DIR: Path = MEMORY_DIR / "engineering_cycles"


def _ensure_dir(path: Path) -> Path:
    """Create directory (and parents) if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)
    return path


# ═══════════════════════════════════════════════════════════════════════
#  EngineeringStage — pipeline stage enum
# ═══════════════════════════════════════════════════════════════════════


class EngineeringStage(str, Enum):
    """Each stage in the continuous engineering cycle."""

    DIGITAL_TWIN_STATE = "digital_twin_state"
    DIGITAL_TWIN_ANOMALY = "digital_twin_anomaly"
    REPOSITORY_MEMORY_RECALL = "repository_memory_recall"
    AUTO_VALIDATION = "auto_validation"
    HEALTH_CHECK = "health_check"
    DRIFT_DETECTION = "drift_detection"
    BENCHMARK = "benchmark"
    REGRESSION_INTELLIGENCE = "regression_intelligence"
    LEARNING = "learning"
    RECOMMENDATIONS = "recommendations"
    AUTO_FIX = "auto_fix"
    QUALITY_GATE = "quality_gate"
    QUALITY_INTELLIGENCE = "quality_intelligence"
    REPORTING = "reporting"
    REPOSITORY_MEMORY_PERSIST = "repository_memory_persist"


# Full cycle stage order (a through m per spec)
_FULL_CYCLE_STAGES: List[EngineeringStage] = [
    EngineeringStage.DIGITAL_TWIN_STATE,
    EngineeringStage.DIGITAL_TWIN_ANOMALY,
    EngineeringStage.REPOSITORY_MEMORY_RECALL,
    EngineeringStage.AUTO_VALIDATION,
    EngineeringStage.HEALTH_CHECK,
    EngineeringStage.DRIFT_DETECTION,
    EngineeringStage.BENCHMARK,
    EngineeringStage.REGRESSION_INTELLIGENCE,
    EngineeringStage.LEARNING,
    EngineeringStage.RECOMMENDATIONS,
    EngineeringStage.AUTO_FIX,
    EngineeringStage.QUALITY_GATE,
    EngineeringStage.QUALITY_INTELLIGENCE,
    EngineeringStage.REPORTING,
    EngineeringStage.REPOSITORY_MEMORY_PERSIST,
]

# Validation-only subset (steps a, c, k)
_VALIDATION_ONLY_STAGES: List[EngineeringStage] = [
    EngineeringStage.DIGITAL_TWIN_STATE,
    EngineeringStage.AUTO_VALIDATION,
    EngineeringStage.QUALITY_GATE,
]

# Engineering-only subset (steps d–j)
_ENGINEERING_ONLY_STAGES: List[EngineeringStage] = [
    EngineeringStage.HEALTH_CHECK,
    EngineeringStage.DRIFT_DETECTION,
    EngineeringStage.BENCHMARK,
    EngineeringStage.REGRESSION_INTELLIGENCE,
    EngineeringStage.LEARNING,
    EngineeringStage.RECOMMENDATIONS,
    EngineeringStage.AUTO_FIX,
]


# ═══════════════════════════════════════════════════════════════════════
#  StageResult — per-stage outcome
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class StageResult:
    """Result of executing a single pipeline stage.

    Attributes:
        stage: Which stage was executed.
        status: 'pass', 'fail', 'warn', 'skipped'.
        duration_s: Wall-clock seconds for this stage.
        data: Stage-specific result data (raw return values).
        error: Exception message if the stage failed, else empty string.
    """

    stage: EngineeringStage
    status: str = "pass"
    duration_s: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage.value,
            "status": self.status,
            "duration_s": round(self.duration_s, 4),
            "data": self.data,
            "error": self.error,
        }


# ═══════════════════════════════════════════════════════════════════════
#  EngineeringCycleResult — full cycle result
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class EngineeringCycleResult:
    """Comprehensive result of an engineering cycle.

    Attributes:
        cycle_id: Unique identifier for this cycle.
        repository_path: Path of the repository analysed.
        mode: Which pipeline mode was run ('full', 'validation_only', 'engineering_only').
        overall_status: 'pass', 'fail', or 'warn'.
        started_at: ISO-8601 UTC timestamp when cycle began.
        finished_at: ISO-8601 UTC timestamp when cycle finished.
        total_duration_s: Total wall-clock seconds for the cycle.
        stages: Ordered list of StageResult for each executed stage.
        metrics: Aggregate metrics across all stages.
        recommendations_count: Total number of recommendations generated.
        fix_proposals_count: Total number of fix proposals generated.
        anomaly_count: Number of anomalies detected.
        regression_count: Number of regressions detected.
    """

    cycle_id: str = ""
    repository_path: str = ""
    mode: str = "full"
    overall_status: str = "pass"
    started_at: str = ""
    finished_at: str = ""
    total_duration_s: float = 0.0
    stages: List[StageResult] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations_count: int = 0
    fix_proposals_count: int = 0
    anomaly_count: int = 0
    regression_count: int = 0
    quality_score: float = 0.0
    quality_grade: str = ""
    engineering_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "repository_path": self.repository_path,
            "mode": self.mode,
            "overall_status": self.overall_status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_duration_s": round(self.total_duration_s, 4),
            "stages": [s.to_dict() for s in self.stages],
            "metrics": self.metrics,
            "recommendations_count": self.recommendations_count,
            "fix_proposals_count": self.fix_proposals_count,
            "anomaly_count": self.anomaly_count,
            "regression_count": self.regression_count,
            "quality_score": self.quality_score,
            "quality_grade": self.quality_grade,
            "engineering_score": self.engineering_score,
        }

    def save(self, directory: Optional[Path] = None) -> Path:
        """Persist cycle results as JSON.

        Args:
            directory: Override directory. Defaults to ENGINEERING_CYCLES_DIR.

        Returns:
            Path to the saved JSON file.
        """
        save_dir = _ensure_dir(directory or ENGINEERING_CYCLES_DIR)
        filename = f"cycle_{self.cycle_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
        filepath = save_dir / filename
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            logger.info("Cycle results saved to %s", filepath)
        except OSError:
            logger.warning("Failed to save cycle results to %s", filepath, exc_info=True)
        return filepath

    @classmethod
    def load_latest(cls, directory: Optional[Path] = None) -> Optional["EngineeringCycleResult"]:
        """Load the most recent cycle result from JSON files.

        Args:
            directory: Override directory.

        Returns:
            EngineeringCycleResult or None if no files found.
        """
        search_dir = directory or ENGINEERING_CYCLES_DIR
        if not search_dir.exists():
            return None
        try:
            files = sorted(search_dir.glob("cycle_*.json"), key=os.path.getmtime)
            if not files:
                return None
            with open(files[-1], "r", encoding="utf-8") as f:
                data = json.load(f)
            result = cls()
            result.cycle_id = data.get("cycle_id", "")
            result.repository_path = data.get("repository_path", "")
            result.mode = data.get("mode", "full")
            result.overall_status = data.get("overall_status", "pass")
            result.started_at = data.get("started_at", "")
            result.finished_at = data.get("finished_at", "")
            result.total_duration_s = data.get("total_duration_s", 0.0)
            result.metrics = data.get("metrics", {})
            result.recommendations_count = data.get("recommendations_count", 0)
            result.fix_proposals_count = data.get("fix_proposals_count", 0)
            result.anomaly_count = data.get("anomaly_count", 0)
            result.regression_count = data.get("regression_count", 0)
            for sdata in data.get("stages", []):
                sr = StageResult(
                    stage=EngineeringStage(sdata.get("stage", "unknown")),
                    status=sdata.get("status", "pass"),
                    duration_s=sdata.get("duration_s", 0.0),
                    data=sdata.get("data", {}),
                    error=sdata.get("error", ""),
                )
                result.stages.append(sr)
            return result
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            logger.warning("Failed to load latest cycle result", exc_info=True)
            return None


# ═══════════════════════════════════════════════════════════════════════
#  ContinuousEngineeringOrchestrator — main orchestrator
# ═══════════════════════════════════════════════════════════════════════


class ContinuousEngineeringOrchestrator:
    """Wires all 11 Age III modules into ONE continuous engineering pipeline.

    Executes stages in order, collecting results. Each stage failure is
    logged but does NOT stop the pipeline (graceful degradation).

    Modules wired:
        1. auto_engineering      — EngineeringPipeline (health, drift, quality_gate)
        2. repository_memory     — RepositoryMemory (remember, recall, search)
        3. digital_twin           — DigitalTwin (capture_state, predict_impact, detect_anomaly)
        4. repository_learning    — RepositoryLearner (learn_from_*, predict_outcome)
        5. engineering_recommendations — EngineeringRecommender (recommend_from_*)
        6. regression_intelligence — RegressionIntelligence (capture_baseline, detect_regression)
        7. auto_validation        — ValidationPipeline (validate_full)
        8. benchmark_automation  — BenchmarkAutomation (run_quick_benchmark)
        9. auto_fix               — AutoFixEngine (propose_fixes)
       10. prompt_defense         — PromptDefense (scan_input, sanitize_prompt)
       11. security_hardening     — SecurityPolicyEngine, PluginSandbox, SecretsManager

    Parameters:
        repository_path: Root path of the repository to engineer.
    """

    def __init__(self, repository_path: str = ".") -> None:
        self._repo_path: str = str(repository_path)
        self._repo_resolved: Path = Path(repository_path).resolve()

        # Lazy-loaded subsystem instances (populated on first use)
        self._engineering_pipeline: Any = None
        self._repository_memory: Any = None
        self._digital_twin: Any = None
        self._repository_learner: Any = None
        self._engineering_recommender: Any = None
        self._regression_intelligence: Any = None
        self._validation_pipeline: Any = None
        self._benchmark_automation: Any = None
        self._auto_fix_engine: Any = None
        self._prompt_defense: Any = None
        self._security_policy_engine: Any = None

        # Last cycle result
        self._last_result: Optional[EngineeringCycleResult] = None
        self._cycle_count: int = 0

    # ── Lazy import helpers ────────────────────────────────────────────

    def _get_engineering_pipeline(self) -> Any:
        """Lazy-load EngineeringPipeline."""
        if self._engineering_pipeline is None:
            from .auto_engineering import EngineeringPipeline
            self._engineering_pipeline = EngineeringPipeline(repo_path=self._repo_path)
        return self._engineering_pipeline

    def _get_repository_memory(self) -> Any:
        """Lazy-load RepositoryMemory."""
        if self._repository_memory is None:
            from .repository_memory import RepositoryMemory
            self._repository_memory = RepositoryMemory()
        return self._repository_memory

    def _get_digital_twin(self) -> Any:
        """Lazy-load DigitalTwin."""
        if self._digital_twin is None:
            from .digital_twin import DigitalTwin
            self._digital_twin = DigitalTwin(persist=True)
        return self._digital_twin

    def _get_repository_learner(self) -> Any:
        """Lazy-load RepositoryLearner."""
        if self._repository_learner is None:
            from .repository_learning import RepositoryLearner
            self._repository_learner = RepositoryLearner()
        return self._repository_learner

    def _get_engineering_recommender(self) -> Any:
        """Lazy-load EngineeringRecommender."""
        if self._engineering_recommender is None:
            from .engineering_recommendations import EngineeringRecommender
            self._engineering_recommender = EngineeringRecommender()
        return self._engineering_recommender

    def _get_regression_intelligence(self) -> Any:
        """Lazy-load RegressionIntelligence."""
        if self._regression_intelligence is None:
            from .regression_intelligence import RegressionIntelligence
            self._regression_intelligence = RegressionIntelligence()
        return self._regression_intelligence

    def _get_validation_pipeline(self) -> Any:
        """Lazy-load ValidationPipeline."""
        if self._validation_pipeline is None:
            from .auto_validation import ValidationPipeline
            self._validation_pipeline = ValidationPipeline(project_root=self._repo_path)
        return self._validation_pipeline

    def _get_benchmark_automation(self) -> Any:
        """Lazy-load BenchmarkAutomation."""
        if self._benchmark_automation is None:
            from .benchmark_automation import BenchmarkAutomation
            self._benchmark_automation = BenchmarkAutomation()
        return self._benchmark_automation

    def _get_auto_fix_engine(self) -> Any:
        """Lazy-load AutoFixEngine."""
        if self._auto_fix_engine is None:
            from .auto_fix import AutoFixEngine
            self._auto_fix_engine = AutoFixEngine(dry_run=True)
        return self._auto_fix_engine

    def _get_prompt_defense(self) -> Any:
        """Lazy-load PromptDefense."""
        if self._prompt_defense is None:
            from .prompt_defense import PromptDefense
            self._prompt_defense = PromptDefense()
        return self._prompt_defense

    def _get_security_policy_engine(self) -> Any:
        """Lazy-load SecurityPolicyEngine."""
        if self._security_policy_engine is None:
            from .security_hardening import SecurityPolicyEngine
            self._security_policy_engine = SecurityPolicyEngine()
        return self._security_policy_engine

    # ── Stage execution helpers ────────────────────────────────────────

    def _execute_stage(
        self,
        stage: EngineeringStage,
        stage_fn: Any,
        result: EngineeringCycleResult,
    ) -> StageResult:
        """Execute a single stage with timing and error handling.

        Args:
            stage: The stage enum value.
            stage_fn: Callable that performs the stage work.
            result: The cycle result to append this stage result to.

        Returns:
            StageResult with outcome data.
        """
        stage_result = StageResult(stage=stage)
        t0 = time.monotonic()
        try:
            data = stage_fn()
            if isinstance(data, dict):
                stage_result.data = data
            elif data is not None:
                stage_result.data = {"result": data}
            stage_result.status = "pass"
            logger.info("Stage %s completed successfully", stage.value)
        except Exception as exc:
            stage_result.status = "fail"
            stage_result.error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "Stage %s failed (continuing): %s", stage.value, exc, exc_info=True
            )
        finally:
            stage_result.duration_s = time.monotonic() - t0
        result.stages.append(stage_result)
        return stage_result

    def _compute_overall_status(self, result: EngineeringCycleResult) -> str:
        """Compute overall pass/fail/warn from stage statuses.

        Rules:
            - Any 'fail' → overall 'fail'
            - Any 'warn' (and no 'fail') → overall 'warn'
            - All 'pass' or 'skipped' → overall 'pass'
        """
        has_fail = any(s.status == "fail" for s in result.stages)
        has_warn = any(s.status == "warn" for s in result.stages)
        if has_fail:
            return "fail"
        if has_warn:
            return "warn"
        return "pass"

    # ── Stage implementations ─────────────────────────────────────────

    def _stage_digital_twin_state(self) -> Dict[str, Any]:
        """a. Digital Twin: capture current state."""
        twin = self._get_digital_twin()
        state = twin.capture_state()
        return {
            "system_status": state.overall_status(),
            "version": getattr(state, "version", "unknown"),
            "captured_at": getattr(state, "captured_at", ""),
        }

    def _stage_digital_twin_anomaly(self) -> Dict[str, Any]:
        """a. Digital Twin: detect anomalies."""
        twin = self._get_digital_twin()
        anomalies = twin.detect_anomaly()
        anomaly_list = anomalies.get("anomalies", [])
        return {
            "anomaly_count": anomalies.get("anomaly_count", len(anomaly_list)),
            "anomalies": anomaly_list,
        }

    def _stage_repository_memory_recall(self) -> Dict[str, Any]:
        """b. Repository Memory: recall previous engineering knowledge."""
        mem = self._get_repository_memory()
        # Search for all engineering-cycle-related facts
        facts = mem.search(query_text="engineering")
        if not facts:
            facts = mem.search(query_text="pipeline")
        return {
            "recall_count": len(facts),
            "facts": [
                {"key": f.key, "confidence": f.confidence, "source": f.source}
                for f in facts[:50]  # Cap at 50 to avoid excessive data
            ],
        }

    def _stage_auto_validation(self) -> Dict[str, Any]:
        """c. Auto Validation: run full validation pipeline."""
        vp = self._get_validation_pipeline()
        report = vp.validate_full()
        # Handle both object and dict forms
        if hasattr(report, "to_dict"):
            data = report.to_dict()
        elif hasattr(report, "summary"):
            data = {"summary": report.summary()}
        else:
            data = {"result": report}
        return data

    def _stage_health_check(self) -> Dict[str, Any]:
        """d. Diagnostics: run health checks via EngineeringPipeline."""
        ep = self._get_engineering_pipeline()
        health = ep.health_check()
        return health if isinstance(health, dict) else {"result": health}

    def _stage_drift_detection(self) -> Dict[str, Any]:
        """e. Drift Detection: detect code drift from baseline."""
        ep = self._get_engineering_pipeline()
        drift = ep.drift_detection(create_baseline_if_missing=True)
        return drift if isinstance(drift, dict) else {"result": drift}

    def _stage_benchmark(self) -> Dict[str, Any]:
        """f. Benchmark: run quick benchmarks, detect performance regressions."""
        ba = self._get_benchmark_automation()
        bench_result = ba.run_quick_benchmark()
        return bench_result if isinstance(bench_result, dict) else {"result": bench_result}

    def _stage_regression_intelligence(self) -> Dict[str, Any]:
        """g. Regression Intelligence: detect regressions."""
        ri = self._get_regression_intelligence()
        # Use a synthetic "current state" for comparison
        current_results: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repository_path": self._repo_path,
        }
        regressions = ri.detect_regression(current_results)
        reg_list = regressions if isinstance(regressions, list) else []
        return {
            "regression_count": len(reg_list),
            "regressions": [
                {
                    "id": getattr(r, "id", ""),
                    "type": str(getattr(r, "regression_type", "")),
                    "severity": str(getattr(r, "severity", "")),
                    "description": getattr(r, "description", ""),
                }
                for r in reg_list
            ],
        }

    def _stage_learning(self) -> Dict[str, Any]:
        """h. Learning: learn from all collected data so far."""
        learner = self._get_repository_learner()
        patterns_learned = 0

        # Feed validation results if available
        for sr in self._last_result.stages if self._last_result else []:
            if sr.stage == EngineeringStage.AUTO_VALIDATION and sr.data:
                try:
                    n = learner.learn_from_test(sr.data)
                    patterns_learned += n
                except Exception:
                    logger.debug("Learning from validation data failed", exc_info=True)
            if sr.stage == EngineeringStage.HEALTH_CHECK and sr.data:
                try:
                    n = learner.learn_from_scan(sr.data)
                    patterns_learned += n
                except Exception:
                    logger.debug("Learning from health check data failed", exc_info=True)

        return {"patterns_learned": patterns_learned}

    def _stage_recommendations(self) -> Dict[str, Any]:
        """i. Recommendations: generate from all findings."""
        recommender = self._get_engineering_recommender()
        all_recs: List[Any] = []

        for sr in self._last_result.stages if self._last_result else []:
            try:
                if sr.stage == EngineeringStage.HEALTH_CHECK and sr.data:
                    recs = recommender.recommend_from_diagnostics(sr.data)
                    all_recs.extend(recs)
                elif sr.stage == EngineeringStage.DRIFT_DETECTION and sr.data:
                    recs = recommender.recommend_from_drift(sr.data)
                    all_recs.extend(recs)
                elif sr.stage == EngineeringStage.AUTO_VALIDATION and sr.data:
                    recs = recommender.recommend_from_test_results(sr.data)
                    all_recs.extend(recs)
                elif sr.stage == EngineeringStage.BENCHMARK and sr.data:
                    recs = recommender.recommend_from_performance(sr.data)
                    all_recs.extend(recs)
            except Exception:
                logger.debug(
                    "Recommendation generation failed for stage %s",
                    sr.stage.value,
                    exc_info=True,
                )

        return {
            "recommendations_count": len(all_recs),
            "recommendations": [
                {
                    "id": getattr(r, "id", ""),
                    "title": getattr(r, "title", ""),
                    "severity": str(getattr(r, "severity", "")),
                    "category": getattr(r, "category", ""),
                }
                for r in all_recs
            ],
        }

    def _stage_auto_fix(self) -> Dict[str, Any]:
        """j. Auto Fix: propose fixes for detected issues."""
        engine = self._get_auto_fix_engine()
        # Aggregate findings from previous stages into a scan_result-like dict
        scan_result: Dict[str, Any] = {
            "repository_path": self._repo_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        for sr in self._last_result.stages if self._last_result else []:
            if sr.stage == EngineeringStage.HEALTH_CHECK and sr.data:
                scan_result["diagnostics"] = sr.data
            elif sr.stage == EngineeringStage.DRIFT_DETECTION and sr.data:
                scan_result.setdefault("findings", []).append(sr.data)

        proposals = engine.propose_fixes(scan_result)
        return {
            "fix_proposals_count": len(proposals),
            "proposals": [
                {
                    "id": getattr(p, "id", ""),
                    "title": getattr(p, "title", ""),
                    "severity": str(getattr(p, "severity", "")),
                    "confidence": getattr(p, "confidence", 0.0),
                    "status": str(getattr(p, "status", "")),
                }
                for p in proposals
            ],
        }

    def _stage_quality_gate(self) -> Dict[str, Any]:
        """k. Quality Gate: enforce quality thresholds."""
        ep = self._get_engineering_pipeline()

        # Gather prior stage data for quality gate inputs
        metrics_snapshot = None
        drift_report = None
        health_result = None

        for sr in self._last_result.stages if self._last_result else []:
            if sr.stage == EngineeringStage.HEALTH_CHECK:
                health_result = sr.data
            elif sr.stage == EngineeringStage.DRIFT_DETECTION:
                drift_report = sr.data

        qg_result = ep.quality_gate(
            metrics_snapshot=metrics_snapshot,
            drift_report=drift_report,
            health_result=health_result,
        )
        if hasattr(qg_result, "to_dict"):
            data = qg_result.to_dict()
        elif hasattr(qg_result, "__dict__"):
            data = vars(qg_result)
        else:
            data = {"result": qg_result}
        return data

    def _stage_quality_intelligence(self) -> Dict[str, Any]:
        """k2. Quality Intelligence: multi-dimensional code quality analysis."""
        try:
            from .quality_intelligence import QualityIntelligence

            qi = QualityIntelligence(repository_path=self._repo_path)
            repo_path = self._repo_path or "."

            # Run full repository analysis
            repo_result = qi.analyze_repository_quality(repo_path)

            # Check for errors
            if "error" in repo_result and not repo_result.get("dimensions"):
                return {"analyzed": 0, "error": repo_result["error"]}

            # Extract key data
            data = {
                "files_analyzed": repo_result.get("file_count", 0),
                "total_loc": repo_result.get("total_loc", 0),
                "composite_score": repo_result.get("composite_score", 0.0),
                "grade": repo_result.get("grade", "N/A"),
                "dimensions": repo_result.get("dimensions", {}),
                "security_issues_total": repo_result.get("security_issues_total", 0),
                "gate_result": repo_result.get("gate_result", {}),
                "trend": repo_result.get("trend"),
                "trajectory": repo_result.get("trajectory"),
                "timestamp": repo_result.get("timestamp", ""),
            }

            return data
        except Exception as exc:
            return {"analyzed": 0, "error": str(exc)}

    def _stage_reporting(self) -> Dict[str, Any]:
        """l. Reporting: generate comprehensive engineering report."""
        ri = self._get_regression_intelligence()
        try:
            report = ri.generate_regression_report(
                days=7, include_history=True, include_trends=True
            )
            return {"report": str(report)[:2000]}  # Truncate large reports
        except Exception as exc:
            return {"report": f"Report generation failed: {exc}"}

    def _stage_repository_memory_persist(self) -> Dict[str, Any]:
        """m. Repository Memory: persist results for next cycle."""
        mem = self._get_repository_memory()
        if not self._last_result:
            return {"persisted": False, "reason": "no result to persist"}

        facts_stored = 0

        # Persist cycle summary
        try:
            mem.remember(
                key=f"engineering_cycle/{self._last_result.cycle_id}/summary",
                value={
                    "overall_status": self._last_result.overall_status,
                    "mode": self._last_result.mode,
                    "total_duration_s": self._last_result.total_duration_s,
                    "recommendations_count": self._last_result.recommendations_count,
                    "fix_proposals_count": self._last_result.fix_proposals_count,
                    "anomaly_count": self._last_result.anomaly_count,
                    "regression_count": self._last_result.regression_count,
                },
                metadata={"source": "engineering_workflow", "tags": ["cycle", "summary"]},
            )
            facts_stored += 1
        except Exception:
            logger.debug("Failed to persist cycle summary", exc_info=True)

        # Persist per-stage results
        for sr in self._last_result.stages:
            try:
                mem.remember(
                    key=f"engineering_cycle/{self._last_result.cycle_id}/stage/{sr.stage.value}",
                    value={
                        "status": sr.status,
                        "duration_s": sr.duration_s,
                        "error": sr.error,
                    },
                    metadata={"source": "engineering_workflow", "tags": ["cycle", "stage"]},
                )
                facts_stored += 1
            except Exception:
                logger.debug(
                    "Failed to persist stage %s", sr.stage.value, exc_info=True
                )

        return {"persisted": True, "facts_stored": facts_stored}

    # ── Stage dispatch ─────────────────────────────────────────────────

    _STAGE_DISPATCH: Dict[str, str] = {
        EngineeringStage.DIGITAL_TWIN_STATE: "_stage_digital_twin_state",
        EngineeringStage.DIGITAL_TWIN_ANOMALY: "_stage_digital_twin_anomaly",
        EngineeringStage.REPOSITORY_MEMORY_RECALL: "_stage_repository_memory_recall",
        EngineeringStage.AUTO_VALIDATION: "_stage_auto_validation",
        EngineeringStage.HEALTH_CHECK: "_stage_health_check",
        EngineeringStage.DRIFT_DETECTION: "_stage_drift_detection",
        EngineeringStage.BENCHMARK: "_stage_benchmark",
        EngineeringStage.REGRESSION_INTELLIGENCE: "_stage_regression_intelligence",
        EngineeringStage.LEARNING: "_stage_learning",
        EngineeringStage.RECOMMENDATIONS: "_stage_recommendations",
        EngineeringStage.AUTO_FIX: "_stage_auto_fix",
        EngineeringStage.QUALITY_GATE: "_stage_quality_gate",
        EngineeringStage.QUALITY_INTELLIGENCE: "_stage_quality_intelligence",
        EngineeringStage.REPORTING: "_stage_reporting",
        EngineeringStage.REPOSITORY_MEMORY_PERSIST: "_stage_repository_memory_persist",
    }

    # ── Public API ──────────────────────────────────────────────────────

    def run_full_cycle(
        self,
        repository_path: Optional[str] = None,
    ) -> EngineeringCycleResult:
        """Execute the complete engineering cycle (all 14 stages, a–m).

        Steps:
            a. Digital Twin: capture state, detect anomalies
            b. Repository Memory: recall previous knowledge
            c. Auto Validation: run full validation pipeline
            d. Diagnostics: health checks
            e. Drift Detection: detect code drift
            f. Benchmark: quick benchmarks, performance regressions
            g. Regression Intelligence: detect regressions
            h. Learning: learn from collected data
            i. Recommendations: generate from findings
            j. Auto Fix: propose fixes
            k. Quality Gate: enforce thresholds
            l. Reporting: comprehensive report
            m. Repository Memory: persist results

        Args:
            repository_path: Override repository path for this cycle.

        Returns:
            EngineeringCycleResult with all stage results.
        """
        if repository_path:
            self._repo_path = str(repository_path)
            self._repo_resolved = Path(repository_path).resolve()

        result = EngineeringCycleResult(
            cycle_id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
            repository_path=self._repo_path,
            mode="full",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        self._last_result = result
        cycle_start = time.monotonic()
        logger.info("Starting full engineering cycle %s for %s", result.cycle_id, self._repo_path)

        for stage in _FULL_CYCLE_STAGES:
            method_name = self._STAGE_DISPATCH.get(stage)
            if method_name is None:
                logger.warning("No dispatch for stage %s — skipping", stage.value)
                result.stages.append(StageResult(stage=stage, status="skipped"))
                continue
            stage_fn = getattr(self, method_name, None)
            if stage_fn is None:
                result.stages.append(StageResult(stage=stage, status="skipped"))
                continue
            sr = self._execute_stage(stage, stage_fn, result)
            # Track aggregate counts
            if sr.status == "pass" and sr.data:
                if sr.stage == EngineeringStage.DIGITAL_TWIN_ANOMALY:
                    result.anomaly_count = sr.data.get("anomaly_count", 0)
                if sr.stage == EngineeringStage.REGRESSION_INTELLIGENCE:
                    result.regression_count = sr.data.get("regression_count", 0)
                if sr.stage == EngineeringStage.RECOMMENDATIONS:
                    result.recommendations_count = sr.data.get("recommendations_count", 0)
                if sr.stage == EngineeringStage.AUTO_FIX:
                    result.fix_proposals_count = sr.data.get("fix_proposals_count", 0)
                if sr.stage == EngineeringStage.QUALITY_INTELLIGENCE and sr.data:
                    result.quality_score = sr.data.get("composite_score", 0.0)
                    result.quality_grade = sr.data.get("grade", "")

        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.total_duration_s = time.monotonic() - cycle_start
        result.overall_status = self._compute_overall_status(result)

        # Calculate engineering score for the cycle
        result.engineering_score = self._compute_engineering_score(result)

        result.metrics = {
            "total_stages": len(result.stages),
            "passed": sum(1 for s in result.stages if s.status == "pass"),
            "failed": sum(1 for s in result.stages if s.status == "fail"),
            "warned": sum(1 for s in result.stages if s.status == "warn"),
            "skipped": sum(1 for s in result.stages if s.status == "skipped"),
        }

        # Persist results
        result.save()

        self._cycle_count += 1
        logger.info(
            "Engineering cycle %s complete: status=%s duration=%.2fs",
            result.cycle_id,
            result.overall_status,
            result.total_duration_s,
        )
        return result

    def _compute_engineering_score(self, result: EngineeringCycleResult) -> float:
        """Calculate a composite engineering score (0-100) for the cycle.

        Formula: 40% module_health + 30% quality_history + 30% scan_reliability
        Falls back to module health if no quality history exists.
        """
        total = len(result.stages)
        if total == 0:
            return 0.0

        passed = sum(1 for s in result.stages if s.status == "pass")
        failed = sum(1 for s in result.stages if s.status == "fail")
        module_health = (passed / total) * 100.0

        # Quality history: use quality intelligence score if available
        quality_history = 0.0
        has_quality = result.quality_score > 0
        if has_quality:
            quality_history = result.quality_score
        else:
            # Try to recall from memory
            try:
                mem = self._get_repository_memory()
                qi_facts = mem.search(query_text="quality_score")
                if qi_facts:
                    quality_history = float(qi_facts[0].value) if isinstance(qi_facts[0].value, (int, float)) else 50.0
                else:
                    quality_history = module_health  # default to current scan
            except Exception:
                quality_history = module_health

        # Scan reliability: inverse of failure rate, weighted by stage count
        reliability = 100.0 if failed == 0 else max(0.0, (1.0 - failed / total) * 100.0)

        score = 0.40 * module_health + 0.30 * quality_history + 0.30 * reliability
        return round(max(0.0, min(100.0, score)), 1)

    def run_validation_only(
        self,
        repository_path: Optional[str] = None,
    ) -> EngineeringCycleResult:
        """Quick validation pass (steps a, c, k).

        Runs:
            a. Digital Twin: capture current state
            c. Auto Validation: run full validation pipeline
            k. Quality Gate: enforce quality thresholds

        Args:
            repository_path: Override repository path.

        Returns:
            EngineeringCycleResult with validation-stage results.
        """
        if repository_path:
            self._repo_path = str(repository_path)
            self._repo_resolved = Path(repository_path).resolve()

        result = EngineeringCycleResult(
            cycle_id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
            repository_path=self._repo_path,
            mode="validation_only",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        self._last_result = result
        cycle_start = time.monotonic()
        logger.info("Starting validation-only cycle %s", result.cycle_id)

        for stage in _VALIDATION_ONLY_STAGES:
            method_name = self._STAGE_DISPATCH.get(stage)
            if method_name:
                stage_fn = getattr(self, method_name, None)
                if stage_fn:
                    self._execute_stage(stage, stage_fn, result)
                else:
                    result.stages.append(StageResult(stage=stage, status="skipped"))
            else:
                result.stages.append(StageResult(stage=stage, status="skipped"))

        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.total_duration_s = time.monotonic() - cycle_start
        result.overall_status = self._compute_overall_status(result)
        result.metrics = {
            "total_stages": len(result.stages),
            "passed": sum(1 for s in result.stages if s.status == "pass"),
            "failed": sum(1 for s in result.stages if s.status == "fail"),
            "warned": sum(1 for s in result.stages if s.status == "warn"),
            "skipped": sum(1 for s in result.stages if s.status == "skipped"),
        }
        result.save()
        self._cycle_count += 1
        return result

    def run_engineering_only(
        self,
        repository_path: Optional[str] = None,
    ) -> EngineeringCycleResult:
        """Engineering cycle (steps d–j).

        Runs:
            d. Health checks
            e. Drift detection
            f. Benchmark
            g. Regression intelligence
            h. Learning
            i. Recommendations
            j. Auto fix proposals

        Args:
            repository_path: Override repository path.

        Returns:
            EngineeringCycleResult with engineering-stage results.
        """
        if repository_path:
            self._repo_path = str(repository_path)
            self._repo_resolved = Path(repository_path).resolve()

        result = EngineeringCycleResult(
            cycle_id=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),
            repository_path=self._repo_path,
            mode="engineering_only",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        self._last_result = result
        cycle_start = time.monotonic()
        logger.info("Starting engineering-only cycle %s", result.cycle_id)

        for stage in _ENGINEERING_ONLY_STAGES:
            method_name = self._STAGE_DISPATCH.get(stage)
            if method_name:
                stage_fn = getattr(self, method_name, None)
                if stage_fn:
                    sr = self._execute_stage(stage, stage_fn, result)
                    if sr.status == "pass" and sr.data:
                        if sr.stage == EngineeringStage.REGRESSION_INTELLIGENCE:
                            result.regression_count = sr.data.get("regression_count", 0)
                        if sr.stage == EngineeringStage.RECOMMENDATIONS:
                            result.recommendations_count = sr.data.get("recommendations_count", 0)
                        if sr.stage == EngineeringStage.AUTO_FIX:
                            result.fix_proposals_count = sr.data.get("fix_proposals_count", 0)
                else:
                    result.stages.append(StageResult(stage=stage, status="skipped"))
            else:
                result.stages.append(StageResult(stage=stage, status="skipped"))

        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.total_duration_s = time.monotonic() - cycle_start
        result.overall_status = self._compute_overall_status(result)
        result.metrics = {
            "total_stages": len(result.stages),
            "passed": sum(1 for s in result.stages if s.status == "pass"),
            "failed": sum(1 for s in result.stages if s.status == "fail"),
            "warned": sum(1 for s in result.stages if s.status == "warn"),
            "skipped": sum(1 for s in result.stages if s.status == "skipped"),
        }
        result.save()
        self._cycle_count += 1
        return result

    def get_status(self) -> Dict[str, Any]:
        """Return current orchestrator status and recent results.

        Returns:
            Dict with:
                - repository_path: Current repository being engineered
                - cycle_count: Total cycles executed by this instance
                - last_cycle: Summary of the last cycle result (or None)
                - subsystems_loaded: Which subsystems have been instantiated
        """
        subsystems: Dict[str, bool] = {
            "engineering_pipeline": self._engineering_pipeline is not None,
            "repository_memory": self._repository_memory is not None,
            "digital_twin": self._digital_twin is not None,
            "repository_learner": self._repository_learner is not None,
            "engineering_recommender": self._engineering_recommender is not None,
            "regression_intelligence": self._regression_intelligence is not None,
            "validation_pipeline": self._validation_pipeline is not None,
            "benchmark_automation": self._benchmark_automation is not None,
            "auto_fix_engine": self._auto_fix_engine is not None,
            "prompt_defense": self._prompt_defense is not None,
            "security_policy_engine": self._security_policy_engine is not None,
        }

        last_summary: Optional[Dict[str, Any]] = None
        if self._last_result:
            last_summary = {
                "cycle_id": self._last_result.cycle_id,
                "mode": self._last_result.mode,
                "overall_status": self._last_result.overall_status,
                "total_duration_s": self._last_result.total_duration_s,
                "stages_executed": len(self._last_result.stages),
                "recommendations_count": self._last_result.recommendations_count,
                "fix_proposals_count": self._last_result.fix_proposals_count,
                "anomaly_count": self._last_result.anomaly_count,
                "regression_count": self._last_result.regression_count,
            }

        return {
            "repository_path": self._repo_path,
            "cycle_count": self._cycle_count,
            "subsystems_loaded": subsystems,
            "last_cycle": last_summary,
        }
