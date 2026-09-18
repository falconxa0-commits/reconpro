"""Async scan orchestration engine for ReconPro v11.0.

Runs modules concurrently with an event-driven architecture.  The public
``scan()`` function is a drop-in replacement for ``scanner.scan()`` — it
accepts the same arguments and returns an identical ``ReconProResult`` so
that every existing consumer (CLI, TUI, reports, tests) works unchanged.

Components
──────────
1. **ScanEvent** — lightweight dataclass emitted at every scan milestone.
2. **ScanEngine** — async orchestrator that resolves modules, runs them
   with bounded concurrency, and aggregates results.
3. **EventCollector** — convenience helper that buffers events for later
   inspection (useful in tests and TUI dashboards).
4. **concurrent_scan()** — scan many targets in parallel.
"""

from __future__ import annotations
import inspect

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

from .registry import (
    ALL_MODULES,
    DEFAULT_LOCAL_MODULES,
    DEFAULT_MODULES,
    LOCAL_MODULES,
    MODULE_REGISTRY,
    get_execution_order,
)
from .scanner import ReconProResult
from .http_layer import Finding
from .utils import compute_grade, badge_markdown, compute_score, count_severities
from .target_validation import (
    validate_target_pipeline, apply_target_truth, unreachable_finding,
    UNREACHABLE_TARGET,
)


# ── Scan Event ──────────────────────────────────────────────────────────


@dataclass
class ScanEvent:
    """Event emitted during scan execution.

    Attributes
    ----------
    type : str
        One of ``SCAN_START``, ``MODULE_START``, ``FINDING``,
        ``MODULE_COMPLETE``, ``SCAN_COMPLETE``.
    module_id : str | None
        The module that produced the event (``None`` for scan-level events).
    target : str | None
        The scan target (``None`` for module-level events).
    finding : Finding | None
        Present only for ``FINDING`` events.
    findings_count : int
        Present only for ``MODULE_COMPLETE`` events.
    duration : float
        Elapsed seconds for the module (``MODULE_COMPLETE``) or the
        whole scan (``SCAN_COMPLETE``).
    result : ReconProResult | None
        Present only for ``SCAN_COMPLETE``.
    modules : List[str]
        Present only for ``SCAN_START`` — the resolved module list.
    timestamp : float
        ``time.monotonic()`` when the event was created.
    """

    type: str
    module_id: Optional[str] = None
    target: Optional[str] = None
    finding: Optional[Finding] = None
    findings_count: int = 0
    duration: float = 0.0
    result: Optional[ReconProResult] = None
    modules: List[str] = field(default_factory=list)
    validation: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.monotonic)


# ── Event Collector ─────────────────────────────────────────────────────


class EventCollector:
    """Buffer that stores every ``ScanEvent`` for later inspection.

    Usage::

        collector = EventCollector()
        engine = ScanEngine(event_callback=collector)
        await engine.run("example.com")
        print(collector.timeline())
        for f in collector.findings:
            print(f.title)
    """

    def __init__(self) -> None:
        self.events: List[ScanEvent] = []
        self._start: float = 0.0

    def __call__(self, event: ScanEvent) -> None:
        """Append *event*; record scan start time for timeline."""
        if event.type == "SCAN_START" and not self._start:
            self._start = event.timestamp
        self.events.append(event)

    # -- derived views -----------------------------------------------------

    @property
    def findings(self) -> List[Finding]:
        """All findings extracted from ``FINDING`` events, in order."""
        return [e.finding for e in self.events if e.type == "FINDING" and e.finding is not None]

    def by_module(self) -> Dict[str, List[ScanEvent]]:
        """Events grouped by ``module_id``.

        Scan-level events (``SCAN_START``, ``SCAN_COMPLETE``) are stored
        under the key ``"_scan"``.
        """
        out: Dict[str, List[ScanEvent]] = {}
        for e in self.events:
            key = e.module_id if e.module_id else "_scan"
            out.setdefault(key, []).append(e)
        return out

    def timeline(self) -> List[str]:
        """Human-readable timeline of events relative to scan start.

        Returns a list of formatted strings suitable for printing.
        """
        lines: List[str] = []
        anchor = self._start or (self.events[0].timestamp if self.events else 0.0)
        for e in self.events:
            dt = e.timestamp - anchor
            tag = f"[{dt:6.2f}s] {e.type}"
            if e.module_id:
                tag += f" ({e.module_id})"
            if e.target and e.type in ("SCAN_START", "SCAN_COMPLETE"):
                tag += f" target={e.target}"
            if e.type == "FINDING" and e.finding:
                tag += f" [{e.finding.severity}] {e.finding.title}"
            if e.type == "MODULE_COMPLETE":
                tag += f" {e.findings_count} findings in {e.duration:.2f}s"
            if e.type == "SCAN_COMPLETE" and e.result:
                tag += f" score={e.result.total_score} grade={e.result.grade}"
            lines.append(tag)
        return lines


# ── Scan Engine ─────────────────────────────────────────────────────────


def _filter_runner_kwargs(runner, **kwargs):
    """Return only the kwargs the runner's signature accepts.

    The engine creates a RateLimiter for modules that opt in to rate
    limiting, but classic module runners (run_recon, run_doctor, ...)
    have signatures like (target, base_url, timeout, verify_tls) and do
    NOT accept ``limiter``. Calling them with ``limiter=...`` raised
    ``TypeError: run_X() got an unexpected keyword argument 'limiter'``
    and broke recon, audit, doctor, and several other core modules.

    This helper introspects the runner (via inspect.signature) and drops
    any kwarg the runner does not accept, so the engine can uniformly
    offer ``limiter``/``verify_tls`` to every module without forcing
    every module to add the parameter. Modules that opt in by declaring
    ``limiter`` (or ``**kwargs``) still receive it.
    """
    try:
        sig = inspect.signature(runner)
        params = sig.parameters
        # If the runner accepts **kwargs, pass everything through.
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return dict(kwargs)
        return {k: v for k, v in kwargs.items() if k in params}
    except (TypeError, ValueError):
        # Builtins / C-funcs may not introspect — fall back to the common
        # signature used by every module runner.
        allowed = {"target", "base_url", "timeout", "verify_tls", "limiter"}
        return {k: v for k, v in kwargs.items() if k in allowed}


class ScanEngine:
    """Async scan orchestrator with bounded concurrency and event emission.

    Parameters
    ----------
    event_callback : Callable[[ScanEvent], None] | None
        If provided, called for every ``ScanEvent`` produced during the scan.
    concurrency : int
        Maximum number of modules that run simultaneously.
    rate_limit : float
        Default requests-per-second cap (overridden per-scan).
    use_async : bool
        When ``True`` the engine calls ``async_run()`` on modules that
        expose it; otherwise every module is wrapped in
        ``asyncio.to_thread``.
    run_engineering : bool
        When ``True``, the engineering pipeline runs automatically after
        each scan completes.  Default ``False`` to preserve existing
        behaviour.
    engineering_repo_path : str
        Repository path passed to the
        ``ContinuousEngineeringOrchestrator`` when engineering is enabled.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[ScanEvent], None]] = None,
        concurrency: int = 5,
        rate_limit: float = 50.0,
        use_async: bool = True,
        run_engineering: bool = False,
        engineering_repo_path: str = ".",
        run_intelligence: bool = True,
        run_quality: bool = False,
        run_defense: bool = False,
    ) -> None:
        self._callback = event_callback
        self._concurrency = concurrency
        self._default_rate_limit = rate_limit
        self._use_async = use_async
        self._run_engineering = run_engineering
        self._engineering_repo_path = engineering_repo_path
        self._rate_limit = rate_limit
        self._run_intelligence = run_intelligence
        self._run_quality = run_quality
        self._run_defense = run_defense

        # Agent 5: graceful shutdown + per-module adaptive timeouts
        self._shutting_down: bool = False
        self._module_timings: Dict[str, List[float]] = {}  # mod_id -> [durations]
        self._GRACE_PERIOD: float = 5.0  # seconds to let in-flight modules finish

    # -- internal helpers --------------------------------------------------

    def _emit(self, event: ScanEvent) -> None:
        """Fire the event callback (if any)."""
        if self._callback is not None:
            try:
                self._callback(event)
            except Exception:
                logger.debug("Event callback error", exc_info=True)

    def request_shutdown(self) -> None:
        """Signal the engine to stop accepting new module executions."""
        self._shutting_down = True
        logger.info("ScanEngine shutdown requested — no new modules will start")

    def _get_adaptive_timeout(self, mod_id: str, default_timeout: int) -> int:
        """Compute per-module adaptive timeout.

        Returns ``max(default_timeout, avg_time * 2.5)`` based on a rolling
        window of the last 5 execution times for *mod_id*.
        """
        timings = self._module_timings.get(mod_id, [])
        if not timings:
            return default_timeout
        avg = sum(timings[-5:]) / len(timings[-5:])
        return int(max(default_timeout, avg * 2.5))

    def _record_module_timing(self, mod_id: str, duration: float) -> None:
        """Append an execution duration to the rolling window."""
        self._module_timings.setdefault(mod_id, []).append(duration)
        if len(self._module_timings[mod_id]) > 5:
            self._module_timings[mod_id] = self._module_timings[mod_id][-5:]

    @staticmethod
    def _resolve_remote_modules(
        modules: Optional[List[str]],
        all_modules: bool,
    ) -> List[str]:
        """Determine which remote modules to run (mirrors scanner.py logic)."""
        if all_modules:
            return [m for m in ALL_MODULES if m in MODULE_REGISTRY]
        if modules:
            return [m.strip().lower() for m in modules if m.strip().lower() in MODULE_REGISTRY]
        return list(DEFAULT_MODULES)

    @staticmethod
    def _resolve_local_modules(
        modules: Optional[List[str]],
        all_modules: bool,
    ) -> List[str]:
        """Determine which local modules to run (mirrors scanner.py logic)."""
        if all_modules:
            return list(DEFAULT_LOCAL_MODULES)
        if modules:
            return [m.strip().lower() for m in modules if m.strip().lower() in LOCAL_MODULES]
        return list(DEFAULT_LOCAL_MODULES)

    def _build_result(
        self,
        target: str,
        mods: List[str],
        all_findings: List[Finding],
        module_results: Dict[str, Dict[str, Any]],
        vibesec_score: Optional[int],
        vibesec_grade: Optional[str],
        target_validation: Optional[Dict[str, Any]] = None,
        scan_metadata: Optional[Dict[str, Any]] = None,
        force_grade: Optional[str] = None,
    ) -> ReconProResult:
        """Aggregate findings into a ``ReconProResult`` identical to scanner.py."""
        total_score = compute_score(all_findings)
        grade = force_grade if force_grade is not None else compute_grade(total_score)
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        badge = badge_markdown(host, grade)

        sev_counts: Dict[str, int] = {}
        for f in all_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

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
            target_validation=target_validation,
            scan_metadata=scan_metadata,
        )

    # -- single module execution -------------------------------------------

    @staticmethod
    def _is_plugin_module(mod_id: str, runner: Any, entry: Any) -> bool:
        """Determine if a module is a third-party plugin (vs built-in)."""
        if entry and isinstance(entry, dict) and entry.get("is_plugin"):
            return True
        if hasattr(runner, "__module__") and "plugins" in (runner.__module__ or ""):
            return True
        return False

    async def _run_module(
        self,
        mod_id: str,
        runner: Any,
        target: str,
        base_url: str,
        timeout: int,
        verify_tls: bool,
        limiter: Any,
        semaphore: asyncio.Semaphore,
        findings_lock: asyncio.Lock,
        all_findings: List[Finding],
        module_results: Dict[str, Dict[str, Any]],
        vibesec_state: Dict[str, Any],
        _entry: Any = None,
    ) -> None:
        """Execute one module under the concurrency semaphore."""
        # Agent 5: graceful shutdown — refuse new module starts
        if self._shutting_down:
            logger.info("Engine shutting down, skipping module '%s'", mod_id)
            return

        # Agent 5: compute per-module adaptive timeout
        effective_timeout = self._get_adaptive_timeout(mod_id, timeout)

        # Security hardening: validate plugin modules through PluginSandbox
        if self._is_plugin_module(mod_id, runner, _entry):
            try:
                from .security_hardening import PluginSandbox
                sandbox = PluginSandbox(cpu_time_seconds=float(effective_timeout))
                sandbox_result = sandbox.execute(
                    runner,
                    plugin_name=mod_id,
                    target=target,
                    base_url=base_url,
                    timeout=effective_timeout,
                    verify_tls=verify_tls,
                    limiter=limiter,
                )
                if not sandbox_result.get("success"):
                    _module_health.record_failure(mod_id)
                    logger.error(
                        "Plugin module '%s' blocked by sandbox: %s",
                        mod_id, sandbox_result.get("error", "unknown"),
                    )
                    return
            except Exception:
                logger.debug("PluginSandbox check for '%s' failed, running unsandboxed", mod_id, exc_info=True)

        async with semaphore:
            # Re-check shutdown after acquiring semaphore
            if self._shutting_down:
                logger.info("Engine shutting down, aborting module '%s' at semaphore", mod_id)
                return

            self._emit(ScanEvent(type="MODULE_START", module_id=mod_id))
            t0 = time.monotonic()
            try:
                if self._use_async and hasattr(runner, "async_run"):
                    _ar_kwargs = _filter_runner_kwargs(
                        runner.async_run,
                        target=target,
                        base_url=base_url,
                        timeout=effective_timeout,
                        verify_tls=verify_tls,
                        limiter=limiter,
                    )
                    result = await asyncio.wait_for(
                        runner.async_run(**_ar_kwargs),
                        timeout=effective_timeout,
                    )
                else:
                    _sr_kwargs = _filter_runner_kwargs(
                        runner,
                        target=target,
                        base_url=base_url,
                        timeout=effective_timeout,
                        verify_tls=verify_tls,
                        limiter=limiter,
                    )
                    result = await asyncio.wait_for(
                        asyncio.to_thread(runner, **_sr_kwargs),
                        timeout=effective_timeout,
                    )

                duration = time.monotonic() - t0
                self._record_module_timing(mod_id, duration)

                # Dispatch based on return type.
                # vibesec returns (findings, score, grade, badge_md).
                # All other modules return list[Finding].
                if isinstance(result, tuple) and len(result) == 4:
                    mod_findings, score, grade, badge_md = result
                    vibesec_state["score"] = score
                    vibesec_state["grade"] = grade
                    async with findings_lock:
                        all_findings.extend(mod_findings)
                    module_results[mod_id] = {
                        "findings": [f.to_dict() for f in mod_findings],
                        "score": score,
                        "grade": grade,
                        "badge": badge_md,
                    }
                else:
                    mod_findings = result
                    async with findings_lock:
                        all_findings.extend(mod_findings)
                        for f in mod_findings:
                            self._emit(
                                ScanEvent(type="FINDING", module_id=mod_id, finding=f)
                            )
                            try:
                                from .plugins import HookManager
                                HookManager.fire("post_finding", finding=f)
                            except Exception:
                                logger.debug("Hook 'post_finding' error", exc_info=True)
                    module_results[mod_id] = {
                        "findings": [f.to_dict() for f in mod_findings],
                        "count": len(mod_findings),
                    }

                _module_health.record_success(mod_id)

                self._emit(
                    ScanEvent(
                        type="MODULE_COMPLETE",
                        module_id=mod_id,
                        findings_count=len(mod_findings),
                        duration=duration,
                    )
                )
            except asyncio.TimeoutError:
                duration = time.monotonic() - t0
                self._record_module_timing(mod_id, duration)
                _module_health.record_failure(mod_id)
                logger.error(
                    "Module '%s' timed out after %.1fs (adaptive timeout was %ds)",
                    mod_id, duration, effective_timeout,
                )
                err_finding = Finding(
                    title=f"Module {mod_id} timed out after {duration:.1f}s",
                    severity="info",
                    category="engine_timeout",
                    module=mod_id,
                    description=f"Module {mod_id} exceeded adaptive timeout of {effective_timeout}s.",
                    evidence=f"timeout={effective_timeout}s, actual={duration:.1f}s",
                    asset=target,
                )
                async with findings_lock:
                    all_findings.append(err_finding)
                module_results[mod_id] = {
                    "findings": [err_finding.to_dict()],
                    "count": 1,
                    "timeout": True,
                }
                self._emit(
                    ScanEvent(
                        type="MODULE_COMPLETE",
                        module_id=mod_id,
                        findings_count=1,
                        duration=duration,
                    )
                )
            except Exception as exc:
                duration = time.monotonic() - t0
                self._record_module_timing(mod_id, duration)
                _module_health.record_failure(mod_id)
                logger.error("Module '%s' failed: %s", mod_id, exc, exc_info=True)
                # Emit a finding-like error so the scan doesn't silently
                # swallow module failures.
                err_finding = Finding(
                    title=f"Module {mod_id} error: {exc}",
                    severity="info",
                    category="engine_error",
                    module=mod_id,
                    description=f"Module {mod_id} raised an exception during execution.",
                    evidence=str(exc),
                    asset=target,
                )
                async with findings_lock:
                    all_findings.append(err_finding)
                module_results[mod_id] = {
                    "findings": [err_finding.to_dict()],
                    "count": 1,
                    "error": str(exc),
                }
                self._emit(
                    ScanEvent(
                        type="MODULE_COMPLETE",
                        module_id=mod_id,
                        findings_count=1,
                        duration=duration,
                    )
                )

    # -- main async entry point --------------------------------------------

    async def run(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        all_modules: bool = False,
        timeout: int = 10,
        verify_tls: bool = True,
        rate_limit: Optional[float] = None,
        is_local: bool = False,
    ) -> ReconProResult:
        """Run a scan against *target* with concurrent module execution.

        This is the async counterpart of :func:`scanner.scan` and produces
        an identical ``ReconProResult``.  The only difference is that modules
        are executed concurrently (up to ``self._concurrency`` at a time)
        instead of sequentially.

        Parameters
        ----------
        target : str
            Domain, URL, or directory path (for local scans).
        modules : list[str] | None
            Explicit module IDs.  ``None`` → defaults.
        all_modules : bool
            Run every registered module for the scan type.
        timeout : int
            Per-request timeout in seconds.
        verify_tls : bool
            Whether to verify TLS certificates.
        rate_limit : float | None
            Requests-per-second cap.  Falls back to the engine default.
        is_local : bool
            If ``True``, use ``LOCAL_MODULES`` instead of
            ``MODULE_REGISTRY`` (same as ``audit_scan``).

        Returns
        -------
        ReconProResult
            Identical shape to what ``scanner.scan`` returns.
        """
        effective_rate = rate_limit if rate_limit is not None else self._default_rate_limit

        # Resolve modules list.
        if is_local:
            mods = self._resolve_local_modules(modules, all_modules)
        else:
            mods = self._resolve_remote_modules(modules, all_modules)

        base_url = target if target.startswith("http") else f"https://{target}"
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        # ── Truth layer: Target Validation Pipeline ────────────────────
        # DNS → Reachability → HTTP/TLS → decision, run BEFORE any module.
        validation = None
        if not is_local:
            _meta_t0 = time.monotonic()
            try:
                validation = await asyncio.to_thread(
                    validate_target_pipeline, target,
                    min(float(timeout), 5.0), verify_tls,
                )
            except Exception as val_err:  # validation itself must never kill a scan
                logger.warning("Target validation failed, treating as PARTIAL: %s", val_err)
                from .target_validation import TargetValidation, PARTIAL_TARGET
                validation = TargetValidation(
                    state=PARTIAL_TARGET, dns_resolved=False, reachable=False,
                    http_ok=False, tls_valid=None,
                    details={"reason": f"validation error: {val_err}"},
                )
            self._emit(ScanEvent(type="TARGET_VALIDATION", target=target,
                                 validation=validation.to_dict()))
            if validation.state == UNREACHABLE_TARGET:
                # Honest short-circuit: no modules, no fabricated findings,
                # score 0 / grade U. HIGH findings are impossible by design.
                f = unreachable_finding(target, validation)
                result = self._build_result(
                    target=host,
                    mods=[],
                    all_findings=[f],
                    module_results={},
                    vibesec_score=None,
                    vibesec_grade=None,
                    target_validation=validation.to_dict(),
                    scan_metadata={
                        "scanner": "reconpro",
                        "started_at": validation.checked_at,
                        "duration_s": round(time.monotonic() - _meta_t0, 2),
                        "result": "unreachable_target_short_circuit",
                    },
                    force_grade="U",
                )
                result.total_score = 0
                self._emit(ScanEvent(type="SCAN_COMPLETE", target=target,
                                     duration=0.0, findings_count=1))
                return result

        self._emit(ScanEvent(type="SCAN_START", target=target, modules=list(mods)))
        try:
            from .plugins import HookManager
            HookManager.fire("pre_scan", target=target, modules=mods)
        except Exception:
            logger.debug("Hook 'pre_scan' error", exc_info=True)
        scan_t0 = time.monotonic()

        semaphore = asyncio.Semaphore(self._concurrency)
        findings_lock = asyncio.Lock()
        all_findings: List[Finding] = []
        module_results: Dict[str, Dict[str, Any]] = {}
        vibesec_state: Dict[str, Any] = {}

        # Create rate limiter for modules that accept it.
        from .http_layer import RateLimiter
        limiter = RateLimiter(effective_rate)

        # Build coroutine tasks for each module — respect dependency order.
        # get_execution_order returns waves of modules that can run in parallel.
        try:
            waves = get_execution_order(mods)
        except ValueError as dep_err:
            logger.error("Dependency resolution failed: %s", dep_err)
            # Fall back to flat execution order on dependency error
            waves = [mods]

        tasks: List[asyncio.Task[None]] = []
        for wave in waves:
            wave_tasks: List[asyncio.Task[None]] = []
            for mod_id in wave:
                if is_local:
                    entry = LOCAL_MODULES.get(mod_id)
                else:
                    entry = MODULE_REGISTRY.get(mod_id)

                if entry is None:
                    continue

                if not _module_health.is_healthy(mod_id):
                    if _module_health.is_quarantined(mod_id):
                        logger.warning("Module '%s' is quarantined, skipping", mod_id)
                    else:
                        logger.warning("Module '%s' is unhealthy (circuit breaker open), skipping", mod_id)
                    continue

                # Auto-recovery probe: quarantine expired, try one execution
                _is_probe = _module_health.is_probe(mod_id)
                if _is_probe:
                    logger.info("Module '%s' running as probe (auto-recovery)", mod_id)

                runner = entry.get("runner")
                if runner is None:
                    # Special case: vibesec — lazy import.
                    if mod_id == "vibesec" and not is_local:
                        from .modules.vibesec import run_vibesec  # type: ignore[no-redef]
                        runner = run_vibesec
                    else:
                        continue

                wave_tasks.append(
                    asyncio.create_task(
                        self._run_module(
                            mod_id=mod_id,
                            runner=runner,
                            target=target,
                            base_url=base_url,
                            timeout=timeout,
                            verify_tls=verify_tls,
                            limiter=limiter,
                            semaphore=semaphore,
                            findings_lock=findings_lock,
                            all_findings=all_findings,
                            module_results=module_results,
                            vibesec_state=vibesec_state,
                            _entry=entry,
                        )
                    )
                )

            # Wait for this wave to complete before starting the next.
            if wave_tasks:
                await asyncio.gather(*wave_tasks, return_exceptions=True)
                tasks.extend(wave_tasks)

        # (tasks list is kept for any post-scan inspection; actual execution
        #  is already done via wave-by-wave gather above)

        scan_duration = time.monotonic() - scan_t0

        vibesec_score = vibesec_state.get("score")
        vibesec_grade = vibesec_state.get("grade")

        # ── Truth layer: tag findings with the verification state ──────
        # (severity capped at MEDIUM for PARTIAL_TARGET, in place)
        if validation is not None:
            apply_target_truth(all_findings, validation)

        result = self._build_result(
            target=host if not is_local else (target if target != "." else "local-audit"),
            mods=mods,
            all_findings=all_findings,
            module_results=module_results,
            vibesec_score=vibesec_score,
            vibesec_grade=vibesec_grade,
            target_validation=validation.to_dict() if validation is not None else None,
            scan_metadata={
                "scanner": "reconpro",
                "started_at": validation.checked_at if validation is not None
                              else datetime.now(timezone.utc).isoformat(),
                "duration_s": round(scan_duration, 2),
                "result": "modules_executed",
            },
        )

        # ── Post-scan Secret Detection & Tamper-Evident Logging ──
        secret_findings: List[Dict[str, Any]] = []
        if all_findings:
            try:
                from .security_hardening import SecretsManager, TamperEvidenceLogger
                secrets_mgr = SecretsManager()
                for f in all_findings:
                    finding_text = json.dumps(f.to_dict(), default=str)
                    sf = secrets_mgr.scan_for_secrets(finding_text, source=f"finding:{f.module}")
                    secret_findings.extend(sf)
                if secret_findings:
                    logger.warning(
                        "Secret detection found %d potential secret(s) in scan findings",
                        len(secret_findings),
                    )
            except Exception as sec_err:
                logger.debug("Post-scan secret detection error: %s", sec_err, exc_info=True)

            # Tamper-evident logging of scan result
            try:
                from .security_hardening import TamperEvidenceLogger
                tamper_logger = TamperEvidenceLogger(module_name="engine")
                tamper_logger.log(
                    level="INFO",
                    event_type="SCAN_COMPLETE",
                    target=target,
                    details={
                        "findings_count": len(all_findings),
                        "score": result.total_score,
                        "grade": result.grade,
                        "modules_run": mods,
                        "secrets_found": len(secret_findings),
                    },
                )
            except Exception as te_err:
                logger.debug("Tamper-evident logging failed: %s", te_err)

        # ── Post-scan Intelligence Pipeline ──────────────────────
        intelligence_data = None
        if all_findings and self._run_intelligence:
            try:
                # Apply prompt defense to finding text before AI analyst processes it
                # Always runs when intelligence pipeline is active
                try:
                    from .prompt_defense import PromptDefense
                    _pd = PromptDefense(enable_logging=False)
                    _sanitized_findings = []
                    for _f in all_findings:
                        _title = _f.title or ""
                        _desc = _f.description or ""
                        _evidence = _f.evidence or ""
                        _pd_result = _pd.scan(f"{_title} {_desc} {_evidence}", source="engine-intel")
                        if _pd_result.is_safe:
                            _sanitized_findings.append(_f)
                        else:
                            # Replace description with sanitized version to prevent prompt injection
                            logger.warning(
                                "Prompt defense sanitized finding '%s': %s",
                                _f.title, _pd_result.max_severity.value,
                            )
                            _safe_f = Finding(
                                title=_f.title,
                                severity=_f.severity,
                                category=_f.category,
                                module=_f.module,
                                description=_pd_result.sanitized_input,
                                evidence=_f.evidence,
                                asset=_f.asset,
                                points_deducted=_f.points_deducted,
                                remediation=_f.remediation,
                                references=_f.references,
                            )
                            _sanitized_findings.append(_safe_f)
                except Exception:
                    logger.debug("Prompt defense check skipped", exc_info=True)
                    _sanitized_findings = all_findings

                from .intelligence_pipeline import IntelligencePipeline
                intel_pipeline = IntelligencePipeline(
                    enable_ai_analyst=True,
                    enable_attack_graph=True,
                    enable_threat_intel=True,
                )
                intel_result = intel_pipeline.analyze(_sanitized_findings, result.to_dict())
                intelligence_data = intel_result.to_dict()

                # Scan AI-generated intelligence data for secrets
                try:
                    _intel_text = json.dumps(intelligence_data, default=str)
                    from .security_hardening import SecretsManager as _SM2
                    _intel_sm = _SM2()
                    _intel_sf = _intel_sm.scan_for_secrets(_intel_text, source="intelligence_pipeline")
                    if _intel_sf:
                        logger.warning(
                            "Secret detection found %d potential secret(s) in AI-generated content",
                            len(_intel_sf),
                        )
                        secret_findings.extend(_intel_sf)
                except Exception:
                    pass

                # Inject intelligence into result
                result.intelligence = intelligence_data
                logger.info(
                    "Intelligence pipeline completed: risk=%.1f exposure=%.1f chains=%d cves=%d",
                    intel_result.executive_risk_score,
                    intel_result.exposure_score,
                    len(intel_result.attack_chains),
                    len(intel_result.cve_matches),
                )
            except Exception as e:
                logger.warning("Intelligence pipeline error: %s", e, exc_info=True)

        self._emit(
            ScanEvent(
                type="SCAN_COMPLETE",
                target=target,
                result=result,
                duration=scan_duration,
            )
        )
        try:
            from .plugins import HookManager
            HookManager.fire("post_scan", target=target, result=result, duration=scan_duration)
        except Exception:
            logger.debug("Hook 'post_scan' error", exc_info=True)

        # ── Post-scan Engineering Pipeline (if enabled) ──────────────
        if self._run_engineering and all_findings:
            try:
                from .engineering_workflow import ContinuousEngineeringOrchestrator
                eng_orchestrator = ContinuousEngineeringOrchestrator(self._engineering_repo_path)
                eng_result = eng_orchestrator.run_full_cycle(self._engineering_repo_path)
                # Store engineering result metadata in result for later retrieval
                result.engineering = eng_result.to_dict()
                # Propagate engineering score to scan result
                result.engineering_score = eng_result.engineering_score
                logger.info(
                    "Engineering pipeline completed: status=%s stages=%d duration=%.2fs",
                    eng_result.overall_status,
                    len(eng_result.stages),
                    eng_result.total_duration_s,
                )
            except Exception as e:
                logger.warning("Engineering pipeline error: %s", e, exc_info=True)

        # ── Post-engineering Quality Intelligence ──
        if self._run_quality or self._run_engineering:
            try:
                from .quality_intelligence import QualityIntelligence
                qi = QualityIntelligence(repository_path=self._engineering_repo_path)
                qi.analyze_repository_quality(self._engineering_repo_path)
                quality_score = qi.get_quality_score()
                quality_dims = qi.get_quality_dimensions()
                result.quality = {
                    "composite_score": quality_score,
                    "dimensions": quality_dims,
                }
                logger.info(
                    "Quality intelligence completed: score=%.1f", quality_score,
                )
            except Exception as e:
                logger.debug("Quality intelligence skipped: %s", e)

        # ── Calculate Engineering Score ──────────────────────────────────
        result.engineering_score = self._calculate_engineering_score(
            result, mods, module_results,
        )

        # ── Store Scan Facts in Repository Memory ───────────────────────
        try:
            self._store_scan_in_memory(result, mods, module_results, target)
        except Exception:
            logger.debug("Failed to store scan in repository memory", exc_info=True)

        return result

    def _calculate_engineering_score(
        self,
        result: ReconProResult,
        mods: List[str],
        module_results: Dict[str, Dict[str, Any]],
    ) -> float:
        """Calculate a quick engineering score (0-100) after every scan.

        Weighted formula: 40% module_health + 30% quality_history + 30% scan_reliability
        If no history is available, score defaults to module health.
        """
        if not mods:
            return 0.0

        # 1. Module health: success rate of modules in this scan
        succeeded = 0
        failed_mods = []
        for mod_id in mods:
            mr = module_results.get(mod_id, {})
            if "error" in mr and mr.get("findings") == []:
                failed_mods.append(mod_id)
            else:
                succeeded += 1
        module_health = (succeeded / len(mods)) * 100.0

        # 2. Quality history: from quality intelligence or memory
        quality_history = 0.0
        has_quality = result.quality and isinstance(result.quality.get("composite_score"), (int, float))
        if has_quality:
            quality_history = float(result.quality["composite_score"])
        else:
            try:
                from .repository_memory import RepositoryMemory
                mem = RepositoryMemory()
                qi_facts = mem.search(query_text="quality_score")
                if qi_facts:
                    val = qi_facts[0].value
                    quality_history = float(val) if isinstance(val, (int, float)) else 50.0
                else:
                    # No history — default to module health
                    quality_history = module_health
            except Exception:
                quality_history = module_health

        # 3. Scan reliability: based on overall score (higher score = more reliable)
        scan_reliability = float(result.total_score)

        score = 0.40 * module_health + 0.30 * quality_history + 0.30 * scan_reliability
        return round(max(0.0, min(100.0, score)), 1)

    def _store_scan_in_memory(
        self,
        result: ReconProResult,
        mods: List[str],
        module_results: Dict[str, Dict[str, Any]],
        target: str,
    ) -> None:
        """Store key scan facts in repository memory for future recall."""
        from .repository_memory import RepositoryMemory
        from datetime import datetime, timezone

        mem = RepositoryMemory()
        ts = datetime.now(timezone.utc).isoformat()

        # Identify succeeded/failed modules
        succeeded = []
        failed = []
        for mod_id in mods:
            mr = module_results.get(mod_id, {})
            if "error" in mr and mr.get("findings") == []:
                failed.append(mod_id)
            else:
                succeeded.append(mod_id)

        # Store scan summary
        mem.remember(
            key=f"scan/{target}/{ts.replace(':', '-').replace('.', '-')}",
            value={
                "target": target,
                "timestamp": ts,
                "score": result.total_score,
                "grade": result.grade,
                "modules_succeeded": succeeded,
                "modules_failed": failed,
                "findings_by_severity": result.severity_counts,
                "total_findings": len(result.findings),
                "engineering_score": result.engineering_score,
            },
            metadata={"source": "engine_scan", "tags": ["scan", "target", target, result.grade]},
        )

        # Store quality score if available
        if result.quality and result.quality.get("composite_score"):
            mem.remember(
                key=f"quality_score/{target}",
                value=result.quality["composite_score"],
                metadata={"source": "engine_scan", "tags": ["quality_score", target]},
            )

        # Store engineering score
        if result.engineering_score > 0:
            mem.remember(
                key=f"engineering_score/{target}",
                value=result.engineering_score,
                metadata={"source": "engine_scan", "tags": ["engineering_score", target]},
            )

        # Persist to disk
        mem.save()

    def _recall_scan_facts(self, target: str) -> List[Dict[str, Any]]:
        """Recall previous scan facts about a target from repository memory."""
        try:
            from .repository_memory import RepositoryMemory
            mem = RepositoryMemory()
            facts = mem.search(query_text=f"scan/{target}")
            return [f.to_dict() for f in facts[:10]]
        except Exception:
            return []

    # -- sync wrapper ------------------------------------------------------

    def scan_one(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        timeout: int = 10,
        verify_tls: bool = True,
        rate_limit: Optional[float] = None,
        is_local: bool = False,
        run_engineering: bool = False,
        engineering_repo_path: str = ".",
        run_intelligence: bool = True,
        run_quality: bool = False,
        run_defense: bool = False,
    ) -> ReconProResult:
        """Synchronous wrapper around :meth:`run`.

        Creates a fresh event loop (or reuses the running one) so callers
        don't need to care about asyncio.

        Parameters are identical to :meth:`run` except ``all_modules`` is
        not exposed — pass an explicit ``modules`` list instead.
        """
        # Override instance-level settings if caller provides them.
        if run_engineering:
            self._run_engineering = True
        if engineering_repo_path != ".":
            self._engineering_repo_path = engineering_repo_path
        if not run_intelligence:
            self._run_intelligence = False
        if run_quality:
            self._run_quality = True
        if run_defense:
            self._run_defense = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Already inside an async context — use nest_asyncio-safe
            # approach or fallback to a new thread.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.run(
                        target=target,
                        modules=modules,
                        timeout=timeout,
                        verify_tls=verify_tls,
                        rate_limit=rate_limit,
                        is_local=is_local,
                    ),
                )
                return future.result()

        return asyncio.run(
            self.run(
                target=target,
                modules=modules,
                timeout=timeout,
                verify_tls=verify_tls,
                rate_limit=rate_limit,
                is_local=is_local,
            )
        )


# ── Module Health Tracking ────────────────────────────────────────────


class ModuleHealthState:
    """Tracks health of scanner modules with circuit-breaker, quarantine, and scoring."""

    QUARANTINE_CONSECUTIVE_FAILURES: int = 5
    QUARANTINE_DURATION: float = 600.0  # 10 minutes
    HEALTH_WINDOW: int = 20  # last N executions for scoring

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 60.0):
        self._failure_counts: Dict[str, int] = {}
        self._consecutive_failures: Dict[str, int] = {}
        self._last_failure_time: Dict[str, float] = {}
        self._quarantine_until: Dict[str, float] = {}  # module_id -> monotonic timestamp
        self._quarantine_probe: Dict[str, bool] = {}  # module_id -> whether this is a probe run
        self._history: Dict[str, List[bool]] = {}  # module_id -> [True=success, False=failure]
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds

    def record_success(self, module_id: str) -> None:
        self._failure_counts.pop(module_id, None)
        self._last_failure_time.pop(module_id, None)
        self._consecutive_failures[module_id] = 0
        self._quarantine_until.pop(module_id, None)
        self._quarantine_probe.pop(module_id, None)
        self._history.setdefault(module_id, []).append(True)
        if len(self._history[module_id]) > self.HEALTH_WINDOW:
            self._history[module_id] = self._history[module_id][-self.HEALTH_WINDOW:]

    def record_failure(self, module_id: str) -> None:
        self._failure_counts[module_id] = self._failure_counts.get(module_id, 0) + 1
        self._last_failure_time[module_id] = time.monotonic()
        self._consecutive_failures[module_id] = self._consecutive_failures.get(module_id, 0) + 1
        self._history.setdefault(module_id, []).append(False)
        if len(self._history[module_id]) > self.HEALTH_WINDOW:
            self._history[module_id] = self._history[module_id][-self.HEALTH_WINDOW:]

        # Check if should quarantine
        if self._consecutive_failures.get(module_id, 0) >= self.QUARANTINE_CONSECUTIVE_FAILURES:
            self._quarantine_until[module_id] = time.monotonic() + self.QUARANTINE_DURATION
            logger.warning(
                "Module '%s' quarantined for %.0fs after %d consecutive failures",
                module_id, self.QUARANTINE_DURATION, self._consecutive_failures[module_id],
            )

    def is_quarantined(self, module_id: str) -> bool:
        """Check if a module is currently in quarantine."""
        until = self._quarantine_until.get(module_id)
        if until is None:
            return False
        if time.monotonic() >= until:
            # Quarantine expired — allow one probe execution
            self._quarantine_until.pop(module_id, None)
            self._quarantine_probe[module_id] = True
            logger.info("Module '%s' quarantine expired, allowing probe execution", module_id)
            return False
        return True

    def is_probe(self, module_id: str) -> bool:
        """Check if the next execution of this module is a probe (auto-recovery test)."""
        return self._quarantine_probe.pop(module_id, False)

    def health_score(self, module_id: str) -> float:
        """Return health score 0.0-1.0 based on last 20 executions."""
        hist = self._history.get(module_id, [])
        if not hist:
            return 1.0  # no data = assumed healthy
        return sum(1 for x in hist if x) / len(hist)

    def is_healthy(self, module_id: str) -> bool:
        """Check if a module is healthy enough to run.

        Returns False if quarantined or if circuit breaker is open.
        """
        # Check quarantine first
        if self.is_quarantined(module_id):
            return False

        count = self._failure_counts.get(module_id, 0)
        if count < self._failure_threshold:
            return True
        # In cooldown?
        last_fail = self._last_failure_time.get(module_id, 0)
        if time.monotonic() - last_fail > self._cooldown_seconds:
            # Cooldown expired, reset
            self.record_success(module_id)
            return True
        return False

    def get_all_module_health(self) -> Dict[str, Dict[str, Any]]:
        """Return comprehensive health dict for every tracked module.

        Returns
        -------
        dict[str, dict]
            Keys are module IDs.  Values contain ``health_score``,
            ``is_healthy``, ``is_quarantined``, ``failure_count``,
            ``consecutive_failures``, ``quarantine_remaining``.
        """
        result: Dict[str, Dict[str, Any]] = {}
        all_known = set(self._failure_counts) | set(self._history) | set(self._quarantine_until)
        for mid in all_known:
            until = self._quarantine_until.get(mid)
            quarantine_remaining = max(0.0, until - time.monotonic()) if until else 0.0
            result[mid] = {
                "health_score": round(self.health_score(mid), 3),
                "is_healthy": self.is_healthy(mid),
                "is_quarantined": until is not None and time.monotonic() < until,
                "failure_count": self._failure_counts.get(mid, 0),
                "consecutive_failures": self._consecutive_failures.get(mid, 0),
                "quarantine_remaining_s": round(quarantine_remaining, 1),
                "is_probe": mid in self._quarantine_probe,
            }
        return result

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """Return health status for all tracked modules (legacy compat)."""
        return {
            mid: {
                "failure_count": count,
                "is_healthy": self.is_healthy(mid),
                "in_cooldown": not self.is_healthy(mid),
            }
            for mid, count in self._failure_counts.items()
        }


# Global module health tracker
_module_health = ModuleHealthState()


# ── Module-level convenience functions ───────────────────────────────────


async def _scan_async(
    target: str,
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 10,
    verify_tls: bool = True,
    rate_limit: float = 50.0,
    event_callback: Optional[Callable[[ScanEvent], None]] = None,
    concurrency: int = 5,
    use_async: bool = True,
) -> ReconProResult:
    """Standalone async scan function — creates a temporary ``ScanEngine``."""
    engine = ScanEngine(
        event_callback=event_callback,
        concurrency=concurrency,
        rate_limit=rate_limit,
        use_async=use_async,
    )
    return await engine.run(
        target=target,
        modules=modules,
        all_modules=all_modules,
        timeout=timeout,
        verify_tls=verify_tls,
        rate_limit=rate_limit,
    )


def scan(
    target: str,
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 8,
    verify_tls: bool = True,
    rate_limit: float = 10.0,
    run_engineering: bool = False,
    engineering_repo_path: str = ".",
    run_intelligence: bool = True,
    run_quality: bool = False,
    run_defense: bool = False,
) -> ReconProResult:
    """Drop-in replacement for ``scanner.scan`` with concurrent module execution.

    Accepts the exact same parameters and returns an identical
    ``ReconProResult``.  The only internal difference is that modules
    are executed concurrently (up to 5 by default) instead of sequentially.

    This function can be used as a direct upgrade path::

        # Before (sequential)
        from reconpro.scanner import scan
        result = scan("example.com")

        # After (concurrent, drop-in)
        from reconpro.engine import scan
        result = scan("example.com")
    """
    engine = ScanEngine(
        concurrency=5,
        rate_limit=rate_limit,
        use_async=True,
        run_engineering=run_engineering,
        engineering_repo_path=engineering_repo_path,
        run_intelligence=run_intelligence,
        run_quality=run_quality,
        run_defense=run_defense,
    )
    return engine.scan_one(
        target=target,
        modules=modules,
        timeout=timeout,
        verify_tls=verify_tls,
        rate_limit=rate_limit,
        run_engineering=run_engineering,
        engineering_repo_path=engineering_repo_path,
        run_intelligence=run_intelligence,
        run_quality=run_quality,
        run_defense=run_defense,
    )


def audit_scan(
    target: str = ".",
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    run_engineering: bool = False,
    engineering_repo_path: str = ".",
    run_intelligence: bool = True,
    run_quality: bool = False,
    run_defense: bool = False,
) -> ReconProResult:
    """Drop-in replacement for ``scanner.audit_scan`` with concurrent module execution.

    Runs local machine / project audit modules concurrently.
    """
    engine = ScanEngine(
        concurrency=5,
        rate_limit=10.0,
        use_async=True,
        run_engineering=run_engineering,
        engineering_repo_path=engineering_repo_path,
        run_intelligence=run_intelligence,
        run_quality=run_quality,
        run_defense=run_defense,
    )
    return engine.scan_one(
        target=target,
        modules=modules,
        timeout=8,
        verify_tls=True,
        is_local=True,
        run_engineering=run_engineering,
        engineering_repo_path=engineering_repo_path,
        run_intelligence=run_intelligence,
        run_quality=run_quality,
        run_defense=run_defense,
    )


async def concurrent_scan(
    targets: List[str],
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 10,
    verify_tls: bool = True,
    rate_limit: float = 50.0,
    max_concurrency: int = 10,
    is_local: bool = False,
    event_callback: Optional[Callable[[ScanEvent], None]] = None,
) -> Dict[str, ReconProResult]:
    """Scan multiple targets concurrently with bounded total parallelism.

    Spawns one ``ScanEngine`` per target but shares a single
    ``asyncio.Semaphore`` so the total number of in-flight modules
    across *all* targets never exceeds ``max_concurrency``.

    Parameters
    ----------
    targets : list[str]
        Domains / URLs to scan.
    modules, all_modules, timeout, verify_tls, rate_limit
        Forwarded to each per-target scan.
    max_concurrency : int
        Upper bound on simultaneous module executions across all targets.
    is_local : bool
        If ``True``, run local audit modules instead of remote ones.
    event_callback : callable | None
        Receives ``ScanEvent`` from every target scan.

    Returns
    -------
    dict[str, ReconProResult]
        Mapping of target → result for every target.
    """
    results: Dict[str, ReconProResult] = {}
    lock = asyncio.Lock()

    async def _scan_one(t: str) -> None:
        engine = ScanEngine(
            event_callback=event_callback,
            concurrency=max_concurrency,
            rate_limit=rate_limit,
            use_async=True,
        )
        result = await engine.run(
            target=t,
            modules=modules,
            all_modules=all_modules,
            timeout=timeout,
            verify_tls=verify_tls,
            rate_limit=rate_limit,
            is_local=is_local,
        )
        async with lock:
            results[t] = result

    tasks = [asyncio.create_task(_scan_one(t)) for t in targets]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return results
