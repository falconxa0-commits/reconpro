"""Parallel multi-target scanning.

Blitz mode: scan N targets simultaneously using ThreadPoolExecutor.

Optimizations over baseline:
  - Single-pass result collection via done_callback (no redundant as_completed loop)
  - Lazy import hoisted out of per-future callback
  - Thread pool size capped to min(max_workers, len(targets))
  - Single-pass summary aggregation during collection
"""
from __future__ import annotations

import concurrent.futures
import threading
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn
from rich.table import Table
from rich.text import Text

from .constants import SEV_COLORS, GRADE_COLORS
from .scanner import scan, audit_scan
from .http_layer import Finding
from .utils import compute_grade

console = Console()


def _scan_one_target(
    target: str,
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 8,
    verify_tls: bool = True,
    rate_limit: float = 10.0,
    is_local: bool = False,
) -> Tuple[str, Any, Optional[Exception]]:
    """Scan a single target. Returns (target, result_or_none, error_or_none)."""
    try:
        if is_local:
            result = audit_scan(target=target, modules=modules)
        else:
            result = scan(
                target, modules=modules, all_modules=all_modules,
                timeout=timeout, verify_tls=verify_tls, rate_limit=rate_limit,
            )
        return (target, result, None)
    except Exception as e:
        return (target, None, e)


def blitz_scan(
    targets: List[str],
    max_workers: int = 4,
    modules: Optional[List[str]] = None,
    all_modules: bool = False,
    timeout: int = 8,
    verify_tls: bool = True,
    rate_limit: float = 10.0,
    save: bool = True,
) -> Dict[str, Any]:
    """Scan multiple targets in parallel.

    Returns a summary dict with all results.

    Optimizations:
      - Thread pool size is capped to the number of targets to avoid idle threads.
      - Result collection, history saving, and progress tracking are all handled
        via a single done_callback — no separate as_completed loop.
      - History import is hoisted out of the callback (avoids repeated imports).
      - Summary stats (total_findings, avg_score) are accumulated incrementally.
    """
    if not targets:
        return {
            "targets_scanned": 0, "successful": 0, "failed": 0,
            "total_findings": 0, "average_score": 0, "average_grade": "F",
            "results": {}, "errors": [],
        }

    # Cap workers to actual target count — no need for idle threads.
    effective_workers = min(max_workers, len(targets))

    # Hoist history import so it runs once, not per-callback.
    save_scan_fn = None
    if save:
        try:
            from .history import save_scan as _save_scan
            save_scan_fn = _save_scan
        except ImportError:
            save = False

    results: Dict[str, Any] = {}
    errors: List[str] = []

    # Incremental summary accumulators (avoids re-iterating results dict).
    total_findings_acc = [0]
    total_score_acc = [0]
    success_count = [0]
    result_lock = threading.Lock()

    console.print(
        f"  [bold]Blitz scanning [cyan]{len(targets)}[/] targets "
        f"with [yellow]{effective_workers}[/] workers...[/]"
    )

    with Progress(
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[bold]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Blitz", total=len(targets))

        def on_done(future: concurrent.futures.Future) -> None:
            """Single-pass callback: collect result, save, update progress."""
            target, result, error = future.result()
            with result_lock:
                if error:
                    errors.append(f"{target}: {error}")
                elif result:
                    results[target] = result
                    success_count[0] += 1
                    # Incremental accumulation for summary.
                    total_findings_acc[0] += len(result.findings)
                    total_score_acc[0] += result.total_score
                    if save_scan_fn is not None:
                        save_scan_fn(result.to_dict(), label="blitz")
            progress.update(task, advance=1)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=effective_workers,
        ) as executor:
            futures = [
                executor.submit(
                    _scan_one_target,
                    target, modules, all_modules,
                    timeout, verify_tls, rate_limit,
                )
                for target in targets
            ]
            for f in futures:
                f.add_done_callback(on_done)
            # Wait for all futures to complete (callbacks fire as they finish).
            concurrent.futures.wait(futures)

    # Build summary from accumulated counters (no re-iteration needed).
    avg_score = (total_score_acc[0] / success_count[0]) if success_count[0] else 0
    avg_grade = compute_grade(int(avg_score))

    summary = {
        "targets_scanned": len(targets),
        "successful": success_count[0],
        "failed": len(errors),
        "total_findings": total_findings_acc[0],
        "average_score": int(avg_score),
        "average_grade": avg_grade,
        "results": {t: r.to_dict() for t, r in results.items()},
        "errors": errors,
    }

    # Render results
    _render_blitz_summary(summary, results)

    return summary


def _render_blitz_summary(summary: Dict, results: Dict) -> None:
    """Render a nice blitz results table."""
    # Score summary table
    table = Table(
        title=f"Blitz Results — {summary['targets_scanned']} targets, {summary['total_findings']} findings",
        border_style="bright_white",
        header_style="bold bright_white",
    )
    table.add_column("Target", style="cyan", width=30)
    table.add_column("Score", style="bold", width=8)
    table.add_column("Grade", style="bold", width=8)
    table.add_column("Findings", style="white", width=10)
    table.add_column("Critical", style="bright_red", width=10)
    table.add_column("High", style="red", width=8)
    table.add_column("Modules", style="dim")

    for target, result in results.items():
        grade = result.grade
        gc = GRADE_COLORS.get(grade, "white")
        sc = result.severity_counts
        table.add_row(
            target[:30],
            str(result.total_score),
            f"[{gc}]{grade}[/{gc}]",
            str(len(result.findings)),
            str(sc.get("critical", 0)),
            str(sc.get("high", 0)),
            ", ".join(result.modules_run),
        )

    console.print(table)

    # Overall
    gc = GRADE_COLORS.get(summary["average_grade"], "white")
    console.print(f"\n  [bold]Average Score:[/] [{gc}]{summary['average_score']}/100 ({summary['average_grade']})[/{gc}]")

    if summary["errors"]:
        console.print(f"\n  [red]{len(summary['errors'])} failed:[/]")
        for e in summary["errors"]:
            console.print(f"    [red]✗[/] {e}")
    console.print()
