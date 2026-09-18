from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

# ── Lazy rich imports (startup budget: <100 ms cold) ─────────────────────
# rich costs ~110 ms to import; the CLI only needs it when something is
# actually PRINTED.  --version / --help / fast subcommands never touch it.
from .lazy_rich import Console, Group, Panel, Progress, SpinnerColumn, \
    TextColumn, TimeElapsedColumn, Table, Text, console, escape

from . import __version__
from .constants import SEV_COLORS, GRADE_COLORS

# Heavy engine/registry/history imports are deferred to _load_heavy()
# (see below) — they pull the entire module registry (~300 ms) and are
# only needed for scan-class commands.

console = console

BANNER = r"""[bold bright_white]
██████╗ ███████╗ ██████╗██╗  ██╗███████╗██████╗ ███████╗██████╗ ██████╗ ██╗    ██╗
██╔══██╗██╔════╝██╔════╝██║  ██╗██╔════╝██╔══██╗██╔════╝██╔════╝██║██╗ ██╔╝
██████╔╝█████╗  ██║     ███████║█████╗  ██████╔╝█████╗  ██║     ██╔╝██╗██║
██╔═══╝ ██╔══╝  ██║     ██╔══██║██╔══╝  ██╔══██╗██╔══╝  ██║     █████╔╝██║
██║     ███████╗╚██████╗██║  ██║███████╗██║  ██║███████╗╚██████╗██╔╝██╗██║
╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝
[/bold bright_white][dim]          E L E V E N   B L A D E S .   O N E   T A R G E T .   O N E   V E R D I C T.[/dim]
"""

# Colors imported from constants.py


# ── Unknown-command guard ───────────────────────────────────────────────
# `reconpro <word>` where <word> is NOT a registered subcommand used to
# silently become a scan target. A typo like `reconpro scna example.com`
# then hung the CLI probing a nonexistent host. Now an unknown first word
# only survives if it looks like a real scan target (URL / IPv4 / dotted
# domain / localhost); anything else is rejected with exit code 2 before
# any network activity can start.
_SCAN_TARGET_RE = re.compile(
    r"^(?:"
    r"https?://\S+"                                   # absolute URL
    r"|localhost(?::\d+)?(?:/\S*)?"                  # localhost[:port][/path]
    r"|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/\S*)?"    # IPv4[:port][/path]
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # dotted labels
    r"[a-zA-Z]{2,}(?::\d+)?(?:/\S*)?"                # …TLD[:port][/path]
    r")$"
)


def looks_like_scan_target(token: str) -> bool:
    """True if *token* is a plausible scan target (URL, IPv4, dotted domain
    or localhost).  Used to keep the `reconpro example.com` shorthand while
    rejecting mistyped subcommands like `reconpro scna`.
    """
    if not token or len(token) > 2048:
        return False
    return _SCAN_TARGET_RE.match(token) is not None


def _positive_int(lo: int = 1, hi: int = 600):
    """argparse type: integer bounded to [lo, hi] (default 1-600).

    Rejects zero/negative/absurd values BEFORE any scan starts — a
    negative timeout previously poisoned every socket call downstream.
    """
    def _check(value: str) -> int:
        try:
            iv = int(value)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"invalid integer value: {value!r}")
        if iv < lo or iv > hi:
            raise argparse.ArgumentTypeError(
                f"value must be between {lo} and {hi}, got {iv}")
        return iv
    return _check


def _positive_float(lo: float = 0.1, hi: float = 1000.0):
    """argparse type: float bounded to [lo, hi] (default 0.1-1000)."""
    def _check(value: str) -> float:
        try:
            fv = float(value)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"invalid float value: {value!r}")
        if fv < lo or fv > hi:
            raise argparse.ArgumentTypeError(
                f"value must be between {lo} and {hi}, got {fv}")
        return fv
    return _check


def _reject_unknown_command(token: str, choices) -> None:
    """Exit code 2 with a helpful, non-scanning error for an unknown command."""
    suggestion = difflib.get_close_matches(token, list(choices), n=1, cutoff=0.6)
    hint = f"\nDid you mean: {suggestion[0]}?" if suggestion else ""
    sys.stderr.write(
        f"error: unknown command '{token}'{hint}\n"
        f"\n"
        f"Usage: reconpro <command> [args]\n"
        f"\n"
        f"* Run 'reconpro --help' for the full command list.\n"
        f"* If you meant to scan a target, be explicit:\n"
        f"      reconpro scan {token}\n"
    )
    raise SystemExit(2)



# ── Rich rendering ──────────────────────────────────────────────────────


def _render_engineering_panel(result) -> None:
    """Display engineering pipeline results in a Rich panel.

    Shows engineering score, quality intelligence, stage summary, and
    top recommendations.  Used by audit, scan, and implicit scan commands.
    """
    if result.engineering:
        eng = result.engineering
        eng_metrics = eng.get('metrics', {})
        passed = eng_metrics.get('passed', 0)
        total = eng_metrics.get('total_stages', 0)
        failed = eng_metrics.get('failed', 0)
        eng_score = eng.get('engineering_score', result.engineering_score)
        qi_score = eng.get('quality_score', 0)
        rec_count = eng.get('recommendations_count', 0)
        score_color = "bright_green" if eng_score >= 70 else "yellow" if eng_score >= 40 else "bright_red"

        lines = [
            f"Status: [bold]{eng.get('overall_status', 'unknown').upper()}[/bold]  |  "
            f"Engineering Score: [bold {score_color}]{eng_score:.1f}/100[/]  |  "
            f"Duration: {eng.get('total_duration_s', 0):.2f}s",
            f"Stages: {passed}/{total} passed" + (f"  |  {failed} failed" if failed else ""),
        ]
        if qi_score > 0:
            lines.append(f"Quality Score: {qi_score:.1f}/100  (Grade: {eng.get('quality_grade', 'N/A')})")
        if rec_count > 0:
            lines.append(f"Recommendations: {rec_count}")

        console.print(Panel(
            "\n".join(lines),
            title="[bold]ENGINEERING PIPELINE[/bold]",
            border_style="bright_cyan",
        ))
    elif result.engineering_score > 0:
        # Show engineering score even without full pipeline
        score_color = "bright_green" if result.engineering_score >= 70 else "yellow" if result.engineering_score >= 40 else "bright_red"
        console.print(Panel(
            f"Engineering Score: [bold {score_color}]{result.engineering_score:.1f}/100[/]",
            title="[bold]ENGINEERING SCORE[/bold]",
            border_style="bright_cyan",
        ))


def _render_summary(result, title: str = "RECONPRO") -> None:
    score = result.total_score
    grade = result.grade
    grade_color = GRADE_COLORS.get(grade, "bold bright_red")
    sc = result.severity_counts
    total = len(result.findings)
    bar_width = 50
    filled = int(score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    # NOTE: Text(...) renders markup LITERALLY — use Text.from_markup()
    # (or plain strings) so [cyan]/[dim] tags actually style the output.
    lines = [
        Text.from_markup(f"\n  {bar} [bold {grade_color}]{score}/100 ({grade})[/]"),
        Text.from_markup(f"\n  Target: [cyan]{escape(result.target)}[/]"),
        Text.from_markup(f"  Modules: [dim]{escape(', '.join(result.modules_run))}[/]"),
        Text(""),
        Text.from_markup(
            f"  Findings: [bold]{total}[/]  "
            f"[bright_red]{sc.get('critical', 0)} critical[/], "
            f"[red]{sc.get('high', 0)} high[/], "
            f"[yellow]{sc.get('medium', 0)} medium[/], "
            f"[green]{sc.get('low', 0)} low[/], "
            f"[dim]{sc.get('info', 0)} info[/]",
        ),
    ]
    # Truth layer — surface the target verification state.
    tv = getattr(result, "target_validation", None)
    if tv:
        state = tv.get("state", "UNKNOWN")
        state_style = {
            "VERIFIED_TARGET": "bold bright_green",
            "PARTIAL_TARGET": "bold yellow",
            "UNREACHABLE_TARGET": "bold bright_red",
        }.get(state, "bold yellow")
        reason = tv.get("details", {}).get("reason", "")
        state_line = Text.from_markup(f"\n  Target State: [{state_style}]{state}[/]")
        if reason and state != "VERIFIED_TARGET":
            state_line.append_text(
                Text.from_markup(f"  [dim]— {escape(reason[:100])}[/]")
            )
        lines.append(state_line)
    if result.vibesec_score is not None:
        lines.append(Text.from_markup(
            f"\n  VibeSec Score: [bold bright_green]{result.vibesec_score}/100 ({result.vibesec_grade})[/]"
        ))
    console.print(Panel(Group(*lines), border_style=grade_color,
                         title=f"[bold]{title}[/bold]", title_align="left", padding=(1, 2)))


def _render_findings_table(result, show_remediation: bool = False) -> None:
    if not result.findings:
        console.print("\n  [bright_green]No findings. Target is clean.[/]")
        return
    table = Table(title=f"Findings — {len(result.findings)} detected",
                  border_style="bright_white", header_style="bold bright_white")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", style="cyan", width=12)
    table.add_column("Category", style="magenta", width=18)
    table.add_column("Finding", style="white")
    table.add_column("Pts", style="yellow", width=5)
    if show_remediation:
        table.add_column("Fix", style="bright_green", width=50)
    for f in result.findings[:80]:
        sev = f.get("severity", "info")
        color = SEV_COLORS.get(sev, "white")
        row = [
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("module", ""), f.get("category", ""),
            f.get("title", "")[:70], str(f.get("points_deducted", 0)),
        ]
        if show_remediation:
            row.append(f.get("remediation", "")[:50])
        table.add_row(*row)
    console.print(table)


def _render_module_breakdown(result) -> None:
    if not result.module_results:
        return
    t = Table(title="Module Breakdown", border_style="dim", header_style="bold dim")
    t.add_column("Module", style="bold", width=16)
    t.add_column("Findings", style="white", width=10)
    t.add_column("Critical", style="bright_red", width=10)
    t.add_column("High", style="red", width=8)
    t.add_column("Medium", style="yellow", width=8)
    for mod_id, mod_data in result.module_results.items():
        findings = mod_data.get("findings", [])
        t.add_row(mod_id.upper(), str(len(findings)),
                   str(sum(1 for f in findings if f.get("severity") == "critical")),
                   str(sum(1 for f in findings if f.get("severity") == "high")),
                   str(sum(1 for f in findings if f.get("severity") == "medium")))
    console.print(t)


def _render_badge(result) -> None:
    if result.badge_markdown:
        console.print(Panel(Group(
            Text("  GitHub README Badge (copy-paste):", style="bold dim"),
            Text(f"  {result.badge_markdown}", style="cyan"),
        ), border_style="dim", title="[dim]Badge[/dim]", title_align="left", padding=(0, 2)))


def _render_remediations(result) -> None:
    actionable = [f for f in result.findings
                  if f.get("remediation") and f.get("severity") not in ("info",)
                  and f.get("points_deducted", 0) > 0]
    if not actionable:
        console.print("\n  [bright_green]No actionable fixes needed.[/]")
        return
    console.print("\n[bold bright_white]  Fix Commands:[/bold bright_white]\n")
    seen = set()
    for f in actionable:
        fix = f.get("remediation", "").strip()
        sev = f.get("severity", "info")
        color = SEV_COLORS.get(sev, "white")
        if fix and fix not in seen:
            seen.add(fix)
            console.print(f"  [{color}]{sev.upper():8}[/{color}]  {fix}")
    console.print()


def _output_result(result, args, title: str = "RECONPRO", show_remediation: bool = False) -> None:
    json_output = getattr(args, "json_output", False)
    output_file = getattr(args, "output_file", None)
    if json_output:
        text = json.dumps(result.to_dict(), indent=2, default=str)
        if output_file:
            with open(output_file, "w") as fp:
                fp.write(text)
            console.print(f"  [green]JSON saved: [cyan]{output_file}[/][/]")
        else:
            print(text)
    else:
        _render_summary(result, title=title)
        console.print()
        _render_module_breakdown(result)
        console.print()
        _render_findings_table(result, show_remediation=show_remediation)
        if show_remediation:
            _render_remediations(result)
        _render_badge(result)
        if output_file:
            with open(output_file, "w") as fp:
                fp.write(json.dumps(result.to_dict(), indent=2, default=str))
            console.print(f"\n  [green]JSON saved: [cyan]{output_file}[/][/]")
    # Auto-save to history — in EVERY mode (JSON scans are the CI/SDK path;
    # export/report/diff all read history and must work after --json scans).
    save_scan(result.to_dict())
    console.print()


_cli_args: argparse.Namespace | None = None


def _banner(args: argparse.Namespace | None = None) -> None:
    """Print banner only when not in JSON mode."""
    if args is None:
        args = _cli_args
    if not getattr(args, 'json_output', False):
        console.print(BANNER)


def _spinner_wrap(msg: str, fn, *a, _json_mode: bool | None = None, **kw):
    """Run a function with a spinner (suppressed in JSON mode)."""
    if _json_mode is None:
        _json_mode = getattr(_cli_args, 'json_output', False) if _cli_args else False
    if _json_mode:
        return fn(*a, **kw)
    with Progress(SpinnerColumn(), TextColumn("[bold]{task.description}[/]"),
                   TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task(msg, total=None)
        result = fn(*a, **kw)
        progress.update(task, completed=True)
    return result


def _print_findings(findings, args, title: str = "SCAN") -> None:
    """Print findings from a module run, respecting JSON mode."""
    if getattr(args, 'json_output', False):
        out = []
        for f in findings:
            out.append({
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "module": f.module,
                "description": f.description,
                "evidence": f.evidence,
                "asset": f.asset,
                "points_deducted": f.points_deducted,
                "remediation": f.remediation,
            })
        print(json.dumps(out, indent=2, default=str))
        return
    else:
        if not findings:
            console.print("  [dim]No findings.[/]")
        else:
            for f in findings:
                c = SEV_COLORS.get(f.severity, "white")
                console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
                if f.evidence:
                    console.print(f"       [dim]{f.evidence[:200]}[/]")
            console.print(f"  [bold]{len(findings)} finding(s).[/]")
    console.print()


# ── Dashboard data collection ──────────────────────────────────────────


def _collect_dashboard_data() -> dict:
    """Gather all metrics for the status dashboard.

    Returns a dict with keys:
      security_score, security_grade, module_health_pct,
      healthy_modules, total_modules, quality_score, engineering_score,
      coverage, regression_status, regression_count, memory_entries,
      last_scan_ago, architecture_score
    """
    data: dict = {}

    # ── Security score from latest scan ───────────────────────────
    latest = get_latest()
    if latest:
        data["security_score"] = latest.get("total_score", 0)
        data["security_grade"] = latest.get("grade", "N/A")
        data["last_scan_target"] = latest.get("target", "")
        saved_at = latest.get("_saved_at", "")
        if saved_at:
            try:
                dt = datetime.fromisoformat(saved_at)
                ago = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()
                data["last_scan_ago"] = _format_ago(ago)
                data["last_scan_seconds"] = ago
            except Exception:
                data["last_scan_ago"] = "unknown"
                data["last_scan_seconds"] = None
        else:
            data["last_scan_ago"] = "unknown"
            data["last_scan_seconds"] = None
    else:
        data["security_score"] = None
        data["security_grade"] = "N/A"
        data["last_scan_ago"] = "no scans"
        data["last_scan_seconds"] = None
        data["last_scan_target"] = ""

    # ── Module health from engine ─────────────────────────────────
    try:
        from .engine import _module_health
        all_mods = set(ALL_MODULES) | set(LOCAL_MODULES.keys())
        healthy = sum(1 for m in all_mods if _module_health.is_healthy(m))
        total = len(all_mods)
        data["healthy_modules"] = healthy
        data["total_modules"] = total
        data["module_health_pct"] = round(healthy / total * 100, 0) if total else 0
    except Exception:
        data["healthy_modules"] = 0
        data["total_modules"] = 0
        data["module_health_pct"] = 0

    # ── Quality score from repository memory / quality intelligence ──
    data["quality_score"] = None
    data["engineering_score"] = None
    data["coverage"] = None
    data["architecture_score"] = None
    try:
        from .repository_memory import RepositoryMemory
        mem = RepositoryMemory()
        q_fact = mem.recall("quality.composite_score")
        if q_fact:
            val = q_fact.value
            if isinstance(val, (int, float)):
                data["quality_score"] = int(val)
        e_fact = mem.recall("engineering.pipeline_score")
        if e_fact:
            val = e_fact.value
            if isinstance(val, (int, float)):
                data["engineering_score"] = int(val)
        c_fact = mem.recall("quality.coverage")
        if c_fact:
            val = c_fact.value
            if isinstance(val, (int, float)):
                data["coverage"] = int(val)
        a_fact = mem.recall("engineering.architecture_score")
        if a_fact:
            val = a_fact.value
            if isinstance(val, (int, float)):
                data["architecture_score"] = int(val)
    except Exception:
        pass

    # Fallback: try quality_intelligence snapshot file
    if data["quality_score"] is None:
        try:
            from .constants import MEMORY_DIR
            snap_file = MEMORY_DIR / "quality_snapshots.json"
            if snap_file.exists():
                with open(snap_file) as f:
                    snapshots = json.load(f)
                if isinstance(snapshots, list) and snapshots:
                    last_snap = snapshots[-1]
                    data["quality_score"] = int(last_snap.get("composite_score", 0))
                    dims = last_snap.get("dimensions", {})
                    cov = dims.get("coverage", {}).get("score")
                    if cov:
                        data["coverage"] = int(cov)
        except Exception:
            pass

    # ── Regression status ─────────────────────────────────────────
    data["regression_status"] = "STABLE"
    data["regression_count"] = 0
    try:
        from .regression_intelligence import RegressionIntelligence
        ri = RegressionIntelligence()
        regressions = ri.detect_regression()
        if regressions:
            data["regression_count"] = len(regressions)
            data["regression_status"] = "UNSTABLE"
    except Exception:
        pass

    # ── Memory entries ─────────────────────────────────────────────
    data["memory_entries"] = 0
    try:
        from .repository_memory import RepositoryMemory
        mem = RepositoryMemory()
        data["memory_entries"] = mem.count()
    except Exception:
        pass

    return data


def _format_ago(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    if seconds < 3600:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m} minute{'' if m == 1 else 's'} ago"
    if seconds < 86400:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m ago"
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    return f"{d}d {h}h ago"


def _render_dashboard(data: dict) -> None:
    """Render the status dashboard using rich.Panel and rich.Table."""
    # ── Main status panel ─────────────────────────────────────────
    score = data.get("security_score")
    grade = data.get("security_grade", "N/A")
    grade_color = GRADE_COLORS.get(grade, "bold bright_red")
    score_str = f"{score}/100 ({grade})" if score is not None else "N/A (no scans)"

    health_pct = data.get("module_health_pct", 0)
    healthy = data.get("healthy_modules", 0)
    total = data.get("total_modules", 0)
    health_color = "green" if health_pct >= 80 else ("yellow" if health_pct >= 50 else "red")

    quality = data.get("quality_score")
    quality_str = f"{quality}/100" if quality is not None else "N/A"

    eng = data.get("engineering_score")
    eng_str = f"{eng}/100" if eng is not None else "N/A"

    cov = data.get("coverage")
    cov_str = f"{cov}%" if cov is not None else "N/A"

    reg_status = data.get("regression_status", "STABLE")
    reg_count = data.get("regression_count", 0)
    reg_color = "green" if reg_status == "STABLE" else "red"
    reg_str = f"{reg_status} ({reg_count} regression{'' if reg_count == 1 else 's'})"

    mem_count = data.get("memory_entries", 0)
    mem_str = f"{mem_count:,}"

    last_scan = data.get("last_scan_ago", "no scans")

    arch = data.get("architecture_score")
    arch_str = f"{arch}/100" if arch is not None else "N/A"

    main_table = Table(show_header=False, box=None, border_style="bright_cyan", padding=(0, 2))
    main_table.add_column("Label", style="bold bright_white", width=22)
    main_table.add_column("Value", style="bright_white")
    main_table.add_row("Security Score:", f"[{grade_color}]{score_str}[/{grade_color}]")
    main_table.add_row("Module Health:", f"[{health_color}]{health_pct:.0f}% ({healthy}/{total} healthy)[/{health_color}]")
    main_table.add_row("Quality Score:", quality_str)
    main_table.add_row("Engineering Score:", eng_str)
    main_table.add_row("Coverage:", cov_str)
    main_table.add_row("Regression Status:", f"[{reg_color}]{reg_str}[/{reg_color}]")
    main_table.add_row("Memory Entries:", mem_str)
    main_table.add_row("Last Scan:", last_scan)
    main_table.add_row("Architecture Score:", arch_str)

    console.print(Panel(
        main_table,
        title=f"[bold bright_white]RECONPRO v{__version__} STATUS DASHBOARD[/bold bright_white]",
        border_style="bright_cyan",
        title_align="center",
        padding=(1, 2),
    ))

    # ── Module health breakdown ────────────────────────────────────
    try:
        from .engine import _module_health
        status = _module_health.get_status()
        if status:
            t = Table(title="Module Health Detail", border_style="dim", header_style="bold dim")
            t.add_column("Module", style="cyan", width=22)
            t.add_column("Failures", justify="right", width=10)
            t.add_column("Status", width=12)
            for mid, info in sorted(status.items()):
                fail_count = info.get("failure_count", 0)
                is_healthy = info.get("is_healthy", True)
                status_str = "[green]HEALTHY[/]" if is_healthy else "[red]UNHEALTHY[/]"
                t.add_row(mid, str(fail_count), status_str)
            console.print()
            console.print(t)
    except Exception:
        pass

    # ── Recent scans ───────────────────────────────────────────────
    recent = list_scans(limit=5)
    if recent:
        t = Table(title="Recent Scans", border_style="dim", header_style="bold dim")
        t.add_column("Date", style="dim", width=16)
        t.add_column("Target", style="cyan", width=25)
        t.add_column("Score", style="bold", width=8)
        t.add_column("Grade", style="bold", width=6)
        t.add_column("Findings", width=10)
        for s in recent:
            g = s.get("grade", "?")
            gc = GRADE_COLORS.get(g, "white")
            t.add_row(
                s.get("_saved_at", "?")[:16],
                s.get("target", "?")[:25],
                str(s.get("total_score", "?")),
                f"[{gc}]{g}[/{gc}]",
                str(len(s.get("findings", []))),
            )
        console.print()
        console.print(t)

    console.print()


# ── CLI entry point ─────────────────────────────────────────────────────


# ── Heavy imports, deferred via lazy shims ────────────────────────────────
# Pulled for real only when (a) _load_heavy() runs (scan-class commands) or
# (b) a shim is first used.  Fast paths (--version, --help, tutorial,
# suggest, wizard, playground, doctor --repair, plugin management) never
# pay the ~300 ms module-registry import cost.  The names exist at module
# level as shims so `unittest.mock.patch("reconpro.cli.save_scan")` etc.
# keep working.
_FAST_SUBCOMMANDS = {
    None, "tutorial", "suggest", "wizard", "playground", "plugin",
}

_HEAVY_SOURCES = {
    # name → (module path, attribute)
    "MODULE_REGISTRY": (".scanner", "MODULE_REGISTRY"),
    "LOCAL_MODULES": (".scanner", "LOCAL_MODULES"),
    "ALL_MODULES": (".scanner", "ALL_MODULES"),
    "DEFAULT_MODULES": (".scanner", "DEFAULT_MODULES"),
    "DEFAULT_LOCAL_MODULES": (".scanner", "DEFAULT_LOCAL_MODULES"),
    "scan": (".engine", "scan"),
    "audit_scan": (".engine", "audit_scan"),
    "_module_health": (".engine", "_module_health"),
    "visualize_dependencies": (".registry", "visualize_dependencies"),
    "get_execution_order": (".registry", "get_execution_order"),
    "MODULE_DEPENDENCIES": (".registry", "MODULE_DEPENDENCIES"),
    "list_scans": (".history", "list_scans"),
    "get_latest": (".history", "get_latest"),
    "diff_scans": (".history", "diff_scans"),
    "save_scan": (".history", "save_scan"),
    "clear_history": (".history", "clear_history"),
    "generate_html_report": (".reports", "generate_html_report"),
    "generate_production_report": (".reports", "generate_production_report"),
    "blitz_scan": (".parallel", "blitz_scan"),
}


class _LazyHeavy:
    """Resolves a heavy import on first use, then replaces itself."""

    __slots__ = ("_module", "_name")

    def __init__(self, module: str, name: str) -> None:
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_name", name)

    def _resolve(self):
        import importlib
        real = getattr(importlib.import_module(self._module, "reconpro"),
                       self._name)
        globals()[self._name] = real
        return real

    # callable shim
    def __call__(self, *args, **kwargs):
        return self._resolve()(*args, **kwargs)

    # attribute / dict shim
    def __getattr__(self, attr):
        return getattr(self._resolve(), attr)

    def __getitem__(self, key):
        return self._resolve()[key]

    def __contains__(self, key):
        return key in self._resolve()

    def __iter__(self):
        return iter(self._resolve())

    def __len__(self):
        return len(self._resolve())


for _name, (_mod, _attr) in _HEAVY_SOURCES.items():
    globals()[_name] = _LazyHeavy(_mod, _name)
del _name, _mod, _attr


def _load_heavy() -> None:
    """Import the engine/registry/history stack into module globals."""
    from .scanner import (
        MODULE_REGISTRY, LOCAL_MODULES,
        ALL_MODULES, DEFAULT_MODULES, DEFAULT_LOCAL_MODULES,
    )
    from .engine import scan, audit_scan
    from .engine import _module_health
    from .registry import visualize_dependencies, get_execution_order, MODULE_DEPENDENCIES
    from .history import list_scans, get_latest, diff_scans, save_scan, clear_history
    from .reports import generate_html_report, generate_production_report
    from .parallel import blitz_scan
    globals().update({
        "MODULE_REGISTRY": MODULE_REGISTRY, "LOCAL_MODULES": LOCAL_MODULES,
        "ALL_MODULES": ALL_MODULES, "DEFAULT_MODULES": DEFAULT_MODULES,
        "DEFAULT_LOCAL_MODULES": DEFAULT_LOCAL_MODULES,
        "scan": scan, "audit_scan": audit_scan, "_module_health": _module_health,
        "visualize_dependencies": visualize_dependencies,
        "get_execution_order": get_execution_order,
        "MODULE_DEPENDENCIES": MODULE_DEPENDENCIES,
        "list_scans": list_scans, "get_latest": get_latest,
        "diff_scans": diff_scans, "save_scan": save_scan,
        "clear_history": clear_history,
        "generate_html_report": generate_html_report,
        "generate_production_report": generate_production_report,
        "blitz_scan": blitz_scan,
    })


# Interactive Textual apps manage their own keyboard handling (terminal is
# in raw mode, so ^C never generates SIGINT).  Every other command gets the
# deterministic force-exit SIGINT handler.
_TUI_COMMANDS = {"nexus", "tui", "chat", "agent", "copilot"}


def _install_sigint_handler() -> None:
    """Make Ctrl+C stop the CLI *immediately* with exit code 130.

    Why a signal handler instead of catching KeyboardInterrupt: the
    cooperative path deadlocks.  py-spy evidence (2026-09 audit): during a
    scan, SIGINT interrupts the event loop, then ``asyncio.run``'s cleanup
    joins the default-executor worker threads — which sit in long socket
    reads (crt.sh lookups, port probes).  The main thread then blocks in
    ``runners.py:close`` and the KeyboardInterrupt NEVER reaches the CLI,
    so the process hangs for minutes with no output.

    The handler writes directly to fd 2 (no locks, safe from a signal
    context — Rich's live display owns its own thread lock) and force-exits
    with the conventional 130 = 128 + SIGINT(2).
    """
    import signal

    def _handler(signum: int, frame) -> None:  # pragma: no cover - signal path
        try:
            os.write(2, b"\nInterrupted \xe2\x80\x94 scan aborted by user (exit 130).\n")
        except Exception:
            pass
        os._exit(130)

    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError):
        # Not the main thread of the process (API embedding) — keep the
        # cooperative KeyboardInterrupt path in that case.
        pass


def main(argv: list[str] | None = None) -> None:
    """CLI entry point — graceful SIGINT handling + structured exit codes.

    Exit codes:
        0    success (including honest no-result scans)
        1    runtime error (no scan data, missing input, etc.)
        2    usage error (unknown command, bad argument values)
        130  interrupted by SIGINT (Ctrl+C)
    """
    try:
        return _main_impl(argv)
    except KeyboardInterrupt:
        # Belt-and-braces: normally SIGINT is handled by the deterministic
        # handler installed in _main_impl (see _install_sigint_handler).
        # If a KeyboardInterrupt still surfaces here (e.g. an API consumer
        # calling main() in-process), exit cleanly instead of dumping an
        # asyncio traceback.
        try:
            console.print("\n  [bold yellow]Interrupted — scan aborted by user (exit 130).[/]")
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        raise SystemExit(130)


def _main_impl(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="reconpro",
        description=(
            "ReconPro Nexus v11 — Async Engine. Evasion. Swarm. Knowledge Graph. 40+ Subcommands.\n"
            "The next-gen security platform with AI agent, swarm, and attack-path chaining.\n\n"
            "Quick Start:  reconpro nexus           (mind-blowing agent TUI)\n"
            "AI Agent:     reconpro agent <goal>   (LLM-powered, 18 tools)\n"
            "Swarm:        reconpro swarm <target>  (SCOUT→HACKER→CODER→GUARDIAN)\n"
            "Adversarial:  reconpro adversarial <target>  (hacker vs coder self-play)\n"
            "Intel:        cve, graph, compliance, passive (threat intel + knowledge graph)\n"
            "Export:       export (SARIF/MD/JSON/HTML)\n"
            "Cloud:        iac, container, cloud-recon, delta (infra security)\n"
            "Defense:      defense, fuzzer, profile, benchmark (auto-fix + scoring)"
        ),
        epilog="""Examples:
  # NEXUS (recommended)
  reconpro nexus                # Mind-blowing agent TUI

  # AI Agent (reasoning + 18 tools)
  reconpro agent \"fully recon example.com, find CVEs, generate SARIF\"
  reconpro agent \"swarm attack myapp.com with 3 rounds\"

  # Swarm Intelligence
  reconpro swarm example.com               # SCOUT→HACKER→CODER→GUARDIAN
  reconpro swarm example.com --mode attack   # SCOUT+HACKER only

  # Adversarial Self-Play
  reconpro adversarial example.com           # 3-round hacker vs coder

  # Remote
  reconpro scan example.com
  reconpro vibesec example.com

  # Local + Code
  reconpro audit              # Full machine audit
  reconpro ast /path/to/code  # AST vulnerability analysis
  reconpro secrets            # Find secrets

  # Threat Intelligence
  reconpro cve SQL injection    # NVD CVE lookup
  reconpro graph example.com   # Knowledge graph

  # Export (CI/CD ready)
  reconpro export report.sarif # SARIF for GitHub Code Scanning
  reconpro export report.md     # Markdown report

  # Advanced
  reconpro blitz t1.com t2.com t3.com
  reconpro subdomains example.com
  reconpro schedule example.com --every 1h
  reconpro serve --port 7890""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", "-v", action="version", version=f"ReconPro {__version__}")
    sub = parser.add_subparsers(dest="subcommand")

    # ── scan ──────────────────────────────────────────────────────
    p = sub.add_parser("scan", help="Full remote scan")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--modules", "-m", type=str)
    p.add_argument("--all", "-a", action="store_true")
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("-o", "--output", dest="output_file", type=str)
    p.add_argument("--timeout", "-t", type=_positive_int(1, 600), default=8)
    p.add_argument("--insecure", "-k", action="store_true")
    p.add_argument("--rate-limit", type=_positive_float(0.1, 1000.0), default=10.0)
    p.add_argument("--engineering", action="store_true", help="Run engineering pipeline after scan")
    p.add_argument("--intelligence", action="store_true", help="Enable intelligence pipeline (default: on)")
    p.add_argument("--no-intelligence", action="store_true", help="Disable intelligence pipeline")
    p.add_argument("--quality", action="store_true", help="Enable quality intelligence scoring")
    p.add_argument("--defense", action="store_true", help="Enable prompt defense validation on AI inputs")

    # ── vibesec ───────────────────────────────────────────────────
    p = sub.add_parser("vibesec", help="Quick VibeSec benchmark")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("-o", "--output", dest="output_file", type=str)
    p.add_argument("--timeout", "-t", type=_positive_int(1, 600), default=8)
    p.add_argument("--insecure", "-k", action="store_true")
    p.add_argument("--rate-limit", type=_positive_float(0.1, 1000.0), default=10.0)

    # ── audit ────────────────────────────────────────────────────
    p = sub.add_parser("audit", help="Full machine audit (ports, firewall, SSH, Docker, env, files)")
    p.add_argument("--modules", "-m", type=str)
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("-o", "--output", dest="output_file", type=str)
    p.add_argument("--engineering", action="store_true", help="Run engineering pipeline after audit")
    p.add_argument("--intelligence", action="store_true", help="Enable intelligence pipeline (default: on)")
    p.add_argument("--no-intelligence", action="store_true", help="Disable intelligence pipeline")
    p.add_argument("--quality", action="store_true", help="Enable quality intelligence scoring")
    p.add_argument("--defense", action="store_true", help="Enable prompt defense validation on AI inputs")

    # ── dev ───────────────────────────────────────────────────────
    p = sub.add_parser("dev", help="Developer project scan (secrets, deps, git, docker)")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("-o", "--output", dest="output_file", type=str)

    # ── doctor (full definition: see plugin/T5 section below) ────

    # ── ports ─────────────────────────────────────────────────────
    p = sub.add_parser("ports", help="Show open ports and risky services")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── secrets ────────────────────────────────────────────────────
    p = sub.add_parser("secrets", help="Find secrets in env vars and codebase")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── list ──────────────────────────────────────────────────────
    p = sub.add_parser("list", help="List available modules")
    p.add_argument("--local", action="store_true")
    p.add_argument("--all", action="store_true")

    # ── NEXUS ────────────────────────────────────────────────────
    sub.add_parser("nexus", help="Launch NEXUS — mind-blowing agent TUI (mouse + keyboard + split-screen)")

    # ── chat ──────────────────────────────────────────────────────
    sub.add_parser("chat", help="Interactive chat mode — talk to ReconPro")

    # ── tui ───────────────────────────────────────────────────────
    sub.add_parser("tui", help="Visual terminal dashboard")

    # ── blitz ─────────────────────────────────────────────────────
    p = sub.add_parser("blitz", help="Parallel multi-target scan")
    p.add_argument("targets", nargs="+", help="Target domains/URLs")
    p.add_argument("--workers", "-w", type=int, default=4)
    p.add_argument("--modules", "-m", type=str)

    # ── agent ─────────────────────────────────────────────────────
    p = sub.add_parser("agent", help="Autonomous agent — give it a goal")
    p.add_argument("goal", help="Natural language goal (e.g. 'fully scan example.com and find subdomains')")

    # ── subdomains ────────────────────────────────────────────────
    p = sub.add_parser("subdomains", help="Discover subdomains")
    p.add_argument("domain", help="Domain to enumerate")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── schedule ──────────────────────────────────────────────────
    p = sub.add_parser("schedule", help="Schedule recurring scans")
    p.add_argument("target", help="Target domain, URL, or 'audit'")
    p.add_argument("--every", "-e", type=str, default="1h", help="Interval: 30m, 1h, 6h, 1d")
    p.add_argument("--modules", "-m", type=str)
    p.add_argument("--max-runs", type=int, default=0, help="Max runs (0=forever)")

    # ── serve ─────────────────────────────────────────────────────
    p = sub.add_parser("serve", help="Start REST API server")
    p.add_argument("--port", "-p", type=int, default=7890)

    # ── report ────────────────────────────────────────────────────
    p = sub.add_parser("report", help="Generate production report (markdown/JSON/HTML) from last scan")
    p.add_argument("-i", "--input", type=str, help="JSON scan file (default: last scan)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output JSON report")
    p.add_argument("--html", action="store_true", help="Output HTML report (default if omitted without --json)")
    p.add_argument("--markdown", action="store_true", help="Output Markdown report (default text format)")
    p.add_argument("-o", "--output", dest="output_file", type=str, help="Write report to file instead of stdout")

    # ── dashboard ─────────────────────────────────────────────────
    p = sub.add_parser("dashboard", help="Unified status dashboard")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── history ───────────────────────────────────────────────────
    p = sub.add_parser("history", help="View scan history")
    p.add_argument("target", nargs="?", default=None)
    p.add_argument("--limit", "-n", type=int, default=10)
    p.add_argument("--clear", action="store_true", help="Delete all history")

    # ── diff ───────────────────────────────────────────────────────
    p = sub.add_parser("diff", help="Compare two scan results")
    p.add_argument("a", nargs="?", default=None, help="First scan file or 'last'")
    p.add_argument("b", nargs="?", default=None, help="Second scan file or 'last-2'")

    # ── screenshot ────────────────────────────────────────────────
    p = sub.add_parser("screenshot", help="Take browser screenshot (needs: pip install reconpro[browser])")
    p.add_argument("url", help="URL to screenshot")

    # ── open ───────────────────────────────────────────────────────
    p = sub.add_parser("open", help="Open URL in browser")
    p.add_argument("url", help="URL to open")

    # ── plugin ────────────────────────────────────────────────────
    p = sub.add_parser("plugin", help="Plugin management (sandboxed SDK)")
    p.add_argument("action", choices=[
        "list", "create", "create-sdk", "run", "install", "verify",
        "upgrade", "remove", "sign", "keys",
    ], help="Action")
    p.add_argument("name", nargs="?", default=None,
                   help="Plugin id / path / name (action-dependent)")
    p.add_argument("target", nargs="?", default=None, help="Target (run action)")
    p.add_argument("--allow-unsigned", action="store_true",
                   help="install: accept unsigned plugins (recorded untrusted)")
    p.add_argument("--json", dest="json_output", action="store_true",
                   help="Machine-readable output")

    # ── doctor / tutorial / wizard / playground / suggest ──────────
    p_doc = sub.add_parser("doctor", help="Health check with fix commands")
    p_doc.add_argument("--repair", action="store_true",
                       help="Automatically apply safe fixes (cache clear, stale "
                            "workspace prune, permission repair, pip check)")
    p_doc.add_argument("--json", dest="json_output", action="store_true")
    p_doc.add_argument("-o", "--output", dest="output_file", type=str)

    p_tut = sub.add_parser("tutorial", help="Interactive guided tutorial")
    p_tut.add_argument("--step", type=int, default=None,
                       help="Jump to a specific step (1-8)")
    p_tut.add_argument("--list", action="store_true", help="List tutorial steps")

    p_wiz = sub.add_parser("wizard", help="Interactive scan wizard (guided Q&A)")
    p_wiz.add_argument("--non-interactive", action="store_true",
                       help="Print the recommended plan without asking")

    p_play = sub.add_parser("playground", help="Sandboxed plugin playground (safe lab)")
    p_play.add_argument("file", nargs="?", default=None,
                        help="Plugin .py file to experiment with")
    p_play.add_argument("--target", "-t", default="example.com")

    p_sug = sub.add_parser("suggest", help="Suggest next commands based on state")
    p_sug.add_argument("--json", dest="json_output", action="store_true")

    # ── swarm ─────────────────────────────────────────────────────
    p = sub.add_parser("swarm", help="Swarm attack: SCOUT→HACKER→CODER→GUARDIAN")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--mode", "-m", type=str, default="full",
                     choices=["full", "recon", "attack", "fix", "verify"])

    # ── adversarial ────────────────────────────────────────────────
    p = sub.add_parser("adversarial", help="Adversarial self-play: hacker vs coder loop")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--rounds", "-r", type=int, default=3)
    p.add_argument("--modules", "-m", type=str)
    p.add_argument("--local", action="store_true", help="Target is local machine")

    # ── ast ─────────────────────────────────────────────────────────
    p = sub.add_parser("ast", help="AST code analysis (Python/JS/TS vulnerability patterns)")
    p.add_argument("path", nargs="?", default=".", help="File or directory to analyze")

    # ── cve ─────────────────────────────────────────────────────────
    p = sub.add_parser("cve", help="CVE/NVD threat intelligence lookup")
    p.add_argument("query", help="Search query (e.g. 'SQL injection', 'CVE-2024-1234')")
    p.add_argument("--limit", "-n", type=int, default=5)

    # ── graph ───────────────────────────────────────────────────────
    p = sub.add_parser("graph", help="Knowledge graph: attack surface, blast radius, chains")
    p.add_argument("target", nargs="?", default=None, help="Target (default: use last scan)")
    p.add_argument("--action", "-a", type=str, default="stats",
                     choices=["stats", "chains", "surface", "blast", "export"])

    # ── iac ──────────────────────────────────────────────────────────
    p = sub.add_parser("iac", help="Infrastructure-as-Code audit (Terraform/CF/Docker/K8s)")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── container ──────────────────────────────────────────────────────
    p = sub.add_parser("container", help="Container escape analysis (Dockerfile + K8s)")
    p.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── cloud-recon ─────────────────────────────────────────────────────
    p = sub.add_parser("cloud-recon", help="Cloud infrastructure recon (AWS/Azure/GCP metadata + assets)")
    p.add_argument("target", help="Target domain or 'local' for metadata probe")
    p.add_argument("--json", dest="json_output", action="store_true")

    # ── defense ────────────────────────────────────────────────────────
    p = sub.add_parser("defense", help="Generate deployable fixes (WAF rules, patches, IaC fixes)")
    p.add_argument("-i", "--input", type=str, help="JSON scan file (default: last scan)")

    # ── fuzzer ──────────────────────────────────────────────────────────
    p = sub.add_parser("fuzzer", help="Context-aware payload fuzzing")
    p.add_argument("url", help="Target URL to fuzz")
    p.add_argument("--param", "-p", type=str, help="Specific parameter to fuzz")
    p.add_argument("--category", "-c", type=str, help="Payload category (sqli, xss, ssti, ...)")

    # ── profile ─────────────────────────────────────────────────────────
    p = sub.add_parser("profile", help="Target fingerprinting + auto scan plan")
    p.add_argument("target", help="Target domain or URL")

    # ── compliance ───────────────────────────────────────────────────────
    p = sub.add_parser("compliance", help="Compliance mapping (SOC2/ISO/PCI/HIPAA/GDPR/CIS)")
    p.add_argument("--frameworks", "-f", type=str, default="soc2,pci-dss",
                     help="Comma-separated frameworks")
    p.add_argument("-i", "--input", type=str, help="JSON scan file (default: last scan)")

    # ── delta ───────────────────────────────────────────────────────────
    p = sub.add_parser("delta", help="Dynamic delta report (compare scans with git blame)")
    p.add_argument("target", nargs="?", default=None, help="Target (default: use last scan)")
    p.add_argument("--format", "-f", type=str, default="markdown", choices=["markdown", "sarif"])

    # ── benchmark ───────────────────────────────────────────────────────
    p = sub.add_parser("benchmark", help="Score tracking + competitive leaderboard")
    p.add_argument("targets", nargs="*", help="Targets to benchmark")
    p.add_argument("--days", "-d", type=int, default=30)
    p.add_argument("--leaderboard", action="store_true", help="Show leaderboard")

    # ── graph-visual ────────────────────────────────────────────────────
    p = sub.add_parser("graph-visual", help="Interactive D3.js knowledge graph visualization")
    p.add_argument("-o", "--output", type=str, default="reconpro_graph.html", help="Output HTML file")

    # ── netmap ──────────────────────────────────────────────────────────
    p = sub.add_parser("netmap", help="Network topology + trust mapping + lateral paths")
    p.add_argument("--subnet", "-s", type=str, help="Subnet to scan (e.g. 192.168.1.0/24)")

    # ── passive ─────────────────────────────────────────────────────────
    p = sub.add_parser("passive", help="Passive DNS + historical intel (VirusTotal, Wayback)")
    p.add_argument("domain", help="Domain to query")

    # ── export ──────────────────────────────────────────────────────────
    p = sub.add_parser("export", help="Export last scan to SARIF/MD/JSON/HTML")
    p.add_argument("output", nargs="?", default="reconpro_report.sarif",
                     help="Output path (format auto-detected from extension)")

    # ── zai (z.ai live stream) ──────────────────────────────────────────
    p = sub.add_parser("zai", help="z.ai live stream AI analysis — zero config, no API keys needed")
    p.add_argument("target", nargs="?", default="", help="Target to scan and analyze (optional: uses last scan if omitted)")
    p.add_argument("--stream", action="store_true", help="Stream AI analysis in real-time (default)")
    p.add_argument("--no-stream", action="store_true", help="Return complete analysis at once")
    p.add_argument("--chat", type=str, default="", help="Free-form chat message (skips scan)")
    p.add_argument("--health", action="store_true", help="Health check: verify z.ai connectivity")
    p.add_argument("--model", type=str, default="glm-4-flash", help="Model name (default: glm-4-flash)")

    # ── wishes (v9.1.0 22-Wish Ritual) ───────────────────────────
    p = sub.add_parser("wishes", help="Execute 22-Wish orchestration ritual against a target")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--modules", "-m", type=str, default=None, help="Comma-separated modules to include")
    p.add_argument("--timeout", type=_positive_int(1, 600), default=8)
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── geoip (v9.1.0 GeoIP Enrichment) ──────────────────────────
    p = sub.add_parser("geoip", help="GeoIP enrichment for IP addresses")
    p.add_argument("ips", nargs="+", help="IP addresses to enrich")
    p.add_argument("--batch", action="store_true", help="Use batch API for multiple IPs")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── threat-feeds (v9.1.0 Threat Feed Ingestion) ───────────────
    p = sub.add_parser("threat-feeds", help="Threat feed ingestion and IP reputation checking")
    p.add_argument("ips", nargs="*", help="IPs to check (checks all feeds + DNSBLs)")
    p.add_argument("--refresh", action="store_true", help="Force refresh all feeds")
    p.add_argument("--stats", action="store_true", help="Show feed statistics only")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── ai-redteam (v9.1.0 AI Red Team) ──────────────────────────
    p = sub.add_parser("ai-redteam", help="AI endpoint discovery, vendor fingerprinting, secret extraction")
    p.add_argument("target", help="Target domain or URL")
    p.add_argument("--timeout", type=_positive_int(1, 600), default=8)
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── supply-chain (v9.1.0 Supply Chain Audit) ─────────────────
    p = sub.add_parser("supply-chain", help="Supply chain audit — GitHub repos or web content analysis")
    p.add_argument("target", help="GitHub repo (owner/repo) or URL to audit")
    p.add_argument("--max-files", type=int, default=30, help="Max files to scrape (GitHub)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── cross-validate (v9.1.0 Cross-Validation) ──────────────────
    p = sub.add_parser("cross-validate", help="Cross-validate ReconPro findings with independent verification")
    p.add_argument("target", nargs="?", default=None, help="Target (default: use last scan)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── quantum-fingerprint (v9.2.0 TCP/IP Stack Fingerprinting via HTTP Timing) ──
    p = sub.add_parser("quantum-fingerprint", help="OS & TCP stack fingerprinting via HTTP timing analysis")
    p.add_argument("target", help="Domain or URL to fingerprint")
    p.add_argument("-t", "--timeout", type=_positive_int(1, 600), default=15, help="Per-probe timeout (default: 15)")
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── dark-web (v9.2.0 Credential Leak & Exposure Scanner) ──────
    p = sub.add_parser("dark-web", help="Monitor paste sites & threat feeds for credential leaks")
    p.add_argument("target", help="Domain, email, keyword, or IP to search")
    p.add_argument("--deep", action="store_true", help="Enable deep scan (more sources)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── info-ops (v9.2.0 Information Operations Analysis) ─────────
    p = sub.add_parser("info-ops", help="Information operations & deception analysis (defensive)")
    p.add_argument("target", help="Domain or URL to analyze")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── steg (v9.2.0 Steganography Detection) ───────────────────
    p = sub.add_parser("steg", help="Detect hidden data in HTTP responses & images")
    p.add_argument("target", help="URL or domain to scan for steganography")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── covert (v9.2.0 Covert Channel Detection) ─────────────────
    p = sub.add_parser("covert", help="Detect & simulate covert channels (DNS/ICMP/timing)")
    p.add_argument("target", help="Domain or URL to analyze")
    p.add_argument("--mode", choices=["detect", "simulate"], default="detect", help="detect or simulate covert channels")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── zero-day (v9.2.0 Zero-Day Pattern Hunter) ────────────────
    p = sub.add_parser("zero-day", help="Hunt for zero-day vulnerability patterns in responses")
    p.add_argument("target", help="URL or domain to hunt")
    p.add_argument("--deep", action="store_true", help="Deep analysis mode")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── ghost (v9.2.0 Infrastructure Ghosting) ───────────────────
    p = sub.add_parser("ghost", help="Clone & ghost infrastructure for deception analysis")
    p.add_argument("target", help="Domain or URL to ghost")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── sigint (v9.2.0 HTTP Traffic SIGINT) ───────────────────────
    p = sub.add_parser("sigint", help="Signal intelligence analysis of HTTP traffic patterns")
    p.add_argument("target", help="Domain or URL for SIGINT analysis")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── attributor (v9.2.0 Nation-State Attribution Engine) ─────
    p = sub.add_parser("attributor", help="Attribute attack infrastructure to nation-state actors")
    p.add_argument("target", help="Domain, IP, or URL to attribute")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── weaponized-report (v9.2.0 Weaponized Report Gen) ─────────
    p = sub.add_parser("weaponized-report", help="Generate weaponized decoy reports (defensive)")
    p.add_argument("target", help="Domain or URL context")
    p.add_argument("--format", choices=["html", "pdf", "json"], default="html", help="Output format")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── honeypot (v9.2.0 Honeypot Detection) ─────────────────────
    p = sub.add_parser("honeypot", help="Detect honeypots & score infrastructure legitimacy")
    p.add_argument("target", help="Domain, IP, or URL to check")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── rate (v9.2.0 Module Rating System) ──────────────────────
    p = sub.add_parser("rate", help="Rate all v11 modules against industry tools /100")
    p.add_argument("--module", "-m", type=str, default=None,
                     help="Rate a specific module (e.g. dead-drop, quantum-fingerprint)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── dead-drop (v9.2.0 Cryptographic Dead Drop) ────────────────
    p = sub.add_parser("dead-drop", help="Detect cryptographic dead drops in DNS/HTTP/CT logs")
    p.add_argument("target", help="Domain or URL to scan")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── info (Diagnostics & Help) ────────────────────────────────
    p = sub.add_parser("info", help="Module help, diagnostics, and version info")
    p.add_argument("--module", "-m", type=str, default=None,
                     help="Show detailed help for a module (e.g. quantum-fingerprint)")
    p.add_argument("--modules", action="store_true",
                     help="List all modules with descriptions")
    p.add_argument("--diagnose", action="store_true",
                     help="Run full system diagnostics")
    p.add_argument("--health", action="store_true",
                     help="Quick health check")
    p.add_argument("--version", "-v", action="store_true", dest="info_version",
                     help="Detailed version information")
    p.add_argument("--examples", action="store_true",
                     help="Show usage examples")
    p.add_argument("--quick-start", action="store_true",
                     help="Show quick-start guide")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── Engineering Commands (Age III) ────────────────────────
    p = sub.add_parser("engineering", help="Run full engineering pipeline (health, drift, quality gates)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")
    p.add_argument("--repo", type=str, default=".", help="Repository path to analyze")

    p = sub.add_parser("validate", help="Run auto-validation pipeline (syntax, imports, types, security, perf)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")
    p.add_argument("--repo", type=str, default=".", help="Repository path to validate")

    p = sub.add_parser("benchmark-engineering", help="Run engineering benchmarks with regression detection")
    p.add_argument("--quick", action="store_true", help="Quick benchmark subset")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    p = sub.add_parser("recommendations", help="View engineering recommendations")
    p.add_argument("--all", action="store_true", help="Show all including dismissed")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")
    p.add_argument("--dismiss", type=str, default=None, help="Dismiss a recommendation by ID")

    p = sub.add_parser("memory", help="Repository memory — store, recall, search engineering facts")
    p.add_argument("--recall", type=str, default=None, help="Recall a fact by key")
    p.add_argument("--search", type=str, default=None, help="Search facts by text")
    p.add_argument("--stats", action="store_true", help="Show memory statistics")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    p = sub.add_parser("digital-twin", help="Digital twin — capture state, simulate changes, detect anomalies")
    p.add_argument("--capture", action="store_true", help="Capture current system state")
    p.add_argument("--anomaly", action="store_true", help="Detect anomalies vs baseline")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    p = sub.add_parser("auto-fix", help="Propose fixes for detected issues")
    p.add_argument("--apply", action="store_true", help="Apply approved fixes (dry-run by default)")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    p = sub.add_parser("regression", help="Regression intelligence — detect and report regressions")
    p.add_argument("--baseline", action="store_true", help="Capture new baseline")
    p.add_argument("--detect", action="store_true", help="Detect regressions vs baseline")
    p.add_argument("--report", action="store_true", help="Generate regression report")
    p.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── health ──────────────────────────────────────────────────
    p_health = sub.add_parser("health", help="Show module health scores and circuit breaker status")
    p_health.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── deps ────────────────────────────────────────────────────
    p_deps = sub.add_parser("deps", help="Visualize module dependency graph")
    p_deps.add_argument("--modules", "-m", type=str, default=None, help="Comma-separated module list (default: all)")
    p_deps.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── palette ──────────────────────────────────────────────
    p_palette = sub.add_parser("palette", help="Interactive command palette (Ctrl+K)")
    p_palette.add_argument("--theme", type=str, default=None, help="Override theme")

    # ── theme ──────────────────────────────────────────────────
    p_theme = sub.add_parser("theme", help="Manage terminal themes")
    p_theme.add_argument("action", nargs="?", default="list", choices=["list", "set", "current"], help="list|set|current")
    p_theme.add_argument("name", nargs="?", help="Theme name to set")

    # ── workspace ──────────────────────────────────────────────
    p_ws = sub.add_parser("workspace", help="Manage scan workspaces")
    p_ws.add_argument("action", nargs="?", default="list", choices=["list", "create", "switch", "delete", "import", "export"], help="Action")
    p_ws.add_argument("name", nargs="?", help="Workspace name")
    p_ws.add_argument("--targets", "-t", type=str, help="Comma-separated targets (for create)")
    p_ws.add_argument("--format", "-f", type=str, default="json", help="Export format (json/text)")

    # ── notifications ──────────────────────────────────────────
    p_notif = sub.add_parser("notifications", help="View notification center")
    p_notif.add_argument("--level", "-l", type=str, help="Filter by level (CRITICAL/WARNING/INFO/SUCCESS)")
    p_notif.add_argument("--limit", "-n", type=int, default=20, help="Max notifications to show")
    p_notif.add_argument("--digest", "-d", action="store_true", help="Show digest")
    p_notif.add_argument("--clear", action="store_true", help="Clear all notifications")
    p_notif.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── copilot ───────────────────────────────────────────────
    p_copilot = sub.add_parser("copilot", help="AI Copilot — explain, summarize, remediate, compare")
    p_copilot.add_argument("action", nargs="?", default="chat", choices=["chat", "explain", "summarize", "remediate", "compare"], help="Action")
    p_copilot.add_argument("args", nargs="*", help="Arguments (finding title, question, etc.)")
    p_copilot.add_argument("--finding", type=str, help="Finding title to explain")
    p_copilot.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    # ── Parse (STRICT — unknown/unrecognized arguments are a hard error, exit 2) ──
    global _cli_args
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    # Implicit scan shorthand: `reconpro <target> [flags]` → `reconpro scan ...`
    # STRICT GUARD: only arguments that look like real scan targets (URLs,
    # IPv4/IPv6 literals, dotted domains, localhost) keep the shorthand.
    # Anything else (e.g. a typo'd subcommand) must fail fast with exit 2
    # BEFORE any network activity — never silently start a scan.
    if argv and not argv[0].startswith("-") and argv[0] not in sub.choices:
        if looks_like_scan_target(argv[0]):
            argv = ["scan"] + argv
        else:
            _reject_unknown_command(argv[0], sub.choices)
    args = parser.parse_args(argv)
    _cli_args = args
    cmd = args.subcommand

    # Deterministic Ctrl+C for everything that is not an interactive TUI.
    if cmd not in _TUI_COMMANDS:
        _install_sigint_handler()
    remaining: list[str] = []  # strict mode: never populated (kept for compat)

    # Fast paths skip the heavy engine import (~300 ms) entirely.
    if cmd not in _FAST_SUBCOMMANDS and not (cmd == "doctor" and getattr(args, "repair", False)):
        _load_heavy()

    # ── LIST ───────────────────────────────────────────────────────
    if cmd == "list":
        show_all = getattr(args, "all", False)
        show_local = getattr(args, "local", False)
        if show_local or show_all:
            console.print("\n[bold bright_yellow]Local Modules:[/bold bright_yellow]\n")
            for mid, e in LOCAL_MODULES.items():
                d = " (default)" if mid in DEFAULT_LOCAL_MODULES else ""
                console.print(f"  [cyan]{mid:12}[/] {e['name']:18}{d}")
        if not show_local or show_all:
            console.print("\n[bold]Remote Modules:[/bold]\n")
            for mid, e in MODULE_REGISTRY.items():
                d = " (default)" if mid in DEFAULT_MODULES else ""
                console.print(f"  [cyan]{mid:12}[/] {e['name']:18}{d}")
        console.print(f"\n  [dim]Total: {len(ALL_MODULES)} modules[/]\n")
        return

    # ── IAC ─────────────────────────────────────────────────────────
    if cmd == "iac":
        _banner(args)
        result = _spinner_wrap(f"Auditing IaC at {args.path}...", audit_scan, target=args.path, modules=["iac_audit"])
        _output_result(result, args, title="IAC AUDIT", show_remediation=True)
        return

    # ── CONTAINER ─────────────────────────────────────────────────
    if cmd == "container":
        _banner(args)
        result = _spinner_wrap(f"Analyzing containers at {args.path}...", audit_scan, target=args.path, modules=["container_sec"])
        _output_result(result, args, title="CONTAINER SECURITY", show_remediation=True)
        return

    # ── CLOUD-RECON ──────────────────────────────────────────────────
    if cmd == "cloud-recon":
        target = args.target
        from .modules.cloud_recon import run_cloud_recon
        findings = _spinner_wrap(f"Cloud recon on {target}...", run_cloud_recon, target, target if target.startswith("http") else f"https://{target}")
        if getattr(args, 'json_output', False):
            print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        else:
            _banner(args)
            if findings:
                for f in findings:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
                console.print(f"  [bold]{len(findings)} cloud finding(s).[/]")
            else:
                console.print("  [dim]No cloud findings.[/]")
            console.print()
        return

    # ── DEFENSE ────────────────────────────────────────────────────
    if cmd == "defense":
        data = None
        if getattr(args, "input", None):
            with open(args.input) as f:
                data = json.load(f)
        if not data:
            data = get_latest()
        if not data:
            if getattr(args, 'json_output', False):
                print(json.dumps({"error": "no scan data", "message": "Run a scan first"}, indent=2))
            else:
                console.print("  [yellow]No scan data. Run a scan first.[/]")
            sys.exit(1)
        from .defense import generate_defense_bundle
        bundle = _spinner_wrap("Generating defenses...", generate_defense_bundle, data.get("target", "unknown"), data.get("findings", []))
        console.print(Panel(bundle.to_report(), border_style="green", title="[bold]DEFENSE BUNDLE[/bold]", padding=(1, 2)))
        console.print()
        return

    # ── FUZZER ────────────────────────────────────────────────────
    if cmd == "fuzzer":
        _banner(args)
        from .fuzzer import FuzzSession, TechDetector
        url = args.url
        base = url if url.startswith("http") else f"https://{url}"
        profile = _spinner_wrap(f"Detecting tech on {base}...", TechDetector().analyze, base)
        console.print(f"  [cyan]Detected:[/] {', '.join(profile.frameworks) or 'unknown'}")
        console.print(f"  [cyan]Language:[/] {profile.language or 'unknown'}")
        console.print(f"  [cyan]WAF:[/] {profile.waf or 'none'}")
        category = getattr(args, "category", None) or "sqli"
        session = FuzzSession(base, profile)
        payloads = session.select_payloads(category)
        console.print(f"  [yellow]{len(payloads)} {category} payloads loaded (tech-aware selection)[/]")
        console.print()
        return

    # ── PROFILE ────────────────────────────────────────────────────
    if cmd == "profile":
        _banner(args)
        from .profiler import profile_target, get_scan_plan
        target = args.target
        profile = _spinner_wrap(f"Profiling {target}...", profile_target, target)
        plan = get_scan_plan(target)
        console.print(f"  [cyan]Frameworks:[/] {', '.join(profile.frameworks) or 'none'}")
        console.print(f"  [cyan]Language:[/] {profile.language or 'unknown'}")
        console.print(f"  [cyan]Server:[/] {profile.server or 'unknown'}")
        console.print(f"  [cyan]WAF:[/] {profile.waf or 'none'}")
        console.print(f"  [cyan]App Type:[/] {profile.app_type}")
        console.print(f"  [bold]Recommended:[/] {', '.join(plan.get('recommended_modules', []))}")
        console.print(f"  [dim]{plan.get('reasoning', '')}[/]")
        console.print()
        return

    # ── WISHES (v9.1.0) ─────────────────────────────────────────
    if cmd == "wishes":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None

        # Run scan first to get module results
        result = _spinner_wrap(f"Scanning {target}...", scan, target, modules=modules,
                                timeout=args.timeout, verify_tls=not args.insecure, rate_limit=10.0)

        from .wishes import WishesOrchestrator
        orchestrator = WishesOrchestrator()
        manifest = _spinner_wrap(
            f"Executing 22-Wish ritual on {target}...",
            orchestrator.execute,
            target=target, base_url=base_url,
            timeout=args.timeout, verify_tls=not args.insecure,
            modules=result.modules_run, module_results=result.module_results,
        )

        if getattr(args, "json_output", False):
            print(json.dumps(manifest, indent=2, default=str))
        else:
            verdict = manifest.get("verdict", {}).get("verdict", "?")
            fear = manifest.get("fear", {})
            console.print(f"  [bold]22-Wish Ritual Complete[/]")
            console.print(f"  [cyan]Verdict:[/] {verdict}")
            console.print(f"  [cyan]Fear Index:[/] {fear.get('fear_index', 0)} ({fear.get('fear_label', '?')})")
            console.print(f"  [cyan]Wishes Granted:[/] {len(manifest.get('wishes_granted', []))}/{manifest.get('wishes_count', 22)}")
            console.print(f"  [cyan]Witness ID:[/] {manifest.get('witness', {}).get('encounter_id', '?')}")
            hall_b = manifest.get('hall_broken', {})
            console.print(f"  [cyan]Hall of Broken:[/] {hall_b.get('total_encounters', 0)} encounters, avg fear {hall_b.get('average_fear', 0)}")
            hall_f = manifest.get('hall_forgotten', {})
            console.print(f"  [cyan]Hall of Forgotten:[/] {hall_f.get('total_encounters', 0)} encounters, avg dread {hall_f.get('average_dread', 0)}")
        console.print()
        return

    # ── GEOIP (v9.1.0) ────────────────────────────────────────────
    if cmd == "geoip":
        _banner(args)
        ips = args.ips
        from .geoip import GeoIPLookup, BatchGeoIP, format_geoip_summary
        if getattr(args, 'batch', False) and len(ips) > 1:
            batch = BatchGeoIP()
            results = _spinner_wrap(f"Enriching {len(ips)} IPs...", batch.enrich_batch, ips)
            if getattr(args, 'json_output', False):
                print(json.dumps(results, indent=2, default=str))
            else:
                for ip, data in results.items():
                    console.print(f"  {format_geoip_summary(data)}")
        else:
            geo = GeoIPLookup()
            for ip in ips:
                result = geo.enrich_ip(ip)
                if getattr(args, 'json_output', False):
                    print(json.dumps(result, indent=2, default=str))
                else:
                    console.print(f"  {format_geoip_summary(result)}")
        console.print()
        return

    # ── THREAT-FEEDS (v9.1.0) ─────────────────────────────────────
    if cmd == "threat-feeds":
        _banner(args)
        from .threat_feeds import ThreatFeedManager, DNSBLChecker, check_ip_reputation
        if getattr(args, 'stats', False):
            mgr = ThreatFeedManager()
            stats = _spinner_wrap("Fetching feed stats...", mgr.refresh_all, force=getattr(args, 'refresh', False))
            if getattr(args, 'json_output', False):
                print(json.dumps(stats, indent=2, default=str))
            else:
                console.print("  [bold]Threat Feed Statistics:[/]")
                for name, count in stats.items():
                    console.print(f"  [cyan]{name:25}[/] {count:>6} indicators")
        elif getattr(args, 'ips', None):
            ips = args.ips
            for ip in ips:
                result = _spinner_wrap(f"Checking {ip}...", check_ip_reputation, ip)
                if getattr(args, 'json_output', False):
                    print(json.dumps(result, indent=2, default=str))
                else:
                    is_mal = result.get('is_malicious', False)
                    color = "bright_red" if is_mal else "bright_green"
                    console.print(f"  [{color}]{ip:18}[/{color}]  score={result.get('threat_score', 0)}  feeds={len(result.get('threat_feeds', []))}  dnsbl={len(result.get('dnsbl_hits', []))}")
                    for hit in result.get('threat_feeds', []):
                        console.print(f"    [red]  Feed:[/] {hit['feed']}")
                    for hit in result.get('dnsbl_hits', []):
                        console.print(f"    [red]  DNSBL:[/] {hit['dnsbl']}")
        else:
            mgr = ThreatFeedManager()
            stats = _spinner_wrap("Refreshing threat feeds...", mgr.refresh_all, force=getattr(args, 'refresh', False))
            if getattr(args, 'json_output', False):
                print(json.dumps(stats, indent=2, default=str))
            else:
                console.print("  [bold]Threat Feed Refresh Complete:[/]")
                for name, count in stats.items():
                    status_color = "bright_green" if count >= 0 else "bright_red"
                    console.print(f"  [{status_color}]{name:25}[/{status_color}] {count:>6} indicators")
        console.print()
        return

    # ── AI-REDTEAM (v9.1.0) ───────────────────────────────────────
    if cmd == "ai-redteam":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .ai_red_team import run_ai_red_team
        results = _spinner_wrap(f"AI red-teaming {target}...", run_ai_red_team, target, base_url,
                                timeout=args.timeout, verify_tls=not args.insecure)
        if getattr(args, 'json_output', False):
            print(json.dumps(results, indent=2, default=str))
        else:
            console.print(f"  [cyan]Endpoints Discovered:[/] {results.get('endpoints_discovered', 0)}")
            console.print(f"  [cyan]Vendors Detected:[/] {results.get('vendors_detected', 0)}")
            console.print(f"  [cyan]Secrets Found:[/] {results.get('secrets_found', 0)}")
            console.print(f"  [cyan]Total Risk Score:[/] {results.get('total_risk_score', 0)}")
            for ep in results.get('endpoints', [])[:10]:
                ai_tag = " [bright_green]AI[/]" if ep.get('has_ai_content') else ""
                console.print(f"    [dim]{ep['status']}[/] {ep['endpoint']:45}{ai_tag}")
            for v in results.get('vendors', []):
                console.print(f"    [yellow]Vendor:[/] {v['vendor']:20} score={v['score']}")
            for s in results.get('secrets', []):
                sev_color = SEV_COLORS.get(s['severity'], 'white')
                console.print(f"    [{sev_color}]{s['severity'].upper():8}[/{sev_color}] {s['type']}: {s['match']}")
        console.print()
        return

    # ── SUPPLY-CHAIN (v9.1.0) ─────────────────────────────────────
    if cmd == "supply-chain":
        _banner(args)
        target = args.target
        from .supply_chain import SCCAudit
        audit = SCCAudit()
        if "/" in target and not target.startswith("http"):
            results = _spinner_wrap(f"Auditing {target}...", audit.audit_github, target, max_files=args.max_files)
            if getattr(args, 'json_output', False):
                print(json.dumps(results, indent=2, default=str))
            else:
                analysis = results.get('analysis', {})
                console.print(f"  [cyan]Files Scraped:[/] {results.get('files_scraped', 0)}")
                console.print(f"  [cyan]API Requests:[/] {results.get('api_requests', 0)}")
                console.print(f"  [cyan]Workflows Found:[/] {results.get('workflows_found', 0)}")
                console.print(f"  [cyan]Secrets Found:[/] {len(analysis.get('secrets_found', []))}")
                console.print(f"  [cyan]Risk Score:[/] {analysis.get('risk_score', 0)}")
                for dep in analysis.get('dependency_files', []):
                    console.print(f"    [cyan]{dep['manager']:10}[/] {dep['file']}")
                for s in analysis.get('secrets_found', []):
                    console.print(f"    [red]{s['type']:20}[/] {s['file']}")
                for sp in analysis.get('suspicious_patterns', []):
                    console.print(f"    [yellow]{sp['pattern']}[/] in {sp.get('file', '?')}")
        else:
            results = _spinner_wrap(f"Auditing {target}...", audit.audit_url, target)
            if getattr(args, 'json_output', False):
                print(json.dumps(results, indent=2, default=str))
            else:
                page = results.get('page', {})
                console.print(f"  [cyan]Status:[/] {page.get('status', 0)}")
                console.print(f"  [cyan]Title:[/] {page.get('title', '?')}")
                console.print(f"  [cyan]Links:[/] {len(page.get('links', []))}")
                console.print(f"  [cyan]Scripts:[/] {len(page.get('scripts', []))}")
        console.print()
        return

    # ── CROSS-VALIDATE (v9.1.0) ───────────────────────────────────
    if cmd == "cross-validate":
        target = getattr(args, 'target', None)
        findings = []
        if target:
            latest = get_latest()
            if latest and latest.get('target', '') == target.replace('https://', '').replace('http://', '').split('/')[0]:
                findings = latest.get('findings', [])
            else:
                _banner(args)
                result = _spinner_wrap(f"Scanning {target}...", scan, target, timeout=8, verify_tls=True, rate_limit=10.0)
                findings = result.findings
        else:
            latest = get_latest()
            if not latest:
                console.print("  [yellow]No scan data. Run a scan first or specify a target.[/]")
                sys.exit(1)
            target = latest.get('target', 'unknown')
            findings = latest.get('findings', [])

        _banner(args)
        from .cross_validator import CrossValidator
        base_url = target if target.startswith('http') else f'https://{target}'
        cv_results = _spinner_wrap(f"Cross-validating {target}...", CrossValidator().validate, target, findings, base_url)
        if getattr(args, 'json_output', False):
            print(json.dumps(cv_results, indent=2, default=str))
        else:
            vr = cv_results.get('verification_rate', 0)
            color = 'bright_green' if vr >= 80 else 'yellow' if vr >= 50 else 'bright_red'
            console.print(f"  [bold]Cross-Validation Results:[/]")
            console.print(f"  [{color}]Verification Rate: {vr}%[/{color}]")
            console.print(f"  [cyan]Verified:[/] {len(cv_results.get('verified', []))} findings")
            console.print(f"  [red]Failed:[/] {len(cv_results.get('failed', []))} findings")
            console.print(f"  [yellow]Mismatches:[/] {len(cv_results.get('mismatches', []))} findings")
            indep = cv_results.get('independent_checks', {})
            dns = indep.get('dns', {})
            http = indep.get('http', {})
            tls = indep.get('tls', {})
            console.print(f"  [dim]DNS records: {dns.get('records', {})}[/]")
            console.print(f"  [dim]HTTP status: {http.get('status', '?')}, headers: {len(http.get('headers', {}))}[/]")
            console.print(f"  [dim]TLS version: {tls.get('version', '?')}[/]")
        console.print()
        return

    # ── COMPLIANCE ───────────────────────────────────────────────────
    if cmd == "compliance":
        _banner(args)
        data = None
        if getattr(args, "input", None):
            with open(args.input) as f:
                data = json.load(f)
        if not data:
            data = get_latest()
        if not data:
            if getattr(args, 'json_output', False):
                print(json.dumps({"error": "no scan data", "message": "Run a scan first"}, indent=2))
            else:
                console.print("  [yellow]No scan data. Run a scan first.[/]")
            sys.exit(1)
        frameworks = [f.strip() for f in args.frameworks.split(",")]
        from .compliance import ComplianceMapper
        mapper = ComplianceMapper()
        report = _spinner_wrap(f"Mapping to {', '.join(frameworks)}...", mapper.map_findings, data.get("findings", []), frameworks)
        for fw, info in report.per_framework.items():
            pct = info.get("compliance_pct", 0)
            color = "green" if pct >= 80 else ("yellow" if pct >= 50 else "red")
            console.print(f"  [{color}]{fw}:[/] {pct:.0f}% ({info.get('covered_controls', 0)}/{info.get('total_controls', 0)} controls)")
        console.print()
        return

    # ── DELTA ───────────────────────────────────────────────────────
    if cmd == "delta":
        _banner(args)
        from .delta import compare_with_last, generate_delta_report
        text = _spinner_wrap("Computing delta...", generate_delta_report, args.target, args.format)
        console.print(text)
        console.print()
        return

    # ── BENCHMARK ───────────────────────────────────────────────────
    if cmd == "benchmark":
        from .benchmark import ScoreTracker
        import json as _json
        tracker = ScoreTracker()
        if getattr(args, 'json_output', False):
            data = {"leaderboard": tracker.get_leaderboard(days=args.days) if args.leaderboard else None}
            print(_json.dumps(data, indent=2, default=str))
        elif args.leaderboard:
            _banner(args)
            report = tracker.get_leaderboard(days=args.days)
            console.print(report)
        else:
            _banner(args)
            console.print("  [dim]Use: reconpro benchmark --leaderboard --days 30[/]")
        console.print()
        return

    # ── GRAPH-VISUAL ────────────────────────────────────────────────
    if cmd == "graph-visual":
        _banner(args)
        from .graph_ui import GraphUIRenderer
        from .knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        graph.load()
        latest = get_latest()
        if latest:
            graph.add_scan_result(latest)
        renderer = GraphUIRenderer()
        path = _spinner_wrap("Generating interactive graph...", renderer.render_to_file, graph.to_dict(), args.output)
        console.print(f"  [green]Graph saved: [cyan]{path}[/][/]")
        console.print(f"  [dim]Open in browser. Features: zoom, search, blast radius, path finder.[/]")
        console.print()
        return

    # ── NETMAP ───────────────────────────────────────────────────────
    if cmd == "netmap":
        from .netmap import run_local
        findings = _spinner_wrap("Mapping network...", run_local)
        if getattr(args, 'json_output', False):
            print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        else:
            _banner(args)
            if not findings:
                console.print("  [bright_green]No network issues found.[/]")
            else:
                for f in findings[:20]:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
            console.print()
        return

    # ── PASSIVE ──────────────────────────────────────────────────────
    if cmd == "passive":
        from .passive_intel import PassiveDNS, WaybackMachine
        domain = args.domain
        json_mode = getattr(args, 'json_output', False)
        wb = WaybackMachine()
        history = _spinner_wrap(f"Querying Wayback Machine for {domain}...", wb.get_history, domain)
        pdns = PassiveDNS()
        dns_results = _spinner_wrap(f"Resolving DNS for {domain}...", pdns.resolve_dns, domain)
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        vt_results = None
        if vt_key:
            vt_results = _spinner_wrap(f"Querying VirusTotal for {domain}...", pdns.query_virustotal, domain, vt_key)
        if json_mode:
            print(json.dumps({"domain": domain, "wayback": history, "dns": dns_results, "virustotal": vt_results}, indent=2, default=str))
        else:
            _banner(args)
            if history:
                console.print(f"  [green]{len(history)}[/] archived page(s) found:")
                for h in history[:10]:
                    console.print(f"    [dim]{h.get('timestamp', '?')}[/] {h.get('url', '?')[:80]}")
            else:
                console.print("  [dim]No Wayback archive data found.[/]")
            if dns_results:
                console.print(f"  [green]{len(dns_results)}[/] DNS record(s):")
                for r in dns_results[:15]:
                    rtype = r.get("type", "?")
                    value = r.get("value", "?")
                    ttl = r.get("ttl", "")
                    console.print(f"    [cyan]{rtype:6s}[/] {value} [dim](TTL {ttl})[/]")
            else:
                console.print("  [dim]No DNS records found.[/]")
            if vt_results:
                console.print(f"  [green]{len(vt_results)}[/] VirusTotal resolution(s):")
                for r in vt_results[:10]:
                    console.print(f"    [cyan]{r.get('ip', '?')}[/]  {r.get('last_resolved', '?')}")
            console.print()
        return

    # ── NEXUS ──────────────────────────────────────────────────
    if cmd == "nexus":
        from .nexus_tui import start_nexus as run_nexus
        run_nexus()
        return

    # ── CHAT ───────────────────────────────────────────────────────
    if cmd == "chat":
        from .chat import start_chat
        _banner(args)
        start_chat()
        return

    # ── TUI ────────────────────────────────────────────────────────
    if cmd == "tui":
        from .nexus_tui import start_nexus
        start_nexus()
        return

    # ── BLITZ ──────────────────────────────────────────────────────
    if cmd == "blitz":
        targets = getattr(args, "targets", [])
        if not targets or len(targets) < 2:
            console.print("  [yellow]Usage: reconpro blitz target1.com target2.com [target3.com ...][/]")
            sys.exit(1)
        _banner(args)
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
        blitz_scan(targets, max_workers=args.workers, modules=modules)
        return

    # ── AGENT ──────────────────────────────────────────────────────
    if cmd == "agent":
        goal = getattr(args, "goal", "")
        if not goal:
            console.print("  [yellow]Usage: reconpro agent \"fully scan example.com and find subdomains\"[/]")
            sys.exit(1)
        _banner(args)
        from .nexus_agent import run_nexus_agent
        run_nexus_agent(goal)
        return

    # ── SWARM ─────────────────────────────────────────────────────
    if cmd == "swarm":
        _banner(args)
        from .swarm import run_swarm
        run_swarm(args.target, mode=args.mode)
        return

    # ── ADVERSARIAL ────────────────────────────────────────────────
    if cmd == "adversarial":
        _banner(args)
        from .adversarial import run_adversarial
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
        run_adversarial(args.target, max_rounds=args.rounds, modules=modules, is_local=args.local)
        return

    # ── AST ────────────────────────────────────────────────────────
    if cmd == "ast":
        _banner(args)
        from .modules.ast_analyzer import ASTAnalyzer
        analyzer = ASTAnalyzer()
        path = os.path.abspath(args.path)
        findings = _spinner_wrap(f"Analyzing {path}...", analyzer.analyze_directory, path)
        if not findings:
            console.print("\n  [bright_green]No vulnerabilities found in code.[/]")
        else:
            table = Table(border_style="dim", header_style="bold dim")
            table.add_column("Severity", style="bold", width=10)
            table.add_column("File", style="cyan", width=30)
            table.add_column("Line", style="dim", width=6)
            table.add_column("Finding")
            for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.severity,4)):
                c = SEV_COLORS.get(f.severity, "white")
                table.add_row(f"[{c}]{f.severity.upper()}[/{c}]", f.asset[-30:] if f.asset else "", str(f.evidence)[:6] if f.evidence else "", f.title[:60])
            console.print(table)
            console.print(f"\n  [bold]{len(findings)} vulnerability pattern(s) found.[/]")
        console.print()
        return

    # ── CVE ─────────────────────────────────────────────────────────
    if cmd == "cve":
        _banner(args)
        from .cve_radar import CVERadar
        radar = CVERadar()
        if args.query.upper().startswith("CVE-"):
            details = _spinner_wrap(f"Looking up {args.query}...", radar.get_cve_details, args.query)
            if details:
                console.print(f"\n  [bold]{details.get('id', args.query)}[/]")
                console.print(f"  Severity: [red]{details.get('severity', '?')}[/]  CVSS: {details.get('cvss', '?')}")
                console.print(f"  {details.get('description', 'No description')[:200]}")
            else:
                console.print(f"  [dim]No results for {args.query}.[/]")
        else:
            results = _spinner_wrap(f"Searching NVD for '{args.query}'...", radar.search_nvd, args.query, args.limit)
            if results:
                for r in results:
                    console.print(f"  [bold]{r.get('id', '?')}[/]  [red]{r.get('severity', '?')}[/]  {r.get('description', '')[:100]}")
                console.print(f"\n  [bold]{len(results)} result(s).[/]")
            else:
                console.print(f"  [dim]No CVEs found for '{args.query}'.[/]")
        console.print()
        return

    # ── GRAPH ───────────────────────────────────────────────────────
    if cmd == "graph":
        _banner(args)
        from .knowledge_graph import SecurityKnowledgeGraph
        graph = SecurityKnowledgeGraph()
        # Load from last scan if available
        latest = get_latest()
        if latest:
            graph.add_scan_result(latest)
        target = args.target or (latest.get("target") if latest else None)
        action = args.action
        if action == "stats" or not target:
            stats = graph.stats()
            console.print(f"\n  [bold]Knowledge Graph Stats:[/]")
            for k, v in stats.items():
                console.print(f"    [cyan]{k}:[/] {v}")
        elif action == "chains":
            chains = graph.find_chains(target)
            if chains:
                console.print(f"\n  [bold]Attack Chains for {target}:[/]")
                for i, chain in enumerate(chains[:10]):
                    console.print(f"    [red]Chain {i+1}:[/] {' → '.join(chain)}")
            else:
                console.print(f"  [dim]No attack chains found for {target}.[/]")
        elif action == "surface":
            surface = graph.get_attack_surface(target)
            console.print(f"\n  [bold]Attack Surface for {target}:[/]")
            for k, v in surface.items():
                console.print(f"    [cyan]{k}:[/] {v}")
        elif action == "blast":
            blast = graph.get_blast_radius(target)
            console.print(f"\n  [bold]Blast Radius from {target}:[/]")
            console.print(f"    [red]{len(blast)} reachable vulnerabilities[/]")
        elif action == "export":
            cypher = graph.to_cypher()
            console.print(f"\n  [bold]Cypher Export:[/] {len(cypher)} statements")
            for line in cypher[:20]:
                console.print(f"    {line[:100]}")
        graph.save()
        console.print(f"\n  [dim]Graph saved to ~/.reconpro/memory/graph.json[/]")
        console.print()
        return

    # ── EXPORT ──────────────────────────────────────────────────────
    if cmd == "export":
        data = get_latest()
        if not data:
            if getattr(args, 'json_output', False):
                print(json.dumps({"error": "no scan data", "message": "Run a scan first"}, indent=2))
            else:
                console.print("  [yellow]No scan data. Run a scan first.[/]")
            sys.exit(1)
        from .formats import export as _export
        path = _spinner_wrap(f"Exporting to {args.output}...", _export, data, args.output)
        console.print(f"  [green]Exported: [cyan]{path}[/][/]")
        return

    # ── SUBDOMAINS ────────────────────────────────────────────────
    if cmd == "subdomains":
        domain = args.domain
        from .subdomains import discover_subdomains
        subs = _spinner_wrap(f"Discovering subdomains of {domain}...", discover_subdomains, domain)
        if getattr(args, 'json_output', False):
            print(json.dumps({"domain": domain, "subdomains": subs}, indent=2))
        else:
            _banner(args)
            console.print(f"  [dim]v{__version__} | subdomain discovery: {domain}[/]\n")
            if not subs:
                console.print("\n  [dim]No subdomains found.[/]")
            else:
                for s in subs:
                    console.print(f"  [cyan]{s}[/]")
                console.print(f"\n  [bold]{len(subs)} subdomain(s) found.[/]")
            console.print()
        return

    # ── SCHEDULE ───────────────────────────────────────────────────
    if cmd == "schedule":
        target = args.target
        is_local = target.lower() == "audit"
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
        from .scheduler import run_scheduled
        run_scheduled(target, interval=args.every, modules=modules,
                      is_local=is_local, max_runs=args.max_runs)
        return

    # ── SERVE ──────────────────────────────────────────────────────
    if cmd == "serve":
        from .server import run_server
        _banner(args)
        run_server(port=args.port)
        return

    # ── DASHBOARD ───────────────────────────────────────────────
    if cmd == "dashboard":
        if getattr(args, "json_output", False):
            data = _collect_dashboard_data()
            # Remove internal keys not useful for JSON output
            data.pop("last_scan_seconds", None)
            print(json.dumps(data, indent=2, default=str))
        else:
            data = _collect_dashboard_data()
            _render_dashboard(data)
        return

    # ── REPORT ──────────────────────────────────────────────────
    if cmd == "report":
        data = None
        if getattr(args, "input", None):
            import json as _json_load
            with open(args.input) as f:
                data = _json_load.load(f)
        else:
            data = get_latest()
        if not data:
            if getattr(args, "json_output", False):
                print(json.dumps({"error": "no scan data"}, indent=2))
            else:
                console.print("  [yellow]No scan data. Run a scan first or use -i <file>.[/]")
            sys.exit(1)

        use_json = getattr(args, "json_output", False)
        use_html = getattr(args, "html", False)
        use_md = getattr(args, "markdown", False)
        output_file = getattr(args, "output_file", None)

        # Default: markdown to stdout unless --html or --json
        if use_json:
            report = generate_production_report(data, format="json")
            if output_file:
                with open(output_file, "w") as fp:
                    fp.write(report)
            else:
                print(report)
        elif use_html:
            path = _spinner_wrap("Generating HTML report...", generate_html_report, data)
            console.print(f"  [green]Report saved: [cyan]{path}[/][/]")
        else:
            # Markdown report (default)
            report = generate_production_report(data, format="markdown")
            if output_file:
                with open(output_file, "w") as fp:
                    fp.write(report)
                console.print(f"  [green]Markdown report saved: [cyan]{output_file}[/][/]")
            else:
                console.print(report)
        return

    # ── HISTORY ───────────────────────────────────────────────────
    if cmd == "history":
        if getattr(args, "clear", False):
            n = clear_history()
            console.print(f"  Cleared {n} scan(s) from history.")
            return
        scans = list_scans(target=getattr(args, "target", None), limit=args.limit)
        if not scans:
            console.print("  [dim]No scan history yet.[/]")
            return
        table = Table(border_style="dim", header_style="bold dim")
        table.add_column("Date", style="dim", width=16)
        table.add_column("Target", style="cyan", width=25)
        table.add_column("Score", style="bold", width=8)
        table.add_column("Grade", style="bold", width=6)
        table.add_column("Findings", width=10)
        table.add_column("File", style="dim")
        for s in scans:
            g = s.get("grade", "?")
            gc = GRADE_COLORS.get(g, "white")
            table.add_row(s.get("_saved_at", "?")[:16], s.get("target", "?")[:25],
                         str(s.get("total_score", "?")), f"[{gc}]{g}[/{gc}]",
                         str(len(s.get("findings", []))), s.get("_file", ""))
        console.print(table)
        console.print()
        return

    # ── DIFF ────────────────────────────────────────────────────────
    if cmd == "diff":
        scans = list_scans(limit=2)
        if len(scans) < 2:
            console.print("  [yellow]Need at least 2 scans. Run some scans first.[/]")
            sys.exit(1)
        d = diff_scans(scans[0]["_file"], scans[1]["_file"])
        change = d["score_change"]
        color = "green" if change > 0 else ("red" if change < 0 else "dim")
        console.print(f"\n  [bold]{d['scan_a']['target']}[/]  score={d['scan_a']['score']} ({d['scan_a']['grade']})")
        console.print(f"  [bold]{d['scan_b']['target']}[/]  score={d['scan_b']['score']} ({d['scan_b']['grade']})")
        console.print(f"  Change: [{color}]{'+' if change > 0 else ''}{change} pts[/{color}]")
        if d["new"]:
            console.print(f"\n  [red]New issues ({len(d['new'])}):[/red]")
            for n in d["new"][:10]:
                console.print(f"    [red]+[/] {n}")
        if d["fixed"]:
            console.print(f"\n  [green]Fixed ({len(d['fixed'])}):[/green]")
            for f in d["fixed"][:10]:
                console.print(f"    [green]-[/] {f}")
        if d["persistent"]:
            console.print(f"\n  [yellow]Still present ({len(d['persistent'])}):[/yellow]")
        console.print()
        return

    # ── SCREENSHOT ─────────────────────────────────────────────────
    if cmd == "screenshot":
        try:
            from .browser_mod import take_screenshot
            path = _spinner_wrap(f"Screenshotting {args.url}...", take_screenshot, args.url)
            console.print(f"  [green]Screenshot: [cyan]{path}[/][/]")
        except ImportError:
            console.print("  [yellow]Install browser support:[/]")
            console.print("    pip install reconpro[browser]")
            console.print("    playwright install")
        return

    # ── OPEN ────────────────────────────────────────────────────────
    if cmd == "open":
        from .browser_mod import open_browser
        open_browser(args.url)
        console.print(f"  Opened [cyan]{args.url}[/] in browser")
        return

    # ── PLUGIN ─────────────────────────────────────────────────────
    if cmd == "plugin":
        from .plugins import discover_plugins, create_plugin_template, run_plugin as _run_plugin
        from pathlib import Path as _P
        action = args.action
        json_mode = getattr(args, "json_output", False)

        def _mgr():
            from .plugin_sdk import PluginManager
            return PluginManager()

        if action == "list":
            plugins = discover_plugins()
            if not plugins:
                console.print("  [dim]No plugins found. Create one: reconpro plugin create-sdk my-check[/]")
            elif json_mode:
                print(json.dumps(plugins, indent=2, default=str))
            else:
                for pid, p in plugins.items():
                    trust = "[green]signed[/]" if p.get("trusted") else "[yellow]unsigned[/]"
                    console.print(f"  [cyan]{pid:16}[/] {p['name'][:20]:20} {trust:10} {p.get('version', ''):8} {p['description'][:48]}")
        elif action == "create":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin create <name>[/]")
                sys.exit(1)
            try:
                path = create_plugin_template(args.name)
            except Exception as exc:
                console.print(f"  [red]Create failed: {escape(str(exc))}[/]")
                sys.exit(1)
            console.print(f"  [green]Legacy template created: [cyan]{escape(str(path))}[/][/]")
            console.print(f"  [dim]For signed SDK plugins use: reconpro plugin create-sdk {args.name}[/]")
        elif action == "create-sdk":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin create-sdk <name>[/]")
                sys.exit(1)
            try:
                from .plugins import create_plugin_skeleton
                path = create_plugin_skeleton(args.name, dest=_P.cwd())
            except Exception as exc:
                console.print(f"  [red]Create failed: {escape(str(exc))}[/]")
                sys.exit(1)
            console.print(f"  [green]SDK plugin skeleton created: [cyan]{escape(str(path))}[/][/]")
            console.print("  [dim]Next: edit main.py, then `reconpro plugin sign <dir>` and `plugin install <dir>`[/]")
        elif action == "run":
            if not args.name or not args.target:
                console.print("  [yellow]Usage: reconpro plugin run <plugin-name> <target>[/]")
                sys.exit(1)
            base_url = args.target if args.target.startswith("http") else f"https://{args.target}"
            findings = _run_plugin(args.name, args.target, base_url)
            for f in findings:
                if isinstance(f, dict):
                    sev, title = f.get("severity", "info"), f.get("title", "")
                else:
                    sev, title = getattr(f, "severity", "info"), getattr(f, "title", "")
                c = SEV_COLORS.get(sev, "white")
                console.print(f"  [{c}]{sev.upper():8}[/{c}]  {title}")
        elif action == "install":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin install <dir-or-file>[/]")
                sys.exit(1)
            try:
                info = _mgr().install(_P(args.name).expanduser(),
                                      allow_unsigned=getattr(args, "allow_unsigned", False))
                console.print(f"  [green]Installed[/] [cyan]{info.id}[/] v{info.version} "
                              f"({'trusted' if info.trusted else 'UNTRUSTED'})")
                console.print(f"  [dim]permissions: {info.permissions.summary()}[/]")
            except Exception as exc:
                console.print(f"  [red]Install failed: {escape(str(exc))}[/]")
                sys.exit(1)
        elif action == "verify":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin verify <plugin-id>[/]")
                sys.exit(1)
            try:
                report = _mgr().verify(args.name)
                if json_mode:
                    print(json.dumps(report, indent=2, default=str))
                else:
                    icon = "[green]PASS[/]" if report["ok"] else "[red]FAIL[/]"
                    console.print(f"  {icon}  {args.name}")
                    for chk in report["checks"]:
                        c = "[green]ok[/]" if chk["ok"] else "[red]FAIL[/]"
                        console.print(f"    {c:14} {chk['check']}"
                                      + (f" [dim]{chk.get('detail','')}[/]" if not chk["ok"] else ""))
                sys.exit(0 if report["ok"] else 1)
            except Exception as exc:
                console.print(f"  [red]Verify failed: {escape(str(exc))}[/]")
                sys.exit(1)
        elif action == "upgrade":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin upgrade <new-plugin-dir>[/]")
                sys.exit(1)
            try:
                info = _mgr().upgrade(_P(args.name).expanduser(),
                                      allow_unsigned=getattr(args, "allow_unsigned", False))
                console.print(f"  [green]Upgraded[/] [cyan]{info.id}[/] to v{info.version}")
            except Exception as exc:
                console.print(f"  [red]Upgrade failed: {escape(str(exc))}[/]")
                sys.exit(1)
        elif action == "remove":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin remove <plugin-id>[/]")
                sys.exit(1)
            try:
                result = _mgr().remove(args.name)
                console.print(f"  [green]Removed[/] [cyan]{args.name}[/] "
                              f"[dim](was v{result['entry'].get('version','?')})[/]")
            except Exception as exc:
                console.print(f"  [red]Remove failed: {escape(str(exc))}[/]")
                sys.exit(1)
        elif action == "sign":
            if not args.name:
                console.print("  [yellow]Usage: reconpro plugin sign <plugin-dir>[/]")
                sys.exit(1)
            try:
                sig = _mgr().sign(_P(args.name).expanduser())
                console.print(f"  [green]Signed[/] [cyan]{args.name}[/]")
                console.print(f"  [dim]signature: {sig[:32]}…[/]")
            except Exception as exc:
                console.print(f"  [red]Sign failed: {escape(str(exc))}[/]")
                sys.exit(1)
        elif action == "keys":
            priv, pub = _mgr().ensure_local_key()
            from .plugin_sdk.crypto import fingerprint
            console.print(f"  [cyan]local dev key[/]  id: {fingerprint(pub)}")
            console.print(f"  public : {pub}")
            console.print(f"  private: ~/.reconpro/plugins/keys/local.ed25519 [dim](0600)[/]")
            console.print("  [dim]share the PUBLIC key; other machines add it via "
                          "`reconpro plugin keys` + trusted dir[/]")
        return

    # ── TUTORIAL / WIZARD / PLAYGROUND / SUGGEST ───────────────────
    if cmd == "tutorial":
        from .cli_extras import run_tutorial
        try:
            run_tutorial(step=args.step, list_only=args.list)
        except IndexError:
            console.print("  [yellow]No such step (1-8). Use --list.[/]")
            sys.exit(1)
        return

    if cmd == "wizard":
        from .cli_extras import run_wizard
        run_wizard(non_interactive=args.non_interactive)
        return

    if cmd == "playground":
        from .cli_extras import run_playground
        sys.exit(run_playground(file=args.file, target=args.target))

    if cmd == "suggest":
        from .cli_extras import run_suggest
        run_suggest(json_output=getattr(args, "json_output", False))
        return

    # ── AUDIT (local) ─────────────────────────────────────────────
    if cmd == "audit":
        _banner(args)
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
        run_eng = getattr(args, "engineering", False)
        run_intel = not getattr(args, "no_intelligence", False)
        run_qual = getattr(args, "quality", False)
        run_def = getattr(args, "defense", False)
        result = _spinner_wrap("Auditing machine...", audit_scan, target="localhost", modules=modules,
                                run_engineering=run_eng, run_intelligence=run_intel,
                                run_quality=run_qual, run_defense=run_def)
        _output_result(result, args, title="HOST AUDIT", show_remediation=True)
        if result.quality:
            qs = result.quality.get("composite_score", 0)
            console.print(Panel(
                f"Quality Score: [bold]{qs:.1f}/100[/bold]",
                title="[bold]QUALITY INTELLIGENCE[/bold]",
                border_style="bright_green",
            ))
        if run_eng:
            _render_engineering_panel(result)
        return

    # ── DEV ────────────────────────────────────────────────────────
    if cmd == "dev":
        path = args.path
        _banner(args)
        result = _spinner_wrap("Scanning project...", audit_scan, target=path, modules=["dev"])
        _output_result(result, args, title="DEV SEC", show_remediation=True)
        return

    # ── DOCTOR ─────────────────────────────────────────────────────
    if cmd == "doctor":
        if getattr(args, "repair", False):
            from .cli_extras import doctor_repair
            _banner(args)
            report = doctor_repair()
            if getattr(args, "json_output", False):
                print(json.dumps(report, indent=2, default=str))
            else:
                for act in report["actions"]:
                    icon = "[green]fixed[/]" if act["status"] == "ok" else "[red]error[/]"
                    console.print(f"  {icon:16} {act['fix']}: {act['detail']}")
                console.print()
            sys.exit(0 if report["ok"] else 1)
        _banner(args)
        result = _spinner_wrap("Running diagnostics...", audit_scan, target="localhost", modules=["doctor"])
        _output_result(result, args, title="DOCTOR", show_remediation=True)
        console.print("  [dim]Tip: `reconpro doctor --repair` applies safe automatic fixes.[/]\n")
        return

    # ── PORTS ──────────────────────────────────────────────────────
    if cmd == "ports":
        from .modules.host import _check_open_ports
        findings = _spinner_wrap("Scanning ports...", _check_open_ports)
        if getattr(args, 'json_output', False):
            print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        else:
            _banner(args)
            if not findings:
                console.print("\n  [bright_green]No risky ports found.[/]")
            else:
                for f in findings:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
            console.print()
        return

    # ── SECRETS ────────────────────────────────────────────────────
    if cmd == "secrets":
        path = args.path
        from .modules.host import _check_env_secrets
        from .modules.dev import _check_env_files, _check_hardcoded_secrets
        all_f = _spinner_wrap("Hunting secrets...", lambda: (
            _check_env_secrets() +
            _check_env_files(os.path.abspath(path)) +
            _check_hardcoded_secrets(os.path.abspath(path))
        ))
        if getattr(args, 'json_output', False):
            print(json.dumps([f.to_dict() for f in all_f], indent=2, default=str))
        else:
            _banner(args)
            total = len(all_f)
            crit = sum(1 for f in all_f if f.severity == "critical")
            high = sum(1 for f in all_f if f.severity == "high")
            if total == 0:
                console.print("\n  [bright_green]No secrets found. Clean.[/]")
            else:
                console.print(Panel(Group(
                    Text(f"\n  [bold bright_red]{total} secret(s) found[/]  [bright_red]{crit} critical[/], [red]{high} high[/]"),
                ), border_style="bright_red", title="[bold]SECRET SCAN[/bold]", padding=(1, 2)))
                console.print()
                for f in all_f:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
                    if f.remediation:
                        console.print(f"           [dim]{f.remediation}[/dim]")
            console.print()
        return

    # ── VIBESEC ────────────────────────────────────────────────────
    if cmd == "vibesec":
        target = args.target
        if not target:
            console.print("  [yellow]Usage: reconpro vibesec <target>[/]")
            sys.exit(1)
        _banner(args)
        result = _spinner_wrap(f"Scanning {target}...", scan, target, modules=["vibesec"],
                                timeout=args.timeout, verify_tls=not args.insecure, rate_limit=args.rate_limit)
        _output_result(result, args)
        return

    # ── SCAN (explicit) ────────────────────────────────────────────
    if cmd == "scan":
        target = args.target
        if not target:
            console.print("  [yellow]Usage: reconpro scan <target>[/]")
            sys.exit(1)
        modules = [m.strip().lower() for m in args.modules.split(",")] if args.modules else None
        if modules:
            valid = set(ALL_MODULES) | set(LOCAL_MODULES)
            unknown = [m for m in modules if m not in valid]
            if unknown:
                console.print(f"  [yellow]Unknown module(s) ignored: {', '.join(unknown)}[/]")
                console.print(f"  [dim]Run `reconpro list` for valid module ids.[/]")
                modules = [m for m in modules if m in valid] or None
        _banner(args)
        run_eng = getattr(args, "engineering", False)
        run_intel = not getattr(args, "no_intelligence", False)
        run_qual = getattr(args, "quality", False)
        run_def = getattr(args, "defense", False)
        result = _spinner_wrap(f"Scanning {target}...", scan, target, modules=modules,
                                all_modules=args.all, timeout=args.timeout,
                                verify_tls=not args.insecure, rate_limit=args.rate_limit,
                                run_engineering=run_eng, run_intelligence=run_intel,
                                run_quality=run_qual, run_defense=run_def)
        _output_result(result, args)
        if result.quality:
            qs = result.quality.get("composite_score", 0)
            console.print(Panel(
                f"Quality Score: [bold]{qs:.1f}/100[/bold]",
                title="[bold]QUALITY INTELLIGENCE[/bold]",
                border_style="bright_green",
            ))
        if run_eng:
            _render_engineering_panel(result)
        return

    # (Implicit-scan shorthand handled at parse time: `reconpro <target>` is
    #  rewritten to `reconpro scan <target>` BEFORE parsing, so it flows through
    #  the strict parser and the normal `scan` dispatch above.)

    # ── ZAI (z.ai live stream) ──────────────────────────────────────
    if cmd == "zai":
        from .integrations.zai_stream import ZAIStreamClient
        client = ZAIStreamClient(model=args.model)

        if getattr(args, "health", False):
            console.print(f"  [cyan]Checking z.ai connectivity...[/]")
            console.print(f"  [dim]{client}[/]")
            result = client.health_check()
            if result["status"] == "connected":
                console.print(f"  [bright_green]CONNECTED[/]  latency: {result['latency_ms']}ms  model: {result['model']}")
                console.print(f"  [dim]Response: {result.get('response_preview', '')}[/]")
            else:
                console.print(f"  [bright_red]ERROR: {result.get('error', 'unknown')}[/]")
            return

        if getattr(args, "chat", ""):
            _banner(args)
            console.print(f"  [cyan]z.ai Live Stream[/]  [dim]model: {args.model}[/]")
            console.print(f"  [dim]{'─' * 50}[/]")
            if not getattr(args, "no_stream", False):
                for chunk in client.chat_stream(args.chat):
                    console.print(chunk, end="")
                console.print()
            else:
                response = client.chat(args.chat)
                console.print(response)
            console.print(f"  [dim]{'─' * 50}[/]")
            return

        # Analyze scan findings
        target = getattr(args, "target", "")
        findings = None
        if target:
            _banner(args)
            result = _spinner_wrap(f"Scanning {target}...", scan, target,
                                    timeout=8, verify_tls=True, rate_limit=10.0)
            findings = result.findings
            scan_target = target
        else:
            # Use last scan from history
            latest = get_latest()
            if not latest:
                console.print("  [yellow]No target specified and no scan history found.[/]")
                console.print("  [dim]Usage: reconpro zai <target>  or  reconpro scan <target> && reconpro zai[/]")
                sys.exit(1)
            findings = latest.get("findings", [])
            scan_target = latest.get("target", "unknown")
            _banner(args)
            console.print(f"  [dim]Using last scan: {scan_target} ({len(findings)} findings)[/]")

        if not findings:
            console.print("  [bright_green]No findings to analyze. Target is clean![/]")
            return

        console.print(f"  [cyan]z.ai Live Stream Analysis[/]  [dim]{len(findings)} findings → {args.model}[/]")
        console.print(f"  [dim]{'─' * 60}[/]")
        if not getattr(args, "no_stream", False):
            for chunk in client.analyze_findings_stream(findings, scan_target):
                console.print(chunk, end="")
            console.print()
        else:
            analysis = client.analyze_findings(findings, scan_target)
            console.print(analysis)
        console.print(f"  [dim]{'─' * 60}[/]")
        return

    # ── quantum-fingerprint (v9.2.0) ──────────────────────────────
    if cmd == "quantum-fingerprint":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.quantum_fingerprint import run_quantum_fingerprint
        findings = _spinner_wrap(
            f"Fingerprinting {target} via HTTP timing...",
            run_quantum_fingerprint, target, base_url,
            timeout=args.timeout, verify_tls=not args.insecure,
        )
        _print_findings(findings, args, title="QUANTUM FINGERPRINT")
        return

    # ── dark-web (v9.2.0) ─────────────────────────────────────────
    if cmd == "dark-web":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.dark_web_monitor import run_dark_web_monitor
        findings = _spinner_wrap(
            f"Scanning paste sites & threat feeds for {target}...",
            run_dark_web_monitor, target, base_url,
        )
        _print_findings(findings, args, title="DARK WEB MONITOR")
        return

    # ── info-ops (v9.2.0) ─────────────────────────────────────────
    if cmd == "info-ops":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.free_info_ops import run_info_ops
        findings = _spinner_wrap(
            f"Analyzing information operations on {target}...",
            run_info_ops, target, base_url,
        )
        _print_findings(findings, args, title="INFO OPS ANALYSIS")
        return

    # ── steg (v9.2.0) ─────────────────────────────────────────────
    if cmd == "steg":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.steganography_detector import run_steganography_detector
        findings = _spinner_wrap(
            f"Detecting steganography on {target}...",
            run_steganography_detector, target, base_url,
        )
        _print_findings(findings, args, title="STEGANOGRAPHY DETECTOR")
        return

    # ── covert (v9.2.0) ──────────────────────────────────────────
    if cmd == "covert":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.covert_channel import run_covert_channel
        findings = _spinner_wrap(
            f"Analyzing covert channels on {target}...",
            run_covert_channel, target, base_url,
        )
        _print_findings(findings, args, title="COVERT CHANNEL")
        return

    # ── zero-day (v9.2.0) ─────────────────────────────────────────
    if cmd == "zero-day":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.zero_day_hunter import run_zero_day_hunter
        findings = _spinner_wrap(
            f"Hunting zero-day patterns on {target}...",
            run_zero_day_hunter, target, base_url,
        )
        _print_findings(findings, args, title="ZERO-DAY HUNTER")
        return

    # ── ghost (v9.2.0) ───────────────────────────────────────────
    if cmd == "ghost":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.infrastructure_ghost import run_infrastructure_ghost
        findings = _spinner_wrap(
            f"Ghosting infrastructure of {target}...",
            run_infrastructure_ghost, target, base_url,
        )
        _print_findings(findings, args, title="INFRASTRUCTURE GHOST")
        return

    # ── sigint (v9.2.0) ──────────────────────────────────────────
    if cmd == "sigint":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.signal_intelligence import run_signal_intelligence
        findings = _spinner_wrap(
            f"Running SIGINT analysis on {target}...",
            run_signal_intelligence, target, base_url,
        )
        _print_findings(findings, args, title="SIGNAL INTELLIGENCE")
        return

    # ── attributor (v9.2.0) ───────────────────────────────────────
    if cmd == "attributor":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.nation_state_attributor import run_nation_state_attributor
        findings = _spinner_wrap(
            f"Attributing {target} to nation-state actors...",
            run_nation_state_attributor, target, base_url,
        )
        _print_findings(findings, args, title="NATION-STATE ATTRIBUTOR")
        return

    # ── weaponized-report (v9.2.0) ─────────────────────────────────
    if cmd == "weaponized-report":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.weaponized_report import run_weaponized_report
        findings = _spinner_wrap(
            f"Generating weaponized report for {target}...",
            run_weaponized_report, target, base_url,
        )
        _print_findings(findings, args, title="WEAPONIZED REPORT")
        return

    # ── honeypot (v9.2.0) ─────────────────────────────────────────
    if cmd == "honeypot":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.honeypot_dance import run_honeypot_dance
        findings = _spinner_wrap(
            f"Dancing with honeypots on {target}...",
            run_honeypot_dance, target, base_url,
        )
        _print_findings(findings, args, title="HONEYPOT DANCE")
        return

    # ── rate (v9.2.0 Module Rating System) ───────────────────
    if cmd == "rate":
        from .ratings import (
            MODULE_RATINGS, V9_MODULES, MODULE_CLI_MAP,
            get_rating, get_all_ratings, compute_team_score,
        )

        # CLI name -> module_id reverse map
        cli_to_id = {v: k for k, v in MODULE_CLI_MAP.items()}

        if getattr(args, 'module', None):
            # Rate a specific module
            cli_name = args.module.lower()
            mod_id = cli_to_id.get(cli_name, cli_name.replace("-", "_"))
            rating = get_rating(mod_id)
            if not rating:
                # Try direct module_id
                rating = get_rating(cli_name)
            if not rating:
                console.print(f"[red]Unknown module: {args.module}[/red]")
                console.print(f"[dim]Available: {', '.join(MODULE_CLI_MAP.values())}[/dim]")
                return

            # JSON output
            if getattr(args, 'json_output', False):
                d = {
                    "module": rating.module_id,
                    "name": rating.name,
                    "score": rating.score,
                    "grade": rating.grade,
                    "category": rating.category,
                    "sub_scores": {
                        "detection_breadth": rating.detection_breadth,
                        "detection_depth": rating.detection_depth,
                        "dependency_footprint": rating.dependency_footprint,
                        "uniqueness": rating.uniqueness,
                        "operational_safety": rating.operational_safety,
                    },
                    "compared_with": rating.compared_with,
                    "parity_pct": rating.parity_pct,
                    "unique_advantages": rating.unique_advantages,
                    "known_limitations": rating.known_limitations,
                    "stats": {
                        "lines_of_code": rating.lines_of_code,
                        "detection_categories": rating.detection_categories,
                        "signature_count": rating.signature_count,
                    },
                }
                print(json.dumps(d, indent=2))
                return

            # Rich table output
            _grade_color = GRADE_COLORS.get(rating.grade, "white")
            console.print()
            console.print(Panel(
                f"[bold]{rating.name}[/bold]\n{rating.category}",
                title="MODULE RATING",
                border_style="bright_cyan",
            ))
            console.print()

            # Score bar
            score_color = "bright_green" if rating.score >= 80 else "yellow" if rating.score >= 70 else "red"
            filled = int(rating.score / 5)
            bar = "[" + "#" * filled + "." * (20 - filled) + "]"
            console.print(f"  OVERALL: [bold {score_color}]{rating.score}/100  {rating.grade}[/bold {score_color}]  {bar}")
            console.print()

            # Sub-scores table
            sub_table = Table(show_header=True, header_style="bold", title="Sub-Scores")
            sub_table.add_column("Dimension", style="cyan")
            sub_table.add_column("Score", justify="right")
            sub_table.add_column("Bar", min_width=22)
            dims = [
                ("Detection Breadth", rating.detection_breadth),
                ("Detection Depth", rating.detection_depth),
                ("Dependency Footprint", rating.dependency_footprint),
                ("Uniqueness", rating.uniqueness),
                ("Operational Safety", rating.operational_safety),
            ]
            for label, val in dims:
                c = "bright_green" if val >= 85 else "yellow" if val >= 70 else "red"
                f_ = int(val / 5)
                b = "#" * f_ + "." * (20 - f_)
                sub_table.add_row(label, f"[{c}]{val}[/]", f"[{c}]{b}[/]")
            console.print(sub_table)
            console.print()

            # Compared with
            console.print(f"  [bold]Compared with:[/bold] {', '.join(rating.compared_with)}")
            if rating.parity_pct > 0:
                console.print(f"  [bold]Functional parity:[/bold] {rating.parity_pct}%")
            else:
                console.print(f"  [bold]Functional parity:[/bold] N/A (no equivalent tool)")
            console.print()

            # Advantages
            console.print(f"  [bold bright_green]Unique Advantages:[/bold bright_green]")
            for adv in rating.unique_advantages:
                console.print(f"    [green]+[/green] {adv}")
            console.print()

            # Limitations
            console.print(f"  [bold yellow]Known Limitations:[/bold yellow]")
            for lim in rating.known_limitations:
                console.print(f"    [yellow]-[/yellow] {lim}")
            console.print()

            # Stats
            console.print(f"  [dim]Lines: {rating.lines_of_code:,}  |  Categories: {rating.detection_categories}  |  Signatures: {rating.signature_count}  |  Dependencies: {rating.external_dependencies}[/dim]")
            return

        # Rate ALL modules
        ratings = get_all_ratings()
        avg_score, team_grade, total_loc, total_cats, total_sigs = compute_team_score()

        if getattr(args, 'json_output', False):
            data = {
                "team_score": avg_score,
                "team_grade": team_grade,
                "total_lines_of_code": total_loc,
                "total_detection_categories": total_cats,
                "total_signatures": total_sigs,
                "modules": [
                    {
                        "module": r.module_id,
                        "name": r.name,
                        "score": r.score,
                        "grade": r.grade,
                        "category": r.category,
                        "sub_scores": {
                            "breadth": r.detection_breadth,
                            "depth": r.detection_depth,
                            "deps": r.dependency_footprint,
                            "unique": r.uniqueness,
                            "safety": r.operational_safety,
                        },
                    }
                    for r in ratings
                ],
            }
            print(json.dumps(data, indent=2))
            return

        # Rich output for all modules
        console.print()
        console.print(Panel(
            f"[bold]ReconPro v{__version__}  |  {len(ratings)} Modules  |  ~{total_loc:,} Lines  |  0 Dependencies[/bold]",
            title="MODULE RATINGS vs INDUSTRY TOOLS",
            border_style="bright_cyan",
        ))
        console.print()

        # Team score
        tc = "bright_green" if avg_score >= 80 else "yellow" if avg_score >= 70 else "red"
        tg = GRADE_COLORS.get(team_grade, "white")
        console.print(f"  [bold]TEAM SCORE:[/bold]  [{tc}]{avg_score}/100  [{tg}]{team_grade}[/{tg}]")
        console.print()

        # Full table
        table = Table(show_header=True, header_style="bold bright_cyan", title=None)
        table.add_column("Module", min_width=28)
        table.add_column("Score", justify="right", min_width=7)
        table.add_column("Grade", justify="center", min_width=5)
        table.add_column("Breadth", justify="right", min_width=7)
        table.add_column("Depth", justify="right", min_width=6)
        table.add_column("Deps", justify="right", min_width=5)
        table.add_column("Unique", justify="right", min_width=6)
        table.add_column("Safety", justify="right", min_width=6)
        table.add_column("vs", min_width=28)

        for r in ratings:
            sc = "bright_green" if r.score >= 85 else "yellow" if r.score >= 70 else "red"
            gc = GRADE_COLORS.get(r.grade, "white")
            vs = ", ".join(r.compared_with[:2])
            if len(r.compared_with) > 2:
                vs += "+"
            table.add_row(
                f"[cyan]{r.name}[/]",
                f"[{sc}]{r.score}/100[/]",
                f"[{gc}]{r.grade}[/]",
                f"{r.detection_breadth}/100",
                f"{r.detection_depth}/100",
                f"{r.dependency_footprint}/100",
                f"{r.uniqueness}/100",
                f"{r.operational_safety}/100",
                f"[dim]{vs}[/dim]",
            )
        console.print(table)
        console.print()

        # Unique capabilities summary
        unique_count = sum(1 for r in ratings if r.uniqueness >= 95)
        console.print(f"  [bold bright_green]{unique_count} modules[/bold bright_green] have [bold]NO open-source equivalent[/bold] (uniqueness = 100/100)")
        console.print(f"  [bold]All 12 modules[/bold] score [bold]100/100[/bold] on dependency footprint (zero external deps)")
        console.print(f"  [bold]All 12 modules[/bold] require [bold]no root access, no pcap, no API keys[/bold]")
        console.print()
        return

    # ── dead-drop (v9.2.0) ───────────────────────────────────────
    if cmd == "dead-drop":
        _banner(args)
        target = args.target
        base_url = target if target.startswith("http") else f"https://{target}"
        from .modules.dead_drop import run_dead_drop
        findings = _spinner_wrap(
            f"Scanning dead drops on {target}...",
            run_dead_drop, target, base_url,
        )
        _print_findings(findings, args, title="DEAD DROP")
        return

    # ── info (Diagnostics & Help) ──────────────────────────────
    if cmd == "info":
        from .diagnostics import run_diagnostics, health_check, get_version_info, generate_debug_report, module_status, validate_config
        from .cli_help import render_module_help, render_all_modules, render_quick_start, render_examples, MODULE_HELP, CLI_COMMANDS

        # Show module-specific help
        if getattr(args, "module", None):
            text = render_module_help(args.module)
            console.print(text)
            return

        # List all modules
        if getattr(args, "modules", False):
            text = render_all_modules()
            console.print(text)
            return

        # Run full diagnostics
        if getattr(args, "diagnose", False):
            if getattr(args, "json_output", False):
                import json as _json
                diag = run_diagnostics()
                print(_json.dumps(diag, indent=2, default=str))
            else:
                report = generate_debug_report()
                console.print(report)
            return

        # Quick health check
        if getattr(args, "health", False):
            hc = health_check()
            if getattr(args, "json_output", False):
                import json as _json
                print(_json.dumps(hc, indent=2))
            else:
                console.print()
                console.print(Panel(
                    "[bold]ReconPro v11 — Health Check[/bold]",
                    border_style="bright_cyan",
                ))
                console.print()
                table = Table(border_style="dim", header_style="bold")
                table.add_column("Category", style="cyan", min_width=18)
                table.add_column("Status", min_width=12)
                for k, v in hc.items():
                    color = "green" if v == "ok" else "yellow" if "warning" in v else "red"
                    table.add_row(k, f"[{color}]{v}[/{color}]")
                console.print(table)
                console.print()
            return

        # Detailed version info
        if getattr(args, "info_version", False):
            vi = get_version_info()
            if getattr(args, "json_output", False):
                import json as _json
                print(_json.dumps(vi, indent=2))
            else:
                console.print()
                console.print(Panel(
                    "[bold]ReconPro v11 — Version Information[/bold]",
                    border_style="bright_cyan",
                ))
                console.print()
                table = Table(border_style="dim", header_style="bold", show_header=False)
                table.add_column("Key", style="cyan", min_width=22)
                table.add_column("Value")
                for k, v in vi.items():
                    table.add_row(k, v)
                console.print(table)
                console.print()
            return

        # Usage examples
        if getattr(args, "examples", False):
            text = render_examples()
            console.print(text)
            return

        # Quick-start guide
        if getattr(args, "quick_start", False):
            text = render_quick_start()
            console.print(text)
            return

        # Default: show quick-start
        text = render_quick_start()
        console.print(text)
        return

    # ── Engineering Commands (Age III) ────────────────────────
    if cmd == "engineering":
        from .engineering_workflow import ContinuousEngineeringOrchestrator
        import json as _json
        repo = getattr(args, "repo", ".")
        if not getattr(args, "json_output", False):
            _banner(args)
            console.print(f"\n  [bold]Running full engineering pipeline on [cyan]{repo}[/]...[/]")
        orchestrator = ContinuousEngineeringOrchestrator()
        result = orchestrator.run_full_cycle(repo)
        if getattr(args, "json_output", False):
            print(_json.dumps(result.to_dict(), indent=2, default=str))
        else:
            # Build detailed engineering output
            total_stages = len(result.stages)
            passed = result.metrics.get("passed", 0)
            failed = result.metrics.get("failed", 0)
            eng_score = result.engineering_score
            score_color = "bright_green" if eng_score >= 70 else "yellow" if eng_score >= 40 else "bright_red"

            # Stage breakdown table
            stage_table = Table(border_style="dim", header_style="bold", show_lines=False)
            stage_table.add_column("Stage", style="cyan", max_width=30)
            stage_table.add_column("Status", justify="center", max_width=10)
            stage_table.add_column("Duration", justify="right", max_width=10)
            for sr in result.stages:
                st_color = "green" if sr.status == "pass" else "red" if sr.status == "fail" else "yellow"
                stage_table.add_row(sr.stage.value, f"[{st_color}]{sr.status}[/{st_color}]", f"{sr.duration_s:.3f}s")

            # Quality intelligence detail
            qi_lines = []
            if result.quality_score > 0:
                qi_color = "bright_green" if result.quality_score >= 70 else "yellow" if result.quality_score >= 40 else "bright_red"
                qi_lines.append(f"Quality Score: [bold {qi_color}]{result.quality_score:.1f}/100[/] (Grade: {result.quality_grade or 'N/A'})")
                # Find quality intelligence stage data
                for sr in result.stages:
                    if sr.stage.value == "quality_intelligence" and sr.data:
                        qi_lines.append(f"Files Analyzed: {sr.data.get('files_analyzed', 0)}")
                        qi_lines.append(f"Total LOC: {sr.data.get('total_loc', 0)}")
                        sec_issues = sr.data.get('security_issues_total', 0)
                        if sec_issues > 0:
                            qi_lines.append(f"[red]Security Issues: {sec_issues}[/]")
                        gate = sr.data.get('gate_result', {})
                        if gate:
                            gate_passed = gate.get('passed', None)
                            if gate_passed is not None:
                                g_status = "[green]PASSED[/]" if gate_passed else "[red]FAILED[/]"
                                qi_lines.append(f"Quality Gate: {g_status}")
                        trend = sr.data.get('trend')
                        if trend:
                            qi_lines.append(f"Trend: {trend.get('direction', 'N/A').upper()}")
                        break

            # Recommendations summary
            rec_lines = []
            if result.recommendations_count > 0:
                rec_lines.append(f"[yellow]{result.recommendations_count} recommendation(s) generated[/]")
                for sr in result.stages:
                    if sr.stage.value == "recommendations" and sr.data:
                        for rec in sr.data.get("recommendations", [])[:5]:
                            sev = rec.get("severity", "info")
                            sev_c = "red" if sev == "critical" else "yellow" if sev in ("high", "medium") else "green"
                            rec_lines.append(f"  [{sev_c}]{sev.upper()}[/{sev_c}] {rec.get('title', 'N/A')}")
                        break

            console.print(Panel(
                Group(
                    Text(f"Status: [bold]{result.overall_status.upper()}[/bold]  |  "
                         f"Engineering Score: [bold {score_color}]{eng_score:.1f}/100[/]  |  "
                         f"Duration: {result.total_duration_s:.2f}s"),
                    Text(f"Stages: {passed}/{total_stages} passed" + (f"  |  {failed} failed" if failed else "")),
                    *(Text(l) for l in qi_lines) if qi_lines else (),
                    *(Text(l) for l in rec_lines) if rec_lines else (),
                ),
                title="[bold]ENGINEERING PIPELINE[/bold]",
                border_style="bright_cyan",
            ))
            console.print(stage_table)
        return

    if cmd == "validate":
        from .auto_validation import ValidationPipeline
        import json as _json
        repo = getattr(args, "repo", ".")
        if not getattr(args, "json_output", False):
            _banner(args)
            console.print(f"\n  [bold]Running validation pipeline on [cyan]{repo}[/]...[/]")
        pipeline = ValidationPipeline(repo)
        report = pipeline.validate_full()
        if getattr(args, "json_output", False):
            print(_json.dumps(report.to_dict(), indent=2, default=str))
        else:
            console.print(Panel(
                f"Status: [bold]{report.summary()}[/bold]\n"
                f"Stages: {len(report.stage_results)}\n"
                f"Total findings: {len(report.all_findings)}",
                title="[bold]VALIDATION[/bold]",
                border_style="bright_cyan",
            ))
        return

    if cmd == "benchmark-engineering":
        from .benchmark_automation import BenchmarkAutomation
        import json as _json
        if not getattr(args, "json_output", False):
            _banner(args)
            console.print("\n  [bold]Running engineering benchmarks...[/]")
        ba = BenchmarkAutomation()
        if getattr(args, "quick", False):
            results = ba.run_quick_benchmark()
        else:
            results = ba.run_full_benchmark()
        report = ba.generate_benchmark_report()
        if getattr(args, "json_output", False):
            print(_json.dumps(results, indent=2, default=str))
        else:
            console.print(Panel(report, title="[bold]BENCHMARKS[/bold]", border_style="bright_cyan"))
        return

    if cmd == "recommendations":
        _banner(args)
        from .engineering_recommendations import get_recommender
        import json as _json
        recommender = get_recommender()
        dismiss_id = getattr(args, "dismiss", None)
        if dismiss_id:
            recommender.dismiss_recommendation(dismiss_id)
            console.print(f"  [green]Dismissed recommendation {dismiss_id}[/]")
            return
        show_all = getattr(args, "all", False)
        recs = recommender.get_all_recommendations()
        if getattr(args, "json_output", False):
            print(_json.dumps([r.to_dict() for r in recs], indent=2, default=str))
        else:
            active = [r for r in recs if not r.dismissed] if not show_all else recs
            if not active:
                console.print("\n  [green]No recommendations. Everything looks good.[/]")
            else:
                # Summary stats
                stats = recommender.get_recommendation_stats()
                console.print(Panel(
                    f"Active: [bold]{stats['active']}[/]  |  "
                    f"Dismissed: {stats['dismissed']}  |  "
                    f"Avg Priority: [bold]{stats.get('average_priority', 0):.1f}[/]  |  "
                    f"Avg Confidence: {stats.get('average_confidence', 0):.0%}",
                    title="[bold]RECOMMENDATIONS[/bold]",
                    border_style="bright_cyan",
                ))

                # Actionable table
                rec_table = Table(border_style="dim", header_style="bold", show_lines=False)
                rec_table.add_column("#", justify="right", style="dim", max_width=4)
                rec_table.add_column("Severity", justify="center", max_width=10)
                rec_table.add_column("Recommendation", style="white")
                rec_table.add_column("Category", style="cyan", max_width=14)
                rec_table.add_column("Effort", justify="center", max_width=8)
                rec_table.add_column("Confidence", justify="right", max_width=10)
                rec_table.add_column("Priority", justify="right", max_width=8)

                for idx, r in enumerate(active[:20], 1):
                    sev_color = "red" if r.severity == "critical" else "yellow" if r.severity in ("high", "medium") else "green"
                    rec_table.add_row(
                        str(idx),
                        f"[{sev_color}]{r.severity.upper()}[/{sev_color}]",
                        r.title,
                        r.category,
                        r.effort_estimate,
                        f"{r.confidence:.0%}",
                        f"{r.priority_score:.1f}",
                    )
                console.print(rec_table)

                # Show detailed description for top 3
                console.print()
                console.print("  [bold]Top Actionable Items:[/bold]")
                for r in active[:3]:
                    sev_color = "red" if r.severity == "critical" else "yellow" if r.severity in ("high", "medium") else "green"
                    console.print(f"\n  [{sev_color}]{r.severity.upper()}[/{sev_color}] {r.title}")
                    if r.description:
                        # Show first 200 chars of description
                        desc = r.description[:200] + ("..." if len(r.description) > 200 else "")
                        console.print(f"    [dim]{desc}[/]")
                    if r.affected_files:
                        files_str = ", ".join(r.affected_files[:3])
                        console.print(f"    [cyan]Files:[/] {files_str}")
                    console.print(f"    [dim]Effort: {r.effort_estimate} | Confidence: {r.confidence:.0%} | ID: {r.id}[/]")

                console.print(f"\n  [dim]Total: {len(active)} active recommendations (showing top 20)[/]")
                console.print("  [dim]Use: reconpro recommendations --dismiss ID to dismiss a recommendation[/]")
        return

    if cmd == "memory":
        _banner(args)
        from .repository_memory import RepositoryMemory
        import json as _json
        mem = RepositoryMemory()
        recall_key = getattr(args, "recall", None)
        search_text = getattr(args, "search", None)
        json_mode = getattr(args, "json_output", False)
        if recall_key:
            fact = mem.recall(recall_key)
            if json_mode:
                print(_json.dumps({"key": recall_key, "found": fact is not None, "value": str(fact.value) if fact else None}, indent=2, default=str))
            elif fact:
                console.print(f"  [cyan]{recall_key}[/]: {fact.value}")
            else:
                console.print(f"  [dim]No fact found for key: {recall_key}[/]")
            return
        if search_text:
            facts = mem.search(search_text)
            if json_mode:
                print(_json.dumps([{"key": f.key, "value": str(f.value)[:100]} for f in facts[:20]], indent=2, default=str))
            else:
                for f in facts[:20]:
                    console.print(f"  [cyan]{f.key}[/]: {str(f.value)[:100]}")
                console.print(f"\n  [dim]Found {len(facts)} facts matching '{search_text}'[/]")
            return
        if getattr(args, "stats", False):
            stats = mem.get_stats()
            if json_mode:
                print(_json.dumps(stats, indent=2, default=str))
            else:
                table = Table(border_style="dim", header_style="bold", title="Repository Memory Stats")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", justify="right")
                for k, v in stats.items():
                    table.add_row(str(k), str(v))
                console.print(table)
            return
        console.print("  Use: reconpro memory --recall KEY | --search TEXT | --stats")
        return

    if cmd == "digital-twin":
        from .digital_twin import DigitalTwin
        import json as _json
        twin = DigitalTwin()
        json_mode = getattr(args, "json_output", False)
        if getattr(args, "capture", False):
            state = twin.capture_state()
            twin.persist()
            if json_mode:
                print(_json.dumps(state.to_dict() if hasattr(state, "to_dict") else {"components": len(state.components), "status": state.overall_status}, indent=2, default=str))
            else:
                _banner(args)
                console.print("\n  [bold]Capturing system state...[/]")
                console.print(f"  [green]State captured and persisted.[/]")
                console.print(f"  Components: {len(state.components)}")
                console.print(f"  Overall status: {state.overall_status}")
            return
        if getattr(args, "anomaly", False):
            anomalies = twin.detect_anomaly()
            if json_mode:
                print(_json.dumps({"anomalies": anomalies, "count": len(anomalies)}, indent=2, default=str))
            else:
                _banner(args)
                console.print("\n  [bold]Detecting anomalies...[/]")
                if anomalies:
                    for a in anomalies[:20]:
                        console.print(f"  [yellow]ANOMALY[/]: {a}")
                else:
                    console.print("  [green]No anomalies detected.[/]")
            return
        if json_mode:
            print(_json.dumps({"error": "specify --capture or --anomaly"}, indent=2))
        else:
            _banner(args)
            console.print("  Use: reconpro digital-twin --capture | --anomaly")
        return

    if cmd == "auto-fix":
        from .auto_fix import AutoFixEngine
        import json as _json
        if not getattr(args, "json_output", False):
            _banner(args)
            console.print("\n  [bold]Analyzing for auto-fix proposals...[/]")
        engine = AutoFixEngine()
        proposals = engine.get_fix_history()
        if getattr(args, "json_output", False):
            print(_json.dumps([p.to_dict() for p in proposals], indent=2, default=str))
        else:
            if proposals:
                for p in proposals[:20]:
                    sev_color = "red" if p.risk_level == "CRITICAL" else "yellow" if p.risk_level == "HIGH" else "green"
                    console.print(f"  [{sev_color}]{p.risk_level}[/{sev_color}] {p.title}")
                    console.print(f"    [dim]File: {p.affected_file} | Confidence: {p.confidence:.0%}[/]")
                console.print(f"\n  [dim]Total: {len(proposals)} proposals | Use --apply to apply approved fixes[/]")
            else:
                console.print("  [green]No fix proposals. Run engineering pipeline first.[/]")
        return

    if cmd == "regression":
        _banner(args)
        from .regression_intelligence import RegressionIntelligence
        import json as _json
        ri = RegressionIntelligence()
        if getattr(args, "baseline", False):
            console.print("\n  [bold]Capturing regression baseline...[/]")
            ri.capture_baseline()
            console.print("  [green]Baseline captured.[/]")
            return
        if getattr(args, "detect", False):
            console.print("\n  [bold]Detecting regressions...[/]")
            regressions = ri.detect_regression()
            if regressions:
                for r in regressions[:20]:
                    console.print(f"  [red]REGRESSION[/]: {r.description}")
                console.print(f"\n  [dim]Total: {len(regressions)} regressions detected[/]")
            else:
                console.print("  [green]No regressions detected.[/]")
            return
        if getattr(args, "report", False):
            report = ri.generate_regression_report()
            if getattr(args, "json_output", False):
                print(_json.dumps(report, indent=2, default=str))
            else:
                console.print(Panel(report, title="[bold]REGRESSION REPORT[/bold]", border_style="bright_cyan"))
            return
        console.print("  Use: reconpro regression --baseline | --detect | --report")
        return

    # ── HEALTH ─────────────────────────────────────────────────
    if cmd == "health":
        import json as _json
        health = _module_health.get_all_module_health()
        if getattr(args, "json_output", False):
            print(_json.dumps(health, indent=2, default=str))
        else:
            if not health:
                console.print("  [green]All modules healthy — no failures recorded.[/]")
                console.print("  [dim]Run a scan first to populate health data.[/]")
            else:
                table = Table(title="Module Health", show_header=True, header_style="bold")
                table.add_column("Module", style="cyan")
                table.add_column("Score", justify="right")
                table.add_column("Status")
                table.add_column("Fails")
                table.add_column("Consec")
                table.add_column("Quarantine")
                for mid, info in sorted(health.items()):
                    score = info["health_score"]
                    score_color = "green" if score >= 0.8 else "yellow" if score >= 0.5 else "red"
                    if info["is_quarantined"]:
                        status = "[red]QUARANTINED[/]"
                    elif not info["is_healthy"]:
                        status = "[yellow]CIRCUIT OPEN[/]"
                    elif info.get("is_probe"):
                        status = "[bright_cyan]PROBE[/]"
                    else:
                        status = "[green]OK[/]"
                    qr = info["quarantine_remaining_s"]
                    q_str = f"{qr:.0f}s" if qr > 0 else "—"
                    table.add_row(
                        mid,
                        f"[{score_color}]{score:.2f}[/{score_color}]",
                        status,
                        str(info["failure_count"]),
                        str(info["consecutive_failures"]),
                        q_str,
                    )
                console.print(table)
        console.print()
        return

    # ── DEPS ───────────────────────────────────────────────────
    if cmd == "deps":
        import json as _json
        mods_arg = getattr(args, "modules", None)
        if mods_arg:
            mod_list = [m.strip().lower() for m in mods_arg.split(",")]
        else:
            mod_list = None
        if getattr(args, "json_output", False):
            out = {
                "dependencies": {k: v for k, v in MODULE_DEPENDENCIES.items() if mod_list is None or k in mod_list},
            }
            try:
                if mod_list:
                    out["execution_order"] = get_execution_order(mod_list)
            except ValueError as e:
                out["error"] = str(e)
            print(_json.dumps(out, indent=2))
        else:
            graph = visualize_dependencies(mod_list)
            console.print(Panel(graph, title="[bold]MODULE DEPENDENCY GRAPH[/bold]", border_style="bright_cyan", padding=(1, 2)))
        console.print()
        return

    # ── PALETTE ──────────────────────────────────────────────
    if cmd == "palette":
        from .command_palette import CommandPalette
        cp = CommandPalette()
        search = getattr(args, "theme", None)
        cp.show(search=search)
        return

    # ── THEME ──────────────────────────────────────────────────
    if cmd == "theme":
        from .theme import Theme
        action = args.action
        if action == "list":
            themes = Theme.available_themes()
            table = Table(title="Available Themes", header_style="bold", border_style="dim")
            table.add_column("Theme", style="cyan", width=18)
            table.add_column("Status", width=10)
            current = Theme.current_name()
            for t in sorted(themes):
                marker = "[bold bright_green]●[/bold bright_green]" if t == current else "[dim]○[/dim]"
                table.add_row(t, marker)
            console.print(table)
        elif action == "set":
            name = args.name
            if name:
                Theme.set_theme(name)
                console.print(f"  [green]Theme set to: {name}[/]")
            else:
                console.print("  [yellow]Usage: reconpro theme set <name>[/]")
        elif action == "current":
            t = Theme.current()
            console.print(f"  Current Theme: [cyan]{Theme.current_name()}[/]")
            console.print(f"  BG={t.BG} FG={t.FG} ACCENT={t.ACCENT}")
        console.print()
        return

    # ── WORKSPACE ──────────────────────────────────────────────
    if cmd == "workspace":
        from .workspace import WorkspaceManager
        wm = WorkspaceManager()
        action = args.action
        if action == "list":
            ws_list = wm.list_workspaces()
            if not ws_list:
                console.print("  [dim]No workspaces. Use 'reconpro workspace create <name> --targets t1.com,t2.com'[/]")
            else:
                table = Table(title="Workspaces", header_style="bold", border_style="dim")
                table.add_column("Name", style="cyan")
                table.add_column("Targets", style="dim")
                table.add_column("Active", width=8)
                for ws in ws_list:
                    is_active = "[bold green]●[/bold green]" if ws.get("active") else ""
                    table.add_row(ws.get("name", ""), ws.get("targets", ""), is_active)
                console.print(table)
        elif action == "create":
            name = args.name
            targets = args.targets
            if name and targets:
                wm.create(name, targets.split(","))
                console.print(f"  [green]Workspace '{name}' created with targets: {targets}[/]")
            else:
                console.print("  [yellow]Usage: reconpro workspace create <name> --targets t1.com,t2.com[/]")
        elif action == "switch":
            name = args.name
            if name:
                wm.switch(name)
                console.print(f"  [green]Switched to workspace: {name}[/]")
            else:
                console.print("  [yellow]Usage: reconpro workspace switch <name>[/]")
        elif action == "delete":
            name = args.name
            if name:
                wm.delete(name)
                console.print(f"  [green]Workspace '{name}' deleted[/]")
            else:
                console.print("  [yellow]Usage: reconpro workspace delete <name>[/]")
        elif action in ("export", "import"):
            name = args.name or "default"
            if action == "export":
                data = wm.export_ws(name)
                console.print(f"  [green]Workspace '{name}' exported ({len(data)} bytes)[/]")
            else:
                console.print("  [yellow]Usage: reconpro workspace import <name>[/]")
        console.print()
        return

    # ── NOTIFICATIONS ──────────────────────────────────────────
    if cmd == "notifications":
        from .notifications import NotificationCenter, NotificationLevel
        nc = NotificationCenter()
        raw_level = getattr(args, "level", None)
        level = NotificationLevel(raw_level.lower()) if raw_level and raw_level.lower() in [e.value for e in NotificationLevel] else None
        limit = getattr(args, "limit", 20)
        digest = getattr(args, "digest", False)
        clear = getattr(args, "clear", False)
        if clear:
            nc.clear()
            console.print("  [green]All notifications cleared.[/]")
            return
        json_out = getattr(args, "json_output", False)
        if json_out:
            import json as _json
            notifs = nc.get_all(level=level)
            print(_json.dumps([{"level": str(n.level), "source": n.source, "timestamp": n.timestamp, "message": n.message} for n in notifs], indent=2, default=str))
            return
        elif digest:
            d = nc.digest()
            console.print(Panel(str(d), title="[bold]Notification Digest[/bold]", border_style="cyan", padding=(1, 2)))
        else:
            notifs = nc.get_all(level=level)
            if not notifs:
                console.print("  [dim]No notifications.[/]")
            else:
                table = Table(title=f"Notifications ({len(notifs)})", show_header=True, header_style="bold", border_style="dim")
                table.add_column("Level", width=10)
                table.add_column("Source", width=12)
                table.add_column("Time", width=8)
                table.add_column("Message")
                for n in notifs:
                    lvl = n.level.value if hasattr(n.level, "value") else str(n.level)
                    lvl_color = {"CRITICAL": "bright_red", "WARNING": "yellow", "ERROR": "red", "INFO": "dim", "SUCCESS": "bright_green"}.get(lvl.upper(), "white")
                    table.add_row(f"[{lvl_color}]{lvl.upper()}[/{lvl_color}]", n.source, n.timestamp[:19] if n.timestamp else "", n.message)
                console.print(table)
        console.print()
        return

    # ── COPILOT ───────────────────────────────────────────────
    if cmd == "copilot":
        from .ai_copilot import AICopilot
        import json as _json
        copilot = AICopilot()
        action = args.action
        finding = getattr(args, "finding", None)
        copilot_args = args.args if hasattr(args, "args") else []
        json_mode = getattr(args, "json_output", False)
        result_data = {"action": action, "status": "executed"}
        if action == "chat":
            message = " ".join(copilot_args) if copilot_args else "Hello"
            copilot.chat(message)
        elif action == "explain" and finding:
            copilot.explain(finding)
        elif action == "explain":
            copilot.explain(" ".join(copilot_args) if copilot_args else "No finding specified")
        elif action == "summarize":
            copilot.summarize()
        elif action == "remediate" and finding:
            copilot.remediate(finding)
        elif action == "remediate":
            copilot.remediate(" ".join(copilot_args) if copilot_args else "No finding specified")
        elif action == "compare":
            copilot.compare()
        console.print()
        return

    # ── No args ─────────────────────────────────────────────────────
    parser.print_help()


if __name__ == "__main__":
    main()
