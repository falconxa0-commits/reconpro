"""Interactive chat mode — talk to ReconPro like a teammate.

Commands parsed from natural language:
  scan example.com                  → run remote scan
  scan example.com with recon,auth → specific modules
  audit                            → audit local machine
  dev /path                        → dev scan
  doctor                           → health check
  blitz t1.com t2.com t3.com      → parallel scan
  subdomains example.com          → discover subdomains
  screenshot example.com          → browser screenshot
  open example.com                 → open in browser
  agent find all subdomains of... → autonomous mode
  history                          → show past scans
  compare                          → diff last two scans
  report                           → HTML report from last scan
  score                            → show last score
  find secrets                     → secret scan
  ports                            → port scan
  export pdf                       → generate report
  help                             → show all commands
  quit / exit                      → leave
"""
from __future__ import annotations

import json
import os
import re
import readline  # noqa: F401 — enables arrow keys / history
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .scanner import scan, audit_scan, MODULE_REGISTRY, LOCAL_MODULES, ALL_MODULES
from .history import list_scans, get_latest, diff_scans, save_scan
from .parallel import blitz_scan
from .subdomains import discover_subdomains
from .reports import generate_html_report
from .agent import run_agent

console = Console()

SEV_COLORS = {
    "critical": "bright_red", "high": "red",
    "medium": "yellow", "low": "green", "info": "dim",
}
GRADE_COLORS = {
    "A+": "bright_green", "A": "green", "B": "yellow",
    "C": "red", "D": "bright_red", "F": "bold bright_red",
}

BANNER_SMALL = r"""[bold bright_white]
██╗     ███████╗██████╗ ███████╗██████╗ ███████╗██████╗
██║     ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗
██║     █████╗  ██████╔╝█████╗  ██████╔╝█████╗  ██████╔╝
██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
███████╗███████╗██║  ██║███████╗██║  ██║███████╗██║  ██╗
╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
[/bold bright_white][dim]            C H A T   M O D E[/dim]"""

HELP_TEXT = """
[bright_white]ReconPro Chat Commands:[/bright_white]

  [cyan]scan[/] <target> [with <mods>]     Remote scan (e.g. scan example.com with recon,auth)
  [cyan]audit[/]                          Audit your local machine
  [cyan]dev[/] [path]                      Developer project scan
  [cyan]doctor[/]                         Quick health check
  [cyan]blitz[/] <t1> <t2> ...            Parallel multi-target scan
  [cyan]subdomains[/] <domain>             Discover subdomains
  [cyan]screenshot[/] <url>                Take browser screenshot (needs: pip install reconpro[browser])
  [cyan]open[/] <url>                      Open URL in browser
  [cyan]agent[/] <goal>                    Autonomous mode (e.g. agent fully scan example.com)
  [cyan]history[/] [target]                Show past scans
  [cyan]compare[/]                         Compare last two scans
  [cyan]report[/]                          Generate HTML report from last scan
  [cyan]secrets[/] [path]                  Hunt for secrets
  [cyan]ports[/]                          Show open ports
  [cyan]score[/]                           Show last scan score
  [cyan]list[/] [--local/--all]            List modules
  [cyan]clear[/]                           Clear screen
  [cyan]help[/]                            Show this help
  [cyan]quit[/] / [cyan]exit[/]                  Leave chat
"""


class ChatSession:
    def __init__(self):
        self.last_result: Optional[Any] = None
        self.last_target: Optional[str] = None
        self.context: Dict[str, Any] = {}
        # Prompt defense — scans every user input for injection threats
        self._defense: Optional[Any] = None
        try:
            from .prompt_defense import PromptDefense
            self._defense = PromptDefense(enable_logging=True)
        except Exception:
            pass

    def start(self):
        console.print(BANNER_SMALL)
        console.print(f"  [dim]v{__version__} | Type [bold]help[/] for commands, [bold]quit[/] to exit[/]")
        console.print()

        while True:
            try:
                user_input = console.input("  [bold bright_cyan]reconpro> [/]").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n  [dim]Goodbye.[/]")
                break

            if not user_input:
                continue

            self._process(user_input)

    def _process(self, text: str):
        # ── Prompt Defense (Agent 10) ───────────────────────────
        # Every user input goes through PromptDefense before processing
        if self._defense is not None:
            try:
                defense_result = self._defense.scan(text, source="chat")
                if not defense_result.is_safe:
                    threat_names = ", ".join(t.pattern_name for t in defense_result.threats[:3])
                    console.print(
                        f"  [bold bright_red]Blocked[/]: Potential prompt injection detected ({threat_names})."
                    )
                    console.print(
                        f"  [dim]Max severity: {defense_result.max_severity.value} | "
                        f"Threats: {len(defense_result.threats)}[/]"
                    )
                    return
            except Exception:
                pass  # Allow input through if defense fails

        low = text.lower().strip()

        # ── Exit ────────────────────────────────────────────────
        if low in ("quit", "exit", "q"):
            console.print("  [dim]Goodbye.[/]")
            sys.exit(0)

        # ── Help ────────────────────────────────────────────────
        if low in ("help", "?", "commands"):
            console.print(HELP_TEXT)
            return

        # ── Clear ───────────────────────────────────────────────
        if low == "clear":
            console.clear()
            return

        # ── Score ───────────────────────────────────────────────
        if low == "score":
            if self.last_result:
                g = self.last_result.grade
                gc = GRADE_COLORS.get(g, "white")
                console.print(f"  Last scan: [{gc}]{self.last_result.total_score}/100 ({g})[/{gc}] — {self.last_result.target}")
            else:
                latest = get_latest()
                if latest:
                    g = latest.get("grade", "?")
                    gc = GRADE_COLORS.get(g, "white")
                    console.print(f"  Latest: [{gc}]{latest.get('total_score', '?')}/100 ({g})[/{gc}] — {latest.get('target', '?')}")
                else:
                    console.print("  [dim]No scans yet. Run a scan first.[/]")
            return

        # ── List modules ─────────────────────────────────────────
        if low.startswith("list"):
            show_local = "--local" in low or "--all" in low
            show_all = "--all" in low
            if show_local or show_all:
                console.print("\n[bold bright_yellow]Local:[/bold bright_yellow]")
                for mid, entry in LOCAL_MODULES.items():
                    console.print(f"  [cyan]{mid:12}[/] {entry['name']}")
            if not show_local or show_all:
                console.print("\n[bold]Remote:[/bold]")
                for mid, entry in MODULE_REGISTRY.items():
                    console.print(f"  [cyan]{mid:12}[/] {entry['name']}")
            console.print()
            return

        # ── History ─────────────────────────────────────────────
        if low.startswith("history"):
            target = None
            parts = low.split()
            if len(parts) > 1 and parts[1] not in ("--", "-"):
                target = parts[1]
            scans = list_scans(target=target, limit=10)
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
                ts = s.get("_saved_at", "?")[:16]
                table.add_row(
                    ts, s.get("target", "?")[:25],
                    str(s.get("total_score", "?")),
                    f"[{gc}]{g}[/{gc}]",
                    str(len(s.get("findings", []))),
                    s.get("_file", ""),
                )
            console.print(table)
            return

        # ── Compare ─────────────────────────────────────────────
        if low.startswith("compare"):
            scans = list_scans(limit=2)
            if len(scans) < 2:
                console.print("  [yellow]Need at least 2 scans in history to compare.[/]")
                return
            d = diff_scans(scans[0]["_file"], scans[1]["_file"])
            console.print(f"\n  [bold]{d['scan_a']['target']}[/]  score={d['scan_a']['score']} ({d['scan_a']['grade']})")
            console.print(f"  [bold]{d['scan_b']['target']}[/]  score={d['scan_b']['score']} ({d['scan_b']['grade']})")
            change = d['score_change']
            color = "green" if change > 0 else ("red" if change < 0 else "dim")
            console.print(f"  Change: [{color}]{'+' if change > 0 else ''}{change} pts[/{color}]")
            if d['new']:
                console.print(f"  [red]New issues ({len(d['new'])}):[/red] {', '.join(d['new'][:5])}")
            if d['fixed']:
                console.print(f"  [green]Fixed ({len(d['fixed'])}):[/green] {', '.join(d['fixed'][:5])}")
            console.print()
            return

        # ── Report ───────────────────────────────────────────────
        if low.startswith("report"):
            source = None
            if self.last_result:
                source = self.last_result.to_dict()
            else:
                source = get_latest()
            if not source:
                console.print("  [yellow]No scan data. Run a scan first.[/]")
                return
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
                task = prog.add_task("Generating HTML report...", total=None)
                path = generate_html_report(source)
                prog.update(task, completed=True)
            console.print(f"  [green]Report saved: [cyan]{path}[/][/]")
            return

        # ── Ports ────────────────────────────────────────────────
        if low == "ports":
            from .modules.host import _check_open_ports
            console.print("  Scanning ports...")
            findings = _check_open_ports()
            if not findings:
                console.print("  [bright_green]No risky ports found.[/]")
            else:
                for f in findings:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
            return

        # ── Secrets ──────────────────────────────────────────────
        if low.startswith("secrets"):
            path = "."
            parts = low.split()
            if len(parts) > 1:
                path = parts[1]
            from .modules.host import _check_env_secrets
            from .modules.dev import _check_env_files, _check_hardcoded_secrets
            console.print("  [bright_red]Hunting secrets...[/]")
            all_f = _check_env_secrets() + _check_env_files(os.path.abspath(path)) + _check_hardcoded_secrets(os.path.abspath(path))
            if not all_f:
                console.print("  [bright_green]Clean. No secrets found.[/]")
            else:
                for f in all_f:
                    c = SEV_COLORS.get(f.severity, "white")
                    console.print(f"  [{c}]{f.severity.upper():8}[/{c}]  {f.title}")
            return

        # ── Audit ────────────────────────────────────────────────
        if low.startswith("audit"):
            console.print("  Auditing machine...")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task("Auditing...", total=None)
                self.last_result = audit_scan(target="localhost")
                save_scan(self.last_result.to_dict())
                prog.update(task, completed=True)
            self._show_quick_result()
            return

        # ── Dev scan ─────────────────────────────────────────────
        if low.startswith("dev ") or low == "dev":
            path = parts = low.split()
            path = parts[1] if len(parts) > 1 else "."
            console.print(f"  Scanning project: {path}")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
                task = prog.add_task("Scanning...", total=None)
                self.last_result = audit_scan(target=path, modules=["dev"])
                prog.update(task, completed=True)
            self._show_quick_result()
            return

        # ── Doctor ───────────────────────────────────────────────
        if low.startswith("doctor"):
            console.print("  Running diagnostics...")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
                task = prog.add_task("Diagnosing...", total=None)
                self.last_result = audit_scan(target="localhost", modules=["doctor"])
                prog.update(task, completed=True)
            self._show_quick_result(show_fixes=True)
            return

        # ── Subdomains ───────────────────────────────────────────
        if low.startswith("subdomain"):
            parts = low.split()
            if len(parts) < 2:
                console.print("  [yellow]Usage: subdomains <domain>[/]")
                return
            domain = parts[1]
            console.print(f"  Discovering subdomains of [cyan]{domain}[/]...")
            subs = discover_subdomains(domain)
            if not subs:
                console.print("  [dim]No subdomains found.[/]")
            else:
                console.print(f"  [green]{len(subs)} subdomain(s):[/green]")
                for s in subs:
                    console.print(f"    [cyan]{s}[/]")
            return

        # ── Screenshot ───────────────────────────────────────────
        if low.startswith("screenshot"):
            parts = low.split()
            if len(parts) < 2:
                console.print("  [yellow]Usage: screenshot <url>[/]")
                return
            url = parts[1]
            try:
                from .browser_mod import take_screenshot
                with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
                    task = prog.add_task("Taking screenshot...", total=None)
                    path = take_screenshot(url)
                    prog.update(task, completed=True)
                console.print(f"  [green]Screenshot saved: [cyan]{path}[/][/]")
            except ImportError:
                console.print("  [yellow]Install browser support: pip install reconpro[browser] && playwright install[/]")
            return

        # ── Open browser ──────────────────────────────────────────
        if low.startswith("open "):
            url = low.split(" ", 1)[1]
            from .browser_mod import open_browser
            open_browser(url)
            console.print(f"  Opened [cyan]{url}[/] in browser")
            return

        # ── Blitz ────────────────────────────────────────────────
        if low.startswith("blitz"):
            targets = re.findall(r'([\w\-]+\.[\w]{2,}(?:\.[\w]{2,})?)', low)
            if len(targets) < 2:
                console.print("  [yellow]Usage: blitz target1.com target2.com target3.com[/]")
                return
            console.print(f"  Blitz scanning [cyan]{len(targets)}[/] targets...")
            blitz_scan(targets, max_workers=min(4, len(targets)))
            return

        # ── Agent ────────────────────────────────────────────────
        if low.startswith("agent "):
            goal = text.split(" ", 1)[1] if " " in text else text
            run_agent(goal)
            return

        # ── Scan (default / explicit) ─────────────────────────────
        if low.startswith("scan ") or low.startswith("vibesec "):
            is_vibesec = low.startswith("vibesec")
            rest = text.split(" ", 1)[1] if " " in text else ""
            modules = None

            # Parse "with recon,auth"
            if "with " in rest.lower():
                m = re.search(r'with\s+([\w,\s]+)', rest, re.IGNORECASE)
                if m:
                    modules = [x.strip().lower() for x in m.group(1).split(",") if x.strip()]
                    rest = rest[:m.start()] + rest[m.end():]

            target = rest.strip().split("with")[0].strip()
            if not target:
                console.print("  [yellow]Usage: scan <target> [with <modules>][/]")
                return

            self.last_target = target
            console.print(f"  Scanning [cyan]{target}[/]...")

            with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task("Scanning...", total=None)
                if is_vibesec:
                    self.last_result = scan(target, modules=["vibesec"])
                else:
                    self.last_result = scan(target, modules=modules)
                save_scan(self.last_result.to_dict())
                prog.update(task, completed=True)
            self._show_quick_result()
            return

        # ── Fallback: treat as a scan target or agent goal ───────
        # If it looks like a domain/URL, scan it
        if re.match(r'^[\w\-]+\.[\w]{2,}', low) or low.startswith("http"):
            self.last_target = low
            console.print(f"  Scanning [cyan]{low}[/]...")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task("Scanning...", total=None)
                self.last_result = scan(low)
                save_scan(self.last_result.to_dict())
                prog.update(task, completed=True)
            self._show_quick_result()
            return

        # ── Unknown command ───────────────────────────────────────
        console.print(f"  [yellow]Unknown command: {text}[/]")
        console.print(f"  Type [bold]help[/] for available commands.")

    def _show_quick_result(self, show_fixes: bool = False):
        """Show a compact result summary."""
        r = self.last_result
        if not r:
            return
        g = r.grade
        gc = GRADE_COLORS.get(g, "white")
        sc = r.severity_counts
        total = len(r.findings)

        bar_w = 30
        filled = int(r.total_score / 100 * bar_w)
        bar = "█" * filled + "░" * (bar_w - filled)

        console.print(f"\n  {bar} [{gc}]{r.total_score}/100 ({g})[/{gc}]  {r.target}")
        console.print(f"  Findings: [bold]{total}[/]  [bright_red]{sc.get('critical',0)} crit[/] [red]{sc.get('high',0)} high[/] [yellow]{sc.get('medium',0)} med[/] [green]{sc.get('low',0)} low[/]")

        # Top 5 findings
        top = sorted(r.findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),4))[:5]
        if top:
            console.print(f"  [dim]Top findings:[/]")
            for f in top:
                c = SEV_COLORS.get(f.get("severity","info"), "white")
                console.print(f"    [{c}]{f['severity'].upper():8}[/{c}] {f['title'][:60]}")

        if show_fixes:
            fixes = set()
            for f in r.findings:
                fix = f.get("remediation", "").strip()
                if fix and f.get("points_deducted", 0) > 0:
                    fixes.add(fix)
            if fixes:
                console.print(f"\n  [bright_green]Fix commands:[/bright_green]")
                for fix in list(fixes)[:8]:
                    console.print(f"    [dim]>[/] {fix}")

        console.print(f"  [dim]Saved to history. Type 'report' for HTML, 'compare' for diff.[/]")
        console.print()


def start_chat():
    """Entry point for chat mode."""
    session = ChatSession()
    session.start()
