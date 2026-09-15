"""Extra CLI experiences: doctor --repair, tutorial, wizard, playground, suggest.

Imported lazily by cli.py so they never slow down startup.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from .constants import RECONPRO_HOME, PLUGIN_DIR, SCAN_HISTORY_DIR

try:  # rich is a hard dependency of the CLI
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
except ImportError:  # pragma: no cover
    console = None


def _print(text: str = "") -> None:
    if console:
        console.print(text)
    else:
        print(text)


# ═══════════════════════════════════════════════════════════════════════════
# doctor --repair
# ═══════════════════════════════════════════════════════════════════════════

def doctor_repair(dry_run: bool = False) -> Dict[str, Any]:
    """Apply safe, local-only repairs. Returns a report dict."""
    actions: List[Dict[str, str]] = []

    def fix(name: str, fn) -> None:
        try:
            detail = fn()
            actions.append({"fix": name, "status": "ok", "detail": detail or "done"})
        except Exception as exc:
            actions.append({"fix": name, "status": "error", "detail": str(exc)})

    def _clear_cache() -> str:
        removed = 0
        for cache in RECONPRO_HOME.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
            removed += 1
        for cache in RECONPRO_HOME.rglob("*.pyc"):
            try:
                cache.unlink()
                removed += 1
            except OSError:
                pass
        return f"removed {removed} cache entries"

    def _fix_home() -> str:
        RECONPRO_HOME.mkdir(parents=True, exist_ok=True)
        PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
        mode = oct(RECONPRO_HOME.stat().st_mode & 0o777)
        try:
            os.chmod(RECONPRO_HOME, 0o700)
        except OSError:
            pass
        return f"~/.reconpro ready (was {mode})"

    def _prune_tmp() -> str:
        cutoff = time.time() - 7 * 86400
        removed = 0
        for entry in Path(tempfile.gettempdir()).glob("reconpro-sbx-*"):
            try:
                if entry.is_dir() and entry.stat().st_mtime < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed += 1
            except OSError:
                pass
        return f"pruned {removed} stale sandbox workdirs (>7d old)"

    def _compact_history() -> str:
        if not SCAN_HISTORY_DIR.is_dir():
            return "no history yet"
        entries = sorted(SCAN_HISTORY_DIR.glob("*.json"))
        if len(entries) > 500:
            for old in entries[:-500]:
                try:
                    old.unlink()
                except OSError:
                    pass
            return f"compacted {len(entries)} -> 500 scan files"
        return f"{len(entries)} scan files (no compact needed)"

    if not dry_run:
        fix("clear-caches", _clear_cache)
        fix("ensure-home", _fix_home)
        fix("prune-stale-sandbox-dirs", _prune_tmp)
        fix("compact-history", _compact_history)

    report = {
        "command": "doctor --repair",
        "dry_run": dry_run,
        "actions": actions,
        "ok": all(a["status"] == "ok" for a in actions),
    }
    return report


# ═══════════════════════════════════════════════════════════════════════════
# tutorial
# ═══════════════════════════════════════════════════════════════════════════

TUTORIAL_STEPS = [
    ("What ReconPro is", "A self-contained security recon platform: 60+ modules, "
     "sandboxed plugins, SARIF/JSON/HTML reporting, zero telemetry."),
    ("Your first scan", "  reconpro scan example.com\nAdd --json for machine output, "
     "-o report.md to save, --modules http,tls to pick modules."),
    ("Local machine audit", "  reconpro audit          # ports, firewall, SSH, Docker\n"
     "  reconpro secrets        # leaked credentials\n  reconpro doctor          # health check"),
    ("Code & cloud", "  reconpro ast /path/to/code    # AST vulnerability patterns\n"
     "  reconpro iac ./infra         # Terraform/K8s/Docker audit\n"
     "  reconpro cloud-recon example.com"),
    ("Threat intel", "  reconpro cve 'sql injection'  # NVD lookup\n"
     "  reconpro graph example.com   # attack-path knowledge graph\n"
     "  reconpro passive example.com"),
    ("Plugins (sandboxed)", "  reconpro plugin create-sdk my-check\n"
     "  reconpro plugin sign ~/.reconpro/plugins/my-check\n"
     "  reconpro plugin install ~/.reconpro/plugins/my-check\n"
     "  reconpro plugin run my-check example.com"),
    ("Reports & CI", "  reconpro export report.sarif   # GitHub Code Scanning\n"
     "  reconpro export report.md\n  reconpro history --json"),
    ("Where to go next", "  reconpro suggest               # next best commands\n"
     "  reconpro wizard                # guided scan plan\n  reconpro list                  # all modules"),
]


def run_tutorial(step: int | None = None, list_only: bool = False) -> None:
    if list_only:
        for i, (title, _) in enumerate(TUTORIAL_STEPS, 1):
            _print(f"  [cyan]{i}.[/] {title}")
        return
    steps = TUTORIAL_STEPS if step is None else [TUTORIAL_STEPS[step - 1]]
    for i, (title, body) in enumerate(steps, start=(step or 1)):
        _print(Panel(body, title=f"[bold]Step {i} — {title}[/]", border_style="cyan"))
    if step is None:
        _print("  [dim]Re-run with --step N to revisit one, or try: reconpro wizard[/]")


# ═══════════════════════════════════════════════════════════════════════════
# wizard
# ═══════════════════════════════════════════════════════════════════════════

def run_wizard(non_interactive: bool = False) -> None:
    _print(Panel("[bold]ReconPro Scan Wizard[/] — build a scan plan step by step",
                 border_style="bright_cyan"))
    if non_interactive:
        _plan({})  # sensible defaults
        return
    answers: Dict[str, Any] = {}

    def ask(label: str, default: str) -> str:
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return default
        return raw or default

    answers["target"] = ask("Target domain/URL", "example.com")
    kind = ask("Scan type: quick|full|web|cloud|local", "quick")
    answers["kind"] = kind
    answers["format"] = ask("Report format: text|json|sarif|md|html", "text")
    if kind == "local":
        answers["path"] = ask("Path to audit", ".")
    _plan(answers)


def _plan(a: Dict[str, Any]) -> None:
    kind = a.get("kind", "quick")
    target = a.get("target", "example.com")
    fmt = a.get("format", "text")
    out_flag = {"json": "--json", "sarif": "-o report.sarif", "md": "-o report.md",
                "html": "-o report.html"}.get(fmt, "")
    plans = {
        "quick": [f"reconpro scan {target} {out_flag}".strip(),
                  f"reconpro profile {target}"],
        "full": [f"reconpro scan {target} --all {out_flag}".strip(),
                 f"reconpro graph {target}",
                 f"reconpro subdomains {target}",
                 "reconpro export report.sarif"],
        "web": [f"reconpro scan {target} --modules http,tls,auth,chain {out_flag}".strip(),
                f"reconpro fuzzer {target}"],
        "cloud": [f"reconpro cloud-recon {target}", "reconpro iac .",
                  "reconpro container ."],
        "local": [f"reconpro audit", "reconpro secrets", "reconpro ast {path}".format(
            path=a.get("path", "."))],
    }
    steps = plans.get(kind, plans["quick"])
    _print(f"\n  [bold]Your {kind} plan for {target}:[/]\n")
    for i, s in enumerate(steps, 1):
        _print(f"   [cyan]{i}.[/] {s}")
    _print("\n  [dim]Copy-paste them in order. Add --json anywhere for machine output.[/]\n")


# ═══════════════════════════════════════════════════════════════════════════
# playground — sandboxed plugin lab
# ═══════════════════════════════════════════════════════════════════════════

PLAYGROUND_TEMPLATE = '''def run(target, base_url="", timeout=8, verify_tls=True):
    """Playground plugin — runs INSIDE the OS-process sandbox.

    Try anything: open() outside the workdir, sockets, subprocesses —
    every escape is blocked and reported back as a sandbox violation.
    """
    return [{
        "title": f"playground ok on {target}",
        "severity": "info", "category": "playground",
        "description": "Your plugin executed safely inside the sandbox.",
    }]
'''


def run_playground(file: str | None = None, target: str = "example.com") -> int:
    from .plugin_sdk import PluginRunner
    from .plugin_sdk.analysis import check_runnable, summarize

    if file:
        path = Path(file).expanduser().resolve()
        if not path.is_file():
            _print(f"  [red]No such file: {path}[/]")
            return 1
        source = path.read_text(errors="replace")
    else:
        path = Path(tempfile.mkdtemp(prefix="reconpro-play-")) / "playground.py"
        path.write_text(PLAYGROUND_TEMPLATE)
        source = PLAYGROUND_TEMPLATE
        _print(f"  [dim]No file given — using the built-in template at {path}[/]")

    runnable, violations = check_runnable(source, __import__(
        "reconpro.plugin_sdk", fromlist=["PermissionSet"]).PermissionSet())
    if not runnable:
        _print(f"  [red]Static analysis refuses this plugin:[/]\n  {summarize(violations)}")
        return 1

    _print(f"  [cyan]Running[/] {path.name} against [bold]{target}[/] "
           f"[dim](sandbox: own PID, no net, no subprocess, workdir-only writes)[/]")
    runner = PluginRunner(wall_timeout_s=10)
    result = runner.execute(path, args={"target": target})
    _print(f"  result: kind={result.kind} ok={result.ok} pid={result.pid} "
           f"duration={result.duration_ms}ms")
    if result.error:
        _print(f"  [yellow]error:[] {result.error[:300]}")
    for f in result.findings:
        _print(f"   • {f.get('title', '')}")
    for v in result.audit_violations[:5]:
        _print(f"  [red]violation:[] {v.get('event')} — {v.get('detail')}")
    return 0 if result.ok else 1


# ═══════════════════════════════════════════════════════════════════════════
# suggest — next best commands
# ═══════════════════════════════════════════════════════════════════════════

def run_suggest(json_output: bool = False) -> List[Dict[str, str]]:
    suggestions: List[Dict[str, str]] = []
    has_history = SCAN_HISTORY_DIR.is_dir() and any(SCAN_HISTORY_DIR.glob("*.json"))

    if not has_history:
        suggestions.append({
            "cmd": "reconpro scan example.com",
            "why": "No scan history yet — run your first scan."})
        suggestions.append({"cmd": "reconpro tutorial", "why": "New here? 8-step tour."})
    else:
        suggestions.append({"cmd": "reconpro history", "why": "You have past scans — review them."})
        suggestions.append({"cmd": "reconpro diff <scan1> <scan2>", "why": "Compare two scans."})
        suggestions.append({"cmd": "reconpro export report.sarif", "why": "Ship results to CI."})
    suggestions.append({"cmd": "reconpro doctor", "why": "Health check (add --repair to autofix)."})
    suggestions.append({"cmd": "reconpro plugin list", "why": "Sandboxed plugins installed?"})
    suggestions.append({"cmd": "reconpro benchmark", "why": "Measure your score."})
    suggestions.append({"cmd": "reconpro secrets", "why": "Local credential leak check."})

    if json_output:
        print(json.dumps(suggestions, indent=2))
    else:
        _print(Panel("[bold]Suggested next steps[/]", border_style="bright_green"))
        for s in suggestions:
            _print(f"   [cyan]{s['cmd']}[/]\n     [dim]{s['why']}[/]\n")
    return suggestions
