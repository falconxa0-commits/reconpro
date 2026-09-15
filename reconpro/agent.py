"""Autonomous agent mode.

Takes a high-level goal and chains scanning modules to achieve it.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .scanner import scan, audit_scan
from .subdomains import discover_subdomains
from .parallel import blitz_scan
from .history import save_scan
from .http_layer import Finding
from .utils import compute_grade

console = Console()


def _parse_goal(goal: str) -> Dict[str, Any]:
    """Parse a natural-language goal into actionable steps."""
    goal_lower = goal.lower()
    steps = []
    targets = []

    # Extract domains/URLs from the goal
    import re
    urls = re.findall(r'https?://[\w\-\.]+(?:/\S*)?', goal)
    domains = re.findall(r'[\w][\w\-]*\.[\w]{2,}(?:\.[\w]{2,})?', goal)
    
    # Remove common non-domain words
    skip = {'the', 'and', 'for', 'with', 'all', 'of', 'to', 'from', 'that', 'this', 'then', 'scan', 'audit', 'check', 'find', 'get', 'show', 'tell', 'me', 'my', 'its', 'every'}
    domains = [d for d in domains if d.lower() not in skip and '.' in d and len(d) > 3]
    
    if urls:
        targets.extend(urls)
    elif domains:
        targets.extend(domains)

    # Determine intent
    is_local = any(w in goal_lower for w in ['machine', 'laptop', 'computer', 'local', 'my system'])
    is_subdomain = any(w in goal_lower for w in ['subdomain', 'sub-domain', 'attack surface'])
    is_full = any(w in goal_lower for w in ['full', 'everything', 'all modules', 'deep', 'complete'])
    is_compare = any(w in goal_lower for w in ['compare', 'difference', 'vs', 'versus', 'against'])
    is_secrets = any(w in goal_lower for w in ['secret', 'credential', 'key', 'token', 'password'])

    return {
        'targets': list(set(targets)),
        'is_local': is_local,
        'is_subdomain': is_subdomain,
        'is_full': is_full,
        'is_compare': is_compare,
        'is_secrets': is_secrets,
        'raw_goal': goal,
    }


def run_agent(goal: str, save: bool = True) -> Dict[str, Any]:
    """Execute an autonomous scan based on a natural language goal.
    
    Returns a dict with all results.
    """
    parsed = _parse_goal(goal)
    results = {
        'goal': goal,
        'steps': [],
        'targets': [],
        'total_findings': 0,
        'results': [],
    }

    console.print(f"\n  [bold bright_cyan]Goal:[/] {goal}")
    console.print(f"  [dim]Parsed intent: {len(parsed['targets'])} target(s), local={parsed['is_local']}, full={parsed['is_full']}, subdomains={parsed['is_subdomain']}[/]")

    # ── Local machine audit ──────────────────────────────────────────
    if parsed['is_local']:
        console.print("\n  [bold]Step 1:[/] Auditing local machine...")
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("  Auditing machine...", total=None)
            result = audit_scan(target="localhost")
            prog.update(task, completed=True)
        
        data = result.to_dict()
        results['results'].append(data)
        results['total_findings'] += len(result.findings)
        results['targets'].append('localhost')
        results['steps'].append('Local machine audit')
        if save:
            save_scan(data, label='agent')

    # ── Subdomain discovery + scan ────────────────────────────────────
    if parsed['is_subdomain'] and parsed['targets']:
        for target in parsed['targets']:
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
            console.print(f"\n  [bold]Step:[/] Discovering subdomains of [cyan]{domain}[/]...")
            subs = discover_subdomains(domain)
            console.print(f"  Found [cyan]{len(subs)}[/] subdomains")
            
            if subs:
                console.print(f"\n  [bold]Step:[/] Blitz scanning all subdomains...")
                blitz_result = blitz_scan(subs, max_workers=4, modules=['recon', 'vibesec'], save=save)
                results['steps'].append(f'Subdomain discovery + blitz ({len(subs)} subs)')
                results['total_findings'] += blitz_result['total_findings']

    # ── Remote target scanning ───────────────────────────────────────
    if parsed['targets'] and not parsed['is_local']:
        modules = None if parsed['is_full'] else None  # use defaults
        all_mods = parsed['is_full']

        if len(parsed['targets']) > 1:
            console.print(f"\n  [bold]Step:[/] Blitz scanning [cyan]{len(parsed['targets'])}[/] targets...")
            blitz_result = blitz_scan(
                parsed['targets'], max_workers=min(4, len(parsed['targets'])),
                modules=modules, all_modules=all_mods, save=save,
            )
            results['total_findings'] += blitz_result['total_findings']
            results['steps'].append(f'Blitz scan ({len(parsed["targets"])} targets)')
            for t, r in blitz_result.get('results', {}).items():
                results['results'].append(r)
                results['targets'].append(t)
        else:
            target = parsed['targets'][0]
            console.print(f"\n  [bold]Step:[/] Scanning [cyan]{target}[/]...")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task("  Scanning...", total=None)
                result = scan(target, modules=modules, all_modules=all_mods)
                prog.update(task, completed=True)
            data = result.to_dict()
            results['results'].append(data)
            results['total_findings'] += len(result.findings)
            results['targets'].append(target)
            results['steps'].append(f'Scan {target}')
            if save:
                save_scan(data, label='agent')

    # ── Compare mode ──────────────────────────────────────────────────
    if parsed['is_compare'] and len(results['results']) >= 2:
        from .history import diff_scans
        a = results['results'][0]
        b = results['results'][-1]
        a['target'] = a.get('target', 'scan-a')
        b['target'] = b.get('target', 'scan-b')
        
        d = diff_scans(json.dumps(a), json.dumps(b))
        results['comparison'] = d
        results['steps'].append('Comparison')
        
        console.print(f"\n  [bold]Comparison:[/]")
        console.print(f"    Score A: {d['scan_a']['score']} ({d['scan_a']['grade']})")
        console.print(f"    Score B: {d['scan_b']['score']} ({d['scan_b']['grade']})")
        console.print(f"    Change: {'+' if d['score_change'] > 0 else ''}{d['score_change']} points")
        if d['new']:
            console.print(f"    New issues: {len(d['new'])}")
        if d['fixed']:
            console.print(f"    Fixed: {len(d['fixed'])}")

    console.print(f"\n  [bold bright_green]Agent complete.[/] {results['total_findings']} total findings across {len(results['targets'])} target(s).")
    console.print(f"  Steps: {', '.join(results['steps'])}\n")
    
    return results
