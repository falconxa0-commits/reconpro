"""Cron-like scheduled scanning.

  reconpro schedule example.com --every 30m
  reconpro schedule example.com --every 1h --modules recon,auth
  reconpro schedule audit --every 6h
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .constants import GRADE_COLORS
from .scanner import scan, audit_scan
from .history import save_scan

console = Console()


def _parse_interval(interval_str: str) -> int:
    """Parse interval string to seconds. Supports: 30m, 1h, 6h, 1d"""
    s = interval_str.strip().lower()
    if s.endswith('m'):
        return int(s[:-1]) * 60
    elif s.endswith('h'):
        return int(s[:-1]) * 3600
    elif s.endswith('d'):
        return int(s[:-1]) * 86400
    else:
        return int(s)


def run_scheduled(
    target: str,
    interval: str = "1h",
    modules: Optional[List[str]] = None,
    is_local: bool = False,
    max_runs: int = 0,
) -> None:
    """Run scans on a schedule.
    
    Args:
        target: URL/domain or 'audit'
        interval: Interval string (e.g. '30m', '1h', '6h')
        modules: Module list (None = defaults)
        is_local: If True, run local audit
        max_runs: 0 = infinite, N = stop after N runs
    """
    interval_secs = _parse_interval(interval)
    runs = 0
    
    console.print(f"  [bold]Scheduled scan configured:[/]")
    console.print(f"    Target: [cyan]{target}[/]")
    console.print(f"    Interval: [yellow]{interval}[/] ({interval_secs}s)")
    console.print(f"    Mode: {'local audit' if is_local else 'remote scan'}")
    console.print(f"    Modules: {modules or 'default'}")
    console.print(f"    Press Ctrl+C to stop.\n")
    
    def _shutdown(sig, frame):
        console.print(f"\n  [yellow]Scheduler stopped after {runs} run(s).[/]")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    
    while True:
        runs += 1
        if max_runs > 0 and runs > max_runs:
            console.print(f"  [dim]Reached max runs ({max_runs}). Stopping.[/]")
            break
            
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"  [dim][{ts}] Run #{runs}...[/]")
        
        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), 
                          TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task(f"  Scanning {target}...", total=None)
                
                if is_local:
                    result = audit_scan(target=target, modules=modules)
                else:
                    result = scan(target, modules=modules)
                
                save_scan(result.to_dict(), label='scheduled')
                prog.update(task, completed=True)
            
            g = result.grade
            gc = GRADE_COLORS.get(g, "white")
            console.print(f"    [{gc}]{result.total_score}/100 ({g})[/{gc}] — {len(result.findings)} findings")
            
        except Exception as e:
            console.print(f"    [red]Error: {e}[/]")
        
        if max_runs <= 0 or runs < max_runs:
            console.print(f"  [dim]Next scan in {interval}...[/]\n")
            time.sleep(interval_secs)
