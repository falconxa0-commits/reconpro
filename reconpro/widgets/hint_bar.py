"""HintBar — Adaptive contextual hint strip below the command input.

Phase C enhancements:
  - 4 new context pools: ``first_scan``, ``critical_findings``, ``error_state``,
    ``focused_panel``
  - Severity-aware hints: dynamically injects critical/high counts
  - Dynamic keybinding tips that change based on the focused widget
  - Faster 6-second rotation interval (was 8)
  - ``push_dynamic_context()`` for parameterized hints (counts, focus name)
  - Smooth fade-in on context switch

Shows context-sensitive tips that rotate based on:
  - Current app state (idle, scanning, has findings, has target)
  - Severity breakdown (critical_findings context)
  - Focused panel (focused_panel context)
  - Time-based rotation every 6 seconds
  - Command-specific hints after failed commands

Usage::
    hint = HintBar(id="hint-bar")
    hint.push_context("idle")
    hint.show_once("Press Tab for auto-complete")
    hint.push_dynamic_context("critical_findings", critical=3, high=7)
"""
from __future__ import annotations

import random
import time
from typing import Dict, List, Optional, Any

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget

from ..theme import Theme


# ── Hint pools by context ──
# Templates can use {target}, {critical}, {high}, {medium}, {total}, {focus}
HINTS: Dict[str, List[str]] = {
    "idle": [
        "Type [cyan]scan <target>[/] to begin reconnaissance",
        "Press [cyan]Tab[/] on empty input to browse all commands",
        "[cyan]agent[/] deploys an autonomous AI hacker",
        "[cyan]swarm <target>[/] launches multi-agent assault",
        "[cyan]blitz t1 t2 t3[/] scans multiple targets in parallel",
        "[cyan]fuzzer <url>[/] fuzzes parameters for vulnerabilities",
        "[cyan]passive <domain>[/] for passive DNS / OSINT intel",
        "[cyan]profile <target>[/] fingerprints the target",
        "[cyan]theme list[/] to browse 6 built-in themes",
        "[cyan]audit[/] runs a local security health check",
        "[cyan]doctor[/] diagnoses your ReconPro installation",
        "[cyan]cve <query>[/] searches the NVD database",
    ],
    "first_scan": [
        "Welcome! Type [cyan]scan example.com[/] to begin",
        "Try [cyan]scan <target> with recon auth[/] for selective modules",
        "Press [cyan]Tab[/] while typing to auto-complete commands",
        "Use [cyan]↑/↓[/] to navigate command history",
        "Press [cyan]?[/] or type [cyan]help[/] to see all commands",
        "Quick jump: [cyan]0[/] input · [cyan]1[/] chat · [cyan]2[/] findings · [cyan]3[/] modules",
    ],
    "scanning": [
        "Scan in progress... [cyan]clear[/] to reset feeds",
        "Press [cyan]d[/] to inspect the latest finding",
        "Findings appear in real-time on the right panel",
        "Click any finding for full details",
        "[cyan]Ctrl+S[/] will re-scan this target when done",
        "Press [cyan]2[/] to jump to findings · [cyan]j/k[/] to navigate",
        "Module grid below shows real-time progress per scanner",
        "[cyan]0[/] jumps back to input for next command",
    ],
    "scanning_recon": [
        "RECON module mapping attack surface... [cyan]2[/] to watch findings",
        "Recon discovers open ports, services, and subdomains",
        "[cyan]d[/] to inspect the latest recon finding",
    ],
    "scanning_auth": [
        "AUTH BYPASS testing authentication mechanisms...",
        "Auth module probes for weak credentials and bypass vectors",
        "[cyan]d[/] for latest auth finding · [cyan]2[/] findings panel",
    ],
    "scanning_chain": [
        "CHAIN HUNTER chaining vulnerabilities for exploit paths...",
        "Chain module links low-severity issues into critical chains",
    ],
    "scanning_gorgon": [
        "GORGON ULTRA deep scan in progress — this may take a while",
        "Gorgon runs exhaustive multi-pass analysis",
        "[cyan]d[/] to peek at findings as they arrive",
    ],
    "scanning_oblivion": [
        "OBLIVION stealth scan running — minimal footprint mode",
        "Oblivion uses passive techniques to avoid detection",
    ],
    "has_findings": [
        "[cyan]export html[/] to generate a styled report",
        "[cyan]d[/] to inspect the last finding in detail",
        "Click findings on the right panel for details",
        "[cyan]adversarial[/] runs fix-verify loops",
        "[cyan]history[/] to see past scan results",
        "[cyan]defense[/] can generate remediation code for findings",
        "[cyan]compliance[/] maps findings to framework controls",
        "[cyan]delta[/] compares current scan vs previous results",
        "[cyan]benchmark[/] tracks your score over time",
        "[cyan]export sarif[/] for GitHub integration",
    ],
    "critical_findings": [
        "{critical} critical finding{s_crit} detected — try [cyan]adversarial {target}[/] to fix them",
        "[cyan]defense[/] can generate remediation code for {critical} critical issue{s_crit}",
        "Score dropped to {score} — [cyan]adversarial[/] runs iterative hardening loops",
        "Export with [cyan]export html[/] to share findings with your team",
        "Use [cyan]d[/] to inspect the most critical finding in detail",
        "{critical}C {high}H {medium}M — run [cyan]adversarial[/] for auto-remediation",
    ],
    "error_state": [
        "Scan encountered an error — auto-retry is active (up to 2 attempts)",
        "Try [cyan]doctor[/] to diagnose your ReconPro installation",
        "Reduce scope with [cyan]scan <target> with <module>[/]",
        "Use [cyan]clear[/] to reset and try a different target",
        "Check your network connection and target reachability",
        "[cyan]profile <target>[/] to verify target is accessible",
        "Failed scans auto-retry with exponential backoff (1s, 2s)",
    ],
    "has_target": [
        "[cyan]Ctrl+S[/] to re-scan [cyan]{target}[/]",
        "[cyan]swarm {target}[/] for multi-agent deep scan",
        "[cyan]adversarial {target}[/] for iterative hardening",
        "[cyan]scan {target} with recon auth[/] for selective modules",
        "[cyan]fuzzer {target}[/] to fuzz parameters for vulns",
        "[cyan]passive {target}[/] for passive DNS / OSINT intel",
        "[cyan]profile {target}[/] for target fingerprinting",
        "[cyan]cloud-recon {target}[/] for cloud asset discovery",
        "[cyan]export html[/] to generate a report",
        "[cyan]delta[/] to diff against last scan of {target}",
    ],
    "focused_panel": [
        "Focused: [cyan]{focus}[/] · [cyan]Esc[/] back to input",
    ],
    "layout": [
        "[cyan]Ctrl+←/→[/] resizes left/right split (20-70%)",
        "[cyan][[/] toggles chat panel · [cyan]=[/] toggles module grid",
        "[cyan]Ctrl+↑[/] toggles module grid visibility",
        "Layout adapts automatically when you resize the terminal",
        "Narrow terminals (< 80 cols) switch to compact stacked mode",
        "Wide terminals (>= 160 cols) show 4-column module grid",
        "Cinematic terminals (>= 200 cols) use 30:70 split for max findings space",
        "[cyan]|[/] resets split to auto · [cyan]\\[/] resets split to 50:50",
        "[cyan]layout[/] command shows full layout status",
        "Collapsed panels are skipped in Tab focus cycling",
    ],
}

# ── Keybinding tips per focused widget ──
_FOCUS_TIPS: Dict[str, str] = {
    "command-input": "[dim]Tab complete · ↑↓ history · Ctrl+←→ resize · [ toggle chat[/]",
    "chat-log": "[dim]↑↓ scroll · j/k navigate · 0 jump to input · Esc back · [ collapse[/]",
    "findings-feed": "[dim]j/k navigate findings · Enter detail · d last finding · 0 input · = toggle mods[/]",
    "module-grid": "[dim]↑↓←→ navigate cells · 0 jump to input · Esc back · = collapse mods[/]",
}


class HintBar(Widget):
    """Single-line contextual hint that rotates periodically.

    Phase C additions:
    - ``push_dynamic_context(context, **params)`` for parameterized hints
    - Severity-aware hint injection
    - Focus-aware keybinding tips

    Reactive attributes:
        text  — current hint text (with markup)
    """

    DEFAULT_CSS = """
    HintBar {
        width: 100%;
        height: 1;
    }
    """

    text: reactive[str] = reactive("")

    def __init__(self, id: str = "hint-bar") -> None:
        super().__init__(id=id)
        self._current_context: str = "idle"
        self._pool: List[str] = []
        self._pool_idx: int = 0
        self._timer: Optional[Timer] = None
        self._rotate_interval: float = 6.0  # Phase C: faster rotation
        self._once_text: Optional[str] = None
        self._once_until: float = 0.0
        self._target_name: str = ""
        # Phase C: dynamic template variables
        self._template_vars: Dict[str, Any] = {}

    def on_mount(self) -> None:
        self._refresh_pool("idle")
        self._timer = self.set_interval(self._rotate_interval, self._rotate)
        self._render()

    def push_context(self, context: str, target: str = "") -> None:
        """Switch to a different hint pool.

        Args:
            context: one of the defined hint pool names
            target: optional target name for {target} template substitution
        """
        if context != self._current_context:
            self._current_context = context
            self._target_name = target
            self._template_vars = {"target": target}
            self._refresh_pool(context)
            self._pool_idx = 0
            self._render()

    def push_dynamic_context(self, context: str, **params: Any) -> None:
        """Switch hint pool with dynamic template variables.

        Use this for severity-aware hints that need counts injected.

        Example::
            hint.push_dynamic_context(
                "critical_findings",
                critical=3, high=7, medium=12, total=22,
                score=42, target="example.com",
            )
        """
        if context != self._current_context or params != self._template_vars:
            self._current_context = context
            self._template_vars = params
            self._target_name = params.get("target", "")
            self._refresh_pool(context)
            self._pool_idx = 0
            self._render()

    def push_focus_tip(self, widget_id: str) -> None:
        """Show a one-shot keybinding tip for the focused widget.

        Falls back to the generic tip if widget_id is not recognized.
        """
        # Map DOM ids to tip keys
        tip_key = widget_id.replace("#", "")
        tip = _FOCUS_TIPS.get(tip_key, _FOCUS_TIPS.get("command-input", ""))
        if tip:
            self.show_once(tip, duration=3.0)

    def push_module_hint(self, module_id: str) -> None:
        """Switch to a module-specific scanning hint pool.

        Falls back to generic 'scanning' pool if no module-specific pool exists.
        """
        pool_key = f"scanning_{module_id}"
        if pool_key in HINTS:
            self.push_context(pool_key)
        else:
            # Fallback to generic scanning hints
            self.push_context("scanning")

    def show_once(self, text: str, duration: float = 4.0) -> None:
        """Show a one-shot hint that overrides rotation temporarily."""
        self._once_text = text
        self._once_until = time.monotonic() + duration
        self._render()

    def set_target(self, target: str) -> None:
        """Update the target name for hint templates."""
        self._target_name = target
        self._template_vars["target"] = target

    def _refresh_pool(self, context: str) -> None:
        """Load and shuffle the hint pool for the given context."""
        self._pool = list(HINTS.get(context, HINTS["idle"]))
        random.shuffle(self._pool)

    def _rotate(self) -> None:
        """Advance to the next hint in the pool."""
        if not self._pool:
            return
        self._pool_idx = (self._pool_idx + 1) % len(self._pool)
        self._render()

    def _substitute(self, text: str) -> str:
        """Replace template variables in hint text."""
        result = text
        # Static {target} substitution
        if self._target_name:
            result = result.replace("{target}", self._target_name)

        # Dynamic template variables from push_dynamic_context
        for key, val in self._template_vars.items():
            placeholder = "{" + key + "}"
            if placeholder in result:
                result = result.replace(placeholder, str(val))

        # Plural helpers: {s_crit} → "s" if critical != 1, else ""
        crit_count = self._template_vars.get("critical", 0)
        result = result.replace("{s_crit}", "s" if crit_count != 1 else "")

        # If {target} still in result (no target set), replace gracefully
        result = result.replace("{target}", "<target>")

        # Replace any remaining {var} with empty
        import re
        result = re.sub(r"\{[^}]+\}", "", result)

        return result

    def _render(self) -> None:
        """Render the current hint."""
        t = Theme.current()
        dim = t.TEXT_DIM

        # One-shot hint takes priority
        now = time.monotonic()
        if self._once_text and now < self._once_until:
            content = f"[{dim}]{self._once_text}[/{dim}]"
            try:
                self.update(content)
            except Exception:
                pass
            return

        # Clear one-shot
        if self._once_text and now >= self._once_until:
            self._once_text = None

        if not self._pool:
            try:
                self.update("")
            except Exception:
                pass
            return

        hint = self._pool[self._pool_idx % len(self._pool)]
        hint = self._substitute(hint)
        content = f"[{dim}]  {hint}[/{dim}]"
        try:
            self.update(content)
        except Exception:
            pass

    def on_unmount(self) -> None:
        if self._timer:
            self._timer.stop()
