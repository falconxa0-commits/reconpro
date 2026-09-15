"""Premium loading animations for ReconPro.

Provides visually rich loading spinners, progress timelines, and animated
score reveals powered by the Rich terminal library.

Classes:
    LoadingAnimation: Context-manager spinner with configurable message.
    ProgressTimeline: Step-by-step timeline with rich status indicators.
    ScoreReveal: Animated score counter with color-coded severity.
"""

from __future__ import annotations

import time
from typing import Any, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

__all__ = ["LoadingAnimation", "ProgressTimeline", "ScoreReveal"]

_CONSOLE = Console()

# ---------------------------------------------------------------------------
# LoadingAnimation
# ---------------------------------------------------------------------------

class LoadingAnimation:
    """A context-manager spinner that wraps long-running operations.

    Usage::

        with LoadingAnimation("Scanning target"):
            time.sleep(2)
        # spinner automatically stops on exit

    Args:
        message: The status message displayed beside the spinner.
        console: Optional Rich console (defaults to a shared instance).
    """

    def __init__(self, message: str = "Loading…", console: Console | None = None) -> None:
        self._message = message
        self._console = console or _CONSOLE
        self._spinner: Progress | None = None

    def __enter__(self) -> LoadingAnimation:
        self._spinner = Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold blue]{task.description}"),
            console=self._console,
            transient=True,
        )
        self._spinner.add_task(self._message, total=None)
        self._spinner.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._spinner is not None:
            self._spinner.stop()

    def update(self, message: str) -> None:
        """Change the spinner message while running."""
        if self._spinner is not None and self._spinner.tasks:
            self._spinner.update(self._spinner.tasks[0].id, description=message)


# ---------------------------------------------------------------------------
# ProgressTimeline
# ---------------------------------------------------------------------------

class ProgressTimeline:
    """Step-by-step progress timeline rendered as a Rich table.

    Each step can be pending, running, done, or failed.  Steps are rendered
    with colour-coded status symbols.

    Usage::

        timeline = ProgressTimeline(["Discover", "Scan", "Report"])
        timeline.start("Discover")
        timeline.complete("Discover")
        timeline.start("Scan")
        timeline.complete("Scan")
        timeline.fail("Report")
        timeline.render()

    Args:
        steps: Ordered sequence of step names.
        console: Optional Rich console.
    """

    _STATUS_ICONS: dict[str, tuple[str, str]] = {
        "pending": ("⏳", "dim"),
        "running": ("🔄", "bold cyan"),
        "done": ("✅", "bold green"),
        "failed": ("❌", "bold red"),
    }

    def __init__(self, steps: Sequence[str], console: Console | None = None) -> None:
        self._console = console or _CONSOLE
        self._steps: list[str] = list(steps)
        self._status: dict[str, str] = {s: "pending" for s in self._steps}

    # -- mutations -----------------------------------------------------------

    def start(self, step: str) -> None:
        """Mark a step as running."""
        if step in self._status:
            self._status[step] = "running"

    def complete(self, step: str) -> None:
        """Mark a step as successfully completed."""
        if step in self._status:
            self._status[step] = "done"

    def fail(self, step: str) -> None:
        """Mark a step as failed."""
        if step in self._status:
            self._status[step] = "failed"

    def reset(self) -> None:
        """Reset every step back to pending."""
        for step in self._status:
            self._status[step] = "pending"

    # -- display -------------------------------------------------------------

    def render(self) -> None:
        """Print the current timeline state as a Rich panel."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("icon", width=3)
        table.add_column("step", style="bold")
        table.add_column("status", width=10)

        for step in self._steps:
            status = self._status[step]
            icon, style = self._STATUS_ICONS.get(status, ("?", "white"))
            table.add_row(
                Text(icon, style=style),
                Text(step),
                Text(status.upper(), style=style),
            )

        done_count = sum(1 for v in self._status.values() if v == "done")
        total = len(self._steps)
        title = f"Timeline  [green]{done_count}[/green]/[white]{total}[/white] complete"

        self._console.print(Panel(table, title=title, border_style="bright_blue"))

    def __repr__(self) -> str:
        return f"ProgressTimeline(steps={self._steps!r}, status={self._status!r})"


# ---------------------------------------------------------------------------
# ScoreReveal
# ---------------------------------------------------------------------------

class ScoreReveal:
    """Animated score reveal with colour-coded severity bands.

    Simulates a counting-up animation from 0 to the target score, then
    prints the final score inside a styled Rich panel.

    Usage::

        ScoreReveal(92).reveal()   # animated count-up to 92
        ScoreReveal(45).reveal()   # shows a warning-band score

    Args:
        score: Integer score between 0 and 100.
        label: Optional label shown above the score.
        console: Optional Rich console.
        animate: If *False*, skip the counting animation.
        steps: Number of intermediate steps in the animation.
    """

    _BANDS = [
        (80, 100, "bold green", "EXCELLENT"),
        (60, 79, "bold yellow", "GOOD"),
        (40, 59, "bold orange3", "MODERATE"),
        (0, 39, "bold red", "CRITICAL"),
    ]

    def __init__(
        self,
        score: int,
        label: str = "Security Score",
        console: Console | None = None,
        animate: bool = True,
        steps: int = 20,
    ) -> None:
        self._score = max(0, min(100, score))
        self._label = label
        self._console = console or _CONSOLE
        self._animate = animate
        self._steps = steps

    # -- helpers -------------------------------------------------------------

    def _band(self) -> tuple[str, str]:
        """Return (style, band_label) for the current score."""
        for lo, hi, style, band in self._BANDS:
            if lo <= self._score <= hi:
                return style, band
        return "white", "UNKNOWN"

    # -- public api ----------------------------------------------------------

    def reveal(self) -> None:
        """Print (optionally animate) the score reveal."""
        style, band = self._band()

        if self._animate:
            with self._console.status("[bold cyan]Calculating…[/bold cyan]"):
                for i in range(1, self._steps + 1):
                    partial = int(self._score * i / self._steps)
                    self._console.print(
                        f"\r  Score: {partial}/100", end="", style=style
                    )
                    time.sleep(0.03)
            self._console.print()  # newline after animation

        score_text = Text(f"{self._score}", style=style)
        score_text += Text("/100", style="dim")
        band_text = Text(f"  {band}", style=style)

        self._console.print(Panel(score_text + band_text, title=self._label, border_style=style))

    def __repr__(self) -> str:
        _, band = self._band()
        return f"ScoreReveal(score={self._score}, band={band!r})"
