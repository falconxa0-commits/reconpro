"""VelocityMeter — Premium real-time throughput indicator.

Shows current scan velocity in a single line with:
  - Color-coded request rate (green=fast, yellow=medium, dim=slow)
  - Findings discovery rate with color thresholds
  - Animated progress bar with glow on completion
  - Elapsed time counter
  - Scanning-active wave indicator
  - Smooth value transitions (no jumps)

Layout::
    ⟨ 234.0 req/s │ 8.2 find/min │ ████████░░ 42% │ 01:23 ⟩

The values are color-coded: high throughput = green, low = dim.
Completion percentage uses a mini progress bar.
"""
from __future__ import annotations

import time
from typing import Optional

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget

from ..theme import Theme


# Wave characters for scanning-active indicator
_WAVE = ["∼", "∼", "≈", "≈", "≋", "≈", "≈", "∼"]


class VelocityMeter(Widget):
    """Real-time scan velocity display with animated indicators.

    Reactive attributes:
        requests_per_sec   — current HTTP request rate
        findings_per_min   — findings discovery rate
        completion_pct     — scan progress 0-100
    """

    DEFAULT_CSS = """
    VelocityMeter {
        width: 100%;
        height: 1;
    }
    """

    requests_per_sec: reactive[float] = reactive(0.0)
    findings_per_min: reactive[float] = reactive(0.0)
    completion_pct: reactive[float] = reactive(0.0)

    def __init__(self, id: str = "velocity-meter") -> None:
        super().__init__(id=id)
        self._start_time: Optional[float] = None
        self._total_requests: int = 0
        self._total_findings: int = 0
        self._req_history: list = []  # (timestamp, count) pairs
        self._find_history: list = []  # (timestamp, count) pairs
        self._timer: Optional[Timer] = None
        self._active: bool = False
        self._wave_idx: int = 0
        # Smoothed display values (avoid jumps)
        self._display_rps: float = 0.0
        self._display_fpm: float = 0.0
        self._display_pct: float = 0.0

    def on_mount(self) -> None:
        self._timer = self.set_interval(0.5, self._tick)
        self._render()

    def start(self) -> None:
        """Begin tracking velocity."""
        self._active = True
        self._start_time = time.monotonic()
        self._total_requests = 0
        self._total_findings = 0
        self._req_history.clear()
        self._find_history.clear()
        self.completion_pct = 0.0
        self._display_rps = 0.0
        self._display_fpm = 0.0
        self._display_pct = 0.0
        self._render()

    def stop(self) -> None:
        """Stop tracking."""
        self._active = False
        self.requests_per_sec = 0.0
        self.findings_per_min = 0.0
        self._render()

    def record_request(self, count: int = 1) -> None:
        """Record completed requests."""
        self._total_requests += count
        self._req_history.append((time.monotonic(), self._total_requests))

    def record_finding(self, count: int = 1) -> None:
        """Record discovered findings."""
        self._total_findings += count
        self._find_history.append((time.monotonic(), self._total_findings))

    def set_completion(self, pct: float) -> None:
        """Set scan completion percentage (0-100)."""
        self.completion_pct = max(0.0, min(100.0, pct))

    def _tick(self) -> None:
        """Recalculate rates and re-render."""
        now = time.monotonic()
        window = 10.0

        # Requests per second (rolling window)
        cutoff = now - window
        self._req_history = [(t, c) for t, c in self._req_history if t > cutoff]
        if len(self._req_history) >= 2:
            dt = self._req_history[-1][0] - self._req_history[0][0]
            dc = self._req_history[-1][1] - self._req_history[0][1]
            self.requests_per_sec = dc / dt if dt > 0 else 0.0
        else:
            self.requests_per_sec = 0.0

        # Findings per minute (rolling window)
        self._find_history = [(t, c) for t, c in self._find_history if t > cutoff]
        if len(self._find_history) >= 2:
            dt = self._find_history[-1][0] - self._find_history[0][0]
            dc = self._find_history[-1][1] - self._find_history[0][1]
            self.findings_per_min = dc / dt * 60 if dt > 0 else 0.0
        else:
            self.findings_per_min = 0.0

        # Smooth transitions (exponential moving average)
        alpha = 0.4
        self._display_rps += (self.requests_per_sec - self._display_rps) * alpha
        self._display_fpm += (self.findings_per_min - self._display_fpm) * alpha
        self._display_pct += (self.completion_pct - self._display_pct) * alpha

        self._wave_idx = (self._wave_idx + 1) % len(_WAVE)
        self._render()

    def _rate_color(self, value: float, thresholds: tuple) -> str:
        """Pick color based on value thresholds (high, med, low)."""
        t = Theme.current()
        if value >= thresholds[0]:
            return t.GREEN
        elif value >= thresholds[1]:
            return t.CYAN
        elif value >= thresholds[2]:
            return t.YELLOW
        elif value > 0:
            return t.TEXT_DIM
        else:
            return t.TEXT_DIM

    def _render(self) -> None:
        """Render the velocity line."""
        t = Theme.current()
        dim = t.TEXT_DIM

        # Use smoothed values for display
        rps = self._display_rps
        fpm = self._display_fpm
        pct = self._display_pct

        rps_color = self._rate_color(rps, (100, 30, 5))
        fpm_color = self._rate_color(fpm, (10, 3, 0.5))

        # ── Animated progress bar ──
        bar_width = 8
        filled = int(pct / 100 * bar_width)
        empty = bar_width - filled

        # Glow on the leading edge when scanning
        if self._active and filled > 0 and filled < bar_width:
            # Pulse the leading edge
            pulse = int(time.monotonic() * 4) % 3
            if pulse == 0:
                bar_fill = "█" * (filled - 1) + "▓" + "█" * 0
                bar_empty_char = "░"
            elif pulse == 1:
                bar_fill = "█" * (filled - 1) + "▒" + "█" * 0
                bar_empty_char = "░"
            else:
                bar_fill = "█" * filled
                bar_empty_char = "░"
            bar_empty_str = bar_empty_char * empty
        else:
            bar_fill = "█" * filled
            bar_empty_str = "░" * empty

        if pct >= 80:
            pct_color = t.GREEN
        elif pct >= 40:
            pct_color = t.YELLOW
        elif pct > 0 and self._active:
            pct_color = t.CYAN
        else:
            pct_color = dim

        # ── Elapsed time ──
        elapsed_str = ""
        if self._start_time and self._active:
            elapsed = time.monotonic() - self._start_time
            mins, secs = divmod(int(elapsed), 60)
            elapsed_str = f"{mins:02d}:{secs:02d}"

        # ── Wave indicator (only when active) ──
        if self._active:
            wave_char = _WAVE[self._wave_idx]
            wave = f"[{t.CYAN}]{wave_char}[/{t.CYAN}] "
        else:
            wave = ""

        # ── Build the line ──
        parts = [
            f"[{dim}]\u27e8[/{dim}]",  # ⟨
            wave,
            f"[{rps_color}]{rps:>6.1f}[/{rps_color}][{dim}] req/s[/{dim}]",
            f"[{dim}] \u2502 [/{dim}]",  # │
            f"[{fpm_color}]{fpm:>5.1f}[/{fpm_color}][{dim}] find/min[/{dim}]",
            f"[{dim}] \u2502 [/{dim}]",  # │
            f"[{pct_color}]{bar_fill}[/{pct_color}][{dim}]{bar_empty_str}[/{dim}] [{pct_color}]{pct:.0f}%[/{pct_color}]",
        ]
        if elapsed_str:
            parts.append(f"[{dim}] \u2502 [/{dim}][{dim}]{elapsed_str}[/{dim}]")
        parts.append(f"[{dim}]\u27e9[/{dim}]")  # ⟩

        content = " ".join(parts)
        try:
            self.update(content)
        except Exception:
            pass  # Not mounted yet

    def on_unmount(self) -> None:
        if self._timer:
            self._timer.stop()
