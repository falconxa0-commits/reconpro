"""Sparkline — Premium mini line chart using Unicode block characters.

Renders a compact single-line chart that shows data trends with:
  - 8-level Unicode block heights (▁▂▃▄▅▆▇█)
  - Gradient coloring: oldest dim → newest bright
  - Trend arrow (↗ ↑ → ↘ ↓) based on recent trajectory
  - Auto-scaling to data range

Usage::
    spark = Sparkline(id="findings-spark", title="FIND/MIN", max_points=40, color=CYAN)
    spark.push(3)
    spark.push(7)
    spark.push(2)
    # Renders: ▁▂▃▇▅▃▁▂  FIND/MIN  ↗ 4.3avg  7pk

The sparkline auto-scales to the data range and colors based
on the theme's severity/grade colors.
"""
from __future__ import annotations

from collections import deque
from typing import List

from textual.reactive import reactive
from textual.widget import Widget

from ..theme import Theme


# 8-level Unicode block heights (bottom to top)
BLOCKS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

# Trend arrows
_TREND_MAP = {
    "strong_up": "⇈",
    "up": "↗",
    "flat": "→",
    "down": "↘",
    "strong_down": "⇊",
}


class Sparkline(Widget):
    """Single-line sparkline chart widget with gradient and trend.

    Reactive attributes:
        color   — hex color for the bars (default: theme accent)
        title   — label shown after the chart
    """

    DEFAULT_CSS = """
    Sparkline {
        width: auto;
        height: 1;
    }
    """

    color: reactive[str] = reactive("")
    title: reactive[str] = reactive("")

    def __init__(
        self,
        max_points: int = 30,
        title: str = "",
        color: str = "",
        id: str = "sparkline",
    ) -> None:
        super().__init__(id=id)
        self._data: deque = deque(maxlen=max_points)
        self._max_points = max_points
        if title:
            self.title = title
        if color:
            self.color = color

    def push(self, value: float) -> None:
        """Add a data point and re-render if mounted."""
        self._data.append(value)
        try:
            self._render()
        except Exception:
            pass

    def push_batch(self, values: List[float]) -> None:
        """Add multiple data points and re-render once."""
        for v in values:
            self._data.append(v)
        try:
            self._render()
        except Exception:
            pass

    def clear(self) -> None:
        """Clear all data points."""
        self._data.clear()
        self._render()

    @property
    def data(self) -> List[float]:
        """Return current data as a list."""
        return list(self._data)

    @property
    def avg(self) -> float:
        """Current average of stored data."""
        if not self._data:
            return 0.0
        return sum(self._data) / len(self._data)

    @property
    def latest(self) -> float:
        """Most recent data point."""
        return self._data[-1] if self._data else 0.0

    @property
    def peak(self) -> float:
        """Peak value in current data."""
        return max(self._data) if self._data else 0.0

    def _detect_trend(self) -> str:
        """Detect recent trend from last N data points.

        Returns one of: strong_up, up, flat, down, strong_down
        """
        data = list(self._data)
        n = min(6, len(data))
        if n < 3:
            return "flat"

        recent = data[-n:]
        # Simple linear regression slope
        x_vals = list(range(n))
        x_mean = sum(x_vals) / n
        y_mean = sum(recent) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, recent))
        denominator = sum((x - x_mean) ** 2 for x in x_vals)

        if denominator == 0:
            return "flat"

        slope = numerator / denominator
        y_range = max(recent) - min(recent)
        if y_range == 0:
            return "flat"

        # Normalize slope to range
        normalized = slope * n / y_range

        if normalized > 0.4:
            return "strong_up"
        elif normalized > 0.1:
            return "up"
        elif normalized > -0.1:
            return "flat"
        elif normalized > -0.4:
            return "down"
        else:
            return "strong_down"

    def _interpolate_color(self, fraction: float) -> str:
        """Interpolate between dim and full color.

        fraction 0.0 = oldest (dim), 1.0 = newest (full color).
        Returns a hex color string.
        """
        t = Theme.current()
        bar_color = self.color or t.ACCENT
        dim_color = t.TEXT_DIM

        def parse_hex(c: str) -> tuple:
            c = c.lstrip("#")
            if len(c) == 6:
                return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
            return (128, 128, 128)

        r1, g1, b1 = parse_hex(dim_color)
        r2, g2, b2 = parse_hex(bar_color)

        # Non-linear: use power curve for more visible gradient
        f = fraction ** 0.6
        r = int(r1 + (r2 - r1) * f)
        g = int(g1 + (g2 - g1) * f)
        b = int(b1 + (b2 - b1) * f)

        return f"#{r:02x}{g:02x}{b:02x}"

    def _render(self) -> None:
        """Render the sparkline with gradient and trend indicator."""
        t = Theme.current()
        bar_color = self.color or t.ACCENT
        dim = t.TEXT_DIM
        title = self.title

        if not self._data:
            # Empty state — dim placeholder
            width = min(self._max_points, 20)
            self.update(f"[{dim}]{'─' * width}[/{dim}] [{dim}]{title}[/{dim}]")
            return

        data = list(self._data)
        data_min = min(data)
        data_max = max(data)
        data_range = data_max - data_min
        n = len(data)

        # ── Build gradient-colored blocks ──
        parts: list = []
        for i, val in enumerate(data):
            # Block index
            if data_range == 0:
                idx = 3  # ▄ mid-height
            else:
                normalized = (val - data_min) / data_range
                idx = int(normalized * (len(BLOCKS) - 1) + 0.5)
                idx = max(0, min(len(BLOCKS) - 1, idx))

            # Gradient: older points dimmer, newer brighter
            if n > 1:
                fraction = i / (n - 1)
            else:
                fraction = 1.0

            # Only color the latest ~40% with gradient, keep older ones dim
            if fraction < 0.6:
                char_color = dim
            else:
                # Remap 0.6-1.0 → 0.0-1.0 for the gradient
                grad_frac = (fraction - 0.6) / 0.4
                char_color = self._interpolate_color(grad_frac)

            # Highlight the peak value
            is_peak = (val == data_max and n > 1)
            if is_peak:
                char_color = bar_color

            parts.append(f"[{char_color}]{BLOCKS[idx]}[/{char_color}]")

        chart = "".join(parts)

        # ── Trend arrow ──
        trend_key = self._detect_trend()
        trend_char = _TREND_MAP[trend_key]
        if trend_key in ("strong_up", "up"):
            trend_color = t.GREEN
        elif trend_key in ("strong_down", "down"):
            trend_color = t.RED
        else:
            trend_color = dim

        # ── Stats ──
        avg = self.avg
        peak = self.peak
        latest = self.latest

        # Show peak in bold if it's the latest value
        if latest >= peak and n > 1:
            peak_style = f"bold {bar_color}"
        else:
            peak_style = dim

        # Build final line
        self.update(
            f"{chart}"
            f"  [{dim}]{title}[/{dim}]"
            f" [{trend_color}]{trend_char}[/{trend_color}]"
            f" [{bar_color}]{avg:.1f}[/{bar_color}][{dim}]avg[/{dim}]"
            f" [{peak_style}]{peak:.0f}[/{peak_style}][{dim}]pk[/{dim}]"
        )

    def watch_title(self, old: str, new: str) -> None:
        try:
            self._render()
        except Exception:
            pass

    def watch_color(self, old: str, new: str) -> None:
        try:
            self._render()
        except Exception:
            pass
