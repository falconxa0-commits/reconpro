"""StatCounter — Premium number display with delta flash and rolling animation.

Shows a count with:
  - Comma-formatted numbers (1,234)
  - Rolling digit animation when value changes
  - Up/down delta indicator with fade
  - Mini inline magnitude bar
  - "Hot" pulse when value spikes

Usage::
    counter = StatCounter(id="finding-count", label="findings")
    counter.set(85, delta=12)  # 85 findings, +12 in last minute
    # Renders: ● 85 findings  ↑12  ██

The delta arrow and number flash the accent color for 1.5s
then fade to the dim color.
"""
from __future__ import annotations

import time
from typing import Optional

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget

from ..theme import Theme


def _format_number(n: int) -> str:
    """Format integer with comma separators."""
    return f"{n:,}"


class StatCounter(Widget):
    """Animated counter with delta indicator and mini-bar.

    Reactive attributes:
        value    — current count
        delta    — recent change (positive = increase)
    """

    DEFAULT_CSS = """
    StatCounter {
        width: auto;
        height: 1;
    }
    """

    value: reactive[int] = reactive(0)
    delta: reactive[int] = reactive(0)

    def __init__(
        self,
        label: str = "",
        icon: str = "●",
        color: str = "",
        id: str = "stat-counter",
    ) -> None:
        super().__init__(id=id)
        self.label = label
        self.icon = icon
        self._custom_color = color
        self._flash_timer: Optional[Timer] = None
        self._flash_until: float = 0.0
        self._flash_duration: float = 1.8
        self._prev_value: int = 0
        self._display_value: int = 0
        self._roll_start: float = 0.0
        self._roll_from: int = 0
        self._roll_to: int = 0
        self._roll_duration: float = 0.4
        self._hot_until: float = 0.0
        self._max_seen: int = 1  # for mini-bar scaling

    def on_mount(self) -> None:
        self._flash_timer = self.set_interval(0.08, self._tick)
        self._display_value = self.value
        self._update_display()

    def set(self, value: int, delta: int = 0) -> None:
        """Update the counter and trigger animations."""
        if value != self.value:
            self._roll_from = self._display_value
            self._roll_to = value
            self._roll_start = time.monotonic()
        self._prev_value = self.value
        self.value = value
        self.delta = delta
        if delta != 0:
            self._flash_until = time.monotonic() + self._flash_duration
        # Track max for mini-bar scaling
        if value > self._max_seen:
            self._max_seen = value
            # "Hot" indicator for sudden spikes
            if delta > 5:
                self._hot_until = time.monotonic() + 1.0
        self._update_display()

    def increment(self, amount: int = 1) -> None:
        """Increment the value by amount, auto-computing delta."""
        self.set(self.value + amount, amount)

    def reset_max(self) -> None:
        """Reset the max-seen tracker for mini-bar rescaling."""
        self._max_seen = max(1, self.value)

    def _tick(self) -> None:
        """Animation tick — handles rolling and flash."""
        now = time.monotonic()
        needs_render = False

        # Rolling animation
        if self._display_value != self._roll_to:
            elapsed = now - self._roll_start
            progress = min(1.0, elapsed / self._roll_duration)
            diff = self._roll_to - self._roll_from
            self._display_value = int(self._roll_from + diff * progress)
            needs_render = True

        # Flash re-render
        if now < self._flash_until:
            needs_render = True

        # Hot pulse
        if now < self._hot_until:
            needs_render = True

        if needs_render:
            self._update_display()

    def _update_display(self) -> None:
        """Render the counter line."""
        t = Theme.current()
        color = self._custom_color or t.ACCENT
        dim = t.TEXT_DIM
        now = time.monotonic()

        # ── Rolling display value ──
        display = self._display_value
        formatted = _format_number(display)

        # ── Flash effect ──
        is_flashing = now < self._flash_until and self.delta != 0
        if is_flashing:
            remaining = self._flash_until - now
            fade = min(1.0, remaining / (self._flash_duration * 0.6))
            delta_color = color if fade > 0.5 else dim
            arrow_style = f"bold {delta_color}" if fade > 0.3 else dim
        else:
            delta_color = dim
            arrow_style = dim

        # ── Delta arrow ──
        if self.delta > 0:
            delta_str = f"[{arrow_style}]\u2191{self.delta}[/{arrow_style}]"
        elif self.delta < 0:
            delta_str = f"[{arrow_style}]\u2193{abs(self.delta)}[/{arrow_style}]"
        else:
            delta_str = ""

        # ── Icon (pulses when hot) ──
        is_hot = now < self._hot_until
        if is_hot:
            pulse = int(now * 8) % 2 == 0
            icon_color = t.RED if pulse else t.ORANGE
            icon_char = "◆"
        elif display == 0:
            icon_color = t.GREEN
            icon_char = self.icon
        else:
            icon_color = color
            icon_char = self.icon

        # ── Mini magnitude bar ──
        FULL = "\u2588"
        EMPTY = "\u2591"
        bar_width = 4
        if self._max_seen > 0:
            bar_fill = display / self._max_seen
        else:
            bar_fill = 0.0
        filled = int(bar_fill * bar_width)
        empty = bar_width - filled
        if filled > 0:
            mini_bar = f"[{color}]{FULL * filled}[/{color}][{dim}]{EMPTY * empty}[/{dim}]"
        else:
            mini_bar = f"[{dim}]{EMPTY * bar_width}[/{dim}]"

        # ── Assemble ──
        content = (
            f"[{icon_color}]{icon_char}[/{icon_color}] "
            f"[bold {color}]{formatted}[/{color}] "
            f"[{dim}]{self.label}[/{dim}]"
            f"  {delta_str}"
            f"  {mini_bar}"
        )
        try:
            self.update(content)
        except Exception:
            pass  # Not mounted yet

    def on_unmount(self) -> None:
        if self._flash_timer:
            self._flash_timer.stop()
