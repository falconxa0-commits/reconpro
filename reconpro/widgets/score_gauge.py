"""ScoreGauge — Premium 3-line animated arc gauge for the header bar.

Renders a score from 0-100 as a multi-line gauge with:
  - Rounded grade capsule (color-coded)
  - Bold score number
  - Smooth animated bar fill with ease-out cubic easing
  - Glow pulse on score change
  - Score delta indicator (+5 / -12)

Layout (3 lines)::
    ╭──╮
    │A+│ 100  ████████████████░░░░
    ╰──╯

Usage in TUI compose::
    yield ScoreGauge(bar_width=16, id="score-gauge")

Then update reactively::
    gauge = self.query_one("#score-gauge", ScoreGauge)
    gauge.set_score(72, "C")
"""
from __future__ import annotations

import math
import time
from typing import Optional

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget

from ..theme import Theme


# ── Block characters for the fill bar ─────────────────────────────────────
BLOCK_FULL = "\u2588"  # █
BLOCK_EMPTY = "\u2591"  # ░
BLOCK_MID = [
    "\u258f", "\u258e", "\u258d", "\u258c",
    "\u258b", "\u258a", "\u2589",  # ▏▎▍▌▋▊▉
]


def _ease_out_cubic(t: float) -> float:
    """Ease-out cubic: fast start, smooth deceleration."""
    return 1.0 - (1.0 - t) ** 3


class ScoreGauge(Widget):
    """Premium 3-line animated score gauge widget.

    Layout (3 lines)::
        ╭──╮
        │A+│ 100  ████████████████░░░░
        ╰──╯

    The grade sits inside a rounded capsule colored by grade.
    The bar animates smoothly with ease-out cubic easing.
    A glow pulse fires on every score change.
    """

    DEFAULT_CSS = """
    ScoreGauge {
        width: auto;
        height: 3;
    }
    """

    score: reactive[int] = reactive(100)
    grade: reactive[str] = reactive("A+")

    def __init__(self, bar_width: int = 16, id: str = "score-gauge") -> None:
        super().__init__(id=id)
        self.bar_width = bar_width
        self._target_score: int = 100
        self._display_score: float = 100.0
        self._anim_timer: Optional[Timer] = None
        self._glow_until: float = 0.0
        self._glow_duration: float = 1.2
        self._anim_start: float = 0.0
        self._anim_from: float = 100.0
        self._anim_duration: float = 0.7
        self._prev_score: int = 100
        self._delta: int = 0
        self._delta_until: float = 0.0

    def on_mount(self) -> None:
        self._anim_timer = self.set_interval(0.04, self._animate)
        self._update_display()

    def set_score(self, score: int, grade: str = "") -> None:
        """Set the target score and optionally the grade.

        The gauge animates smoothly from current to target
        using ease-out cubic easing. A glow pulse triggers on change.
        """
        new_target = max(0, min(100, score))
        if new_target != self._target_score:
            self._anim_from = self._display_score
            self._anim_start = time.monotonic()
            self._delta = new_target - self._prev_score
            self._prev_score = new_target
            if self._delta != 0:
                self._delta_until = time.monotonic() + 2.0
        self._target_score = new_target
        if grade:
            self.grade = grade
        self._glow_until = time.monotonic() + self._glow_duration

    def _animate(self) -> None:
        """Smoothly interpolate displayed score toward target."""
        diff = self._target_score - self._display_score
        is_animating = abs(diff) > 0.3
        is_glowing = time.monotonic() < self._glow_until
        is_showing_delta = time.monotonic() < self._delta_until

        if is_animating:
            elapsed = time.monotonic() - self._anim_start
            total_diff = self._target_score - self._anim_from
            if abs(total_diff) > 0.1:
                progress = min(1.0, elapsed / self._anim_duration)
                eased = _ease_out_cubic(progress)
                self._display_score = self._anim_from + total_diff * eased
            else:
                speed = max(0.8, abs(diff) * 0.18)
                if diff > 0:
                    self._display_score = min(
                        self._target_score, self._display_score + speed
                    )
                else:
                    self._display_score = max(
                        self._target_score, self._display_score - speed
                    )
            self.score = int(round(self._display_score))

        if is_animating or is_glowing or is_showing_delta:
            self._update_display()

    def _build_bar(self, score: int, color: str, dim: str) -> tuple[str, str]:
        """Build the horizontal fill bar. Returns (filled_markup, empty_markup)."""
        filled = score / 100.0 * self.bar_width
        full_blocks = int(filled)
        remainder = filled - full_blocks

        if remainder > 0 and full_blocks < self.bar_width:
            partial_idx = min(
                int(remainder * len(BLOCK_MID)), len(BLOCK_MID) - 1
            )
            filled_chars = BLOCK_FULL * full_blocks + BLOCK_MID[partial_idx]
            empty_count = self.bar_width - full_blocks - 1
        else:
            filled_chars = BLOCK_FULL * full_blocks
            empty_count = self.bar_width - full_blocks

        empty_chars = BLOCK_EMPTY * max(0, empty_count)
        return filled_chars, empty_chars

    def _update_display(self) -> None:
        """Render the 3-line gauge as styled Textual markup."""
        t = Theme.current()
        score = int(round(self._display_score))
        grade = self.grade
        color = t.grade_color(grade)
        dim = t.TEXT_DIM
        now = time.monotonic()
        glow_active = now < self._glow_until

        # ── Glow intensity ──
        if glow_active:
            remaining = self._glow_until - now
            base = min(1.0, remaining / (self._glow_duration * 0.5))
            pulse = 0.5 + 0.5 * math.sin(now * 10.0)
            glow_intensity = base * (0.6 + 0.4 * pulse)
        else:
            glow_intensity = 0.0

        # ── Frame color (capsule border) ──
        if glow_intensity > 0.6:
            frame_color = color
        elif glow_intensity > 0.2:
            frame_color = t.ORANGE
        else:
            frame_color = t.DIM_CYAN

        # ── Grade markup ──
        if glow_active:
            grade_markup = f"[bold {color}]{grade:>2}[/]"
        else:
            grade_markup = f"[{color}]{grade:>2}[/]"

        # ── Score markup ──
        score_color = color
        if glow_active and int(now * 6) % 2 == 0:
            score_color = t.ORANGE
        score_str = f"[{score_color} bold]{score:>3}[/{score_color}]"

        # ── Delta indicator ──
        delta_str = ""
        show_delta = now < self._delta_until and self._delta != 0
        if show_delta:
            fade = min(1.0, (self._delta_until - now) / 1.0)
            if self._delta > 0:
                dc = t.GREEN if fade > 0.5 else dim
                delta_str = f" [{dc}]\u2191{self._delta}[/{dc}]"
            else:
                dc = t.RED if fade > 0.5 else dim
                delta_str = f" [{dc}]\u2193{abs(self._delta)}[/{dc}]"

        # ── Bar ──
        filled_chars, empty_chars = self._build_bar(score, color, dim)
        bar_filled = f"[{color}]{filled_chars}[/{color}]"
        bar_empty = f"[{dim}]{empty_chars}[/{dim}]"

        # ── 3-line layout ──
        # Line 1: top of capsule only
        # Line 2: grade in capsule + score + bar + delta
        # Line 3: bottom of capsule only
        top = f"  [{frame_color}]\u256d\u2500\u2500\u256e[/{frame_color}]"
        mid = (
            f"  [{frame_color}]\u2502[/{frame_color}]"
            f"{grade_markup}"
            f"[{frame_color}]\u2502[/{frame_color}] "
            f"{score_str} "
            f"[{dim}][/{dim}]"
            f"{bar_filled}{bar_empty}"
            f"{delta_str}"
        )
        bot = f"  [{frame_color}]\u2570\u2500\u2500\u256f[/{frame_color}]"

        content = f"{top}\n{mid}\n{bot}"
        try:
            self.update(content)
        except Exception:
            pass  # Not mounted yet

    def on_unmount(self) -> None:
        if self._anim_timer:
            self._anim_timer.stop()
