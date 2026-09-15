"""ToastContainer — Stacked auto-dismissing notification toasts.

Phase E: Non-intrusive notifications that appear in the top-right corner,
auto-dismiss after a configurable duration, and stack vertically.

Severity levels: success, error, warning, info.
Each toast is a bordered box with an icon, message, and optional action hint.

Usage in NexusApp::

    toasts = self.query_one("#toast-container", ToastContainer)
    toasts.show("Scan complete", severity="success")
    toasts.show("Connection refused", severity="error", action="Type 'scan <target>' to retry")

"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget

from ..theme import Theme


@dataclass
class ToastItem:
    """A single toast notification."""
    id: int
    message: str
    severity: str = "info"  # success | error | warning | info
    action: str = ""  # optional action hint shown in dim text
    created: float = field(default_factory=time.monotonic)
    duration: float = 4.0  # auto-dismiss seconds
    dismissed: bool = False


# Icon per severity — uses simple Unicode symbols for maximum compat
_SEV_ICONS: dict = {
    "success": "[green]OK[/green]",
    "error": "[red]!![/red]",
    "warning": "[yellow]??[/yellow]",
    "info": "[cyan]ii[/cyan]",
}

# Border color per severity
_SEV_BORDERS: dict = {
    "success": "#00cc66",
    "error": "#ff4444",
    "warning": "#ffaa00",
    "info": "#4488ff",
}

# Default duration per severity
_SEV_DURATIONS: dict = {
    "error": 6.0,
    "warning": 5.0,
    "success": 3.5,
    "info": 3.0,
}


class ToastContainer(Widget):
    """Stacked auto-dismissing toast notification area.

    Renders as a layered overlay in the top-right corner of the screen.
    Toasts stack downward with the newest on top. Each toast auto-dismisses
    after its duration expires. Maximum 4 visible toasts; oldest silently removed.

    Uses ``layer: overlay`` CSS to float above all content.
    """

    DEFAULT_CSS = """
    ToastContainer {
        layer: overlay;
        width: 48;
        max-height: 18;
        dock: right;
        offset-y: 3;
        offset-x: 1;
    }
    """

    def __init__(self, max_visible: int = 4, id: str = "toast-container") -> None:
        super().__init__(id=id)
        self._toasts: List[ToastItem] = []
        self._next_id: int = 0
        self._max_visible: int = max_visible
        self._tick_timer: Optional[Timer] = None

    def on_mount(self) -> None:
        self._tick_timer = self.set_interval(0.3, self._tick)

    def show(
        self,
        message: str,
        severity: str = "info",
        action: str = "",
        duration: Optional[float] = None,
    ) -> int:
        """Push a new toast notification.

        Args:
            message: Primary message text (supports Rich markup).
            severity: One of 'success', 'error', 'warning', 'info'.
            action: Optional action hint shown dimmed below the message.
            duration: Auto-dismiss time in seconds (None = severity default).

        Returns:
            The toast id (can be used to dismiss early).
        """
        if duration is None:
            duration = _SEV_DURATIONS.get(severity, 3.0)

        toast = ToastItem(
            id=self._next_id,
            message=message,
            severity=severity,
            action=action,
            duration=duration,
        )
        self._next_id += 1
        self._toasts.append(toast)

        # Trim oldest if over max
        while len(self._toasts) > self._max_visible:
            self._toasts.pop(0)

        self._render()
        return toast.id

    def dismiss(self, toast_id: int) -> None:
        """Dismiss a specific toast by id."""
        for t in self._toasts:
            if t.id == toast_id:
                t.dismissed = True
                break
        self._toasts = [t for t in self._toasts if not t.dismissed]
        self._render()

    def dismiss_all(self) -> None:
        """Dismiss all active toasts."""
        self._toasts.clear()
        self._render()

    def _tick(self) -> None:
        """Periodic check: remove expired toasts."""
        now = time.monotonic()
        before = len(self._toasts)
        self._toasts = [
            t for t in self._toasts
            if not t.dismissed and (now - t.created) < t.duration
        ]
        if len(self._toasts) != before:
            self._render()

    def _render(self) -> None:
        """Rebuild the visual toast stack.

        Each toast is a 2-line bordered box:
          Line 1: [border] icon  message
          Line 2: [border]       action_hint (if any)
        """
        theme = Theme.current()
        dim = theme.TEXT_DIM
        bg = theme.BG

        active = [t for t in self._toasts if not t.dismissed]

        if not active:
            try:
                self.update("")
            except Exception:
                pass
            return

        blocks: List[str] = []

        for toast in reversed(active):  # newest first (top)
            border_color = _SEV_BORDERS.get(toast.severity, "#4488ff")
            icon = _SEV_ICONS.get(toast.severity, "[cyan]?[/cyan]")

            # Compute remaining time for a subtle progress indicator
            elapsed = time.monotonic() - toast.created
            remaining = max(0, toast.duration - elapsed)
            frac = remaining / toast.duration if toast.duration > 0 else 0
            filled = max(1, int(frac * 8))
            bar = " " + "*" * filled + "." * (8 - filled)

            # Build the 2-line toast block
            line1 = f" [{border_color}]{icon} {toast.message}[/{border_color}]"
            line2_parts = f"       [{dim}]{bar}[/{dim}]"
            if toast.action:
                line2_parts += f"  [{dim}]{toast.action}[/{dim}]"

            blocks.append(line1)
            blocks.append(line2_parts)
            blocks.append("")  # blank separator between toasts

        content = "\n".join(blocks)
        try:
            self.update(content)
        except Exception:
            pass

    def on_unmount(self) -> None:
        if self._tick_timer:
            self._tick_timer.stop()
