"""Notification center for ReconPro.

An in-memory notification store with severity levels, timestamps, and
digest generation.  Designed to collect alerts from scan modules, AI
analysis, drift monitors, and other subsystems.

Classes:
    NotificationCenter: Add, query, digest, and clear notifications.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = ["NotificationCenter", "NotificationLevel"]

import sys

_CONSOLE = Console(file=sys.stderr)


class NotificationLevel(str, Enum):
    """Severity levels for notifications."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SUCCESS = "success"


@dataclass
class Notification:
    """A single notification entry.

    Attributes:
        id: Unique identifier (auto-generated UUID4).
        title: Short title / subject line.
        message: Detailed body text.
        level: Severity level.
        source: Subsystem that produced the notification.
        timestamp: When the notification was created (UTC).
        metadata: Arbitrary extra data attached to the notification.
    """

    title: str
    message: str
    level: NotificationLevel = NotificationLevel.INFO
    source: str = "reconpro"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    metadata: dict[str, Any] = field(default_factory=dict)


# Mapping from level → Rich style
_LEVEL_STYLE: dict[NotificationLevel, tuple[str, str]] = {
    NotificationLevel.INFO: ("ℹ️", "bold blue"),
    NotificationLevel.WARNING: ("⚠️", "bold yellow"),
    NotificationLevel.ERROR: ("❌", "bold red"),
    NotificationLevel.CRITICAL: ("🔥", "bold bright_red"),
    NotificationLevel.SUCCESS: ("✅", "bold green"),
}


class NotificationCenter:
    """In-memory notification store for ReconPro.

    Collects notifications from any subsystem and provides methods to
    query, summarise (digest), and clear them.

    Usage::

        nc = NotificationCenter()
        nc.add("Scan complete", "Found 42 hosts", NotificationLevel.SUCCESS, "recon")
        nc.get_all()
        nc.digest()
        nc.clear()

    Args:
        console: Optional Rich console.
        max_size: Maximum number of notifications to keep (oldest evicted).
    """

    def __init__(
        self,
        console: Console | None = None,
        max_size: int = 1000,
    ) -> None:
        self._console = console or _CONSOLE
        self._max_size = max_size
        self._notifications: list[Notification] = []

    # -- mutations -----------------------------------------------------------

    def add(
        self,
        title: str,
        message: str,
        level: NotificationLevel | str = NotificationLevel.INFO,
        source: str = "reconpro",
        metadata: dict[str, Any] | None = None,
    ) -> Notification:
        """Add a new notification and return it.

        Args:
            title: Short title.
            message: Detailed message.
            level: Severity level (string or enum).
            source: Originating subsystem name.
            metadata: Optional dict of extra data.

        Returns:
            The created ``Notification``.
        """
        if isinstance(level, str):
            level = NotificationLevel(level.lower())
        notification = Notification(
            title=title,
            message=message,
            level=level,
            source=source,
            metadata=metadata or {},
        )
        self._notifications.append(notification)

        # Evict oldest when over capacity
        while len(self._notifications) > self._max_size:
            self._notifications.pop(0)

        return notification

    # -- queries -------------------------------------------------------------

    def get_all(self, level: NotificationLevel | None = None) -> list[Notification]:
        """Return all notifications, optionally filtered by *level*.

        Results are rendered in a Rich table.

        Args:
            level: If provided, only return notifications of this level.

        Returns:
            List of matching notifications.
        """
        results = (
            [n for n in self._notifications if n.level == level]
            if level
            else list(self._notifications)
        )

        self._render_table(results)
        return results

    def _render_table(self, notifications: list[Notification]) -> None:
        """Render notifications in a Rich table."""
        if not notifications:
            self._console.print(
                Panel("[dim]No notifications.[/dim]", title="Notifications",
                      border_style="dim")
            )
            return

        table = Table(
            title="🔔 Notifications",
            show_lines=True,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
        )
        table.add_column("ID", style="dim", width=12, no_wrap=True)
        table.add_column("Level", width=10)
        table.add_column("Title", style="bold")
        table.add_column("Message", style="dim")
        table.add_column("Source", width=12)
        table.add_column("Time", width=20)

        for n in notifications:
            icon, style = _LEVEL_STYLE.get(n.level, ("?", "white"))
            table.add_row(
                n.id,
                Text(f"{icon} {n.level.value}", style=style),
                n.title,
                n.message,
                n.source,
                n.timestamp[:19],
            )

        self._console.print(table)

    # -- digest --------------------------------------------------------------

    def digest(self) -> dict[str, Any]:
        """Generate a summary digest and print it.

        Returns:
            Dict with counts per level, latest notification, and total.
        """
        counts: dict[str, int] = {lvl.value: 0 for lvl in NotificationLevel}
        for n in self._notifications:
            counts[n.level.value] = counts.get(n.level.value, 0) + 1

        latest = self._notifications[-1] if self._notifications else None

        digest_data: dict[str, Any] = {
            "total": len(self._notifications),
            "counts": counts,
            "latest": {
                "id": latest.id,
                "title": latest.title,
                "level": latest.level.value,
                "timestamp": latest.timestamp,
            } if latest else None,
        }

        # -- render ---
        table = Table(title="📊 Notification Digest", border_style="bright_magenta",
                       title_style="bold bright_magenta")
        table.add_column("Level", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)

        for lvl in NotificationLevel:
            cnt = counts.get(lvl.value, 0)
            _, style = _LEVEL_STYLE[lvl]
            table.add_row(Text(f"{lvl.value}", style=style), str(cnt))

        table.add_row("[bold]TOTAL[/bold]", f"[bold]{len(self._notifications)}[/bold]")

        self._console.print(table)

        if latest:
            self._console.print(
                Panel(
                    f"[bold]{latest.title}[/bold]  [dim]({latest.level.value})[/dim]\n"
                    f"{latest.message}",
                    title="Latest Notification",
                    border_style="bright_magenta",
                )
            )

        return digest_data

    # -- clear ---------------------------------------------------------------

    def clear(self, level: NotificationLevel | None = None) -> int:
        """Clear notifications.

        Args:
            level: If provided, only clear notifications of this level.

        Returns:
            Number of notifications removed.
        """
        before = len(self._notifications)
        if level:
            self._notifications = [n for n in self._notifications if n.level != level]
        else:
            self._notifications.clear()
        removed = before - len(self._notifications)

        self._console.print(
            Panel(
                f"[bold green]Cleared {removed} notification(s).[/bold green]",
                title="Notifications",
                border_style="green",
            )
        )
        return removed

    # -- dunder --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._notifications)

    def __repr__(self) -> str:
        return f"NotificationCenter(count={len(self._notifications)})"
