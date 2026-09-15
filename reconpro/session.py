"""Session management for ReconPro.

Provides save, load, list, and restore operations for named sessions.
Session data is persisted as JSON files under ``~/.reconpro/sessions/``.

Classes:
    SessionManager: Save, load, list, and restore scan / work sessions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

__all__ = ["SessionManager"]

_CONSOLE = Console()

_DEFAULT_BASE = Path.home() / ".reconpro" / "sessions"


class SessionManager:
    """Save, load, list, and restore named sessions.

    Each session is stored as a JSON file under ``~/.reconpro/sessions/``.
    The file name is ``<name>.json``.  Session metadata includes a
    creation timestamp and optional tags.

    Usage::

        sm = SessionManager()
        sm.save("quick-scan", {"hosts": ["10.0.0.1"], "findings": 3})
        data = sm.load("quick-scan")
        sm.list_sessions()
        sm.restore("quick-scan")

    Args:
        base_dir: Override the root sessions directory.
        console: Optional Rich console.
    """

    def __init__(
        self,
        base_dir: Path | str | None = None,
        console: Console | None = None,
    ) -> None:
        self._base: Path = Path(base_dir) if base_dir else _DEFAULT_BASE
        self._console = console or _CONSOLE
        self._base.mkdir(parents=True, exist_ok=True)

    # -- internal helpers ----------------------------------------------------

    def _session_path(self, name: str) -> Path:
        return self._base / f"{name}.json"

    def _read(self, name: str) -> dict[str, Any]:
        """Read raw session dict from disk."""
        path = self._session_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Session '{name}' not found at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, name: str, data: dict[str, Any]) -> None:
        """Write session dict to disk."""
        path = self._session_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )

    # -- public API ----------------------------------------------------------

    def save(self, name: str, data: dict[str, Any], tags: list[str] | None = None) -> dict[str, Any]:
        """Save a named session to disk.

        Args:
            name: Session name (used as the file stem).
            data: Arbitrary session data to persist.
            tags: Optional list of tag strings for categorisation.

        Returns:
            The full session record (metadata + data).
        """
        session: dict[str, Any] = {
            "name": name,
            "created": datetime.now(timezone.utc).isoformat(),
            "tags": tags or [],
            "data": data,
        }
        self._write(name, session)

        self._console.print(
            Panel(
                f"[bold green]Session '{name}' saved.[/bold green]\n"
                f"[dim]Tags: {', '.join(session['tags']) or 'none'}[/dim]\n"
                f"[dim]Path: {self._session_path(name)}[/dim]",
                title="💾 Session Saved",
                border_style="green",
            )
        )
        return session

    def load(self, name: str) -> dict[str, Any]:
        """Load a session by name.

        Args:
            name: Session name.

        Returns:
            The session data dict.

        Raises:
            FileNotFoundError: If the session does not exist.
        """
        session = self._read(name)
        self._console.print(
            Panel(
                f"[bold cyan]Session '{name}' loaded.[/bold cyan]\n"
                f"[dim]Created: {session.get('created', 'unknown')}[/dim]",
                title="📂 Session Loaded",
                border_style="cyan",
            )
        )
        return session["data"]

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all saved sessions and print a summary table.

        Returns:
            A list of metadata dicts, one per session.
        """
        sessions: list[dict[str, Any]] = []
        for path in sorted(self._base.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                sessions.append({
                    "name": raw.get("name", path.stem),
                    "created": raw.get("created", "unknown"),
                    "tags": raw.get("tags", []),
                    "size": path.stat().st_size,
                })
            except (json.JSONDecodeError, OSError):
                sessions.append({
                    "name": path.stem,
                    "created": "unknown",
                    "tags": [],
                    "size": path.stat().st_size,
                })

        # -- render table ---
        if not sessions:
            self._console.print(
                Panel("[dim]No saved sessions.[/dim]", title="📁 Sessions",
                      border_style="dim")
            )
            return sessions

        table = Table(
            title="📁 Saved Sessions",
            show_lines=False,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
        )
        table.add_column("Name", style="bold", no_wrap=True)
        table.add_column("Created", style="dim", width=22)
        table.add_column("Tags", style="dim", width=20)
        table.add_column("Size", justify="right", width=8)

        for s in sessions:
            tags_str = ", ".join(s["tags"]) if s["tags"] else "[dim]—[/dim]"
            table.add_row(
                s["name"],
                str(s["created"])[:19],
                tags_str,
                f"{s['size']}B",
            )

        self._console.print(table)
        self._console.print(
            f"  [dim]{len(sessions)} session(s) in {self._base}[/dim]"
        )
        return sessions

    def restore(self, name: str) -> dict[str, Any]:
        """Restore (load + print details of) a named session.

        This is equivalent to :meth:`load` but renders additional metadata
        such as tags and creation time.

        Args:
            name: Session name.

        Returns:
            The session data dict.

        Raises:
            FileNotFoundError: If the session does not exist.
        """
        session = self._read(name)
        data = session.get("data", {})

        tags = session.get("tags", [])
        tags_str = ", ".join(tags) if tags else "none"
        created = session.get("created", "unknown")

        self._console.print(
            Panel(
                f"[bold green]Session restored: {name}[/bold green]\n\n"
                f"[bold]Created:[/bold] {created}\n"
                f"[bold]Tags:[/bold] {tags_str}\n"
                f"[bold]Data keys:[/bold] {', '.join(data.keys()) if isinstance(data, dict) else 'N/A'}",
                title="🔄 Session Restored",
                border_style="green",
            )
        )
        return data

    # -- dunder --------------------------------------------------------------

    def __repr__(self) -> str:
        count = len(list(self._base.glob("*.json")))
        return f"SessionManager(base={self._base}, count={count})"
