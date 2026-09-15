"""Interactive command palette for ReconPro.

Provides a searchable command registry that prints available commands in a
styled Rich table.  Commands are registered declaratively and can be listed,
searched, or displayed interactively.

Classes:
    CommandPalette: Registry and display layer for available commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = ["CommandPalette"]

_CONSOLE = Console()


@dataclass(frozen=True)
class Command:
    """A single registered command entry.

    Attributes:
        name: The command name / trigger string.
        description: Human-readable explanation.
        category: Grouping category (e.g. *scan*, *report*).
    """

    name: str
    description: str
    category: str = "general"


class CommandPalette:
    """Registry and display layer for the ReconPro command palette.

    Maintains an ordered list of commands and renders them in a searchable
    Rich table.  The built-in ``RECON_COMMANDS`` class attribute seeds the
    palette with sensible defaults.

    Usage::

        palette = CommandPalette()
        palette.show()                    # show all commands
        palette.show(search="scan")       # filter by keyword
        palette.register(Command("foo", "Does foo"))
        palette.show(search="foo")

    Args:
        console: Optional Rich console (defaults to shared instance).
    """

    #: Default commands shipped with ReconPro.
    RECON_COMMANDS: list[Command] = [
        Command("scan", "Run a full reconnaissance scan", "scan"),
        Command("quick", "Fast surface-level scan", "scan"),
        Command("deep", "Deep scan with all modules enabled", "scan"),
        Command("report", "Generate a findings report", "report"),
        Command("summary", "Print an executive summary", "report"),
        Command("export", "Export results to file", "report"),
        Command("workspace", "Manage workspaces", "config"),
        Command("session", "Manage sessions", "config"),
        Command("notifications", "View notification center", "config"),
        Command("copilot", "Open AI Copilot assistant", "ai"),
        Command("help", "Show this command palette", "general"),
        Command("clear", "Clear the terminal", "general"),
        Command("exit", "Exit ReconPro", "general"),
    ]

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or _CONSOLE
        self._commands: list[Command] = list(self.RECON_COMMANDS)

    # -- mutations -----------------------------------------------------------

    def register(self, command: Command) -> None:
        """Register a new command.  Duplicates (by name) are replaced."""
        self._commands = [c for c in self._commands if c.name != command.name]
        self._commands.append(command)

    def unregister(self, name: str) -> None:
        """Remove a command by name (no-op if not found)."""
        self._commands = [c for c in self._commands if c.name != name]

    # -- queries -------------------------------------------------------------

    def get_all(self) -> list[Command]:
        """Return a shallow copy of all registered commands."""
        return list(self._commands)

    def search(self, keyword: str) -> list[Command]:
        """Return commands whose name or description contains *keyword* (case-insensitive)."""
        kw = keyword.lower()
        return [
            c
            for c in self._commands
            if kw in c.name.lower() or kw in c.description.lower()
        ]

    # -- display -------------------------------------------------------------

    def show(self, search: str | None = None) -> None:
        """Render the command palette as a Rich table.

        Args:
            search: Optional keyword filter.  When provided, only matching
                    commands are displayed.
        """
        commands = self.search(search) if search else self._commands

        if not commands:
            self._console.print(
                Panel(
                    "[dim]No commands found.[/dim]",
                    title="Command Palette",
                    border_style="red",
                )
            )
            return

        table = Table(
            title="⚡ Command Palette",
            show_lines=True,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
        )
        table.add_column("Command", style="bold cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_column("Category", style="dim", width=10)

        category_colours: dict[str, str] = {
            "scan": "bold green",
            "report": "bold yellow",
            "config": "bold magenta",
            "ai": "bold blue",
            "general": "white",
        }

        for cmd in commands:
            cat_style = category_colours.get(cmd.category, "white")
            table.add_row(cmd.name, cmd.description, Text(cmd.category, style=cat_style))

        self._console.print(table)

        if search:
            self._console.print(
                f"  [dim]Showing {len(commands)} result(s) for '{search}'[/dim]"
            )
        else:
            self._console.print(
                f"  [dim]{len(commands)} command(s) available — use :filter to narrow[/dim]"
            )

    def __len__(self) -> int:
        return len(self._commands)

    def __repr__(self) -> str:
        return f"CommandPalette(commands={len(self._commands)})"
