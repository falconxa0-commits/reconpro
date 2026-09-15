"""Workspace management for ReconPro.

Manages named workspaces that persist under ``~/.reconpro/workspaces/``.
Each workspace is a directory on disk that can be created, switched,
deleted, exported (archived), and imported.

Classes:
    WorkspaceManager: CRUD + export/import operations on workspaces.
"""

from __future__ import annotations

import json
import shutil
import zipfile

from .safe_archive import safe_extract_zip, UnsafeArchiveError
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

__all__ = ["WorkspaceManager"]

_CONSOLE = Console()

_DEFAULT_BASE = Path.home() / ".reconpro" / "workspaces"


class WorkspaceManager:
    """Create, list, switch, delete, export, and import workspaces.

    All workspaces live under ``~/.reconpro/workspaces/<name>/``.  A small
    metadata file (``workspace.json``) is stored inside each workspace.

    Args:
        base_dir: Override the root directory for workspaces.  Defaults to
                  ``~/.reconpro/workspaces/``.
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
        self._active: str | None = self._detect_active()

    # -- internal helpers ----------------------------------------------------

    def _detect_active(self) -> str | None:
        """Read the ``active_workspace`` marker file if it exists."""
        marker = self._base / ".active"
        if marker.exists():
            return marker.read_text(encoding="utf-8").strip() or None
        return None

    def _set_active_marker(self, name: str | None) -> None:
        marker = self._base / ".active"
        if name is None:
            marker.unlink(missing_ok=True)
        else:
            marker.write_text(name, encoding="utf-8")

    def _meta_path(self, name: str) -> Path:
        return self._workspace_dir(name) / "workspace.json"

    def _workspace_dir(self, name: str) -> Path:
        return self._base / name

    def _read_meta(self, name: str) -> dict[str, Any]:
        meta = self._meta_path(name)
        if meta.exists():
            return json.loads(meta.read_text(encoding="utf-8"))
        return {}

    def _write_meta(self, name: str, meta: dict[str, Any]) -> None:
        self._meta_path(name).parent.mkdir(parents=True, exist_ok=True)
        self._meta_path(name).write_text(
            json.dumps(meta, indent=2, default=str),
            encoding="utf-8",
        )

    # -- public API ----------------------------------------------------------

    def list_workspaces(self) -> list[dict[str, Any]]:
        """List all workspaces and print a summary table.

        Returns:
            A list of metadata dicts, one per workspace.
        """
        workspaces: list[dict[str, Any]] = []
        for entry in sorted(self._base.iterdir()):
            if entry.is_dir() and not entry.name.startswith("."):
                meta = self._read_meta(entry.name)
                meta.setdefault("name", entry.name)
                meta.setdefault("created", "unknown")
                meta.setdefault("active", entry.name == self._active)
                workspaces.append(meta)

        # -- render table ---
        table = Table(
            title="📁 Workspaces",
            show_lines=False,
            border_style="bright_cyan",
            title_style="bold bright_cyan",
        )
        table.add_column("Name", style="bold")
        table.add_column("Created", style="dim")
        table.add_column("Status", width=10)

        for ws in workspaces:
            status = "[bold green]● active[/bold green]" if ws.get("active") else "[dim]inactive[/dim]"
            table.add_row(ws["name"], str(ws.get("created", "—")), status)

        self._console.print(table)
        self._console.print(f"  [dim]{len(workspaces)} workspace(s) — active: {self._active or 'none'}[/dim]")
        return workspaces

    def create(self, name: str, description: str = "") -> dict[str, Any]:
        """Create a new workspace.

        Args:
            name: Workspace name (must be a valid directory name).
            description: Optional description stored in metadata.

        Returns:
            The workspace metadata dict.
        """
        ws_dir = self._workspace_dir(name)
        if ws_dir.exists():
            self._console.print(
                Panel(f"[bold red]Workspace '{name}' already exists.[/bold red]",
                      border_style="red")
            )
            return self._read_meta(name)

        meta: dict[str, Any] = {
            "name": name,
            "description": description,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        self._write_meta(name, meta)
        self._console.print(
            Panel(
                f"[bold green]Workspace '{name}' created.[/bold green]",
                title="Workspace",
                border_style="green",
            )
        )
        return meta

    def switch(self, name: str) -> None:
        """Switch the active workspace.

        Args:
            name: Name of the workspace to activate.
        """
        ws_dir = self._workspace_dir(name)
        if not ws_dir.is_dir():
            self._console.print(
                Panel(f"[bold red]Workspace '{name}' does not exist.[/bold red]",
                      border_style="red")
            )
            return

        self._active = name
        self._set_active_marker(name)
        self._console.print(
            Panel(
                f"[bold green]Switched to workspace '{name}'.[/bold green]",
                title="Workspace",
                border_style="green",
            )
        )

    def delete(self, name: str) -> bool:
        """Delete a workspace directory and its metadata.

        Args:
            name: Workspace name.

        Returns:
            *True* if deleted, *False* if it did not exist.
        """
        ws_dir = self._workspace_dir(name)
        if not ws_dir.is_dir():
            self._console.print(
                Panel(f"[bold red]Workspace '{name}' does not exist.[/bold red]",
                      border_style="red")
            )
            return False

        shutil.rmtree(ws_dir)
        if self._active == name:
            self._active = None
            self._set_active_marker(None)

        self._console.print(
            Panel(
                f"[bold yellow]Workspace '{name}' deleted.[/bold yellow]",
                title="Workspace",
                border_style="yellow",
            )
        )
        return True

    def export(self, name: str, output_path: Path | str | None = None) -> Path:
        """Export a workspace as a ``.zip`` archive.

        Args:
            name: Workspace name to export.
            output_path: Destination path.  Defaults to
                          ``~/.reconpro/workspaces/<name>.zip``.

        Returns:
            Path to the created zip file.
        """
        ws_dir = self._workspace_dir(name)
        if not ws_dir.is_dir():
            self._console.print(
                Panel(f"[bold red]Workspace '{name}' does not exist.[/bold red]",
                      border_style="red")
            )
            raise FileNotFoundError(f"Workspace '{name}' not found")

        dest = Path(output_path) if output_path else self._base / f"{name}.zip"
        dest.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in ws_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(ws_dir)
                    zf.write(file_path, arcname)

        self._console.print(
            Panel(
                f"[bold green]Exported '{name}' → {dest}[/bold green]",
                title="Workspace Export",
                border_style="green",
            )
        )
        return dest

    def import_ws(
        self,
        archive_path: Path | str,
        new_name: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Import a workspace from a ``.zip`` archive.

        Args:
            archive_path: Path to the zip file.
            new_name: Override workspace name (defaults to stem of the zip).
            overwrite: If *True*, replace an existing workspace.

        Returns:
            The imported workspace metadata.
        """
        archive = Path(archive_path)
        if not archive.exists():
            self._console.print(
                Panel(f"[bold red]Archive not found: {archive}[/bold red]",
                      border_style="red")
            )
            raise FileNotFoundError(str(archive))

        name = new_name or archive.stem
        ws_dir = self._workspace_dir(name)

        if ws_dir.exists():
            if overwrite:
                shutil.rmtree(ws_dir)
            else:
                self._console.print(
                    Panel(
                        f"[bold red]Workspace '{name}' already exists. "
                        f"Use overwrite=True to replace.[/bold red]",
                        border_style="red",
                    )
                )
                raise FileExistsError(name)

        ws_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, "r") as zf:
            # Safe extraction: rejects path traversal, symlink members and
            # archives that decompress beyond the size cap (zip bombs).
            try:
                safe_extract_zip(zf, ws_dir)
            except UnsafeArchiveError as exc:
                shutil.rmtree(ws_dir, ignore_errors=True)
                self._console.print(
                    Panel(f"[bold red]Refusing unsafe archive: {exc}[/bold red]",
                          border_style="red")
                )
                raise

        meta = self._read_meta(name)
        meta.setdefault("name", name)
        meta["imported_from"] = str(archive)
        self._write_meta(name, meta)

        self._console.print(
            Panel(
                f"[bold green]Imported workspace '{name}' from {archive}[/bold green]",
                title="Workspace Import",
                border_style="green",
            )
        )
        return meta

    # -- dunder --------------------------------------------------------------

    @property
    def active(self) -> str | None:
        """Name of the currently active workspace (or *None*)."""
        return self._active

    def __repr__(self) -> str:
        return f"WorkspaceManager(base={self._base}, active={self._active!r})"
