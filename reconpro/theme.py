"""ReconPro Unified Theme System.

Single source of truth for ALL colors, styles, and visual tokens.
Every module (TUI, CLI, HTML reports, chat) imports from here.

Usage:
    from .theme import Theme
    t = Theme.current()
    t.CYAN  # -> "#00ffcc"
    t.sev_style("critical")  # -> "bold #ff0044"

Theme switching (live, no restart):
    Theme.set_theme("midnight")
    Theme.set_theme("matrix")
"""
from __future__ import annotations

import sys
try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ════════════════════════════════════════════════════════════════════════════════
# Theme Definitions
# ════════════════════════════════════════════════════════════════════════════════

THEMES: Dict[str, Dict[str, Any]] = {
    # ── Cyberpunk (default — current look) ──────────────────────────────────
    "cyberpunk": {
        "name": "Cyberpunk Neon",
        "bg": "#0a0a14",
        "panel_bg": "#0e0e1c",
        "header_bg": "#0c0c18",
        "input_bg": "#0f0f1e",
        "border": "#1a1a2e",
        "text": "#ccccdd",
        "text_dim": "#666688",
        "cyan": "#00ffcc",
        "dim_cyan": "#0a4a3a",
        "red": "#ff0044",
        "dim_red": "#4a0a1a",
        "yellow": "#ffdd00",
        "green": "#00ff88",
        "orange": "#ff8800",
        "muted": "#888899",
        "accent": "#00ffcc",
        "scrollbar_bg": "#0a0a14",
        "scrollbar_fg": "#0a4a3a",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #ff0044",
            "high": "#ff0044",
            "medium": "#ffdd00",
            "low": "#00ff88",
            "info": "#666688",
        },
        "severity_hex": {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f1c40f",
            "low": "#2ecc71",
            "info": "#95a5a6",
        },
        "grade": {
            "A+": "#00ff88",
            "A": "#44dd66",
            "B": "#ffdd00",
            "C": "#ff8800",
            "D": "#ff4444",
            "F": "#ff0044",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#0a0a0f",
            "card_bg": "#111118",
            "border": "#1a1a2e",
            "text": "#e0e0e0",
            "muted": "#666666",
        },
    },

    # ── Midnight (professional deep blue) ──────────────────────────────────
    "midnight": {
        "name": "Midnight",
        "bg": "#0c0e1a",
        "panel_bg": "#111428",
        "header_bg": "#0f1120",
        "input_bg": "#131630",
        "border": "#1e2245",
        "text": "#c8cde0",
        "text_dim": "#556080",
        "cyan": "#6ba3f7",
        "dim_cyan": "#2a3a5a",
        "red": "#f85149",
        "dim_red": "#4a2020",
        "yellow": "#e3b341",
        "green": "#56d364",
        "orange": "#db8b0e",
        "muted": "#7d8590",
        "accent": "#6ba3f7",
        "scrollbar_bg": "#0c0e1a",
        "scrollbar_fg": "#2a3a5a",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #f85149",
            "high": "#f85149",
            "medium": "#e3b341",
            "low": "#56d364",
            "info": "#556080",
        },
        "severity_hex": {
            "critical": "#f85149",
            "high": "#e67e22",
            "medium": "#e3b341",
            "low": "#56d364",
            "info": "#7d8590",
        },
        "grade": {
            "A+": "#56d364",
            "A": "#3fb950",
            "B": "#e3b341",
            "C": "#db8b0e",
            "D": "#f85149",
            "F": "#da3633",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#0d1117",
            "card_bg": "#161b22",
            "border": "#21262d",
            "text": "#c9d1d9",
            "muted": "#7d8590",
        },
    },

    # ── Matrix (hacker green-on-black) ─────────────────────────────────────
    "matrix": {
        "name": "Matrix",
        "bg": "#000a00",
        "panel_bg": "#001200",
        "header_bg": "#000e00",
        "input_bg": "#001500",
        "border": "#003300",
        "text": "#00cc44",
        "text_dim": "#336633",
        "cyan": "#00ff66",
        "dim_cyan": "#004d22",
        "red": "#ff3333",
        "dim_red": "#4d0a0a",
        "yellow": "#ccff00",
        "green": "#00ff66",
        "orange": "#88cc00",
        "muted": "#337733",
        "accent": "#00ff66",
        "scrollbar_bg": "#000a00",
        "scrollbar_fg": "#004d22",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #ff3333",
            "high": "#ff3333",
            "medium": "#ccff00",
            "low": "#00ff66",
            "info": "#336633",
        },
        "severity_hex": {
            "critical": "#ff3333",
            "high": "#ff6633",
            "medium": "#ccff00",
            "low": "#00ff66",
            "info": "#337733",
        },
        "grade": {
            "A+": "#00ff66",
            "A": "#00cc44",
            "B": "#ccff00",
            "C": "#88cc00",
            "D": "#ff6633",
            "F": "#ff3333",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#000a00",
            "card_bg": "#001200",
            "border": "#003300",
            "text": "#00cc44",
            "muted": "#337733",
        },
    },

    # ── Solarized Dark ─────────────────────────────────────────────────────
    "solarized": {
        "name": "Solarized Dark",
        "bg": "#002b36",
        "panel_bg": "#073642",
        "header_bg": "#002b36",
        "input_bg": "#073642",
        "border": "#586e75",
        "text": "#839496",
        "text_dim": "#586e75",
        "cyan": "#2aa198",
        "dim_cyan": "#0e4c46",
        "red": "#dc322f",
        "dim_red": "#4a1512",
        "yellow": "#b58900",
        "green": "#859900",
        "orange": "#cb4b16",
        "muted": "#586e75",
        "accent": "#268bd2",
        "scrollbar_bg": "#002b36",
        "scrollbar_fg": "#0e4c46",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #dc322f",
            "high": "#dc322f",
            "medium": "#b58900",
            "low": "#859900",
            "info": "#586e75",
        },
        "severity_hex": {
            "critical": "#dc322f",
            "high": "#cb4b16",
            "medium": "#b58900",
            "low": "#859900",
            "info": "#586e75",
        },
        "grade": {
            "A+": "#859900",
            "A": "#6c8700",
            "B": "#b58900",
            "C": "#cb4b16",
            "D": "#dc322f",
            "F": "#dc322f",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#002b36",
            "card_bg": "#073642",
            "border": "#586e75",
            "text": "#839496",
            "muted": "#586e75",
        },
    },

    # ── Blood (offensive red/amber) ─────────────────────────────────────────
    "blood": {
        "name": "Blood",
        "bg": "#0a0008",
        "panel_bg": "#12000e",
        "header_bg": "#0e000a",
        "input_bg": "#150010",
        "border": "#2a0020",
        "text": "#cc8899",
        "text_dim": "#663344",
        "cyan": "#ff6699",
        "dim_cyan": "#4a1a30",
        "red": "#ff0033",
        "dim_red": "#4a000d",
        "yellow": "#ffaa00",
        "green": "#ff6633",
        "orange": "#ff8800",
        "muted": "#884466",
        "accent": "#ff0033",
        "scrollbar_bg": "#0a0008",
        "scrollbar_fg": "#4a1a30",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #ff0033",
            "high": "#ff0033",
            "medium": "#ffaa00",
            "low": "#ff6633",
            "info": "#663344",
        },
        "severity_hex": {
            "critical": "#ff0033",
            "high": "#ff4444",
            "medium": "#ffaa00",
            "low": "#ff6633",
            "info": "#884466",
        },
        "grade": {
            "A+": "#ff6633",
            "A": "#cc5522",
            "B": "#ffaa00",
            "C": "#ff4444",
            "D": "#ff0033",
            "F": "#cc0022",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#0a0008",
            "card_bg": "#12000e",
            "border": "#2a0020",
            "text": "#cc8899",
            "muted": "#663344",
        },
    },

    # ── Snow (light mode) ───────────────────────────────────────────────────
    "snow": {
        "name": "Snow",
        "bg": "#f5f6fa",
        "panel_bg": "#ffffff",
        "header_bg": "#eef0f6",
        "input_bg": "#ffffff",
        "border": "#d0d5e0",
        "text": "#2c3e50",
        "text_dim": "#95a5a6",
        "cyan": "#2980b9",
        "dim_cyan": "#bdc3c7",
        "red": "#e74c3c",
        "dim_red": "#f5b7b1",
        "yellow": "#f39c12",
        "green": "#27ae60",
        "orange": "#e67e22",
        "muted": "#7f8c8d",
        "accent": "#2980b9",
        "scrollbar_bg": "#eef0f6",
        "scrollbar_fg": "#bdc3c7",
        "spinner_frames": ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        "severity": {
            "critical": "bold #e74c3c",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#27ae60",
            "info": "#95a5a6",
        },
        "severity_hex": {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f39c12",
            "low": "#27ae60",
            "info": "#95a5a6",
        },
        "grade": {
            "A+": "#27ae60",
            "A": "#229954",
            "B": "#f39c12",
            "C": "#e67e22",
            "D": "#e74c3c",
            "F": "#c0392b",
        },
        "grade_rich": {
            "A+": "bright_green",
            "A": "green",
            "A-": "green",
            "B+": "yellow",
            "B": "yellow",
            "B-": "dark_orange",
            "C+": "dark_orange",
            "C": "red",
            "C-": "red",
            "D": "bright_red",
            "F": "bold bright_red",
        },
        "html": {
            "body_bg": "#f5f6fa",
            "card_bg": "#ffffff",
            "border": "#d0d5e0",
            "text": "#2c3e50",
            "muted": "#7f8c8d",
        },
    },
}

# Config file paths
_CONFIG_DIR = Path.home() / ".reconpro"
_CONFIG_FILE = _CONFIG_DIR / "config.toml"
_CUSTOM_THEMES_DIR = _CONFIG_DIR / "themes"


# ════════════════════════════════════════════════════════════════════════════════
# Theme Class
# ════════════════════════════════════════════════════════════════════════════════


class Theme:
    """Unified theme providing all visual tokens.

    Attributes are set dynamically from the active theme dict.
    Access colors via attributes or helper methods.
    """

    _active: Theme | None = None
    _active_name: str = "cyberpunk"

    def __init__(self, data: Dict[str, Any]) -> None:
        # Flatten top-level color tokens as attributes
        color_keys = [
            "bg", "panel_bg", "header_bg", "input_bg", "border",
            "text", "text_dim", "cyan", "dim_cyan", "red", "dim_red",
            "yellow", "green", "orange", "muted", "accent",
            "scrollbar_bg", "scrollbar_fg",
        ]
        for key in color_keys:
            setattr(self, key.upper(), data.get(key, "#ffffff"))

        # Nested dicts stored as-is
        self._severity = data.get("severity", {})
        self._severity_hex = data.get("severity_hex", {})
        self._grade = data.get("grade", {})
        self._grade_rich = data.get("grade_rich", {})
        self._html = data.get("html", {})
        self._spinner_frames = data.get(
            "spinner_frames",
            ["\u28cb", "\u28d9", "\u28f9", "\u28fa", "\u28fc", "\u28f4", "\u28e6", "\u28e7", "\u28e7", "\u28cf"],
        )
        self._data = data

    # ── Accessors ───────────────────────────────────────────────────────────

    @property
    def spinner_frames(self) -> List[str]:
        return list(self._spinner_frames)

    def sev_style(self, severity: str) -> str:
        """Get Rich/Textual markup style for a severity level.

        Returns something like 'bold #ff0044' for TUI/CLI use.
        """
        return self._severity.get(severity.lower(), self.TEXT_DIM)

    def sev_hex(self, severity: str) -> str:
        """Get hex color for a severity level (for HTML reports)."""
        return self._severity_hex.get(severity.lower(), "#999999")

    def grade_color(self, grade: str) -> str:
        """Get hex color for a grade (A+ through F)."""
        return self._grade.get(grade, "#ccccdd")

    def grade_rich(self, grade: str) -> str:
        """Get Rich named color for a grade (for CLI output)."""
        return self._grade_rich.get(grade, "bold bright_red")

    def html_style(self) -> Dict[str, str]:
        """Get HTML report style tokens."""
        return dict(self._html)

    def to_dict(self) -> Dict[str, Any]:
        """Return the raw theme data dict."""
        return dict(self._data)

    # ── Theme Registry & Switching ──────────────────────────────────────────

    @classmethod
    def available_themes(cls) -> List[str]:
        """Return list of available theme names."""
        return list(THEMES.keys())

    @classmethod
    def current(cls) -> Theme:
        """Get the current active theme (loads from config if needed)."""
        if cls._active is None:
            cls._load_from_config()
        return cls._active  # type: ignore[return-value]

    @classmethod
    def current_name(cls) -> str:
        """Get the current theme name."""
        if cls._active is None:
            cls._load_from_config()
        return cls._active_name

    @classmethod
    def set_theme(cls, name: str) -> None:
        """Switch to a named theme. Returns True if successful."""
        name = name.lower().strip()

        # Check built-in themes
        if name in THEMES:
            cls._active = Theme(THEMES[name])
            cls._active_name = name
            cls._save_to_config()
            return

        # Check custom themes
        custom = cls._load_custom_theme(name)
        if custom:
            cls._active = Theme(custom)
            cls._active_name = name
            cls._save_to_config()
            return

        raise ValueError(
            f"Unknown theme '{name}'. Available: {', '.join(cls.available_themes())}"
        )

    # ── Config Persistence ──────────────────────────────────────────────────

    @classmethod
    def _load_from_config(cls) -> None:
        """Load theme preference from config file."""
        try:
            if _CONFIG_FILE.exists() and tomllib is not None:
                cfg = tomllib.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
                name = cfg.get("theme", {}).get("name", "cyberpunk")
            else:
                name = "cyberpunk"
        except Exception:
            name = "cyberpunk"

        if name in THEMES:
            cls._active = Theme(THEMES[name])
            cls._active_name = name
        else:
            # Fallback: try loading as custom theme
            custom = cls._load_custom_theme(name)
            if custom:
                cls._active = Theme(custom)
                cls._active_name = name
            else:
                cls._active = Theme(THEMES["cyberpunk"])
                cls._active_name = "cyberpunk"

    @classmethod
    def _save_to_config(cls) -> None:
        """Persist theme preference to config file."""
        try:
            _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if _CONFIG_FILE.exists() and tomllib is not None:
                cfg = tomllib.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            else:
                cfg = {}
            if "theme" not in cfg:
                cfg["theme"] = {}
            cfg["theme"]["name"] = cls._active_name
            lines = ["[theme]", f"name = \"{cls._active_name}\""]
            _CONFIG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception:
            pass  # Silent fail — theme still works in-memory

    @classmethod
    def _load_custom_theme(cls, name: str) -> Optional[Dict[str, Any]]:
        """Load a user-created theme from ~/.reconpro/themes/<name>.toml."""
        try:
            if _CUSTOM_THEMES_DIR.exists():
                path = _CUSTOM_THEMES_DIR / f"{name}.toml"
                if path.exists():
                    if tomllib is not None:
                        return tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return None

    @classmethod
    def save_custom_theme(cls, name: str, data: Dict[str, Any], overwrite: bool = False) -> str:
        """Save a custom theme to disk. Returns the file path."""
        _CUSTOM_THEMES_DIR.mkdir(parents=True, exist_ok=True)
        path = _CUSTOM_THEMES_DIR / f"{name}.toml"
        if path.exists() and not overwrite:
            raise FileExistsError(f"Theme '{name}' already exists. Use overwrite=True.")
        # Write simple TOML
        lines = [f"# Custom ReconPro theme: {name}"]
        for k, v in data.items():
            if isinstance(v, dict):
                lines.append(f"\n[{k}]")
                for sk, sv in v.items():
                    if isinstance(sv, str):
                        lines.append(f"{sk} = \"{sv}\"")
                    elif isinstance(sv, (int, float)):
                        lines.append(f"{sk} = {sv}")
                    elif isinstance(sv, list):
                        lines.append(f"{sk} = {sv}")
            elif isinstance(v, str):
                lines.append(f"{k} = \"{v}\"")
            elif isinstance(v, (int, float)):
                lines.append(f"{k} = {v}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def __repr__(self) -> str:
        return f"<Theme:{self._active_name}>"
