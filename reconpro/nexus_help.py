"""HelpOverlay — Visual modal help screen for NEXUS.

Phase E: A rich, structured help modal that replaces the chat-dumped
help text with a visually organized overlay. Shows commands grouped by
category, keybindings, and layout controls. Closes on Escape or click.

"""
from __future__ import annotations

from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.screen import ModalScreen
from textual.widgets import Static, Label, Button

from .theme import Theme


# ── Command groups for the help overlay ──
_CMD_GROUPS = [
    {
        "title": "SCAN & ATTACK",
        "commands": [
            ("scan <target>", "Remote security scan"),
            ("scan <t> with <mods>", "Selective module scan"),
            ("blitz <t1> <t2> ...", "Parallel multi-target"),
            ("agent <goal>", "Autonomous AI agent"),
            ("swarm <target>", "Multi-agent swarm"),
            ("adversarial <target>", "Adversarial fix-verify loop"),
        ],
    },
    {
        "title": "RECON & INTEL",
        "commands": [
            ("passive <domain>", "Passive DNS / OSINT"),
            ("fuzzer <url>", "Fuzz parameters"),
            ("cve <query>", "CVE / NVD lookup"),
            ("profile <target>", "Target fingerprinting"),
            ("subdomains <domain>", "Subdomain discovery"),
            ("cloud-recon <target>", "Cloud asset recon"),
            ("netmap", "Network topology"),
        ],
    },
    {
        "title": "AUDIT & ANALYSIS",
        "commands": [
            ("audit", "Local machine audit"),
            ("dev [path]", "Dev project scan"),
            ("doctor", "Health check"),
            ("iac [path]", "IaC audit"),
            ("container [path]", "Container analysis"),
            ("ast [path]", "AST code analysis"),
        ],
    },
    {
        "title": "POST-SCAN",
        "commands": [
            ("export <fmt>", "Export last scan (sarif/md/json/html)"),
            ("defense", "Generate remediation code"),
            ("compliance", "Compliance framework mapping"),
            ("delta", "Diff vs last scan"),
            ("benchmark", "Score tracking"),
            ("history", "Scan history"),
            ("graph", "Knowledge graph stats"),
        ],
    },
    {
        "title": "META & LAYOUT",
        "commands": [
            ("help / ?", "Show this help overlay"),
            ("theme [name|list]", "Switch theme"),
            ("layout", "Show layout status"),
            ("clear", "Clear all feeds"),
            ("quit", "Exit NEXUS"),
        ],
    },
]

_KEYBINDINGS = [
    ("Tab", "Auto-complete / quick-pick / cycle focus"),
    ("Esc", "Dismiss popup / close modal / back to input"),
    ("Enter", "Open finding detail"),
    ("j / k", "Navigate findings & chat (vim)"),
    ("Arrow keys", "Navigate module grid cells"),
    ("d", "Inspect last finding"),
    ("0 / 1 / 2 / 3", "Jump: input / chat / findings / modules"),
    ("Ctrl+L", "Clear findings feed"),
    ("Ctrl+S", "Re-scan last target"),
    ("Ctrl+Left/Right", "Resize left/right split"),
    ("Ctrl+Up", "Toggle module grid"),
    ("[", "Toggle chat panel"),
    ("=", "Toggle module grid"),
    ("|", "Reset split to auto"),
    ("", "Reset split to 50:50"),
]


class HelpOverlay(ModalScreen):
    """Rich, structured help modal for NEXUS.

    Displays commands organized by category, keybindings, and layout
    controls in a scrollable overlay with a dark semi-transparent backdrop.
    Closes on Escape, 'q', or clicking Close.
    """

    DEFAULT_CSS = """
    HelpOverlay {
        align: center middle;
    }
    .help-backdrop {
        background: rgba(5, 5, 15, 0.88);
        width: 100%;
        height: 100%;
    }
    .help-frame {
        width: 80;
        max-height: 90%;
        max-width: 90;
        margin: 0 auto;
        padding: 1 2;
    }
    .help-title {
        text-align: center;
        margin-bottom: 1;
    }
    .help-section-title {
        margin-top: 1;
        margin-bottom: 0;
    }
    .help-cmd {
        margin-bottom: 0;
    }
    .help-sep {
        margin-top: 1;
        margin-bottom: 1;
    }
    .help-actions {
        align: center middle;
        margin-top: 1;
    }
    .help-actions Button {
        margin: 0 2;
    }
    """

    def compose(self):
        theme = Theme.current()
        cyan = theme.CYAN
        accent = theme.ACCENT
        dim = theme.TEXT_DIM
        yellow = theme.YELLOW
        green = theme.GREEN
        red = theme.RED
        border = theme.BORDER
        panel_bg = theme.PANEL_BG

        with Vertical(classes="help-backdrop"):
            with Vertical(classes="help-frame"):
                # Title
                yield Static(
                    f"[{cyan} bold]RECONPRO NEXUS v11.2.0[/{cyan}]  [{dim}]COMMAND REFERENCE[/{dim}]",
                    classes="help-title",
                )

                # Command groups
                with VerticalScroll():
                    for group in _CMD_GROUPS:
                        yield Static(
                            f"[{accent} bold]  {group['title']}[/{accent}]",
                            classes="help-section-title",
                        )
                        for cmd, desc in group["commands"]:
                            yield Static(
                                f"    [{cyan}]{cmd:<28}[/{cyan}] [{dim}]{desc}[/{dim}]",
                                classes="help-cmd",
                            )

                    # Separator
                    yield Static(f"[{border}]{chr(9472) * 60}[/{border}]", classes="help-sep")

                    # Keybindings
                    yield Static(
                        f"[{accent} bold]  KEYBINDINGS[/{accent}]",
                        classes="help-section-title",
                    )
                    for key, desc in _KEYBINDINGS:
                        yield Static(
                            f"    [{cyan}]{key:<22}[/{cyan}] [{dim}]{desc}[/{dim}]",
                            classes="help-cmd",
                        )

                # Close button
                with Horizontal(classes="help-actions"):
                    yield Button("Close", variant="primary", id="close-help")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-help":
            self.dismiss()

    def on_key(self, event: Key) -> None:
        """Dismiss on Escape or q."""
        if event.key in ("escape", "q"):
            self.dismiss()
            event.stop()
