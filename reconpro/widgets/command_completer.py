"""CommandCompleter — Fuzzy auto-complete dropdown for the NEXUS command bar.

Phase C enhancements:
  - Arg-level completion: targets, formats (sarif/md/json/html), theme names,
    module names after ``with`` clause
  - Improved fuzzy scoring with word-boundary and consecutive-char bonuses
  - Alias display beside command names (e.g. ``scan (s)``)
  - Visual selection highlight with background tint
  - Footer hint line showing keybindings (Tab accept, Esc dismiss)
  - Target history completion fed from the app's command history
  - Consecutive-character bonus in fuzzy matching for better ranking

Usage in NexusApp compose::
    yield CommandCompleter(id="cmd-completer")

Wire up in NexusApp::
    def on_input_changed(self, event):
        completer = self.query_one("#cmd-completer", CommandCompleter)
        completer.show_suggestions(event.value)

    def on_key(self, event):
        if event.key == "tab" and completer.visible:
            completer.accept_top()
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import List, Tuple, Optional, Dict, Set

from textual.reactive import reactive
from textual.timer import Timer
from textual.widget import Widget
from textual.containers import Horizontal, Vertical

from ..theme import Theme


# ── Command database: (name, aliases, description, takes_args, context) ──
# context: None = always, "needs_target" = only if target exists, "no_scan" = only when idle
COMMAND_DB: List[Tuple[str, List[str], str, bool, Optional[str]]] = [
    # ── Core scan commands ──
    ("scan",       ["s"],    "Scan a remote target",                     True,  None),
    ("audit",      ["a"],    "Audit local machine",                       False, "no_scan"),
    ("dev",        [],       "Scan dev project",                          True,  "no_scan"),
    ("doctor",     [],       "Health check",                              False, "no_scan"),
    ("blitz",      ["b"],    "Parallel multi-target scan",                True,  None),
    ("subdomains", ["sub"],  "Discover subdomains",                       True,  None),
    ("agent",      [],       "Autonomous AI agent",                       True,  None),
    ("swarm",      [],       "Multi-agent swarm attack",                  True,  None),
    ("adversarial", ["adv"], "Adversarial fix-verify loop",               True,  None),
    # ── Intelligence & recon ──
    ("graph",      ["g"],    "Knowledge graph stats",                     False, None),
    ("passive",    [],       "Passive DNS / OSINT intel",                  True,  None),
    ("fuzzer",     ["fuzz"], "Fuzz parameters for vulns",                 True,  None),
    ("cve",        [],       "CVE / NVD vulnerability lookup",            True,  None),
    ("profile",    [],       "Target fingerprinting",                     True,  None),
    ("netmap",     [],       "Network topology map",                      False, "no_scan"),
    # ── Post-scan actions ──
    ("export",     ["exp"],  "Export last scan (sarif/md/json/html)",     True,  "needs_target"),
    ("session",    [],       "View & save session state",                   False, None),
    ("history",    ["h"],    "Scan history",                              False, None),
    ("defense",    [],       "Generate remediation code",                  False, "needs_target"),
    ("compliance", [],       "Compliance framework mapping",              False, "needs_target"),
    ("delta",      [],       "Dynamic delta report vs last scan",          False, "needs_target"),
    ("benchmark",  [],       "Score tracking & leaderboard",               False, None),
    # ── Analysis ──
    ("iac",        [],       "Infrastructure-as-Code audit",              True,  "no_scan"),
    ("container",  [],       "Container escape analysis",                  True,  "no_scan"),
    ("ast",        [],       "AST code analysis",                         True,  "no_scan"),
    ("cloud-recon", [],      "Cloud asset recon",                         True,  None),
    # ── Meta ──
    ("layout",     [],       "Show layout status & controls",              False, None),
    ("theme",      [],       "Switch theme",                               True,  None),
    ("clear",      ["c"],    "Clear all feeds",                            False, None),
    ("help",       ["?"],    "Show commands",                              False, None),
    ("quit",       ["q", "exit"], "Exit NEXUS",                           False, None),
]

# ── Arg-level completion tables ──
EXPORT_FORMATS = ["sarif", "md", "json", "html"]


# Build a set of all known aliases for quick lookup
_ALL_ALIASES: Dict[str, str] = {}
for _cmd, _aliases, *_ in COMMAND_DB:
    for _a in _aliases:
        _ALL_ALIASES[_a] = _cmd


def _fuzzy_score(query: str, candidate: str) -> float:
    """Score how well *query* matches *candidate*.

    Returns 0.0 – 1.0.  Higher is better.
    Scoring tiers:
      1.0  exact prefix
      0.95 alias exact prefix
      0.90 word-start match (query at a word boundary in candidate)
      0.7  substring anywhere
      0.5 × SequenceMatcher ratio  (fuzzy)

    Phase C addition: consecutive-character bonus of +0.05 per run of
    2+ consecutive matching chars, capped at +0.15.
    """
    q = query.lower()
    c = candidate.lower()

    if not q:
        return 0.0

    # Exact prefix
    if c.startswith(q):
        return 1.0

    # Alias exact prefix
    for cmd, aliases, *_ in COMMAND_DB:
        if c == cmd:
            for alias in aliases:
                if alias.startswith(q):
                    return 0.95

    # Word-boundary match: query appears right after a non-alpha char
    for i in range(1, len(c) - len(q) + 1):
        if not c[i - 1].isalnum() and c[i:i + len(q)] == q:
            return 0.90

    # Substring match
    if q in c:
        return 0.7

    # Fuzzy match using SequenceMatcher
    ratio = SequenceMatcher(None, q, c).ratio()
    base = ratio * 0.5

    # Consecutive-character bonus
    bonus = _consecutive_bonus(q, c)
    return min(base + bonus, 1.0)


def _consecutive_bonus(query: str, candidate: str) -> float:
    """Measure how many consecutive chars from query appear in candidate.

    Walk through *candidate*; for each run of consecutive chars that
    also appear consecutively in *query*, add 0.05 (max 0.15).
    """
    if len(query) < 2:
        return 0.0
    bonus = 0.0
    ci = 0
    run = 0
    for ch in query:
        # Find ch in candidate starting from ci
        idx = candidate.find(ch, ci)
        if idx != -1:
            if idx == ci:
                run += 1
            else:
                if run >= 2:
                    bonus += 0.05
                run = 1
            ci = idx + 1
        else:
            if run >= 2:
                bonus += 0.05
            run = 0
    if run >= 2:
        bonus += 0.05
    return min(bonus, 0.15)


def _highlight_match(text: str, query: str, color: str, dim: str) -> str:
    """Highlight matching characters in text with color.

    For fuzzy matches, highlights each character of query that appears
    in order within text.  Consecutive matches get a ``bold`` tag.
    """
    if not query:
        return f"[{dim}]{text}[/{dim}]"

    q = query.lower()
    t_lower = text.lower()

    # Prefix match — highlight the prefix portion
    if t_lower.startswith(q):
        matched = text[:len(q)]
        rest = text[len(q):]
        return f"[{color} bold]{matched}[/{color}] [{dim}]{rest}[/{dim}]"

    # Character-by-character fuzzy highlight with consecutive-bold
    result: List[str] = []
    qi = 0
    prev_matched = False
    for i, ch in enumerate(text):
        if qi < len(q) and t_lower[i] == q[qi]:
            style = f"{color} bold" if prev_matched else color
            result.append(f"[{style}]{ch}[/{style}]")
            qi += 1
            prev_matched = True
        else:
            result.append(f"[{dim}]{ch}[/{dim}]")
            prev_matched = False

    # If we didn't match all chars, just dim the whole thing
    if qi < len(q):
        return f"[{dim}]{text}[/{dim}]"

    return "".join(result)


class CommandCompleter(Widget):
    """Floating auto-complete dropdown for command input.

    Shows up to 6 fuzzy-matched command suggestions with descriptions,
    alias hints, and a keybinding footer.  Supports arg-level completion
    for export formats, theme names, module names, and target history.
    """

    DEFAULT_CSS = """
    CommandCompleter {
        width: auto;
        height: auto;
        max-height: 9;
        display: none;
        layer: popup;
    }
    CommandCompleter.visible {
        display: block;
    }
    """

    visible: reactive[bool] = reactive(False)

    def __init__(self, id: str = "cmd-completer") -> None:
        super().__init__(id=id)
        self._suggestions: List[Tuple[str, str, float, Optional[str]]] = []
        # (cmd, desc, score, alias_hint)
        self._selected_idx: int = 0
        self._current_query: str = ""
        self._dismiss_timer: Optional[Timer] = None
        self._max_visible: int = 6
        self._context_has_target: bool = False
        self._context_scanning: bool = False
        # ── Phase C: arg-level completion state ──
        self._mode: str = "command"  # command | arg_target | arg_format | arg_theme | arg_module
        self._target_history: List[str] = []
        self._module_names: List[str] = []

    def configure_context(
        self,
        has_target: bool,
        is_scanning: bool,
        target_history: Optional[List[str]] = None,
        module_names: Optional[List[str]] = None,
    ) -> None:
        """Update context for contextual and arg-level filtering."""
        self._context_has_target = has_target
        self._context_scanning = is_scanning
        if target_history is not None:
            self._target_history = target_history
        if module_names is not None:
            self._module_names = module_names

    def show_suggestions(self, text: str) -> None:
        """Compute and show fuzzy matches for the typed text.

        Phase C routing:
        - Empty input  → show top commands (quick-pick mode)
        - First word   → command completion (fuzzy against COMMAND_DB)
        - ``scan <partial>`` / ``blitz <partial>`` → target history
        - ``export <partial>`` → format list
        - ``theme <partial>`` → theme name list
        - ``... with <partial>`` → module name list
        """
        text_stripped = text.strip()
        self._current_query = text_stripped
        parts = text_stripped.split()

        if not parts:
            self.hide()
            return

        # ── Phase C enhanced: empty-query quick-pick on first space ──
        if len(parts) == 1 and not parts[0]:
            self._mode = "command"
            self._show_quick_pick()
            return

        first_word = parts[0].lower()

        # ── Detect arg-level completion mode ──
        # "defense <partial>" or "compliance <partial>" → no arg completion yet
        # (these commands take no positional args in the TUI)

        # "fuzzer <partial>" → target completion
        # "cve <partial>" → free text (no completion)
        # "profile <partial>" → target completion
        # "passive <partial>" → target completion
        # "cloud-recon <partial>" → target completion

        # "... with <partial>" → module names
        if len(parts) >= 3 and parts[-2].lower() == "with":
            self._mode = "arg_module"
            self._show_arg_suggestions(parts[-1], self._module_names, "module")
            return

        # "theme <partial>" → theme names
        if first_word == "theme" and len(parts) == 2 and parts[1].lower() not in ("list", "ls"):
            self._mode = "arg_theme"
            theme_names = Theme.available_themes()
            self._show_arg_suggestions(parts[1], theme_names, "theme")
            return

        # "export <partial>" → formats
        if first_word == "export" and len(parts) == 2:
            self._mode = "arg_format"
            self._show_arg_suggestions(parts[1], EXPORT_FORMATS, "format")
            return

        # "scan <partial>", "blitz <partial>", etc. → target history
        target_taking_cmds = {
            "scan", "blitz", "swarm", "subdomains", "agent",
            "adversarial", "dev", "passive", "fuzzer", "profile",
            "cloud-recon", "iac", "container", "ast", "cve",
        }
        if first_word in target_taking_cmds and len(parts) == 2:
            self._mode = "arg_target"
            # Combine target history with the current partial as a candidate
            candidates = list(self._target_history)
            if parts[1] and parts[1] not in candidates:
                candidates.insert(0, parts[1])
            self._show_arg_suggestions(parts[1], candidates, "target")
            return

        # ── Default: command completion ──
        self._mode = "command"
        query_part = parts[0]

        if not query_part:
            self.hide()
            return

        # Score all commands
        scored: List[Tuple[str, str, float, Optional[str]]] = []
        for cmd, aliases, desc, takes_args, ctx in COMMAND_DB:
            # Context filtering
            if ctx == "needs_target" and not self._context_has_target:
                continue
            if ctx == "no_scan" and self._context_scanning:
                continue

            # Score against command name
            score = _fuzzy_score(query_part, cmd)
            alias_hint: Optional[str] = None

            if score > 0.25:
                if aliases:
                    alias_hint = ", ".join(aliases)
                scored.append((cmd, desc, score, alias_hint))
                continue

            # Score against aliases
            for alias in aliases:
                alias_score = _fuzzy_score(query_part, alias)
                if alias_score > 0.25:
                    alias_hint = ", ".join(aliases)
                    scored.append((cmd, desc, alias_score * 0.9, alias_hint))
                    break

        # Sort by score descending, take top N
        scored.sort(key=lambda x: x[2], reverse=True)
        self._suggestions = scored[:self._max_visible]
        self._selected_idx = 0

        if self._suggestions:
            self.visible = True
            self._render()
        else:
            self.hide()

    def _show_arg_suggestions(
        self, query: str, candidates: List[str], kind: str
    ) -> None:
        """Show arg-level suggestions for the given candidate list."""
        if not query:
            # Show all candidates when query is empty (after space)
            scored = [(c, self._arg_description(c, kind), 1.0, None) for c in candidates[:self._max_visible]]
        else:
            scored = []
            for c in candidates:
                s = _fuzzy_score(query, c)
                if s > 0.2:
                    scored.append((c, self._arg_description(c, kind), s, None))
            scored.sort(key=lambda x: x[2], reverse=True)
            scored = scored[:self._max_visible]

        if not scored:
            self.hide()
            return

        self._suggestions = scored
        self._selected_idx = 0
        self.visible = True
        self._render()

    @staticmethod
    def _arg_description(candidate: str, kind: str) -> str:
        """Return a short description for an arg-level suggestion."""
        if kind == "format":
            descs = {"sarif": "GitHub SARIF", "md": "Markdown", "json": "JSON", "html": "HTML report"}
            return descs.get(candidate, "")
        if kind == "theme":
            from ..theme import THEMES
            t = THEMES.get(candidate, {})
            return t.get("name", candidate)
        if kind == "module":
            return "scan module"
        if kind == "target":
            return "recent target"
        return ""

    def show_quick_pick(self) -> None:
        """Show top-priority commands when Tab is pressed on empty input.

        Displays the most useful commands (scan, agent, blitz, etc.)
        at score 1.0 so they appear as a quick-pick menu.
        """
        # Priority commands shown on empty-input Tab
        quick_cmds = [
            "scan", "audit", "doctor", "blitz", "agent",
            "swarm", "subdomains", "adversarial", "export",
            "session", "theme", "help", "clear", "quit",
        ]
        scored: List[Tuple[str, str, float, Optional[str]]] = []
        for cmd, aliases, desc, takes_args, ctx in COMMAND_DB:
            if ctx == "needs_target" and not self._context_has_target:
                continue
            if ctx == "no_scan" and self._context_scanning:
                continue
            if cmd in quick_cmds:
                alias_hint = ", ".join(aliases) if aliases else None
                scored.append((cmd, desc, 1.0, alias_hint))

        # Append remaining commands not in quick_cmds
        for cmd, aliases, desc, takes_args, ctx in COMMAND_DB:
            if ctx == "needs_target" and not self._context_has_target:
                continue
            if ctx == "no_scan" and self._context_scanning:
                continue
            if cmd not in quick_cmds:
                alias_hint = ", ".join(aliases) if aliases else None
                scored.append((cmd, desc, 0.5, alias_hint))

        self._suggestions = scored[:self._max_visible]
        self._selected_idx = 0
        if self._suggestions:
            self.visible = True
            self._render()

    def hide(self) -> None:
        """Dismiss the completer."""
        self.visible = False
        self._suggestions = []
        self._selected_idx = 0
        self._mode = "command"
        try:
            self.update("")
        except Exception:
            pass

    def accept_top(self) -> Optional[str]:
        """Accept the currently selected suggestion.

        For command mode, returns the full command name.
        For arg mode, returns the arg text to append.
        Returns None if no suggestions.
        """
        if not self._suggestions:
            return None

        idx = self._selected_idx % len(self._suggestions)
        item = self._suggestions[idx][0]
        self.hide()
        return item

    def cycle_selection(self, direction: int = 1) -> None:
        """Cycle through suggestions (direction: 1=down, -1=up)."""
        if not self._suggestions:
            return
        n = len(self._suggestions)
        self._selected_idx = (self._selected_idx + direction) % n
        self._render()

    def _render(self) -> None:
        """Render the suggestion dropdown with selection highlight."""
        t = Theme.current()
        cyan = t.CYAN
        dim = t.TEXT_DIM
        accent = t.ACCENT
        sel_bg = t.HEADER_BG
        sel_border = t.BORDER

        if not self._suggestions:
            self.update("")
            return

        lines: List[str] = []
        query = ""
        if self._mode == "command":
            query = self._current_query.split()[0] if self._current_query else ""
        else:
            # For arg mode, use the last word as query for highlighting
            parts = self._current_query.split()
            query = parts[-1] if parts else ""

        for i, (cmd, desc, score, alias_hint) in enumerate(self._suggestions):
            is_selected = (i == self._selected_idx % len(self._suggestions))

            # Highlighted text
            highlighted = _highlight_match(cmd, query, cyan, dim)

            # Alias hint
            alias_str = ""
            if alias_hint:
                alias_str = f" [{dim}]({alias_hint})[/{dim}]"

            # Selection indicator with visual highlight
            if is_selected:
                indicator = f"[{cyan}]▸[/{cyan}]"
                line = f" {indicator} {highlighted}{alias_str}  [{dim}]{desc}[/{dim}]"
            else:
                indicator = f" [{dim}] [/{dim}]"
                line = f" {indicator} {highlighted}{alias_str}  [{dim}]{desc}[/{dim}]"

            lines.append(line)

        # Footer: keybinding hints + match quality
        if self._mode == "command":
            top_score = self._suggestions[0][2]
            if top_score < 0.6:
                footer = f"[{dim}]  Tab accept · ↑↓ navigate · Esc dismiss · fuzzy[{int(top_score * 100)}%][/{dim}]"
            else:
                footer = f"[{dim}]  Tab accept · ↑↓ navigate · Esc dismiss[/{dim}]"
        else:
            kind_label = self._mode.replace("arg_", "")
            footer = f"[{dim}]  Tab accept · ↑↓ navigate · {kind_label} completion[/{dim}]"
        lines.append(footer)

        content = "\n".join(lines)
        try:
            self.update(content)
        except Exception:
            pass

    def watch_visible(self, old: bool, new: bool) -> None:
        """Toggle CSS class for show/hide."""
        if new:
            self.set_class(True, "visible")
        else:
            self.set_class(False, "visible")
