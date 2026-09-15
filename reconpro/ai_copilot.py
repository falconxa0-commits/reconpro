"""AI Copilot assistant for ReconPro.

Provides an interactive AI assistant interface that can chat, explain
findings, summarise reports, suggest remediations, and compare scans.
Gracefully degrades when API keys are unavailable by displaying an
informative message instead of crashing.

Classes:
    AICopilot: Conversational AI assistant with security-focused methods.
"""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

__all__ = ["AICopilot"]

_CONSOLE = Console()

# Environment variables checked for availability
_API_KEY_VARS = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "RECONPRO_AI_KEY"]


def _api_key_available() -> bool:
    """Return *True* if at least one known AI API key is set."""
    return any(os.environ.get(var) for var in _API_KEY_VARS)


class AICopilot:
    """AI-powered assistant for ReconPro security operations.

    Provides a conversational interface with security-aware methods.  When
    no API keys are configured, every method prints a graceful degradation
    message and returns a stub result — no exceptions raised.

    Usage::

        copilot = AICopilot()
        copilot.chat("What is SQL injection?")
        copilot.explain({"type": "sqli", "severity": "high"})
        copilot.summarize([{"finding": "open port 22"}])
        copilot.remediate({"type": "sqli"})
        copilot.compare(scan_a, scan_b)

    Args:
        console: Optional Rich console.
        model: Preferred model name (informational; used in stub output).
    """

    def __init__(
        self,
        console: Console | None = None,
        model: str = "reconpro-ai",
    ) -> None:
        self._console = console or _CONSOLE
        self._model = model
        self._available = _api_key_available()
        self._conversation_history: list[dict[str, str]] = []

    # -- internal helpers ----------------------------------------------------

    def _print_unavailable(self) -> None:
        """Print the graceful-degradation notice."""
        self._console.print(
            Panel(
                "[bold yellow]AI Copilot requires API keys.[/bold yellow]\n\n"
                "Set one of the following environment variables to enable:\n"
                "  • [cyan]OPENAI_API_KEY[/cyan]\n"
                "  • [cyan]ANTHROPIC_API_KEY[/cyan]\n"
                "  • [cyan]RECONPRO_AI_KEY[/cyan]\n\n"
                "Without an API key, Copilot operates in offline stub mode\n"
                "and returns placeholder responses.",
                title="🤖 AI Copilot",
                border_style="yellow",
            )
        )

    def _print_stub(self, method: str, context: str = "") -> str:
        """Print a stub response and return it."""
        self._print_unavailable()
        response = (
            f"[{method.upper()}] Offline stub response "
            f"(model={self._model}). {context}"
        )
        self._console.print(
            Panel(f"[dim]{response}[/dim]", title="Copilot Response",
                  border_style="dim")
        )
        return response

    def _print_available_banner(self) -> None:
        """Print a banner indicating API connectivity (for future use)."""
        self._console.print(
            Panel(
                "[bold green]🤖 AI Copilot is online[/bold green]\n"
                f"[dim]Model: {self._model}[/dim]",
                title="AI Copilot",
                border_style="green",
            )
        )

    # -- public methods ------------------------------------------------------

    def chat(self, message: str) -> str:
        """Send a chat message and receive a response.

        Args:
            message: The user's question or prompt.

        Returns:
            The assistant's response text.
        """
        self._conversation_history.append({"role": "user", "content": message})

        self._console.print(
            Panel(
                f"[bold cyan]You:[/bold cyan] {message}",
                title="💬 Chat",
                border_style="cyan",
            )
        )

        if not self._available:
            response = self._print_stub("chat", f"Query: {message[:60]}")
        else:
            # In a real implementation this would call the AI API.
            response = (
                f"[stub] AI response for: {message[:80]} "
                f"(model={self._model})"
            )
            self._print_available_banner()
            self._console.print(
                Panel(
                    Markdown(response),
                    title="🤖 Copilot",
                    border_style="green",
                )
            )

        self._conversation_history.append({"role": "assistant", "content": response})
        return response

    def explain(self, finding: dict[str, Any]) -> str:
        """Explain a security finding in natural language.

        Args:
            finding: A dict with at least ``type`` and optionally
                     ``severity``, ``description``, ``evidence``, etc.

        Returns:
            Explanation text.
        """
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "n/a")

        self._console.print(
            Panel(
                f"[bold]Finding:[/bold] {finding_type}  "
                f"[dim](severity: {severity})[/dim]",
                title="🔍 Explain",
                border_style="bright_blue",
            )
        )

        if not self._available:
            return self._print_stub("explain", f"Finding type: {finding_type}")
        else:
            response = (
                f"This is a {finding_type} finding with severity {severity}. "
                f"Explanation would be generated by the AI model."
            )
            self._console.print(
                Panel(Markdown(response), title="🤖 Explanation",
                      border_style="green")
            )
            return response

    def summarize(self, data: list[dict[str, Any]]) -> str:
        """Generate a human-readable summary of scan results or findings.

        Args:
            data: A list of dicts (e.g. scan results, findings).

        Returns:
            Summary text.
        """
        count = len(data)

        self._console.print(
            Panel(
                f"[bold]Summarizing {count} item(s)…[/bold]",
                title="📝 Summarize",
                border_style="bright_blue",
            )
        )

        if not self._available:
            return self._print_stub("summarize", f"Items: {count}")
        else:
            response = (
                f"Summary of {count} items. "
                f"Full AI summary would be generated by the model."
            )
            self._console.print(
                Panel(Markdown(response), title="🤖 Summary",
                      border_style="green")
            )
            return response

    def remediate(self, finding: dict[str, Any]) -> str:
        """Suggest remediation steps for a security finding.

        Args:
            finding: A dict describing the finding (must have ``type``).

        Returns:
            Remediation advice text.
        """
        finding_type = finding.get("type", "unknown")

        self._console.print(
            Panel(
                f"[bold]Remediation advice for:[/bold] {finding_type}",
                title="🛠️ Remediate",
                border_style="bright_blue",
            )
        )

        if not self._available:
            return self._print_stub("remediate", f"Finding type: {finding_type}")
        else:
            response = (
                f"Remediation steps for {finding_type}:\n"
                f"1. Identify the root cause\n"
                f"2. Apply the recommended fix\n"
                f"3. Re-scan to verify resolution"
            )
            self._console.print(
                Panel(Markdown(response), title="🤖 Remediation",
                      border_style="green")
            )
            return response

    def compare(
        self,
        scan_a: dict[str, Any],
        scan_b: dict[str, Any],
    ) -> str:
        """Compare two scan results and highlight differences.

        Args:
            scan_a: First scan result dict.
            scan_b: Second scan result dict.

        Returns:
            Comparison analysis text.
        """
        a_label = scan_a.get("label", scan_a.get("id", "Scan A"))
        b_label = scan_b.get("label", scan_b.get("id", "Scan B"))

        self._console.print(
            Panel(
                f"[bold]Comparing:[/bold] {a_label} [dim]vs[/dim] {b_label}",
                title="⚖️ Compare",
                border_style="bright_blue",
            )
        )

        if not self._available:
            return self._print_stub(
                "compare", f"{a_label} vs {b_label}"
            )
        else:
            response = (
                f"Comparison between {a_label} and {b_label}.\n"
                f"Detailed diff analysis would be generated by the AI model."
            )
            self._console.print(
                Panel(Markdown(response), title="🤖 Comparison",
                      border_style="green")
            )
            return response

    # -- dunder --------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """*True* if at least one API key is configured."""
        return self._available

    @property
    def conversation_length(self) -> int:
        """Number of messages in the conversation history."""
        return len(self._conversation_history)

    def __repr__(self) -> str:
        return (
            f"AICopilot(model={self._model!r}, "
            f"available={self._available}, "
            f"messages={len(self._conversation_history)})"
        )
