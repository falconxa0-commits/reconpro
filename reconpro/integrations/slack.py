"""ReconPro v11.1.0 — Slack integration client.

Zero-dependency Slack Webhook & Block Kit client using only the Python stdlib.
Sends finding alerts, scan summaries, and daily digests to Slack channels.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Severity → Slack accent colour mapping
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#E01E5A",
    "high":     "#EB3630",
    "medium":   "#F2C744",
    "low":      "#46A89A",
    "info":     "#697689",
}

SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🚨",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️",
}


def _load_config(path: Path) -> dict[str, str]:
    """Load config from YAML or JSON (no external deps)."""
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)  # type: ignore[return-value]
    except json.JSONDecodeError:
        pass
    # Minimal YAML parser for flat key: value
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            data[key] = value
    return data


def _default_config_path() -> Path:
    return Path.home() / ".reconpro" / "integrations" / "slack.yaml"


class SlackClient:
    """Minimal Slack client for ReconPro notifications."""

    def __init__(self, webhook_url: str = "", bot_token: str | None = None) -> None:
        cfg_path = _default_config_path()
        cfg: dict[str, str] = {}

        if cfg_path.exists():
            cfg = _load_config(cfg_path)

        self.webhook_url = webhook_url or cfg.get("webhook_url", "")
        self.bot_token = bot_token or cfg.get("bot_token")

        if not self.webhook_url:
            raise ValueError(
                f"SlackClient requires a webhook_url. "
                f"Set it explicitly or in {cfg_path}"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, payload: dict) -> bool:
        """POST a JSON payload to the configured webhook URL."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return "ok" in body.lower()
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Slack webhook failed ({exc.code}): {error_body}"
            ) from exc

    @staticmethod
    def _truncate(text: str, max_len: int = 3000) -> str:
        """Truncate text for Slack's 3001-char block text limit."""
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    @staticmethod
    def _markdown_to_mrkdwn(text: str) -> str:
        """Best-effort conversion of basic Markdown to Slack mrkdwn."""
        # Convert ### → *bold*
        for prefix in ("### ", "## ", "# "):
            text = text.replace(prefix, "*")
        # Convert **text** → *text* (bold)
        import re
        text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text)
        # Convert `code` → `code` (already compatible)
        return text

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_message(
        self,
        channel: str = "",
        text: str = "",
        blocks: list[dict] | None = None,
    ) -> bool:
        """Send a message to a Slack channel via webhook.

        Args:
            channel: Optional channel override (e.g. "#security-alerts").
                    If empty, uses the webhook's default channel.
            text: Fallback plain-text shown in notifications.
            blocks: Optional list of Slack Block Kit blocks for rich layout.

        Returns:
            True if the message was accepted by Slack.
        """
        payload: dict[str, Any] = {"text": text or "(no content)"}
        if channel:
            payload["channel"] = channel
        if blocks:
            payload["blocks"] = blocks
        return self._post(payload)

    def send_finding_alert(self, finding: dict) -> bool:
        """Send a richly-formatted finding alert using Slack Blocks.

        The alert includes a header with severity emoji, the finding title,
        description, remediation guidance, and a context row with metadata.
        """
        severity = finding.get("severity", "medium").lower()
        title = finding.get("title", "Untitled Finding")
        description = finding.get("description", "No description provided.")
        remediation = finding.get("remediation", "See full report for details.")
        target = finding.get("target", "")
        cve = finding.get("cve", "")
        cvss = finding.get("cvss_score", "")
        emoji = SEVERITY_EMOJI.get(severity, "⚠️")
        color = SEVERITY_COLORS.get(severity, "")

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity.upper()}: {title}",
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": self._truncate(self._markdown_to_mrkdwn(description)),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation:*\n{self._truncate(self._markdown_to_mrkdwn(remediation), 1000)}",
                },
            },
        ]

        # Context row with metadata
        context_elements: list[dict] = []
        if target:
            context_elements.append({"type": "mrkdwn", "text": f"*Target:* {target}"})
        if cve:
            context_elements.append({"type": "mrkdwn", "text": f"*CVE:* {cve}"})
        if cvss:
            context_elements.append({"type": "mrkdwn", "text": f"*CVSS:* {cvss}"})
        context_elements.append({
            "type": "mrkdwn",
            "text": f"*Severity:* {severity}",
        })
        if context_elements:
            blocks.append({
                "type": "context",
                "elements": context_elements,
            })

        # Action button placeholder (Slack requires a valid action_id)
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Details", "emoji": True},
                    "url": finding.get("url", "https://reconpro.local"),
                    "action_id": "view_finding_details",
                },
            ],
        })

        fallback = f"{emoji} [{severity.upper()}] {title} — {target}"
        return self.send_message(text=fallback, blocks=blocks)

    def send_scan_summary(self, scan_data: dict) -> bool:
        """Send a scan summary with score, grade, severity counts, and top findings."""
        target = scan_data.get("target", "Unknown")
        score = scan_data.get("score", 0)
        grade = scan_data.get("grade", "?")
        total = scan_data.get("total_findings", 0)
        severity_counts = scan_data.get("severity_counts", {})
        top_findings = scan_data.get("top_findings", [])
        scan_date = scan_data.get("scan_date", "")
        duration = scan_data.get("duration", "")

        # Determine overall emoji
        if grade in ("A", "B"):
            grade_emoji = "✅"
        elif grade == "C":
            grade_emoji = "⚠️"
        else:
            grade_emoji = "🚨"

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 Scan Complete: {target}",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]

        # Score & grade section
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{grade_emoji} *Score:* {score}/100  |  *Grade:* {grade}  |  "
                    f"*Findings:* {total}"
                ),
            },
        })

        # Severity breakdown
        sev_parts: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(sev, 0)
            if count:
                sev_parts.append(f"{SEVERITY_EMOJI.get(sev, '')} {sev}: {count}")
        if sev_parts:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Severity Breakdown:*\n" + "  • ".join(sev_parts),
                },
            })

        # Top findings
        if top_findings:
            finding_lines: list[str] = []
            for i, f in enumerate(top_findings[:5], 1):
                f_sev = f.get("severity", "?").lower()
                f_title = f.get("title", "Unknown")
                finding_lines.append(
                    f"{i}. {SEVERITY_EMOJI.get(f_sev, '')} *{f_title}* ({f_sev})"
                )
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Findings:*\n" + "\n".join(finding_lines),
                },
            })

        # Context with date & duration
        context_els: list[dict] = []
        if scan_date:
            context_els.append({"type": "mrkdwn", "text": f"*Date:* {scan_date}"})
        if duration:
            context_els.append({"type": "mrkdwn", "text": f"*Duration:* {duration}"})
        if context_els:
            blocks.append({"type": "context", "elements": context_els})

        fallback = f"Scan of {target}: score {score}, grade {grade}, {total} findings"
        return self.send_message(text=fallback, blocks=blocks)

    def send_daily_digest(self, findings_by_target: dict[str, list[dict]]) -> bool:
        """Send an aggregated daily digest across all targets scanned today.

        Args:
            findings_by_target: Mapping of target name → list of finding dicts.
        """
        from datetime import datetime, timezone

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        total_targets = len(findings_by_target)
        total_findings = sum(len(f) for f in findings_by_target.values())

        # Aggregate severity counts across all targets
        global_sev: dict[str, int] = {}
        for _target, findings in findings_by_target.items():
            for f in findings:
                sev = f.get("severity", "info").lower()
                global_sev[sev] = global_sev.get(sev, 0) + 1

        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 ReconPro Daily Digest — {today}",
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Targets Scanned:* {total_targets}  |  "
                        f"*Total Findings:* {total_findings}"
                    ),
                },
            },
        ]

        # Global severity summary
        sev_parts: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = global_sev.get(sev, 0)
            if count:
                sev_parts.append(f"{SEVERITY_EMOJI.get(sev, '')} {sev}: {count}")
        if sev_parts:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Overall Severity:* " + "  • ".join(sev_parts),
                },
            })

        # Per-target breakdown
        for target_name, findings in findings_by_target.items():
            crit = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
            high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
            med  = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
            low  = sum(1 for f in findings if f.get("severity", "").lower() == "low")

            # Top finding for this target
            top = ""
            if findings:
                sorted_f = sorted(
                    findings,
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        x.get("severity", "info").lower(), 5
                    ),
                )
                top = sorted_f[0].get("title", "")

            block_text = (
                f"*{target_name}*\n"
                f"  🚨 {crit} critical  🔴 {high} high  🟡 {med} medium  🟢 {low} low"
            )
            if top:
                block_text += f"\n  *Top:* {top}"

            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": block_text},
            })

        # Footer context
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"_Generated by ReconPro v11.1.0 on {today}_",
                },
            ],
        })

        fallback = f"Daily Digest ({today}): {total_targets} targets, {total_findings} findings"
        return self.send_message(text=fallback, blocks=blocks)
