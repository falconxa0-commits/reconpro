"""ReconPro v8.5 — Jira integration client.

Zero-dependency Jira Cloud REST API v3 client using only the Python stdlib.
Creates, updates, transitions, and syncs security findings as Jira issues.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Severity → Jira priority mapping
# ---------------------------------------------------------------------------
SEVERITY_PRIORITY: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

# Known Jira transition names we might use
_DONE_TRANSITIONS = {"done", "closed", "resolved"}


def _load_config(path: Path) -> dict[str, Any]:
    """Load a YAML or JSON config file.

    We first attempt to read the file as raw text and parse JSON.
    If that fails and PyYAML is somehow available we try yaml.safe_load.
    Otherwise we fall back to a minimal inline YAML-like parser that
    handles the flat key: value structure used for ReconPro configs.
    """
    text = path.read_text(encoding="utf-8")

    # Try JSON first (works for .json and also .yaml that happens to be JSON)
    try:
        return json.loads(text)  # type: ignore[return-value]
    except json.JSONDecodeError:
        pass

    # Minimal YAML parser for flat key: value pairs (no external deps)
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
    return Path.home() / ".reconpro" / "integrations" / "jira.yaml"


class JiraClient:
    """Minimal Jira Cloud REST v3 client for ReconPro finding sync."""

    def __init__(
        self,
        server_url: str = "",
        email: str = "",
        api_token: str = "",
        project_key: str = "",
    ) -> None:
        cfg_path = _default_config_path()
        cfg: dict[str, str] = {}

        if cfg_path.exists():
            cfg = _load_config(cfg_path)  # type: ignore[assignment]

        self.server_url = (server_url or cfg.get("server_url", "")).rstrip("/")
        self.email = email or cfg.get("email", "")
        self.api_token = api_token or cfg.get("api_token", "")
        self.project_key = project_key or cfg.get("project_key", "")

        if not all([self.server_url, self.email, self.api_token, self.project_key]):
            raise ValueError(
                "JiraClient requires server_url, email, api_token, and project_key. "
                f"Set them explicitly or in {cfg_path}"
            )

        credentials = f"{self.email}:{self.api_token}"
        self._auth_header = f"Basic {base64.b64encode(credentials.encode()).decode()}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> dict | list | bytes:
        url = f"{self.server_url}/rest/api/3{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._auth_header)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return json.loads(raw)  # type: ignore[return-value]
                return raw
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Jira API {method} {path} failed ({exc.code}): {error_body}"
            ) from exc

    def _build_description(self, description: str, findings: list[dict]) -> str:
        """Build Atlassian Document Format (ADF) description with optional findings table."""
        paragraphs: list[dict] = []

        # Main description paragraph
        paragraphs.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": description}],
        })

        if findings:
            # Spacer
            paragraphs.append({"type": "paragraph"})

            # Build table rows
            header_row = {
                "type": "tableRow",
                "cells": [
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Title"}]}]},
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Status"}]}]},
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Remediation"}]}]},
                ],
            }
            rows = [header_row]
            for f in findings:
                title = f.get("title", "Unknown")
                severity = f.get("severity", "medium")
                status = f.get("status", "open")
                remediation = f.get("remediation", "N/A")
                # Truncate long remediation text for table readability
                if len(remediation) > 120:
                    remediation = remediation[:117] + "..."
                cell_content = lambda t: [{"type": "paragraph", "content": [{"type": "text", "text": t}]}]  # noqa: E731
                rows.append({
                    "type": "tableRow",
                    "cells": [
                        {"type": "tableCell", "content": cell_content(title)},
                        {"type": "tableCell", "content": cell_content(severity)},
                        {"type": "tableCell", "content": cell_content(status)},
                        {"type": "tableCell", "content": cell_content(remediation)},
                    ],
                })

            paragraphs.append({
                "type": "table",
                "attrs": {"isNumbered": False, "layout": "default-width"},
                "content": rows,
            })

        return json.dumps({
            "type": "doc",
            "version": 1,
            "content": paragraphs,
        })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_issue(
        self,
        summary: str,
        description: str,
        severity: str = "medium",
        component: str = "",
        labels: list[str] | None = None,
        findings: list[dict] | None = None,
    ) -> dict:
        """Create a Jira issue from a security finding.

        Returns dict with keys: key, url, status.
        """
        labels = labels or []
        findings = findings or []
        priority = SEVERITY_PRIORITY.get(severity.lower(), "Medium")

        fields: dict[str, Any] = {
            "project": {"key": self.project_key},
            "summary": summary,
            "description": json.loads(self._build_description(description, findings)),
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": ["security", "reconpro"] + labels,
        }

        if component:
            fields["components"] = [{"name": component}]

        result = self._request("POST", "/issue", {"fields": fields})  # type: ignore[arg-type]
        key = result["key"]  # type: ignore[index]
        return {
            "key": key,
            "url": f"{self.server_url}/browse/{key}",
            "status": "created",
        }

    def update_issue(self, issue_key: str, status: str, comment: str = "") -> bool:
        """Transition an issue to a new status and optionally add a comment."""
        status_lower = status.lower().strip()

        # Fetch available transitions for the issue
        issue_data = self._request("GET", f"/issue/{issue_key}?fields=status,transitions")  # type: ignore[arg-type]
        transitions = issue_data["transitions"]  # type: ignore[index]

        target_id = None
        for t in transitions:
            tname = t["name"].lower()
            if tname == status_lower or tname in _DONE_TRANSITIONS and status_lower in _DONE_TRANSITIONS:
                target_id = t["id"]
                break

        if target_id is None:
            # Try partial match
            for t in transitions:
                if status_lower in t["name"].lower():
                    target_id = t["id"]
                    break

        if target_id is not None:
            self._request("PUT", f"/issue/{issue_key}/transitions", {
                "transition": {"id": target_id},
            })

        if comment:
            self._request("POST", f"/issue/{issue_key}/comment", {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment}],
                    }],
                },
            })

        return True

    def search_issues(self, jql: str, max_results: int = 50) -> list[dict]:
        """Search issues using JQL. Returns list of issue dicts."""
        params = urllib.parse.urlencode({
            "jql": jql,
            "maxResults": max_results,
        })
        result = self._request("GET", f"/search?{params}")  # type: ignore[arg-type]
        return result.get("issues", [])  # type: ignore[return-value]

    def sync_findings(self, findings: list[dict], target: str = "") -> list[dict]:
        """Sync security findings to Jira issues.

        For each critical/high finding, search for an existing Jira issue
        whose summary contains the finding title.  If none is found, create
        a new issue.  If a previously tracked issue no longer has a matching
        finding in the current scan, transition it to Done.

        Returns a list of action dicts:
            {action: 'created'|'updated'|'closed', key: str, finding_title: str}
        """
        results: list[dict] = []
        target_prefix = f"[{target}] " if target else ""

        # Collect only critical and high findings for sync
        actionable = [
            f for f in findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]

        # Track which Jira keys we match so we can close stale ones
        matched_keys: set[str] = set()

        for finding in actionable:
            title = finding.get("title", "Untitled Finding")
            summary_query = f'"{title}" AND project = {self.project_key}'
            existing = self.search_issues(summary_query, max_results=5)

            if existing:
                issue = existing[0]
                key = issue["key"]
                matched_keys.add(key)

                # Update with a comment noting the re-detection
                scan_info = finding.get("scan_date", "latest scan")
                comment = (
                    f"Finding re-detected in {target or 'scan'} on {scan_info}. "
                    f"Severity: {finding.get('severity', 'unknown')}."
                )
                self.update_issue(key, status="", comment=comment)
                results.append({
                    "action": "updated",
                    "key": key,
                    "finding_title": title,
                })
            else:
                # Create a new issue for this finding
                result = self.create_issue(
                    summary=f"{target_prefix}[Security] {title}",
                    description=finding.get("description", title),
                    severity=finding.get("severity", "high"),
                    labels=["auto-sync", f"target-{target}"] if target else ["auto-sync"],
                    findings=[finding],
                )
                matched_keys.add(result["key"])
                results.append({
                    "action": "created",
                    "key": result["key"],
                    "finding_title": title,
                })

        # Find previously synced issues that are no longer in the current scan
        sync_label = "auto-sync"
        if target:
            stale_jql = (
                f'project = {self.project_key} AND labels = {sync_label} '
                f'AND labels = target-{target} AND status != Done'
            )
        else:
            stale_jql = (
                f'project = {self.project_key} AND labels = {sync_label} AND status != Done'
            )
        stale_issues = self.search_issues(stale_jql, max_results=100)

        for issue in stale_issues:
            key = issue["key"]
            if key not in matched_keys:
                issue_summary = issue.get("fields", {}).get("summary", "")
                self.update_issue(
                    key,
                    status="Done",
                    comment=(
                        "Auto-closed by ReconPro sync: this finding was not present "
                        f"in the latest scan of {target or 'the target'}."
                    ),
                )
                results.append({
                    "action": "closed",
                    "key": key,
                    "finding_title": issue_summary,
                })

        return results

    def get_issue(self, issue_key: str) -> dict:
        """Retrieve a single issue by key."""
        return self._request("GET", f"/issue/{issue_key}")  # type: ignore[return-value]

    def add_comment(self, issue_key: str, comment: str) -> bool:
        """Add a comment to an existing issue."""
        self._request("POST", f"/issue/{issue_key}/comment", {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": comment}],
                }],
            },
        })
        return True

    def delete_issue(self, issue_key: str) -> bool:
        """Delete an issue by key. Use with caution."""
        self._request("DELETE", f"/issue/{issue_key}")  # type: ignore[arg-type]
        return True
