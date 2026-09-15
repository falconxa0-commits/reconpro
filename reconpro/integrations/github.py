"""ReconPro v8.5 — GitHub integration client.

Zero-dependency GitHub REST API client using only the Python stdlib.
Creates issues from findings, posts PR comments, sets commit statuses,
uploads SARIF for Code Scanning, and syncs findings.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# GitHub API base
GITHUB_API = "https://api.github.com"

# Severity → GitHub label mapping
SEVERITY_LABELS: dict[str, str] = {
    "critical": "security/critical",
    "high": "security/high",
    "medium": "security/medium",
    "low": "security/low",
    "info": "security/info",
}

# DREAD component labels for structured risk scoring
DREAD_LABELS = ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")


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
    return Path.home() / ".reconpro" / "integrations" / "github.yaml"


class GitHubClient:
    """Minimal GitHub REST API client for ReconPro finding sync."""

    def __init__(
        self,
        token: str = "",
        owner: str = "",
        repo: str = "",
    ) -> None:
        cfg_path = _default_config_path()
        cfg: dict[str, str] = {}

        if cfg_path.exists():
            cfg = _load_config(cfg_path)

        self.token = token or cfg.get("token", "")
        self.owner = owner or cfg.get("owner", "")
        self.repo = repo or cfg.get("repo", "")

        if not all([self.token, self.owner, self.repo]):
            raise ValueError(
                "GitHubClient requires token, owner, and repo. "
                f"Set them explicitly or in {cfg_path}"
            )

        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ReconPro/8.5",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict | list | bytes:
        url = f"{GITHUB_API}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)

        headers = dict(self._headers)
        if extra_headers:
            headers.update(extra_headers)
        if data is not None:
            headers["Content-Type"] = "application/json"

        for key, value in headers.items():
            req.add_header(key, value)

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
                f"GitHub API {method} {path} failed ({exc.code}): {error_body}"
            ) from exc

    def _repo_path(self) -> str:
        return f"/repos/{self.owner}/{self.repo}"

    def _ensure_labels(self, labels: list[str]) -> list[str]:
        """Ensure that all required labels exist in the repo, creating missing ones."""
        existing_result = self._request("GET", f"{self._repo_path()}/labels?per_page=100")
        existing_names: set[str] = set()
        if isinstance(existing_result, list):
            for lbl in existing_result:
                existing_names.add(lbl.get("name", ""))

        for label in labels:
            if label not in existing_names:
                # Determine colour from label name
                if "critical" in label:
                    colour = "b60205"
                elif "high" in label:
                    colour = "d93f0b"
                elif "medium" in label:
                    colour = "fbca04"
                elif "low" in label:
                    colour = "0e8a16"
                else:
                    colour = "1d76db"

                try:
                    self._request("POST", f"{self._repo_path()}/labels", {
                        "name": label,
                        "color": colour,
                        "description": f"Auto-created by ReconPro v8.5",
                    })
                    existing_names.add(label)
                except RuntimeError:
                    # Label might already exist with different casing, ignore
                    pass

        return labels

    # ------------------------------------------------------------------
    # Public API — Issues
    # ------------------------------------------------------------------

    def create_issue(
        self,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict:
        """Create a GitHub issue.

        Returns dict with keys: number, url, html_url.
        """
        labels = labels or []
        # Ensure labels exist before creating the issue
        self._ensure_labels(labels)

        payload: dict[str, Any] = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        result = self._request("POST", f"{self._repo_path()}/issues", payload)  # type: ignore[arg-type]
        return {
            "number": result["number"],  # type: ignore[index]
            "url": result["url"],  # type: ignore[index]
            "html_url": result["html_url"],  # type: ignore[index]
        }

    def create_issue_from_finding(self, finding: dict) -> dict:
        """Create a GitHub issue from a ReconPro finding dict.

        Maps severity to labels and includes description, evidence,
        remediation, and DREAD score in the issue body.
        """
        title = finding.get("title", "Untitled Security Finding")
        severity = finding.get("severity", "medium").lower()
        description = finding.get("description", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        target = finding.get("target", "")
        cve = finding.get("cve", "")
        cvss_score = finding.get("cvss_score", "")
        dread = finding.get("dread", {})

        # Build labels
        labels = ["security", "reconpro", "auto-sync"]
        sev_label = SEVERITY_LABELS.get(severity)
        if sev_label:
            labels.append(sev_label)
        if target:
            # Sanitize target for label use (GitHub labels: max 50 chars, lowercase)
            safe_target = target.replace("https://", "").replace("http://", "").replace("/", "-")[:50].lower()
            labels.append(f"target:{safe_target}")

        # Build issue body
        parts: list[str] = []

        if cve:
            parts.append(f"**CVE:** {cve}")
        if cvss_score:
            parts.append(f"**CVSS Score:** {cvss_score}")
        if target:
            parts.append(f"**Target:** {target}")
        parts.append(f"**Severity:** {severity}")
        parts.append("")

        if description:
            parts.append("## Description")
            parts.append(description)
            parts.append("")

        if evidence:
            parts.append("## Evidence")
            parts.append("")
            parts.append("```")
            parts.append(str(evidence)[:2000])
            parts.append("```")
            parts.append("")

        if remediation:
            parts.append("## Remediation")
            parts.append(remediation)
            parts.append("")

        if dread:
            parts.append("## DREAD Score")
            parts.append("")
            parts.append("| Component | Score |")
            parts.append("|-----------|-------|")
            total = 0
            for component in DREAD_LABELS:
                score = dread.get(component, 0)
                total += score
                parts.append(f"| {component.capitalize()} | {score}/10 |")
            avg = total / len(DREAD_LABELS) if DREAD_LABELS else 0
            parts.append(f"| **Average** | **{avg:.1f}/10** |")
            parts.append("")

        parts.append("---")
        parts.append("_Created automatically by ReconPro v8.5_")

        body = "\n".join(parts)

        prefixed_title = f"[Security] {title}"
        return self.create_issue(title=prefixed_title, body=body, labels=labels)

    def close_issue(self, issue_number: int, comment: str = "") -> bool:
        """Close (not delete) a GitHub issue."""
        self._request("PATCH", f"{self._repo_path()}/issues/{issue_number}", {
            "state": "closed",
        })
        if comment:
            self.post_issue_comment(issue_number, comment)
        return True

    def post_issue_comment(self, issue_number: int, body: str) -> bool:
        """Post a comment on a GitHub issue."""
        self._request("POST", f"{self._repo_path()}/issues/{issue_number}/comments", {
            "body": body,
        })
        return True

    # ------------------------------------------------------------------
    # Public API — Pull Requests
    # ------------------------------------------------------------------

    def post_pr_comment(self, pr_number: int, body: str) -> bool:
        """Post a comment on a pull request."""
        self._request("POST", f"{self._repo_path()}/pulls/{pr_number}/comments", {
            "body": body,
        })
        return True

    def create_commit_status(
        self,
        sha: str,
        state: str,
        description: str = "",
        target_url: str = "",
        context: str = "reconpro/security-scan",
    ) -> bool:
        """Set a commit status (state: 'success', 'failure', 'pending', 'error')."""
        if state not in ("success", "failure", "pending", "error"):
            raise ValueError(f"Invalid commit status state: {state!r}")

        payload: dict[str, str] = {
            "state": state,
            "description": description,
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url

        self._request("POST", f"{self._repo_path()}/statuses/{sha}", payload)  # type: ignore[arg-type]
        return True

    # ------------------------------------------------------------------
    # Public API — Code Scanning (SARIF)
    # ------------------------------------------------------------------

    def upload_sarif(self, sarif_data: str | dict | bytes) -> bool:
        """Upload a SARIF file for GitHub Code Scanning.

        Uses the SARIF upload endpoint which accepts a JSON payload with
        a base64-encoded commit_oid and the SARIF content.

        Args:
            sarif_data: SARIF JSON as a string, dict, or raw bytes.

        Returns:
            True if the upload was accepted.
        """
        import base64

        if isinstance(sarif_data, dict):
            sarif_json = json.dumps(sarif_data)
        elif isinstance(sarif_data, bytes):
            sarif_json = sarif_data.decode("utf-8", errors="replace")
        else:
            sarif_json = sarif_data

        sarif_bytes = sarif_json.encode("utf-8")

        # Get the default branch to derive a commit SHA for the upload
        repo_info = self._request("GET", self._repo_path())  # type: ignore[arg-type]
        default_branch = repo_info.get("default_branch", "main")  # type: ignore[index]

        try:
            ref_result = self._request("GET", f"{self._repo_path()}/git/ref/heads/{default_branch}")  # type: ignore[arg-type]
            commit_sha = ref_result["object"]["sha"]  # type: ignore[index]
        except (RuntimeError, KeyError, TypeError):
            commit_sha = ""  # GitHub will use the default branch

        # The SARIF upload endpoint
        url = f"{GITHUB_API}{self._repo_path()}/code-scanning/sarifs"
        payload = json.dumps({
            "commit_oid": commit_sha,
            "ref": f"refs/heads/{default_branch}",
            "sarif": sarif_json,
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, method="PUT")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "ReconPro/8.5")

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status < 400  # type: ignore[attr-defined]
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub SARIF upload failed ({exc.code}): {error_body}"
            ) from exc

    # ------------------------------------------------------------------
    # Public API — Sync
    # ------------------------------------------------------------------

    def list_open_security_issues(self) -> list[dict]:
        """List all open issues with security labels."""
        params = urllib.parse.urlencode({
            "labels": "security",
            "state": "open",
            "per_page": 100,
        })
        result = self._request("GET", f"{self._repo_path()}/issues?{params}")  # type: ignore[arg-type]
        if isinstance(result, list):
            return result
        return []

    def sync_findings(self, findings: list[dict]) -> list[dict]:
        """Sync security findings to GitHub issues.

        - Creates issues for new critical/high findings.
        - Closes issues whose findings are no longer present.

        Returns a list of action dicts:
            {action: 'created'|'closed', number: int, finding_title: str}
        """
        results: list[dict] = []

        # Separate actionable findings from the full list
        actionable = [
            f for f in findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        actionable_titles = {f.get("title", "").lower() for f in actionable}

        # Get existing open security issues
        existing_issues = self.list_open_security_issues()

        # Track which existing issues we still see in the current scan
        matched_numbers: set[int] = set()

        for finding in actionable:
            title = finding.get("title", "Untitled Finding")

            # Check if an issue with this title already exists
            found_issue = None
            for issue in existing_issues:
                issue_title = issue.get("title", "")
                # Match if the issue title contains the finding title (case-insensitive)
                if title.lower() in issue_title.lower():
                    found_issue = issue
                    break

            if found_issue:
                # Issue already exists — add a comment noting re-detection
                number = found_issue["number"]
                matched_numbers.add(number)
                scan_date = finding.get("scan_date", "latest scan")
                self.post_issue_comment(
                    number,
                    f"🔍 **Re-detected** in scan on {scan_date}. "
                    f"Severity: {finding.get('severity', 'unknown')}.",
                )
                results.append({
                    "action": "updated",
                    "number": number,
                    "finding_title": title,
                })
            else:
                # Create a new issue
                result = self.create_issue_from_finding(finding)
                matched_numbers.add(result["number"])
                results.append({
                    "action": "created",
                    "number": result["number"],
                    "finding_title": title,
                })

        # Close issues for findings that are no longer present
        for issue in existing_issues:
            number = issue["number"]
            if number in matched_numbers:
                continue

            issue_title = issue.get("title", "")
            # Check if this issue's title matches any finding we know about
            still_present = False
            for finding in actionable:
                if finding.get("title", "").lower() in issue_title.lower():
                    still_present = True
                    break

            if not still_present:
                self.close_issue(
                    number,
                    comment=(
                        "🟢 **Auto-closed by ReconPro sync:** this finding was not "
                        "present in the latest scan."
                    ),
                )
                results.append({
                    "action": "closed",
                    "number": number,
                    "finding_title": issue_title,
                })

        return results

    def get_issue(self, issue_number: int) -> dict:
        """Retrieve a single issue by number."""
        return self._request("GET", f"{self._repo_path()}/issues/{issue_number}")  # type: ignore[return-value]

    def search_issues(self, query: str) -> list[dict]:
        """Search issues using GitHub's search API.

        The query is automatically scoped to the configured repo.
        """
        repo_query = f"{query} repo:{self.owner}/{self.repo}"
        params = urllib.parse.urlencode({"q": repo_query, "per_page": 50})
        result = self._request("GET", f"/search/issues?{params}")  # type: ignore[arg-type]
        if isinstance(result, dict):
            return result.get("items", [])  # type: ignore[return-value]
        return []
