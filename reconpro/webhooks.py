"""VCS Webhook Listeners for ReconPro v11.1.0.

Receives GitHub and GitLab webhooks, triggers scans on changed files,
and posts results as PR/MR comments or commit statuses.

Endpoints:
  POST /webhook/github   — GitHub push / pull_request events
  POST /webhook/gitlab   — GitLab push / merge_request events
  GET  /webhook/config   — List active webhook configurations

Config stored at ~/.reconpro/config/webhooks.json
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from pathlib import Path

_CONFIG_DIR = Path.home() / ".reconpro" / "config"
_CONFIG_FILE = _CONFIG_DIR / "webhooks.json"


# ── Config helpers ─────────────────────────────────────────────────────


def _load_config() -> Dict[str, Any]:
    """Load webhook configuration from disk."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(cfg: Dict[str, Any]) -> None:
    """Persist webhook configuration to disk."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _get_secret(provider: str) -> str:
    """Get webhook secret for a provider from config."""
    cfg = _load_config()
    return cfg.get(provider, {}).get("secret", "")


def _get_api_token(provider: str) -> str:
    """Get API token for posting comments/statuses."""
    cfg = _load_config()
    return cfg.get(provider, {}).get("api_token", "")


def _post_pr_comment(
    provider: str,
    repo_full: str,
    pr_number: int,
    body: str,
) -> bool:
    """Post a comment on a PR/MR using the provider's API.

    Uses only stdlib urllib. Returns True on success.
    """
    token = _get_api_token(provider)
    if not token:
        return False

    try:
        import urllib.request
        import urllib.error

        if provider == "github":
            url = (
                f"https://api.github.com/repos/{repo_full}"
                f"/issues/{pr_number}/comments"
            )
            payload = json.dumps({"body": body}).encode()
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "Content-Type": "application/json",
                    "User-Agent": "ReconPro-Webhook/11.1.0",
                },
            )
        elif provider == "gitlab":
            url = (
                f"https://gitlab.com/api/v4/projects"
                f"/{repo_full.replace('/', '%2F')}/merge_requests"
                f"/{pr_number}/notes"
            )
            payload = json.dumps({"body": body}).encode()
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={
                    "PRIVATE-TOKEN": token,
                    "Content-Type": "application/json",
                },
            )
        else:
            return False

        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception:
        return False


def _set_commit_status(
    repo_full: str,
    sha: str,
    state: str,
    description: str,
    target_url: str = "",
) -> bool:
    """Set a GitHub commit status via the API."""
    token = _get_api_token("github")
    if not token:
        return False
    try:
        import urllib.request

        url = (
            f"https://api.github.com/repos/{repo_full}"
            f"/statuses/{sha}"
        )
        payload = json.dumps({
            "state": state,
            "description": description,
            "target_url": target_url,
            "context": "reconpro/security-scan",
        }).encode()
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "User-Agent": "ReconPro-Webhook/11.1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status in (200, 201)
    except Exception:
        return False


# ── GitHub Webhook Handler ──────────────────────────────────────────────


class GitHubWebhookHandler:
    """Parse and handle GitHub webhook events."""

    @staticmethod
    def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
        """Verify HMAC-SHA256 signature of a GitHub webhook payload.

        Args:
            payload: Raw request body bytes.
            signature: Value of X-Hub-Signature-256 header (sha256=...).
            secret: Webhook secret configured in GitHub.

        Returns:
            True if the signature is valid.
        """
        if not secret or not signature:
            return False
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(f"sha256={expected}", signature)

    @staticmethod
    def parse_event(headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        """Extract structured event data from GitHub webhook headers + body.

        Returns dict with keys: event_type, action, repo, branch,
        changed_files, sha, pr_number, sender.
        """
        event_type = headers.get("X-GitHub-Event", "unknown")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"event_type": event_type, "error": "invalid JSON body"}

        repo_data = data.get("repository", {})
        repo_full = repo_data.get("full_name", "")

        result: Dict[str, Any] = {
            "event_type": event_type,
            "action": data.get("action", ""),
            "repo": repo_full,
            "branch": "",
            "changed_files": [],
            "sha": "",
            "pr_number": None,
            "sender": data.get("sender", {}).get("login", ""),
            "raw": data,
        }

        if event_type == "pull_request":
            pr = data.get("pull_request", {})
            result["branch"] = pr.get("head", {}).get("ref", "")
            result["sha"] = pr.get("head", {}).get("sha", "")
            result["pr_number"] = pr.get("number")
            # Collect changed files from the PR (if included in webhook)
            for f in pr.get("changed_files", []):
                result["changed_files"].append(f if isinstance(f, str) else f.get("filename", ""))
            # Also check additions/deletions lists
            if not result["changed_files"]:
                for key in ("added_files", "modified_files", "removed_files"):
                    for f in pr.get(key, []):
                        name = f if isinstance(f, str) else f.get("filename", "")
                        if name and name not in result["changed_files"]:
                            result["changed_files"].append(name)

        elif event_type == "push":
            result["branch"] = data.get("ref", "").replace("refs/heads/", "")
            result["sha"] = data.get("after", "")
            for commit in data.get("commits", []):
                for f in commit.get("added", []) + commit.get("modified", []) + commit.get("removed", []):
                    if f not in result["changed_files"]:
                        result["changed_files"].append(f)

        return result

    @staticmethod
    def handle_pull_request(event: Dict[str, Any]) -> Dict[str, Any]:
        """Determine scan scope for a pull_request event.

        Returns dict with: scan_type, files, target, repo, pr_number, sha.
        scan_type is 'incremental' (only changed files) or 'full'.
        """
        action = event.get("action", "")
        pr_number = event.get("pr_number")
        repo = event.get("repo", "")
        changed_files = event.get("changed_files", [])
        sha = event.get("sha", "")
        branch = event.get("branch", "")

        # Only scan on opened, synchronize, or reopened
        scan_actions = {"opened", "synchronize", "reopened"}
        if action not in scan_actions:
            return {
                "scan_type": "skip",
                "reason": f"Action '{action}' does not trigger a scan",
                "repo": repo,
                "pr_number": pr_number,
            }

        if changed_files:
            scan_type = "incremental"
        else:
            scan_type = "full"

        return {
            "scan_type": scan_type,
            "files": changed_files if scan_type == "incremental" else [],
            "target": repo,
            "repo": repo,
            "pr_number": pr_number,
            "sha": sha,
            "branch": branch,
        }

    @staticmethod
    def handle_push(event: Dict[str, Any]) -> Dict[str, Any]:
        """Determine scan scope for a push event.

        Full scan on push to main/master, incremental on other branches.
        """
        branch = event.get("branch", "")
        repo = event.get("repo", "")
        changed_files = event.get("changed_files", [])
        sha = event.get("sha", "")

        main_branches = {"main", "master"}

        if branch in main_branches:
            return {
                "scan_type": "full",
                "files": [],
                "target": repo,
                "repo": repo,
                "pr_number": None,
                "sha": sha,
                "branch": branch,
            }

        if changed_files:
            return {
                "scan_type": "incremental",
                "files": changed_files,
                "target": repo,
                "repo": repo,
                "pr_number": None,
                "sha": sha,
                "branch": branch,
            }

        return {
            "scan_type": "skip",
            "reason": "No changed files on non-main branch",
            "repo": repo,
            "pr_number": None,
        }

    @staticmethod
    def generate_status(event: Dict[str, Any], scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a GitHub commit status dict from a scan result.

        Returns dict with: state (pending/success/failure/error),
        description, target_url, context.
        """
        grade = scan_result.get("grade", "N/A")
        score = scan_result.get("total_score", 0)
        sev = scan_result.get("severity_counts", {})
        critical_count = sev.get("critical", 0)
        high_count = sev.get("high", 0)

        if critical_count > 0:
            state = "failure"
            description = f"ReconPro: {grade} ({score}/100) — {critical_count} critical, {high_count} high"
        elif high_count > 0:
            state = "failure"
            description = f"ReconPro: {grade} ({score}/100) — {high_count} high findings"
        elif score >= 80:
            state = "success"
            description = f"ReconPro: {grade} ({score}/100) — No critical/high findings"
        else:
            state = "failure"
            description = f"ReconPro: {grade} ({score}/100) — Score below threshold"

        return {
            "state": state,
            "description": description,
            "target_url": "",
            "context": "reconpro/security-scan",
            "sha": event.get("sha", ""),
            "repo": event.get("repo", ""),
        }


# ── GitLab Webhook Handler ──────────────────────────────────────────────


class GitLabWebhookHandler:
    """Parse and handle GitLab webhook events."""

    @staticmethod
    def verify_token(headers: Dict[str, str], secret: str) -> bool:
        """Verify the X-Gitlab-Token header against the configured secret.

        GitLab uses a simple static token (not HMAC).
        """
        if not secret:
            return True  # No secret configured — allow
        token = headers.get("X-Gitlab-Token", "")
        return hmac.compare_digest(token, secret)

    @staticmethod
    def parse_event(headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        """Extract structured event data from GitLab webhook headers + body.

        Returns dict with: event_type, action, repo, branch,
        changed_files, sha, mr_iid, sender.
        """
        event_type = headers.get("X-Gitlab-Event", "unknown")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"event_type": event_type, "error": "invalid JSON body"}

        project = data.get("project", {})
        repo_path = project.get("path_with_namespace", "")

        result: Dict[str, Any] = {
            "event_type": event_type,
            "action": data.get("object_attributes", {}).get("action", ""),
            "repo": repo_path,
            "branch": "",
            "changed_files": [],
            "sha": "",
            "mr_iid": None,
            "sender": data.get("user", {}).get("username", ""),
            "raw": data,
        }

        attrs = data.get("object_attributes", {})

        if event_type == "Merge Request Hook":
            result["branch"] = attrs.get("source_branch", "")
            result["sha"] = attrs.get("last_commit", {}).get("id", "")
            result["mr_iid"] = attrs.get("iid")
            # Collect changed files
            for key in ("added_files", "modified_files", "removed_files"):
                for f in attrs.get(key, []):
                    if isinstance(f, dict):
                        name = f.get("filename", "") or f.get("old_path", "")
                    else:
                        name = str(f)
                    if name and name not in result["changed_files"]:
                        result["changed_files"].append(name)

        elif event_type == "Push Hook":
            result["branch"] = attrs.get("ref", "").replace("refs/heads/", "")
            result["sha"] = attrs.get("after", "")
            for commit in data.get("commits", []):
                for f in commit.get("added", []) + commit.get("modified", []) + commit.get("removed", []):
                    if f not in result["changed_files"]:
                        result["changed_files"].append(f)

        return result

    @staticmethod
    def handle_merge_request(event: Dict[str, Any]) -> Dict[str, Any]:
        """Determine scan scope for a GitLab merge request event.

        Returns dict with: scan_type, files, target, repo, mr_iid, sha.
        """
        action = event.get("action", "")
        mr_iid = event.get("mr_iid")
        repo = event.get("repo", "")
        changed_files = event.get("changed_files", [])
        sha = event.get("sha", "")
        branch = event.get("branch", "")

        scan_actions = {"open", "update", "reopen"}
        if action not in scan_actions:
            return {
                "scan_type": "skip",
                "reason": f"Action '{action}' does not trigger a scan",
                "repo": repo,
                "mr_iid": mr_iid,
            }

        if changed_files:
            scan_type = "incremental"
        else:
            scan_type = "full"

        return {
            "scan_type": scan_type,
            "files": changed_files if scan_type == "incremental" else [],
            "target": repo,
            "repo": repo,
            "mr_iid": mr_iid,
            "sha": sha,
            "branch": branch,
        }


# ── Webhook HTTP Server ─────────────────────────────────────────────────


class _WebhookRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the webhook server."""

    _gh_handler = GitHubWebhookHandler()
    _gl_handler = GitLabWebhookHandler()

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr logging."""
        pass

    def _json_response(self, code: int, data: Any) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _headers_dict(self) -> Dict[str, str]:
        return {k: v for k, v in self.headers.items()}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/webhook/config":
            cfg = _load_config()
            # Redact secrets from response
            safe = {}
            for provider, settings in cfg.items():
                safe[provider] = {
                    k: ("***" if "secret" in k.lower() or "token" in k.lower() else v)
                    for k, v in settings.items()
                }
                safe[provider]["secret_set"] = bool(settings.get("secret"))
                safe[provider]["token_set"] = bool(settings.get("api_token"))
            self._json_response(200, {"config": safe})
            return

        self._json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        body = self._read_body()
        hdrs = self._headers_dict()

        try:
            if path == "/webhook/github":
                self._handle_github(hdrs, body)
            elif path == "/webhook/gitlab":
                self._handle_gitlab(hdrs, body)
            else:
                self._json_response(404, {"error": "Not found"})
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Hub-Signature-256, X-Gitlab-Token")
        self.end_headers()

    # ── GitHub route ────────────────────────────────────────────────

    def _handle_github(self, hdrs: Dict[str, str], body: bytes) -> None:
        secret = _get_secret("github")
        sig = hdrs.get("X-Hub-Signature-256", "")

        if secret and not GitHubWebhookHandler.verify_signature(body, sig, secret):
            self._json_response(401, {"error": "Invalid signature"})
            return

        event = GitHubWebhookHandler.parse_event(hdrs, body)
        event_type = event.get("event_type", "unknown")

        if event_type == "pull_request":
            scope = GitHubWebhookHandler.handle_pull_request(event)
            self._execute_scan_and_respond("github", event, scope)
        elif event_type == "push":
            scope = GitHubWebhookHandler.handle_push(event)
            self._execute_scan_and_respond("github", event, scope)
        else:
            self._json_response(200, {
                "status": "ignored",
                "event_type": event_type,
                "reason": "Unsupported event type",
            })

    # ── GitLab route ────────────────────────────────────────────────

    def _handle_gitlab(self, hdrs: Dict[str, str], body: bytes) -> None:
        secret = _get_secret("gitlab")

        if secret and not GitLabWebhookHandler.verify_token(hdrs, secret):
            self._json_response(401, {"error": "Invalid token"})
            return

        event = GitLabWebhookHandler.parse_event(hdrs, body)
        event_type = event.get("event_type", "unknown")

        if event_type == "Merge Request Hook":
            scope = GitLabWebhookHandler.handle_merge_request(event)
            self._execute_scan_and_respond("gitlab", event, scope)
        elif event_type == "Push Hook":
            # Reuse GitHub push logic (structurally identical)
            scope = GitHubWebhookHandler.handle_push(event)
            self._execute_scan_and_respond("gitlab", event, scope)
        else:
            self._json_response(200, {
                "status": "ignored",
                "event_type": event_type,
                "reason": "Unsupported event type",
            })

    # ── Scan execution + comment posting ────────────────────────────

    def _execute_scan_and_respond(
        self,
        provider: str,
        event: Dict[str, Any],
        scope: Dict[str, Any],
    ) -> None:
        """Run the scan (or skip) and post results."""
        scan_type = scope.get("scan_type", "skip")

        if scan_type == "skip":
            self._json_response(200, {"status": "skipped", "reason": scope.get("reason", "")})
            return

        # Acknowledge immediately, run scan in background
        self._json_response(202, {
            "status": "accepted",
            "scan_type": scan_type,
            "repo": event.get("repo", ""),
            "branch": event.get("branch", ""),
        })

        # Run scan in a background thread so the webhook returns quickly
        t = threading.Thread(
            target=self._background_scan,
            args=(provider, event, scope),
            daemon=True,
        )
        t.start()

    @staticmethod
    def _background_scan(
        provider: str,
        event: Dict[str, Any],
        scope: Dict[str, Any],
    ) -> None:
        """Execute the scan in the background and post results."""
        try:
            from .scanner import scan
            from .history import save_scan
            from .delta import generate_delta_report

            target = scope.get("target", "")
            files = scope.get("files", [])

            # Run the scan
            result = scan(target, modules=None, timeout=10, verify_tls=True)
            scan_dict = result.to_dict()
            save_scan(scan_dict, label="webhook")

            # Generate delta report if there's a previous scan
            delta_md = generate_delta_report(target, format="markdown")

            # Set commit status (GitHub)
            sha = event.get("sha", "")
            repo = event.get("repo", "")
            if provider == "github" and sha:
                status = GitHubWebhookHandler.generate_status(event, scan_dict)
                state = status["state"]
                desc = status["description"]
                _set_commit_status(repo, sha, state, desc)

            # Post PR/MR comment
            pr_number = event.get("pr_number") or event.get("mr_iid")
            if pr_number and repo:
                comment_body = (
                    f"## ReconPro Security Scan Results\n\n"
                    f"**Grade:** {scan_dict.get('grade', 'N/A')} | "
                    f"**Score:** {scan_dict.get('total_score', 0)}/100 | "
                    f"**Findings:** {scan_dict.get('total_findings', 0)}\n\n"
                )
                sev = scan_dict.get("severity_counts", {})
                if sev.get("critical", 0) or sev.get("high", 0):
                    comment_body += f"**Critical:** {sev.get('critical', 0)} | **High:** {sev.get('high', 0)}\n\n"

                if delta_md:
                    comment_body += f"### Delta Report\n\n{delta_md}\n"

                _post_pr_comment(provider, repo, pr_number, comment_body)

        except Exception:
            pass  # Background scan failure — already returned 202


class WebhookServer(HTTPServer):
    """HTTP server that listens for GitHub and GitLab webhooks.

    Usage:
        server = WebhookServer(port=7891)
        server.serve_forever()
    """

    def __init__(self, port: int = 7891, host: str = "0.0.0.0") -> None:
        self.host = host
        self.port = port
        super().__init__((host, port), _WebhookRequestHandler)

    # DEAD CODE: consider removal
    def serve_forever(self, poll_interval: float = 0.5) -> None:
        print(f"  [bright_green]ReconPro Webhook Server v11.1.0[/] running on [cyan]http://{self.host}:{self.port}[/]")
        print(f"  [dim]POST /webhook/github  |  POST /webhook/gitlab  |  GET /webhook/config[/]")
        print(f"  [dim]Press Ctrl+C to stop[/]")
        try:
            super().serve_forever(poll_interval)
        except KeyboardInterrupt:
            print("\n  [yellow]Webhook server stopped.[/]")
            self.server_close()


# DEAD CODE: consider removal
def run_webhook_server(port: int = 7891) -> None:
    """Start the webhook server (convenience function)."""
    server = WebhookServer(port=port)
    server.serve_forever()


# ═══════════════════════════════════════════════════════════════════════════
# OUTBOUND NOTIFICATION WEBHOOKS — Slack, Discord, Microsoft Teams
# ═══════════════════════════════════════════════════════════════════════════

class NotificationWebhook:
    """Base class for outbound notification webhooks."""

    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.channel = channel

    def send(self, message: str, severity: str = "info") -> bool:
        raise NotImplementedError

    def _post(self, payload: Dict[str, Any]) -> bool:
        try:
            import urllib.request
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                self.webhook_url, data=data, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "ReconPro/9"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False


class SlackWebhook(NotificationWebhook):
    """Send scan results to Slack via incoming webhook."""

    SEVERITY_COLORS = {
        "critical": "#FF0000", "high": "#FF6600",
        "medium": "#FFAA00", "low": "#00CC00", "info": "#0088FF",
    }

    def send(self, message: str, severity: str = "info", title: str = "ReconPro Scan",
             findings: Optional[List[Dict]] = None, score: Optional[int] = None) -> bool:
        severity = severity.lower()
        blocks = []
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": f"{'🔴' if severity in ('critical','high') else '🟡' if severity == 'medium' else '🟢'} {title}"},
        })
        if score is not None:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Security Score:* {score}/100"}})
        if findings:
            sev_count = {}
            for f in findings:
                s = f.get("severity", "info").lower()
                sev_count[s] = sev_count.get(s, 0) + 1
            summary = "  ".join(f"`{k.upper()}: {v}`" for k, v in sorted(sev_count.items(), key=lambda x: ["critical","high","medium","low","info"].index(x[0]) if x[0] in ["critical","high","medium","low","info"] else 99))
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Findings:* {summary}"}})
            # Top 5 critical/high findings
            top = [f for f in findings if f.get("severity","").lower() in ("critical","high")][:5]
            for f in top:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"• *{f.get('title','')}* — `{f.get('category','')}`"}})
        if message:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": message}})
        payload = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel
        return self._post(payload)


class DiscordWebhook(NotificationWebhook):
    """Send scan results to Discord via webhook."""

    SEVERITY_COLORS = {
        "critical": 15158332, "high": 15158588,
        "medium": 15157532, "low": 3066993, "info": 3447003,
    }

    def send(self, message: str, severity: str = "info", title: str = "ReconPro Scan",
             findings: Optional[List[Dict]] = None, score: Optional[int] = None) -> bool:
        severity = severity.lower()
        embed = {
            "title": title,
            "description": message[:2000] if message else "",
            "color": self.SEVERITY_COLORS.get(severity, 3447003),
            "footer": {"text": "ReconPro v11.1.0"},
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [],
        }
        if score is not None:
            embed["fields"].append({"name": "Security Score", "value": f"{score}/100", "inline": True})
        if findings:
            sev_count = {}
            for f in findings:
                s = f.get("severity", "info").lower()
                sev_count[s] = sev_count.get(s, 0) + 1
            embed["fields"].append({
                "name": "Findings", "value": "\n".join(f"**{k.upper()}:** {v}" for k,v in sorted(sev_count.items())),
                "inline": True,
            })
            top = [f for f in findings if f.get("severity","").lower() in ("critical","high")][:5]
            for f in top:
                embed["fields"].append({"name": f.get("title",""), "value": f.get("description","")[:500], "inline": False})
        payload = {"embeds": [embed]}
        if self.channel:
            payload["channel_id"] = self.channel  # Not typically used but available
        return self._post(payload)


class TeamsWebhook(NotificationWebhook):
    """Send scan results to Microsoft Teams via incoming webhook."""

    SEVERITY_COLORS = {
        "critical": "FF0000", "high": "FF6600",
        "medium": "FFAA00", "low": "00CC00", "info": "0088FF",
    }

    # DEAD CODE: consider removal
    def send(self, message: str, severity: str = "info", title: str = "ReconPro Scan",
             findings: Optional[List[Dict]] = None, score: Optional[int] = None) -> bool:
        severity = severity.lower()
        facts = []
        if score is not None:
            facts.append({"name": "Security Score", "value": f"{score}/100"})
        if findings:
            sev_count = {}
            for f in findings:
                s = f.get("severity", "info").lower()
                sev_count[s] = sev_count.get(s, 0) + 1
            facts.append({"name": "Findings", "value": ", ".join(f"{k.upper()}: {v}" for k,v in sorted(sev_count.items()))})
        top = [f for f in findings if f.get("severity","").lower() in ("critical","high")][:5]
        for f in top:
            facts.append({"name": f.get("title",""), "value": f.get("category","")})
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": self.SEVERITY_COLORS.get(severity, "0088FF"),
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "activitySubtitle": f"ReconPro v11.1.0 — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                "facts": facts,
                "text": message[:2000] if message else "",
            }],
        }
        return self._post(payload)


def send_scan_notification(
    webhook_url: str,
    platform: str = "slack",
    findings: Optional[List[Dict]] = None,
    score: Optional[int] = None,
    title: str = "ReconPro Scan Complete",
    message: str = "",
) -> bool:
    """Convenience function to send a notification to any supported platform."""
    platform = platform.lower().strip()
    cls_map = {"slack": SlackWebhook, "discord": DiscordWebhook, "teams": TeamsWebhook}
    cls = cls_map.get(platform, SlackWebhook)
    notifier = cls(webhook_url)
    return notifier.send(message=message, title=title, findings=findings, score=score)


__all__ = [
    "GitHubWebhookHandler",
    "GitLabWebhookHandler",
    "WebhookServer",
    "run_webhook_server",
    "NotificationWebhook",
    "SlackWebhook",
    "DiscordWebhook",
    "TeamsWebhook",
    "send_scan_notification",
]
