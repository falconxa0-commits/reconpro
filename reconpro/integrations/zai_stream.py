"""ReconPro v7.0 — z.ai Live Stream Integration.

Streams ReconPro scan results through z.ai's LLM for real-time AI-powered
security analysis. Zero-configuration — auto-discovers credentials from
/etc/.z-ai-config, ~/.z-ai-config, or <project>/.z-ai-config.

No API keys required. Works out of the box in the Z.ai environment.

Usage as a module::

    from reconpro.integrations.zai_stream import ZAIStreamClient

    client = ZAIStreamClient()
    for chunk in client.analyze_findings_stream(findings, target="example.com"):
        print(chunk, end="", flush=True)

Usage as a ReconPro integration::

    from reconpro.integrations import ZAIStreamClient
    client = ZAIStreamClient()
    result = client.sync_findings(findings_dicts, target="example.com")
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


# ── Config Discovery ─────────────────────────────────────────────────────

CONFIG_SEARCH_PATHS: List[Path] = [
    Path("/etc/.z-ai-config"),
    Path.home() / ".z-ai-config",
    Path.cwd() / ".z-ai-config",
]


def _discover_config() -> Dict[str, str]:
    """Auto-discover z.ai credentials from standard config locations.

    Searches in order: /etc/.z-ai-config, ~/.z-ai-config, ./.z-ai-config
    Returns the first valid config found, or raises RuntimeError.
    """
    for p in CONFIG_SEARCH_PATHS:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("baseUrl") and data.get("apiKey"):
                    return data
            except (json.JSONDecodeError, OSError):
                continue
    raise RuntimeError(
        'z.ai config not found. Create .z-ai-config in /etc/, ~/, or project root '
        'with: {"baseUrl": "https://...", "apiKey": "..."}'
    )


def _default_config_path() -> Path:
    for p in CONFIG_SEARCH_PATHS:
        if p.exists():
            return p
    return CONFIG_SEARCH_PATHS[0]


# ── SSE Parser ───────────────────────────────────────────────────────

def _parse_sse_stream(response) -> Generator[str, None, None]:
    """Parse Server-Sent Events from an HTTPResponse object.

    Yields the 'content' field from each SSE 'data:' line.
    Handles chunked transfer encoding and partial line buffering.
    """
    buffer = ""
    while True:
        chunk = response.read(4096)
        if not chunk:
            break
        # Decode bytes to str (SSE is always UTF-8)
        try:
            text = chunk.decode("utf-8", errors="replace")
        except AttributeError:
            text = chunk  # Already a str
        buffer += text
        # Process complete lines
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            if line.startswith("data: "):
                payload = line[6:]
                if payload.strip() == "[DONE]":
                    return
                try:
                    obj = json.loads(payload)
                    # OpenAI-compatible: choices[0].delta.content
                    content = (
                        obj.get("choices", [{}])[0]
                        .get("delta", {})
                        .get("content", "")
                    )
                    if content:
                        yield content
                except (json.JSONDecodeError, IndexError, KeyError, TypeError):
                    # Non-JSON data line — yield raw text
                    if payload.strip():
                        yield payload


# ── SSL Context ───────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx


# ── Prompt Templates ───────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are ReconPro AI, an elite security analyst embedded inside the ReconPro Enterprise reconnaissance platform. You provide real-time, actionable security intelligence.

When analyzing scan findings, follow this format:

## Threat Assessment
[Brief overall risk posture]

## Critical Findings
[Numbered list of the most severe issues with specific remediation]

## Attack Surface Analysis
[Surface-level exposure assessment]

## Recommendations
[Prioritized action items]

Be concise, technical, and actionable. Use severity indicators: CRITICAL, HIGH, MEDIUM, LOW, INFO."""


def _build_finding_prompt(findings: List[Dict[str, Any]], target: str) -> str:
    """Build a user prompt from ReconPro findings."""
    # Cap at 50 findings to stay within context limits
    capped = findings[:50]
    finding_blocks = []
    for i, f in enumerate(capped, 1):
        sev = f.get("severity", "info").upper()
        title = f.get("title", "Unknown")
        desc = f.get("description", "")[:200]
        cat = f.get("category", "")
        asset = f.get("asset", "")
        dread = f.get("dread_score", 0)
        dread_display = dread
        if isinstance(dread, dict):
            d_val = dread.get("damage", 0)
            r_val = dread.get("reproducibility", 0)
            e_val = dread.get("exploitability", 0)
            a_val = dread.get("affected_users", 0)
            dam_val = dread.get("discoverability", 0)
            vals = [d_val, r_val, e_val, a_val, dam_val]
            if all(isinstance(x, (int, float)) for x in vals):
                dread_display = round(sum(vals) / 5, 1)
            else:
                dread_display = dread
        finding_blocks.append(
            "[{}] [{}] {}\n"
            "    Category: {} | Asset: {} | DREAD: {}\n"
            "    {}".format(i, sev, title, cat, asset, dread_display, desc)
        )
    findings_text = "\n".join(finding_blocks)
    return (
        "Analyze these {} security findings from a ReconPro scan "
        "against target: {}\n\n"
        "## Scan Results ({} of {} shown)\n\n"
        "{}\n\n"
        "Provide a comprehensive threat assessment, highlight critical findings, "
        "analyze the attack surface, and give prioritized remediation recommendations."
        .format(len(findings), target, len(capped), len(findings), findings_text)
    )


# ── Main Client ─────────────────────────────────────────────────────

class ZAIStreamClient:
    """z.ai Live Stream client for ReconPro.

    Auto-discovers credentials — no API key configuration needed.
    Streams AI analysis of security findings in real-time via SSE.
    """

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        chat_id: str = "",
        token: str = "",
        model: str = "glm-4-flash",
        timeout: int = 30,
    ) -> None:
        """Initialize the z.ai stream client.

        If no credentials are provided, auto-discovers from config files.
        """
        # Auto-discover if not explicitly provided
        if not base_url or not api_key:
            cfg = _discover_config()
            self.base_url = (base_url or cfg.get("baseUrl", "")).rstrip("/")
            self.api_key = api_key or cfg.get("apiKey", "")
            self.chat_id = chat_id or cfg.get("chatId", "")
            self.token = token or cfg.get("token", "")
            self.user_id = cfg.get("userId", "")
        else:
            self.base_url = base_url.rstrip("/")
            self.api_key = api_key
            self.chat_id = chat_id
            self.token = token
            self.user_id = ""

        self.model = model
        self.timeout = timeout
        self._config_path = _default_config_path()

    def _make_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(self.api_key),
            "X-Z-AI-From": "Z",
        }
        if self.chat_id:
            headers["X-Chat-Id"] = self.chat_id
        if self.user_id:
            headers["X-User-Id"] = self.user_id
        if self.token:
            headers["X-Token"] = self.token
        return headers

    def _request(self, endpoint: str, body: Dict[str, Any], stream: bool = False):
        """Make an HTTP request to the z.ai API.

        Returns the HTTPResponse object for streaming, or parsed JSON for non-streaming.
        """
        url = "{}/{}".format(self.base_url, endpoint.lstrip("/"))
        headers = self._make_headers()
        # Match z.ai SDK: always include thinking field
        if "thinking" not in body:
            body["thinking"] = {"type": "disabled"}
        data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        ctx = _ssl_ctx()

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            return resp
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                "z.ai API error {}: {}".format(e.code, error_body)
            ) from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                "z.ai connection failed: {}".format(e.reason)
            ) from e

    # ── Streaming Analysis ──────────────────────────────────────────

    def analyze_findings_stream(
        self,
        findings: List[Dict[str, Any]],
        target: str = "unknown",
        system_prompt: str = "",
        model: str = "",
    ) -> Generator[str, None, None]:
        """Stream AI analysis of scan findings via SSE."""
        user_msg = _build_finding_prompt(findings, target)
        sys_msg = system_prompt or SYSTEM_PROMPT
        use_model = model or self.model

        body = {
            "model": use_model,
            "messages": [
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": user_msg},
            ],
            "stream": True,
            "temperature": 0.3,
            "max_tokens": 4096,
        }

        resp = self._request("/chat/completions", body, stream=True)
        yield from _parse_sse_stream(resp)

    def analyze_findings(
        self,
        findings: List[Dict[str, Any]],
        target: str = "unknown",
        system_prompt: str = "",
        model: str = "",
    ) -> str:
        """Analyze findings and return the complete AI response (non-streaming)."""
        user_msg = _build_finding_prompt(findings, target)
        sys_msg = system_prompt or SYSTEM_PROMPT
        use_model = model or self.model

        body = {
            "model": use_model,
            "messages": [
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": user_msg},
            ],
            "stream": False,
            "temperature": 0.3,
            "max_tokens": 4096,
        }

        resp = self._request("/chat/completions", body, stream=False)
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    # ── Quick Chat (free-form) ───────────────────────────────────────────

    def chat_stream(
        self,
        message: str,
        system_prompt: str = "You are a helpful security assistant.",
        model: str = "",
    ) -> Generator[str, None, None]:
        """Stream a free-form chat message through z.ai."""
        body = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message},
            ],
            "stream": True,
            "temperature": 0.7,
            "max_tokens": 2048,
        }
        resp = self._request("/chat/completions", body, stream=True)
        yield from _parse_sse_stream(resp)

    def chat(self, message: str, system_prompt: str = "", model: str = "") -> str:
        """Send a free-form chat message (non-streaming)."""
        body = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": system_prompt or "You are a helpful assistant."},
                {"role": "user", "content": message},
            ],
            "stream": False,
            "temperature": 0.7,
            "max_tokens": 2048,
        }
        resp = self._request("/chat/completions", body, stream=False)
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    # ── ReconPro Integration Pattern ──────────────────────────────────

    def sync_findings(
        self,
        findings: List[Dict[str, Any]],
        target: str = "unknown",
    ) -> Dict[str, Any]:
        """Analyze findings and return a structured result dict.

        Follows the same pattern as JiraClient.sync_findings() and
        GitHubClient.sync_findings() for consistency.
        """
        analysis = self.analyze_findings(findings, target)
        return {
            "action": "analyzed",
            "analysis": analysis,
            "target": target,
            "findings_count": len(findings),
            "model": self.model,
            "stream_supported": True,
        }

    def sync_findings_stream(
        self,
        findings: List[Dict[str, Any]],
        target: str = "unknown",
    ) -> Generator[Dict[str, Any], None, None]:
        """Stream analysis results as structured events."""
        full_text = []
        for chunk in self.analyze_findings_stream(findings, target):
            full_text.append(chunk)
            yield {"type": "chunk", "content": chunk, "target": target}
        yield {
            "type": "done",
            "content": "".join(full_text),
            "target": target,
            "findings_count": len(findings),
            "model": self.model,
        }

    # ── Health Check ──────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        """Verify connectivity to z.ai API."""
        start = time.monotonic()
        try:
            response = self.chat("Say 'OK' and nothing else.", model=self.model)
            elapsed = (time.monotonic() - start) * 1000
            return {
                "status": "connected",
                "model": self.model,
                "base_url": self.base_url,
                "latency_ms": round(elapsed, 1),
                "response_preview": response[:100],
            }
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return {
                "status": "error",
                "error": str(e),
                "base_url": self.base_url,
                "latency_ms": round(elapsed, 1),
            }

    def __repr__(self) -> str:
        return "ZAIStreamClient(base_url={!r}, model={!r}, config={!r})".format(
            self.base_url, self.model, self._config_path
        )
