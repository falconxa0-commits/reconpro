#!/usr/bin/env python3
"""github-app validator (PHOENIX 7-d) — LIVE webhook round-trip.

1. manifest.yml parses (yaml.safe_load) with the required GitHub App keys:
   name "ReconPro Sentinel", default_events pull_request + security_and_analysis,
   default_permissions contents:read + checks:write + security_events:write
   (only VALID GitHub permission keys — verified against the documented set);
2. smoke_webhook.py implements the X-Hub-Signature-256 scheme (HMAC-SHA256,
   hmac.compare_digest);
3. LIVE: starts smoke_webhook.py on a free localhost port, then
   a. GET /healthz -> 200,
   b. POSTs a SIGNED pull_request payload (signature computed with the same
      Python HMAC the README documents) -> expects 200 + "signature":"valid",
   c. POSTs the same body with a TAMPERED signature -> expects 401,
   d. POSTs with no signature at all -> expects 401,
   e. kills the server and inspects its log lines.

Exit code 0 = PASS, 1 = FAIL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # github-app
PYTHON = os.environ.get("RECONPRO_PYTHON", sys.executable)

failures: list[str] = []
checks = 0


def check(cond: bool, name: str, detail: str = "") -> None:
    global checks
    checks += 1
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(name)


# Valid GitHub App permission keys (docs: "Permissions required for GitHub Apps")
VALID_PERMISSION_KEYS = {
    "actions", "administration", "attestations", "checks", "contents",
    "deployments", "discussions", "environments", "issues", "members",
    "metadata", "organization_administration", "organization_custom_properties",
    "organization_custom_org_roles", "organization_copilot_seat_management",
    "organization_events", "organization_hooks", "organization_personal_access_tokens",
    "organization_personal_access_token_requests", "organization_plan",
    "organization_projects", "organization_rulesets", "organization_secrets",
    "organization_self_hosted_runners", "organization_user_blocking",
    "packages", "pages", "profile", "pull_requests", "repository_advisories",
    "repository_custom_properties", "repository_hooks", "repository_projects",
    "repository_rulesets", "secret_scanning_alerts", "secrets",
    "security_events", "security_and_analysis", "statuses", "team_discussions",
    "vulnerability_alerts", "workflows",
}
VALID_PERMISSION_VALUES = {"read", "write", "admin"}


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── 1. manifest.yml ────────────────────────────────────────────────────────
manifest = None
try:
    with open(os.path.join(ROOT, "manifest.yml"), encoding="utf-8") as fp:
        manifest = yaml.safe_load(fp)
    check(True, "manifest.yml parses (yaml.safe_load)")
except (yaml.YAMLError, OSError) as e:
    check(False, "manifest.yml parses (yaml.safe_load)", str(e))

if manifest:
    check(manifest.get("name") == "ReconPro Sentinel", "app name", str(manifest.get("name")))
    events = manifest.get("default_events") or []
    check("pull_request" in events and "security_and_analysis" in events, "default_events pull_request + security_and_analysis", str(events))
    perms = manifest.get("default_permissions") or {}
    check(perms.get("contents") == "read", "permissions contents: read", str(perms.get("contents")))
    check(perms.get("checks") == "write", "permissions checks: write", str(perms.get("checks")))
    check(perms.get("security_events") == "write", "permissions security_events: write", str(perms.get("security_events")))
    bad_keys = set(perms) - VALID_PERMISSION_KEYS
    bad_vals = {v for v in perms.values() if v not in VALID_PERMISSION_VALUES}
    check(not bad_keys and not bad_vals, "all permission keys/values are valid GitHub App names", f"unknown={bad_keys or 'none'}")
    hook = manifest.get("hook_attributes") or {}
    check(isinstance(hook.get("url"), str) and str(hook.get("url")).startswith("https://"), "hook_attributes.url https endpoint", str(hook.get("url")))
    check("url" in manifest and str(manifest.get("url")).startswith("https://"), "manifest url")
    check("public" in manifest, "manifest declares public/private", str(manifest.get("public")))

# ── 2. smoke_webhook.py source contract ────────────────────────────────────
src = open(os.path.join(ROOT, "smoke_webhook.py"), encoding="utf-8").read()
check("X-Hub-Signature-256" in src, "validates X-Hub-Signature-256 header")
check("hmac.new(SECRET, raw_body, hashlib.sha256)" in src, "HMAC-SHA256 over raw body")
check("hmac.compare_digest" in src, "constant-time comparison (hmac.compare_digest)")
check("http.server" in src, "stdlib http.server (no aiohttp dependency)")
check("sha256=" in src, "sha256= prefix handling per GitHub spec")
check("/healthz" in src, "health endpoint /healthz")

# ── 3. LIVE webhook round-trip ─────────────────────────────────────────────
SECRET = "reconpro-smoke-secret-7d"
PORT = free_port()
BASE = f"http://127.0.0.1:{PORT}"
server = subprocess.Popen(
    [PYTHON, os.path.join(ROOT, "smoke_webhook.py"), "--port", str(PORT), "--secret", SECRET],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
try:
    # wait for the listener
    healthy = False
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"{BASE}/healthz", timeout=1) as r:
                if r.status == 200:
                    healthy = True
                    break
        except Exception:
            time.sleep(0.1)
    check(healthy, "LIVE: smoke_webhook.py server started (healthz probe)")

    if healthy:
        with urllib.request.urlopen(f"{BASE}/healthz", timeout=3) as r:
            check(r.status == 200 and "ok" in r.read().decode(), "LIVE: GET /healthz -> 200 ok")

    payload = json.dumps({
        "action": "opened",
        "repository": {"full_name": "falconxa0-commits/reconpro"},
        "pull_request": {"number": 42, "head": {"sha": "deadbeef"}},
    }).encode("utf-8")

    # (a) SIGNED delivery — same HMAC computation the README documents
    sig = "sha256=" + hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"{BASE}/webhook",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "7d-smoke-0001",
            "X-Hub-Signature-256": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = json.loads(r.read().decode())
            check(r.status == 200, "LIVE: signed delivery -> HTTP 200", f"status={r.status}")
            check(body.get("signature") == "valid" and body.get("status") == "ok", 'LIVE: server verdict "signature valid"', json.dumps(body))
            check(body.get("event") == "pull_request" and body.get("pr") == 42, "LIVE: payload parsed (event/PR number)", json.dumps({k: body.get(k) for k in ("event", "pr", "repo")}))
    except urllib.error.HTTPError as e:
        check(False, "LIVE: signed delivery -> HTTP 200", f"got {e.code}")

    # (b) TAMPERED signature -> 401
    bad_sig = "sha256=" + "0" * 64
    req2 = urllib.request.Request(
        f"{BASE}/webhook",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "7d-smoke-0002",
            "X-Hub-Signature-256": bad_sig,
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req2, timeout=5)
        check(False, "LIVE: tampered signature rejected (401)", "got 200")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        check(e.code == 401 and body.get("signature") == "invalid", "LIVE: tampered signature rejected (401 invalid)", f"status={e.code}")

    # (c) missing signature -> 401
    req3 = urllib.request.Request(f"{BASE}/webhook", data=payload, headers={"Content-Type": "application/json", "X-GitHub-Event": "push"}, method="POST")
    try:
        urllib.request.urlopen(req3, timeout=5)
        check(False, "LIVE: missing signature rejected (401)", "got 200")
    except urllib.error.HTTPError as e:
        check(e.code == 401, "LIVE: missing signature rejected (401)", f"status={e.code}")
finally:
    server.send_signal(signal.SIGTERM)
    try:
        out, _ = server.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        out, _ = server.communicate()
    server_log = (out or "").strip()
    check("ACCEPT delivery=7d-smoke-0001" in server_log and "signature=valid" in server_log, "server log shows the accepted signed delivery", server_log.splitlines()[-1] if server_log else "no log")
    check("REJECT delivery=7d-smoke-0002" in server_log, "server log shows the rejected tampered delivery")

# ── summary ─────────────────────────────────────────────────────────────────
print()
print(f"github-app validation: {checks - len(failures)}/{checks} checks passed.")
if failures:
    print("RESULT: FAIL", file=sys.stderr)
    sys.exit(1)
print("RESULT: PASS")
sys.exit(0)
