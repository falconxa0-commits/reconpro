#!/usr/bin/env python3
"""smoke_webhook.py — LIVE GitHub App webhook receiver (PHOENIX 7-d).

A real HTTP server (stdlib http.server — aiohttp is not guaranteed in this
environment) that implements GitHub's webhook signature scheme:

  header  X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of raw body, keyed
                               with the app's webhook secret>
  spec    https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

Behaviour:
  POST /webhook — verify the HMAC-SHA256 signature with
                  hmac.compare_digest (constant time):
                    valid   -> 200 {"status":"ok","signature":"valid",...}
                    invalid -> 401 {"status":"unauthorized",...}
  GET  /healthz -> 200 {"status":"ok"} (liveness probe)

Run it:
  python3 github-app/smoke_webhook.py --port 18765 --secret my-webhook-secret

Then deliver a SIGNED payload (see github-app/tools/validate.py, which does
exactly this and prints the server's verdict):
  curl -sS -X POST http://127.0.0.1:18765/webhook \
    -H 'Content-Type: application/json' \
    -H 'X-GitHub-Event: pull_request' \
    -H "X-Hub-Signature-256: sha256=$(python3 - <<'PY'
import hmac, hashlib, sys
secret = b"my-webhook-secret"
body = open('/tmp/payload.json','rb').read()
print(hmac.new(secret, body, hashlib.sha256).hexdigest())
PY
)" --data-binary @/tmp/payload.json

This server was LIVE-TESTED in the sandbox that shipped it (signed request →
200 "signature valid"; tampered signature → 401). It is a smoke/acceptance
harness, not a production handler: the scan-on-PR orchestration (clone, run
reconpro, upload SARIF) is documented in README.md.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "test-webhook-secret").encode("utf-8")


def signature_valid(raw_body: bytes, header_value: str | None) -> bool:
    """Validate GitHub's X-Hub-Signature-256 header against the raw body."""
    if not header_value:
        return False
    header_value = header_value.strip()
    if not header_value.lower().startswith("sha256="):
        return False
    received = header_value.split("=", 1)[1].strip().lower()
    expected = hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received, expected)


class ReconProWebhookHandler(BaseHTTPRequestHandler):
    server_version = "ReconProSentinel/0.1"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "service": "reconpro-sentinel-webhook"})
        else:
            self._send(404, {"status": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/webhook":
            self._send(404, {"status": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        event = self.headers.get("X-GitHub-Event", "unknown")
        delivery = self.headers.get("X-GitHub-Delivery", "-")
        sig_header = self.headers.get("X-Hub-Signature-256")

        if not signature_valid(raw, sig_header):
            print(f"[webhook] REJECT delivery={delivery} event={event} — invalid signature", file=sys.stderr, flush=True)
            self._send(401, {"status": "unauthorized", "signature": "invalid"})
            return

        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"status": "bad_request", "signature": "valid"})
            return

        action = payload.get("action")
        repo = (payload.get("repository") or {}).get("full_name")
        pr = (payload.get("pull_request") or {}).get("number")
        print(
            f"[webhook] ACCEPT delivery={delivery} event={event} action={action} "
            f"repo={repo} pr={pr} signature=valid bytes={len(raw)}",
            file=sys.stderr,
            flush=True,
        )
        # Production handler would enqueue: clone PR head -> reconpro dev/ast ->
        # export SARIF -> checks API + code-scanning upload. This smoke server
        # acknowledges instead (honest about what is live-tested).
        self._send(200, {
            "status": "ok",
            "signature": "valid",
            "event": event,
            "delivery": delivery,
            "action": action,
            "repo": repo,
            "pr": pr,
        })

    def log_message(self, fmt: str, *args) -> None:  # keep stdout quiet
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="ReconPro Sentinel webhook smoke server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18765)
    ap.add_argument("--secret", default=os.environ.get("GITHUB_WEBHOOK_SECRET", "test-webhook-secret"))
    args = ap.parse_args()

    global SECRET
    SECRET = args.secret.encode("utf-8")

    server = ThreadingHTTPServer((args.host, args.port), ReconProWebhookHandler)
    print(f"[webhook] ReconPro Sentinel listening on http://{args.host}:{args.port}/webhook (secret: {'***' if args.secret else 'EMPTY'})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
