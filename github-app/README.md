# ReconPro Sentinel — GitHub App

Webhook-driven CI companion for the [ReconPro](..) security scanner: when a
pull request is opened or updated, the app runs `reconpro` on the PR head and
reports findings as check runs and SARIF Code Scanning results.

```
github-app/
  manifest.yml       GitHub App manifest (create the app from this file)
  smoke_webhook.py   LIVE-TESTED webhook receiver (stdlib http.server +
                     GitHub X-Hub-Signature-256 HMAC-SHA256 validation)
  tools/validate.py  validator: manifest contract + live signed/tampered
                     webhook round-trip
```

## 1. Create the App from the manifest

Host `manifest.yml` (e.g. `https://reconpro.example.com/github-app/manifest.yml`)
and open:

```
https://github.com/settings/apps/new?manifest=<URL-encoded manifest>
```

GitHub renders the permission/event review screen from the manifest:

| Setting | Value |
|---|---|
| Name | `ReconPro Sentinel` |
| Webhook events | `pull_request`, `security_and_analysis` |
| Permissions | `contents: read`, `checks: write`, `security_events: write` |
| Visibility | private (manifest `public: false`) |

After you click "Create GitHub App", GitHub POSTs the app's `id`, `pem` and
`webhook_secret` to `manifest.redirect_url` — store them server-side.

## 2. Set the webhook secret and deploy the handler

```bash
export GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 20)"
python3 github-app/smoke_webhook.py --host 0.0.0.0 --port 8080 --secret "$GITHUB_WEBHOOK_SECRET"
```

The receiver validates every delivery per the GitHub spec
(`X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>`, compared
with `hmac.compare_digest`) before parsing it.

**Smoke-tested in the sandbox (real output):**

```console
$ curl -sS -w '\nHTTP_STATUS=%{http_code}\n' -X POST http://127.0.0.1:18765/webhook \
    -H 'Content-Type: application/json' -H 'X-GitHub-Event: pull_request' \
    -H "X-Hub-Signature-256: sha256=89f55533…" --data-binary @payload.json
{"status": "ok", "signature": "valid", "event": "pull_request", "delivery": "7d-curl-demo",
 "action": "opened", "repo": "falconxa0-commits/reconpro", "pr": 42}
HTTP_STATUS=200
# tampered signature → HTTP_STATUS=401
```

## 3. What the production handler adds (beyond the smoke server)

The shipped receiver is a genuine HTTP + HMAC validation harness, and it
honestly stops there. A production deployment would, after signature
validation:

1. authenticate as the installation (JWT from the app private key →
   installation access token);
2. fetch the PR diff / clone the head ref;
3. run `python -m reconpro.cli dev/ast/secrets` + `reconpro export pr.sarif`
   (identical flow to `actions/reconpro-scan`);
4. post check runs (`checks: write`) and upload the SARIF
   (`security_events: write`, code scanning ingest endpoint).

## Validate

```bash
python3 github-app/tools/validate.py   # manifest + LIVE signed/tampered round-trip
```

25/25 checks passing at ship time (see `ide/README.md` status table).
