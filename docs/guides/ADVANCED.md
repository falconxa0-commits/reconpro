# Guide — Advanced usage

Blitz multi-target scans, `--insecure` and PARTIAL targets, the plugin
system, history and diff. Every command and output on this page was
executed against v11.2.0; network-dependent examples are marked
**(network)**. The `--insecure` experiment uses a real local HTTPS
server with a self-signed certificate, started for this purpose.

## Blitz — parallel multi-target scanning

```
reconpro blitz [-h] [--workers WORKERS] [--modules MODULES] targets [targets ...]
```

`blitz` scans many targets in parallel through the same engine
(`engine.py:concurrent_scan()` — a shared `asyncio.Semaphore(10)` caps
total in-flight work across **all** targets):

```bash
reconpro blitz <t1.example.com> <t2.example.com> <t3.example.com>   # (network)
reconpro blitz <t1.example.com> <t2.example.com> --workers 4       # (network)
reconpro blitz <t1.example.com> <t2.example.com> --modules recon     # (network)
```

Each target goes through the truth layer independently — one
unreachable target in a blitz list yields that target's honest `U`
result without sinking the others.

## Module selection beyond the default

The default remote scan runs 20 modules. Two knobs change that:

```bash
reconpro scan <your-target.com> --modules recon,auth,chain    # (network) exactly these
reconpro scan <your-target.com> --all                         # (network) all 25 remote
```

Unknown module IDs are silently dropped (verified — see
[SCANNING.md](SCANNING.md#module-selection)); always confirm with
`modules_run` in the JSON. `reconpro list` prints the catalog.

## Rate limiting

```bash
reconpro scan <your-target.com> --rate-limit 2      # (network) 2 req/s, shared across modules
reconpro scan <your-target.com> --all --rate-limit 0.5   # (network) everything, very politely
```

Valid range 0.1–1000 (default 10.0); outside it, exit 2. The limiter is
process-wide for the scan, so `--all` at a low rate is the way to run a
loud scan quietly.

## Insecure mode & PARTIAL targets

TLS is verified **by default everywhere**. `--insecure` / `-k` is the
single, audited opt-out (see [../SECURITY.md](../SECURITY.md) for the
enforcement story — an AST regression test guarantees no other code
path can construct an unverified context).

The subtlety worth understanding (verified against a local HTTPS server
with a self-signed certificate):

### Without `--insecure` — the self-signed target stays PARTIAL

```
$ reconpro scan https://127.0.0.1:8765 --json -t 10       # self-signed cert
"target_validation": {"state": "PARTIAL_TARGET", "dns_resolved": true,
                      "reachable": true, "http_ok": false, "tls_valid": null}
"grade": "F", "total_findings": 64, "severity_counts": {"medium": 28, "low": 17, "info": 19}
```

The DNS and TCP layers passed, but the HTTP(S) probe could not validate
the TLS handshake → `PARTIAL_TARGET`. **Every finding is capped at
medium** (28 medium, 17 low, 19 info — no high, no critical) and each
carries `confidence: 0.5` and `verification_state: "PARTIAL_TARGET"`.
This is the honest result: ReconPro cannot fully verify the server, so
it refuses to make high-severity claims about it.

### With `--insecure` — VERIFIED, with the caveat recorded

```
$ reconpro scan https://127.0.0.1:8765 --json -t 10 --insecure
"target_validation": {"state": "VERIFIED_TARGET", "dns_resolved": true,
                      "reachable": true, "http_ok": true, "tls_valid": false}
"grade": "F", "total_findings": 224, "severity_counts": {"high": 77, "critical": 17, ...}
```

With verification disabled, the HTTP probe succeeds and the target
validates as `VERIFIED_TARGET` — **but the report permanently records
`tls_valid: false`**, so anyone reading the JSON knows the scan ran
without TLS validation. The severity cap does **not** apply (that cap
belongs to the PARTIAL state, not to the `--insecure` flag): 77 high
and 17 critical findings were possible because the target was actually
reached and answered.

> **Rule of thumb**: `--insecure` buys you full-depth scanning of
> self-signed/internal hosts, at the cost of a `tls_valid: false` mark
> on every result. It never buys you false findings — the truth layer
> still ran DNS → TCP → HTTP before any module executed.

## The plugin system

Plugins are **separate OS processes** behind a CPython audit hook
(RLIMIT_AS 128 MiB, CPU 10 s, FSIZE 16 MiB; subprocess/sockets/
privilege-escalation/out-of-workdir-writes blocked), Ed25519-signed at
install, hash-pinned, with drift detection. The complete contract:
[../PLUGINS.md](../PLUGINS.md). The 6-step loop:

```bash
reconpro plugin create-sdk my-check     # 1. scaffold
$EDITOR my-check/main.py                 # 2. implement run() → findings
reconpro plugin sign my-check           # 3. Ed25519-sign the source
reconpro plugin install my-check        # 4. verify + register
reconpro plugin verify my-check         # 5. hash + signature + static checks
reconpro plugin run my-check example.com  # 6. run it in the sandbox    (network)
```

Verified behaviors worth knowing:

- Editing the installed source makes `plugin verify` fail on
  `source_hash` (drift detection is enforced, not decorative).
  Recovery: `plugin remove <id>`, re-`sign`, re-`install`.
- A plugin that tries `open("/tmp/marker", "w")` gets a sandbox
  violation and the marker is never created — live transcript in
  [../PLUGINS.md](../PLUGINS.md).
- `reconpro playground` runs a plugin file (or the built-in template)
  inside the sandbox **without installing anything** — the safe lab.

## History and diff

Every scan is saved to `~/.reconpro/history/` (one JSON per scan).
`reconpro history` prints the table (to stderr — it has no `--json`
flag; passing one is exit 2), `reconpro diff` compares two saved scans:

```
$ reconpro diff
  127.0.0.1:8765  score=0 (F)
  127.0.0.1:8765  score=0 (F)
  Change: 0 pts

  New issues (24):
    + Covert Channel Risk Assessment: LOW (10.2%)
    + Honeypot Identified — Effectiveness: 81% (HIGHLY CONVINCING)
    + Missing CSP header
    ...
  Fixed (183):
    - Auth bypass via Authorization on /api/admin
    ...
```

(The diff above is real: it compares the PARTIAL scan of the self-signed
server — 64 capped findings — with the later `--insecure` scan of the
same server: 224 findings. The 24 "new issues" are the ones that had
been severity-capped before.)

Usage: `reconpro diff [a] [b]` where each argument is a scan file or
`last` (default `last` vs `last-2`). This is the regression-detection
workflow: scan before a change, deploy, scan again, diff.

## Export formats in one table

| Command | Produces | Notes |
|---|---|---|
| `reconpro export r.sarif` | SARIF 2.1.0 | GitHub Code Scanning |
| `reconpro export r.md` | Markdown | grade badge included |
| `reconpro export r.json` | canonical JSON | same schema as `--json` |
| `reconpro export r.html` | HTML | single file, no assets |
| `reconpro export r.pdf` | print-ready HTML | Ctrl+P → save as PDF |
| *(Python API)* `generate_csv_report()` | CSV | not available via CLI `export` |

Full details and the fallback caveat (unknown extension → JSON):
[REPORTS.md](REPORTS.md).

## The `serve` API and scheduling

```bash
reconpro serve --port 7890        # REST wrapper around the same results
reconpro schedule example.com --every 1h     # (network) recurring scans
```

`serve` exposes the scan pipeline over HTTP for dashboards; `schedule`
persists recurring scans. Both are covered command-by-command in
[../reference/CLI_REFERENCE.md](../reference/CLI_REFERENCE.md).

## Related

- [ENTERPRISE.md](ENTERPRISE.md) — CI/CD, air-gapped verification
- [SCANNING.md](SCANNING.md) — truth-state semantics in depth
- [../PLUGINS.md](../PLUGINS.md) — the full plugin contract
- [../SDKS.md](../SDKS.md) — driving the CLI from Python/TS/Go/Rust/Java
