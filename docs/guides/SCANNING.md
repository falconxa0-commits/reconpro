# Guide — Scanning: modules, timeouts, rate limits, and honest-scan semantics

How to drive the ReconPro scanner well. Everything on this page was
executed against v11.2.0 (commands marked **(network)** need internet
access and are shown with the outputs we could verify offline, or with
`<your-target.com>` placeholders).

The scanner is one pipeline with a fixed contract:

```
reconpro scan <target>
        │
        ▼
TARGET VALIDATION (DNS → TCP → HTTP/TLS)      ← the truth layer runs FIRST
        │
        ├─ UNREACHABLE_TARGET → short-circuit: no modules run,
        │                        grade "U", one info finding
        ├─ PARTIAL_TARGET     → modules run, severities capped at MEDIUM
        └─ VERIFIED_TARGET    → modules run, no cap
        ▼
ENGINE (concurrent, per-module adaptive timeouts, health circuit breakers)
        ▼
FINDINGS (each carries evidence + confidence + verification_state)
```

## Module selection

The module catalog is defined in exactly one place,
`reconpro/registry.py` — **28 modules: 25 remote/advanced + 3 local**
(`host`, `dev`, `doctor`). Verified:

```
$ reconpro list --all | tail -1
  Total: 28 modules
```

A default remote scan runs **20 modules** (the `DEFAULT_MODULES` list in
`registry.py`) — verified live: a `--insecure` scan of a local test
server reported `modules_run` with exactly 20 entries, from `recon` to
`dead_drop`.

| Flag | What it does |
|---|---|
| *(default)* | run the 20 default remote modules |
| `--modules recon,auth,chain` | run exactly these module IDs |
| `--all`, `-a` | run all 25 remote modules |
| `reconpro audit` | local machine audit (`host`, `dev`, `doctor`) |
| `reconpro dev <path>` | local project scan (the `dev` module) |

**Unknown module IDs are dropped, not erroring** — the engine resolves
your list against the registry and keeps only real IDs
(`ScanEngine._resolve_remote_modules` filters on `MODULE_REGISTRY`).
The truth shows up in the JSON as `modules_run` — always check it:

```
$ reconpro scan nonexistent-target-xyz.invalid --modules recon,notamodule,alsofake --json -t 2
{ "modules_run": [], "grade": "U", ... }
```

(This target was unreachable, so nothing ran; on a reachable target the
same command would run only `recon` and silently ignore the other two
IDs.) If you typo a module name, compare your `--modules` list against
`modules_run` in the JSON output — or run `reconpro list` first.

### Which modules for which job

| You want | Run |
|---|---|
| Fast surface recon of one web app | `--modules recon` |
| Auth posture | `--modules recon,auth` |
| Honeypot / deception awareness | `--modules honeypot_dance,info_ops` |
| Everything (slower, noisier) | `--all` |
| Secrets in a codebase (local) | `reconpro secrets <path>` / `reconpro dev <path>` |
| Machine posture (local) | `reconpro audit` / `reconpro doctor` |

## Timeouts

- `--timeout`, `-t` — **per-request** timeout in seconds, range
  **1–600**, default **8**.
- Out-of-range values are a hard usage error, exit `2` (verified:
  `--timeout 0`, `--timeout 601`, and `--timeout -5` all exit 2).
- Inside the engine each module additionally gets an **adaptive
  timeout**: `max(requested_timeout, rolling_average × 2.5)` over the
  module's recent executions (`engine.py:_get_adaptive_timeout`), so a
  habitually slow module is not killed prematurely — and a fast one is
  not allowed to hang.
- `reconpro blitz` and the Python `concurrent_scan()` API cap the whole
  multi-target run the same way.

Practical defaults we verified: an unreachable domain with `-t 2`
returns in about a second (the truth layer fails fast); a slow target
such as a black-holed IP needs a human-scale `-t` (e.g. `30`) unless you
want the TCP probe to be the thing that gives up first.

## Rate limiting

- `--rate-limit` — global requests-per-second cap, range **0.1–1000**,
  default **10.0** (CLI) / `50.0` (Python `concurrent_scan()`).
- Out-of-range exits `2` (verified: `--rate-limit 2000` and
  `--rate-limit 0.01`).
- Use `--rate-limit 1` for fragile targets, or where you must not look
  like a scanner. The limiter is shared across all modules in a scan, so
  `--all --rate-limit 2` is the polite way to run everything.

## Honest-scan semantics (the truth layer)

Every remote scan validates the target **before** any module runs:
DNS resolution → TCP connect → HTTP(S) probe (`reconpro/target_validation.py`).
The resulting state is recorded in the JSON (`target_validation.state`)
and stamped onto every finding (`verification_state`).

### The three states

| State | Meaning | Modules run | Severity cap | Finding confidence |
|---|---|---|---|---|
| `VERIFIED_TARGET` | DNS + TCP + HTTP(S) all answered | yes | none | 0.9 |
| `PARTIAL_TARGET` | DNS ok (maybe TCP), HTTP validation failed — non-HTTP service, TLS failure, probe error | yes (passive/DNS checks may still be valid) | **medium** | 0.5 |
| `UNREACHABLE_TARGET` | DNS failed or no TCP connection | **none** | info only (single honest finding) | 0.95 that the target is unreachable |

### UNREACHABLE_TARGET — the honest no-result

Verified, byte-for-byte meaning:

```
$ reconpro scan nonexistent-target-xyz.invalid --json -t 2
{
  "total_findings": 1,
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",                      ← U = unreachable: no claim is made
  "modules_run": [],
  "target_validation": {"state": "UNREACHABLE_TARGET", "dns_resolved": false, ...},
  "scan_metadata": {"result": "unreachable_target_short_circuit", ...}
}
```

The single finding is `info` severity: *"Target unreachable — scan not
performed"* with the actual DNS error as evidence. A HIGH-severity
finding against a target that was never reached is **impossible by
construction** — the modules that could produce one never execute, and
the state cap (`apply_target_truth()`) clamps anything constructed
manually to `low` anyway.

### PARTIAL_TARGET — capped claims

When the target resolves but HTTP validation fails, modules still run
(DNS-based and passive checks may be legitimate), but every finding is
capped at **medium** with an explicit downgrade note in its evidence.

Verified against a local HTTPS server with a **self-signed certificate**
(the classic PARTIAL case — TLS verification is on by default and the
handshake cannot be validated):

```
$ reconpro scan https://127.0.0.1:8765 --json -t 10        # self-signed cert
"target_validation": {"state": "PARTIAL_TARGET", "dns_resolved": true,
                      "reachable": true, "http_ok": false, "tls_valid": null}
"grade": "F", "total_findings": 64, "severity_counts": {"medium": 28, "low": 17, "info": 19}
   ← no high, no critical — the cap is enforced
```

Each of those 64 findings carries `confidence: 0.5` and
`verification_state: "PARTIAL_TARGET"`. Compare the same server scanned
with `--insecure` in [ADVANCED.md](ADVANCED.md#insecure-mode--partial-targets):
the state becomes `VERIFIED_TARGET` (with `tls_valid: false`) and
high/critical findings are possible again — 224 findings including
high and critical.

### Why this design

A scanner that reports `HIGH No rate limiting` about a host it never
reached is not reporting — it is inventing. The truth layer makes
ReconPro's output safe to act on: **if a finding says HIGH, a verified
target actually exhibited it.** The exit code stays `0` for an
unreachable target — it is an honest *result*, not an error.

## Practical recipes

```bash
# Quick single-module look at one target (network)
reconpro scan <your-target.com> --modules recon --json --timeout 30

# Polite deep scan
reconpro scan <your-target.com> --all --rate-limit 2 --timeout 60 --json -o deep.json

# "Is this thing even up?" — the truth layer answers first
reconpro scan <your-target.com> --json | jq '.target_validation.state'

# Local, always works offline
reconpro doctor --json
reconpro dev . --json
reconpro secrets . --json
```

Verified local example — `reconpro dev . --json` on **this repository**
returning four findings (grade B, score 68):

```
- info | Git repo: reconpro-live (12 recent commits)
- low  | No pre-commit hooks in reconpro-live
- critical | Hardcoded password in validate.js
- critical | Credential in .git/config remote URL: reconpro-live
```

(Local findings carry `verification_state: "UNVERIFIED"` — there is no
remote target to validate; the truth layer only stamps remote scans.)

## What to read next

- [REPORTS.md](REPORTS.md) — the four report formats and their fields
- [ADVANCED.md](ADVANCED.md) — blitz, diff, `--insecure`, plugins
- [../reference/CONFIGURATION.md](../reference/CONFIGURATION.md) —
  `~/.reconpro/` on disk, environment variables
- [../reference/API.md](../reference/API.md) — every JSON field, documented
- [../development/ARCHITECTURE.md](../development/ARCHITECTURE.md) — how
  the engine and truth layer are actually built
