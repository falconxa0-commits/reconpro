# Architecture — how ReconPro is actually built

This page maps the runtime from argv to report, file by file, with the
design decisions called out. Everything here was read from (and verified
against) the v11.2.0 source tree in this repository; line references are
given so you can check them yourself. Reading order matches data flow:

```
argv ─▶ cli.py ─▶ target_validation.py ─▶ engine.py ─▶ registry.py
                │                          │             (module runners)
                │                          ▼
                │                    http_layer.py  (Finding + HTTP stack)
                ▼                          ▼
        scanner.py  (ReconProResult) ─▶ reports.py / formats.py
                                       │
                                       ▼
                          history.py (~/.reconpro/history/*.json)
```

## 1. The CLI — `reconpro/cli.py`

- **81 subcommands**, built with 81 `add_parser()` calls (counted; the
  same 81 names appear in `reconpro --help`).
- **Strict parsing**: the entrypoint calls `parser.parse_args()` — never
  `parse_known_args`. Unknown flags and unknown commands are hard
  errors (exit 2). A bare first argument that *looks like a scan target*
  (URL / IPv4 / dotted domain / `localhost`, via `looks_like_scan_target()`)
  is kept as the `reconpro example.com` shorthand; anything else gets a
  did-you-mean suggestion (difflib) and exit 2.
- **Streams**: `--json` output goes to **stdout**, human (Rich) output to
  **stderr** — the docker/kubectl convention, so pipes are always clean.
- **Startup budget**: fast-path subcommands
  (`_FAST_SUBCOMMANDS = {None, "tutorial", "suggest", "wizard", "playground", "plugin"}`)
  never import the engine or rich; everything else calls `_load_heavy()`.
  Rich names come from `reconpro/lazy_rich.py` as lazy proxies
  (`_ConsoleProxy`, `_LazyClass`) — see
  [../PERFORMANCE.md](../PERFORMANCE.md) for the measured effect
  (~48 ms cold start vs ~570 ms before).

## 2. The truth layer — `reconpro/target_validation.py`

Runs **before any module** for every remote scan:

1. `_resolve_dns(host)` — resolver with timeout; IP literals
   (`_is_ip_literal`) skip DNS.
2. `_tcp_reachable(host, port)` — TCP connect (port 443, or the URL port).
3. `_http_probe(url, timeout, verify_tls)` — an HTTPS GET, verifying TLS
   by default.

The outcome is a `TargetValidation` dataclass (`state`, `dns_resolved`,
`reachable`, `http_ok`, `tls_valid`, `details`, `checked_at`) in one of
three states:

| State | Decided by | Consequence |
|---|---|---|
| `VERIFIED_TARGET` | DNS + TCP + HTTP(S) all OK | modules run; no severity cap |
| `PARTIAL_TARGET` | DNS ok, HTTP validation failed (non-HTTP service, TLS failure, probe error) | modules run; severities capped at **medium** |
| `UNREACHABLE_TARGET` | DNS failed, or no TCP connection | **short-circuit** — no modules, score 0, grade `U`, one honest finding |

Two functions apply the truth to results:

- `apply_target_truth(findings, validation)` — stamps every finding with
  `verification_state`, sets `confidence` from `state_confidence(state)`
  (VERIFIED 0.9 / PARTIAL 0.5 / default 0.2), and downgrades any
  severity above the state cap with an explicit
  `[downgraded from high: target state PARTIAL_TARGET]` note appended to
  the evidence. (UNREACHABLE caps at `low` — belt-and-braces for
  hand-constructed findings; the short-circuit means modules never
  produced any.)
- `unreachable_finding(target, validation)` — the single info finding
  ("Target unreachable — scan not performed"), whose evidence is the
  actual DNS/TCP error.

Verified live (v11.2.0): `reconpro scan nonexistent-target-xyz.invalid
--json -t 2` → `grade U`, `total_score 0`, `modules_run []`,
`scan_metadata.result = "unreachable_target_short_circuit"`, and the one
finding carries `confidence 0.95` — the pipeline's own confidence *that
the target is unreachable*.

## 3. The engine — `reconpro/engine.py`

`ScanEngine` is the async orchestrator:

- **Concurrent modules** — `asyncio.Semaphore(concurrency)` (default 5)
  bounds in-flight modules; modules exposing `async_run()` are awaited
  natively, the rest are wrapped in `asyncio.to_thread`.
- **Adaptive timeouts** — `_get_adaptive_timeout()` computes
  `max(requested_timeout, avg × 2.5)` over a rolling window of the last
  5 executions (`_record_module_timing`), so a habitually slow module is
  not killed prematurely and a fast one cannot hang undetected. A module
  exceeding its adaptive timeout gets a timeout finding and counts as a
  failure.
- **Module-health circuit breakers** — `ModuleHealthState` tracks every
  module: 3 failures inside a 60 s cooldown opens the breaker (module is
  skipped); **5 consecutive failures quarantines the module for 600 s**;
  when quarantine expires, exactly one **probe** execution is allowed
  (auto-recovery); health score = successes over the last 20 executions.
- **Module resolution** — `_resolve_remote_modules()` filters the
  requested `--modules` list against `MODULE_REGISTRY`: unknown IDs are
  dropped, not fatal. That is why the JSON's `modules_run` is the ground
  truth of what ran.
- **The honest short-circuit** — in `run()`, an `UNREACHABLE_TARGET`
  validation returns immediately: no module runs, the result is the
  single unreachable finding.
- `concurrent_scan()` (used by `reconpro blitz`) runs whole scans in
  parallel under a shared `asyncio.Semaphore(10)` across all targets,
  each target independently passing through the truth layer.
- `ScanEvent` / `EventCollector` — structured progress events for
  observability (feeds `reconpro dashboard` / the TUI).

## 4. The module registry — `reconpro/registry.py`

The single source of truth for the catalog:

- `build_module_registry()` — **25 remote/advanced modules**, runners
  imported lazily via `_get_runners()`.
- `build_local_modules()` — **3 local modules** (`host`, `dev`, `doctor`).
- `DEFAULT_MODULES` — the **20 modules** a default remote scan runs;
  `DEFAULT_LOCAL_MODULES` — the 3 local defaults for `audit`.
- `get_execution_order()` — Kahn topological sort over
  `MODULE_DEPENDENCIES` producing **parallel groups** (deterministic
  order inside a group); raises `ValueError` on circular dependencies.
- `visualize_dependencies()` — renders the dependency graph as text.

Counts verified three ways: `reconpro list --all` footer ("Total: 28
modules"), `reconpro info --diagnose`
(`module_count: 28, remote_modules: 25, local_modules: 3,
default_modules: 20`), and by counting keys in the source. Every module
is execution-tested in `reconpro/tests/test_module_execution.py`.

## 5. Findings — `reconpro/http_layer.py`

The `Finding` dataclass is the atomic unit of output — 12 fields:

```python
title, severity, category, module, description, evidence, asset,
points_deducted, remediation, dread_score,
confidence,            # 0.0–1.0 (v11.2.0)
verification_state     # VERIFIED_TARGET | PARTIAL_TARGET |
                       # UNREACHABLE_TARGET | UNVERIFIED (v11.2.0)
```

`evidence` is the "show your work" field — what was actually observed
(a secret match, a header value, a DNS error). Full field table and the
JSON it produces: [../reference/API.md](../reference/API.md).

`http_layer.py` is also the audited boundary for TLS: the only two ways
to construct an unverified SSL context are `_unverified_context()`
(reachable only behind explicit `--insecure`/`-k`) and
`inspection_context()` (cert *inspection*, never data transport). An
AST regression test enforces exactly this — see
[../SECURITY.md](../SECURITY.md).

## 6. Results and reports — `reconpro/scanner.py`, `reconpro/reports.py`, `reconpro/formats.py`

- `scan()` (remote) and `audit_scan()` (local) in `scanner.py` return a
  `ReconProResult`; `.to_dict()` is the canonical JSON schema (with
  `target_validation` + `scan_metadata`).
- `reports.py` renders Markdown / HTML / SARIF 2.1.0 / CSV /
  printable-PDF; `formats.py` maps export extensions to writers
  (`.sarif/.md/.markdown/.json/.html/.htm/.pdf`; unknown extensions
  fall back to JSON — documented honestly in
  [../guides/REPORTS.md](../guides/REPORTS.md)).
- SARIF targets GitHub Code Scanning: per-rule
  `properties["security-severity"]`, per-result
  `confidence`/`verification_state`.

## 7. History — `reconpro/history.py`

Every scan is appended to `~/.reconpro/history/` as one JSON file
(`YYYYMMDD_HHMMSS_<target>.json`). The most recent entry is the "last
scan" that `reconpro export`, `report`, `diff` and the SDKs operate on;
`reconpro history` renders the table (stderr — it deliberately has no
`--json` flag).

## Where to go next

- [TESTING.md](TESTING.md) — how the 3301-test suite is chunked and run
- [../security/THREAT_MODEL.md](../security/THREAT_MODEL.md) — the
  security reasoning behind these pieces
- [../reference/CONFIGURATION.md](../reference/CONFIGURATION.md) — what
  lives on disk in `~/.reconpro/`
