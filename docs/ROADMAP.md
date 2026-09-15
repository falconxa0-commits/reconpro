# ReconPro Roadmap

Where the project is going. Statuses are honest: **proposed** = not started,
**in-progress** = work has landed partially, **shipped** = done and verified.
Dates are targets, not promises — this is a direction document, and items
move only when their verification story moves with them.

Current release: **v11.1.0** (live on
[PyPI](https://pypi.org/project/reconpro/) and
[GitHub Releases](https://github.com/falconxa0-commits/reconpro/releases)).

## v11.2.0 — depth and polish (next minor)

| # | Feature | Why | Status |
|---|---|---|---|
| 1 | **Sdist byte-reproducibility** | the wheel is byte-identical across builds; the sdist is not (tar/gzip nondeterminism under setuptools). Fix via `tarfile` + `SOURCE_DATE_EPOCH` normalization so both artifacts verify bit-for-bit | proposed |
| 2 | **GPG public key distribution** | v11.1.0 ships `SHA256SUMS.asc` but the GPG public key was never published, so third parties can only verify via Ed25519 (which *is* in-repo). Publish the GPG pubkey in `tools/keys/` + README, and add it to the `verify` flow | proposed |
| 3 | **`ruff` rule-set expansion** | CI lints `E9,F63` (fatal errors) today because of 7 pre-existing `F821` hits in dead code. Delete the dead code, move CI to a strict selection (`E,F,W,I` minimum) via `[tool.ruff]` in `pyproject.toml` | proposed |
| 4 | **Full-suite pytest in one invocation** | the suite currently runs in chunks because a single full `pytest` hangs (known issue). Root-cause the hang (suspected: shared event loops / textual fixtures), retire `tools/ci_test_groups.txt` | proposed |
| 5 | **Windows + macOS first-class CI matrix** | CI is ubuntu-only today. Add `windows-latest`/`macos-latest` to `ci.yml`, fix what falls over, document platform caveats honestly | proposed |
| 6 | **Report themes** | `reconpro report` already emits MD/JSON/HTML/SARIF; add selectable HTML themes + a dark mode for the HTML report | proposed |
| 7 | **`reconpro compliance` framework packs** | map findings to CIS Benchmarks and DISA STIG IDs alongside the existing MITRE ATT&CK mapping | proposed |
| 8 | **JetBrains plugin: real IDE host verification** | the plugin skeleton is structurally validated only (no IDE host ran it). Stand up gradle-intellij verify task or a marketplace CI channel | proposed |
| 9 | **Performance: cold start < 30 ms** | ~46 ms median today (from ~570 ms). Finish lazy-import coverage for `graph`/`intel` clusters | proposed |
| 10 | **SDK parity: `audit` + `export` methods** | SDKs wrap `scan` JSON today; expose typed `audit()`, `export(format)` and streaming progress callbacks across python/node/go/rust/java | proposed |

## v11.3.x — enterprise features

The enterprise track. Everything below assumes the v11.2 foundation
(reproducibility, stricter lint, platform matrix).

- **RBAC policy packs** — role files (`scanner`, `auditor`, `admin`) that
  gate which commands/modules a user may invoke; enforced in the CLI before
  any module runs, violations audited.
- **Audit event stream** — every scan, plugin install, export and policy
  decision emits a signed JSONL event (append-only, hash-chained) suitable
  for SIEM ingestion (Splunk/ELK/Graylog) and after-the-fact attestation.
- **SIEM export connectors** — first-class formats beyond SARIF: Splunk CIM,
  Elastic ECS, OSV-for-deps; `reconpro export --format ecs`.
- **Air-gapped operation** — offline threat-intel bundles with signature +
  freshness verification, documented proxy allow-lists, zero telemetry
  (already true today — keep it provable).
- **Compliance reporting** — one command: `reconpro compliance --framework
  soc2,iso27001 --period Q3` producing an evidence-backed control mapping
  from scan history.
- **Signed policy packs** — org scan policies (module allow-lists, rate
  limits, severity thresholds) as Ed25519-signed TOML; `--policy org.toml`
  verifies before use.
- **Long-term support window** — publish a written LTS policy for patch
  releases of the latest minor.

## v12.0 — plugin marketplace

A registry for the sandboxed plugin SDK — the SDK, signer, verifier and
drift detection all exist today; the marketplace is distribution on top.

- **`reconpro plugin search/install/upgrade <name>@<version>`** against a
  registry index (static JSON to start — a CDN bucket, no server needed).
- **Registry index format** — signed index JSON: plugin id, versions,
  source hash, Ed25519 signature, publisher key id, sandbox permission
  class, minimum CLI version.
- **Publisher key distribution** — a trust root file shipped with the CLI
  mapping publisher ids to public keys; installing a plugin requires a
  valid chain: trust-root → publisher key → plugin signature → source hash.
- **Permission classes at install time** — `network=none | egress-list |
  domains-list`, surfaced in `plugin install` output and enforced by the
  existing sandbox audit hook.
- **Ratings & attestations (later)** — download counts, publisher
  attestations, automated re-verification bot that re-runs `plugin verify`
  daily against the index.
- **`plugin bundle`** — pin a set of plugins + versions + hashes as one
  installable, so teams share an identical scanning surface.

## v12.x — cloud dashboard

A hosted console over the same engine. The constraint: the CLI remains
fully functional standalone — the dashboard is an optional lens.

- **Scan orchestration** — queue, run and fan out scans across runners;
  live status over WebSocket; retry/cancel; per-target rate limits.
- **Live findings feed** — streaming severity-tagged findings as scans
  produce them (the CLI's JSON stream, relayed).
- **Trend & regression views** — score-over-time per target, new-vs-fixed
  finding deltas (the `reconpro diff` engine, elevated).
- **Shared report links** — signed, expiring URLs to rendered HTML reports
  (the existing `report` HTML output, hosted).
- **Self-hosted mode** — the dashboard ships as a container with the same
  Ed25519 verification story; no cloud dependency required.

## v12.x — team management

- **Organizations & workspaces** — org → workspace → target hierarchy with
  per-workspace policy packs.
- **Roles** — owner / maintainer / scanner / viewer, mapped onto RBAC
  policy packs; SSO (OIDC) for the dashboard; SCIM for directory sync.
- **Delegated scans** — grant a runner or teammate a narrowly-scoped
  capability ("scan target X, modules recon+auth, expires in 1h") — signed
  capability tokens, verified by the CLI before the run.
- **Shared scan surface** — org-level plugin bundles and module configs so
  everyone grades targets identically.
- **Notification routing** — findings → Slack/Jira/email with severity
  thresholds per workspace (builds on the existing integrations extras).

## Non-goals (explicit)

- **No payload generation / exploitation** — ReconPro finds and explains
  risk; it does not weaponize findings. Not negotiable.
- **No telemetry by default** — opt-in only, ever, and documented.
- **No server-side scanning of third-party targets** — the cloud dashboard
  orchestrates *your* runners against *your* targets.
- **No weakening of the plugin sandbox** — marketplace features may add
  permission classes, never remove the audit hook or rlimits.

## Verification culture (unchanged)

Every roadmap item ships with the same bar as v11.1.0: reproducible
artifacts, signed checksums, SBOM, a `verify` command that actually detects
tampering, and CI that fails loudly. A feature that cannot carry its
verification story does not ship.
