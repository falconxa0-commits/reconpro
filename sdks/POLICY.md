# ReconPro SDK Versioning & Compatibility Policy

This document is the contract between the ReconPro CLI (`reconpro`, 11.x line) and
every official SDK (`sdks/python`, `sdks/go`, `sdks/rust`, `sdks/typescript`,
`sdks/node`). It defines how SDKs are versioned, what is (and is not) covered by
compatibility guarantees, and what happens when something breaks.

---

## 1. SemVer

Every SDK package follows **Semantic Versioning 2.0.0** (`MAJOR.MINOR.PATCH`):

- **MAJOR** — incompatible changes to the SDK's public API or to the consumed CLI
  contract (see §3).
- **MINOR** — new, backwards-compatible functionality (new methods, new optional
  parameters, new result fields surfaced as *optional*).
- **PATCH** — bug fixes and documentation, no API changes.

Pre-release tags (`1.0.0-rc.1`) mark Beta-tier packages that are feature-complete
but awaiting CI verification on a real toolchain. They may change before `1.0.0`.

## 2. Stability tiers

| Tier | Meaning | Current members |
|---|---|---|
| **Stable** | API is covered by compatibility guarantees (§3–§5). Safe for production pinning (`^1` ranges). | `reconpro_sdk` (Python, 1.0.0), `reconpro-sdk` (TypeScript, 1.0.0) |
| **Beta** | API is settled but the package has not yet been compiled/tested on its target toolchain in CI after its latest rewrite (Go, Rust: no local toolchain exists — CI (`.github/workflows/sdks.yml`) is the verifier of record). Expect only additive changes before 1.0.0. | `sdk-go` (Go, 1.0.0-rc.1), `reconpro-sdk` (Rust, 1.0.0-rc.1) |
| **Experimental** | Structure/wrapper only; no compatibility promises, may change or be dropped in any release. | `sdks/java` |
| **Maintenance** | Superseded by another SDK; only critical fixes (security, contract breakage) are accepted. | `sdks/node` (plain-JS — superseded by `sdks/typescript`) |

A package may only move *up* a tier after: (a) its full test suite passes against
the pinned CLI version, and (b) for Go/Rust, the `SDKs` CI workflow is green.

## 3. What the compatibility contract is

The CLI is invoked as a subprocess (`reconpro <command> --json`); SDKs never
link the CLI as a library. The contract therefore consists of exactly five
things — **everything else is explicitly NOT part of the contract**:

1. **The JSON schema emitted on STDOUT for `--json` commands** (`scan`, `vibesec`,
   `audit`, `dev`, `doctor`). The canonical shape (CLI 11.2.0) is:
   - top level: `target`, `modules_run`, `total_findings`, `severity_counts`,
     `total_score`, `grade`, `findings[]`, `target_validation`,
     `scan_metadata`, plus optional `vibesec_score`, `vibesec_grade`,
     `badge_markdown`, `module_results`, `intelligence`, `engineering`,
     `quality`, `engineering_score`
   - `findings[]`: `title`, `severity`, `category`, `module`, `description`,
     `evidence`, `asset`, `points_deducted`, `remediation`, `dread_score`,
     `confidence`, `verification_state`
   - `target_validation`: `state` (`VERIFIED_TARGET` | `PARTIAL_TARGET` |
     `UNREACHABLE_TARGET`), `dns_resolved`, `reachable`, `http_ok`,
     `tls_valid`, `details`, `checked_at` — may be `null` for local scans
     (`audit`, `dev`)
   - `scan_metadata`: `scanner`, `started_at`, `duration_s`, `result`
2. **Exit codes**: `0` success · `1` runtime error · `2` usage error ·
   `130` interrupted (SIGINT).
3. **Stream separation** (docker/kubectl convention): machine-readable JSON on
   **stdout**, human pretty UI on **stderr**. SDKs capture stdout and may ignore
   or forward stderr.
4. **Command surface used by SDKs**: `scan <target> [--json] [-o FILE]
   [--modules M] [--insecure] [--timeout S]`, `vibesec <target> --json`,
   `audit --json`, `dev [path] --json`, `doctor --json`, `export <path>`,
   `--version`.
5. **Binary name**: `reconpro` on PATH (configurable per SDK, e.g. env
   `RECONPRO_BINARY` or a constructor option).

**Additive = compatible.** Unknown JSON keys MUST be ignored by SDK parsers,
and new optional CLI flags are not breaking. Missing optional keys MUST default
safely (e.g. `confidence` → `null`, `target_validation` → `null`). SDKs are
required to tolerate both.

**Not part of the contract** (may change in any CLI release without an SDK major):
human-readable text on stderr or stdout of non-`--json` commands, pretty formatting,
progress spinners, `history` table layout, flag aliases not listed above, and the
content/wording of finding descriptions.

## 4. Breaking-change policy

A change is **breaking** if it removes or renames a contract key, changes a
JSON value type incompatibly, changes exit-code semantics, mixes JSON into
stderr, or changes the command surface above.

When a breaking change is unavoidable in the CLI:

1. The CLI ships the new behaviour behind the **same major line** only if both
   shapes can be emitted (never done so far); otherwise the CLI major bumps.
2. The affected SDK releases a **new MAJOR** and simultaneously keeps the previous
   major on a **deprecation window** of at least **90 days / two CLI minor
   releases** (whichever is longer) receiving security and contract fixes only.
3. The SDK major bump ships with: a `MIGRATION.md` section in its README, a
   `DeprecationWarning` (Python) / doc-comment deprecation notice (Go/Rust/TS)
   on removed APIs in the old major, and a CHANGELOG entry.
4. `sdks/POLICY.md` §6 support matrix is updated in the same commit.

## 5. Error-code contract (SDK side)

All SDKs expose structurally equivalent errors with a machine-readable `code`:

| Code | Meaning |
|---|---|
| `BIN_NOT_FOUND` | the `reconpro` binary could not be spawned (bad path / not on PATH) |
| `TIMEOUT` | per-call timeout exceeded (default 300 s; configurable) |
| `NON_ZERO_EXIT` | CLI exited non-zero; `exitCode` + captured `stderr` attached |
| `INVALID_JSON` | CLI exited 0 but stdout was not parseable JSON |

Python/TypeScript additionally use client-side validation codes
(`INVALID_TARGET` for shell-metacharacter targets, `UNSUPPORTED_FORMAT` for bad
export formats). New codes may only be ADDED (never renumbered/renamed).

## 6. Support matrix

| SDK | Package version | Tier | Verified against CLI | Notes |
|---|---|---|---|---|
| Python `reconpro_sdk` | 1.0.0 | Stable | 11.2.0 (local pytest, this repo) | stdlib only |
| TypeScript `reconpro-sdk` | 1.0.0 | Stable | 11.2.0 (local `bun test` + plain-node dist smoke) | zero runtime deps, ships compiled `dist/` |
| Go `sdk-go` | 1.0.0-rc.1 | Beta | 11.2.0 (CI `SDKs` workflow — no local toolchain) | stdlib only |
| Rust `reconpro-sdk` | 1.0.0-rc.1 | Beta | 11.2.0 (CI `SDKs` workflow — no local toolchain) | serde + serde_json only |
| Node `reconpro-sdk` (JS) | 0.2.0 | Maintenance | 11.2.0 (local `node --test`) | superseded by TypeScript SDK |
| Java | — | Experimental | 11.1.0-era contract | not updated this phase |

Supported pairings: **SDK 1.x ↔ CLI 11.x**. SDKs are tolerant of older 11.x
minors (unknown keys ignored, optional keys defaulted) but the pinned
verification target is the CLI version in the row above. The CLI's own
versioning (11.x, currently 11.2.0) follows SemVer at the package level with
`tools/bump_version.py` + release gate; SDK majors are decoupled from CLI
majors — they track the *contract*, not the CLI version number.

## 7. Testing requirements per SDK release

- Python: `/path/to/venv/python -m pytest sdks/python/tests` — must pass.
- TypeScript: `bun test` in `sdks/typescript` + `node tests/dist-smoke.mjs`
  (proves the compiled `dist/` works under plain Node ≥18).
- Go / Rust: `bash sdks/{go,rust}/smoke.sh` — must pass where the toolchain
  exists; CI is the verifier of record. Locally without a toolchain the scripts
  honestly exit 3 (`ENVIRONMENT BLOCKED`) — they never fake a pass.
- Contract tests use the **truth-layer fixture**: a scan of a
  `nonexistent-*.invalid` target is fully offline and MUST return
  `grade == "U"`, `target_validation.state == "UNREACHABLE_TARGET"`, one honest
  info finding, and `confidence`/`verification_state` on every finding.
