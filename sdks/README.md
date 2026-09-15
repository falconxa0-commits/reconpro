# ReconPro SDKs

Five minimal SDKs wrapping the ReconPro CLI (v11.1.0) — every SDK shells out as
`$RECONPRO_PYTHON -m reconpro.cli <args>` with an **ARGUMENT LIST** (never a
shell string), exposes `version()` / `doctor()` / `history()` / `scan(target)` /
`export(path, format)`, configures the python executable via `RECONPRO_PYTHON`
(default `/home/z/.venv/bin/python3`), uses a 120s default timeout, and reports
typed errors carrying the CLI exit code + stderr.

## Status matrix

| Language | Status | How to run tests | Entry point |
|---|---|---|---|
| Python | **TESTED** — `5 passed, 1 skipped` (pytest; skip = network scan test) | `cd /home/z/my-project/download/reconpro-github && /home/z/.venv/bin/python3 -m pytest sdks/python/tests -q` | `sdks/python/reconpro_sdk/client.py` (`ReconProClient`) |
| Node.js | **TESTED** — `6 pass / 0 fail` (node:test, node v24.19.0) | `node --test "sdks/node/test/*.test.js"` (from repo root) or `cd sdks/node && npm test` | `sdks/node/src/index.js` (`ReconProClient`) |
| Java | **TESTED** — `ALL TESTS PASSED` (5/5 hand asserts) + offline example | `cd sdks/java && bash build.sh` | `sdks/java/src/main/java/com/reconpro/sdk/ReconProClient.java` |
| Go | **TESTED** — build + vet + all tests + offline example pass on GitHub Actions (Go 1.22, ubuntu-latest; `.github/workflows/sdks.yml`) | locally where Go exists: `cd sdks/go && bash smoke.sh` | `sdks/go/client.go` (package `reconpro`) |
| Rust | **TESTED** — build + all tests + offline example pass on GitHub Actions (Rust stable, ubuntu-latest; `.github/workflows/sdks.yml`) | locally where Rust exists: `cd sdks/rust && bash smoke.sh` | `sdks/rust/src/client.rs` (crate `reconpro_sdk`) |

Go and Rust were authored without local toolchains; their first real
compilation happened in the `SDKs` CI workflow, which caught and fixed two
real Rust bugs (a `build_args` lifetime error and a test env-restore bug).
Both SDKs now build and pass tests on every push to `main`.

## Verified CLI quirks (all SDKs adapted to these)

- `--version` → `ReconPro 11.1.0` on STDOUT, exit 0.
- `doctor --json` → JSON on STDOUT, exit 0 (human output without `--json` goes to STDERR).
- `history` has **no** `--json` flag: passing it exits 2 with an argparse usage error on
  STDERR. The human table also goes to STDERR. → all `history()` methods return raw text.
- `export <path>` takes a single output path; format auto-detected from the extension
  (`.sarif/.md/.json/.html`). Requires a previous scan — `export()` is implemented in
  all five SDKs but **untested** (no network scans were run in this environment).
- Java toolchain quirk: this sandbox ships a JRE-only OpenJDK 21 (no `javac`);
  `sdks/java/build.sh` falls back to the Eclipse batch compiler (ecj via `java -jar`).
- Node quirk (v24.19.0): `node --test <dir>` fails (`MODULE_NOT_FOUND`) — use a glob.

## Offline examples

All examples take `--offline` (skips the network `scan` call):
`sdks/{python/examples/basic.py, node/examples/basic.mjs, java/examples/Basic.java,
go/examples/basic/main.go, rust/examples/basic.rs}`.
