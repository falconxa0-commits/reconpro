# SDKs — wrapping the CLI from other languages

`sdks/` contains five minimal, consistent wrappers around the
`reconpro` CLI (v11.1.0). Every SDK invokes the CLI as
`$RECONPRO_PYTHON -m reconpro.cli <args>` with an **argument list**
(never a shell string), uses a 120 s default timeout, and reports typed
errors carrying the CLI exit code + stderr.

Shared configuration across all five:

| Variable | Default | Meaning |
|---|---|---|
| `RECONPRO_PYTHON` | `/home/z/.venv/bin/python3` | python executable used to run the CLI |
| `RECONPRO_ROOT` | `/home/z/my-project/download/reconpro-github` | subprocess cwd |
| `RECONPRO_TIMEOUT` / `RECONPRO_TIMEOUT_MS` | 120 s / 120000 ms | per-call timeout |

## Status matrix (from sdks/README.md — claims verified in-session)

| Language | Status | Tests | Entry point |
|---|---|---|---|
| Python | **TESTED** — 5 passed, 1 skipped (skip = network scan test) | `/home/z/.venv/bin/python3 -m pytest sdks/python/tests -q` | `sdks/python/reconpro_sdk/client.py` |
| Node.js | **TESTED** — 6 pass / 0 fail (node v24.19.0, node:test) | `node --test "sdks/node/test/*.test.js"` (glob required — `node --test <dir>` fails on this node version) or `cd sdks/node && npm test` | `sdks/node/src/index.js` |
| Java | **TESTED** — 5/5 hand asserts + offline example | `cd sdks/java && bash build.sh` (falls back to ecj — the sandbox has a JRE-only OpenJDK 21 without `javac`) | `sdks/java/src/main/java/com/reconpro/sdk/ReconProClient.java` |
| Go | **TESTED** — build + vet + tests + offline example on GitHub Actions (Go 1.22; `.github/workflows/sdks.yml`) | `cd sdks/go && bash smoke.sh` where Go exists | `sdks/go/client.go` |
| Rust | **TESTED** — build + tests + offline example on GitHub Actions (Rust stable; `.github/workflows/sdks.yml`) | `cd sdks/rust && bash smoke.sh` where Rust exists | `sdks/rust/src/client.rs` |

Go and Rust were authored without local toolchains; the `SDKs` CI workflow
performed their first real compilation (catching and fixing two genuine Rust
bugs — a `build_args` lifetime error and a test env-restore bug). Both now
build and pass tests on every push to `main`.

## Common API surface

All five SDKs expose (types vary by language):

- `version()` → `"ReconPro 11.1.0"`
- `doctor()` → parsed (or raw, for zero-dep SDKs) JSON of `doctor --json`
- `history()` → **raw text** — the CLI's `history` has no `--json` flag
  (passing one exits 2); the human table goes to stderr
- `scan(target)` → scan result (network; shell metacharacters in the
  target are rejected client-side)
- `export(path, format)` → export the last scan (implemented
  everywhere, **untested** — it requires a prior scan and no network
  scans were run in this environment)

## Python — `reconpro_sdk`

```python
from reconpro_sdk import ReconProClient

client = ReconProClient()          # env-configured
print(client.version())            # "ReconPro 11.1.0"
print(client.doctor()["grade"])    # "B" (parsed JSON dict)
```

Failures raise `SdkError` with `.exit_code`, `.stderr`, `.command`.
Run the offline example: `python sdks/python/examples/basic.py --offline`.

## Node.js — `reconpro-sdk` (zero-dependency ESM)

```js
import { ReconProClient } from "sdks/node/src/index.js";

const client = new ReconProClient();
console.log(await client.version());   // "ReconPro 11.1.0"
console.log((await client.doctor()).grade);
```

Errors: `SdkError` with `.exitCode`, `.stderr`, `.command`.
Run: `node sdks/node/examples/basic.mjs --offline`.

## Java — `ReconProClient` (JDK 17+, zero-dependency)

```java
ReconProClient client = new ReconProClient();
System.out.println(client.version());    // "ReconPro 11.1.0"
System.out.println(client.doctor());     // raw JSON string (no parser included)
```

`run(cliArgs)` returns a `Result` record `(exitCode, stdout, stderr)`.
Errors: `ReconProClient.SdkException` with `.exitCode` and
`.stderrText`. Build + test: `cd sdks/java && bash build.sh`.

## Go — package `reconpro` (CI-verified)

```go
client := reconpro.NewClient()
ver, err := client.Version()          // "ReconPro 11.1.0"
doctor, err := client.Doctor()        // map[string]any from doctor --json
```

`exec.CommandContext` with an argument list; killed on deadline.
Errors carry exit status + stderr.

## Rust — crate `reconpro_sdk` (CI-verified, std-only)

```rust
let client = Client::default();
let ver = client.version()?;          // "ReconPro 11.1.0"
let doctor = client.doctor()?;        // raw JSON string (std-only)
```

`SdkError` enum: `Exit(String)` / `Io(String)`; child killed on
deadline via `try_wait` polling.

## SDK-visible CLI quirks (all verified)

- `--version` → stdout, exit 0.
- `doctor --json` → JSON on stdout, exit 0; the human (Rich) output and
  the banner go to **stderr**.
- `history` → no `--json` flag (exit 2 with usage on stderr); table on
  stderr.
- `export <path>` → format auto-detected from extension
  (`.sarif/.md/.json/.html`); requires a previously saved scan.

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for the full command surface
and [GETTING_STARTED.md](GETTING_STARTED.md) for the JSON/stderr
convention.
