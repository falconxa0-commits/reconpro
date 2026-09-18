# SDKs — driving the CLI from Python, TypeScript, Go, Rust, Node

`sdks/` contains six wrappers around the `reconpro` CLI (v11.2.0
contract). Every SDK spawns the **`reconpro` binary itself** with an
**argument list** (never a shell string), parses the machine-readable
JSON from **stdout**, and ignores the human output on stderr
(the docker/kubectl convention). All of them expose the same core
surface — `version()`, `scan(target)`, `audit()`, `dev(path)`,
`doctor()`, `export(path, format)` — with **typed results for the
truth layer** (`target_validation.state`,
per-finding `confidence` + `verification_state`) and structured
errors carrying the CLI exit code + stderr.

Versioning, stability tiers and the compatibility contract:
[`sdks/POLICY.md`](../sdks/POLICY.md).

## Status matrix (v11.2.0)

| SDK | Tier | Config (env) | Tests |
|---|---|---|---|
| [`python/`](../sdks/python) — `reconpro_sdk` 1.0.0 | **Stable** | `RECONPRO_BINARY` (default `reconpro`), `RECONPRO_TIMEOUT` (300 s) | **28 passed** locally (venv pytest vs CLI 11.2.0) + CI |
| [`typescript/`](../sdks/typescript) — `reconpro-sdk` 1.0.0 | **Stable** | `RECONPRO_BINARY`, `RECONPRO_TIMEOUT_MS` (300 000 ms) | **22 pass** (bun test) + plain-node dist smoke, locally + CI |
| [`go/`](../sdks/go) — `sdk-go` 1.0.0-rc.1 | **Beta** | `RECONPRO_BINARY` | CI is the verifier of record (`.github/workflows/sdks.yml`) |
| [`rust/`](../sdks/rust) — `reconpro-sdk` 1.0.0-rc.1 | **Beta** | `RECONPRO_BINARY` | CI is the verifier of record (`.github/workflows/sdks.yml`) |
| [`node/`](../sdks/node) — `reconpro-sdk` 0.2.0 (plain JS) | **Maintenance** | `RECONPRO_PYTHON`, `RECONPRO_ROOT`, `RECONPRO_TIMEOUT_MS` | **8 pass** (node:test, stub-backed); superseded by `typescript/` |
| [`java/`](../sdks/java) | **Experimental** | — | structure-only wrapper; not yet on the 11.2.0 contract |

Default timeout is **300 s** per call in the Stable SDKs. On machines
without Go/Rust toolchains the local `smoke.sh` scripts exit 3
("ENVIRONMENT BLOCKED") rather than fake a pass — the `SDKs` GitHub
Actions workflow is the verifier of record for those two.

## The one-paragraph contract

What the SDKs promise (from
[`sdks/POLICY.md`](../sdks/POLICY.md) §3): the **JSON schema on stdout**
for `--json` commands, the **exit codes** (0 success · 1 runtime error ·
2 usage error · 130 interrupted), the **stream separation**, the
**command surface**, and the **binary name**. Everything else is not
covered. SDKs are **additive-tolerant**: unknown JSON keys are ignored
(kept in a `raw` view) and missing optional keys default safely
(`confidence` → `null`, `target_validation` → `null`) — an older SDK
keeps working against a newer CLI.

Error codes are stable and equivalent across languages:
`BIN_NOT_FOUND` / `TIMEOUT` / `NON_ZERO_EXIT` / `INVALID_JSON`
(plus client-side `INVALID_TARGET` / `UNSUPPORTED_FORMAT` where
applicable) — [`sdks/POLICY.md`](../sdks/POLICY.md) §5.

## Python — `reconpro_sdk` (Stable)

Stdlib-only; frozen dataclasses (`ScanResult`, `Finding`,
`TargetValidation`, `ScanMetadata`) with a `.raw` escape hatch:

```python
from reconpro_sdk import ReconProClient

client = ReconProClient()            # binary: arg → RECONPRO_BINARY → "reconpro" on PATH
print(client.version())              # ReconPro 11.2.0
result = client.scan("nonexistent-demo.invalid")     # offline: truth layer answers
print(result.grade, result.target_validation.state)  # U UNREACHABLE_TARGET
f = result.findings[0]
print(f.confidence, f.verification_state)           # 0.95 UNREACHABLE_TARGET
print(client.export("/tmp/report.sarif"))            # SARIF 2.1.0 from the last scan
```

*(This exact snippet was executed against the real CLI while writing
this page — the printed values are real.)* Failures raise `SdkError`
with `.code`, `.exit_code`, `.stderr`, `.command`. Methods: `version`,
`scan`, `vibesec`, `audit`, `dev`, `doctor`, `export`. Install:
`pip install -e sdks/python`; run the suite:
`python -m pytest sdks/python/tests -q` → 28 passed.

## TypeScript — `reconpro-sdk` (Stable)

Zero runtime dependencies, ESM, node ≥ 18; ships a compiled `dist/`
with hand-maintained `.d.ts`:

```ts
import { ReconProClient } from "reconpro-sdk";

const client = new ReconProClient();          // { binaryPath?, timeoutMs? }
const version = await client.version();       // ReconPro 11.2.0
const result = await client.scan("nonexistent-demo.invalid");
console.log(result.grade, result.targetValidation?.state); // U UNREACHABLE_TARGET
await client.exportReport("sarif");
```

`ReconProError` carries `.code` (the six-code union), `.exitCode`,
`.stderr`, `.command`. Tests: `bun test` (22 pass) +
`node tests/dist-smoke.mjs` (compiled-dist smoke).

## Go — package `reconpro` (Beta)

```go
client := reconpro.NewClient()                // RECONPRO_BINARY env → "reconpro"
version, _ := client.Version(ctx)             // ReconPro 11.2.0
result, _ := client.Scan(ctx, "nonexistent-demo.invalid")
fmt.Println(result.Grade, result.TargetValidation.State) // U UNREACHABLE_TARGET
```

Typed `ScanResult`/`Finding`/`TargetValidation`/`ScanMetadata` + `Raw
map[string]any`; `CommandError` / `TimeoutError` / `JSONError`;
`context.Context` on every method; `exec.CommandContext` with an
argument list, killed on deadline.

## Rust — crate `reconpro_sdk` (Beta)

```rust
let client = reconpro_sdk::Client::new();     // RECONPRO_BINARY env → "reconpro"
let version = client.version()?;              // ReconPro 11.2.0
let result = client.scan("nonexistent-demo.invalid")?;
println!("{} {}", result.grade, result.target_validation.as_ref().unwrap().state);
```

serde defaults everywhere (legacy + future CLIs parse); `SdkError`
enum (`Io`/`Timeout`/`NonZeroExit`/`InvalidJson`/`InvalidUsage`);
pipe-drain reader threads + `try_wait` deadline kill.

## Node.js, plain JS — `sdks/node` (Maintenance)

Kept working, superseded by `typescript/`:

```js
import { ReconProClient } from "sdks/node/src/index.js";   // RECONPRO_PYTHON/RECONPRO_ROOT/RECONPRO_TIMEOUT_MS
const client = new ReconProClient();
const report = await client.scan("nonexistent-demo.invalid");
console.log(report.grade, report.target_validation.state); // U UNREACHABLE_TARGET
```

## SDK-visible CLI behavior (all verified)

- `--version` → stdout, exit 0.
- `--json` commands → JSON on stdout; banner + Rich tables → stderr.
- Unreachable targets are an **honest exit-0 result** (`grade "U"`,
  `target_validation.state "UNREACHABLE_TARGET"`,
  `scan_metadata.result "unreachable_target_short_circuit"`) — SDKs do
  not raise for them; that is the truth layer working.
- `history` has **no** `--json` flag (exit 2) — the table goes to stderr.
- `export <path>` auto-detects the format from the extension and needs a
  previously saved scan.

See [reference/CLI_REFERENCE.md](reference/CLI_REFERENCE.md) for the
full command surface, [reference/API.md](reference/API.md) for the JSON
schema, and [`sdks/README.md`](../sdks/README.md) for the per-SDK
verification evidence.
