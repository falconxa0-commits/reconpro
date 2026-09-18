# ReconPro SDKs

Official SDKs wrapping the ReconPro CLI (>= 11.2.0). Every SDK shells out as
`reconpro <command> --json` with an **argument list** (never a shell string),
parses the machine-readable JSON from STDOUT, and ignores/forwards the
pretty UI on STDERR (docker/kubectl convention). All of them expose the
same core surface — `version()` (verification ping), `scan(target)`,
`audit()`, `dev(path)`, `export(path, format)` — with typed results for the
CLI 11.2.0 JSON contract (including the truth layer: `target_validation`
with `VERIFIED_TARGET` / `PARTIAL_TARGET` / `UNREACHABLE_TARGET`, and
per-finding `confidence` + `verification_state`) and structured errors
carrying the CLI exit code + stderr.

**Versioning, stability tiers, and the compatibility contract** (what is
and is not covered, breaking-change policy, support matrix):
**[`POLICY.md`](POLICY.md)**.

## Ecosystem

| SDK | Tier | Test command | Verification |
|---|---|---|---|
| [`python/`](python) — `reconpro_sdk` 1.0.0 | **Stable** | `python -m pytest sdks/python/tests -q` | **Local run: 28 passed** (venv pytest vs CLI 11.2.0; CLI-backed + hermetic stub tests) |
| [`typescript/`](typescript) — `reconpro-sdk` 1.0.0 | **Stable** | `cd sdks/typescript && bun test && node tests/dist-smoke.mjs` | **Local run: 22 pass / 0 fail** (bun 1.3.14) + dist smoke under plain node; stub + real CLI |
| [`go/`](go) — `sdk-go` 1.0.0-rc.1 | **Beta** | `cd sdks/go && bash smoke.sh` | **CI is the verifier of record** (`.github/workflows/sdks.yml`: Go 1.22 — build, vet, hermetic tests, offline examples; runs on push/PR). No local Go toolchain in the authoring sandbox — the 11.2.0-contract rewrite awaits its first CI run |
| [`rust/`](rust) — `reconpro-sdk` 1.0.0-rc.1 | **Beta** | `cd sdks/rust && bash smoke.sh` | **CI is the verifier of record** (`.github/workflows/sdks.yml`: Rust stable — build, tests, offline examples; runs on push/PR). No local Rust toolchain in the authoring sandbox — the 11.2.0-contract rewrite awaits its first CI run |
| [`node/`](node) — `reconpro-sdk` 0.2.0 (JS) | **Maintenance** | `cd sdks/node && npm test` | **Local run: 8 pass / 0 fail** (node:test, stub-backed). Superseded by `typescript/` |
| [`java/`](java) | **Experimental** | `cd sdks/java && bash build.sh` | structure-only wrapper, not updated to the 11.2.0 contract this phase |

Tier meanings, per-SDK support matrix, and the full rules: [`POLICY.md`](POLICY.md) §2/§6.

## Quick example per SDK

Every snippet below scans a nonexistent `*.invalid` target — the CLI truth
layer short-circuits unreachable targets **offline and instantly**
(`grade == "U"`, `target_validation.state == "UNREACHABLE_TARGET"`, one
honest info finding) — so they run without network access.

### Python (`sdks/python`)

```python
from reconpro_sdk import ReconProClient, SdkError

client = ReconProClient()            # binary: arg → RECONPRO_BINARY env → "reconpro"
print(client.version())              # ReconPro 11.2.0
result = client.scan("nonexistent-demo.invalid")
print(result.grade, result.target_validation.state)      # U UNREACHABLE_TARGET
print(result.findings[0].confidence, result.findings[0].verification_state)
print(client.export("/tmp/report.sarif"))
```

### TypeScript (`sdks/typescript`)

```ts
import { ReconProClient, UNREACHABLE_TARGET } from "reconpro-sdk";

const client = new ReconProClient();         // { binaryPath?, timeoutMs? }
const version = await client.version();       // ReconPro 11.2.0
const result = await client.scan("nonexistent-demo.invalid");
console.log(result.grade, result.targetValidation?.state); // U UNREACHABLE_TARGET
console.log(result.findings[0]?.confidence, result.findings[0]?.verificationState);
await client.exportReport("sarif");
```

### Go (`sdks/go`)

```go
client := reconpro.NewClient()                // RECONPRO_BINARY env → "reconpro"
version, _ := client.Version(ctx)             // ReconPro 11.2.0
result, _ := client.Scan(ctx, "nonexistent-demo.invalid")
fmt.Println(result.Grade, result.TargetValidation.State) // U UNREACHABLE_TARGET
fmt.Println(result.Findings[0].Confidence, *result.Findings[0].VerificationState)
sarif, _ := client.Export(ctx, "/tmp/report.sarif", "sarif")
```

### Rust (`sdks/rust`)

```rust
let client = reconpro_sdk::Client::new();     // RECONPRO_BINARY env → "reconpro"
let version = client.version()?;              // ReconPro 11.2.0
let result = client.scan("nonexistent-demo.invalid")?;
println!("{} {}", result.grade, result.target_validation.as_ref().unwrap().state);
let f = &result.findings[0];
println!("{} {:?}", f.confidence, f.verification_state);
let sarif = client.export("/tmp/report.sarif", "sarif")?;
```

### Node.js, plain JS (`sdks/node` — maintenance)

```js
import { ReconProClient } from "reconpro-sdk"; // sdks/node
const client = new ReconProClient();
const report = await client.scan("nonexistent-demo.invalid");
console.log(report.grade, report.target_validation.state);
```

## The contract in one paragraph

The JSON schema on STDOUT for `--json` commands, the exit codes
(0 success · 1 runtime error · 2 usage error · 130 interrupted), the
stream separation, the command surface, and the binary name are the
contract — **everything else is not** (see [`POLICY.md`](POLICY.md) §3).
SDKs are additive-tolerant: unknown JSON keys are ignored (kept in a `raw`
view) and missing optional keys default safely (`confidence` → `null`,
`target_validation` → `null`). Error codes on the SDK side are stable and
equivalent across languages: `BIN_NOT_FOUND` / `TIMEOUT` / `NON_ZERO_EXIT` /
`INVALID_JSON` (plus client-side `INVALID_TARGET` / `UNSUPPORTED_FORMAT`
where applicable) — [`POLICY.md`](POLICY.md) §5.

## Honest verification status

- **Python, TypeScript, Node (JS)**: test suites were executed locally in
  this repository against CLI 11.2.0 (venv `reconpro`) — exact commands and
  results above.
- **Go, Rust**: authored without local toolchains (the sandbox has none);
  the `SDKs` GitHub Actions workflow is the verifier of record. Their local
  `smoke.sh` scripts exit 3 ("ENVIRONMENT BLOCKED") rather than fake a pass.
  Note: the pre-rewrite Go/Rust sources passed that CI on earlier commits;
  the current 11.2.0-contract rewrites (typed truth-layer fields, stub-binary
  tests) have not yet been compiled anywhere — first compile happens on the
  next CI run after these changes are pushed.
- All hermetic tests (every SDK) run against tiny stub binaries emitting
  canned JSON byte-faithful to CLI 11.2.0 — no CLI installation needed for
  `go test` / `cargo test` / `bun test` / `pytest` / `node --test`.
