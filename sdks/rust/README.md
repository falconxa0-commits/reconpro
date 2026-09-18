# reconpro-sdk (Rust) — Beta

Typed Rust SDK around the ReconPro CLI (>= 11.2.0). Every call shells out via
`std::process::Command` with an **argument list** — never a shell string — and
deserializes the JSON contract from STDOUT with serde; the CLI's pretty UI
goes to STDERR (docker/kubectl convention) and is captured only for error
reporting.

Stability tier: **Beta (1.0.0-rc.1)** — versioning & compatibility policy:
[`../POLICY.md`](../POLICY.md). This SDK has **no local Rust toolchain** to
compile it (honest environment limitation); the `SDKs` CI workflow
(`.github/workflows/sdks.yml`) builds and tests it on every push.

## API

| Method | Returns | Notes |
|---|---|---|
| `Client::new()` | `Client` | binary via `RECONPRO_BINARY` env, default `"reconpro"` on PATH; 300 s default timeout (pub fields `binary_path` / `timeout` to override) |
| `version()` | `Result<String, SdkError>` | verification ping (`reconpro --version`), e.g. `"ReconPro 11.2.0"` |
| `scan(target)` | `Result<ScanResult, SdkError>` | remote scan; offline `*.invalid` demo returns grade `"U"` + `UNREACHABLE_TARGET` |
| `vibesec(target)` | `Result<ScanResult, SdkError>` | vibesec module scan |
| `audit()` | `Result<ScanResult, SdkError>` | local host/dev audit (offline) |
| `dev(path)` | `Result<ScanResult, SdkError>` | scan a local directory (offline) |
| `doctor()` | `Result<ScanResult, SdkError>` | local health check (offline) |
| `export(path, format)` | `Result<String, SdkError>` | CLI `export`; format `sarif`/`md`/`json`/`html` (extension appended when missing) |

`ScanResult` is fully typed for the CLI 11.2.0 contract: `target`,
`modules_run`, `total_findings`, `severity_counts`, `total_score`, `grade`,
`findings` (each `Finding` carries the truth-layer `confidence:
Option<f64>` and `verification_state: Option<String>`),
`target_validation: Option<TargetValidation>` (`state` / `dns_resolved` /
`reachable` / `http_ok` / `tls_valid` / `details` / `checked_at`; `None`
for local scans), `scan_metadata: Option<ScanMetadata>` (`scanner` /
`started_at` / `duration_s` / `result`), plus the `unreachable()` helper.
Every field carries a `#[serde(default)]`, so results from **older CLIs**
(no truth-layer fields) and **newer CLIs** (unknown extra keys, ignored by
serde) both deserialize — additive-tolerant per `sdks/POLICY.md` §3.

## Errors (matchable enum)

| `SdkError` variant | Meaning | Payload |
|---|---|---|
| `Io(String)` | spawn/stream failure (binary not found) | message mentions the binary |
| `Timeout { seconds }` | per-call timeout exceeded (process killed) | |
| `NonZeroExit { code, stderr }` | CLI exited non-zero | exit code (0/1/2/130 contract) + captured stderr |
| `InvalidJson(String)` | exit 0 but stdout not parseable JSON | message carries the output head |
| `InvalidUsage(String)` | client-side validation (bad target / bad export format) | |

## Dependencies

`serde` (derive) + `serde_json` only — by policy (`sdks/POLICY.md`).

## Run tests (where Rust exists)

```
cd sdks/rust && bash smoke.sh    # cargo build --all-targets && cargo test && offline examples
# or directly:  cargo test
```

`cargo test` is **hermetic** — every CLI-backed case runs against a tiny
shell-script stub binary emitting canned JSON byte-faithful to CLI 11.2.0
(including a `future_field` unknown key to pin forward-compatibility), so no
reconpro installation is needed. The truth-layer contract test asserts
grade `"U"`, `target_validation.state == UNREACHABLE_TARGET`, finding
`confidence == 0.95`, `verification_state == "UNREACHABLE_TARGET"`.

## Examples

- `examples/basic.rs` — version ping + typed scan result (offline `*.invalid`
  demo by default; pass a real target for a live scan)
- `examples/export.rs` — scan then export SARIF + Markdown
- `examples/error_handling.rs` — every `SdkError` variant, matched

## Files

`src/lib.rs`, `src/client.rs` (entry point), `tests/client.rs`,
`examples/{basic,export,error_handling}.rs`, `Cargo.toml`, `smoke.sh`.
