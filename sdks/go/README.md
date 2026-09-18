# reconpro-sdk (Go) — Beta

Thin Go SDK around the ReconPro CLI (>= 11.2.0). Every call shells out via
`exec.CommandContext` with an **argument list** (never a shell string) and
parses the JSON contract from STDOUT; the CLI's pretty UI goes to STDERR.

Stability tier: **Beta (1.0.0-rc.1)** — versioning & compatibility policy:
[`../POLICY.md`](../POLICY.md). This SDK has **no local Go toolchain** to
compile it (honest environment limitation); the `SDKs` CI workflow
(`.github/workflows/sdks.yml`) builds, vets, and tests it on every push.

## API (all methods take a `context.Context` first)

| Method | Returns | Notes |
|---|---|---|
| `NewClient()` | `*Client` | binary via `RECONPRO_BINARY` env, default `"reconpro"` on PATH; 5 min default timeout |
| `Version(ctx)` | `(string, error)` | verification ping (`reconpro --version`) |
| `Scan(ctx, target)` | `(*ScanResult, error)` | remote scan; offline `*.invalid` demo returns grade `"U"` + `UNREACHABLE_TARGET` |
| `Vibesec(ctx, target)` | `(*ScanResult, error)` | vibesec module scan |
| `Audit(ctx)` | `(*ScanResult, error)` | local host/dev audit (offline) |
| `Dev(ctx, path)` | `(*ScanResult, error)` | scan a local directory (offline) |
| `Doctor(ctx)` | `(*ScanResult, error)` | local health check (offline) |
| `Export(ctx, path, format)` | `(string, error)` | CLI `export`; format `sarif`/`md`/`json`/`html` (extension appended when missing) |

`ScanResult` is fully typed for the CLI 11.2.0 contract: `Target`,
`ModulesRun`, `TotalFindings`, `SeverityCounts`, `TotalScore`, `Grade`,
`Findings[]` (each with the truth-layer `Confidence *float64` and
`VerificationState *string`), `TargetValidation` (`State`/`DnsResolved`/
`Reachable`/`HttpOK`/`TlsValid`/`Details`/`CheckedAt`, `nil` for local
scans), `ScanMetadata` (`Scanner`/`StartedAt`/`DurationS`/`Result`), plus
`Raw map[string]any` (the complete decoded document — unknown future keys
stay accessible) and the `Unreachable()` helper. Unknown JSON keys are
ignored by `encoding/json`, so newer CLIs remain compatible.

## Errors (use `errors.As`)

| Type | Meaning | Fields |
|---|---|---|
| `*CommandError` | CLI exited non-zero | `ExitCode` (0/1/2/130 contract), `Stderr`, `Command` |
| `*TimeoutError` | per-call timeout exceeded | `Timeout`, `Command` |
| `*JSONError` | exit 0 but stdout not JSON (implements `Unwrap`) | `Err`, `Details` (stdout head) |
| wrapped `error` | spawn failure (binary not found) | message mentions the binary |

## Run tests

`go test ./...` is **hermetic** — every CLI-backed case runs against a tiny
shell-script stub binary (canned JSON byte-faithful to CLI 11.2.0), so no
reconpro installation is needed:

```
cd sdks/go && bash smoke.sh   # build + vet + hermetic tests + offline examples
```

## Examples

- `examples/basic` — version ping + typed scan result (offline by default,
  `--target example.com` for a live scan)
- `examples/export` — scan then export SARIF + Markdown
- `examples/error-handling` — every error type, `errors.As` branching
