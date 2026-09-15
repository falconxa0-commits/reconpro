# reconpro-sdk (Rust)

Thin, std-only (zero-dependency) Rust wrapper around the ReconPro CLI
(`python -m reconpro.cli`). Every call uses `std::process::Command` with an
**argument list** — never a shell string.

> **STATUS: COMPILE-BLOCKED — rust toolchain absent in this environment.**
> Neither `cargo` nor `rustc` is installed in the sandbox where this SDK was
> written, so `src/client.rs`, `tests/client.rs`, and `examples/basic.rs` have
> NOT been compiled or run. Run `bash smoke.sh` where Rust exists before trusting it.

## API
| Method | Returns | Notes |
|---|---|---|
| `version()` | `Result<String, SdkError>` | e.g. `"ReconPro 11.1.0"` |
| `doctor()` | `Result<String, SdkError>` | raw JSON of `doctor --json` (std-only: no JSON parser) |
| `history()` | `Result<String, SdkError>` | raw text — CLI quirk: `history` has **no** `--json` flag; table on STDERR |
| `scan(target)` | `Result<String, SdkError>` | raw JSON; network; shell metacharacters rejected client-side |
| `export(path, format)` | `Result<String, SdkError>` | CLI `export` subcommand, format from extension |

## Errors
`SdkError` enum: `Exit(String)` (nonzero exit / timeout / invalid output; message
carries exit code + stderr) and `Io(String)` (spawn / stream failure).

## Config
- env `RECONPRO_PYTHON` (default `/home/z/.venv/bin/python3`)
- env `RECONPRO_ROOT` (default `/home/z/my-project/download/reconpro-github`) — subprocess cwd
- `Client { timeout }` — default 120s (polling `try_wait`, child killed on deadline)

## Run tests (where Rust exists)
```
cd sdks/rust && bash smoke.sh    # cargo build --all-targets && cargo test && example
# or directly:  cargo test
```
Tests: `version` (asserts "11.1.0"), `bad_python` (env `RECONPRO_PYTHON=/nonexistent`
→ `SdkError::Io`), `build_args_uses_argument_list`, `scan_rejects_shell_metacharacters`.

## Files
`src/lib.rs`, `src/client.rs` (entry point), `tests/client.rs`,
`examples/basic.rs`, `Cargo.toml`, `smoke.sh`.
