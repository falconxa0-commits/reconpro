# reconpro-sdk (Go)

Thin Go SDK around the ReconPro CLI (`python -m reconpro.cli`). Every call uses
`exec.CommandContext` with an **argument list** — never a shell string.

> **STATUS: COMPILE-BLOCKED — go toolchain absent in this environment.**
> The `go` binary is not installed in the sandbox where this SDK was written, so
> `client.go`, `client_test.go`, and `examples/basic/main.go` have NOT been
> compiled or run. Review + run `bash smoke.sh` where Go exists before trusting it.

## API
| Method | Returns | Notes |
|---|---|---|
| `Version()` | `(string, error)` | e.g. `"ReconPro 11.1.0"`; error includes exit status + stderr |
| `Doctor()` | `(map[string]any, error)` | parsed JSON of `doctor --json` |
| `History(target)` | `(string, error)` | raw text — CLI quirk: `history` has **no** `--json` flag; human table on STDERR |
| `Scan(target)` | `(map[string]any, error)` | network; shell metacharacters rejected client-side |
| `Export(path, format)` | `(string, error)` | CLI `export` subcommand, format from extension (sarif/md/json/html) |

## Config
`Client{PythonPath, Root, Timeout}` fields; `NewClient()` reads `RECONPRO_PYTHON`
(default `/home/z/.venv/bin/python3`) and `RECONPRO_ROOT` (default
`/home/z/my-project/download/reconpro-github`). Default timeout 120s
(`exec.CommandContext`, killed on deadline).

## Run tests (where Go exists)
```
cd sdks/go && bash smoke.sh     # go build ./... && go vet ./... && go test ./...
# or directly:  go test ./...
```
Tests: `TestVersion` (asserts "11.1.0"), `TestVersionBadPythonPath`,
`TestScanRejectsShellMetacharacters` (client-side), `TestBuildArgsUsesArgumentList`,
`TestExportValidatesFormat`. Set `RECONPRO_SKIP=1` to skip CLI-backed tests.

## Files
`client.go` (entry point), `client_test.go`, `examples/basic/main.go`, `go.mod`, `smoke.sh`.
