# reconpro-sdk (Node.js)

Zero-dependency Node.js wrapper around the ReconPro CLI (`python -m reconpro.cli`).
Every call spawns the CLI with an **argument list** (never a shell string).

## API
| Method | Returns | Notes |
|---|---|---|
| `version()` | `Promise<string>` | e.g. `"ReconPro 11.1.0"` |
| `doctor()` | `Promise<object>` | parsed JSON of `doctor --json` |
| `history(target?, limit)` | `Promise<string>` | raw text — CLI quirk: `history` has **no** `--json` flag (human table on STDERR) |
| `scan(target)` | `Promise<object>` | network; shell metacharacters in targets rejected client-side |
| `export(path, format)` | `Promise<string>` | CLI `export` subcommand, format from extension — needs a prior scan |

Errors: `SdkError` with `.exitCode`, `.stderr`, `.command`.

## Config
- `RECONPRO_PYTHON` (default `/home/z/.venv/bin/python3`)
- `RECONPRO_ROOT` (default `/home/z/my-project/download/reconpro-github`)
- `RECONPRO_TIMEOUT_MS` (default `120000`)

## Run tests
```
cd sdks/node && npm test          # node --test "test/*.test.js"
# or from the repo root:
node --test "sdks/node/test/*.test.js"
```
Quirk (node v24.19.0): `node --test <dir>` fails with `MODULE_NOT_FOUND`
(the directory is treated as a module entry), so a glob pattern is required.
Status: **TESTED** — 6/6 tests pass (node v24.19.0).

## Run example
```
node sdks/node/examples/basic.mjs --offline
```

`export()` is implemented but **untested** (requires a prior scan; no network scans were run here).
