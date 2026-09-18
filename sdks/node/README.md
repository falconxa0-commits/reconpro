# reconpro-sdk (Node.js, plain JS) — Maintenance tier

> **Superseded by the typed TypeScript SDK** in [`../typescript`](../typescript)
> (same JSON contract, full type surface, compiled `dist/`, `bun test` +
> plain-node dist smoke). This plain-JS package is in **Maintenance**
> (0.2.0): only critical fixes (security, contract breakage) are accepted —
> see [`../POLICY.md`](../POLICY.md) §2.

Zero-dependency Node.js wrapper around the ReconPro CLI
(`python -m reconpro.cli`). Every call spawns the CLI with an **argument
list** (never a shell string).

## API
| Method | Returns | Notes |
|---|---|---|
| `version()` | `Promise<string>` | e.g. `"ReconPro 11.2.0"` |
| `doctor()` | `Promise<object>` | parsed JSON of `doctor --json` |
| `history(target?, limit)` | `Promise<string>` | raw text — CLI quirk: `history` has **no** `--json` flag (human table on STDERR) |
| `scan(target)` | `Promise<object>` | network; shell metacharacters in targets rejected client-side |
| `export(path, format)` | `Promise<string>` | CLI `export` subcommand, format from extension — needs a prior scan |

Errors: `SdkError` with `.exitCode`, `.stderr`, `.command`.

## Config
- `RECONPRO_PYTHON` (default `python3`)
- `RECONPRO_ROOT` (default `.` — subprocess cwd)
- `RECONPRO_TIMEOUT_MS` (default `120000`)

## Run tests
```
cd sdks/node && npm test          # node --test "test/*.test.js"
# or from the repo root:
node --test "sdks/node/test/*.test.js"
```
Quirk (node v24.19.0): `node --test <dir>` fails with `MODULE_NOT_FOUND`
(the directory is treated as a module entry), so a glob pattern is required.
Tests are hermetic (shell-script stub "python" binaries; no reconpro
installation needed).

## Run example
```
node sdks/node/examples/basic.mjs --offline
```
