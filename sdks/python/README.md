# reconpro-sdk (Python)

Thin, dependency-free Python wrapper around the ReconPro CLI (`python -m reconpro.cli`).
Every call shells out with an **argument list** (never a shell string).

## API
| Method | Returns | Notes |
|---|---|---|
| `version()` | `str` | e.g. `"ReconPro 11.1.0"` |
| `doctor()` | `dict` | parsed JSON of `doctor --json` |
| `history(target=None, limit=10)` | `str` | raw text — CLI quirk: `history` has **no** `--json` flag (human table on STDERR; `history --json` exits 2) |
| `scan(target)` | `dict` | network; targets validated client-side (shell metacharacters rejected) |
| `export(path, format="sarif")` | `str` | CLI `export` subcommand; format from extension (`.sarif/.md/.json/.html`) — needs a previous scan |

## Config
- `RECONPRO_PYTHON` (default `/home/z/.venv/bin/python3`) — python executable
- `RECONPRO_ROOT` (default `/home/z/my-project/download/reconpro-github`) — subprocess cwd
- `RECONPRO_TIMEOUT` (default `120` seconds)
- Failures raise `SdkError` with `.exit_code`, `.stderr`, `.command`.

## Run tests
```
cd /home/z/my-project/download/reconpro-github
/home/z/.venv/bin/python3 -m pytest sdks/python/tests -q
```
Status: **TESTED** — 5 passed, 1 skipped (`test_scan`, reason="network").

## Run example
```
/home/z/.venv/bin/python3 sdks/python/examples/basic.py --offline
```

## Files
`reconpro_sdk/` (client, exceptions), `tests/test_client.py`, `examples/basic.py`, `pyproject.toml`.
`export()` is implemented but **untested** (requires a prior scan in history; no network scans were run here).
