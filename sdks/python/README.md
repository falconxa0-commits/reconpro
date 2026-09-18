# reconpro-sdk (Python) — Stable

Typed, **stdlib-only** Python SDK around the ReconPro CLI (>= 11.2.0). Every
call spawns `reconpro <command> --json` with an **argument list** (never a
shell string) and parses the JSON contract from STDOUT; the CLI's pretty UI
goes to STDERR and is captured only for error reporting.

Stability tier: **Stable** — versioning & compatibility policy:
[`../POLICY.md`](../POLICY.md).

## Install / import

No dependencies (Python >= 3.9). From a checkout:

```python
sys.path.insert(0, "sdks/python")           # or pip install . from this dir
from reconpro_sdk import ReconProClient, SdkError
```

## API

| Method | Returns | Notes |
|---|---|---|
| `ReconProClient(binary_path=None, timeout=None)` | — | binary via arg → `RECONPRO_BINARY` env → `"reconpro"` on PATH; timeout via arg → `RECONPRO_TIMEOUT` env → 300 s |
| `version()` | `str` | verification ping (`reconpro --version`), e.g. `"ReconPro 11.2.0"` |
| `scan(target, *, output_file=None, modules=None, insecure=False)` | `ScanResult` | remote scan; `output_file` persists the JSON via CLI `-o` |
| `vibesec(target, *, output_file=None)` | `ScanResult` | vibesec module scan |
| `audit()` | `ScanResult` | local host/dev audit (offline) |
| `dev(path=".")` | `ScanResult` | scan a local directory (offline) |
| `doctor()` | `ScanResult` | local health check (offline) |
| `export(path, format="sarif")` | `str` | `reconpro export <path>` (format from extension; appended when missing); returns path written |

`ScanResult` is a frozen dataclass: `target`, `modules_run`, `total_findings`,
`severity_counts`, `total_score`, `grade`, `findings[]` (each `Finding` has the
full truth-layer fields incl. `confidence` and `verification_state`),
`target_validation` (`state` / `dns_resolved` / `reachable` / `http_ok` /
`tls_valid` / `details` / `checked_at`, `None` for local scans),
`scan_metadata` (`scanner` / `started_at` / `duration_s` / `result`), plus
`.raw` (the complete parsed JSON dict — unknown future keys stay accessible)
and helpers `.unreachable`, `.findings_by_severity(sev)`.

## Errors — structured `SdkError`

| `.code` | Raised when | Extras |
|---|---|---|
| `BIN_NOT_FOUND` | binary missing / not executable | |
| `TIMEOUT` | per-call timeout exceeded | |
| `NON_ZERO_EXIT` | CLI exit != 0 | `.exit_code` (0/1/2/130 contract), `.stderr` |
| `INVALID_JSON` | exit 0 but stdout not JSON | `.stderr` carries stdout head |
| `INVALID_TARGET` (`TargetValidationError`) | shell metacharacters in target (defence in depth) | |
| `UNSUPPORTED_FORMAT` (`UnsupportedFormatError`) | export format not sarif/md/json/html | |

## Run tests

```
/home/z/tmp-capture/rp-dev/bin/python -m pytest sdks/python/tests -q
```
CLI-backed tests auto-skip when no `reconpro` binary is found
(`RECONPRO_BINARY` env → PATH → known venv paths); everything else is hermetic
(shell-stub binaries). The truth-layer contract test scans a nonexistent
`*.invalid` target — fully offline, instant, and asserts `grade == "U"` +
`target_validation.state == UNREACHABLE_TARGET`.

## Run example

```
/home/z/tmp-capture/rp-dev/bin/python sdks/python/examples/basic.py            # offline .invalid demo
/home/z/tmp-capture/rp-dev/bin/python sdks/python/examples/basic.py example.com  # live scan
```

## Files
`reconpro_sdk/` (`client.py`, `models.py`, `exceptions.py`, `__init__.py`),
`tests/` (`conftest.py`, `test_client.py`), `examples/basic.py`,
`pyproject.toml`, `LICENSE`, this README.
