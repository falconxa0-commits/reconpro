# reconpro-scan — GitHub Action

Composite action that runs the [ReconPro](../..) security scanner CLI
(`python -m reconpro.cli`) over your checkout and ships the results to GitHub:

1. **`reconpro ast <target>`** — Python/JS/TS vulnerability pattern analysis
   (Rich findings table lands in the step log);
2. **`reconpro secrets <target> --json`** — secrets scan, JSON listing saved
   as `reconpro-secrets.json` and summarized in the log;
3. **`reconpro dev <target>`** — project scan (secrets/deps/git/docker) which
   seeds the "last scan" used by export;
4. **`reconpro export reconpro-report.sarif`** — SARIF 2.1.0 report;
5. **`actions/upload-artifact@v4`** — report + secrets JSON as artifact
   `reconpro-report`;
6. **`github/codeql-action/upload-sarif@v3`** — SARIF ingested into GitHub
   Code Scanning (category `/reconpro`) when `format: sarif`.

> **Status:** manifest-validated + the exact CLI command sequence is
> executed locally by `python3 actions/tools/validate.py` (exit 0). The
> GitHub-hosted run itself obviously cannot execute in this sandbox.

## Usage

### In the reconpro repo itself

```yaml
# .github/workflows/reconpro-scan.yml
name: ReconPro Scan (demo)
on:
  push:
    branches: [main, master]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # needed by codeql-action/upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ReconPro (ast + secrets + SARIF)
        uses: ./actions/reconpro-scan
        with:
          target: .
          python-version: '3.11'
          timeout: '300'
```

### From another repository

```yaml
      - name: ReconPro (ast + secrets + SARIF)
        uses: falconxa0-commits/reconpro/actions/reconpro-scan@v11
        with:
          target: .
          python-version: '3.11'
```

(When the checked-out repo is **not** reconpro itself, the install step pulls
the CLI from PyPI — `pip install reconpro`. To pin a version, set
`RECONPRO_INSTALL_SPEC: reconpro==11.1.0` as job/workflow env.)

## Inputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | File or directory passed to `ast` / `secrets` / `dev` |
| `workspace` | `${{ github.workspace }}` | cwd for the CLI and outputs |
| `format` | `sarif` | `reconpro export` format: `sarif`/`json`/`md`/`html` (SARIF ingestion only when `sarif`) |
| `timeout` | `300` | Seconds per CLI invocation (GNU `timeout`) |
| `python-version` | `3.11` | `actions/setup-python` version |

## Outputs

| Output | Description |
|---|---|
| `sarif-path` | e.g. `reconpro-report.sarif` (relative to `workspace`) |
| `secrets-json-path` | `reconpro-secrets.json` |

## CLI stream facts the action relies on

- human output (banner + Rich tables) → **stderr** (shows in the step log),
  `--json` → **stdout** (redirected to files);
- `reconpro ast <single-file>` is an upstream no-op — pass a directory
  (default `.`);
- `export` serialises the *last* scan — hence the `dev` step before it.

## Validate

```bash
python3 actions/tools/validate.py   # exit 0 = PASS
```
