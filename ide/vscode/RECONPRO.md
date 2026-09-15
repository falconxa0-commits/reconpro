# RECONPRO.md — ReconPro quick start for this workspace

> ReconPro v11.1.0 — Python security scanner CLI. This file is the 60-second
> quick start for using the extension + tasks shipped in `ide/vscode/`.

## 1. Point the extension at your Python

The extension runs the CLI as:

```
<reconpro.pythonPath> -m reconpro.cli <subcommand> [args]
```

So `reconpro` must be importable by that interpreter. In this repo:

```jsonc
// .vscode/settings.json (workspace)
{ "reconpro.pythonPath": "/home/z/.venv/bin/python3" }
```

(no venv? `pip install reconpro==11.1.0` first, keep `python3`)

## 2. Commands (Ctrl+Shift+P)

| Command | What it does |
|---|---|
| `ReconPro: Scan Workspace (AST + Secrets)` | Runs `ast`, `secrets --json`, `dev` and `export *.sarif`, then fills the **Problems** panel from the SARIF; every step also streams to the `ReconPro` output channel |
| `ReconPro: Doctor: Health Check (JSON)` | Runs `doctor --json`, shows findings/score/grade |
| `ReconPro: Show Version` | Runs `--version` |

## 3. Tasks (Ctrl+Shift+B / Terminal: Run Task)

- `ReconPro: AST Analysis (workspace)` — `ast ${workspaceFolder}`
- `ReconPro: Secrets Scan (workspace)` — `secrets ${workspaceFolder}`
- `ReconPro: Doctor (health check)` — `doctor`

All three use `type: "process"` (argv array — no shell) and have
problemMatchers for the CLI's Rich table output.

## 4. Gotchas learned from the real CLI (v11.1.0)

1. **Streams are inverted vs. convention**: human output (banner, tables) goes
   to **stderr**; machine output (`--json`, `--version`) goes to **stdout**.
   The extension handles both.
2. **`ast <single-file>` finds nothing** — upstream routes single files
   through `analyze_directory()` which no-ops on files. Always scan the
   directory (the extension/tasks always use the workspace root).
3. **SARIF export needs a "last scan"** — `export report.sarif` serialises the
   last scan saved by commands like `dev`/`doctor`/`scan`. `ast` and `secrets`
   alone never enter the SARIF; that is why the scan command runs `dev` first.
4. The `ast` table's "Line" column actually contains the first 6 chars of the
   finding *evidence*, not a line number (upstream bug) — the task matcher
   captures it as the `code` field, never as a line.

## 5. CI parity

The same flow runs in CI via `actions/reconpro-scan` (see
`/actions/reconpro-scan/README.md`) — `ast` + `secrets` + `dev` + SARIF
export, uploaded as an artifact and ingested by GitHub Code Scanning.
