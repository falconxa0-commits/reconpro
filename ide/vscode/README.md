# reconpro-vscode — ReconPro security scanner for VS Code

Runs the [ReconPro](../..) CLI (`python -m reconpro.cli`) inside VS Code:
workspace scans, secrets detection and machine health checks, with findings
surfaced in the **Problems** panel via SARIF 2.1.0.

> **Status (honest):** manifest + tasks + code are structurally validated by
> `node tools/validate.js` (also runs `node --check` on the extension and
> executes the exact CLI invocations the commands/tasks perform). It is NOT
> load-tested inside a real VS Code — no VS Code exists in the build sandbox.
> Packaging with `vsce` is left as a follow-up.

## Features

- **Scan Workspace** (`reconpro.scanWorkspace`) — runs `ast`, `secrets --json`,
  `dev` then `export *.sarif`; SARIF results become `vscode.Diagnostic`
  entries (severity mapped from SARIF level + `security-severity`, remediation
  appended to the diagnostic message). Every step also streams to the
  `ReconPro` output channel — the fallback when no SARIF is available.
- **Doctor** (`reconpro.doctor`) — `doctor --json`, prints
  findings/score/grade summary.
- **Version** (`reconpro.version`).
- **Tasks** — three `type: "process"` tasks (argv arrays, no shell) with
  problemMatchers for the CLI's Rich table output.
- **SARIF editing** — language + TextMate grammar + snippets for `.sarif`.

## Configuration

| Property | Default | Meaning |
|---|---|---|
| `reconpro.pythonPath` | `python3` | Interpreter used to run `-m reconpro.cli` |
| `reconpro.timeoutSec` | `120` | Kill switch per CLI invocation |

```jsonc
{ "reconpro.pythonPath": "/home/z/.venv/bin/python3" }
```

## Quick start

See [RECONPRO.md](RECONPRO.md) — the 60-second tour including the real CLI's
stream routing (human output → **stderr**, JSON → stdout) and its
`ast <file>` single-file quirk (always scan a directory).

## Run the validator

```bash
node ide/vscode/tools/validate.js     # exits 0 on success, 1 on failure
```

## CI parity

`actions/reconpro-scan` reproduces the same flow (ast + secrets + dev + SARIF
export + Code Scanning upload) on GitHub.

## License

MIT — see [LICENSE](LICENSE) (copy of the repo root license).
