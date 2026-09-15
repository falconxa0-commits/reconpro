# Getting Started with ReconPro

ReconPro v11.1.0 is a pure-Python security reconnaissance CLI: 28 scan
modules (remote, local, advanced), 81 top-level commands, a sandboxed
plugin SDK, and JSON/SARIF/Markdown/HTML output for CI pipelines.

Every command in this guide was executed against this repository
(`python -m reconpro.cli` on Python 3.12) unless marked **(network)** —
those require internet access and were not run while writing this page.

## Installation

### From PyPI-style index (pip install reconpro)

```bash
pip install reconpro
```

Optional extras: `pip install "reconpro[full]"` (aiohttp, playwright,
openai/anthropic, networkx, scapy, shodan, websockets) or pick
individually: `async`, `browser`, `llm`, `graph`, `raw`, `intel`,
`collab`, `integrations`.

Runtime dependencies: `rich>=13`, `textual>=0.40`, `requests>=2.28`.
Python **3.10+**.

### From source

```bash
git clone <this repo>
cd reconpro-github
pip install -e .           # editable install
# or build a wheel yourself:
python tools/release_manager.py build --reproducible
pip install dist/reconpro-11.1.0-py3-none-any.whl
```

### Run without installing (this repo only)

```bash
cd /path/to/reconpro-github
python -m reconpro.cli --version     # → ReconPro 11.1.0
```

Note: the wheel in `dist/` is signed — see [RELEASE.md](RELEASE.md) for
how to verify it before installing a downloaded artifact.

## Your first five minutes

### 1. Check the version

```bash
reconpro --version
# ReconPro 11.1.0
```

### 2. Take the guided tour (8 steps)

```bash
reconpro tutorial
reconpro tutorial --list       # see the step list first
```

Real output of `reconpro tutorial --list`:

```
  1. What ReconPro is
  2. Your first scan
  3. Local machine audit
  4. Code & cloud
  5. Threat intel
  6. Plugins (sandboxed)
  7. Reports & CI
  8. Where to go next
```

### 3. Ask what to do next

```bash
reconpro suggest               # human-readable panel
reconpro suggest --json        # machine-readable
```

Real (truncated) output of `reconpro suggest --json` on a fresh install:

```json
[
  {
    "cmd": "reconpro scan example.com",
    "why": "No scan history yet — run your first scan."
  },
  {
    "cmd": "reconpro tutorial",
    "why": "New here? 8-step tour."
  },
  {
    "cmd": "reconpro doctor",
    "why": "Health check (add --repair to autofix)."
  }
]
```

### 4. Check your own machine's health (no network)

```bash
reconpro doctor --json
reconpro doctor --repair       # auto-apply safe fixes
```

`reconpro doctor --json` runs a local health check (~15 s) and prints a
JSON object with `total_findings`, `severity_counts`, `total_score`,
`grade`, and per-finding `remediation` text. On the machine this guide
was written on it reported 7 findings (grade B, score 66) — passwords,
disk encryption, SSH settings and similar local posture items.

### 5. Scan a target (network)

```bash
reconpro scan example.com --modules recon --json --timeout 60  # (network)
reconpro vibesec example.com --json                           # (network) quick benchmark
```

### 6. Scan a code directory (no network)

```bash
reconpro dev /path/to/project     # secrets, deps, git, docker
reconpro ast /path/to/code        # AST vulnerability patterns
reconpro secrets /path/to/code --json
```

Verified example — `reconpro dev <dir> --json` on a directory containing
a Python file with `password = "hunter2"` and `subprocess.run(cmd, shell=True)`
reported:

```
total_findings: 1
grade: A
 - Hardcoded password in sample.py critical
```

### 7. Export the last scan for CI

```bash
reconpro export report.sarif     # SARIF 2.1.0 (GitHub Code Scanning)
reconpro export report.md        # Markdown report
reconpro export report.json      # raw JSON
reconpro export report.html      # HTML report
```

Format is auto-detected from the file extension. `export` uses the most
recent saved scan (a previous `scan`/`audit`/`dev`/`doctor` run), so run
one of those first. The exported `report.sarif` from our test run
declares `"version": "2.1.0"` with `tool.driver.name = "ReconPro"`.

## The interactive helpers

| Command | What it does |
|---|---|
| `reconpro tutorial` | 8-step guided tour; `--step N` jumps to step N |
| `reconpro wizard` | Interactive scan wizard; `--non-interactive` prints the recommended plan without asking |
| `reconpro suggest` | Recommends next commands based on your state (history, plugins, doctor) |
| `reconpro nexus` | Visual agent TUI (mouse + keyboard, split-screen) |
| `reconpro chat` | Interactive chat mode |
| `reconpro tui` | Visual terminal dashboard |
| `reconpro palette` | Interactive command palette (Ctrl+K) |
| `reconpro playground` | Sandboxed plugin lab — runs the built-in template in the plugin sandbox without installing anything |

Real output of `reconpro wizard --non-interactive`:

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ ReconPro Scan Wizard — build a scan plan step by step                        │
╰──────────────────────────────────────────────────────────────────────────────╯

  Your quick plan for example.com:

   1. reconpro scan example.com
   2. reconpro profile example.com

  Copy-paste them in order. Add --json anywhere for machine output.
```

Real output of `reconpro playground` (no arguments — it uses a built-in
template and a mock target):

```
  No file given — using the built-in template at
/tmp/reconpro-play-XXXXXXX/playground.py
  Running playground.py against example.com (sandbox: own PID, no net, no
subprocess, workdir-only writes)
  result: kind=ok ok=True pid=23234 duration=1ms
   • playground ok on example.com
```

## Module catalog

```bash
reconpro list             # 28 remote/advanced modules
reconpro list --local     # + local modules (host, dev, doctor)
reconpro list --all       # everything
```

Real `reconpro list` output (truncated):

```
Remote Modules:

  recon        RECON              (default)
  auth         AUTH BYPASS        (default)
  ...
  Total: 28 modules
```

## Where to go next

- [CLI_REFERENCE.md](CLI_REFERENCE.md) — every subcommand, options, examples, exit codes
- [PLUGINS.md](PLUGINS.md) — write, sign, install and run sandboxed plugins
- [SECURITY.md](SECURITY.md) — the security posture of the tool itself
- [RELEASE.md](RELEASE.md) — building, signing and verifying releases
- [SDKS.md](SDKS.md) — Python/Node/Java/Go/Rust wrappers around the CLI
- [IDE.md](IDE.md) — VS Code / JetBrains / Neovim / GitHub integrations
- [PERFORMANCE.md](PERFORMANCE.md) — cold-start budget and lazy-import design
