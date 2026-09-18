# Getting Started with ReconPro

ReconPro v11.2.0 is a pure-Python security reconnaissance CLI: 28 scan
modules (25 remote/advanced + 3 local), 81 top-level commands, a
sandboxed plugin SDK, a target-validation **truth layer**, and
JSON/SARIF/Markdown/HTML output for CI pipelines.

Every command in this guide was executed against this repository
(`reconpro` 11.2.0 on Python 3.12) unless marked **(network)** — those
require internet access and were not run while writing this page.

## Installation

### From PyPI

```bash
pip install reconpro
```

Live at https://pypi.org/project/reconpro/ — v11.2.0 ships as a
byte-reproducible wheel and sdist, both covered by Ed25519-signed
checksums; see [RELEASE.md](RELEASE.md) for artifact verification.

Optional extras: `pip install "reconpro[full]"` (aiohttp, playwright,
openai/anthropic, networkx, scapy, shodan, websockets) or pick
individually: `async`, `browser`, `llm`, `graph`, `raw`, `intel`,
`collab`, `integrations`.

Runtime dependencies: `rich>=13`, `textual>=0.40`, `requests>=2.28`,
`cryptography>=41`. Python **3.10+**.

### From source

```bash
git clone https://github.com/falconxa0-commits/reconpro.git
cd reconpro
pip install -e .           # editable install
# or build a wheel + sdist yourself (byte-reproducible):
python tools/release_manager.py build --reproducible
```

### Verify what you installed (recommended)

See [keys/README.md](keys/README.md) for the full procedure — the short
version, after downloading release assets into one directory:

```bash
sha256sum -c SHA256SUMS                 # every artifact hash
gpg --import docs/keys/reconpro-release-5F3D637E.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # the GPG signature
```

### Run without installing (this repo only)

```bash
cd /path/to/reconpro
python -m reconpro.cli --version     # → ReconPro 11.2.0
```

## Your first five minutes

### 1. Check the version

```bash
reconpro --version
# ReconPro 11.2.0
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

`reconpro doctor --json` runs a local health check and prints a JSON
object with `total_findings`, `severity_counts`, `total_score`, `grade`,
and per-finding `remediation` text. On the machine this guide was
written on it reported 7 findings (grade B, score 66) — passwords, disk
encryption, SSH settings and similar local posture items.

### 5. Scan a target (network)

```bash
reconpro scan example.com --modules recon --json --timeout 60  # (network)
reconpro vibesec example.com --json                           # (network) quick benchmark
```

Before any module runs, ReconPro validates the target
(DNS → TCP → HTTP/TLS). If the target cannot be reached you get an
**honest no-result** — verified:

```bash
reconpro scan nonexistent-target-xyz.invalid --json -t 2
```

```jsonc
{
  "total_findings": 1,           // one explanation finding, severity info
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",                  // U = unreachable, no claim is made
  "modules_run": [],
  "target_validation": {"state": "UNREACHABLE_TARGET", "dns_resolved": false, ...},
  "scan_metadata": {"started_at": "2026-09-18T00:37:01.499796+00:00",
                    "duration_s": 0.01, "result": "unreachable_target_short_circuit"}
}
```

HIGH-severity findings against an unreachable target are impossible by
construction. Semantics: [guides/SCANNING.md](guides/SCANNING.md).

### 6. Scan a code directory (no network)

```bash
reconpro dev /path/to/project     # secrets, deps, git, docker
reconpro ast /path/to/code        # AST vulnerability patterns
reconpro secrets /path/to/code --json
```

Verified example — `reconpro dev <dir> --json` on a directory containing
a Python file with `API_KEY = "AKIAIOSFODNN7EXAMPLE"` reported:

```
total_findings: 1
grade: A
 - Hardcoded API key in app.py  critical  (confidence 0.8)
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
declares `"version": "2.1.0"` with `tool.driver.name = "ReconPro"`, and
every SARIF result carries `confidence` + `verification_state` in its
properties. More: [guides/REPORTS.md](guides/REPORTS.md).

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
reconpro list             # the remote/advanced module catalog (25 listed)
reconpro list --local     # only the 3 local modules (host, dev, doctor)
reconpro list --all       # both sections — the full 28
```

(The footer line `Total: 28 modules` counts the whole catalog in every
variant — it is the registry size, not the filtered list length.)

Real `reconpro list --all` output (truncated):

```
Local Modules:

  host         HOST AUDIT         (default)
  dev          DEV SEC            (default)
  doctor       DOCTOR             (default)

Remote Modules:

  recon        RECON              (default)
  auth         AUTH BYPASS        (default)
  ...
  container_sec CONTAINER SEC
  iac_audit    IaC AUDIT

  Total: 28 modules
```

`reconpro info --diagnose` confirms the split: 28 modules total — 25
remote/advanced + 3 local; 20 run in a default remote scan.

## Where to go next

- [TUTORIALS.md](TUTORIALS.md) — the beginner track, install → first SARIF report
- [reference/CLI_REFERENCE.md](reference/CLI_REFERENCE.md) — every subcommand, options, examples, exit codes
- [guides/SCANNING.md](guides/SCANNING.md) — module selection, timeouts, rate limits, truth states
- [reference/CONFIGURATION.md](reference/CONFIGURATION.md) — `~/.reconpro/` layout and environment variables
- [PLUGINS.md](PLUGINS.md) — write, sign, install and run sandboxed plugins
- [SECURITY.md](SECURITY.md) — the security posture of the tool itself
- [RELEASE.md](RELEASE.md) — building, signing and verifying releases
- [SDKS.md](SDKS.md) — Python/Node/Java/Go/Rust wrappers around the CLI
- [IDE.md](IDE.md) — VS Code / JetBrains / Neovim / GitHub integrations
- [PERFORMANCE.md](PERFORMANCE.md) — cold-start budget and lazy-import design
