# IDE & CI Integrations

Editor plugins, a composite GitHub Action and a GitHub App shipped with
this repository. Every integration follows the same no-shell contract
(argv list / ProcessBuilder / jobstart list — never a concatenated shell
string) and every claim below is backed by a validator script that was
actually run. What "validated" means per integration — and what
honestly is NOT tested — is the point of this page.

Index: `ide/README.md` (full status table), one-shot runner
`python3 ide/tools/validate_all.py` (runs all five validators, exit 0 =
all green — 214 checks, all passing).

## VS Code — `ide/vscode/`

Extension skeleton: 3 commands (`reconpro.scanWorkspace`, `reconpro.doctor`,
`reconpro.version`), `reconpro.pythonPath` / `reconpro.timeoutSec`
configuration, contributed problemMatcher, SARIF language + grammar +
snippets, and `.vscode/tasks.json` with three `type: "process"` tasks.
`src/extension.js` spawns `<python> -m reconpro.cli` via
`child_process.spawn` with an **argv array and `shell:false`**, maps
SARIF 2.1.0 results to `vscode.Diagnostic`.

**Validated** (`node ide/vscode/tools/validate.js` → 61/61): manifests
parse; manifest contract; `node --check`; spawn-argv regex contract;
live execution of the exact task/extension commands against a fixture
(`--version`, `ast`, `secrets --json`, `doctor --json`, `dev`, `export`
→ SARIF), with the tasks.json problemMatcher regexes applied to the
**real** CLI output.

Not tested: loading the extension in a real VS Code host (none in the
development sandbox) and `.vsix` packaging (`vsce` unavailable).

## JetBrains — `ide/jetbrains/`

IntelliJ-platform plugin skeleton: `plugin.xml` (tool window +
configurable + action group), 8 Kotlin sources including
`ReconProRunner.kt` (ProcessBuilder argument list, COLUMNS=200,
SARIF 2.1.0 → annotation model), `build.gradle.kts`.

**Structural validation only — COMPILE-BLOCKED** (no IDEA/Gradle/kotlinc
in the sandbox): `python3 ide/jetbrains/tools/validate.py` → 39/39 —
plugin.xml contract, class references resolve, no-`Runtime.exec`/no-concat
contract, plus live execution of the runner's exact argv.

## Neovim — `ide/neovim/`

Lua plugin: `lua/reconpro/{init,commands}.lua` (jobstart argv **list**,
uv timer kill, Rich-table parser, JSON decoder, quickfix builders),
`plugin/reconpro.lua` with 4 user commands (`:ReconProScan`,
`:ReconProSecrets`, `:ReconProDoctor`, `:ReconProVersion`), full vimdoc
(`doc/reconpro.txt`, 13 tags), syntax file.

**Structural validation only — no `nvim` binary in the sandbox**
(only vim 9.1, which lacks `jobstart`/`vim.api`):
`python3 ide/neovim/tools/validate.py` → 47/47 — no-shell contract,
user commands, setqflist wiring, vimdoc tags, live execution of the
exact argv lists + a faithful Python port of the Lua parser extracting
real findings.

## GitHub Action — `actions/reconpro-scan/`

Composite action: inputs `target/workspace/format/timeout/python-version`,
outputs `sarif-path/secrets-json-path`; steps: setup-python@v5 → install
detection (PyPI or `pip install .` for this repo) → `ast` →
`secrets --json` → `dev` (seeds the export) → `export` →
upload-artifact@v4 → codeql-action/upload-sarif@v3 (gated on sarif).
Inputs reach the steps via env, never inline interpolation. Demo
workflow: `.github/workflows/reconpro-scan.yml`.

**Manifest-validated + executed live on GitHub** (`python3
actions/tools/validate.py` → 42/42 locally; the demo workflow
`.github/workflows/reconpro-scan.yml` has run green on GitHub Actions on
every push to `main`, including on the live repository — see the Actions
badge in the README).

## GitHub App — `github-app/`

"ReconPro Sentinel" app manifest (`manifest.yml`: default_events
pull_request + security_and_analysis; permissions contents:read,
checks:write, security_events:write) and `smoke_webhook.py` — a stdlib
`ThreadingHTTPServer` that validates `X-Hub-Signature-256`
(HMAC-SHA256 over the raw body, `hmac.compare_digest`).

**LIVE-TESTED** (`python3 github-app/tools/validate.py` → 25/25):
manifest contract; real HTTP round-trip — signed `pull_request` payload
→ 200 `"signature":"valid"`, tampered → 401, missing header → 401.
The scan-on-PR orchestration (installation auth → clone → scan →
checks/SARIF) is documented, not implemented — honest scope.

## Shared upstream CLI quirks (all integrations compensate)

- human output (banner + Rich tables) → **stderr**; `--json` and
  `--version` → **stdout**;
- `reconpro ast <single-file>` is a no-op (the CLI routes files through a
  directory analyzer) — integrations always scan a directory;
- `export` needs a prior `dev`/`doctor`/`scan` to have saved a "last
  scan";
- Rich tables truncate at 80 columns — integrations pin `COLUMNS=200`.

## Run everything

```bash
python3 ide/tools/validate_all.py    # vscode 61, jetbrains 39, neovim 47,
                                     # actions 42, github-app 25 — exit 0
```

See [SDKS.md](SDKS.md) for language SDKs and
[CLI_REFERENCE.md](CLI_REFERENCE.md) for the commands these
integrations invoke.
