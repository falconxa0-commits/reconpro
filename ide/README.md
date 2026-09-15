# ReconPro IDE / Editor / CI Integrations — index

Everything shipped by **PHOENIX task 7-d (IDE Integration Engineer)** for the
`reconpro` CLI (v11.1.0, `python -m reconpro.cli`).

```
ide/
  README.md                ← you are here (index + honest status table)
  tools/validate_all.py    ← one-shot orchestrator: runs ALL validators below
  vscode/                  VS Code extension skeleton + tasks + SARIF tooling
  jetbrains/               IntelliJ-platform plugin skeleton (compile-blocked)
  neovim/                  Lua plugin (:ReconProScan & friends) + vimdoc
actions/
  reconpro-scan/           Composite GitHub Action (ast + secrets + dev + SARIF)
  tools/validate.py
.github/workflows/
  reconpro-scan.yml        Demo workflow calling ./actions/reconpro-scan
github-app/
  manifest.yml             "ReconPro Sentinel" GitHub App manifest
  smoke_webhook.py         LIVE-TESTED webhook receiver (HMAC-SHA256)
  tools/validate.py
```

## Status table (what "validated" means here)

| Integration | Status | Validation evidence |
|---|---|---|
| **VS Code extension** (`ide/vscode/`) | **Validated** (manifest + live CLI smoke; NOT loaded in a real VS Code — none in sandbox) | `node ide/vscode/tools/validate.js` → 61/61: every JSON parses; manifest contract (publisher `reconpro`, `^1.85.0`, 3 commands, config keys, problemMatchers, SARIF language); `node --check` on extension.js; spawn(argv-array, `shell:false`) regex contract; **executes the exact task/extension commands live** (`--version`, `ast`, `secrets --json`, `doctor --json`, `dev`, `export`) and applies the tasks.json problemMatcher regexes to the real CLI output (ast: 4 problems, secrets: 2, doctor: 7) |
| **JetBrains plugin** (`ide/jetbrains/`) | **Structural validation only — COMPILE-BLOCKED** (no IntelliJ IDEA/Gradle/kotlinc in sandbox) | `python3 ide/jetbrains/tools/validate.py` → 39/39: plugin.xml parses + id/since-build 241/toolWindow/configurable/actions; every referenced class exists as .kt; ProcessBuilder argv-list + no-Runtime.exec/no-concat contract (comment-stripped); **live execution** of the runner's exact argv (`doctor --json`, `ast <fixture>`, `dev` + `export` → SARIF 2.1.0 with rules+results) |
| **Neovim plugin** (`ide/neovim/`) | **Structural validation only — no `nvim` binary in sandbox** (`which nvim` empty; only vim 9.1, which lacks `jobstart`/`vim.api`) | `python3 ide/neovim/tools/validate.py` → 47/47: jobstart argv-list contract (no `os.execute`/`vim.fn.system`/`io.popen` — comments stripped), 4 user commands, `setqflist` wiring, bracket-balance sanity, vimdoc tags (13), syntax file; **live execution** of the exact argv lists + a faithful Python port of the Lua table-row parser extracting real findings (4 rows, CRITICAL→type E) |
| **GitHub Action** (`actions/reconpro-scan/`) | **Manifest-validated + live step-sequence executed locally** (a GitHub-hosted run is impossible in the sandbox) | `python3 actions/tools/validate.py` → 42/42: action.yml + demo workflow parse; inputs/outputs/composite steps; setup-python@v5 / upload-artifact@v4 / codeql-action/upload-sarif@v3; **executes the step commands locally** (`timeout 300 … ast/secrets/dev/export`) with PYTHONPATH simulating the post-`pip install` state, and verifies the artifact payloads (secrets JSON + SARIF 2.1.0) |
| **GitHub App webhook** (`github-app/`) | **LIVE-TESTED** (real HTTP round-trip in the sandbox) | `python3 github-app/tools/validate.py` → 25/25: manifest.yml contract (valid permission keys only); HMAC-SHA256 `X-Hub-Signature-256` scheme; **real server run**: signed delivery → 200 `"signature":"valid"`, tampered → 401, missing → 401, server log inspected; plus a literal `curl` demonstration (200 + `signature valid` / 401) |

**Honest gaps** (also labelled in each README):

- No VS Code, IntelliJ, Neovim or GitHub runners exist in this sandbox. Every
  "validated" claim above is backed by a validator script that was actually
  run (outputs captured in the worklog); anything requiring those hosts is
  labelled structural/compile-blocked, not "tested".
- The VS Code extension is not packaged (`.vsix`) — `vsce` is unavailable.
- The JetBrains skeleton needs `gradle buildPlugin` on an IDEA machine.
- The GitHub App handler validates and acknowledges deliveries; the
  scan-on-PR orchestration (installation auth → clone → scan → checks/SARIF
  upload) is documented, not implemented — that is honest scope.
- Shared CLI quirks all integrations compensate for (upstream, not modified):
  human output → **stderr**, `--json`/`--version` → **stdout**;
  `reconpro ast <single-file>` is a no-op (directory-only), so every
  integration scans a directory; `export` needs a prior `dev`/`doctor`/`scan`
  to have saved a "last scan"; the ast table's "Line" column holds evidence
  text and file paths truncate to 30 chars.

## Run everything

```bash
python3 ide/tools/validate_all.py     # runs all 5 validators, exit 0 = all green
```

Individual: `ide/vscode/tools/validate.js` (node), `ide/jetbrains/tools/validate.py`,
`ide/neovim/tools/validate.py`, `actions/tools/validate.py`,
`github-app/tools/validate.py`.
