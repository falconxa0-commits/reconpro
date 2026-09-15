# Changelog — reconpro-vscode

All notable changes to the ReconPro VS Code extension are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [0.1.0] — 2026-09-05 (PHOENIX RESURRECTION, Task 7-d)

### Added
- `reconpro.scanWorkspace` command: runs `ast`, `secrets --json`, `dev` and
  `export <tmp>.sarif` (argv-array spawns, `shell: false`), parses SARIF 2.1.0
  into `vscode.Diagnostic` entries; console fallback to the `ReconPro` output
  channel whenever SARIF is missing/unparseable or findings have no
  file-resolvable location.
- `reconpro.doctor` command: `doctor --json` → findings/score/grade summary.
- `reconpro.version` command.
- Configuration: `reconpro.pythonPath` (default `python3`),
  `reconpro.timeoutSec` (default 120).
- Contributed problem matcher `reconpro-table` + three ready-to-run
  `.vscode/tasks.json` tasks (`ast`, `secrets`, `doctor`) using
  `type: "process"` (no shell).
- SARIF language support: `languages` contribution, TextMate grammar
  (`syntaxes/sarif.tmLanguage.json`), snippets, language configuration.
- Validation harness `tools/validate.js` (JSON manifests + `node --check` +
  live CLI smoke: runs the exact task commands and applies the
  problemMatcher regexes to the CLI's real output).

### Known limitations (honest)
- Not yet packaged (`.vsix`) — `vsce` is unavailable in this sandbox; the
  manifest is validated structurally and the CLI flow is executed live.
- `reconpro ast <file>` upstream single-file no-op quirk: we always scan the
  workspace root directory (see RECONPRO.md §4.2).
- Human CLI output goes to stderr, JSON to stdout (upstream behaviour) —
  handled, but means "task output" panels show stderr content.
