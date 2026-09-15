# reconpro-jetbrains — ReconPro for IntelliJ Platform IDEs (2024.1+)

IntelliJ / PyCharm / WebStorm plugin skeleton that runs the
[ReconPro](../..) CLI (`python -m reconpro.cli`) via **ProcessBuilder with an
argv list — never a shell string**, and turns its SARIF 2.1.0 output into
in-editor annotations.

> **STATUS — COMPILE-BLOCKED IN THIS SANDBOX (honest).** There is no IntelliJ
> IDEA, no Gradle and no Kotlin compiler in the environment that produced this
> skeleton. What IS verified: `python3 tools/validate.py` parses
> `plugin.xml` (XML well-formedness + required declarations), checks the
> Kotlin sources for the ProcessBuilder/no-shell contract, and **executes the
> exact CLI invocations the plugin performs** (doctor JSON, ast on a fixture,
> dev+export SARIF parse). Kotlin compilation itself must happen on a machine
> with IntelliJ IDEA + Gradle (instructions below).

## What's inside

| Path | Purpose |
|---|---|
| `resources/META-INF/plugin.xml` | `idea-plugin` descriptor: id `com.reconpro.intellij`, `since-build="241"`, toolWindow + projectConfigurable extensions, action group *Tools ▸ ReconPro* (Scan Project / Doctor / Show CLI Version) |
| `src/com/reconpro/sdk/ReconProRunner.kt` | Core: `buildCommand()` argv list, `run()` via ProcessBuilder (COLUMNS=200, no shell), `parseSarif()` → `Finding` annotation model, `scanProject()` = `dev` → `export *.sarif` flow |
| `src/com/reconpro/sdk/ReconProScanAction.kt` | Pooled-thread scan (ast + secrets + dev + export), annotates from SARIF, tool-window console fallback |
| `src/com/reconpro/sdk/ReconProDoctorAction.kt` | `doctor --json` → findings/score/grade dialog |
| `src/com/reconpro/sdk/ReconProVersionAction.kt` | `--version` |
| `src/com/reconpro/sdk/ReconProToolWindowFactory.kt` | Bottom "ReconPro" tool window (raw CLI streams) |
| `src/com/reconpro/sdk/ReconProSettingsConfigurable.kt` + `ReconProSettings.kt` | Tools ▸ ReconPro settings (python path, timeout) |
| `src/com/reconpro/sdk/ReconProAnnotator.kt` | SARIF finding → line range / virtual file resolution |
| `build.gradle.kts` | gradle-intellij-plugin build (Kotlin 2.0.21, IC 2024.1, JBR 17) |

## Build (on a machine with IntelliJ IDEA + Gradle)

```bash
cd ide/jetbrains
gradle buildPlugin          # produces build/distributions/reconpro-0.1.0.zip
gradle runIde               # sandbox IDE with the plugin loaded
gradle test reconproSmoke   # reconproSmoke executes the CLI contract (doctor --json)
```

Then install `build/distributions/reconpro-0.1.0.zip` via
*Settings ▸ Plugins ▸ ⚙ ▸ Install Plugin from Disk…*.

## Verified CLI contract (what the plugin relies on)

1. Human output (banner, Rich tables) → **stderr**; `--json`/`--version` → **stdout**.
2. `reconpro dev <dir>` saves the "last scan"; `reconpro export <f>.sarif` serialises it.
3. `reconpro ast <single-file>` is an upstream no-op (analyzes directories only) —
   the scan action always targets the project root.
4. `COLUMNS=200` forces deterministic Rich table widths (set by `run()`).

## Validate in this repo (no IDE required)

```bash
python3 ide/jetbrains/tools/validate.py   # exit 0 = PASS
```
