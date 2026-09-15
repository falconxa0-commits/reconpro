# reconpro-sdk (Java)

Zero-dependency Java wrapper around the ReconPro CLI (`python -m reconpro.cli`), JDK 17+.
Every call uses a ProcessBuilder **argument list** — never a shell string.

## API
| Method | Returns | Notes |
|---|---|---|
| `version()` | `String` | e.g. `"ReconPro 11.1.0"` |
| `doctor()` | `String` | raw JSON of `doctor --json` (zero-dep: no JSON parser included) |
| `history()` | `String` | raw text — CLI quirk: `history` has **no** `--json` flag; human table on STDERR |
| `scan(target)` | `String` | raw JSON; network; shell metacharacters rejected client-side |
| `export(path, format)` | `String` | CLI `export` subcommand, format from extension (`.sarif/.md/.json/.html`) — needs a prior scan |
| `run(cliArgs)` | `Result` record | `(exitCode, stdout, stderr)` for successful runs |

Errors: `ReconProClient.SdkException` (RuntimeException) with `.exitCode` (-1 = spawn/timeout) and `.stderrText`.

## Config
- env `RECONPRO_PYTHON` (default `/home/z/.venv/bin/python3`)
- env `RECONPRO_ROOT` (default `/home/z/my-project/download/reconpro-github`) — subprocess cwd
- default timeout 120s (`waitFor`, killed via `destroyForcibly`)

## Run tests + example
```
cd sdks/java && bash build.sh
```
Compiler note: this sandbox ships a **JRE-only OpenJDK 21** (`java` present, `javac`
absent — contradicting the stated environment facts). `build.sh` therefore prefers
`javac` and falls back to the Eclipse batch compiler (ecj, downloaded once from
Maven Central, run via `java -jar ... -source 21 -target 21`). Tests are executed
with the system `java`.
Status: **TESTED** — compiles (ecj 3.36.0, source level 21); ClientTest 5/5 PASS +
offline example runs (see build.sh output).

## Files
`src/main/java/com/reconpro/sdk/ReconProClient.java` (entry point),
`src/test/java/ClientTest.java`, `examples/Basic.java`, `build.sh`.
`export()` is implemented but **untested** (requires a prior scan; no network scans were run here).
