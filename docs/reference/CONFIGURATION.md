# Configuration

ReconPro is configuration-light: a fresh install works with **zero
configuration**, and everything has a sensible default. This page maps
everything that lives on disk (`~/.reconpro/`), the optional
`config.json`, and the environment variables the CLI actually reads.

Everything below was verified against v11.2.0 source
(`reconpro/constants.py`, `reconpro/diagnostics.py`, `reconpro/history.py`)
and against a live `~/.reconpro/` directory in active use.

## The home directory: `~/.reconpro/`

`RECONPRO_HOME` is `Path.home() / ".reconpro"` (`reconpro/constants.py`)
— it is created on first use. The observed layout on a machine that has
run scans, plugins and the engineering pipeline:

| Path | Owner | Contents |
|---|---|---|
| `history/` | `reconpro/history.py` | one JSON file per saved scan (`YYYYMMDD_HHMMSS_<target>.json`); feeds `reconpro history`, `diff`, `report`, `export` |
| `plugins/` | `reconpro/plugins.py`, `reconpro/plugin_sdk/` | installed plugins (`<id>/` SDK dirs, loose `*.py` legacy plugins), `registry.json` (0600), `keys/` (your dev keypair + trusted public keys) |
| `memory/` | `reconpro/memory.py` | knowledge-graph memory: `graph.json`, `repository_memory.json`, `benchmarks/`, `engineering_cycles/`, `quality_snapshots.json`, … |
| `drift/` | `reconpro/drift_monitor.py` | per-target drift snapshots (`drift/<target>/`) |
| `threat_feeds/` | `reconpro/threat_feeds.py` | downloaded/cached threat-feed data |
| `baselines/`, `metrics/`, `hall/` | engineering systems | benchmark baselines, run metrics, and the "hall" (wishes) state |
| `prompt_defense.log` | `reconpro/prompt_defense.py` | rotated prompt-injection defense audit log |
| `security_chain.log` | `reconpro/security_hardening.py` | tamper-evident (hash-chained) security event log |
| `workspaces/` | `reconpro/workspace.py` | named scan workspaces (`workspaces/<name>/`) |
| `config.json` | you (optional) | see below |

A subtlety, documented honestly: `constants.py` also defines
`SCAN_HISTORY_DIR = ~/.reconpro/scans`, which some diagnostics check —
but the operative scan writer is `history.py`'s
`HISTORY_DIR = ~/.reconpro/history` (verified: 101 scan files live
there on the machine this page was written on). Scans go to `history/`.

## `~/.reconpro/config.json`

Optional. If present, it must be a valid JSON **object** — that is the
only rule the validator enforces today (`diagnostics.validate_config()`):

- missing file → fine, defaults are used (reported as `info`)
- valid JSON object → fine
- invalid JSON, non-object, or unreadable/binary content → the doctor
  reports an `error` finding with the exact parse error and the
  suggestion `rm ~/.reconpro/config.json` (a corrupted config must never
  crash the CLI — regression-tested in `test_truth_layer.py`)

Verified behavior of `reconpro doctor` with a deliberately corrupted
config:

```
$ echo -e '\x00\x01binary garbage' > ~/.reconpro/config.json
$ reconpro doctor --json        # still exits 0, reports the problem as a finding
$ rm ~/.reconpro/config.json
```

There is **no** documented set of settings keys yet — ReconPro's knobs
are CLI flags (`--timeout`, `--rate-limit`, `--modules`, …), not config
keys. The config file exists so that future versions can grow one
without a breaking change; today it is validated, not interpreted.

## Environment variables

The complete list of environment variables read by the runtime (checked
by grep across `reconpro/`, excluding tests):

| Variable | Read by | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | AI components (`nexus_agent`, `chain_engine`, `ai_copilot`) | OpenAI key for LLM-backed features (`agent`, `chat`, `copilot`) |
| `ANTHROPIC_API_KEY` | same | Anthropic key (used when no OpenAI key) |
| `RECONPRO_MODEL` | `nexus_agent.py` | model override for the AI agent (default `gpt-4o-mini` / `claude-sonnet-4-20250514`) |
| `RECONPRO_AI_KEY` | `ai_copilot.py` | additional accepted key variable for the copilot |
| `VIRUSTOTAL_API_KEY` | `cli.py` (passive intel) | VirusTotal quota for `reconpro passive` |
| `NVD_API_KEY` | `cve_radar.py` | NVD API rate-limit quota for `reconpro cve` |
| `RECONPRO_SANDBOX=1` | set *by* the plugin runner in the worker | marks the sandboxed plugin process (informational) |
| `RECONPRO_TEST_PYPI` | release tooling | post-publish release-test mode |

The **plugin sandbox strips** `RECONPRO_RELEASE_KEY`,
`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY` and
`ANTHROPIC_API_KEY` from the worker environment even when a manifest
allowlists them (see [PLUGINS.md](../PLUGINS.md)).

The SDKs additionally read `RECONPRO_PYTHON`, `RECONPRO_ROOT`,
`RECONPRO_TIMEOUT` / `RECONPRO_TIMEOUT_MS` — see
[SDKS.md](../SDKS.md).

There is **no telemetry** — none of these variables are required, and
nothing is sent anywhere unless you invoke a command that explicitly
needs it.

## Command-line overrides (the knobs that exist today)

| Flag | Range | Default | Verified behavior |
|---|---|---|---|
| `--timeout`, `-t` | 1–600 (seconds) | 8 | `--timeout 0`, `-5`, `601` all exit `2` with the usage error |
| `--rate-limit` | 0.1–1000 (req/s) | 10.0 | `--rate-limit 2000` and `0.01` exit `2` |
| `--modules`, `-m` | comma-separated module IDs (see `reconpro list`) | 20 default remote modules | unknown IDs are silently dropped from the plan; check `modules_run` in the JSON |
| `--insecure`, `-k` | flag | TLS verified | disables TLS verification for that scan; the target then typically validates as `VERIFIED_TARGET` with `tls_valid: false` — see [guides/ADVANCED.md](../guides/ADVANCED.md#insecure-mode--partial-targets) |
| `--all`, `-a` | flag | — | runs all 25 remote modules |
| `--json` | flag | human output | JSON on stdout, human output on stderr |

Anything else is a hard usage error (exit 2) — the CLI never guesses.
