# ReconPro Documentation

Start here. This index maps the whole documentation tree; every page was
written against **v11.2.0** and every command shown on any page was
executed (or is clearly marked as requiring network access / a
`<your-target.com>` placeholder).

The one rule of this documentation: **repository reality is the only
truth** — numbers are counted, outputs are pasted from real runs, and
anything that cannot be verified is labeled as such or removed.

## The map

```
docs/
├── README.md                 ← you are here (index)
├── GETTING_STARTED.md       getting started: install → first scan
├── TUTORIALS.md             beginner track: install → first SARIF report
│
├── guides/                  how to use ReconPro well
│   ├── SCANNING.md          module selection, timeouts, rate limits,
│   │                        honest-scan semantics (truth states)
│   ├── REPORTS.md           JSON/SARIF/MD/HTML + truth-layer fields
│   ├── ADVANCED.md          blitz, diff, --insecure & PARTIAL_TARGET,
│   │                        plugins, history, export formats
│   ├── ENTERPRISE.md        CI/CD, exit-code contract, air-gapped
│   │                        verification, key rotation
│   └── SDKS.md → ../SDKS.md   driving the CLI from Python/TS/Go/Rust
│
├── reference/               lookup pages
│   ├── CLI_REFERENCE.md     all 81 subcommands (captured --help output)
│   ├── CONFIGURATION.md     ~/.reconpro/ layout, config.json, env vars
│   └── API.md               JSON output schema + Python API
│
├── security/               the security story
│   └── THREAT_MODEL.md      what ReconPro protects against; the tool's
│                            own attack surface; sandbox design
│
├── development/            for contributors
│   ├── ARCHITECTURE.md      registry → engine → modules → findings
│   ├── TESTING.md           chunked test strategy, how to run, CI
│   └── ../CONTRIBUTING.md   setup, the four CI gates, style, releasing
│
├── SECURITY.md             security posture of the CLI itself
├── PLUGINS.md              plugin SDK: sandbox, permissions, signing
├── SDKS.md                 python/node/java/go/rust SDKs
├── IDE.md                  VS Code / JetBrains / Neovim / Actions / App
├── PERFORMANCE.md          cold-start numbers + lazy-import design
├── RELEASE.md              release engineering (build, sign, verify)
├── PROVENANCE.md           the trust chain, transition by transition
├── RELEASES.md             release transparency: keys + per-version evidence
├── ROADMAP.md              where the project is going
├── keys/                   release public keys + verification guide
└── screenshots/            real terminal captures (animated SVGs)
```

## Reading paths

| You are… | Read in this order |
|---|---|
| **New to ReconPro** | [GETTING_STARTED.md](GETTING_STARTED.md) → [TUTORIALS.md](TUTORIALS.md) → [reference/CLI_REFERENCE.md](reference/CLI_REFERENCE.md) |
| **Putting it in CI** | [guides/ENTERPRISE.md](guides/ENTERPRISE.md) → [guides/REPORTS.md](guides/REPORTS.md) → [TUTORIALS.md#t3--sarif-in-ci-github-actions](TUTORIALS.md#t3--sarif-in-ci-github-actions) |
| **Driving it from code** | [SDKS.md](SDKS.md) → [guides/ADVANCED.md](guides/ADVANCED.md) → [reference/API.md](reference/API.md) |
| **Scanning seriously** | [guides/SCANNING.md](guides/SCANNING.md) → [guides/ADVANCED.md](guides/ADVANCED.md) → [reference/CONFIGURATION.md](reference/CONFIGURATION.md) |
| **Writing a plugin** | [PLUGINS.md](PLUGINS.md) → [guides/ADVANCED.md#the-plugin-system](guides/ADVANCED.md#the-plugin-system) |
| **Auditing the tool** | [SECURITY.md](SECURITY.md) → [security/THREAT_MODEL.md](security/THREAT_MODEL.md) → [PROVENANCE.md](PROVENANCE.md) → [keys/README.md](keys/README.md) |
| **Contributing code** | [../CONTRIBUTING.md](../CONTRIBUTING.md) → [development/ARCHITECTURE.md](development/ARCHITECTURE.md) → [development/TESTING.md](development/TESTING.md) |
| **Packaging for an air-gapped org** | [guides/ENTERPRISE.md](guides/ENTERPRISE.md) → [RELEASE.md](RELEASE.md) → [RELEASES.md](RELEASES.md) |

## Conventions used across these pages

- **Commands marked `(network)`** reach out to the internet; everything
  else runs locally.
- **Exit codes**: `0` success · `1` runtime failure · `2` usage error
  (unknown command/flag, bad `--timeout`/`--rate-limit`) · `130` SIGINT.
- **JSON on stdout, human output on stderr** — `--json` commands are
  pipe-safe.
- **Placeholders** look like `<your-target.com>`; everything else is a
  literal command that was executed.
