# ReconPro CLI

**ReconPro v11.1.0** — a pure-Python security reconnaissance engine.
28 scan modules (remote, local, advanced), 81 top-level commands, a
sandboxed plugin SDK, and machine-readable output (JSON / SARIF / MD /
HTML) for CI/CD pipelines. Driven by `rich` for terminal output, strict
about arguments, fast to start (~46 ms cold).

- **28 scan modules** — recon, auth bypass, chain hunter, bot hunter,
  Gorgon, Oblivion, VibeSec, NHI graph, Pegasus, cloud recon, quantum
  fingerprinting, dark-web monitoring, info-ops, steganography, covert
  channels, zero-day hunting, infra ghosting, SIGINT, nation-state
  attribution, honeypot detection, dead drops, container/IaC security,
  and more — see `reconpro list`
- **81 top-level commands** — scan, audit, dev, doctor, tutorial,
  wizard, playground, suggest, plugin (sandboxed SDK), nexus, agent,
  swarm, adversarial, cve, graph, compliance, serve, report, history,
  diff, export, engineering, copilot, and ~60 more —
  see [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
- **Sandboxed plugin SDK** — plugins run in a separate OS process with
  RLIMIT_AS 128 MiB / CPU 10 s / FSIZE 16 MiB, an audit hook blocking
  subprocess/sockets/privilege changes/out-of-workdir writes, Ed25519
  signing, and an install/verify/upgrade lifecycle —
  see [docs/PLUGINS.md](docs/PLUGINS.md)
- **3200+ tests** (3262 collected; ~3277 test functions across 53 files)
  including 150 dedicated prompt-injection-defense tests, 34
  AST+behavioural security-sweep tests, and a plugin sandbox-attack suite
- **Strict CLI** — unknown or unrecognized arguments exit 2, always
  (never silently ignored); JSON on stdout, human output on stderr
- **TLS verified by default** everywhere; `--insecure`/`-k` is the
  single, audited opt-out
- **Prompt-injection defense** on all AI-facing components (chat,
  agent, copilot): injection detection, threat classification,
  sanitization, audit logging
- **Release pipeline** — reproducible wheel builds, CycloneDX 1.5 SBOM,
  SHA256SUMS with Ed25519 + GPG signatures, a verify command that
  actually detects tampering — see [docs/RELEASE.md](docs/RELEASE.md)
- **Language SDKs** — Python / Node.js / Java (tested) and Go / Rust
  (compile-blocked: no toolchains in the dev environment) —
  see [docs/SDKS.md](docs/SDKS.md)
- **IDE & CI support** — VS Code extension skeleton, JetBrains plugin
  skeleton, Neovim lua plugin, composite GitHub Action, GitHub App
  webhook — see [docs/IDE.md](docs/IDE.md)
- **Fast startup** — ~46 ms median cold start (was ~570 ms) via
  lazy rich + lazy engine imports; CI gate at 100 ms —
  see [docs/PERFORMANCE.md](docs/PERFORMANCE.md)

## Installation

```bash
pip install reconpro                        # from a PyPI-style index
# or from the built wheel in this repo:
pip install ./dist/reconpro-11.1.0-py3-none-any.whl
# or from source:
pip install -e .
```

Optional extras: `pip install "reconpro[full]"` (aiohttp, playwright,
openai/anthropic, networkx, scapy, shodan, websockets) or pick
individually: `async`, `browser`, `llm`, `graph`, `raw`, `intel`,
`collab`, `integrations`.

Runtime dependencies: `rich>=13`, `textual>=0.40`, `requests>=2.28`.
Python **3.10+**. Verify a downloaded release first —
[docs/RELEASE.md](docs/RELEASE.md).

## Quick start

```bash
reconpro --version                    # ReconPro 11.1.0
reconpro tutorial                     # 8-step guided tour
reconpro suggest                      # what should I run next?
reconpro doctor --json                # local health check (no network)
reconpro list                         # 28-module catalog
reconpro scan example.com --modules recon --json --timeout 60   # (network)
reconpro audit                        # full local machine audit
reconpro dev /path/to/project         # secrets, deps, git, docker
reconpro export report.sarif          # SARIF 2.1.0 for Code Scanning
reconpro wizard --non-interactive     # print a recommended scan plan
```

Full walkthrough: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

## Python API

```python
from reconpro import scan, audit_scan, __version__

result = scan("example.com", modules=["recon"], timeout=60)  # (network)
print(result.total_score, result.grade)
print(__version__)                        # 11.1.0
```

## Documentation

| Document | Contents |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | install, first scan, doctor, tutorial, wizard, suggest — with real outputs |
| [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | every one of the 81 subcommands: usage, options tables, examples, exit codes (captured from real `--help` output) |
| [docs/PLUGINS.md](docs/PLUGINS.md) | plugin SDK: sandbox guarantees, permissions, manifest, signing, lifecycle, worked example |
| [docs/SECURITY.md](docs/SECURITY.md) | strict CLI, TLS-by-default, shell-free execution, safe archives, prompt defense, plugin sandbox, reporting |
| [docs/RELEASE.md](docs/RELEASE.md) | release_manager.py, SBOM, checksums, signatures, reproducibility, CI workflows, version bumping |
| [docs/SDKS.md](docs/SDKS.md) | the five language SDKs and their status |
| [docs/IDE.md](docs/IDE.md) | VS Code / JetBrains / Neovim / GitHub Action / GitHub App |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | startup numbers, benchmark tool, CI gate, lazy-import architecture |

## Repository layout

```
reconpro/            the package (28 modules, CLI, engine, plugin SDK, tests)
docs/                this documentation set
tools/               release_manager, bench_startup, security_scan, bump_version, ci scripts
sdks/                python / node / java / go / rust SDKs
ide/                 vscode / jetbrains / neovim integrations
actions/             composite GitHub Action (reconpro-scan)
github-app/          GitHub App manifest + webhook receiver
.github/workflows/   ci.yml, release.yml, security.yml, reconpro-scan.yml
dist/                signed release artifacts (wheel, sdist, SBOM, SHA256SUMS, signatures)
```

## Honest status notes

- CI workflows exist in `.github/workflows/` and mirror locally
  verified commands, but this repository has **not been pushed to
  GitHub** and the workflows have never run there — hence no CI badges
  on this README.
- The test suite runs in CI chunks: the full suite in one pytest
  invocation hangs (known issue); a handful of files are excluded with
  documented reasons (see `tools/ci_test_groups.txt`).
- Go/Rust SDKs and the JetBrains plugin are complete but compile-blocked
  in the development environment (toolchains absent); their validation
  status is stated precisely in [docs/SDKS.md](docs/SDKS.md) and
  [docs/IDE.md](docs/IDE.md).

## License

MIT © ReconPro Security. See [LICENSE](LICENSE).
