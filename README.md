<div align="center">

# ReconPro v11

**Pure-Python security reconnaissance engine — 28 modules, 81 commands, honest by construction.**

[![CI](https://github.com/falconxa0-commits/reconpro/actions/workflows/ci.yml/badge.svg)](https://github.com/falconxa0-commits/reconpro/actions/workflows/ci.yml)
[![Security](https://github.com/falconxa0-commits/reconpro/actions/workflows/security.yml/badge.svg)](https://github.com/falconxa0-commits/reconpro/actions/workflows/security.yml)
[![SDKs](https://github.com/falconxa0-commits/reconpro/actions/workflows/sdks.yml/badge.svg)](https://github.com/falconxa0-commits/reconpro/actions/workflows/sdks.yml)
[![Release](https://github.com/falconxa0-commits/reconpro/actions/workflows/release.yml/badge.svg)](https://github.com/falconxa0-commits/reconpro/actions/workflows/release.yml)
[![PyPI version](https://img.shields.io/pypi/v/reconpro.svg)](https://pypi.org/project/reconpro/)
[![PyPI downloads](https://img.shields.io/pypi/dm/reconpro.svg)](https://pypi.org/project/reconpro/)
[![Python versions](https://img.shields.io/pypi/pyversions/reconpro.svg)](https://pypi.org/project/reconpro/)
[![License: MIT](https://img.shields.io/pypi/l/reconpro.svg)](LICENSE)

[Quickstart](#quickstart--60-seconds) · [Verify a release](#verifying-a-release) · [Architecture](#architecture) · [Screenshots](#screenshots) · [All documentation](#documentation)

</div>

---

ReconPro **v11.2.0** is a pure-Python security reconnaissance platform:
remote and local scanning behind a **truth layer** that validates every
target before claiming anything about it, a sandboxed plugin SDK,
machine-readable output (JSON / SARIF / Markdown / HTML) for CI/CD
pipelines, MITRE ATT&CK mapping, and reproducible, signed releases.

Every number on this page was counted or measured from the repository,
not invented:

- **28 scan modules** (25 remote/advanced + 3 local: `host`, `dev`,
  `doctor`) — counted via `reconpro list --all`; every module is
  execution-tested (`reconpro/tests/test_module_execution.py`)
- **81 top-level commands** — counted from `reconpro --help` and from the
  81 `add_parser()` calls in `reconpro/cli.py`
- **3301 tests across 53 files** (`pytest --collect-only` on this tree),
  including a plugin sandbox-attack suite, a 150-test prompt-injection
  defense suite, and a secret-detection corpus with **22 positive secret
  classes (zero missed) and 15 negative lookalike classes (zero false
  positives)**
- **Strict CLI** — unknown commands and arguments exit `2` with
  did-you-mean suggestions; the `reconpro example.com` shorthand still
  works for URL / IPv4 / dotted-domain / localhost targets
- **Honest scans** — a target that cannot be resolved or reached is
  reported as such (score 0, grade `U`, one explanation finding); HIGH
  severity findings against unreachable targets are impossible by
  construction
- **Every finding carries evidence** plus a `confidence` (0–1) and the
  `verification_state` of the target it came from
  (`VERIFIED_TARGET` / `PARTIAL_TARGET` / `UNREACHABLE_TARGET`)
- **TLS verified by default** everywhere; `--insecure`/`-k` is the single,
  audited opt-out — it validates the target with `tls_valid: false`
  permanently recorded in the report, and when the target only partially
  verifies (PARTIAL_TARGET, e.g. self-signed cert without `--insecure`)
  severities are capped at MEDIUM
- **Sandboxed plugin SDK** — separate OS process with RLIMIT_AS 128 MiB /
  CPU 10 s / FSIZE 16 MiB, an audit hook blocking subprocess/sockets/
  privilege changes/out-of-workdir writes, Ed25519 signing, and an
  install/verify/upgrade lifecycle — [docs/PLUGINS.md](docs/PLUGINS.md)
- **Prompt-injection defense** on all AI-facing components (chat, agent,
  copilot)
- **Reproducible, signed releases** — byte-identical wheel **and** sdist
  rebuilds, CycloneDX 1.5 SBOM with licenses, `SHA256SUMS` with Ed25519 +
  GPG signatures, a `PROVENANCE.json` trust chain, and a mandatory release
  gate — [docs/RELEASE.md](docs/RELEASE.md),
  [docs/RELEASES.md](docs/RELEASES.md)
- **Language SDKs** — Python / Node.js / Java / Go / Rust wrappers around
  the CLI's JSON output — [docs/SDKS.md](docs/SDKS.md)
- **Fast startup** — the `--version` cold start measured **49.0 ms
  median** (7-run `tools/bench_startup.py` session on the v11.2.0
  release tree; p95 ≤ 49.2 ms; ~46 ms on the developer workstation where the
  lazy-import work landed); CI gate at 100 ms —
  [docs/PERFORMANCE.md](docs/PERFORMANCE.md)

## Quickstart — 60 seconds

```bash
pip install reconpro

reconpro --version      # ReconPro 11.2.0
reconpro doctor         # health-check this machine (local, no network)
reconpro tutorial       # 8-step guided tour
reconpro scan example.com --modules recon --json --timeout 60   # (network)
```

Runnable scripts for every workflow live in [`examples/`](examples/) —
each one was executed before being committed.

## Installation

```bash
pip install reconpro          # from PyPI
```

Optional extras: `pip install "reconpro[full]"` (aiohttp, playwright,
openai/anthropic, networkx, scapy, shodan, websockets) or pick
individually: `async`, `browser`, `llm`, `graph`, `raw`, `intel`,
`collab`, `integrations`.

Runtime dependencies: `rich>=13`, `textual>=0.40`, `requests>=2.28`,
`cryptography>=41`. Python **3.10+**.

From source:

```bash
git clone https://github.com/falconxa0-commits/reconpro.git
cd reconpro
pip install -e .                # editable install
# or build a reproducible wheel + sdist yourself:
python tools/release_manager.py build --reproducible
```

## Verifying a release

Every release ships `SHA256SUMS` signed with **Ed25519** (authoritative)
plus a GnuPG detach-signature, a CycloneDX 1.5 SBOM, and a
`PROVENANCE.json` trust chain (developer → commit → source digest →
build → signatures → user). The GPG public key
(`5F3D 637E FDE1 E8F5 6568 BEE0 2331 2E75 1E3F 9F89`) is published in
[docs/keys/](docs/keys/) and on `keyserver.ubuntu.com` /
`keys.openpgp.org`.

```bash
# after downloading the release assets (wheel, sdist, SBOM, SHA256SUMS,
# SHA256SUMS.ed25519, SHA256SUMS.asc) into one directory:

sha256sum -c SHA256SUMS                 # 1. every artifact hash

python3 - <<'EOF'                       # 2. the Ed25519 signature
from pathlib import Path
pub = bytes.fromhex(Path("tools/keys/release_key.pub").read_text().strip())
sig = bytes.fromhex(Path("SHA256SUMS.ed25519").read_text().strip())
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
Ed25519PublicKey.from_public_bytes(pub).verify(sig, Path("SHA256SUMS").read_bytes())
print("Ed25519 signature: VALID")
EOF

gpg --import docs/keys/reconpro-release-5F3D637E.asc   # 3. the GPG signature
gpg --verify SHA256SUMS.asc SHA256SUMS
```

From a repository checkout you can instead run the all-in-one verifier
(exit 0 = hashes, signatures, SBOM, manifest and provenance chain all
consistent):

```bash
python tools/release_manager.py verify
```

Full procedure, key-rotation process and per-release evidence:
[docs/RELEASE.md](docs/RELEASE.md), [docs/keys/](docs/keys/),
[docs/RELEASES.md](docs/RELEASES.md), [docs/PROVENANCE.md](docs/PROVENANCE.md).

## Architecture

```
                 ┌────────────────────────────────────────────┐
                 │  CLI (reconpro/cli.py — 81 subcommands)    │
                 │  strict argv parsing · JSON on stdout,     │
                 │  human output on stderr · exit 0/1/2/130   │
                 └───────────────┬────────────────────────────┘
                                 │  remote scan?
                                 ▼
                 ┌────────────────────────────────────────────┐
                 │  TARGET VALIDATION PIPELINE (truth layer)   │
                 │  DNS ──▶ TCP ──▶ HTTP/TLS                   │
                 │  VERIFIED_TARGET │ PARTIAL_TARGET │         │
                 │  UNREACHABLE_TARGET (short-circuit: no     │
                 │  modules run, score 0, grade U)             │
                 └───────────────┬────────────────────────────┘
                                 ▼
                 ┌────────────────────────────────────────────┐
                 │  ENGINE (reconpro/engine.py, async)         │
                 │  concurrent modules · per-module adaptive   │
                 │  timeouts · module-health circuit breakers │
                 │  (unhealthy modules are quarantined)       │
                 └───────────────┬────────────────────────────┘
                                 ▼
        ┌────────────────────────────────────────────────────────┐
        │  28 MODULES (reconpro/registry.py is the single        │
        │  source of truth): recon, auth, chain, bot, gorgon,    │
        │  oblivion, vibesec, nhi, pegasus, cloud_recon, team,   │
        │  quantum_fingerprint, dark_web_monitor, info_ops,       │
        │  steganography_detector, covert_channel, zero_day_     │
        │  hunter, infrastructure_ghost, signal_intelligence,     │
        │  nation_state_attributor, weaponized_report,            │
        │  honeypot_dance, dead_drop, container_sec, iac_audit    │
        │  + local: host, dev, doctor                             │
        └───────────────┬────────────────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────────────────┐
        │  FINDINGS — every one carries: evidence, confidence    │
        │  (0–1), verification_state, severity, category,       │
        │  remediation, points_deducted (reconpro/http_layer.py   │
        │  Finding dataclass)                                    │
        └───────────────┬────────────────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────────────────┐
        │  REPORTS — JSON / SARIF 2.1.0 / Markdown / HTML        │
        │  (+ printable-HTML PDF export; CSV via the Python API) │
        │  each report includes target_validation + scan_metadata │
        │  (started_at, duration_s)                              │
        └───────────────┬────────────────────────────────────────┘
                        ▼
           HISTORY (~/.reconpro/history/*.json — one file per scan;
           feeds `reconpro history`, `diff`, `export`, `report`)
```

Details: [docs/development/ARCHITECTURE.md](docs/development/ARCHITECTURE.md).

## Screenshots

Real terminal captures — animated SVGs recorded from actual runs (see
`docs/screenshots/`; regenerate any of them with the commands shown):

<table>
<tr>
<td width="50%">

**The command surface** — `reconpro --help`

<img src="docs/screenshots/help.svg" alt="reconpro --help output: 81 subcommands from scan to copilot" width="100%">

</td>
<td width="50%">

**The module catalog** — `reconpro list`

<img src="docs/screenshots/list.svg" alt="reconpro list output: 28 modules from recon to dead-drop" width="100%">

</td>
</tr>
<tr>
<td width="50%">

**A live scan** — `reconpro ports`

<img src="docs/screenshots/ports.svg" alt="reconpro ports output: banner and 5 open ports detected" width="100%">

</td>
<td width="50%">

**Machine audit** — `reconpro doctor`

<img src="docs/screenshots/doctor.svg" alt="reconpro doctor output: findings table with severities and remediations" width="100%">

</td>
</tr>
</table>

## Use it in CI — SARIF in ~10 lines

```yaml
- uses: falconxa0-commits/reconpro/actions/reconpro-scan@v11.2.0
  with:
    target: .
```

The composite action runs AST analysis + secrets + project scan, exports
SARIF 2.1.0, uploads the artifact and ingests it into GitHub Code
Scanning. Tutorial:
[docs/TUTORIALS.md](docs/TUTORIALS.md#t3--sarif-in-ci-github-actions);
pipeline exit-code contract:
[docs/guides/ENTERPRISE.md](docs/guides/ENTERPRISE.md).

## Python API

```python
from reconpro import scan, audit_scan, __version__

result = audit_scan(".")                     # local, no network
print(result.total_score, result.grade)      # 0-100, A+..F
print(result.severity_counts)                # {'critical': 3, ...}

result = scan("example.com", modules=["recon"], timeout=60)   # (network)
for f in result.findings:                    # every finding carries
    print(f["confidence"], f["verification_state"])
```

Full JSON schema (including `target_validation` and `scan_metadata`):
[docs/reference/API.md](docs/reference/API.md).

## Documentation

Start at [docs/README.md](docs/README.md) — the documentation index.

| Document | Contents |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | install, first scan, doctor, tutorial, wizard, suggest — with real outputs |
| [docs/TUTORIALS.md](docs/TUTORIALS.md) | beginner track: first scan, machine audit, SARIF in CI, first plugin, SDKs |
| [docs/reference/CLI_REFERENCE.md](docs/reference/CLI_REFERENCE.md) | all 81 subcommands: usage, options tables, examples, exit codes |
| [docs/reference/CONFIGURATION.md](docs/reference/CONFIGURATION.md) | `~/.reconpro/` layout, config.json, environment variables |
| [docs/reference/API.md](docs/reference/API.md) | the JSON output schema + Python API, field by field |
| [docs/guides/SCANNING.md](docs/guides/SCANNING.md) | module selection, timeouts, rate limiting, honest-scan semantics |
| [docs/guides/REPORTS.md](docs/guides/REPORTS.md) | JSON/SARIF/MD/HTML reports and the truth-layer fields |
| [docs/guides/ADVANCED.md](docs/guides/ADVANCED.md) | blitz multi-target, diff, `--insecure` + PARTIAL_TARGET, plugins |
| [docs/guides/ENTERPRISE.md](docs/guides/ENTERPRISE.md) | CI/CD, exit-code contract, air-gapped verification, key rotation |
| [docs/PLUGINS.md](docs/PLUGINS.md) | plugin SDK: sandbox guarantees, permissions, manifest, signing, lifecycle |
| [docs/SECURITY.md](docs/SECURITY.md) | security posture: strict CLI, TLS-by-default, shell-free execution, sandbox |
| [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md) | what ReconPro protects against; attack surface of the tool itself |
| [docs/development/ARCHITECTURE.md](docs/development/ARCHITECTURE.md) | registry, engine, http_layer, finding schema, target validation |
| [docs/development/TESTING.md](docs/development/TESTING.md) | chunked test strategy, how to run it, what CI runs |
| [docs/RELEASE.md](docs/RELEASE.md) | release_manager, SBOM, checksums, signatures, reproducibility, gate |
| [docs/PROVENANCE.md](docs/PROVENANCE.md) | the commit → build → signature → user trust chain |
| [docs/RELEASES.md](docs/RELEASES.md) | release transparency: keys table, per-version evidence |
| [docs/SDKS.md](docs/SDKS.md) | the six language SDKs (Python/TS/Go/Rust/Node/Java) and their status |
| [docs/IDE.md](docs/IDE.md) | VS Code / JetBrains / Neovim / GitHub Action / GitHub App |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | startup numbers, benchmark tool, CI gate, lazy-import architecture |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what is next: enterprise, plugin marketplace, cloud dashboard, teams |
| [CONTRIBUTING.md](CONTRIBUTING.md) | developer onboarding: setup, gates, style, releasing |

## Repository layout

```
reconpro/            the package (28 modules, CLI, engine, plugin SDK, tests)
examples/            runnable CLI + Python examples (executed before commit)
docs/                documentation + screenshots/ (real terminal captures)
tools/               release_manager, release gate, bench_startup, security_scan
sdks/                python / node / java / go / rust SDKs
ide/                 vscode / jetbrains / neovim integrations
actions/             composite GitHub Action (reconpro-scan)
github-app/          GitHub App manifest + webhook receiver
.github/workflows/   ci.yml · security.yml · sdks.yml · release.yml · reconpro-scan.yml
dist/                signed release artifacts (wheel, sdist, SBOM, SHA256SUMS, signatures)
```

## Honest status notes

- **The repository is live and CI is green.** All five workflows (`CI`,
  `Security`, `SDKs`, `Release`, `ReconPro Scan`) pass on `main`; history
  includes failed-and-fixed runs — nothing is hidden, see the Actions tab.
- **The test suite runs in CI chunks**: the full suite in one pytest
  invocation hangs (known issue); a handful of files are excluded with
  documented reasons (see `tools/ci_test_groups.txt`).
- **Both wheel and sdist are byte-reproducible** since v11.2.0 (the
  release gate double-builds and compares bytes; the pre-v11.2.0 sdist
  was not — that gap is documented in [docs/RELEASES.md](docs/RELEASES.md)).
- **GPG key is published** at [docs/keys/](docs/keys/) (the v11.1.0 key
  was never published — recorded honestly as a gap in
  [docs/RELEASES.md](docs/RELEASES.md)).
- **Go/Rust SDKs are CI-verified** on GitHub Actions runners (the `SDKs`
  workflow compiles and tests them with real toolchains); a dev sandbox
  without toolchains gets an honest `exit 3 ENVIRONMENT BLOCKED` from
  `smoke.sh`. The **JetBrains plugin remains structurally validated only**
  (no IDE host) — see [docs/IDE.md](docs/IDE.md).
- **The `compliance` command maps findings to framework controls**
  (e.g. SOC2, PCI-DSS); it is a mapping/reporting aid, **not** a
  certification or audit attestation.

## Roadmap

Shipped in v11.2.0: sdist byte-reproducibility, GPG key publication,
mandatory release gate, scanner truth layer, strict unknown-command
handling, secret-detection corpus. Next: stricter lint, one-shot pytest,
Windows/macOS CI matrix, report themes, CIS/STIG compliance packs —
and beyond: enterprise RBAC + audit streams, a signed **plugin
marketplace**, a **cloud dashboard** over the same engine, and **team
management** — full plan in [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — setup, the four CI gates to run
locally, code style, and the project's one rule: *repository reality is
the only truth*.

## License

MIT © ReconPro Security. See [LICENSE](LICENSE).
