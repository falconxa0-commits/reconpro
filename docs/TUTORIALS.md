# ReconPro Tutorials — the beginner track

Hands-on tutorials, ordered from zero to CI integration. Every command
shown here was executed on a clean install (`pip install reconpro`,
v11.2.0) while writing this page — outputs are real, not illustrative.

> Time budget: T1 ≈ 5 min · T2 ≈ 10 min · T3 ≈ 10 min · T4 ≈ 15 min

## T1 — First scan in 5 minutes

### 1. Install (Python 3.10+)

```bash
python -m venv .venv && source .venv/bin/activate
pip install reconpro
reconpro --version        # ReconPro 11.2.0
```

Optional extras, only if you need them: `pip install "reconpro[full]"`.

### 2. Health-check your own machine (no network)

```bash
reconpro doctor
```

`doctor` audits the local machine: firewall, SSH hardening, disk
encryption, mandatory access control, kernel CVEs, world-writable
paths. It prints a findings table, per-finding fix commands, and exits 0
when it ran cleanly. `reconpro doctor --json` gives the same data
machine-readably; `reconpro doctor --repair` applies the safe automatic
fixes.

### 3. Meet the catalog

```bash
reconpro list             # the 28-module catalog
reconpro tutorial --list  # the 8-step guided tour overview
reconpro tutorial         # …then start it for real
```

### 4. First remote scan

Only scan targets you own or are authorized to test:

```bash
reconpro scan example.com --modules recon --json --timeout 60    # (network)
```

`--json` puts machine-readable results on stdout (human output goes to
stderr, so pipes stay clean). Add modules with `--modules recon,auth,chain`
or see `reconpro scan --help` for the full option set.

**What you get, and what you don't**: every remote scan first validates
the target (DNS → TCP → HTTP/TLS). Try it against a domain that cannot
resolve:

```bash
reconpro scan nonexistent-target-xyz.invalid --json -t 2
```

Real output (v11.2.0):

```jsonc
{
  "total_findings": 1,
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",                    // unreachable — no claim is made
  "modules_run": [],
  "target_validation": {"state": "UNREACHABLE_TARGET", "dns_resolved": false},
  "scan_metadata": {"duration_s": 0.01, "result": "unreachable_target_short_circuit"}
}
```

That single finding is the honest explanation ("Target unreachable —
scan not performed"), not a fake audit. A scanner that reports HIGH
findings about a host it never reached is lying to you; ReconPro is
built not to.

## T2 — Audit your machine and keep a report

```bash
reconpro ports            # live open-port + risky-service check
reconpro audit            # full local audit (seeds the "last scan")
reconpro export audit-report.md     # Markdown, grade badge included
reconpro export audit-report.sarif  # SARIF 2.1.0 for tooling
reconpro history          # every scan stored on this machine
```

Real `reconpro history` table (this machine, truncated):

```
┃ Date             ┃ Target                    ┃ Score   ┃ Grade  ┃ Findings  ┃
│ 2026-09-18T00:37 │ demo-app                  │ 85      │ A      │ 1         │
│ 2026-09-18T00:37 │ nonexistent-target-xyz.in │ 0       │ U      │ 1         │
│ 2026-09-18T00:36 │ localhost                 │ 0       │ F      │ 19        │
```

The runnable version of this tutorial is
[`examples/cli/02-machine-audit.sh`](../examples/cli/02-machine-audit.sh).

## T3 — SARIF in CI (GitHub Actions)

The repo ships a composite action: [`actions/reconpro-scan`](../actions/reconpro-scan).
It installs the CLI, runs AST analysis + secrets scan + project scan, exports
SARIF, uploads it as an artifact, and ingests it into GitHub Code Scanning.

Create `.github/workflows/reconpro.yml` in **your** repository:

```yaml
name: ReconPro

on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: falconxa0-commits/reconpro/actions/reconpro-scan@v11.2.0
        with:
          target: .
          format: sarif      # sarif | json | md | html
          timeout: '300'
```

Inputs: `target` (file or dir, default `.`), `workspace`, `format`
(extension-driven, default `sarif`), `timeout` (seconds per invocation),
`python-version` (default `3.11`). Outputs: `sarif-path`,
`secrets-json-path`.

Pin an exact version by setting the job env `RECONPRO_INSTALL_SPEC` —
e.g. `reconpro==11.2.0` — otherwise the action installs the CLI from PyPI
(or from the repo itself when it *is* reconpro).

This is the same pipeline the project runs on itself — see
[`.github/workflows/reconpro-scan.yml`](../.github/workflows/reconpro-scan.yml)
(the demo workflow) for a live, green example. The full pipeline
exit-code contract (what a `1` vs `2` vs `130` means for your pipeline)
is documented in [guides/ENTERPRISE.md](guides/ENTERPRISE.md#the-exit-code-contract-for-pipelines).

## T4 — Your first sandboxed plugin

Plugins run in a separate OS process with RLIMIT_AS 128 MiB / CPU 10 s /
FSIZE 16 MiB, an audit hook blocking subprocess/sockets/privilege
escalation/out-of-workdir writes, and Ed25519 signing. The full contract is
in [docs/PLUGINS.md](PLUGINS.md); the 6-step loop:

```bash
reconpro plugin create-sdk my-check   # 1. scaffold
$EDITOR my-check/main.py              # 2. make run() return findings
reconpro plugin sign my-check         # 3. Ed25519-sign the source dir
reconpro plugin install my-check      # 4. verify + register
reconpro plugin verify my-check       # 5. hash drift + signature + statics
reconpro plugin run my-check example.com   # 6. run it in the sandbox
```

If the installed source is edited after install, `plugin verify` fails on
`source_hash` — drift detection is enforced, not decorative. Recovery:
`plugin remove <id>`, re-`sign`, re-`install`.

Experiment safely in `reconpro playground` first — it exercises the sandbox
without touching your plugin registry.

## T5 — SDKs in 5 minutes

Client SDKs wrap the CLI's JSON output in typed results:

| SDK | Example | Status |
|---|---|---|
| Python | [`sdks/python/examples/basic.py`](../sdks/python/examples/basic.py) | tested locally + in CI |
| Node.js | [`sdks/node/examples/basic.mjs`](../sdks/node/examples/basic.mjs) | tested locally + in CI |
| Java | [`sdks/java/examples/Basic.java`](../sdks/java/examples/Basic.java) | tested locally |
| Go | [`sdks/go/examples/basic/main.go`](../sdks/go/examples/basic/main.go) | compiled + tested on Actions runners (`SDKs` workflow) |
| Rust | [`sdks/rust/examples/basic.rs`](../sdks/rust/examples/basic.rs) | compiled + tested on Actions runners (`SDKs` workflow) |

```bash
# Python SDK, from the repo:
pip install -e sdks/python
python sdks/python/examples/basic.py --target 127.0.0.1
```

## Where to go next

- [reference/CLI_REFERENCE.md](reference/CLI_REFERENCE.md) — every subcommand, captured from real `--help`
- [guides/SCANNING.md](guides/SCANNING.md) — how to drive the scanner well
- [SECURITY.md](SECURITY.md) — the security contract (TLS by default, sandbox, prompt defense)
- [RELEASE.md](RELEASE.md) — reproducible releases, SBOM, signatures
- [ROADMAP.md](ROADMAP.md) — where the project is going
- [CONTRIBUTING.md](../CONTRIBUTING.md) — become a contributor
