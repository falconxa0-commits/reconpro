# Contributing to ReconPro

Thanks for helping. This project has one rule above all: **repository
reality is the only truth** — claims in docs and PRs must be backed by
commands that were actually run.

## Development setup

```bash
git clone https://github.com/falconxa0-commits/reconpro.git
cd reconpro

python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"       # package + pytest/pytest-cov
pip install ruff               # same linter CI uses

reconpro --version             # smoke: ReconPro 11.1.0
```

Python 3.10+ for development; CI tests 3.11 / 3.12 / 3.13.

## Repository map

```
reconpro/            the package — 28 modules, CLI, engine, plugin SDK
reconpro/tests/      3200+ tests across 53 files
docs/                user + operator documentation
examples/            runnable CLI and Python examples
tools/               release_manager, bench_startup, security_scan, chunked-test runner
sdks/                python / node / java / go / rust client SDKs
ide/                 vscode / jetbrains / neovim integrations
actions/             composite GitHub Action (reconpro-scan)
github-app/          GitHub App manifest + webhook receiver
.github/workflows/   ci.yml · security.yml · sdks.yml · release.yml · reconpro-scan.yml
```

## Running the gates (mirror of CI)

CI runs exactly these — run them locally before pushing:

```bash
# 1. Lint — fatal-error selection (E9/F63) until [tool.ruff] lands
ruff check reconpro --select E9,F63

# 2. Tests — chunked, because one full-suite pytest invocation hangs (known issue)
bash tools/run_test_chunks.sh

# 3. Startup gate — median cold start must be <= 100 ms
python tools/bench_startup.py --threshold-ms 100 --json-out bench_startup.json

# 4. Security AST scan — fails on NEW findings vs the baseline
python tools/security_scan.py \
  --baseline-file tools/security_baseline.json \
  --sarif-out security_scan.sarif
```

Notes on the test suite:

- Chunk membership lives in `tools/ci_test_groups.txt`; a handful of files
  are excluded **with documented reasons** at the bottom of that file. Do
  not merge excluded files back without re-running the per-file sweep
  (`tools/test_sweep.sh`).
- The plugin-sandbox and security suites are the project's crown jewels —
  if your change touches `reconpro/plugin_sdk/`, `safe_command.py`,
  `safe_archive.py` or the CLI argument handling, those groups must stay
  green.

## The local SDK smoke tests (Go/Rust need toolchains)

```bash
bash sdks/python/smoke.sh    # runs everywhere
bash sdks/node/smoke.sh      # needs node
bash sdks/go/smoke.sh        # needs go toolchain; exits 3 (ENVIRONMENT BLOCKED) without
bash sdks/rust/smoke.sh      # needs cargo; exits 3 without
```

On machines without Go/Rust toolchains, the `SDKs` GitHub Actions workflow
compiles and tests them on real runners — a green `SDKs` run is the
authoritative check for those two.

## Making changes

1. **Small, honest commits.** If a commit message says "fix X", the diff
   should fix X.
2. **Tests move with code.** New behavior needs a test in the right chunk;
   moved tests need `ci_test_groups.txt` updated.
3. **Docs are deliverables.** If you add a command or change output, update
   `docs/CLI_REFERENCE.md` (it is generated from real `--help` output) and
   the relevant guide.
4. **No new security-baseline findings.** Run gate 4 above; if your change
   legitimately resolves an old finding, shrink the baseline — never grow
   it to make CI pass.
5. **PR description = evidence.** Paste the commands you ran and their exit
   codes. "Works on my machine" is not evidence; `bash tools/run_test_chunks.sh`
   output is.

## Releasing (maintainers)

Releases are reproducible and signed — read [docs/RELEASE.md](docs/RELEASE.md)
first. The short version:

```bash
python tools/bump_version.py <new-version>   # updates version + docs refs
python tools/release_manager.py all --reproducible
python tools/release_manager.py verify       # must exit 0
git tag vX.Y.Z && git push --tags           # release.yml builds + signs + publishes
```

The wheel is byte-reproducible; the sdist is not (tar/gzip nondeterminism
under the setuptools backend — documented in the release manifest). The
Ed25519 signature over `SHA256SUMS` is authoritative.

## Security issues

Do **not** open public issues for vulnerabilities. Follow the reporting
guidance in [docs/SECURITY.md](docs/SECURITY.md).

## Code style

- Python 3.10+ typing, ES-style imports, no wildcard imports.
- Rich markup in CLI output must be escaped — user-controlled strings go
  through `rich.markup.escape` (see `docs/SECURITY.md`, "Rich markup
  injection").
- Strict CLI: unknown arguments exit 2, always. JSON on stdout, human
  output on stderr.
- MIT license; by contributing you agree your work is licensed the same way.
