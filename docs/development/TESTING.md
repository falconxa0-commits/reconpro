# Testing — the chunked strategy, how to run it, what CI runs

**3301 tests across 53 files** (counted live: `python -m pytest
reconpro/tests --collect-only -q` → "3301 tests collected"; `ls
reconpro/tests/test_*.py | wc -l` → 53). This page explains why they run
in chunks, how to run them yourself, and exactly what CI executes on
every push.

## Why chunked? (the known hang)

Running the **full suite in a single pytest invocation hangs** in this
repository — a known issue (the root cause is documented in the test
tooling; module-level event-loop and socket interactions between
otherwise-green files). The workaround is the design, not a secret:

- every test file is green **individually** (proven by
  `tools/test_sweep.sh`, which sweeps each file with a 20 s per-file cap
  and records PASS/FAIL/TIMEOUT per file);
- CI therefore runs the files in **explicit chunks** — each chunk is its
  own pytest invocation with a hard `timeout 600`;
- **zero files are currently excluded**: all 53 files run in CI (the
  exclusion list at the bottom of `tools/ci_test_groups.txt` documents
  the history — four previously-failing files were fixed and moved back
  in on 2026-09-05).

## The chunk file — `tools/ci_test_groups.txt`

```
smoke:            test_constants test_plugin_sdk test_plugin_sandbox_attacks
                  test_security_sweep test_utils test_formats test_scoring
                  test_finding test_scanner test_registry test_plugins
unit-core:        test_interfaces test_property test_input_validation
                  test_http_probe test_plugin_security test_security_regression
                  test_security_hardening test_security_hardening_v2
unit-security:    test_truth_layer test_security test_stress
                  test_rate_limiter test_regression_v11
                  test_intelligence_pipeline test_threat_intel
                  test_repository_memory
unit-engineering: test_engineering_integration
                  test_engineering_recommendations test_engineering_workflow
                  test_repository_learning test_regression_intelligence
                  test_auto_fix test_observability
unit-ai:          test_ai_analyst test_attack_graph test_auto_engineering
                  test_digital_twin test_pipeline_e2e
cli-misc:         test_cli test_diagnostics test_performance
                  test_prompt_defense test_quality_intelligence
                  test_coverage_boost test_enterprise
modules:          test_module_execution
slow:             test_auto_validation test_benchmark_automation
                  test_integration test_memory test_reliability
```

*(Illustrative summary — the authoritative list is the file itself.)*

The crown jewels are the security groups: `smoke` contains the
plugin-sandbox attack suite and the AST security-sweep invariants;
`unit-security` contains the truth-layer regression suite.

## How to run tests

```bash
# everything the way CI does it (chunked, 600 s hard cap per chunk):
bash tools/run_test_chunks.sh

# one chunk only:
python -m pytest reconpro/tests/test_truth_layer.py reconpro/tests/test_security.py -q

# a single file:
python -m pytest reconpro/tests/test_plugin_sandbox_attacks.py -q

# fast local mirror of the CI gates (lint → smoke → bench → security):
bash tools/ci_local.sh

# re-derive chunk membership after adding/moving tests (per-file sweep):
bash tools/test_sweep.sh /tmp/sweep.txt
```

`tools/run_test_chunks.sh` honors `PYTHON=` (interpreter) and
`GROUP_TIMEOUT=` (per-chunk cap, default 600 s); it exits non-zero if any
chunk fails **or times out**, printing per-group PASS/FAIL/TIMEOUT lines.

## What CI runs

`.github/workflows/ci.yml` — on every push/PR, matrix
**Python 3.11 / 3.12 / 3.13**, `ubuntu-latest`, 45-minute job timeout:

1. **Lint** — `ruff check reconpro --select E9,F63` (fatal-error
   selection; a full `[tool.ruff]` config is on the roadmap).
2. **Tests** — `bash tools/run_test_chunks.sh` (the chunked suite).
3. **Startup gate** — `python tools/bench_startup.py --threshold-ms 100`
   — median cold start must be ≤ 100 ms (measured: ~48 ms median on the
   authoring machine; see [../PERFORMANCE.md](../PERFORMANCE.md)).
4. **Security AST scan** — `python tools/security_scan.py --baseline-file
   tools/security_baseline.json` — fails the build on **new** findings vs
   the committed baseline.
5. Uploads the bench JSON + security SARIF as artifacts per matrix leg.

`.github/workflows/security.yml` — daily at 03:00 UTC (plus PRs): the
same security AST scan in baseline mode, a strict-mode informational
run, **pip-audit** with a pinning-check fallback, and SARIF upload.

`.github/workflows/sdks.yml` — the five language SDK suites (Python
pytest, TypeScript bun + plain-node dist smoke, Go, Rust on Actions
toolchains).

`.github/workflows/release.yml` — the release pipeline (tag-triggered);
see [../RELEASE.md](../RELEASE.md).

## Writing tests (what CI expects of you)

- New behavior needs a test **in the right chunk** — if you add a file,
  register it in `tools/ci_test_groups.txt` (a sweep with
  `tools/test_sweep.sh` proves it is individually green).
- Security invariants get AST tests (`test_security_sweep.py` is the
  template — it walks the source tree and asserts *structural* facts like
  "no unverified SSL context outside the two audited helpers").
- Truth-layer behavior belongs in `test_truth_layer.py`; plugin-sandbox
  attacks in `test_plugin_sandbox_attacks.py`.
- The release gate re-runs the full suite before anything ships — a
  security fix can never ship unverified.

## Honest limits

- The one-shot full-suite pytest hang is **not fixed** — it is contained
  by design (chunks + per-chunk timeouts). Fixing it is roadmap work.
- The JetBrains/Neovim integrations are structurally validated only (no
  IDE hosts in CI) — see [../IDE.md](../IDE.md).
- Coverage is not yet gated on a percentage; the AST security scan and
  the chunked suites are the gates that matter today.

## Where to go next

- [../../CONTRIBUTING.md](../../CONTRIBUTING.md) — the four local gates,
  mirrored from CI, and the PR evidence rule
- [ARCHITECTURE.md](ARCHITECTURE.md) — what sits under the tests
- [../PERFORMANCE.md](../PERFORMANCE.md) — the startup budget in detail
