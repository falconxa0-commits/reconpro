# PACKAGE MANIFEST — ReconPro CLI

**Release:** 11.1.0 "Celestial Ascension" (matches the web app changelog)
**Task ID:** CA-9 — CLI Release Engineer, Operation Celestial Ascension
**Date:** 2026-08-24
**Source tree:** `download/reconpro-github/` (flat layout, `reconpro/` package)

---

## Artifacts

| Artifact | Filename | Size (bytes) | SHA-256 |
|---|---|---|---|
| Wheel | `dist/reconpro-11.1.0-py3-none-any.whl` | 1,585,540 | `c9c1af42d8f9f93f5dc3f0b11dadba47bad91c627ee18f91e121027a3bb93add` |
| sdist | `dist/reconpro-11.1.0.tar.gz` | 1,485,372 | `b1c7835e4ad3af0a7ee417a08687bae85266ab273f4ed4d424cbce0821b7a88d` |

Canonical copies: `download/reconpro-11.1.0-py3-none-any.whl` and
`download/reconpro-11.1.0.tar.gz` (byte-identical, hashes above).
Built with `python -m build` (build 1.5.0, setuptools 84.0.0 backend,
`pyproject.toml` PEP 517/621). Prior releases
(`reconpro-11.0.0/11.0.1-py3-none-any.whl`) remain in the repo root for history.

## Package identity

- **Name:** `reconpro`
- **Version:** `11.1.0` — canonical in exactly three agreed places:
  1. `pyproject.toml` → `version = "11.1.0"`
  2. `reconpro/__init__.py` → `__version__ = "11.1.0"` (drives SDK import)
  3. `reconpro/constants.py` → `__version__ = "11.1.0"` (drives `reconpro --version`
     via `cli.py`'s `from . import __version__` → prints `ReconPro 11.1.0`)
- **Summary:** ReconPro v11 — Enterprise Security Reconnaissance Platform.
  28 Modules. 77 Commands. MITRE ATT&CK. SARIF/PDF/CSV. Pure Python.
  (Counts corrected from the stale "30 Modules. 50+ Commands.")
- **Author:** ReconPro Security \<security@reconpro.io\>
- **License:** MIT (SPDX expression; `LICENSE` file ships in wheel under
  `reconpro-11.1.0.dist-info/licenses/LICENSE`)
- **Requires-Python:** `>=3.10` (corrected from the original `>=3.8`, which the
  codebase never guaranteed — the platform targets Python 3.10+; all union
  annotations are guarded by `from __future__ import annotations`)
- **Entry point:** `reconpro = reconpro.cli:main` (console script)
- **URLs:** Homepage/Docs/Repository/Issues/Changelog → reconpro.io + GitHub

## Dependencies

Runtime: `rich>=13.0.0`, `textual>=0.40.0`, `requests>=2.28.0`

Extras: `test` (pytest, pytest-cov) · `async` (aiohttp) · `browser` (playwright) ·
`llm` (openai, anthropic) · `graph` (networkx) · `raw` (scapy) · `intel` (shodan) ·
`collab` (websockets) · `integrations` (jira, slack-sdk) · `full` (all of the above)

## Package contents

- **198 `.py` files** shipped (identical file set to the 11.0.0/11.0.1 wheels):
  - 100 top-level modules (`reconpro/*.py`)
  - `reconpro/modules/` — 30 files (28 registered scan modules + `__init__` +
    `ast_analyzer.py` helper)
  - `reconpro/tests/` — 49 files (in-package test suite, as in prior releases)
  - `reconpro/integrations/` — 7 files · `reconpro/widgets/` — 8 files ·
    `reconpro/scripts/` — 4 files (historical v11 report generators)
- **194 importable modules** (`pkgutil.walk_packages`) — import audit 194/194 OK
- **77 top-level subcommands** (`scan`, `vibesec`, `audit`, `doctor`, `nexus`,
  `agent`, `swarm`, `cve`, `graph`, `compliance`, `serve`, `report`, …)
- Zero `__pycache__` / `.pyc` in either artifact (verified programmatically)

## What was fixed in this release (metadata/hygiene only — no logic changes)

1. **Version canonicalization:** source said 11.0.1, primary venv reported
   11.0.2 (in-place patch), venv dist-info said 11.0.0. All now 11.1.0.
   Also bumped runtime-facing version strings (User-Agents, nexus TUI `VERSION`,
   `wishes.RECONPRO_VERSION`, webhook/Slack/regression footers, nexus banner)
   and the 5 test assertions that pinned the old version.
2. **Created `pyproject.toml`** (PEP 621) — no packaging config existed at all;
   prior wheels were hand-repacked zip archives. Metadata mirrors the original
   METADATA with corrected module/command counts and URLs added.
3. **Created `LICENSE`** (MIT, © ReconPro Security) and **`README.md`** (concise
   CLI readme pointing to `docs/CLI.md`, which lives at
   `/home/z/my-project/docs/CLI.md`).
4. **Stale banners:** 23 × "ReconPro v10" / "RECONPRO v10" strings → v11
   (version-info panel, quick-start guide, usage examples, debug report,
   report footer, docstrings). `scripts/` historical generators intentionally
   keep their v11.0.0 strings (they document the v11.0.0 unification).
5. **`Requires-Python`** corrected `>=3.8` → `>=3.10`.
6. **Sandbox fix (environment, not package):** pip in `.venv` was broken — both
   the vendored `pip/_vendor/certifi/cacert.pem` and the installed
   `certifi/cacert.pem` were missing. Restored from
   `/etc/ssl/certs/ca-certificates.crt`; pip + PyPI network then worked,
   enabling `pip install build` and normal isolated builds.

## Verification performed

### Fresh-venv install (`/tmp/ca9-venv`, Python 3.12.13, wheel-only install)

| Check | Result |
|---|---|
| `pip install dist/reconpro-11.1.0-py3-none-any.whl` | exit 0 |
| `reconpro --version` | `ReconPro 11.1.0`, exit 0 |
| `reconpro --help` | exit 0, full command reference |
| `reconpro list` | exit 0, `Total: 28 modules` |
| `reconpro info --version` | panel `ReconPro v11 — Version Information`, version 11.1.0 |
| SDK: `from reconpro import scan, audit_scan, ReconProResult, __version__` | OK, `__version__ == "11.1.0"` |
| `pip show reconpro` | Version 11.1.0 |

### CLI verification matrix (all exit 0, zero tracebacks)

| Command | Where | Exit |
|---|---|---|
| `reconpro --version` | fresh venv + primary venv | 0 / 0 |
| `reconpro --help` | fresh venv + primary venv | 0 / 0 |
| `reconpro list` | fresh venv + primary venv | 0 / 0 |
| `reconpro scan --help` | fresh venv | 0 |
| `reconpro vibesec --help` | fresh venv | 0 |
| `reconpro audit --help` | fresh venv | 0 |
| `reconpro doctor --help` | fresh venv | 0 |
| `reconpro cve --help` | fresh venv | 0 |
| `reconpro nexus --help` | fresh venv | 0 |
| `reconpro report --help` | fresh venv | 0 |
| `reconpro history --help` | fresh venv | 0 |
| `reconpro compliance --help` | fresh venv | 0 |
| `reconpro serve --help` | fresh venv | 0 |
| **ALL 77 subcommands `--help`** | primary venv | **77/77 PASS** |

### Import + test audit (primary venv, source tree)

- `import reconpro` → OK; `pkgutil.walk_packages` import sweep → **194/194 OK**
  (the only initial failure was `reconpro.tests.test_quality_intelligence`
  needing `pytest`, a dev dependency — resolved by installing pytest; a `test`
  extra now documents this)
- `pytest reconpro/tests/test_constants.py reconpro/tests/test_diagnostics.py` →
  **147 passed** (includes the version-consistency assertions)
- `pytest reconpro/tests/test_cli.py reconpro/tests/test_regression_intelligence.py` →
  **164 passed**
- JSON mode (`scan --json`) was proven working by task Ω∞-back-to-back-test
  (16 real findings on example.com, engine code unchanged since — only
  version strings and packaging changed in 11.1.0)

### Primary venv (`download/reconpro-github/.venv`)

Reinstalled with `pip install --force-reinstall dist/reconpro-11.1.0-*.whl` →
`reconpro --version` = `ReconPro 11.1.0`, `pip show reconpro` = 11.1.0,
`reconpro list` = 28 modules.

## Limitations / notes

- No network scan was re-run in this task — the previous agent's proof
  (Ω∞-back-to-back-test: 16 findings, score 63, grade C on example.com) covers
  engine functionality; 11.1.0 changes no engine logic.
- The wheel has **not** been pushed to the GitHub repo (falconxa0-commits/reconpro-ux);
  that publishing step belongs to the release owner. Local artifacts + hashes
  above are the source of truth.
- The sdist contains the standard setuptools `reconpro.egg-info/` metadata
  directory (6 files) — expected PEP 517 behavior, not dev leftovers.
- `reconpro/tests/` and `reconpro/scripts/` ship in-package for file parity with
  the 11.0.0/11.0.1 wheels; `scripts/` files retain historical v11.0.0 strings.
- Build-time environment note: `.venv` pip required the cacert.pem restoration
  described above; after that fix the standard `python -m build` flow worked
  with no offline workarounds.
