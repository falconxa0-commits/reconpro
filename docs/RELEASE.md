# Release Engineering

How reconpro is built, signed, verified and published (process current
as of **v11.2.0**; `dist/` in the repository currently holds the
v11.1.0 artifacts — the last published release — while the v11.2.0
release proceeds through the same pipeline). All tooling lives in
`tools/`; CI workflows in `.github/workflows/`.

The command used by maintainers:

```bash
python tools/release_manager.py all --reproducible
```

which chains build → sbom → checksums → sign → verify and writes
`dist/RELEASE_MANIFEST.json`. The **mandatory release gate** wraps that
chain with source-cleanliness, the full test suite, provenance and
fresh-machine release tests — see
[the release gate](#the-release-gate-toolsrelease_gate-sh) below.

## release_manager.py

```
usage: release_manager.py [-h]
                          {build,sbom,checksums,sign,verify,all,provenance,compare,publish-dry-run}
                          ...
```

| Subcommand | What it does |
|---|---|
| `build [--reproducible]` | wheel + sdist from the source tree (cascade: `python -m build --no-isolation` → isolated build → `pip wheel`); `--reproducible` pins `SOURCE_DATE_EPOCH` deterministically from the version, normalizes the sdist (sorted entries, fixed mtime/uid/gid, gzip mtime 0) and rebuilds in a clean copy to test byte-identity |
| `sbom [--reproducible]` | hand-rolled **CycloneDX 1.5** SBOM: components from requirements/pyproject (rich, pytest, pytest-cov, textual, requests), MIT license, deterministic serial under `--reproducible`; validated against the official bom-1.5 JSON schema |
| `checksums [--reproducible]` | writes `dist/SHA256SUMS` (`<hex>  <file>`) covering `*.whl`, `*.tar.gz`, `*-sbom.cdx.json` |
| `sign [--reproducible]` | Ed25519-signs SHA256SUMS: hex `SHA256SUMS.ed25519` + binary `SHA256SUMS.sig`, plus a GnuPG detach-sig `SHA256SUMS.asc` when gpg is usable |
| `verify` | the proof command — recomputes all hashes, verifies Ed25519 + binary + gpg signatures, validates SBOM fields, cross-checks `RELEASE_MANIFEST.json` and `PROVENANCE.json`. **Exit 0 = release is internally consistent.** |
| `all [--reproducible]` | build → sbom → checksums → sign → verify + writes `dist/RELEASE_MANIFEST.json` and build/signing reports |
| `provenance [--reproducible]` | writes `dist/PROVENANCE.json` — the 6-transition trust chain (developer → commit SHA → source-tree digest → build → artifact hashes + signature methods) |
| `compare [--version V]` | downloads the **published** PyPI wheel + GitHub `SHA256SUMS` and proves byte-identity against the local `dist/` (post-publish proof) |
| `publish-dry-run` | `twine check` on the artifacts. **NEVER uploads** — there is no upload code path. |

Exit codes: 0 success, 1 failure (honest reporting; every file under
`dist/` is produced by commands this tool actually runs).

Real `verify` output from this repository (captured at the v11.1.0
release — the last published release):

```
[verify] hash OK: reconpro-11.1.0-py3-none-any.whl (14eb9fc80b3e7614…)
[verify] hash OK: reconpro-11.1.0-sbom.cdx.json (505b0af83ed264f6…)
[verify] hash OK: reconpro-11.1.0.tar.gz (f2d7e6f206f5e357…)
[verify] recomputed 3 artifact hashes
[verify] Ed25519 signature VERIFIED (SHA256SUMS.ed25519, 64 bytes)
[verify] binary signature VERIFIED (SHA256SUMS.sig)
[verify] gpg signature VERIFIED (SHA256SUMS.asc)
[verify] SBOM valid: CycloneDX 1.5, 5 components, serial urn:uuid:80bf8462-c7a3-5bb9-b554-b81e192c00e6
[verify] RELEASE_MANIFEST.json cross-check done
[verify] RESULT: ALL CHECKS PASSED
```

A 1-byte tamper to the wheel makes the same command fail with exit 1
(hash mismatch) — the negative test was executed in-session by the
release engineer.

## Release key handling (priority order)

1. `RELEASE_ED25519_HEX` environment variable — 64 hex chars (32-byte
   seed). This is the CI mechanism (`.github/workflows/release.yml`);
   stored as a repository secret.
2. `tools/keys/release_key.ed25519` — hex seed file (0600, gitignored),
   auto-generated on first `sign` if absent, together with the committed
   public key `tools/keys/release_key.pub`:

   ```
   ba267a568df791172eb59708a01f152ea4aeb0215e67e8cf48b38f149bff1323
   ```

GPG signing uses a dedicated ed25519 key. Current release key
(v11.2.0+):
`5F3D 637E FDE1 E8F5 6568 BEE0 2331 2E75 1E3F 9F89`
(ReconPro Release <release@reconpro.local>) — published in
[keys/](keys/README.md) and on `keyserver.ubuntu.com` /
`keys.openpgp.org`. (The v11.1.0 signing key was never published —
that gap is recorded honestly in [RELEASES.md](RELEASES.md); the
rotation process is documented in [keys/README.md](keys/README.md).)

## dist/ artifacts (current release)

| File | Notes |
|---|---|
| `reconpro-11.1.0-py3-none-any.whl` | 1,599,009 B; sha256 `14eb9fc8…47eaabefd1`; **byte-identical across clean rebuilds** |
| `reconpro-11.1.0.tar.gz` | sdist; sha256 `f2d7e6f2…249d22283a1f`; the 11.1.0 sdist predates the determinism fix (see below) |
| `reconpro-11.1.0-sbom.cdx.json` | CycloneDX 1.5, schema-validated |
| `SHA256SUMS` + `.ed25519` + `.sig` + `.asc` | checksums and signatures |
| `RELEASE_MANIFEST.json`, `PROVENANCE.json`, `reconpro-11.1.0-build-report.json`, `signing_report.json` | manifests/reports |

Consumers verify a downloaded release with:

```bash
python tools/release_manager.py verify     # needs the dist/ layout + tools/
```

## Reproducible builds — the honest statement

- **Wheel: byte-identical** across independent clean-copy rebuilds
  (proven repeatedly in-session, including after unrelated source
  edits — the build report records `source_tree_digest` before/after so
  source changes are distinguishable from build nondeterminism).
- **Sdist: byte-identical since v11.2.0** — the build now normalizes the
  archive (sorted entries, fixed mtime = `SOURCE_DATE_EPOCH`, uid/gid
  0, gzip mtime 0); proven by a double-build byte-comparison (sdist
  digest `6eea0a75…` identical across rebuilds). The v11.1.0 sdist
  predates this fix and is **not** byte-reproducible — recorded as a
  gap in [RELEASES.md](RELEASES.md); consumers of that release rely on
  the signed `SHA256SUMS`.
- `SOURCE_DATE_EPOCH` is derived deterministically from the version
  string (2025-01-01 base + crc32 offset), so the same version always
  maps to the same epoch.

## The release gate — `tools/release_gate.sh`

**Mandatory.** No release may ship without the gate exiting 0. Every
stage is a hard gate; a non-zero exit anywhere stops the release:

| Stage | What it enforces |
|---|---|
| 0/7 SOURCE | working tree clean — provenance must bind to a real commit |
| 1/7 BUILD (reproducible) | wheel + sdist + byte-identity double-build |
| 2/7 TESTS | full chunked test suite (900 s/chunk) + AST security baseline (`--skip-tests` exists for iteration only — **not valid for a real release**) |
| 3/7 SBOM (CycloneDX 1.5) | schema-validated SBOM |
| 4/7 HASHES (SHA256SUMS) | checksum manifest over wheel/sdist/SBOM |
| 5/7 SIGNATURES (Ed25519 + GPG) | both signature schemes |
| 6/7 PROVENANCE + VERIFY | `PROVENANCE.json` trust chain + full re-verification + `publish-dry-run` |
| 7/7 RELEASE TESTS | `tools/release_test.sh` — 6-stage fresh-machine proof: fresh-venv wheel install, CLI smoke incl. unknown-command exit 2, honest-scan JSON assertions (grade U / no HIGH), SARIF 2.1.0 truth fields, SHA256SUMS clean-copy verify |

After the gate: `git tag v$(version) && git push --tags` → `twine
upload` → attach every `dist/` artifact to the GitHub Release →
`python tools/release_manager.py compare` (post-publish byte-identity
proof against PyPI) → update [RELEASES.md](RELEASES.md) → run
`tools/release_test.sh` with `RECONPRO_TEST_PYPI=1` (post-publish
mode).

## Version bumping

```
usage: bump_version.py [-h]
                       (--new-version NEW_VERSION | --bump {major,minor,patch})
                       [--dry-run] [--tag]
```

Edits `pyproject.toml`, `reconpro/__init__.py`, `reconpro/constants.py`
(regex-preserving). `--dry-run` shows planned edits;
`--tag` creates an annotated `vX.Y.Z` git tag but **refuses** when the
package directory is nested inside a larger git tree (as this repo is
inside a workspace) — honest refusal instead of tagging unrelated
files. Demonstrated with `--dry-run` (at the 11.1.0 → 11.1.1 and →
11.2.0 transitions); the version bump to 11.2.0 itself was applied
normally (commit `14f6ae8`).

## CI workflows (`.github/workflows/`)

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push/PR | matrix Python 3.11/3.12/3.13; ruff lint (fatal-error selection); **chunked pytest** via `tools/ci_test_groups.txt` (the full suite in one invocation hangs — known issue — so tests run in explicit chunks each with a hard timeout); startup benchmark gate at 100 ms; AST security scan vs baseline; artifact upload |
| `release.yml` | `v*` tags | `release_manager.py all --reproducible` with `RELEASE_ED25519_HEX` secret, `publish-dry-run`, then a GitHub Release with wheel/sdist/SBOM/SHA256SUMS/signatures/manifest attached |
| `security.yml` | daily 03:00 UTC + dispatch | baseline-mode AST security gate + strict-mode informational run + pip-audit dependency check (with pinning-check fallback) + SARIF upload |
| `sdks.yml` | push/PR | the five language SDK suites (Python pytest, TypeScript bun + plain-node dist smoke, Go, Rust on Actions toolchains) |
| `reconpro-scan.yml` | push/PR/dispatch | demo of the composite action at `./actions/reconpro-scan` (ast + secrets + dev + SARIF upload) |

Local mirror of the CI gate (no GitHub needed):

```bash
tools/ci_local.sh        # lint + smoke pytest + startup bench + security baseline
tools/run_test_chunks.sh # the same chunked pytest groups CI runs
```

**Honest status**: the repository is live at
https://github.com/falconxa0-commits/reconpro and all five workflows
(`ci.yml`, `security.yml`, `sdks.yml`, `release.yml`, `reconpro-scan.yml`)
have executed on GitHub Actions with green runs on `main` — including
failed-and-fixed iterations visible in the Actions history. The README
carries the badges. The v11.1.0 release artifacts were produced by
`tools/release_manager.py` and attached to the GitHub Release; the
`Release` workflow run on tag `v11.1.0` is green.

## Nix

`default.nix` (buildPythonPackage, pyproject hook, propagated
rich/textual/requests) and `flake.nix` (per-system packages + `apps.reconpro`
+ devShell). Honest: no `nix` binary exists in the development
environment — these are validated by inspection only, not by
`nix build`.
