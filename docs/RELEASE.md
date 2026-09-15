# Release Engineering

How reconpro 11.1.0 is built, signed, verified and published. All tooling
lives in `tools/`; CI workflows in `.github/workflows/`.

The command used by maintainers:

```bash
python tools/release_manager.py all --reproducible
```

which chains build → sbom → checksums → sign → verify and writes
`dist/RELEASE_MANIFEST.json`.

## release_manager.py

```
usage: release_manager.py [-h]
                          {build,sbom,checksums,sign,verify,all,publish-dry-run}
                          ...
```

| Subcommand | What it does |
|---|---|
| `build [--reproducible]` | wheel + sdist from the source tree (cascade: `python -m build --no-isolation` → isolated build → `pip wheel`); `--reproducible` pins `SOURCE_DATE_EPOCH` deterministically from the version and rebuilds in a clean copy to test byte-identity |
| `sbom [--reproducible]` | hand-rolled **CycloneDX 1.5** SBOM: components from requirements/pyproject (rich, pytest, pytest-cov, textual, requests), MIT license, deterministic serial under `--reproducible`; validated against the official bom-1.5 JSON schema |
| `checksums [--reproducible]` | writes `dist/SHA256SUMS` (`<hex>  <file>`) covering `*.whl`, `*.tar.gz`, `*-sbom.cdx.json` |
| `sign [--reproducible]` | Ed25519-signs SHA256SUMS: hex `SHA256SUMS.ed25519` + binary `SHA256SUMS.sig`, plus a GnuPG detach-sig `SHA256SUMS.asc` when gpg is usable |
| `verify` | the proof command — recomputes all hashes, verifies Ed25519 + binary + gpg signatures, validates SBOM fields, cross-checks `RELEASE_MANIFEST.json`. **Exit 0 = release is internally consistent.** |
| `all [--reproducible]` | build → sbom → checksums → sign → verify + writes `dist/RELEASE_MANIFEST.json` and build/signing reports |
| `publish-dry-run` | `twine check` on the artifacts. **NEVER uploads** — there is no upload code path. |

Exit codes: 0 success, 1 failure (honest reporting; every file under
`dist/` is produced by commands this tool actually runs).

Real `verify` output from this repository:

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

GPG signing uses a dedicated ed25519 key
`C89B85E08AC24AB3CF3B8282D94A4C97A98EE87B`
(ReconPro Release <release@reconpro.local>).

## dist/ artifacts (current release)

| File | Notes |
|---|---|
| `reconpro-11.1.0-py3-none-any.whl` | 1,599,009 B; sha256 `14eb9fc8…47eaabefd1`; **byte-identical across clean rebuilds** |
| `reconpro-11.1.0.tar.gz` | sdist; sha256 `f2d7e6f2…249d22283a1f`; NOT bit-reproducible (see below) |
| `reconpro-11.1.0-sbom.cdx.json` | CycloneDX 1.5, schema-validated |
| `SHA256SUMS` + `.ed25519` + `.sig` + `.asc` | checksums and signatures |
| `RELEASE_MANIFEST.json`, `reconpro-11.1.0-build-report.json`, `signing_report.json` | manifests/reports |

Consumers verify a downloaded release with:

```bash
python tools/release_manager.py verify     # needs the dist/ layout + tools/
```

## Reproducible builds — the honest statement

- **Wheel: byte-identical** across independent clean-copy rebuilds
  (proven three times in-session, including after unrelated source
  edits — the build report records `source_tree_digest` before/after so
  source changes are distinguishable from build nondeterminism).
- **Sdist: NOT byte-identical** — tar/gzip nondeterminism under the
  setuptools backend. This is recorded in the build report; consumers
  rely on the signed `SHA256SUMS` rather than reproducing the sdist
  byte-for-byte.
- `SOURCE_DATE_EPOCH` is derived deterministically from the version
  string (2025-01-01 base + crc32 offset), so the same version always
  maps to the same epoch.

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
files. Demonstrated with `--dry-run` (11.1.0 → 11.1.1 and → 11.2.0);
the version was deliberately not changed.

## CI workflows (`.github/workflows/`)

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push/PR | matrix Python 3.11/3.12/3.13; ruff lint (fatal-error selection); **chunked pytest** via `tools/ci_test_groups.txt` (the full suite in one invocation hangs — known issue — so tests run in explicit chunks each with a hard timeout); startup benchmark gate at 100 ms; AST security scan vs baseline; artifact upload |
| `release.yml` | `v*` tags | `release_manager.py all --reproducible` with `RELEASE_ED25519_HEX` secret, `publish-dry-run`, then a GitHub Release with wheel/sdist/SBOM/SHA256SUMS/signatures/manifest attached |
| `security.yml` | daily 03:00 UTC + dispatch | baseline-mode AST security gate + strict-mode informational run + pip-audit dependency check (with pinning-check fallback) + SARIF upload |
| `reconpro-scan.yml` | push/PR/dispatch | demo of the composite action at `./actions/reconpro-scan` (ast + secrets + dev + SARIF upload) |

Local mirror of the CI gate (no GitHub needed):

```bash
tools/ci_local.sh        # lint + smoke pytest + startup bench + security baseline
tools/run_test_chunks.sh # the same chunked pytest groups CI runs
```

**Honest status**: these workflows are YAML-validated and their steps
mirror locally-verified commands, but they have **never executed on
GitHub Actions** (this repository has not been pushed to GitHub). There
is no CI badge in the README for exactly that reason.

## Nix

`default.nix` (buildPythonPackage, pyproject hook, propagated
rich/textual/requests) and `flake.nix` (per-system packages + `apps.reconpro`
+ devShell). Honest: no `nix` binary exists in the development
environment — these are validated by inspection only, not by
`nix build`.
