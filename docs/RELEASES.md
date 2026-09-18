# Release Transparency

Every ReconPro release, its exact hashes, signing keys, and evidence.
This page is updated at every release; the authoritative per-release
record is `PROVENANCE.json` + `RELEASE_MANIFEST.json` attached to the
GitHub release.

## Current release keys

| Key | Fingerprint / value | In effect |
|---|---|---|
| Ed25519 (authoritative) | `tools/keys/release_key.pub` — hex pubkey starting `5a6bc09f…` (rotated at v11.2.0; the v11.1.0-era key starting `68227195…` lives at the `v11.1.0` tag) | v11.2.0+ |
| GPG `ReconPro Release <release@reconpro.local>` | `5F3D 637E FDE1 E8F5 6568  BEE0 2331 2E75 1E3F 9F89` | v11.2.0+ |
| GPG (v11.1.0, never published — known gap) | `CAB5F283…` (full fingerprint lost with the original build env) | v11.1.0 only |

Key rotation process: [keys/README.md](keys/README.md#key-rotation-process).
Both v11.2.0 keys are built and applied in CI via repository secrets.

## Releases

### v11.2.0 — 2026-09-18

| Field | Value |
|---|---|
| Commit | `9cd481b` (tag `v11.2.0`; built + signed in CI by the Release workflow, run 35304263393) |
| Wheel | `reconpro-11.2.0-py3-none-any.whl` — sha256 `0b7cb0e96423f343…` (full hash in release `SHA256SUMS`) |
| Sdist | `reconpro-11.2.0.tar.gz` — sha256 `8b1386c274691d98…` (deterministically normalized; byte-reproducible) |
| SBOM | `reconpro-11.2.0-sbom.cdx.json` (CycloneDX 1.5; per-component SPDX licenses; vulnerability-audit metadata) |
| Signatures | `SHA256SUMS.ed25519` + `.sig` (Ed25519, rotated key `5a6bc09f…`) + `SHA256SUMS.asc` (GPG `5F3D637E…` — **verified Good signature against the published key**) |
| Provenance | `PROVENANCE.json` — 6-transition trust chain (developer→source→build→artifact→signature→user) |
| Reproducible | ✅ wheel + sdist byte-identical across independent builds (double-build inside `release_manager.py build --reproducible`) |
| Gates passed | CI (chunked suite) ✓ · SDKs (Go/Rust/TypeScript) ✓ · ReconPro Scan ✓ · Release workflow `all --reproducible` + `publish-dry-run` ✓ |
| Release tests | `tools/release_test.sh` 6/6 on the built wheel AND on the published PyPI package (`RECONPRO_TEST_PYPI=1`) — fresh venv install, CLI smoke incl. unknown-cmd exit 2, honest-scan (UNREACHABLE_TARGET → grade U, no HIGH), JSON + SARIF truth fields, SHA256SUMS re-verify |
| Post-publish audit | PyPI wheel + sdist downloaded and proven **byte-identical** to the signed GitHub release assets (sha256 match against the verified `SHA256SUMS`) |
| PyPI | https://pypi.org/project/reconpro/11.2.0/ |

### v11.1.0 — 2026-09-17

| Field | Value |
|---|---|
| PyPI | `reconpro==11.1.0` (wheel + sdist) |
| GitHub tag | `v11.1.0` |
| Assets | wheel, sdist, SBOM, `SHA256SUMS` (+ Ed25519 + GPG signatures) — 9 assets |
| GPG key | `CAB5F283…` — **public key was never published** (recorded as a gap at the time; consumers had to rely on Ed25519 + PyPI TLS) |
| Ed25519 public key | published as `tools/keys/release_key.pub` in the repo at that tag |
| Reproducible | wheel ✅ byte-identical; sdist ❌ not byte-reproducible (fixed in v11.2.0 by deterministic sdist normalization) |
| Verification | `sha256sum -c SHA256SUMS` + Ed25519 verified; PyPI↔GitHub artifacts byte-identical (independently audited) |

## Verification quickstart

```bash
# from the release assets:
sha256sum -c SHA256SUMS                 # all artifact hashes
python tools/release_manager.py verify   # + signatures + SBOM + provenance chain
```

## Disclosure history

* 2026-09-18 — v11.2.0: release keys published in-repo
  (`docs/keys/`), sdist reproducibility fixed, mandatory release gate
  introduced.
* 2026-09-17 — v11.1.0: first fully signed release; GPG public key
  publication was missed and honestly documented as a known gap
  (README warning at the time).
