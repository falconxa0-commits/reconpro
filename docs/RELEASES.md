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
| Commit | (recorded in the release's `PROVENANCE.json`; tag `v11.2.0`) |
| Wheel | `reconpro-11.2.0-py3-none-any.whl` — hash in release `SHA256SUMS` |
| Sdist | `reconpro-11.2.0.tar.gz` (deterministically normalized; byte-reproducible) |
| SBOM | `reconpro-11.2.0-sbom.cdx.json` (CycloneDX 1.5, licenses + audit metadata) |
| Signatures | `SHA256SUMS.ed25519` + `SHA256SUMS.sig` (Ed25519) + `SHA256SUMS.asc` (GPG `5F3D637E…`) |
| Provenance | `PROVENANCE.json` — 6-transition trust chain, machine-verified |
| Reproducible | ✅ wheel + sdist byte-identical across independent builds (double-build in release gate) |
| Gates passed | `tools/release_gate.sh` all 8 stages (source-clean, reproducible build, full test suite, AST security baseline, SBOM, hashes, signatures + provenance, fresh-machine release tests) |
| Release tests | fresh venv install, CLI smoke (unknown-cmd exit 2), honest-scan (UNREACHABLE→grade U, no HIGH), JSON + SARIF truth fields, SHA256SUMS re-verify — all passed |

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
