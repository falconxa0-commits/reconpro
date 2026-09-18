# Provenance Chain

How a byte of ReconPro source code becomes a byte you can trust on your
machine. Every trust transition below is **machine-verified** by
`tools/release_manager.py` and recorded per-release in
`dist/PROVENANCE.json` (schema `reconpro-provenance/1.0`).

```
Developer ──commit──▶ Source ──build──▶ Artifact ──sign──▶ User
              │            │               │              │
         git SHA     tree digest    SHA256SUMS      verify locally
        (signed                        (Ed25519
         history)                      + GPG)
```

## 1. Developer → Commit

* All changes land through commits on `main`; the commit SHA is the unit
  of trust (`git rev-parse HEAD`).
* The release gate **refuses to run on a dirty tree** (stage 0 of
  `tools/release_gate.sh`), so a release always binds to exactly one
  commit.

## 2. Commit → Source snapshot

* `source_tree_digest()` hashes every `reconpro/**/*.py` plus the
  packaging metadata (`pyproject.toml`, `README.md`, `LICENSE`,
  `requirements.txt`), producing a single SHA-256 for the exact build
  inputs. Recorded in `PROVENANCE.json` as `trust_chain[1]`.
* Purpose: if anyone rebuilds from the same commit, any difference in
  output can only come from the build, not from source drift.

## 3. Source → Artifact (build)

* `tools/release_manager.py build --reproducible` builds wheel + sdist
  with a deterministic `SOURCE_DATE_EPOCH` derived from the version
  string.
* **Reproducibility is tested at build time**: the tool immediately
  rebuilds in a clean copy and compares bytes. The wheel and the
  normalized sdist must be byte-identical, or the release gate fails
  (stage 1).
* The sdist is additionally **normalized** (`normalize_sdist`): sorted
  entries, fixed mtimes, zeroed uid/gid, gzip mtime 0 — this is what
  makes the sdist reproducible at all.

## 4. Artifact → Signed hashes

* `checksums` writes `SHA256SUMS` covering wheel, sdist, and SBOM.
* `sign` produces:
  * `SHA256SUMS.ed25519` — Ed25519 (RFC 8032) hex signature; public key
    at [`tools/keys/release_key.pub`](../tools/keys/release_key.pub).
  * `SHA256SUMS.sig` — the same signature, binary form.
  * `SHA256SUMS.asc` — GnuPG detach-signature; public key at
    [`docs/keys/`](keys/) (see [keys/README.md](keys/README.md) for the
    fingerprint, verification commands, and rotation process).
* Self-verification runs before the step is allowed to succeed.

## 5. Signed hashes → User

* Every release publishes the artifacts + `SHA256SUMS` + all three
  signature files on the GitHub release page (and the wheel/sdist to
  PyPI).
* Users verify: `sha256sum -c SHA256SUMS`, then the Ed25519 signature
  (a 10-line Python snippet, in [keys/README.md](keys/README.md)) or
  `gpg --verify SHA256SUMS.asc SHA256SUMS`.
* `tools/release_manager.py verify` re-validates hashes, all
  signatures, the SBOM, `RELEASE_MANIFEST.json`, and the PROVENANCE
  trust chain in one command — a 1-byte tamper anywhere exits 1.
* `tools/release_manager.py compare` downloads the *published* PyPI +
  GitHub artifacts and proves they match the locally verified build
  (post-publish audit).

## 6. Continuous verification

* The release gate (Source → Build → Test → SBOM → Hash → Signature →
  Publish checks) is mandatory: `bash tools/release_gate.sh`.
* Release tests (`tools/release_test.sh`) prove the artifact installs
  and behaves on a fresh machine (CLI smoke, honest-scan semantics,
  SARIF validity, hash re-verification).
* Dependency vulnerabilities are audited daily (pip-audit in
  [.github/workflows/security.yml](../.github/workflows/security.yml));
  Dependabot keeps versions current
  ([.github/dependabot.yml](../.github/dependabot.yml)).
* Release transparency (per-version hashes, keys, SBOM links) lives in
  [RELEASES.md](RELEASES.md).
