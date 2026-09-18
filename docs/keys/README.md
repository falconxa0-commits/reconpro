# ReconPro Release Keys

Release artifacts are integrity-protected by **two independent signature
schemes** over the same `SHA256SUMS` manifest:

1. **Ed25519** (RFC 8032) — raw 32-byte keypair. Public key:
   [`tools/keys/release_key.pub`](../../tools/keys/release_key.pub)
   (hex, one line). This is the authoritative signature.
2. **GnuPG detach-signature** — public key block below, also uploaded to
   `keyserver.ubuntu.com` and `keys.openpgp.org`.

## Current key (v11.2.0+)

| Field | Value |
|---|---|
| GPG fingerprint | `5F3D 637E FDE1 E8F5 6568  BEE0 2331 2E75 1E3F 9F89` |
| UID | `ReconPro Release <release@reconpro.local>` |
| Algorithm | ed25519 (sign + cert) |
| Public key block | [`reconpro-release-5F3D637E.asc`](reconpro-release-5F3D637E.asc) |

The v11.1.0 release (2026-09-17) was signed with a key whose fingerprint
was `CAB5F283…` — that key existed only in the original build
environment and **was never published**, which was recorded as a known
gap at the time. From v11.2.0 onward the release key is published in this
repository before the release ships, and each release's signing key is
listed in [docs/RELEASES.md](../RELEASES.md).

## How to verify a release

```bash
# 1. download the release assets (wheel, sdist, SBOM, SHA256SUMS,
#    SHA256SUMS.ed25519, SHA256SUMS.asc) from the GitHub release page
#
# 2. verify every artifact hash
sha256sum -c SHA256SUMS

# 3a. verify the Ed25519 signature (recommended — no key management)
python3 - <<'EOF'
from pathlib import Path
pub = bytes.fromhex(Path("tools/keys/release_key.pub").read_text().strip())
sig = bytes.fromhex(Path("SHA256SUMS.ed25519").read_text().strip())
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
Ed25519PublicKey.from_public_bytes(pub).verify(sig, Path("SHA256SUMS").read_bytes())
print("Ed25519 signature: VALID")
EOF

# 3b. or verify the GPG detach-signature
gpg --import docs/keys/reconpro-release-5F3D637E.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Every check must pass. A single flipped byte anywhere makes
`sha256sum -c` or the signature verification fail — there is no
"partial" verification.

## Key rotation process

1. **Generate the new key** in a controlled environment:
   `gpg --batch --pinentry-mode looploop --quick-gen-key \
    "ReconPro Release <release@reconpro.local>" ed25519 sign never`
   (and a fresh `tools/keys/release_key.ed25519` seed for Ed25519,
   stored in a secret manager — never in the repository).
2. **Publish before first use**: commit the new public key block under
   `docs/keys/reconpro-release-<SHORTFPR>.asc`, update the "Current
   key" table above, and send it to `keyserver.ubuntu.com` +
   `keys.openpgp.org`.
3. **Sign one release with BOTH keys** (old and new) as a transition
   anchor, noting the overlap in `docs/RELEASES.md`.
4. **Retire the old key**: publish a signed revocation, keep the old
   public-key file in `docs/keys/` for verifying historical artifacts,
   and mark the row in `docs/RELEASES.md` as rotated.
5. Never reuse a seed. A key that may have leaked is rotated
   immediately, before the next release, with a security advisory if any
   artifact signed by it is still trusted downstream.

## Provenance

Every release also ships `PROVENANCE.json` — the full
developer → commit → source-digest → build → artifact → signature →
user trust chain with machine-checkable evidence (see
[PROVENANCE.md](../PROVENANCE.md)). `python tools/release_manager.py verify`
re-validates the entire chain locally.
