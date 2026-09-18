# Security Policy

## Supported versions

ReconPro is pre-1.0-style software with a single supported line: the
latest `11.x` release. Security fixes land in the newest patch release;
there are no separate maintenance branches yet.

| Version | Supported | Notes |
|---|---|---|
| 11.2.x (latest) | ✅ | active line — security fixes land here |
| ≤ 11.1.x | ❌ | upgrade to the latest release |

## Reporting a vulnerability

**Do not open a public GitHub issue for security findings.**

1. Use GitHub's private advisory flow:
   *Security* tab → *Report a vulnerability*. This reaches the
   maintainers privately and lets us coordinate a fix and disclosure.
2. Include: affected version (`reconpro --version`), reproduction steps
   (command line + observed vs. expected), and impact assessment.
3. You will receive an acknowledgement within **72 hours**.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | ≤ 72 hours |
| Triage + severity assignment (CVSS) | ≤ 7 days |
| Fix for critical/high findings | ≤ 14 days (patch release) |
| Fix for medium/low findings | next scheduled release |
| Coordinated public disclosure | with (or after) the patch release, max 90 days from report |

## Disclosure process

1. Reporter and maintainers agree on severity and fix approach.
2. Fix is developed on a private branch with a regression test that
   fails before / passes after the fix.
3. Patch release goes through the full release gate
   (`tools/release_gate.sh`) — including the new regression test — so a
   security fix can never ship unverified.
4. Release + advisory are published simultaneously; reporters are
   credited (opt-out available).

## What we consider a security issue

* Anything in [docs/SECURITY.md](docs/SECURITY.md) (our security
  posture) that is claimed but not actually enforced.
* Command/shell injection, path traversal, unsafe deserialization,
  SSRF, or secret leakage through the CLI or its modules.
* Supply-chain weaknesses: signature bypass, SBOM mismatches, hash
  misbinding in the release process.
* Plugin sandbox escapes.

## Verification of releases

Every release ships signed `SHA256SUMS` (Ed25519 + GPG), a CycloneDX
SBOM, and a provenance record. See [docs/keys/README.md](docs/keys/README.md)
for the release keys and step-by-step verification instructions.
