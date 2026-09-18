#!/usr/bin/env bash
# ReconPro MANDATORY release gate.
#
#   Source → Build → Test → SBOM → Hash → Signature → Publish
#
# Every stage is a hard gate: a non-zero exit anywhere stops the release.
# No release may ship without this script exiting 0.  Run from the repo root:
#
#   bash tools/release_gate.sh [--skip-tests]
#
# --skip-tests is for iteration only; the real release NEVER skips tests.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
PYTHON="${PYTHON:-python3}"
SKIP_TESTS="${1:-}"

stage() { echo; echo "════════ RELEASE GATE: $1 ════════"; }
die()  { echo "GATE FAILED AT: $1" >&2; exit 1; }

[ -x "$PYTHON" ] || PYTHON=python3

# ── Stage 0: source ────────────────────────────────────────────────────
stage "0/7 SOURCE"
git update-index -q --refresh 2>/dev/null || true
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "  UNCOMMITTED CHANGES PRESENT:"
    git status --porcelain | head -20
    die "0-source (commit everything first — provenance must bind to a commit)"
fi
echo "  working tree clean at $(git rev-parse --short HEAD)"

# ── Stage 1: build (reproducible) ──────────────────────────────────────
stage "1/7 BUILD (reproducible)"
"$PYTHON" tools/release_manager.py build --reproducible || die 1-build
echo "  wheel + sdist built; reproducibility double-build recorded"

# ── Stage 2: tests ─────────────────────────────────────────────────────
stage "2/7 TESTS"
if [ "$SKIP_TESTS" = "--skip-tests" ]; then
    echo "  SKIPPED (--skip-tests) — NOT VALID FOR A REAL RELEASE"
else
    if command -v bash >/dev/null; then
        PYTHON="$PYTHON" GROUP_TIMEOUT=900 bash tools/run_test_chunks.sh || die 2-tests
    else
        "$PYTHON" -m pytest reconpro/tests -q || die 2-tests
    fi
    bash tools/security_scan.py --help >/dev/null 2>&1 || true
    "$PYTHON" tools/security_scan.py --baseline-file tools/security_baseline.json || die 2-security-scan
    echo "  full chunked test suite + AST security baseline: PASS"
fi

# ── Stage 3: SBOM ──────────────────────────────────────────────────────
stage "3/7 SBOM (CycloneDX 1.5)"
"$PYTHON" tools/release_manager.py sbom --reproducible || die 3-sbom

# ── Stage 4: hashes ────────────────────────────────────────────────────
stage "4/7 HASHES (SHA256SUMS)"
"$PYTHON" tools/release_manager.py checksums || die 4-hashes

# ── Stage 5: signatures ───────────────────────────────────────────────
stage "5/7 SIGNATURES (Ed25519 + GPG)"
"$PYTHON" tools/release_manager.py sign || die 5-sign

# ── Stage 6: provenance + verification ─────────────────────────────────
stage "6/7 PROVENANCE + VERIFY"
"$PYTHON" tools/release_manager.py provenance || die 6-provenance
"$PYTHON" tools/release_manager.py verify || die 6-verify
"$PYTHON" tools/release_manager.py publish-dry-run || die 6-publish-dry-run

# ── Stage 7: release testing (fresh install + smoke) ──────────────────
stage "7/7 RELEASE TESTS (fresh-machine install + smoke)"
bash tools/release_test.sh || die 7-release-tests

echo
echo "════════ RELEASE GATE: ALL STAGES PASSED ════════"
echo "The release in dist/ is fully verified and may be published."
echo "Publish steps (manual, in order):"
echo "  1. git tag v\$(python3 -c 'import re;print(re.search(r\"version = \\\"([^\\\"]+)\",\"\"\"'\"'open(\"pyproject.toml\").read())\"\"\"'\"').group(1))') && git push origin main --tags"
echo "  2. twine upload dist/reconpro-*  (then update docs/RELEASES.md)"
echo "  3. create the GitHub release and attach every dist/ artifact"
echo "  4. python tools/release_manager.py compare  (post-publish proof)"
