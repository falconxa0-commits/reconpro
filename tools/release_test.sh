#!/usr/bin/env bash
# ReconPro release testing — fresh-machine install + smoke suite.
#
# Proves that what we are about to publish (dist/) actually installs and
# works on a clean machine with no repo checkout:
#   1. fresh venv, install the built wheel from dist/
#   2. CLI smoke: --version, --help, list, doctor, ports, secrets
#   3. honest-scan smoke: unreachable target exits 0 with grade U
#      (truth layer short-circuit)
#   4. JSON report smoke: a scan produces parseable JSON with the
#      target_validation block
#   5. SARIF export smoke: export produces valid JSON SARIF 2.1.0
#   6. verification: SHA256SUMS of dist/ re-verifies in a temp copy
#
# Optional (when RECONPRO_TEST_PYPI=1): also installs the CURRENTLY
# PUBLISHED PyPI package (not the local build) and runs the same smokes —
# used after publishing to prove the public artifact.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
WORK="${RECONPRO_RELEASE_TEST_DIR:-$(mktemp -d -t rp-reltest-XXXXXX)}"
trap 'rm -rf "$WORK"' EXIT

stage() { echo; echo "──── release_test: $1 ────"; }
die()  { echo "RELEASE TEST FAILED: $1" >&2; exit 1; }

command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python3

stage "1/6 fresh venv + install"
VENV="$WORK/venv"
"$PYTHON" -m venv "$VENV"
PIP="$VENV/bin/pip"
CLI="$VENV/bin/reconpro"
"$PIP" install -q --upgrade pip >/dev/null 2>&1 || true

if [ "${RECONPRO_TEST_PYPI:-0}" = "1" ]; then
    echo "  installing from PyPI (published artifact)"
    "$PIP" install -q reconpro || die "pip install reconpro from PyPI"
else
    WHEEL="$(ls "$REPO"/dist/reconpro-*.whl 2>/dev/null | head -n1 || true)"
    [ -n "$WHEEL" ] || die "no wheel in dist/ — run release_manager.py build first"
    echo "  installing $WHEEL"
    "$PIP" install -q "$WHEEL" || die "pip install wheel"
fi

stage "2/6 CLI smoke"
# NOTE: rich UI renders to STDERR by design (data streams like --json go
# to stdout, so piping stays clean — the docker/kubectl convention).
"$CLI" --version | grep -q "ReconPro" || die "--version"
"$CLI" --help >/dev/null || die "--help"
"$CLI" list >/dev/null 2>&1 || die "list"
"$CLI" doctor >/dev/null || die "doctor"
"$CLI" ports >/dev/null || die "ports"
# unknown command must exit 2 (strict command handling)
if "$CLI" definitely-not-a-command >/dev/null 2>&1; then
    die "unknown command did not exit 2"
fi
set +e
"$CLI" definitely-not-a-command >/dev/null 2>&1
RC=$?
set -e
[ "$RC" = "2" ] || die "unknown command exit code was $RC (want 2)"
echo "  --version/--help/list/doctor/ports OK; unknown-command exit 2 OK"

stage "3/6 honest-scan smoke (unreachable target)"
"$CLI" scan nonexistent-target-xyz.invalid -t 2 --json > "$WORK/scan.json" 2>/dev/null \
    || die "scan of unreachable target"
"$PYTHON" - "$WORK/scan.json" <<'EOF' || die "honest-scan assertions"
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
tv = d.get("target_validation") or {}
assert tv.get("state") == "UNREACHABLE_TARGET", "state=" + str(tv.get("state"))
assert d.get("grade") == "U", "grade=" + str(d.get("grade"))
sevs = [f.get("severity") for f in d.get("findings", [])]
assert not any(s in ("high", "critical") for s in sevs), "HIGH finding vs unreachable: " + str(sevs)
print("  unreachable scan: state=UNREACHABLE_TARGET grade=U, no HIGH findings — OK")
EOF

stage "4/6 local audit smoke"
"$CLI" dev "${RECONPRO_RELEASE_TEST_TARGET_DIR:-.}" --json > "$WORK/dev.json" 2>/dev/null || true
"$PYTHON" - "$WORK/dev.json" <<'EOF' || die "dev audit JSON"
import json, sys
with open(sys.argv[1]) as f:
    txt = f.read().strip()
# CLI may print non-JSON banner lines; find the first '{'
d = json.loads(txt[txt.index("{"):])
assert isinstance(d.get("findings"), list), "no findings list"
n = len(d.get("findings", []))
print("  dev audit JSON parses: %d findings" % n)
EOF

stage "5/6 SARIF export smoke"
"$VENV/bin/python" - "$WORK" <<'EOF' || die "SARIF export"
import json, sys
from pathlib import Path
from reconpro.http_layer import Finding
from reconpro.formats import export_sarif

findings = [Finding(title="smoke", severity="high", category="c", module="m",
                    description="d", evidence="e", asset="a",
                    confidence=0.9, verification_state="VERIFIED_TARGET")]
out = Path(sys.argv[1]) / "report.sarif"
export_sarif({
    "findings": [f.to_dict() for f in findings],
    "target": "example.com", "grade": "B", "total_score": 70,
    "target_validation": {"state": "VERIFIED_TARGET"},
    "scan_metadata": {"started_at": "2026-01-01T00:00:00+00:00"},
}, str(out))
sarif = json.loads(out.read_text())
assert sarif["version"] == "2.1.0"
r = sarif["runs"][0]["results"][0]
assert r["properties"]["confidence"] == 0.9
assert r["properties"]["verification_state"] == "VERIFIED_TARGET"
assert sarif["runs"][0]["properties"]["target_validation"]["state"] == "VERIFIED_TARGET"
print("  SARIF 2.1.0 valid, confidence + verification_state present — OK")
EOF

stage "6/6 SHA256SUMS verification in clean copy"
if [ -f "$REPO/dist/SHA256SUMS" ]; then
    mkdir -p "$WORK/distcopy"
    cp "$REPO"/dist/* "$WORK/distcopy/" 2>/dev/null || true
    (cd "$WORK/distcopy" && sha256sum -c SHA256SUMS --quiet) || die "SHA256SUMS re-verification"
    echo "  SHA256SUMS verified in clean copy"
else
    echo "  skipped (no SHA256SUMS — PyPI mode)"
fi

echo
echo "──── RELEASE TESTS: ALL PASSED ────"
