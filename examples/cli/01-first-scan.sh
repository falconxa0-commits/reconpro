#!/usr/bin/env bash
# ReconPro quickstart — the five commands everyone runs first.
#
# Safe by default: steps 1-4 are local-only (no network). Step 5 is a real
# remote scan and is commented out — un-comment when you have a target you
# are authorized to scan.
set -euo pipefail

echo "== 1. Confirm the install =="
reconpro --version

echo
echo "== 2. Health-check this machine (local only, no network) =="
reconpro doctor

echo
echo "== 3. Browse the 28-module catalog =="
reconpro list

echo
echo "== 4. Guided tour (8 steps) =="
reconpro tutorial --list    # overview; run bare `reconpro tutorial` to start it

echo
echo "== 5. First remote scan (NETWORK — only against targets you own) =="
# reconpro scan example.com --modules recon --json --timeout 60
echo "   (edit this file to enable the scan line above)"

echo
echo "Next: docs/TUTORIALS.md — tutorials from first scan to SARIF in CI."
