#!/usr/bin/env bash
# Developer workflow: scan a code project, export SARIF, summarize results.
#
# Usage: bash 03-project-to-sarif.sh /path/to/project   (default: .)
# Local only: `dev` scans secrets, dependencies, git and docker config.
set -euo pipefail

TARGET="${1:-.}"

echo "== Project scan: secrets, deps, git, docker =="
reconpro dev "$TARGET"

echo
echo "== Export SARIF 2.1.0 =="
reconpro export "$TARGET/reconpro-report.sarif"

echo
echo "== Summary =="
python3 - "$TARGET/reconpro-report.sarif" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fp:
    sarif = json.load(fp)

results = sarif.get("runs", [{}])[0].get("results", [])
print(f"SARIF results: {len(results)}")
for r in results[:10]:
    text = r.get("message", {}).get("text", "")[:80]
    print(f"  {r.get('level', 'note').upper():>8}  {text}")
if len(results) > 10:
    print(f"  ... and {len(results) - 10} more")
EOF

echo
echo "CI tip: the composite action at actions/reconpro-scan does this"
echo "      and uploads to GitHub Code Scanning — see docs/TUTORIALS.md."
