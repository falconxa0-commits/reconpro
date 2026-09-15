#!/usr/bin/env bash
# Runs the pytest groups defined in tools/ci_test_groups.txt.
# Each group runs as a SEPARATE pytest invocation with a hard timeout —
# this is the chunking strategy that avoids the known full-suite hang.
# Used by .github/workflows/ci.yml (and usable locally, but prefer
# tools/ci_local.sh which runs the fast smoke subset only).
set -u
PYTHON="${PYTHON:-python3}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
GROUPS_FILE="${GROUPS_FILE:-tools/ci_test_groups.txt}"
GROUP_TIMEOUT="${GROUP_TIMEOUT:-600}"
FAILED=0

while IFS= read -r line; do
  case "$line" in ""|\#*) continue ;; esac
  group="${line%%:*}"
  files="${line#*:}"
  echo "=== test group: ${group} ==="
  # shellcheck disable=SC2086
  if timeout "$GROUP_TIMEOUT" "$PYTHON" -m pytest $files \
      -q --no-header -p no:cacheprovider; then
    echo "=== group ${group}: PASS ==="
  else
    rc=$?
    if [ "$rc" -eq 124 ]; then
      echo "=== group ${group}: TIMEOUT after ${GROUP_TIMEOUT}s (known-hang containment) ==="
    else
      echo "=== group ${group}: FAIL (exit ${rc}) ==="
    fi
    FAILED=1
  fi
done < "$GROUPS_FILE"

if [ "$FAILED" -ne 0 ]; then
  echo "CI CHUNKED TESTS: FAILED"
  exit 1
fi
echo "CI CHUNKED TESTS: ALL GROUPS PASSED"
