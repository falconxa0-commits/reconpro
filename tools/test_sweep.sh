#!/usr/bin/env bash
# Sweep each test file INDIVIDUALLY (never the full suite — known hang).
# Per-file hard timeout; records pass/fail/timeout per file for CI grouping.
set -u
PY="${PYTHON:-/home/z/.venv/bin/python3}"
cd "$(dirname "$0")/.."
OUT="${1:-/tmp/test_sweep_results.txt}"
[ -f "$OUT" ] || : > "$OUT"
for f in reconpro/tests/test_*.py; do
  name=$(basename "$f")
  if grep -q "^PASS\|^FAIL\|^TIMEOUT" "$OUT" 2>/dev/null && grep -q "  ${name}  " "$OUT"; then
    continue  # resume: already swept
  fi
  start=$(date +%s)
  if timeout 20 "$PY" -m pytest "$f" -q --no-header -p no:cacheprovider > "/tmp/sweep_$name.log" 2>&1; then
    tail_line=$(tail -1 "/tmp/sweep_$name.log")
    echo "PASS  $name  ${tail_line}" >> "$OUT"
  else
    rc=$?
    tail_line=$(tail -1 "/tmp/sweep_$name.log")
    if [ "$rc" -eq 124 ]; then
      echo "TIMEOUT(20s)  $name  ${tail_line}" >> "$OUT"
    else
      echo "FAIL(rc=$rc)  $name  ${tail_line}" >> "$OUT"
    fi
  fi
  echo "swept $name ($(($(date +%s)-start))s)" >> "$OUT.progress" 2>/dev/null || true
done
echo "SWEEP_DONE" >> "$OUT"
