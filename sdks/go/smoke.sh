#!/usr/bin/env bash
# Smoke test for the Go SDK.
#
# Honesty contract: if the Go toolchain is absent this script MUST exit
# non-zero with an explicit "ENVIRONMENT BLOCKED" message. It never
# reports success when nothing was compiled or tested.
set -uo pipefail
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
  echo "GO SDK SMOKE: ENVIRONMENT BLOCKED — 'go' toolchain not installed."
  echo "  Source/tests/examples are complete in this directory; compile"
  echo "  on a machine with Go >= 1.21:  go build ./... && go test ./..."
  exit 3
fi

set -e
go build ./...
go vet ./...
go test ./...
go run ./examples/basic --offline
echo "GO SDK SMOKE OK"
