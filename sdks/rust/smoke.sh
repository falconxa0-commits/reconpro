#!/usr/bin/env bash
# Smoke test for the Rust SDK.
#
# Honesty contract: if the Rust toolchain is absent this script MUST exit
# non-zero with an explicit "ENVIRONMENT BLOCKED" message. It never
# reports success when nothing was compiled or tested.
set -uo pipefail
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "RUST SDK SMOKE: ENVIRONMENT BLOCKED — 'cargo' toolchain not installed."
  echo "  Source/tests/examples are complete in this directory; compile"
  echo "  on a machine with Rust stable:  cargo build && cargo test"
  exit 3
fi

set -e
cargo build --all-targets
# --test-threads=1: version()/bad_python() mutate RECONPRO_PYTHON (documented
# in tests/client.rs) — serialize to avoid cross-test env races.
cargo test -- --test-threads=1
cargo run --example basic -- --offline
echo "RUST SDK SMOKE OK"
