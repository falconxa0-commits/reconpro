#!/usr/bin/env bash
# Smoke test for the Rust SDK.
#
# Honesty contract: if the Rust toolchain is absent this script MUST exit
# non-zero with an explicit "ENVIRONMENT BLOCKED" message. It never
# reports success when nothing was compiled or tested.
#
# `cargo test` is hermetic (stub-binary tests, canned JSON byte-faithful to
# CLI 11.2.0). The examples run against the REAL CLI — needs reconpro
# (>= 11.2.0) on PATH or via RECONPRO_BINARY; all example scans use offline
# *.invalid targets.
set -uo pipefail
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "RUST SDK SMOKE: ENVIRONMENT BLOCKED — 'cargo' toolchain not installed."
  echo "  Source/tests/examples are complete in this directory; compile"
  echo "  on a machine with Rust stable:  cargo build && cargo test"
  exit 3
fi

BIN="${RECONPRO_BINARY:-reconpro}"
if ! command -v "$BIN" >/dev/null 2>&1 && [ ! -x "$BIN" ]; then
  echo "RUST SDK SMOKE: ENVIRONMENT BLOCKED — reconpro CLI not found (PATH or RECONPRO_BINARY)."
  exit 3
fi

set -e
cargo build --all-targets
cargo test
cargo run --example basic            # offline *.invalid demo by default
cargo run --example export
cargo run --example error-handling
echo "RUST SDK SMOKE OK"
