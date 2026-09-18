#!/usr/bin/env python3
"""Basic reconpro_sdk usage (typed results + structured errors).

Run:  python examples/basic.py [target] [--offline]

Defaults to an OFFLINE demo: a scan of a nonexistent ``.invalid`` target,
which the CLI truth-layer short-circuits instantly (grade "U",
UNREACHABLE_TARGET) — no network access happens. Pass a real target to run
a full scan.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro_sdk import (  # noqa: E402
    ReconProClient,
    SdkError,
    UNREACHABLE_TARGET,
)


def show(result) -> None:
    tv = result.target_validation
    print(f"  target          : {result.target}")
    print(f"  grade           : {result.grade} (score {result.total_score})")
    print(f"  total findings  : {result.total_findings}")
    print(f"  severity counts : {result.severity_counts}")
    if tv is not None:
        print(f"  target state    : {tv.state} (dns={tv.dns_resolved} "
              f"reachable={tv.reachable} http_ok={tv.http_ok})")
    if result.scan_metadata is not None:
        print(f"  scan            : {result.scan_metadata.result} in "
              f"{result.scan_metadata.duration_s}s")
    for finding in result.findings[:3]:
        print(f"  - [{finding.severity}] {finding.title}")
        print(f"    confidence={finding.confidence} "
              f"verification_state={finding.verification_state}")


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--offline"]
    offline = "--offline" in sys.argv or not args
    target = args[0] if args else "nonexistent-demo.invalid"

    client = ReconProClient()
    try:
        print(f"version: {client.version()}")

        result = client.scan(target)
        print(f"scan ({'offline demo' if offline else 'live'}):")
        show(result)

        if result.unreachable and target.endswith(".invalid"):
            print("  → truth layer: no claims made about an unreachable target "
                  f"(state={UNREACHABLE_TARGET})")

        out = "/tmp/reconpro-sdk-demo.sarif"
        client.export(out, format="sarif")
        print(f"export: {out}")

        print(f"raw keys still accessible: {sorted(result.raw)[:4]}...")
        _ = json.dumps(result.raw)[:0]  # raw is a plain dict, JSON-serializable
    except SdkError as exc:
        print(f"sdk error [{exc.code}] exit={exc.exit_code}: {exc}", file=sys.stderr)
        if exc.stderr:
            print(f"stderr: {exc.stderr[:300]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
