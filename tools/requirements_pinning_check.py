#!/usr/bin/env python3
"""Requirements pinning check — fallback when pip-audit is unavailable.

Prints how many entries in requirements.txt are not pinned with ``==``.
Informational by design (exit 0): unpinned ranges limit pip-audit
reproducibility but are not themselves a vulnerability.

Used by .github/workflows/security.yml (dependency-audit step fallback).
"""
from __future__ import annotations

from pathlib import Path


def main() -> int:
    req_path = Path("requirements.txt")
    if not req_path.exists():
        print(f"ERROR: {req_path} not found (run from repo root)")
        return 1
    reqs = [line.split("#")[0].strip() for line in req_path.read_text().splitlines()]
    reqs = [r for r in reqs if r]
    unpinned = [r for r in reqs if "==" not in r]
    print(f"{len(reqs)} requirements, {len(unpinned)} not == pinned:")
    for r in unpinned:
        print(f"  UNPINNED: {r}")
    print(
        "NOTE: unpinned ranges limit pip-audit reproducibility; "
        "pin with == or use a lockfile for hermetic deploys."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
