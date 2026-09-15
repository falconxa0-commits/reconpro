#!/usr/bin/env python3
"""validate_all.py — one-shot orchestrator for ALL PHOENIX 7-d validators.

Runs, in order:
  1. ide/vscode/tools/validate.js        (node — VS Code extension)
  2. ide/jetbrains/tools/validate.py     (JetBrains plugin, compile-blocked)
  3. ide/neovim/tools/validate.py        (Neovim lua plugin, structural)
  4. actions/tools/validate.py           (composite action + demo workflow)
  5. github-app/tools/validate.py        (LIVE HMAC webhook round-trip)

Each validator is run as a subprocess (node / python3), its tail is echoed
and its exit code is captured. Exit code 0 only if ALL validators exit 0.

Note: the CLI runs inside validators mutate ~/.reconpro scan history (`dev`
saves the "last scan" which `export` serialises) — sequential execution
avoids racing the last-scan slot between validators.
"""
from __future__ import annotations

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NODE = os.environ.get("NODE_BIN", "node")
PYTHON = os.environ.get("RECONPRO_PYTHON", "/home/z/.venv/bin/python3")

VALIDATORS: list[tuple[str, str, list[str]]] = [
    ("vscode", "VS Code extension (manifest + tasks + live CLI smoke)", [NODE, os.path.join(REPO, "ide", "vscode", "tools", "validate.js")]),
    ("jetbrains", "JetBrains plugin skeleton (XML + contract + live CLI smoke)", [PYTHON, os.path.join(REPO, "ide", "jetbrains", "tools", "validate.py")]),
    ("neovim", "Neovim lua plugin (jobstart contract + live argv + parser port)", [PYTHON, os.path.join(REPO, "ide", "neovim", "tools", "validate.py")]),
    ("actions", "Composite GitHub Action + demo workflow (yaml + live step sequence)", [PYTHON, os.path.join(REPO, "actions", "tools", "validate.py")]),
    ("github-app", "GitHub App manifest + LIVE webhook HMAC round-trip", [PYTHON, os.path.join(REPO, "github-app", "tools", "validate.py")]),
]


def run_one(name: str, label: str, argv: list[str]) -> tuple[int, str]:
    print(f"\n{'=' * 78}\n== {name}: {label}\n== $ {' '.join(argv)}\n{'=' * 78}")
    proc = subprocess.run(argv, cwd=REPO, capture_output=True, text=True, timeout=420)
    out = (proc.stdout or "") + (proc.stderr or "")
    # print full output; it is short enough and doubles as the audit trail
    print(out.rstrip())
    return proc.returncode, out


def main() -> int:
    results: list[tuple[str, int, str]] = []
    for name, label, argv in VALIDATORS:
        code, out = run_one(name, label, argv)
        summary = ""
        for line in out.splitlines():
            if "checks passed" in line or "RESULT:" in line:
                summary = line
        results.append((name, code, summary))
        print(f"\n>> {name}: exit={code} {('· ' + summary) if summary else ''}")

    print("\n" + "=" * 78)
    print("FINAL SWEEP — PHOENIX 7-d IDE/CI integration validators")
    print("=" * 78)
    ok = True
    for name, code, summary in results:
        status = "PASS" if code == 0 else "FAIL"
        if code != 0:
            ok = False
        print(f"{status}  {name:<12} exit={code}  {summary}")
    print("\nRESULT: " + ("ALL GREEN" if ok else "FAILURES PRESENT"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
