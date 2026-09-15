#!/usr/bin/env python3
"""Version bump + tag automation for ReconPro.

Updates the version consistently in:
  - pyproject.toml            ^version = "X.Y.Z"   (regex, formatting preserved)
  - reconpro/__init__.py      __version__ = "X.Y.Z"
  - reconpro/constants.py     __version__ = "X.Y.Z"  (what --version prints)

Usage:
  tools/bump_version.py --bump patch [--dry-run] [--tag]
  tools/bump_version.py --new-version 11.2.0 [--dry-run] [--tag]

--tag creates an annotated git tag vX.Y.Z, but ONLY when the package
directory is itself the root of a git repository (checked via
`git rev-parse --show-toplevel`). This repo currently lives INSIDE a larger
git tree (/home/z/my-project), so tagging is refused with an honest message
unless run from a standalone clone.

NOTE: the release engineering task deliberately does NOT bump the version —
other agents test against 11.1.0. Demonstration below uses --dry-run only.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGETS = [
    ("pyproject.toml", r'(^version\s*=\s*)"[^"]+"'),
    ("reconpro/__init__.py", r'(^__version__\s*=\s*)"[^"]+"'),
    ("reconpro/constants.py", r'(^__version__\s*=\s*)"[^"]+"'),
]

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def current_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit("[fatal] no version in pyproject.toml")
    return m.group(1)


def bump(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise SystemExit(f"[fatal] unknown bump part: {part}")


def plan_edits(new_version: str) -> list[tuple[str, str, str]]:
    """Return [(file, old_text, new_text)] for every planned substitution."""
    edits = []
    for relpath, pattern in TARGETS:
        path = REPO / relpath
        if not path.exists():
            print(f"[bump] NOTE: {relpath} not present — skipped")
            continue
        text = path.read_text(encoding="utf-8")
        m = re.search(pattern, text, re.MULTILINE)
        if not m:
            print(f"[bump] NOTE: no version pattern in {relpath} — skipped")
            continue
        old_line = m.group(0)
        new_line = re.sub(r'"[^"]+"', f'"{new_version}"', old_line, count=1)
        if old_line == new_line:
            continue
        edits.append((relpath, old_line, new_line))
    return edits


def git_toplevel() -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            return Path(proc.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="ReconPro version bumper")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--new-version", help="exact version, e.g. 11.2.0")
    group.add_argument("--bump", choices=["major", "minor", "patch"],
                       help="bump the given component")
    ap.add_argument("--dry-run", action="store_true",
                    help="show planned edits without writing anything")
    ap.add_argument("--tag", action="store_true",
                    help="also create an annotated git tag vX.Y.Z (standalone "
                         "git repo only)")
    args = ap.parse_args()

    old = current_version()
    new = args.new_version or bump(old, args.bump)
    if not SEMVER.match(new):
        print(f"[bump] FAIL: {new!r} is not a strict X.Y.Z semver")
        return 1
    if new == old:
        print(f"[bump] FAIL: version is already {old}")
        return 1

    edits = plan_edits(new)
    print(f"[bump] version: {old} -> {new}  "
          f"({'DRY RUN — no files written' if args.dry_run else 'applying'})")
    for relpath, old_line, new_line in edits:
        print(f"[bump]   {relpath}: {old_line.strip()}  ->  {new_line.strip()}")
    if not edits:
        print("[bump] FAIL: no editable version sites found")
        return 1

    if not args.dry_run:
        for relpath, old_line, new_line in edits:
            path = REPO / relpath
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace(old_line, new_line, 1), encoding="utf-8")
        print(f"[bump] wrote {len(edits)} files")

    if args.tag:
        top = git_toplevel()
        if args.dry_run:
            print(f"[bump] --tag (dry-run): would run: git tag -a v{new} -m "
                  f"'reconpro v{new}'")
        elif top is None:
            print("[bump] FAIL: --tag requested but not inside a git repository")
            return 1
        elif top.resolve() != REPO.resolve():
            print(f"[bump] FAIL: --tag refused: package dir is nested inside a "
                  f"larger git tree ({top}); tagging would affect unrelated files. "
                  f"Tag manually in a standalone clone.")
            return 1
        else:
            proc = subprocess.run(
                ["git", "-C", str(REPO), "tag", "-a", f"v{new}",
                 "-m", f"reconpro v{new}"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                print(f"[bump] FAIL: git tag failed: {proc.stderr.strip()}")
                return 1
            print(f"[bump] created annotated tag v{new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
