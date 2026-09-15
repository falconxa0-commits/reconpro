#!/usr/bin/env python3
"""Programmatic usage: audit a directory and summarize the result.

Runs 100% locally (no network). Try it on any project:

    python examples/python/audit_report.py /path/to/project
"""
import json
import sys

from reconpro import __version__, audit_scan


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    result = audit_scan(target)

    total = sum(result.severity_counts.values())
    print(f"ReconPro {__version__} — audit of {result.target!r}")
    print(f"  modules run : {', '.join(result.modules_run) or '(none)'}")
    print(f"  findings    : {total}  {json.dumps(result.severity_counts)}")
    print(f"  score/grade : {result.total_score} / {result.grade}")

    for finding in result.findings[:10]:
        sev = (finding.get("severity") or "info").upper()
        title = finding.get("title", "")
        print(f"  [{sev:>8}] {title}")
    if len(result.findings) > 10:
        print(f"  ... and {len(result.findings) - 10} more")

    print()
    print("Remediation for the top finding:")
    if result.findings:
        top = result.findings[0]
        print(f"  {top.get('remediation', '(none listed)')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
