#!/usr/bin/env python3
"""Basic reconpro-sdk usage.  Run:  python examples/basic.py [--offline]"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro_sdk import ReconProClient, SdkError  # noqa: E402


def main() -> int:
    offline = "--offline" in sys.argv
    client = ReconProClient()
    try:
        print(f"version: {client.version()}")
        doc = client.doctor()
        print(f"doctor: grade={doc.get('grade')} findings={doc.get('total_findings')}")
        print(f"history: {client.history().splitlines()[0] if client.history() else '(empty)'}")
        if offline:
            print("scan skipped (--offline)")
        else:
            result = client.scan("example.com")
            print(f"scan: {json.dumps(result)[:200]}...")
    except SdkError as exc:
        print(f"sdk error (exit {exc.exit_code}): {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
