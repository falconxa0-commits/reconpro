#!/usr/bin/env python3
"""ReconPro v11 — Test Runner.

Discovers and runs all tests in the tests/ directory.
Usage:
    python -m tests.run_tests
    python reconpro/tests/run_tests.py
    python reconpro/tests/run_tests.py -v
"""

import sys
import os
import unittest

# Ensure the parent package is importable
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(TEST_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

# Discover tests in this directory
def discover_tests():
    loader = unittest.TestLoader()
    suite = loader.discover(TEST_DIR, pattern="test_*.py")
    return suite


def main():
    # Determine verbosity
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    suite = discover_tests()
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)

    # Summary
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, 'skipped') else 0
    print(f"\n{'='*60}")
    print(f"TOTAL: {total} tests | PASS: {total - failures - errors - skipped} | "
          f"FAIL: {failures} | ERROR: {errors} | SKIP: {skipped}")
    print(f"{'='*60}")

    # Exit with non-zero code on failure
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
