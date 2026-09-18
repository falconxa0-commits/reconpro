"""pytest setup: make the in-tree SDK importable and locate the real CLI.

CLI-backed tests use the ``real_client`` fixture (session-scoped) and are
auto-skipped when no reconpro binary can be found — so the suite remains
runnable on machines without the CLI installed. All other tests are hermetic
(they run against tiny shell-script stub binaries).
"""

import os
import shutil
import sys

import pytest

# Make the in-tree SDK importable without installing it.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_KNOWN_VENVS = (
    "/home/z/tmp-capture/rp-dev/bin/reconpro",  # sandbox dev venv
)


def _find_default_binary():
    env = os.environ.get("RECONPRO_BINARY")
    if env:
        return env
    found = shutil.which("reconpro")
    if found:
        return found
    for candidate in _KNOWN_VENVS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


if "RECONPRO_BINARY" not in os.environ:
    _binary = _find_default_binary()
    if _binary:
        os.environ["RECONPRO_BINARY"] = _binary


@pytest.fixture(scope="session")
def real_client():
    """A ReconProClient bound to the real CLI (skips the test if absent)."""
    from reconpro_sdk import ReconProClient

    binary = os.environ.get("RECONPRO_BINARY", "reconpro")
    resolved = shutil.which(binary) or (binary if os.path.isfile(binary) else None)
    if resolved is None:
        pytest.skip(f"reconpro CLI not found (RECONPRO_BINARY={binary!r})")
    return ReconProClient(binary_path=resolved)


@pytest.fixture
def make_stub(tmp_path):
    """Factory: write an executable shell-script stub binary, return its path."""

    def _make(body: str, name: str = "reconpro-stub") -> str:
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return str(path)

    return _make
