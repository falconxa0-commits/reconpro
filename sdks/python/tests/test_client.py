import pytest

from reconpro_sdk import ReconProClient, SdkError


def test_version():
    assert "11.1.0" in ReconProClient().version()


def test_version_wrong_python(monkeypatch):
    monkeypatch.setenv("RECONPRO_PYTHON", "/nonexistent")
    with pytest.raises(SdkError):
        ReconProClient().version()


def test_invalid_target_chars():
    with pytest.raises(ValueError):
        ReconProClient().scan("example.com; rm -rf /")


def test_build_command_is_argument_list():
    cmd = ReconProClient().build_command(["--version"])
    assert isinstance(cmd, list)  # never a shell string
    assert cmd[-1] == "--version" and "-m" in cmd and "reconpro.cli" in cmd


def test_history_returns_text():
    # CLI quirk: `history` has no --json flag; human output goes to STDERR.
    text = ReconProClient().history()
    assert isinstance(text, str) and text


@pytest.mark.skip(reason="network")
def test_scan():
    result = ReconProClient().scan("example.com")
    assert isinstance(result, dict)
