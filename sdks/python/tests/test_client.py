"""Test suite for reconpro_sdk (Python, Stable tier — see sdks/POLICY.md).

Two layers:
- **Hermetic stub tests** (no CLI needed): structured error codes (BIN_NOT_FOUND,
  TIMEOUT, NON_ZERO_EXIT, INVALID_JSON), exit-code/stderr capture, tolerant
  JSON parsing, argument-list construction, client-side validation.
- **CLI-backed tests** (auto-skipped when no reconpro binary is found):
  version ping, audit, dev, scan ``-o`` round-trip, export, usage-error exit
  semantics, and the truth-layer contract: an offline scan of a nonexistent
  ``*.invalid`` target MUST return grade "U" with
  ``target_validation.state == UNREACHABLE_TARGET`` and confidence /
  verification_state populated on every finding.
"""

import json
from pathlib import Path

import pytest

from reconpro_sdk import (
    BIN_NOT_FOUND,
    INVALID_JSON,
    INVALID_TARGET,
    NON_ZERO_EXIT,
    TIMEOUT,
    UNSUPPORTED_FORMAT,
    UNREACHABLE_TARGET,
    VALID_TARGET_STATES,
    ReconProClient,
    ScanResult,
    SdkError,
    TargetValidationError,
    UnsupportedFormatError,
)

# ───────────────────────────── canned CLI fixtures ──────────────────────────
# Byte-faithful to `reconpro scan <x>.invalid --json` on CLI 11.2.0 (plus an
# unknown "future_field" to pin forward-compatibility).
CANNED_UNREACHABLE = {
    "target": "nonexistent-target-blah.invalid",
    "modules_run": [],
    "total_findings": 1,
    "severity_counts": {"info": 1},
    "total_score": 0,
    "grade": "U",
    "badge_markdown": "![ReconPro U](...)",
    "vibesec_score": None,
    "vibesec_grade": None,
    "module_results": {},
    "findings": [
        {
            "title": "Target unreachable — scan not performed: nonexistent-target-blah.invalid",
            "severity": "info",
            "category": "target_validation",
            "module": "engine",
            "description": "The target validation pipeline could not verify the target...",
            "evidence": "state=UNREACHABLE_TARGET; DNS resolution failed",
            "asset": "nonexistent-target-blah.invalid",
            "points_deducted": 0,
            "remediation": "Verify the target hostname is correct and authorized...",
            "dread_score": 0.0,
            "confidence": 0.95,
            "verification_state": "UNREACHABLE_TARGET",
        }
    ],
    "intelligence": None,
    "engineering": None,
    "quality": None,
    "engineering_score": 0.0,
    "target_validation": {
        "state": "UNREACHABLE_TARGET",
        "dns_resolved": False,
        "reachable": False,
        "http_ok": False,
        "tls_valid": None,
        "details": {"host": "nonexistent-target-blah.invalid",
                    "dns": {"ok": False, "ips": [], "error": "[Errno -2]"}},
        "checked_at": "2026-09-18T00:35:16.676717+00:00",
    },
    "scan_metadata": {
        "scanner": "reconpro",
        "started_at": "2026-09-18T00:35:16.676717+00:00",
        "duration_s": 0.01,
        "result": "unreachable_target_short_circuit",
    },
    "future_field": {"anything": ["the", "CLI", "may", "add"]},
}


def _stub_json(make_stub, payload):
    body = f"cat <<'EOF'\n{json.dumps(payload, indent=2)}\nEOF\n"
    return make_stub(body)


# ───────────────────────────── hermetic tests ───────────────────────────────

def test_build_command_is_argument_list():
    cmd = ReconProClient(binary_path="/x/reconpro").build_command(["scan", "t", "--json"])
    assert cmd == ["/x/reconpro", "scan", "t", "--json"]
    assert isinstance(cmd, list)  # never a shell string


def test_scan_rejects_shell_metacharacters():
    with pytest.raises(TargetValidationError) as excinfo:
        ReconProClient().scan("example.com; rm -rf /")
    assert excinfo.value.code == INVALID_TARGET


def test_empty_target_rejected():
    with pytest.raises(TargetValidationError):
        ReconProClient().scan("   ")


def test_binary_not_found():
    client = ReconProClient(binary_path="/nonexistent/reconpro-xyz")
    with pytest.raises(SdkError) as excinfo:
        client.version()
    assert excinfo.value.code == BIN_NOT_FOUND
    assert excinfo.value.command[0] == "/nonexistent/reconpro-xyz"


def test_timeout_raises_structured_error(make_stub):
    stub = make_stub("sleep 10\n")
    client = ReconProClient(binary_path=stub, timeout=0.5)
    with pytest.raises(SdkError) as excinfo:
        client.version()
    assert excinfo.value.code == TIMEOUT


def test_non_zero_exit_captures_exit_code_and_stderr(make_stub):
    stub = make_stub('echo "usage: boom" >&2\nexit 2\n')
    client = ReconProClient(binary_path=stub)
    with pytest.raises(SdkError) as excinfo:
        client.version()
    err = excinfo.value
    assert err.code == NON_ZERO_EXIT
    assert err.exit_code == 2
    assert "boom" in err.stderr


def test_invalid_json_raises_structured_error(make_stub):
    stub = make_stub("echo 'this is not json'\n")
    client = ReconProClient(binary_path=stub)
    with pytest.raises(SdkError) as excinfo:
        client.scan("example.com")
    assert excinfo.value.code == INVALID_JSON


def test_non_object_json_rejected(make_stub):
    stub = make_stub("echo '[1, 2, 3]'\n")
    client = ReconProClient(binary_path=stub)
    with pytest.raises(SdkError) as excinfo:
        client.audit()
    assert excinfo.value.code == INVALID_JSON


def test_version_with_stub(make_stub):
    stub = make_stub('echo "ReconPro 11.2.0"\n')
    client = ReconProClient(binary_path=stub)
    assert client.version() == "ReconPro 11.2.0"


def test_scan_truth_layer_contract_hermetic(make_stub):
    """Full typed parse of the unreachable-target contract against canned JSON."""
    stub = _stub_json(make_stub, CANNED_UNREACHABLE)
    result = ReconProClient(binary_path=stub).scan("nonexistent-target-blah.invalid")

    assert isinstance(result, ScanResult)
    assert result.grade == "U"
    assert result.total_findings == 1
    assert result.total_score == 0.0
    assert result.modules_run == ()
    assert result.severity_counts == {"info": 1}
    assert result.unreachable is True

    tv = result.target_validation
    assert tv is not None
    assert tv.state == UNREACHABLE_TARGET
    assert tv.state in VALID_TARGET_STATES
    assert tv.dns_resolved is False
    assert tv.reachable is False
    assert tv.http_ok is False

    finding = result.findings[0]
    assert finding.severity == "info"
    assert finding.verification_state == UNREACHABLE_TARGET
    assert finding.confidence == pytest.approx(0.95)
    assert finding.category == "target_validation"
    assert finding.points_deducted == 0.0

    meta = result.scan_metadata
    assert meta is not None
    assert meta.scanner == "reconpro"
    assert meta.result == "unreachable_target_short_circuit"
    assert meta.duration_s == pytest.approx(0.01)

    # raw keeps the full document incl. unknown fields (forward compat)
    assert result.raw["future_field"]["anything"][0] == "the"


def test_scan_result_tolerates_missing_optional_fields(make_stub):
    minimal = {"target": "example.com", "grade": "B", "total_findings": 0}
    stub = _stub_json(make_stub, minimal)
    result = ReconProClient(binary_path=stub).scan("example.com")
    assert result.grade == "B"
    assert result.target_validation is None
    assert result.findings == ()
    assert result.scan_metadata is None
    assert result.modules_run == ()


def test_scan_result_tolerates_null_target_validation(make_stub):
    payload = dict(CANNED_UNREACHABLE)
    payload["target_validation"] = None  # local scans (audit/dev) emit null
    stub = _stub_json(make_stub, payload)
    result = ReconProClient(binary_path=stub).scan("nonexistent-target-blah.invalid")
    assert result.target_validation is None
    assert result.unreachable is False


def test_legacy_finding_without_confidence_fields(make_stub):
    """Findings from older CLIs (no confidence/verification_state) still parse."""
    payload = {
        "target": "example.com", "grade": "B", "total_findings": 1,
        "findings": [{"title": "Old finding", "severity": "low"}],
    }
    stub = _stub_json(make_stub, payload)
    result = ReconProClient(binary_path=stub).scan("example.com")
    finding = result.findings[0]
    assert finding.title == "Old finding"
    assert finding.confidence is None
    assert finding.verification_state is None


def test_export_rejects_unsupported_format():
    with pytest.raises(UnsupportedFormatError) as excinfo:
        ReconProClient().export("/tmp/report", format="pdf")
    assert excinfo.value.code == UNSUPPORTED_FORMAT


def test_output_file_result_is_read_back_from_file(make_stub, tmp_path):
    """CLI quirk: with -o the JSON goes ONLY to the file (stdout stays empty);
    the SDK must read the result back from the file."""
    payload_json = json.dumps(CANNED_UNREACHABLE, indent=2)
    body = (
        "out=\"\"\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = \"-o\" ]; then out=\"$2\"; fi\n"
        "  shift\n"
        "done\n"
        f"cat > \"$out\" <<'EOF'\n{payload_json}\nEOF\n"
    )
    stub = make_stub(body)
    out = tmp_path / "scan.json"
    result = ReconProClient(binary_path=stub).scan(
        "nonexistent-target-blah.invalid", output_file=str(out)
    )
    assert out.is_file()
    assert json.loads(out.read_text(encoding="utf-8"))["grade"] == "U"
    assert result.grade == "U"  # read back from the file, not stdout
    assert result.target_validation.state == UNREACHABLE_TARGET


def test_output_file_missing_raises_invalid_json(make_stub, tmp_path):
    """Stub claims -o but writes nothing → structured INVALID_JSON error."""
    stub = make_stub("exit 0\n")  # prints nothing, writes nothing
    out = tmp_path / "never-written.json"
    with pytest.raises(SdkError) as excinfo:
        ReconProClient(binary_path=stub).scan("example.com", output_file=str(out))
    assert excinfo.value.code == INVALID_JSON


def test_empty_path_rejected():
    with pytest.raises(ValueError):
        ReconProClient().export("   ")
    with pytest.raises(ValueError):
        ReconProClient().dev("  ")


def test_env_config_is_honoured(monkeypatch):
    monkeypatch.setenv("RECONPRO_BINARY", "/from/env/reconpro")
    monkeypatch.setenv("RECONPRO_TIMEOUT", "12.5")
    client = ReconProClient()
    assert client.binary_path == "/from/env/reconpro"
    assert client.timeout == pytest.approx(12.5)


def test_constructor_overrides_env(monkeypatch):
    monkeypatch.setenv("RECONPRO_BINARY", "/from/env/reconpro")
    client = ReconProClient(binary_path="/explicit/reconpro", timeout=1.5)
    assert client.binary_path == "/explicit/reconpro"
    assert client.timeout == 1.5


# ─────────────────────────── CLI-backed tests ───────────────────────────────

def test_version_ping(real_client):
    version = real_client.version()
    assert version.startswith("ReconPro")
    assert "11." in version


def test_usage_error_exit_code_semantics(real_client):
    """Exit code 2 (usage error) must surface as SdkError(NON_ZERO_EXIT)."""
    with pytest.raises(SdkError) as excinfo:
        real_client._run(["scan", "--definitely-not-a-flag"])
    err = excinfo.value
    assert err.code == NON_ZERO_EXIT
    assert err.exit_code == 2
    assert err.stderr.strip()  # argparse usage error text captured


def test_scan_unreachable_target_truth_contract(real_client):
    """Offline truth-layer contract: *.invalid scan is instant and honest."""
    result = real_client.scan("nonexistent-reconpro-sdk-test.invalid")

    assert result.grade == "U"
    assert result.total_findings == 1
    assert result.total_score == 0.0
    assert result.modules_run == ()
    assert result.unreachable is True

    tv = result.target_validation
    assert tv is not None and tv.state == UNREACHABLE_TARGET
    assert tv.dns_resolved is False
    assert tv.reachable is False

    finding = result.findings[0]
    assert finding.severity == "info"  # HIGH impossible by construction
    assert finding.verification_state == UNREACHABLE_TARGET
    assert finding.confidence is not None and 0.0 <= finding.confidence <= 1.0

    meta = result.scan_metadata
    assert meta is not None
    assert meta.scanner == "reconpro"
    assert meta.started_at
    assert meta.duration_s is not None and meta.duration_s >= 0
    assert meta.result  # e.g. "unreachable_target_short_circuit"


def test_audit_returns_typed_result(real_client):
    result = real_client.audit()
    assert isinstance(result, ScanResult)
    assert result.modules_run  # host/dev/doctor run locally
    assert result.target_validation is None  # local audit: no remote target
    assert result.total_findings >= 0


def test_dev_scan_returns_typed_result(real_client, tmp_path):
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    result = real_client.dev(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert result.grade  # some grade always present
    assert "dev" in result.modules_run


def test_doctor_returns_typed_result(real_client):
    result = real_client.doctor()
    assert isinstance(result, ScanResult)
    assert "doctor" in result.modules_run


def test_scan_output_file_roundtrip(real_client, tmp_path):
    out = tmp_path / "scan.json"
    result = real_client.scan("nonexistent-reconpro-sdk-test.invalid",
                              output_file=str(out))
    assert out.is_file()
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["target"] == "nonexistent-reconpro-sdk-test.invalid"
    assert on_disk["grade"] == "U" == result.grade


def test_export_after_scan(real_client, tmp_path):
    real_client.scan("nonexistent-reconpro-sdk-export.invalid")

    sarif_path = real_client.export(str(tmp_path / "report.sarif"))
    assert Path(sarif_path).is_file()
    sarif = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://raw.githubusercontent.com/oasis-tcs/sarif")

    md_path = real_client.export(str(tmp_path / "report"), format="md")
    assert md_path.endswith(".md")  # extension appended by the SDK
    assert Path(md_path).stat().st_size > 0


def test_scan_with_modules_filter(real_client):
    """--modules restricts the run; still JSON-conformant (offline target)."""
    result = real_client.scan("nonexistent-reconpro-sdk-test.invalid",
                              modules=["host"])
    assert result.grade == "U"  # unreachable short-circuit precedes modules
