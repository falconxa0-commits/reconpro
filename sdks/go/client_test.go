package reconpro

import (
        "context"
        "errors"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"
)

// Hermetic tests: every CLI-backed case runs against a tiny shell-script
// stub binary (the same pattern the SDKs CI workflow uses for the real CLI).
// No reconpro installation is required for `go test ./...`.

// cannedUnreachable is byte-faithful to `reconpro scan <x>.invalid --json`
// on CLI 11.2.0 (plus an unknown "future_field" to pin forward-compat).
const cannedUnreachable = `{
  "target": "nonexistent-target-blah.invalid",
  "modules_run": [],
  "total_findings": 1,
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",
  "findings": [
    {
      "title": "Target unreachable — scan not performed",
      "severity": "info",
      "category": "target_validation",
      "module": "engine",
      "description": "honest no-result: no security claims are made",
      "evidence": "state=UNREACHABLE_TARGET; DNS resolution failed",
      "asset": "nonexistent-target-blah.invalid",
      "points_deducted": 0,
      "remediation": "Verify the target hostname is correct and authorized",
      "dread_score": 0.0,
      "confidence": 0.95,
      "verification_state": "UNREACHABLE_TARGET"
    }
  ],
  "target_validation": {
    "state": "UNREACHABLE_TARGET",
    "dns_resolved": false,
    "reachable": false,
    "http_ok": false,
    "tls_valid": null,
    "details": {"host": "nonexistent-target-blah.invalid"},
    "checked_at": "2026-09-18T00:35:16+00:00"
  },
  "scan_metadata": {
    "scanner": "reconpro",
    "started_at": "2026-09-18T00:35:16+00:00",
    "duration_s": 0.01,
    "result": "unreachable_target_short_circuit"
  },
  "future_field": {"anything": ["the", "CLI", "may", "add"]}
}`

// cannedLegacy is an old-CLI result WITHOUT the truth-layer fields — the
// SDK must still parse it (all new fields optional/nil).
const cannedLegacy = `{"target":"example.com","grade":"B","total_findings":1,
 "findings":[{"title":"Old finding","severity":"low"}]}`

// cannedLocal is a local scan (audit/dev): target_validation is null.
const cannedLocal = `{"target":"","modules_run":["dev"],"total_findings":0,
 "severity_counts":{},"total_score":100,"grade":"A+","findings":[],
 "target_validation":null,
 "scan_metadata":{"scanner":"reconpro","started_at":"t","duration_s":0.1,"result":"ok"}}`

func writeStub(t *testing.T, body string) string {
        t.Helper()
        path := filepath.Join(t.TempDir(), "reconpro")
        if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
                t.Fatalf("write stub: %v", err)
        }
        return path
}

func stubClient(t *testing.T, body string) *Client {
        t.Helper()
        return &Client{BinaryPath: writeStub(t, body), Timeout: 10 * time.Second}
}

func TestVersionWithStub(t *testing.T) {
        client := stubClient(t, `echo "ReconPro 11.2.0"`)
        version, err := client.Version(context.Background())
        if err != nil {
                t.Fatalf("Version() error: %v", err)
        }
        if version != "ReconPro 11.2.0" {
                t.Fatalf("unexpected version %q", version)
        }
}

func TestScanTruthLayerContract(t *testing.T) {
        client := stubClient(t, "cat <<'EOF'\n"+cannedUnreachable+"\nEOF\n")
        result, err := client.Scan(context.Background(), "nonexistent-target-blah.invalid")
        if err != nil {
                t.Fatalf("Scan() error: %v", err)
        }
        if result.Grade != "U" {
                t.Fatalf("grade = %q, want U", result.Grade)
        }
        if result.TotalFindings != 1 || result.TotalScore != 0 {
                t.Fatalf("totals = %d/%v, want 1/0", result.TotalFindings, result.TotalScore)
        }
        if len(result.ModulesRun) != 0 {
                t.Fatalf("modules_run = %v, want empty", result.ModulesRun)
        }
        if !result.Unreachable() {
                t.Fatalf("Unreachable() = false, want true")
        }
        tv := result.TargetValidation
        if tv == nil {
                t.Fatal("TargetValidation is nil")
        }
        if tv.State != StateUnreachableTarget {
                t.Fatalf("state = %q, want %q", tv.State, StateUnreachableTarget)
        }
        if tv.DnsResolved == nil || *tv.DnsResolved {
                t.Fatalf("dns_resolved = %v, want false", tv.DnsResolved)
        }
        if len(tv.Details) == 0 {
                t.Fatal("details should decode as non-empty raw JSON")
        }
        if len(result.Findings) != 1 {
                t.Fatalf("findings = %d, want 1", len(result.Findings))
        }
        f := result.Findings[0]
        if f.Severity != "info" { // HIGH impossible by construction
                t.Fatalf("severity = %q, want info", f.Severity)
        }
        if f.Confidence == nil || *f.Confidence != 0.95 {
                t.Fatalf("confidence = %v, want 0.95", f.Confidence)
        }
        if f.VerificationState == nil || *f.VerificationState != StateUnreachableTarget {
                t.Fatalf("verification_state = %v, want %q", f.VerificationState, StateUnreachableTarget)
        }
        meta := result.ScanMetadata
        if meta == nil {
                t.Fatal("ScanMetadata is nil")
        }
        if meta.Scanner != "reconpro" || meta.Result != "unreachable_target_short_circuit" {
                t.Fatalf("metadata = %+v", meta)
        }
        if meta.DurationS != 0.01 {
                t.Fatalf("duration_s = %v, want 0.01", meta.DurationS)
        }
        if result.Raw["future_field"] == nil {
                t.Fatal("Raw should keep unknown fields for forward compatibility")
        }
}

func TestScanLegacyResultWithoutTruthLayerFields(t *testing.T) {
        client := stubClient(t, "cat <<'EOF'\n"+cannedLegacy+"\nEOF\n")
        result, err := client.Scan(context.Background(), "example.com")
        if err != nil {
                t.Fatalf("Scan() error: %v", err)
        }
        if result.Grade != "B" {
                t.Fatalf("grade = %q, want B", result.Grade)
        }
        if result.TargetValidation != nil {
                t.Fatalf("TargetValidation = %+v, want nil", result.TargetValidation)
        }
        if result.ScanMetadata != nil {
                t.Fatalf("ScanMetadata = %+v, want nil", result.ScanMetadata)
        }
        if len(result.Findings) != 1 {
                t.Fatalf("findings = %d, want 1", len(result.Findings))
        }
        f := result.Findings[0]
        if f.Confidence != nil || f.VerificationState != nil {
                t.Fatalf("confidence/verification_state = %v/%v, want nil/nil",
                        f.Confidence, f.VerificationState)
        }
}

func TestLocalScanHasNilTargetValidation(t *testing.T) {
        client := stubClient(t, "cat <<'EOF'\n"+cannedLocal+"\nEOF\n")
        result, err := client.Audit(context.Background())
        if err != nil {
                t.Fatalf("Audit() error: %v", err)
        }
        if result.Grade != "A+" {
                t.Fatalf("grade = %q, want A+", result.Grade)
        }
        if result.TargetValidation != nil || result.Unreachable() {
                t.Fatalf("local scan must have nil target_validation, got %+v",
                        result.TargetValidation)
        }
        if len(result.ModulesRun) != 1 || result.ModulesRun[0] != "dev" {
                t.Fatalf("modules_run = %v, want [dev]", result.ModulesRun)
        }
}

func TestNonZeroExitReturnsCommandError(t *testing.T) {
        client := stubClient(t, `echo "usage: boom" >&2
exit 2`)
        _, err := client.Version(context.Background())
        if err == nil {
                t.Fatal("expected error for exit 2")
        }
        var cmdErr *CommandError
        if !errors.As(err, &cmdErr) {
                t.Fatalf("expected *CommandError, got %T: %v", err, err)
        }
        if cmdErr.ExitCode != ExitUsageError {
                t.Fatalf("ExitCode = %d, want %d", cmdErr.ExitCode, ExitUsageError)
        }
        if !strings.Contains(cmdErr.Stderr, "boom") {
                t.Fatalf("stderr = %q, want it to contain captured text", cmdErr.Stderr)
        }
}

func TestInvalidJSONReturnsJSONError(t *testing.T) {
        client := stubClient(t, `echo "this is not json"`)
        _, err := client.Scan(context.Background(), "example.com")
        if err == nil {
                t.Fatal("expected error for invalid JSON")
        }
        var jsonErr *JSONError
        if !errors.As(err, &jsonErr) {
                t.Fatalf("expected *JSONError, got %T: %v", err, err)
        }
        if !strings.Contains(jsonErr.Details, "this is not json") {
                t.Fatalf("details = %q, want stdout head", jsonErr.Details)
        }
}

func TestTimeoutReturnsTimeoutError(t *testing.T) {
        client := stubClient(t, `sleep 5`)
        client.Timeout = 150 * time.Millisecond
        _, err := client.Version(context.Background())
        if err == nil {
                t.Fatal("expected timeout error")
        }
        var timeoutErr *TimeoutError
        if !errors.As(err, &timeoutErr) {
                t.Fatalf("expected *TimeoutError, got %T: %v", err, err)
        }
        if timeoutErr.Timeout != 150*time.Millisecond {
                t.Fatalf("timeout = %s, want 150ms", timeoutErr.Timeout)
        }
}

func TestBinaryNotFound(t *testing.T) {
        client := &Client{BinaryPath: "/nonexistent/reconpro-xyz", Timeout: time.Second}
        _, err := client.Version(context.Background())
        if err == nil {
                t.Fatal("expected error for nonexistent binary")
        }
        if !strings.Contains(err.Error(), "failed to start") {
                t.Fatalf("expected spawn error mentioning the binary, got %v", err)
        }
}

func TestScanRejectsShellMetacharacters(t *testing.T) {
        client := &Client{BinaryPath: "/x/reconpro"} // never spawned
        if _, err := client.Scan(context.Background(), "example.com; rm -rf /"); err == nil {
                t.Fatal("expected client-side rejection of shell metacharacters")
        } else if !strings.Contains(err.Error(), "metacharacters") {
                t.Fatalf("unexpected error: %v", err)
        }
}

func TestBuildArgsUsesArgumentList(t *testing.T) {
        client := &Client{BinaryPath: "/x/reconpro"}
        args := client.buildArgs("scan", "example.com", "--json")
        want := []string{"/x/reconpro", "scan", "example.com", "--json"}
        if len(args) != len(want) {
                t.Fatalf("buildArgs = %v, want %v", args, want)
        }
        for i := range want {
                if args[i] != want[i] {
                        t.Fatalf("buildArgs = %v, want %v", args, want)
                }
        }
}

func TestExportValidatesFormat(t *testing.T) {
        client := &Client{BinaryPath: "/x/reconpro"} // never spawned
        if _, err := client.Export(context.Background(), "/tmp/report", "pdf"); err == nil {
                t.Fatal("expected error for unsupported export format")
        }
}

func TestNewClientReadsEnv(t *testing.T) {
        t.Setenv("RECONPRO_BINARY", "/from/env/reconpro")
        client := NewClient()
        if client.BinaryPath != "/from/env/reconpro" {
                t.Fatalf("BinaryPath = %q, want /from/env/reconpro", client.BinaryPath)
        }
        if client.Timeout != DefaultTimeout {
                t.Fatalf("Timeout = %s, want %s", client.Timeout, DefaultTimeout)
        }
}

func TestDevValidatesPath(t *testing.T) {
        client := &Client{BinaryPath: "/x/reconpro"} // never spawned
        if _, err := client.Dev(context.Background(), "   "); err == nil {
                t.Fatal("expected error for empty path")
        }
}
