// Package reconpro is a thin Go SDK around the ReconPro CLI (>= 11.2.0).
// Every call shells out via exec.CommandContext with an ARGUMENT LIST —
// never a shell string — and parses the JSON contract from STDOUT. The
// CLI's pretty UI is printed to STDERR (docker/kubectl convention) and is
// captured only for error reporting.
//
// Config (struct fields or env): RECONPRO_BINARY (default "reconpro",
// resolved via PATH). Default timeout 5 minutes.
//
// CLI exit-code contract: 0 success, 1 runtime error, 2 usage error,
// 130 interrupted. Non-zero exits return a *CommandError carrying the exit
// code and captured stderr. Versioning & compatibility policy: sdks/POLICY.md.
package reconpro

import (
        "context"
        "encoding/json"
        "errors"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "time"
)

const (
        DefaultBinary  = "reconpro" // resolved via PATH by exec.CommandContext
        DefaultTimeout = 5 * time.Minute
)

// CLI exit codes (process contract — see sdks/POLICY.md).
const (
        ExitSuccess      = 0
        ExitRuntimeError = 1
        ExitUsageError   = 2
        ExitInterrupted  = 130
)

// TargetValidation states (the truth layer).
const (
        StateVerifiedTarget    = "VERIFIED_TARGET"
        StatePartialTarget     = "PARTIAL_TARGET"
        StateUnreachableTarget = "UNREACHABLE_TARGET"
)

var exportFormats = []string{"sarif", "md", "json", "html"}

const invalidTargetChars = ";$`&|<>(){}[]!*'\"\\\n\r\t "

// CommandError is a non-zero CLI exit (exit code + captured stderr).
type CommandError struct {
        ExitCode int
        Stderr   string
        Command  []string
}

func (e *CommandError) Error() string {
        return fmt.Sprintf("reconpro CLI exited with code %d: %s", e.ExitCode, firstLine(e.Stderr))
}

// TimeoutError is a per-call timeout expiry.
type TimeoutError struct {
        Timeout time.Duration
        Command []string
}

func (e *TimeoutError) Error() string {
        return fmt.Sprintf("reconpro CLI timed out after %s", e.Timeout)
}

// JSONError is an exit-0 run whose stdout could not be decoded as JSON.
type JSONError struct {
        Err     error
        Details string // stdout head, for diagnostics
        Command []string
}

func (e *JSONError) Error() string {
        return fmt.Sprintf("reconpro CLI produced invalid JSON: %v", e.Err)
}

// Unwrap allows errors.Is/As on the underlying decode error.
func (e *JSONError) Unwrap() error { return e.Err }

// Finding is one vulnerability/observation emitted by a reconpro module.
// Confidence and VerificationState are the truth-layer fields added in
// CLI 11.2.0; unknown JSON keys are ignored (forward compatible).
type Finding struct {
        Title             string   `json:"title"`
        Severity          string   `json:"severity"`
        Category          string   `json:"category"`
        Module            string   `json:"module"`
        Description       string   `json:"description"`
        Evidence          string   `json:"evidence"`
        Asset             string   `json:"asset"`
        PointsDeducted    float64  `json:"points_deducted"`
        Remediation       string   `json:"remediation"`
        DreadScore        float64  `json:"dread_score"`
        Confidence        *float64 `json:"confidence"`        // 0..1, nil when unmeasured
        VerificationState *string  `json:"verification_state"` // VERIFIED_/PARTIAL_/UNREACHABLE_TARGET
}

// TargetValidation is the truth-layer result for the scanned target
// (nil for local scans such as audit/dev).
type TargetValidation struct {
        State       string          `json:"state"`
        DnsResolved *bool           `json:"dns_resolved"`
        Reachable   *bool           `json:"reachable"`
        HttpOK      *bool           `json:"http_ok"`
        TlsValid    *bool           `json:"tls_valid"`
        Details     json.RawMessage `json:"details"`
        CheckedAt   string          `json:"checked_at"`
}

// ScanMetadata describes when/how the scan ran.
type ScanMetadata struct {
        Scanner   string  `json:"scanner"`
        StartedAt string  `json:"started_at"`
        DurationS float64 `json:"duration_s"`
        Result    string  `json:"result"`
}

// ScanResult is the typed scan JSON contract (scan/vibesec/audit/dev/doctor).
// Raw carries the complete decoded document so keys added by future CLIs
// remain accessible without an SDK release.
type ScanResult struct {
        Target           string            `json:"target"`
        ModulesRun       []string          `json:"modules_run"`
        TotalFindings    int               `json:"total_findings"`
        SeverityCounts   map[string]int    `json:"severity_counts"`
        TotalScore       float64           `json:"total_score"`
        Grade            string            `json:"grade"`
        VibesecScore     *float64          `json:"vibesec_score"`
        VibesecGrade     *string           `json:"vibesec_grade"`
        Findings         []Finding         `json:"findings"`
        TargetValidation *TargetValidation `json:"target_validation"`
        ScanMetadata     *ScanMetadata     `json:"scan_metadata"`
        Raw              map[string]any     `json:"-"`
}

// Unreachable reports whether the truth layer short-circuited an
// unreachable target (grade "U", no modules run).
func (r *ScanResult) Unreachable() bool {
        return r.TargetValidation != nil &&
                r.TargetValidation.State == StateUnreachableTarget
}

// Client shells out to the reconpro CLI.
type Client struct {
        BinaryPath string        // reconpro binary (env RECONPRO_BINARY, default "reconpro")
        Timeout    time.Duration // per-call timeout (default 5m)
}

// NewClient builds a Client from env (RECONPRO_BINARY) with defaults.
func NewClient() *Client {
        bin := os.Getenv("RECONPRO_BINARY")
        if bin == "" {
                bin = DefaultBinary
        }
        return &Client{BinaryPath: bin, Timeout: DefaultTimeout}
}

func (c *Client) timeoutOrDefault() time.Duration {
        if c.Timeout <= 0 {
                return DefaultTimeout
        }
        return c.Timeout
}

// buildArgs returns the argument list for exec.CommandContext
// (unit-testable; no shell string is ever built).
func (c *Client) buildArgs(cliArgs ...string) []string {
        return append([]string{c.BinaryPath}, cliArgs...)
}

// run executes the CLI, returning stdout and stderr. Non-zero exits return
// a *CommandError (exit code + stderr); timeouts a *TimeoutError; spawn
// failures (binary not found) a wrapped error mentioning the binary.
func (c *Client) run(ctx context.Context, cliArgs ...string) (string, string, error) {
        if ctx == nil {
                ctx = context.Background()
        }
        ctx, cancel := context.WithTimeout(ctx, c.timeoutOrDefault())
        defer cancel()
        args := c.buildArgs(cliArgs...)
        cmd := exec.CommandContext(ctx, args[0], args[1:]...) // argument list, never a shell string
        var stdout, stderr strings.Builder
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        if ctx.Err() == context.DeadlineExceeded {
                return "", "", &TimeoutError{Timeout: c.timeoutOrDefault(), Command: args}
        }
        if err != nil {
                var exitErr *exec.ExitError
                if errors.As(err, &exitErr) {
                        return stdout.String(), stderr.String(),
                                &CommandError{ExitCode: exitErr.ExitCode(), Stderr: stderr.String(), Command: args}
                }
                return stdout.String(), stderr.String(),
                        fmt.Errorf("reconpro SDK: failed to start %s: %w", args[0], err)
        }
        return stdout.String(), stderr.String(), nil
}

// runJSON runs a --json command and decodes the typed result. When
// outputFile is non-empty the CLI writes the JSON only to that file
// (stdout stays empty), so the result is read back from disk.
func (c *Client) runJSON(ctx context.Context, outputFile string, cliArgs ...string) (*ScanResult, error) {
        stdout, _, err := c.run(ctx, cliArgs...)
        if err != nil {
                return nil, err
        }
        if outputFile != "" {
                data, readErr := os.ReadFile(outputFile)
                if readErr != nil {
                        return nil, &JSONError{
                                Err:     fmt.Errorf("no JSON written to %s: %w", outputFile, readErr),
                                Details: snippet(stdout),
                        }
                }
                stdout = string(data)
        }
        var result ScanResult
        if err := json.Unmarshal([]byte(stdout), &result); err != nil {
                return nil, &JSONError{Err: err, Details: snippet(stdout)}
        }
        raw := make(map[string]any)
        if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
                return nil, &JSONError{Err: err, Details: snippet(stdout)}
        }
        result.Raw = raw
        return &result, nil
}

// Version returns the CLI version string, e.g. "ReconPro 11.2.0". A
// successful return doubles as a liveness + version verification ping.
func (c *Client) Version(ctx context.Context) (string, error) {
        out, _, err := c.run(ctx, "--version")
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(out), nil
}

// Scan runs a full remote scan of a domain/URL and returns the typed result.
// Scanning a nonexistent "*.invalid" target is fully offline and returns
// grade "U" with TargetValidation.State == StateUnreachableTarget.
func (c *Client) Scan(ctx context.Context, target string) (*ScanResult, error) {
        validated, err := validateTarget(target)
        if err != nil {
                return nil, err
        }
        return c.runJSON(ctx, "", "scan", validated, "--json")
}

// Vibesec runs the vibesec module against a target.
func (c *Client) Vibesec(ctx context.Context, target string) (*ScanResult, error) {
        validated, err := validateTarget(target)
        if err != nil {
                return nil, err
        }
        return c.runJSON(ctx, "", "vibesec", validated, "--json")
}

// Audit runs the local host/dev-environment audit (offline).
func (c *Client) Audit(ctx context.Context) (*ScanResult, error) {
        return c.runJSON(ctx, "", "audit", "--json")
}

// Dev scans a local directory path (offline). Use "." for the cwd.
func (c *Client) Dev(ctx context.Context, path string) (*ScanResult, error) {
        if strings.TrimSpace(path) == "" {
                return nil, fmt.Errorf("path must be non-empty")
        }
        return c.runJSON(ctx, "", "dev", path, "--json")
}

// Doctor runs the local health check (offline).
func (c *Client) Doctor(ctx context.Context) (*ScanResult, error) {
        return c.runJSON(ctx, "", "doctor", "--json")
}

// Export writes the last scan to path via the CLI `export` subcommand
// (format auto-detected from the extension; .ext appended when missing).
// format must be one of sarif/md/json/html. Returns the path written.
func (c *Client) Export(ctx context.Context, path, format string) (string, error) {
        supported := false
        for _, f := range exportFormats {
                if f == format {
                        supported = true
                        break
                }
        }
        if !supported {
                return "", fmt.Errorf("unsupported export format %q; expected one of %v", format, exportFormats)
        }
        if strings.TrimSpace(path) == "" {
                return "", fmt.Errorf("export path must be non-empty")
        }
        out := path
        if filepath.Ext(out) == "" {
                out += "." + format
        }
        if _, _, err := c.run(ctx, "export", out); err != nil {
                return "", err
        }
        return out, nil
}

// validateTarget rejects shell metacharacters client-side, before spawning.
func validateTarget(target string) (string, error) {
        text := strings.TrimSpace(target)
        if text == "" {
                return "", fmt.Errorf("target must be a non-empty string")
        }
        if strings.ContainsAny(text, invalidTargetChars) {
                return "", fmt.Errorf("target contains shell metacharacters: %q", text)
        }
        return text, nil
}

// firstLine returns the first non-empty line of s (for compact error text).
func firstLine(s string) string {
        for _, line := range strings.Split(s, "\n") {
                if t := strings.TrimSpace(line); t != "" {
                        return t
                }
        }
        return ""
}

// snippet truncates s to at most 300 bytes for diagnostics.
func snippet(s string) string {
        const max = 300
        if len(s) <= max {
                return s
        }
        return s[:max] + "..."
}
