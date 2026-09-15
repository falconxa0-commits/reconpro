// Package reconpro is a thin Go SDK around the ReconPro CLI
// (`<python> -m reconpro.cli ...`). Every call shells out via
// exec.CommandContext with an ARGUMENT LIST — never a shell string.
//
// Config (struct fields or env): RECONPRO_PYTHON (default "python3",
// resolved via PATH), RECONPRO_ROOT (subprocess cwd, default ".").
// Default timeout 120s.
//
// Verified CLI quirks (reconpro 11.1.0): `--version` and `doctor --json`
// write to STDOUT; `history` has NO --json flag (exit 2) and its human
// table goes to STDERR, so History() returns raw text. `export` takes one
// output path, format auto-detected from the extension.
package reconpro

import (
        "context"
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "time"
)

const (
        DefaultPython  = "python3" // resolved via PATH by exec.CommandContext
        DefaultRoot    = "."       // subprocess working directory
        DefaultTimeout = 120 * time.Second
)

var exportFormats = []string{"sarif", "md", "json", "html"}

const invalidTargetChars = ";$`&|<>(){}[]!*'\"\\\n\r\t "

// Client shells out to the reconpro CLI.
type Client struct {
        PythonPath string        // python executable that runs the CLI
        Root       string        // working directory for the subprocess
        Timeout    time.Duration // per-call timeout
}

// NewClient builds a Client from env vars (RECONPRO_PYTHON / RECONPRO_ROOT)
// with defaults for anything unset.
func NewClient() *Client {
        py := os.Getenv("RECONPRO_PYTHON")
        if py == "" {
                py = DefaultPython
        }
        root := os.Getenv("RECONPRO_ROOT")
        if root == "" {
                root = DefaultRoot
        }
        return &Client{PythonPath: py, Root: root, Timeout: DefaultTimeout}
}

func (c *Client) timeout() time.Duration {
        if c.Timeout <= 0 {
                return DefaultTimeout
        }
        return c.Timeout
}

// buildArgs returns the argument list for exec.CommandContext
// (unit-testable; no shell string is ever built).
func (c *Client) buildArgs(cliArgs ...string) []string {
        return append([]string{c.PythonPath, "-m", "reconpro.cli"}, cliArgs...)
}

// run executes the CLI, returning stdout and stderr. Nonzero exits return an
// error that includes the exit status and the captured stderr.
func (c *Client) run(ctx context.Context, cliArgs ...string) (string, string, error) {
        if ctx == nil {
                ctx = context.Background()
        }
        ctx, cancel := context.WithTimeout(ctx, c.timeout())
        defer cancel()
        args := c.buildArgs(cliArgs...)
        cmd := exec.CommandContext(ctx, args[0], args[1:]...) // argument list, never a shell string
        cmd.Dir = c.Root
        var stdout, stderr strings.Builder
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()
        if ctx.Err() == context.DeadlineExceeded {
                return "", "", fmt.Errorf("reconpro CLI timed out after %s", c.timeout())
        }
        if err != nil {
                return stdout.String(), stderr.String(), fmt.Errorf("reconpro CLI failed (exit status: %v): %s", err, stderr.String())
        }
        return stdout.String(), stderr.String(), nil
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

// Version returns the CLI version string, e.g. "ReconPro 11.1.0".
func (c *Client) Version() (string, error) {
        out, _, err := c.run(context.Background(), "--version")
        if err != nil {
                return "", err
        }
        return strings.TrimSpace(out), nil
}

// Doctor runs the local health check and returns the parsed JSON report.
func (c *Client) Doctor() (map[string]any, error) {
        out, _, err := c.run(context.Background(), "doctor", "--json")
        if err != nil {
                return nil, err
        }
        var report map[string]any
        if err := json.Unmarshal([]byte(out), &report); err != nil {
                return nil, fmt.Errorf("reconpro CLI produced invalid JSON: %w", err)
        }
        return report, nil
}

// History returns scan history as raw text (CLI quirk: history has no
// --json flag; the human table goes to STDERR).
func (c *Client) History(target string) (string, error) {
        args := []string{"history"}
        if target != "" {
                validated, err := validateTarget(target)
                if err != nil {
                        return "", err
                }
                args = append(args, validated)
        }
        stdout, stderr, err := c.run(context.Background(), args...)
        if err != nil {
                return "", err
        }
        if strings.TrimSpace(stderr) != "" {
                return strings.TrimSpace(stderr), nil
        }
        return strings.TrimSpace(stdout), nil
}

// Scan runs a full remote scan (hits the network) and returns parsed JSON.
func (c *Client) Scan(target string) (map[string]any, error) {
        validated, err := validateTarget(target)
        if err != nil {
                return nil, err
        }
        out, _, err := c.run(context.Background(), "scan", validated, "--json")
        if err != nil {
                return nil, err
        }
        var report map[string]any
        if err := json.Unmarshal([]byte(out), &report); err != nil {
                return nil, fmt.Errorf("reconpro CLI produced invalid JSON: %w", err)
        }
        return report, nil
}

// Export writes the last scan to path (format auto-detected from the
// extension by the CLI `export` subcommand; .ext appended when missing).
// format must be one of sarif/md/json/html. Returns the path written.
func (c *Client) Export(path, format string) (string, error) {
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
        if path == "" {
                return "", fmt.Errorf("export path must be non-empty")
        }
        out := path
        if filepath.Ext(out) == "" {
                out += "." + format
        }
        if _, _, err := c.run(context.Background(), "export", out); err != nil {
                return "", err
        }
        return out, nil
}
