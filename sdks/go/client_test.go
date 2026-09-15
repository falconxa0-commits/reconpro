package reconpro

import (
	"os"
	"strings"
	"testing"
)

// CLI-backed tests are skipped when RECONPRO_SKIP is set. (This SDK cannot be
// compiled in the sandbox it was written in — go toolchain absent — see README.)
func skipIfRequested(t *testing.T) {
	t.Helper()
	if os.Getenv("RECONPRO_SKIP") != "" {
		t.Skip("RECONPRO_SKIP set — skipping CLI-backed tests")
	}
}

func TestVersion(t *testing.T) {
	skipIfRequested(t)
	version, err := NewClient().Version()
	if err != nil {
		t.Fatalf("Version() error: %v", err)
	}
	if !strings.Contains(version, "11.1.0") {
		t.Fatalf("unexpected version %q", version)
	}
}

func TestVersionBadPythonPath(t *testing.T) {
	skipIfRequested(t)
	client := NewClient()
	client.PythonPath = "/nonexistent/python"
	if _, err := client.Version(); err == nil {
		t.Fatal("expected error for nonexistent python path")
	} else if !strings.Contains(err.Error(), "reconpro CLI") {
		t.Fatalf("expected CLI error, got %v", err)
	}
}

func TestScanRejectsShellMetacharacters(t *testing.T) {
	if _, err := NewClient().Scan("example.com; rm -rf /"); err == nil {
		t.Fatal("expected client-side rejection of shell metacharacters")
	}
}

func TestBuildArgsUsesArgumentList(t *testing.T) {
	client := &Client{PythonPath: "/py", Root: DefaultRoot}
	args := client.buildArgs("doctor", "--json")
	want := []string{"/py", "-m", "reconpro.cli", "doctor", "--json"}
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
	if _, err := NewClient().Export("/tmp/report", "pdf"); err == nil {
		t.Fatal("expected error for unsupported export format")
	}
}
