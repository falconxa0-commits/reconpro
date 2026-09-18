// Report export flow: offline scan → export SARIF + Markdown.
//
// Run:  go run ./examples/export
//
// Scans a nonexistent "*.invalid" target first (offline, instant) so the
// CLI has a last scan in its history to export.
package main

import (
        "context"
        "fmt"
        "os"

        "github.com/reconpro/sdk-go"
)

func main() {
        client := reconpro.NewClient()
        ctx := context.Background()

        result, err := client.Scan(ctx, "nonexistent-export-demo.invalid")
        if err != nil {
                fmt.Fprintln(os.Stderr, "scan error:", err)
                os.Exit(1)
        }
        fmt.Println("scanned:", result.Target, "grade:", result.Grade)

        // Format is auto-detected from the extension by the CLI.
        sarif, err := client.Export(ctx, "/tmp/reconpro-sdk-demo.sarif", "sarif")
        if err != nil {
                fmt.Fprintln(os.Stderr, "sarif export error:", err)
                os.Exit(1)
        }
        fmt.Println("exported:", sarif)

        // No extension → the SDK appends ".md" for the requested format.
        md, err := client.Export(ctx, "/tmp/reconpro-sdk-demo", "md")
        if err != nil {
                fmt.Fprintln(os.Stderr, "markdown export error:", err)
                os.Exit(1)
        }
        fmt.Println("exported:", md)

        if _, err := client.Export(ctx, "/tmp/reconpro-sdk-demo.pdf", "pdf"); err != nil {
                fmt.Println("unsupported format correctly rejected:", err)
        }
}
