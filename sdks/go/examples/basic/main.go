// Basic reconpro-sdk usage: version ping + typed scan result.
//
// Run:  go run ./examples/basic [--target example.com]
//
// By default it scans a nonexistent "*.invalid" target — fully offline (the
// CLI truth layer short-circuits unreachable targets instantly), so this
// example runs without network access. Pass --target for a real scan.
package main

import (
        "context"
        "flag"
        "fmt"
        "os"

        "github.com/reconpro/sdk-go"
)

func boolStr(b *bool) string {
        if b == nil {
                return "unknown"
        }
        if *b {
                return "yes"
        }
        return "no"
}

func strOrDash(s *string) string {
        if s == nil {
                return "-"
        }
        return *s
}

func confStr(f *float64) string {
        if f == nil {
                return "n/a"
        }
        return fmt.Sprintf("%.2f", *f)
}

func main() {
        target := flag.String("target", "nonexistent-demo.invalid",
                "target to scan (default: offline unreachable demo)")
        flag.Parse()

        client := reconpro.NewClient()
        ctx := context.Background()

        version, err := client.Version(ctx)
        if err != nil {
                fmt.Fprintln(os.Stderr, "version error:", err)
                os.Exit(1)
        }
        fmt.Println("version         :", version)

        result, err := client.Scan(ctx, *target)
        if err != nil {
                fmt.Fprintln(os.Stderr, "scan error:", err)
                os.Exit(1)
        }

        fmt.Println("target          :", result.Target)
        fmt.Println("grade           :", result.Grade, "(score", result.TotalScore, ")")
        fmt.Println("total findings  :", result.TotalFindings)
        fmt.Println("severity counts :", result.SeverityCounts)
        if tv := result.TargetValidation; tv != nil {
                fmt.Println("target state    :", tv.State,
                        "(dns:", boolStr(tv.DnsResolved),
                        "reachable:", boolStr(tv.Reachable),
                        "http_ok:", boolStr(tv.HttpOK), ")")
        }
        if meta := result.ScanMetadata; meta != nil {
                fmt.Println("scan            :", meta.Result, "in", meta.DurationS, "s")
        }
        for _, f := range result.Findings {
                fmt.Println("  - [" + f.Severity + "] " + f.Title)
                fmt.Println("    confidence =", confStr(f.Confidence),
                        " verification_state =", strOrDash(f.VerificationState))
        }
        if result.Unreachable() {
                fmt.Println("truth layer     : no claims made about an unreachable target")
        }
}
