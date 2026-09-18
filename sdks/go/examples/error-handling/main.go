// Structured error handling with the reconpro SDK: every failure mode maps
// to a typed error you can branch on.
//
// Run:  go run ./examples/error-handling
//
// Demonstrates: spawn failure (binary not found), *CommandError (non-zero
// exit with ExitCode + Stderr), *TimeoutError, and client-side target
// validation. Fully offline.
package main

import (
        "context"
        "errors"
        "fmt"
        "time"

        "github.com/reconpro/sdk-go"
)

func main() {
        ctx := context.Background()

        // 1. Binary not found (bad path / not on PATH).
        missing := &reconpro.Client{BinaryPath: "/nonexistent/reconpro", Timeout: 5 * time.Second}
        if _, err := missing.Version(ctx); err != nil {
                fmt.Println("spawn failure  :", err)
        }

        // 2. Healthy ping — the version() call doubles as verification.
        client := reconpro.NewClient()
        if version, err := client.Version(ctx); err != nil {
                var cmdErr *reconpro.CommandError
                if errors.As(err, &cmdErr) {
                        // e.g. exit 2 = usage error (see sdks/POLICY.md §3).
                        fmt.Printf("CLI exit %d   : %s\n", cmdErr.ExitCode, cmdErr.Stderr)
                } else {
                        fmt.Println("version error  :", err)
                }
        } else {
                fmt.Println("CLI healthy    : version ping →", version)
        }

        // 3. Timeout → *TimeoutError (per-call, configurable).
        slow := &reconpro.Client{Timeout: 1 * time.Nanosecond}
        if _, err := slow.Version(ctx); err != nil {
                var timeoutErr *reconpro.TimeoutError
                if errors.As(err, &timeoutErr) {
                        fmt.Println("timeout        :", err)
                }
        }

        // 4. Client-side target validation (defence in depth).
        if _, err := client.Scan(ctx, "example.com; rm -rf /"); err != nil {
                fmt.Println("rejected target:", err)
        }
}
