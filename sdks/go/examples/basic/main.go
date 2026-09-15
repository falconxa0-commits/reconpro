// Basic reconpro-sdk usage.  Run:  go run ./examples/basic [--offline]
package main

import (
        "flag"
        "fmt"
        "os"

        "github.com/reconpro/sdk-go"
)

func main() {
        offline := flag.Bool("offline", false, "skip scan() (network)")
        flag.Parse()

        client := reconpro.NewClient()
        version, err := client.Version()
        if err != nil {
                fmt.Fprintln(os.Stderr, "error:", err)
                os.Exit(1)
        }
        fmt.Println("version:", version)

        if *offline {
                fmt.Println("scan skipped (--offline)")
                return
        }
        report, err := client.Scan("example.com")
        if err != nil {
                fmt.Fprintln(os.Stderr, "scan error:", err)
                os.Exit(1)
        }
        fmt.Println("scan grade:", report["grade"], "findings:", report["total_findings"])
}
