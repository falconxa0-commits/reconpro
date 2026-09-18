//! Report export flow: offline scan → export SARIF + Markdown.
//!
//! Run:  cargo run --example export
//!
//! Scans a nonexistent "*.invalid" target first (offline, instant) so the
//! CLI has a last scan in its history to export.

fn main() {
    let client = reconpro_sdk::Client::new();

    match client.scan("nonexistent-export-demo.invalid") {
        Ok(result) => println!("scanned: {} grade: {}", result.target, result.grade),
        Err(e) => {
            eprintln!("scan error: {e}");
            std::process::exit(1);
        }
    }

    // Format is auto-detected from the extension by the CLI.
    match client.export("/tmp/reconpro-sdk-demo.sarif", "sarif") {
        Ok(path) => println!("exported: {path}"),
        Err(e) => {
            eprintln!("sarif export error: {e}");
            std::process::exit(1);
        }
    }

    // No extension → the SDK appends ".md" for the requested format.
    match client.export("/tmp/reconpro-sdk-demo", "md") {
        Ok(path) => println!("exported: {path}"),
        Err(e) => {
            eprintln!("markdown export error: {e}");
            std::process::exit(1);
        }
    }

    match client.export("/tmp/reconpro-sdk-demo.pdf", "pdf") {
        Err(e) => println!("unsupported format correctly rejected: {e}"),
        Ok(_) => unreachable!("pdf must be rejected client-side"),
    }
}
