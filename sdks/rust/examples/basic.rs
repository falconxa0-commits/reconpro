//! Basic reconpro-sdk usage: version ping + typed scan result.
//!
//! Run:  cargo run --example basic [-- <target>]
//!
//! By default it scans a nonexistent "*.invalid" target — fully offline
//! (the CLI truth layer short-circuits unreachable targets instantly).
//! A custom target:  cargo run --example basic -- example.com

fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "nonexistent-demo.invalid".into());
    let client = reconpro_sdk::Client::new();

    match client.version() {
        Ok(version) => println!("version         : {version}"),
        Err(e) => {
            eprintln!("version error: {e}");
            std::process::exit(1);
        }
    }

    match client.scan(&target) {
        Ok(result) => {
            println!("target          : {}", result.target);
            println!("grade           : {} (score {})", result.grade, result.total_score);
            println!("total findings  : {}", result.total_findings);
            println!("severity counts : {:?}", result.severity_counts);
            if let Some(tv) = &result.target_validation {
                println!(
                    "target state    : {} (dns={} reachable={} http_ok={})",
                    tv.state,
                    tv.dns_resolved.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()),
                    tv.reachable.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()),
                    tv.http_ok.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()),
                );
            }
            if let Some(meta) = &result.scan_metadata {
                println!("scan            : {} in {}s", meta.result.as_deref().unwrap_or("-"), meta.duration_s.unwrap_or(0.0));
            }
            for f in result.findings.iter().take(3) {
                println!("  - [{}] {}", f.severity, f.title);
                println!(
                    "    confidence={} verification_state={}",
                    f.confidence.map(|c| format!("{c:.2}")).unwrap_or_else(|| "n/a".into()),
                    f.verification_state.as_deref().unwrap_or("-"),
                );
            }
            if result.unreachable() {
                println!("truth layer     : no claims made about an unreachable target");
            }
        }
        Err(e) => {
            eprintln!("scan error: {e}");
            std::process::exit(1);
        }
    }
}
