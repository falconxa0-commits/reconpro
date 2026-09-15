//! Basic reconpro-sdk usage.  Run:  cargo run --example basic [--offline]

fn main() {
    let offline = std::env::args().any(|a| a == "--offline");
    let client = reconpro_sdk::Client::new();
    match client.version() {
        Ok(version) => println!("version: {version}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    if offline {
        println!("scan skipped (--offline)");
        return;
    }
    match client.scan("example.com") {
        Ok(report) => println!("scan: {} bytes", report.len()),
        Err(e) => {
            eprintln!("scan error: {e}");
            std::process::exit(1);
        }
    }
}
