//! Structured error handling with the reconpro SDK: every failure mode is
//! a matchable `SdkError` variant.
//!
//! Run:  cargo run --example error-handling
//!
//! Demonstrates: Io (binary not found), NonZeroExit (exit code + stderr),
//! Timeout, InvalidUsage (client-side target validation). Fully offline.

use reconpro_sdk::{Client, SdkError};
use std::time::Duration;

fn main() {
    // 1. Binary not found (bad path / not on PATH).
    let missing = Client {
        binary_path: "/nonexistent/reconpro".to_string(),
        timeout: Duration::from_secs(5),
    };
    if let Err(e) = missing.version() {
        println!("spawn failure  : {e}");
    }

    // 2. Healthy ping — version() doubles as verification.
    let client = Client::new();
    match client.version() {
        Ok(version) => println!("CLI healthy    : version ping → {version}"),
        Err(e) => report(e),
    }

    // 3. Timeout → SdkError::Timeout (per-call, configurable).
    let slow = Client { timeout: Duration::from_nanos(1), ..Client::new() };
    if let Err(e) = slow.version() {
        report(e);
    }

    // 4. Client-side target validation (defence in depth).
    if let Err(e) = client.scan("example.com; rm -rf /") {
        report(e);
    }
}

fn report(e: SdkError) {
    match &e {
        SdkError::Io(msg) => println!("io error       : {msg}"),
        SdkError::Timeout { seconds } => println!("timeout        : after {seconds:.3}s"),
        SdkError::NonZeroExit { code, stderr } => {
            println!("non-zero exit  : code={code} stderr={stderr:?}")
        }
        SdkError::InvalidJson(msg) => println!("invalid json   : {msg}"),
        SdkError::InvalidUsage(msg) => println!("rejected input : {msg}"),
    }
}
