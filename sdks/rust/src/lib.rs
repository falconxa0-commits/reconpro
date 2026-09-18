//! reconpro-sdk — typed Rust SDK around the ReconPro CLI (>= 11.2.0).
//!
//! Every call shells out via `std::process::Command` with an **argument
//! list** — never a shell string. Stability tier: **Beta (1.0.0-rc.1)** —
//! see sdks/POLICY.md.

pub mod client;

pub use client::{
    Client, Finding, ScanMetadata, ScanResult, SdkError, SeverityCounts, TargetValidation,
    DEFAULT_BINARY, DEFAULT_TIMEOUT, EXIT_INTERRUPTED, EXIT_RUNTIME_ERROR, EXIT_SUCCESS,
    EXIT_USAGE_ERROR, EXPORT_FORMATS, STATE_PARTIAL_TARGET, STATE_UNREACHABLE_TARGET,
    STATE_VERIFIED_TARGET,
};
