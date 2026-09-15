//! reconpro-sdk — thin std-only wrapper around the ReconPro CLI
//! (`<python> -m reconpro.cli ...`). Every call shells out via
//! `std::process::Command` with an ARGUMENT LIST — never a shell string.

pub mod client;

pub use client::{Client, SdkError};
