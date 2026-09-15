//! Thin subprocess wrapper around the reconpro CLI.
//!
//! Config (struct fields or env): RECONPRO_PYTHON (default
//! /home/z/.venv/bin/python3), RECONPRO_ROOT (subprocess cwd, default
//! /home/z/my-project/download/reconpro-github). Default timeout 120s.
//!
//! Verified CLI quirks (reconpro 11.1.0): `--version` and `doctor --json`
//! write to STDOUT; `history` has NO --json flag (exit 2) and its human
//! table goes to STDERR, so history() returns raw text. `export` takes one
//! output path, format auto-detected from the extension.

use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_PYTHON: &str = "/home/z/.venv/bin/python3";
pub const DEFAULT_ROOT: &str = "/home/z/my-project/download/reconpro-github";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const EXPORT_FORMATS: [&str; 4] = ["sarif", "md", "json", "html"];
const INVALID_TARGET_CHARS: &str = ";$`&|<>(){}[]!*'\"\\\n\r\t ";

/// Typed SDK error: CLI failure (nonzero exit / bad output) or process I/O failure.
#[derive(Debug)]
pub enum SdkError {
    /// Nonzero exit, timeout, or invalid output. Message carries the exit
    /// code and captured stderr.
    Exit(String),
    /// Failed to spawn the CLI process (e.g. bad python path) or stream I/O error.
    Io(String),
}

impl SdkError {
    /// True when the error is a spawn/I/O failure rather than a CLI exit.
    pub fn is_io(&self) -> bool {
        matches!(self, SdkError::Io(_))
    }
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Exit(msg) => write!(f, "reconpro CLI error: {msg}"),
            SdkError::Io(msg) => write!(f, "reconpro SDK I/O error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {}

/// SDK client that shells out to the reconpro CLI.
pub struct Client {
    /// Python executable used to run the CLI (env RECONPRO_PYTHON).
    pub python_path: String,
    /// Working directory for the subprocess (env RECONPRO_ROOT).
    pub root: PathBuf,
    /// Per-call timeout (default 120s).
    pub timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Builds a client from env vars with defaults for anything unset.
    pub fn new() -> Self {
        let python_path =
            env::var("RECONPRO_PYTHON").unwrap_or_else(|_| DEFAULT_PYTHON.to_string());
        let root = env::var("RECONPRO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_ROOT));
        Self { python_path, root, timeout: DEFAULT_TIMEOUT }
    }

    /// Argument list used to spawn the CLI (unit-testable; never a shell string).
    pub fn build_args<'a>(&self, cli_args: &[&'a str]) -> Vec<&'a str> {
        let mut args: Vec<&str> = vec![self.python_path.as_str(), "-m", "reconpro.cli"];
        args.extend_from_slice(cli_args);
        args
    }

    fn spawn(&self, cli_args: &[&str]) -> std::io::Result<std::process::Child> {
        // Argument list via std::process::Command — no shell involved.
        Command::new(&self.python_path)
            .current_dir(&self.root)
            .args(["-m", "reconpro.cli"])
            .args(cli_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn run(&self, cli_args: &[&str]) -> Result<String, SdkError> {
        let mut child = self
            .spawn(cli_args)
            .map_err(|e| SdkError::Io(format!("failed to start {}: {e}", self.python_path)))?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        return Err(SdkError::Exit(format!(
                            "timed out after {:?} (process killed)",
                            self.timeout
                        )));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(SdkError::Io(format!("wait failed: {e}"))),
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|e| SdkError::Io(format!("failed to collect output: {e}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() {
            return Err(SdkError::Exit(format!(
                "exited with code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.replace('\n', " ").chars().take(400).collect::<String>()
            )));
        }
        Ok(stdout)
    }

    /// CLI version string, e.g. "ReconPro 11.1.0".
    pub fn version(&self) -> Result<String, SdkError> {
        self.run(&["--version"]).map(|out| out.trim().to_string())
    }

    /// Local health check → raw JSON string (std-only SDK: no JSON parser).
    pub fn doctor(&self) -> Result<String, SdkError> {
        self.run(&["doctor", "--json"])
    }

    /// Scan history as raw text (CLI quirk: history has no --json flag).
    pub fn history(&self) -> Result<String, SdkError> {
        let out = self.run(&["history"])?;
        Ok(out.trim().to_string())
    }

    /// Full remote scan of a domain/URL (hits the network) → raw JSON string.
    pub fn scan(&self, target: &str) -> Result<String, SdkError> {
        let validated = validate_target(target)?;
        self.run(&["scan", validated.as_str(), "--json"])
    }

    /// Exports the last scan to `path` (CLI `export` subcommand, format from
    /// extension; `.fmt` appended when missing). Returns the path written.
    pub fn export(&self, path: &str, format: &str) -> Result<String, SdkError> {
        if !EXPORT_FORMATS.contains(&format) {
            return Err(SdkError::Exit(format!(
                "unsupported export format {format:?}; expected one of {EXPORT_FORMATS:?}"
            )));
        }
        if path.trim().is_empty() {
            return Err(SdkError::Exit("export path must be non-empty".to_string()));
        }
        let mut out = path.to_string();
        if !out.rsplit('/').next().unwrap_or("").contains('.') {
            out.push('.');
            out.push_str(format);
        }
        self.run(&["export", out.as_str()])?;
        Ok(out)
    }
}

/// Client-side target validation: rejects shell metacharacters before spawning.
fn validate_target(target: &str) -> Result<String, SdkError> {
    let text = target.trim();
    if text.is_empty() {
        return Err(SdkError::Exit("target must be a non-empty string".to_string()));
    }
    if text.chars().any(|c| INVALID_TARGET_CHARS.contains(c)) {
        return Err(SdkError::Exit(format!(
            "target contains shell metacharacters: {text:?}"
        )));
    }
    Ok(text.to_string())
}
