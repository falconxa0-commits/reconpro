//! Typed Rust SDK around the ReconPro CLI (>= 11.2.0).
//!
//! Every call shells out via `std::process::Command` with an **argument
//! list** — never a shell string — and parses the JSON contract from STDOUT.
//! The CLI's pretty UI is printed to STDERR (docker/kubectl convention) and
//! is captured only for error reporting.
//!
//! Config (pub fields or env): `RECONPRO_BINARY` (default "reconpro",
//! resolved via PATH), timeout (default 300 s). CLI exit-code contract:
//! 0 success · 1 runtime error · 2 usage error · 130 interrupted.
//! Versioning & compatibility policy: sdks/POLICY.md.
//!
//! Parsing is **additive-tolerant** (see sdks/POLICY.md §3): every field
//! carries a `#[serde(default)]`, so results from older CLIs (without the
//! truth-layer `confidence` / `verification_state` / `target_validation`
//! fields) and newer CLIs (with unknown extra keys) both deserialize.

use std::collections::BTreeMap;
use std::env;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

pub const DEFAULT_BINARY: &str = "reconpro";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// CLI exit codes (process contract — see sdks/POLICY.md).
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_RUNTIME_ERROR: i32 = 1;
pub const EXIT_USAGE_ERROR: i32 = 2;
pub const EXIT_INTERRUPTED: i32 = 130;

/// `target_validation.state` values (the truth layer).
pub const STATE_VERIFIED_TARGET: &str = "VERIFIED_TARGET";
pub const STATE_PARTIAL_TARGET: &str = "PARTIAL_TARGET";
pub const STATE_UNREACHABLE_TARGET: &str = "UNREACHABLE_TARGET";

pub const EXPORT_FORMATS: [&str; 4] = ["sarif", "md", "json", "html"];

const INVALID_TARGET_CHARS: &str = ";$`&|<>(){}[]!*'\"\\\n\r\t ";

/// Severity name → finding count.
pub type SeverityCounts = BTreeMap<String, u32>;

/// Typed SDK error. `Io` = spawn/stream failure (binary not found);
/// `Timeout` = per-call timeout; `NonZeroExit` = CLI exited non-zero
/// (code + captured stderr); `InvalidJson` = exit-0 but stdout was not
/// parseable JSON; `InvalidUsage` = client-side validation.
#[derive(Debug)]
pub enum SdkError {
    Io(String),
    Timeout { seconds: f64 },
    NonZeroExit { code: i32, stderr: String },
    InvalidJson(String),
    InvalidUsage(String),
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
            SdkError::Io(msg) => write!(f, "reconpro SDK I/O error: {msg}"),
            SdkError::Timeout { seconds } => {
                write!(f, "reconpro CLI timed out after {seconds:.1}s (process killed)")
            }
            SdkError::NonZeroExit { code, stderr } => {
                let first = stderr
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("");
                write!(f, "reconpro CLI exited with code {code}: {first}")
            }
            SdkError::InvalidJson(msg) => write!(f, "reconpro CLI produced invalid JSON: {msg}"),
            SdkError::InvalidUsage(msg) => write!(f, "reconpro SDK usage error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {}

/// One vulnerability/observation emitted by a reconpro module.
/// `confidence` and `verification_state` are the truth-layer fields added
/// in CLI 11.2.0 (both optional for older results).
#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub module: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub asset: String,
    #[serde(default)]
    pub points_deducted: f64,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub dread_score: f64,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub verification_state: Option<String>,
}

/// Truth-layer result for the scanned target (`None` for local scans such
/// as audit/dev).
#[derive(Debug, Clone, Deserialize)]
pub struct TargetValidation {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub dns_resolved: Option<bool>,
    #[serde(default)]
    pub reachable: Option<bool>,
    #[serde(default)]
    pub http_ok: Option<bool>,
    #[serde(default)]
    pub tls_valid: Option<bool>,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub checked_at: Option<String>,
}

/// When/how the scan ran.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanMetadata {
    #[serde(default = "default_scanner")]
    pub scanner: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub duration_s: Option<f64>,
    #[serde(default)]
    pub result: Option<String>,
}

fn default_scanner() -> String {
    "reconpro".to_string()
}

/// Typed scan result (scan / vibesec / audit / dev / doctor). Unknown JSON
/// keys are ignored by serde, so newer CLIs remain compatible.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanResult {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub modules_run: Vec<String>,
    #[serde(default)]
    pub total_findings: u32,
    #[serde(default)]
    pub severity_counts: SeverityCounts,
    #[serde(default)]
    pub total_score: f64,
    #[serde(default)]
    pub grade: String,
    #[serde(default)]
    pub vibesec_score: Option<f64>,
    #[serde(default)]
    pub vibesec_grade: Option<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub target_validation: Option<TargetValidation>,
    #[serde(default)]
    pub scan_metadata: Option<ScanMetadata>,
}

impl ScanResult {
    /// True when the truth layer short-circuited an unreachable target
    /// (grade "U", no modules run).
    pub fn unreachable(&self) -> bool {
        self.target_validation
            .as_ref()
            .map(|tv| tv.state == STATE_UNREACHABLE_TARGET)
            .unwrap_or(false)
    }
}

/// SDK client that shells out to the reconpro CLI.
pub struct Client {
    /// reconpro binary (env `RECONPRO_BINARY`, default "reconpro" on PATH).
    pub binary_path: String,
    /// Per-call timeout (default 300 s).
    pub timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Builds a client from env (`RECONPRO_BINARY`) with defaults.
    pub fn new() -> Self {
        let binary_path =
            env::var("RECONPRO_BINARY").unwrap_or_else(|_| DEFAULT_BINARY.to_string());
        Self { binary_path, timeout: DEFAULT_TIMEOUT }
    }

    /// Spawns the CLI with an argument list (never a shell string) and
    /// collects stdout/stderr. Output pipes are drained on reader threads so
    /// large JSON payloads cannot deadlock the pipe buffer.
    fn run(&self, cli_args: &[&str]) -> Result<String, SdkError> {
        let mut child = Command::new(&self.binary_path)
            .args(cli_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                SdkError::Io(format!(
                    "failed to start {}: {e} (set binary_path or RECONPRO_BINARY)",
                    self.binary_path
                ))
            })?;

        let mut stdout_pipe = child.stdout.take().expect("stdout piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr piped");
        let stdout_reader = thread::spawn(move || {
            let mut buf = String::new();
            let _ = stdout_pipe.read_to_string(&mut buf);
            buf
        });
        let stderr_reader = thread::spawn(move || {
            let mut buf = String::new();
            let _ = stderr_pipe.read_to_string(&mut buf);
            buf
        });

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait(); // reap
                        return Err(SdkError::Timeout {
                            seconds: self.timeout.as_secs_f64(),
                        });
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(SdkError::Io(format!("wait failed: {e}"))),
            }
        };

        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();
        if !status.success() {
            return Err(SdkError::NonZeroExit {
                code: status.code().unwrap_or(-1),
                stderr: stderr.chars().take(400).collect(),
            });
        }
        Ok(stdout)
    }

    /// Runs a `--json` command and decodes the typed result.
    fn run_json(&self, cli_args: &[&str]) -> Result<ScanResult, SdkError> {
        let stdout = self.run(cli_args)?;
        serde_json::from_str(&stdout).map_err(|e| {
            SdkError::InvalidJson(format!(
                "{e} (output head: {})",
                stdout.chars().take(200).collect::<String>()
            ))
        })
    }

    /// CLI version string, e.g. "ReconPro 11.2.0". A successful return
    /// doubles as a liveness + version verification ping.
    pub fn version(&self) -> Result<String, SdkError> {
        self.run(&["--version"]).map(|out| out.trim().to_string())
    }

    /// Full remote scan of a domain/URL. Scanning a nonexistent "*.invalid"
    /// target is fully offline and returns grade "U" with
    /// `target_validation.state == STATE_UNREACHABLE_TARGET`.
    pub fn scan(&self, target: &str) -> Result<ScanResult, SdkError> {
        let validated = validate_target(target)?;
        self.run_json(&["scan", &validated, "--json"])
    }

    /// Runs the vibesec module against a target.
    pub fn vibesec(&self, target: &str) -> Result<ScanResult, SdkError> {
        let validated = validate_target(target)?;
        self.run_json(&["vibesec", &validated, "--json"])
    }

    /// Local host/dev-environment audit (offline).
    pub fn audit(&self) -> Result<ScanResult, SdkError> {
        self.run_json(&["audit", "--json"])
    }

    /// Scans a local directory path (offline). Use "." for the cwd.
    pub fn dev(&self, path: &str) -> Result<ScanResult, SdkError> {
        if path.trim().is_empty() {
            return Err(SdkError::InvalidUsage("path must be non-empty".to_string()));
        }
        self.run_json(&["dev", path, "--json"])
    }

    /// Local health check (offline).
    pub fn doctor(&self) -> Result<ScanResult, SdkError> {
        self.run_json(&["doctor", "--json"])
    }

    /// Exports the last scan to `path` via the CLI `export` subcommand
    /// (format auto-detected from the extension; `.fmt` appended when
    /// missing). Returns the path written.
    pub fn export(&self, path: &str, format: &str) -> Result<String, SdkError> {
        if !EXPORT_FORMATS.contains(&format) {
            return Err(SdkError::InvalidUsage(format!(
                "unsupported export format {format:?}; expected one of {EXPORT_FORMATS:?}"
            )));
        }
        if path.trim().is_empty() {
            return Err(SdkError::InvalidUsage(
                "export path must be non-empty".to_string(),
            ));
        }
        let mut out = path.to_string();
        if Path::new(&out).extension().is_none() {
            out.push('.');
            out.push_str(format);
        }
        self.run(&["export", &out])?;
        Ok(out)
    }
}

/// Client-side target validation: rejects shell metacharacters before
/// spawning (defence in depth — arguments are a list, so no shell injection
/// is possible anyway).
fn validate_target(target: &str) -> Result<String, SdkError> {
    let text = target.trim();
    if text.is_empty() {
        return Err(SdkError::InvalidUsage(
            "target must be a non-empty string".to_string(),
        ));
    }
    if text.chars().any(|c| INVALID_TARGET_CHARS.contains(c)) {
        return Err(SdkError::InvalidUsage(format!(
            "target contains shell metacharacters: {text:?}"
        )));
    }
    Ok(text.to_string())
}
