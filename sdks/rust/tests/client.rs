//! Hermetic tests: every CLI-backed case runs against a tiny shell-script
//! stub binary (canned JSON byte-faithful to CLI 11.2.0) — no reconpro
//! installation is required for `cargo test`.
//!
//! Stub env mutation (bad_binary restores RECONPRO_BINARY exactly) is
//! serialized by smoke.sh (`--test-threads=1`) to avoid cross-test races.

use reconpro_sdk::{
    Client, SdkError, STATE_UNREACHABLE_TARGET, STATE_VERIFIED_TARGET,
};
use std::sync::atomic::{AtomicU32, Ordering};

static STUB_SEQ: AtomicU32 = AtomicU32::new(0);

fn write_stub(body: &str) -> String {
    let seq = STUB_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir()
        .join(format!("reconpro-sdk-test-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("reconpro");
    // Write + fsync + drop: on overlayfs-backed CI runners, executing a
    // freshly-written file can transiently fail with ETXTBSY ("Text file
    // busy") because the copy-up is deferred. sync_all() forces it.
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).expect("create stub");
        f.write_all(format!("#!/bin/sh\n{body}").as_bytes())
            .expect("write stub");
        f.sync_all().expect("sync stub");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path.to_string_lossy().to_string()
}

fn stub_client(body: &str) -> Client {
    Client {
        binary_path: write_stub(body),
        timeout: std::time::Duration::from_secs(10),
    }
}

const CANNED_UNREACHABLE: &str = r#"{
  "target": "nonexistent-target-blah.invalid",
  "modules_run": [],
  "total_findings": 1,
  "severity_counts": {"info": 1},
  "total_score": 0,
  "grade": "U",
  "findings": [
    {
      "title": "Target unreachable — scan not performed",
      "severity": "info",
      "category": "target_validation",
      "module": "engine",
      "description": "honest no-result: no security claims are made",
      "evidence": "state=UNREACHABLE_TARGET; DNS resolution failed",
      "asset": "nonexistent-target-blah.invalid",
      "points_deducted": 0,
      "remediation": "Verify the target hostname is correct and authorized",
      "dread_score": 0.0,
      "confidence": 0.95,
      "verification_state": "UNREACHABLE_TARGET"
    }
  ],
  "target_validation": {
    "state": "UNREACHABLE_TARGET",
    "dns_resolved": false,
    "reachable": false,
    "http_ok": false,
    "tls_valid": null,
    "details": {"host": "nonexistent-target-blah.invalid"},
    "checked_at": "2026-09-18T00:35:16+00:00"
  },
  "scan_metadata": {
    "scanner": "reconpro",
    "started_at": "2026-09-18T00:35:16+00:00",
    "duration_s": 0.01,
    "result": "unreachable_target_short_circuit"
  },
  "future_field": {"anything": ["the", "CLI", "may", "add"]}
}"#;

const CANNED_LEGACY: &str = r#"{"target":"example.com","grade":"B","total_findings":1,
 "findings":[{"title":"Old finding","severity":"low"}]}"#;

const CANNED_LOCAL: &str = r#"{"target":"","modules_run":["dev"],"total_findings":0,
 "severity_counts":{},"total_score":100,"grade":"A+","findings":[],
 "target_validation":null,
 "scan_metadata":{"scanner":"reconpro","started_at":"t","duration_s":0.1,"result":"ok"}}"#;

#[test]
fn version() {
    let client = stub_client("echo 'ReconPro 11.2.0'");
    let version = client.version().expect("version() should succeed");
    assert_eq!(version, "ReconPro 11.2.0");
}

#[test]
fn scan_truth_layer_contract() {
    let client = stub_client(&format!("cat <<'EOF'\n{CANNED_UNREACHABLE}\nEOF\n"));
    let result = client
        .scan("nonexistent-target-blah.invalid")
        .expect("scan() should succeed");

    assert_eq!(result.grade, "U");
    assert_eq!(result.total_findings, 1);
    assert_eq!(result.total_score, 0.0);
    assert!(result.modules_run.is_empty());
    assert!(result.unreachable());

    let tv = result.target_validation.as_ref().expect("target_validation");
    assert_eq!(tv.state, STATE_UNREACHABLE_TARGET);
    assert_eq!(tv.state, "UNREACHABLE_TARGET");
    assert_eq!(tv.dns_resolved, Some(false));
    assert_eq!(tv.reachable, Some(false));
    assert_eq!(tv.http_ok, Some(false));

    assert_eq!(result.findings.len(), 1);
    let f = &result.findings[0];
    assert_eq!(f.severity, "info"); // HIGH impossible by construction
    assert_eq!(f.confidence, Some(0.95));
    assert_eq!(f.verification_state.as_deref(), Some("UNREACHABLE_TARGET"));

    let meta = result.scan_metadata.as_ref().expect("scan_metadata");
    assert_eq!(meta.scanner, "reconpro");
    assert_eq!(meta.result.as_deref(), Some("unreachable_target_short_circuit"));
    assert_eq!(meta.duration_s, Some(0.01));
}

#[test]
fn scan_legacy_result_without_truth_layer_fields() {
    // Older CLI results (no confidence/verification_state/target_validation)
    // must still deserialize — serde defaults everywhere.
    let client = stub_client(&format!("cat <<'EOF'\n{CANNED_LEGACY}\nEOF\n"));
    let result = client.scan("example.com").expect("scan() should succeed");
    assert_eq!(result.grade, "B");
    assert!(result.target_validation.is_none());
    assert!(result.scan_metadata.is_none());
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].confidence, None);
    assert_eq!(result.findings[0].verification_state, None);
}

#[test]
fn local_scan_has_none_target_validation() {
    let client = stub_client(&format!("cat <<'EOF'\n{CANNED_LOCAL}\nEOF\n"));
    let result = client.audit().expect("audit() should succeed");
    assert_eq!(result.grade, "A+");
    assert!(result.target_validation.is_none());
    assert!(!result.unreachable());
    assert_eq!(result.modules_run, vec!["dev".to_string()]);
}

#[test]
fn unknown_fields_are_ignored() {
    let client = stub_client(&format!("cat <<'EOF'\n{CANNED_UNREACHABLE}\nEOF\n"));
    let result = client.scan("nonexistent-target-blah.invalid").unwrap();
    // "future_field" above proves serde ignores unknown keys without error.
    assert_eq!(result.target_validation.unwrap().state, STATE_UNREACHABLE_TARGET);
    assert_ne!(STATE_VERIFIED_TARGET, STATE_UNREACHABLE_TARGET); // sanity: 3 distinct states
}

#[test]
fn non_zero_exit_carries_code_and_stderr() {
    let client = stub_client("echo 'usage: boom' >&2\nexit 2");
    let err = client.version().err().expect("expected non-zero exit error");
    match err {
        SdkError::NonZeroExit { code, stderr } => {
            assert_eq!(code, 2);
            assert!(stderr.contains("boom"), "stderr captured: {stderr}");
        }
        other => panic!("expected NonZeroExit, got {other:?}"),
    }
}

#[test]
fn invalid_json_is_structured() {
    let client = stub_client("echo 'this is not json'");
    let err = client.scan("example.com").err().expect("expected json error");
    match err {
        SdkError::InvalidJson(msg) => assert!(msg.contains("this is not json"), "{msg}"),
        other => panic!("expected InvalidJson, got {other:?}"),
    }
}

#[test]
fn timeout_kills_process() {
    let client = Client {
        binary_path: write_stub("sleep 5"),
        timeout: std::time::Duration::from_millis(200),
    };
    let err = client.version().err().expect("expected timeout");
    match err {
        SdkError::Timeout { seconds } => assert!((0.1..=1.0).contains(&seconds), "{seconds}"),
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn binary_not_found() {
    let client = Client {
        binary_path: "/nonexistent/reconpro-xyz".to_string(),
        timeout: std::time::Duration::from_secs(5),
    };
    let err = client.version().err().expect("expected io error");
    assert!(err.is_io(), "expected Io error, got {err:?}");
}

#[test]
fn scan_rejects_shell_metacharacters() {
    let client = Client {
        binary_path: "/x/reconpro".to_string(), // never spawned
        timeout: std::time::Duration::from_secs(5),
    };
    let err = client
        .scan("example.com; rm -rf /")
        .err()
        .expect("expected client-side rejection");
    assert!(matches!(err, SdkError::InvalidUsage(_)), "got {err:?}");
}

#[test]
fn export_rejects_unsupported_format() {
    let client = Client {
        binary_path: "/x/reconpro".to_string(), // never spawned
        timeout: std::time::Duration::from_secs(5),
    };
    let err = client
        .export("/tmp/report", "pdf")
        .err()
        .expect("expected unsupported-format error");
    assert!(matches!(err, SdkError::InvalidUsage(_)), "got {err:?}");
}

#[test]
fn dev_rejects_empty_path() {
    let client = Client {
        binary_path: "/x/reconpro".to_string(), // never spawned
        timeout: std::time::Duration::from_secs(5),
    };
    assert!(matches!(client.dev("   "), Err(SdkError::InvalidUsage(_))));
}
