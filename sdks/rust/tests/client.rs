use reconpro_sdk::{Client, SdkError};

// NOTE: version() and bad_python() both mutate the process env
// (RECONPRO_PYTHON). If cargo test runs them in parallel and flakes, run
// `cargo test -- --test-threads=1`.

#[test]
fn version() {
    // Pin the python executable via env var (the documented config path).
    std::env::set_var("RECONPRO_PYTHON", "/home/z/.venv/bin/python3");
    let version = Client::new().version().expect("version() should succeed");
    assert!(version.contains("11.1.0"), "unexpected version: {version}");
}

#[test]
fn bad_python() {
    std::env::set_var("RECONPRO_PYTHON", "/nonexistent/python");
    let result = Client::new().version();
    // Restore for other tests regardless of outcome.
    std::env::set_var("RECONPRO_PYTHON", "/home/z/.venv/bin/python3");
    match result {
        Err(SdkError::Io(_)) => {} // spawn failure for a bad path — expected
        other => panic!("expected SdkError::Io, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn build_args_uses_argument_list() {
    let client = Client::new();
    let args = client.build_args(&["--version"]);
    assert_eq!(
        args,
        vec![client.python_path.as_str(), "-m", "reconpro.cli", "--version"]
    );
}

#[test]
fn scan_rejects_shell_metacharacters() {
    let err = Client::new().scan("example.com; rm -rf /").err().expect("expected rejection");
    assert!(matches!(err, SdkError::Exit(_)));
}
