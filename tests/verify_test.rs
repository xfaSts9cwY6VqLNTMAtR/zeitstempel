/// Integration tests for ots-verify.
///
/// These test the full verification pipeline from file → parse → verify.
/// The Bitcoin API tests require network access.

use std::process::Command;

/// Helper: run ots-verify as a subprocess and capture output.
fn run_ots_verify(args: &[&str]) -> (i32, String, String) {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .args(args)
        .output()
        .expect("failed to execute ots-verify");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn test_help() {
    let (code, stdout, _) = run_ots_verify(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Standalone OpenTimestamps proof verifier"));
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn test_info_mode() {
    let (code, stdout, _) = run_ots_verify(&["--info", "tests/fixtures/hello-world.txt.ots"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("SHA256"));
    assert!(stdout.contains("03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"));
    assert!(stdout.contains("Bitcoin block #358391"));
}

#[test]
fn test_wrong_file_for_proof() {
    // Create a temporary file with wrong content
    let tmp = "/tmp/ots-verify-test-wrong.txt";
    std::fs::write(tmp, b"This is NOT Hello World!\n").unwrap();

    let (code, _, stderr) = run_ots_verify(&[tmp, "tests/fixtures/hello-world.txt.ots"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("digest mismatch") || stderr.contains("different file"));

    std::fs::remove_file(tmp).ok();
}

#[test]
fn test_missing_file() {
    let (code, _, stderr) = run_ots_verify(&["nonexistent.txt", "tests/fixtures/hello-world.txt.ots"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("Error reading"));
}

#[test]
fn test_invalid_ots_file() {
    let tmp = "/tmp/ots-verify-test-invalid.ots";
    std::fs::write(tmp, b"not a valid ots file").unwrap();

    let (code, _, stderr) = run_ots_verify(&["tests/fixtures/hello-world.txt", tmp]);
    assert_ne!(code, 0);
    assert!(stderr.contains("bad magic") || stderr.contains("Error"));

    std::fs::remove_file(tmp).ok();
}

#[test]
fn test_no_args() {
    let (code, _, stderr) = run_ots_verify(&[]);
    assert_ne!(code, 0);
    assert!(stderr.contains("Usage:"));
}

/// Full verification against the Bitcoin blockchain.
/// Requires network access — marked with ignore for offline CI.
#[test]
fn test_full_bitcoin_verification() {
    let (code, stdout, _) = run_ots_verify(&[
        "tests/fixtures/hello-world.txt",
        "tests/fixtures/hello-world.txt.ots",
    ]);
    assert_eq!(code, 0, "verification should succeed");
    assert!(stdout.contains("Verified!"));
    assert!(stdout.contains("358391"));
    assert!(stdout.contains("Merkle root match confirmed"));
}
