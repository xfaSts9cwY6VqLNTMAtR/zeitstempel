/// Integration tests for zeitstempel.
///
/// These test the full verification pipeline from file -> parse -> verify.
/// The Bitcoin API tests require network access.

use std::process::Command;

/// Helper: run zeitstempel as a subprocess and capture output.
fn run_zeitstempel(args: &[&str]) -> (i32, String, String) {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .args(args)
        .output()
        .expect("failed to execute zeitstempel");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn test_help() {
    let (code, stdout, _) = run_zeitstempel(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Standalone OpenTimestamps CLI"));
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn test_version() {
    let (code, stdout, _) = run_zeitstempel(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("zeitstempel 0.1.0"));
}

#[test]
fn test_info_subcommand() {
    let (code, stdout, _) = run_zeitstempel(&["info", "tests/fixtures/hello-world.txt.ots"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("SHA256"));
    assert!(stdout.contains("03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"));
    assert!(stdout.contains("Bitcoin block #358391"));
}

#[test]
fn test_verify_wrong_file() {
    let tmp = "/tmp/zeitstempel-test-wrong.txt";
    std::fs::write(tmp, b"This is NOT Hello World!\n").unwrap();

    let (code, _, stderr) = run_zeitstempel(&["verify", tmp, "tests/fixtures/hello-world.txt.ots"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("digest mismatch") || stderr.contains("different file"));

    std::fs::remove_file(tmp).ok();
}

#[test]
fn test_verify_missing_file() {
    let (code, _, stderr) = run_zeitstempel(&["verify", "nonexistent.txt", "tests/fixtures/hello-world.txt.ots"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("Error reading"));
}

#[test]
fn test_verify_invalid_ots() {
    let tmp = "/tmp/zeitstempel-test-invalid.ots";
    std::fs::write(tmp, b"not a valid ots file").unwrap();

    let (code, _, stderr) = run_zeitstempel(&["verify", "tests/fixtures/hello-world.txt", tmp]);
    assert_ne!(code, 0);
    assert!(stderr.contains("bad magic") || stderr.contains("Error"));

    std::fs::remove_file(tmp).ok();
}

#[test]
fn test_no_args() {
    let (code, stdout, _) = run_zeitstempel(&[]);
    assert_ne!(code, 0);
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn test_legacy_bare_two_arg_form() {
    // The legacy form (without "verify" subcommand) should still work
    let (code, stdout, _) = run_zeitstempel(&[
        "tests/fixtures/hello-world.txt",
        "tests/fixtures/hello-world.txt.ots",
    ]);
    assert_eq!(code, 0, "legacy two-arg form should still work");
    assert!(stdout.contains("Verified!"));
}

/// Full verification via the verify subcommand against the Bitcoin blockchain.
#[test]
fn test_full_bitcoin_verification() {
    let (code, stdout, _) = run_zeitstempel(&[
        "verify",
        "tests/fixtures/hello-world.txt",
        "tests/fixtures/hello-world.txt.ots",
    ]);
    assert_eq!(code, 0, "verification should succeed");
    assert!(stdout.contains("Verified!"));
    assert!(stdout.contains("358391"));
    assert!(stdout.contains("Merkle root match confirmed"));
}
