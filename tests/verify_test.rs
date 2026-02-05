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

// ── Stamp subcommand tests ───────────────────────────────────────

#[test]
fn test_stamp_creates_ots_file() {
    let tmp_dir = std::env::temp_dir().join("zeitstempel-test-stamp");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let input = tmp_dir.join("stamp-test.txt");
    let ots = tmp_dir.join("stamp-test.txt.ots");

    // Clean up from any previous run
    std::fs::remove_file(&ots).ok();

    std::fs::write(&input, b"Stamp integration test\n").unwrap();

    let (code, stdout, stderr) = run_zeitstempel(&[
        "stamp",
        input.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stamp should succeed. stderr: {}", stderr);
    assert!(stdout.contains("Timestamp proof created"), "should confirm creation");
    assert!(ots.exists(), ".ots file should exist");

    // Clean up
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&ots).ok();
    std::fs::remove_dir(&tmp_dir).ok();
}

#[test]
fn test_stamp_then_info_shows_pending() {
    let tmp_dir = std::env::temp_dir().join("zeitstempel-test-stamp-info");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let input = tmp_dir.join("info-test.txt");
    let ots = tmp_dir.join("info-test.txt.ots");

    // Clean up from any previous run
    std::fs::remove_file(&ots).ok();

    std::fs::write(&input, b"Stamp then info test\n").unwrap();

    // Stamp the file
    let (code, _, stderr) = run_zeitstempel(&["stamp", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stamp should succeed. stderr: {}", stderr);

    // Inspect with info — should show Pending attestation(s)
    let (code, stdout, _) = run_zeitstempel(&["info", ots.to_str().unwrap()]);
    assert_eq!(code, 0, "info should succeed");
    assert!(stdout.contains("Pending"), "should show Pending attestation");
    assert!(stdout.contains("SHA256"), "should show SHA256 hash op");
    assert!(stdout.contains("calendar.opentimestamps.org"), "should show calendar URI");

    // Clean up
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&ots).ok();
    std::fs::remove_dir(&tmp_dir).ok();
}

#[test]
fn test_stamp_then_verify_digest_matches() {
    let tmp_dir = std::env::temp_dir().join("zeitstempel-test-stamp-verify");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let input = tmp_dir.join("verify-test.txt");
    let ots = tmp_dir.join("verify-test.txt.ots");

    // Clean up from any previous run
    std::fs::remove_file(&ots).ok();

    std::fs::write(&input, b"Stamp then verify test\n").unwrap();

    // Stamp the file
    let (code, _, stderr) = run_zeitstempel(&["stamp", input.to_str().unwrap()]);
    assert_eq!(code, 0, "stamp should succeed. stderr: {}", stderr);

    // Verify should succeed (pending, but digest matches)
    let (code, stdout, stderr) = run_zeitstempel(&[
        "verify",
        input.to_str().unwrap(),
        ots.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "verify should succeed (exit 0 for pending). stderr: {}", stderr);
    assert!(stdout.contains("Pending"), "should show Pending status");

    // Clean up
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&ots).ok();
    std::fs::remove_dir(&tmp_dir).ok();
}

#[test]
fn test_stamp_refuses_to_overwrite() {
    let tmp_dir = std::env::temp_dir().join("zeitstempel-test-stamp-overwrite");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let input = tmp_dir.join("overwrite-test.txt");
    let ots = tmp_dir.join("overwrite-test.txt.ots");

    std::fs::write(&input, b"Overwrite test\n").unwrap();
    // Pre-create the .ots file
    std::fs::write(&ots, b"existing proof").unwrap();

    let (code, _, stderr) = run_zeitstempel(&["stamp", input.to_str().unwrap()]);
    assert_ne!(code, 0, "stamp should refuse to overwrite");
    assert!(stderr.contains("already exists"), "should warn about existing file");

    // Clean up
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&ots).ok();
    std::fs::remove_dir(&tmp_dir).ok();
}

#[test]
fn test_stamp_missing_file() {
    let (code, _, stderr) = run_zeitstempel(&["stamp", "/tmp/zeitstempel-nonexistent-12345.txt"]);
    assert_ne!(code, 0, "stamp should fail for missing file");
    assert!(stderr.contains("Error reading"), "should report read error");
}

#[test]
fn test_help_includes_stamp() {
    let (code, stdout, _) = run_zeitstempel(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("stamp"), "help should mention stamp subcommand");
}
