/// Upgrade logic — replace pending calendar attestations with completed Bitcoin proofs.
///
/// When you `stamp` a file, the calendar server returns a "pending" attestation:
/// your digest was submitted but not yet anchored to the Bitcoin blockchain.
/// After a few hours (1-3 Bitcoin blocks), the proof chain is complete.
///
/// The `upgrade` command contacts the calendar server, fetches the completed
/// sub-tree, and replaces the pending attestation in the .ots file.

use std::fmt;
use std::io::Read;
use std::thread;
use std::time::Duration;

use crate::operations;
use crate::parser::{self, Attestation, OtsFile, Timestamp};
use crate::writer;

/// Statistics returned after an upgrade attempt.
pub struct UpgradeResult {
    pub upgraded: usize,
    pub still_pending: usize,
    pub errors: Vec<String>,
    pub already_complete: bool,
}

#[derive(Debug)]
pub enum UpgradeError {
    Parse(String),
    Io(String),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpgradeError::Parse(msg) => write!(f, "parse error: {}", msg),
            UpgradeError::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// Try to upgrade all pending attestations in an OTS file.
///
/// Returns the (possibly modified) OtsFile and statistics about what happened.
pub fn upgrade(ots: &mut OtsFile) -> UpgradeResult {
    let mut result = UpgradeResult {
        upgraded: 0,
        still_pending: 0,
        errors: Vec::new(),
        already_complete: false,
    };

    // Check if there are any pending attestations at all
    if !has_pending(&ots.timestamp) {
        result.already_complete = true;
        return result;
    }

    // Walk the tree, starting with the file digest as the initial message
    let msg = ots.file_digest.clone();
    upgrade_timestamp(&mut ots.timestamp, &msg, &mut result, 0);

    result
}

const MAX_DEPTH: usize = 256;

/// Recursively walk the timestamp tree, upgrading pending attestations.
///
/// `msg` tracks the current hash state at this node — operations transform
/// it as we descend. When we find a Pending attestation, we contact the
/// calendar server and try to replace it with the completed sub-tree.
fn upgrade_timestamp(ts: &mut Timestamp, msg: &[u8], result: &mut UpgradeResult, depth: usize) {
    if depth > MAX_DEPTH {
        result.errors.push("proof tree exceeds maximum depth".into());
        return;
    }
    // Process pending attestations — we may need to remove some and add ops
    let mut new_attestations = Vec::new();
    let mut new_ops = Vec::new();

    for att in ts.attestations.drain(..) {
        if let Attestation::Pending { ref uri } = att {
            match fetch_upgrade(uri, msg) {
                Ok(Some(sub_tree)) => {
                    // Upgraded! Merge the sub-tree into this node.
                    // The sub-tree's attestations and ops become ours.
                    for sub_att in sub_tree.attestations {
                        new_attestations.push(sub_att);
                    }
                    for sub_op in sub_tree.ops {
                        new_ops.push(sub_op);
                    }
                    result.upgraded += 1;
                }
                Ok(None) => {
                    // Still pending — keep the attestation as-is
                    new_attestations.push(att);
                    result.still_pending += 1;
                }
                Err(e) => {
                    // Error — keep the attestation and report
                    new_attestations.push(att);
                    result.errors.push(e);
                }
            }
        } else {
            // Non-pending attestation — keep as-is
            new_attestations.push(att);
        }
    }

    ts.attestations = new_attestations;
    ts.ops.extend(new_ops);

    // Recurse into operation children
    for (op, child) in &mut ts.ops {
        let new_msg = match operations::apply(op, msg) {
            Ok(m) => m,
            Err(e) => {
                result.errors.push(format!("Operation failed: {}", e));
                continue;
            }
        };
        upgrade_timestamp(child, &new_msg, result, depth + 1);
    }
}

/// Contact the calendar server and try to fetch the completed proof.
///
/// Returns:
/// - `Ok(Some(timestamp))` if the server returned a completed sub-tree
/// - `Ok(None)` if still pending (404 or incomplete response)
/// - `Err(message)` on network/parse errors
fn fetch_upgrade(uri: &str, msg: &[u8]) -> Result<Option<Timestamp>, String> {
    let url = format!("{}/timestamp/{}", uri.trim_end_matches('/'), parser::hex(msg));

    let response = match ureq::get(&url)
        .timeout(Duration::from_secs(15))
        .set("Accept", "application/vnd.opentimestamps.v1")
        .set("User-Agent", "zeitstempel")
        .call()
    {
        Ok(resp) => resp,
        Err(ureq::Error::Status(404, _)) => return Ok(None),
        Err(e) => {
            return Err(format!("Could not reach calendar server at {}: {}", uri, e));
        }
    };

    // Read the response body
    let mut body = Vec::new();
    response.into_reader()
        .take(1_048_576) // 1MB max
        .read_to_end(&mut body)
        .map_err(|e| format!("Error reading response from {}: {}", uri, e))?;

    if body.is_empty() {
        return Ok(None);
    }

    // Parse the response as a timestamp sub-tree
    let sub_tree = parser::parse_timestamp_from_bytes(&body, msg)
        .map_err(|e| format!("Failed to parse calendar response from {}: {}", uri, e))?;

    Ok(Some(sub_tree))
}

/// Check if a timestamp tree contains any pending attestations.
fn has_pending(ts: &Timestamp) -> bool {
    for att in &ts.attestations {
        if matches!(att, Attestation::Pending { .. }) {
            return true;
        }
    }
    for (_, child) in &ts.ops {
        if has_pending(child) {
            return true;
        }
    }
    false
}

/// Find the Bitcoin block height in a timestamp tree (for reporting).
pub fn find_bitcoin_height(ts: &Timestamp) -> Option<u64> {
    for att in &ts.attestations {
        if let Attestation::Bitcoin { height } = att {
            return Some(*height);
        }
    }
    for (_, child) in &ts.ops {
        if let Some(h) = find_bitcoin_height(child) {
            return Some(h);
        }
    }
    None
}

/// Run the full upgrade workflow: read, upgrade, write back if changed.
///
/// Returns true if the file was modified.
pub fn run_upgrade(ots_path: &str, wait: bool) -> Result<bool, UpgradeError> {
    let ots_data = std::fs::read(ots_path)
        .map_err(|e| UpgradeError::Io(format!("Error reading '{}': {}", ots_path, e)))?;

    let mut ots = parser::parse_ots(&ots_data)
        .map_err(|e| UpgradeError::Parse(format!("Failed to parse '{}': {}", ots_path, e)))?;

    if wait {
        return run_upgrade_wait(&mut ots, ots_path);
    }

    let result = upgrade(&mut ots);
    print_result(&result, &ots);

    if result.upgraded > 0 {
        write_back(&ots, ots_path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Polling mode: try to upgrade repeatedly until all pending attestations
/// are complete. The user can Ctrl+C to stop.
fn run_upgrade_wait(ots: &mut OtsFile, ots_path: &str) -> Result<bool, UpgradeError> {
    // Quick check: anything to upgrade at all?
    if !has_pending(&ots.timestamp) {
        println!("Nothing to upgrade — all attestations are already anchored to Bitcoin.");
        return Ok(false);
    }

    println!("Waiting for calendar server to anchor timestamp to Bitcoin...");
    println!("Polling every 3 minutes. Press Ctrl+C to stop.");
    println!();

    let mut attempt = 0;
    let mut any_upgraded = false;

    loop {
        attempt += 1;
        let result = upgrade(ots);

        if result.upgraded > 0 {
            any_upgraded = true;
        }

        if result.already_complete || (result.still_pending == 0 && result.errors.is_empty()) {
            // All done!
            print_result(&result, ots);
            if any_upgraded {
                write_back(ots, ots_path)?;
            }
            return Ok(any_upgraded);
        }

        // Save intermediate progress if we upgraded some but not all
        if result.upgraded > 0 {
            write_back(ots, ots_path)?;
        }

        println!("Still waiting... (attempt {})", attempt);
        if !result.errors.is_empty() {
            for e in &result.errors {
                println!("  Warning: {}", e);
            }
        }
        println!();

        thread::sleep(Duration::from_secs(180));
    }
}

/// Print user-friendly output for an upgrade result.
fn print_result(result: &UpgradeResult, ots: &OtsFile) {
    if result.already_complete {
        println!("Nothing to upgrade — all attestations are already anchored to Bitcoin.");
        return;
    }

    if result.upgraded > 0 {
        if let Some(height) = find_bitcoin_height(&ots.timestamp) {
            println!("Upgraded! Attestation now anchored to Bitcoin block #{}.", height);
        } else {
            println!("Upgraded! {} attestation(s) now anchored to Bitcoin.", result.upgraded);
        }
    }

    if result.still_pending > 0 {
        println!();
        println!(
            "Still pending — {} attestation(s) not yet anchored to Bitcoin.",
            result.still_pending
        );
        println!("This typically takes a few hours (1-3 Bitcoin blocks).");
        println!("Try again later, or use `--wait` to let zeitstempel poll until complete.");
    }

    for e in &result.errors {
        println!();
        println!("  {}", e);
    }
}

/// Write the modified OTS file back to disk.
fn write_back(ots: &OtsFile, path: &str) -> Result<(), UpgradeError> {
    let bytes = writer::write_ots(ots);
    std::fs::write(path, &bytes)
        .map_err(|e| UpgradeError::Io(format!("Error writing '{}': {}", path, e)))?;
    Ok(())
}
