/// Verification logic — hash the input file, walk the proof tree,
/// and check attestations against the Bitcoin blockchain.

use crate::parser::{self, OtsFile, Timestamp, Attestation};
use crate::operations;
use crate::bitcoin;

/// Result of verifying one attestation path.
pub enum VerifyResult {
    /// Merkle root matched a Bitcoin block.
    BitcoinVerified {
        height: u64,
        block_hash: String,
        timestamp: u64,
    },
    /// Proof chain ends at a pending calendar.
    Pending {
        uri: String,
    },
    /// Merkle root did NOT match.
    Failed {
        height: u64,
        expected: Vec<u8>,
        got: Vec<u8>,
    },
    /// Attestation type we don't verify (Litecoin, Ethereum, Unknown).
    Skipped {
        reason: String,
    },
    /// Network or API error during verification.
    Error {
        message: String,
    },
}

/// Verify a file against its .ots proof.
///
/// Returns one `VerifyResult` per attestation path in the proof tree.
pub fn verify_file(file_data: &[u8], ots_data: &[u8]) -> Result<Vec<VerifyResult>, String> {
    // 1. Parse the .ots file
    let ots = parser::parse_ots(ots_data)
        .map_err(|e| format!("Failed to parse .ots file: {}", e))?;

    // 2. Hash the input file
    let computed_digest = operations::hash_file_contents(file_data, ots.hash_op);

    // 3. Compare digests
    if computed_digest != ots.file_digest {
        return Err(format!(
            "File digest mismatch!\n  Expected (from .ots): {}\n  Computed (from file): {}\n  This .ots proof is for a different file.",
            parser::hex(&ots.file_digest),
            parser::hex(&computed_digest),
        ));
    }

    // 4. Walk the proof tree, collecting results
    let mut results = Vec::new();
    walk_timestamp(&ots.timestamp, &ots.file_digest, &mut results);

    Ok(results)
}

/// Verify an .ots proof where the input is already a content hash.
///
/// This is for KanBanito's double-hash pattern: the "file" is a
/// content-hash.txt containing 64 hex chars (the SHA256 of the data).
/// The .ots header hash op was applied to that hash string.
pub fn verify_hash_file(hash_file_data: &[u8], ots_data: &[u8]) -> Result<Vec<VerifyResult>, String> {
    // Same as verify_file — the hash_file is just treated as any file
    verify_file(hash_file_data, ots_data)
}

/// Parse and return the OtsFile without verifying (for --info mode).
pub fn parse_only(ots_data: &[u8]) -> Result<OtsFile, String> {
    parser::parse_ots(ots_data)
        .map_err(|e| format!("Failed to parse .ots file: {}", e))
}

// ── Tree walker ────────────────────────────────────────────────────

/// Recursively walk the timestamp tree, applying operations and
/// checking attestations.
fn walk_timestamp(ts: &Timestamp, msg: &[u8], results: &mut Vec<VerifyResult>) {
    // Check attestations at this node
    for att in &ts.attestations {
        results.push(check_attestation(att, msg));
    }

    // Follow operation branches
    for (op, child) in &ts.ops {
        let new_msg = operations::apply(op, msg);
        walk_timestamp(child, &new_msg, results);
    }
}

/// Check a single attestation against the blockchain (or report pending).
fn check_attestation(att: &Attestation, msg: &[u8]) -> VerifyResult {
    match att {
        Attestation::Bitcoin { height } => verify_bitcoin(*height, msg),
        Attestation::Pending { uri } => VerifyResult::Pending { uri: uri.clone() },
        Attestation::Litecoin { height } => VerifyResult::Skipped {
            reason: format!("Litecoin block #{} — not verified (no Litecoin API configured)", height),
        },
        Attestation::Ethereum { height } => VerifyResult::Skipped {
            reason: format!("Ethereum block #{} — not verified (no Ethereum API configured)", height),
        },
        Attestation::Unknown { tag, .. } => VerifyResult::Skipped {
            reason: format!("Unknown attestation type (tag: {})", parser::hex(tag)),
        },
    }
}

/// Verify a Bitcoin attestation by checking the merkle root.
fn verify_bitcoin(height: u64, msg: &[u8]) -> VerifyResult {
    // Fetch block info from the API
    let block_info = match bitcoin::get_block_info(height) {
        Ok(info) => info,
        Err(e) => return VerifyResult::Error {
            message: format!("Could not fetch Bitcoin block #{}: {}", height, e),
        },
    };

    // Convert API merkle root (big-endian hex) to little-endian bytes
    let expected_le = match bitcoin::merkle_root_to_le_bytes(&block_info.merkle_root) {
        Ok(bytes) => bytes,
        Err(e) => return VerifyResult::Error {
            message: format!("Bad merkle root from API: {}", e),
        },
    };

    // Compare!
    if msg == expected_le.as_slice() {
        VerifyResult::BitcoinVerified {
            height,
            block_hash: block_info.block_hash,
            timestamp: block_info.timestamp,
        }
    } else {
        VerifyResult::Failed {
            height,
            expected: expected_le,
            got: msg.to_vec(),
        }
    }
}
