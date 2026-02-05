/// Stamping logic — hash a file and submit to OpenTimestamps calendar servers.
///
/// The stamping flow:
///   1. SHA256-hash the file
///   2. Generate a 16-byte random nonce (privacy protection)
///   3. Compute calendar_digest = SHA256(nonce || file_digest)
///   4. POST the 32-byte calendar_digest to calendar server(s)
///   5. Build the .ots binary from header + operations + calendar responses

use std::fmt;
use std::io::Read;
use sha2::{Sha256, Digest};

use crate::parser;
use crate::writer;

/// Calendar servers to submit to (first two for speed).
const CALENDAR_SERVERS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
];

#[derive(Debug)]
pub enum StampError {
    NoCalendarResponse(String),
    Http(String),
    Rng(String),
}

impl fmt::Display for StampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StampError::NoCalendarResponse(msg) => write!(f, "no calendar server responded: {}", msg),
            StampError::Http(msg) => write!(f, "HTTP error: {}", msg),
            StampError::Rng(msg) => write!(f, "random number generation failed: {}", msg),
        }
    }
}

impl std::error::Error for StampError {}

/// Stamp file data and return the complete .ots proof bytes.
///
/// The returned bytes can be written directly to a `.ots` file.
pub fn stamp_file(file_data: &[u8]) -> Result<Vec<u8>, StampError> {
    // 1. Compute file digest
    let file_digest = Sha256::digest(file_data);

    // 2. Generate 16-byte random nonce for privacy
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| StampError::Rng(format!("{}", e)))?;

    // 3. Compute calendar digest: SHA256(nonce || file_digest)
    let mut hasher = Sha256::new();
    hasher.update(&nonce);
    hasher.update(&file_digest);
    let calendar_digest = hasher.finalize();

    // 4. Submit to calendar servers in parallel-ish (sequential with short timeout)
    let mut responses: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for server in CALENDAR_SERVERS {
        match submit_to_calendar(server, &calendar_digest) {
            Ok(response) => responses.push((server, response)),
            Err(e) => errors.push(format!("{}: {}", server, e)),
        }
    }

    if responses.is_empty() {
        return Err(StampError::NoCalendarResponse(errors.join("; ")));
    }

    // 5. Build the .ots binary
    let mut buf = Vec::new();

    // Header + version
    writer::write_header(&mut buf);
    writer::write_varuint(&mut buf, 1); // version 1

    // Hash operation + file digest
    writer::write_hash_op(&mut buf, parser::HashOp::Sha256);
    buf.extend_from_slice(&file_digest);

    // Prepend(nonce) operation
    buf.push(parser::TAG_PREPEND);
    writer::write_varbytes(&mut buf, &nonce);

    // SHA256 operation (produces the calendar_digest)
    buf.push(parser::TAG_SHA256);

    // Calendar responses — if multiple, use fork markers
    if responses.len() > 1 {
        // All but the last get a fork prefix (0xFF)
        for (_server, response) in &responses[..responses.len() - 1] {
            buf.push(parser::TAG_FORK);
            buf.extend_from_slice(response);
        }
    }
    // Last (or only) response — no fork prefix
    if let Some((_server, response)) = responses.last() {
        buf.extend_from_slice(response);
    }

    Ok(buf)
}

/// Submit a 32-byte digest to a calendar server via HTTP POST.
///
/// Returns the raw binary timestamp tree bytes from the server.
fn submit_to_calendar(server: &str, digest: &[u8]) -> Result<Vec<u8>, StampError> {
    let url = format!("{}/digest", server);

    let response = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(15))
        .set("Accept", "application/vnd.opentimestamps.v1")
        .set("User-Agent", "zeitstempel")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_bytes(digest)
        .map_err(|e| StampError::Http(format!("{}: {}", url, e)))?;

    let mut body = Vec::new();
    response.into_reader()
        .take(65536) // 64KB max — calendar responses are typically ~4KB
        .read_to_end(&mut body)
        .map_err(|e| StampError::Http(format!("reading response from {}: {}", url, e)))?;

    if body.is_empty() {
        return Err(StampError::Http(format!("empty response from {}", url)));
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        // Verify getrandom works and produces different values
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut a).unwrap();
        getrandom::getrandom(&mut b).unwrap();
        assert_ne!(a, b, "two random nonces should differ");
    }

    #[test]
    fn test_calendar_digest_computation() {
        // Verify the nonce || digest → SHA256 computation is deterministic
        let file_data = b"Hello World!\n";
        let file_digest = Sha256::digest(file_data);

        let nonce = [0u8; 16]; // zero nonce for reproducibility

        let mut hasher = Sha256::new();
        hasher.update(&nonce);
        hasher.update(&file_digest);
        let calendar_digest = hasher.finalize();

        // Should be 32 bytes
        assert_eq!(calendar_digest.len(), 32);

        // Should differ from file_digest (nonce changes it)
        assert_ne!(calendar_digest.as_slice(), file_digest.as_slice());
    }
}
