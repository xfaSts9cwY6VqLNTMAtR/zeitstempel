/// Bitcoin block header lookups via public APIs.
///
/// We query Blockstream.info first, with mempool.space as fallback.
/// The two endpoints we need:
///   GET /api/block-height/{height}  → block hash (plain text)
///   GET /api/block/{hash}           → JSON with merkle_root, timestamp, etc.

use std::fmt;

/// Information about a Bitcoin block relevant for OTS verification.
#[derive(Debug)]
pub struct BlockInfo {
    pub height: u64,
    pub block_hash: String,
    pub merkle_root: String,  // hex, display order (big-endian)
    pub timestamp: u64,       // Unix epoch seconds
}

#[derive(Debug)]
pub enum ApiError {
    Http(String),
    Parse(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Http(msg)  => write!(f, "HTTP error: {}", msg),
            ApiError::Parse(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

/// Fetch block info for a given block height.
///
/// Tries Blockstream.info first, falls back to mempool.space.
pub fn get_block_info(height: u64) -> Result<BlockInfo, ApiError> {
    get_block_info_from("https://blockstream.info/api", height)
        .or_else(|_| {
            eprintln!("  (Blockstream unavailable, trying mempool.space...)");
            get_block_info_from("https://mempool.space/api", height)
        })
}

fn get_block_info_from(base_url: &str, height: u64) -> Result<BlockInfo, ApiError> {
    // Step 1: Get block hash from height
    let hash_url = format!("{}/block-height/{}", base_url, height);
    let block_hash = http_get_text(&hash_url)?;

    // Sanity check: block hash should be 64 hex chars
    let block_hash = block_hash.trim().to_string();
    if block_hash.len() != 64 {
        return Err(ApiError::Parse(format!(
            "expected 64-char block hash, got {} chars: '{}'",
            block_hash.len(), block_hash
        )));
    }

    // Step 2: Get block details (JSON) from hash
    let block_url = format!("{}/block/{}", base_url, block_hash);
    let json_text = http_get_text(&block_url)?;

    let json: serde_json::Value = serde_json::from_str(&json_text)
        .map_err(|e| ApiError::Parse(format!("invalid JSON: {}", e)))?;

    let merkle_root = json["merkle_root"]
        .as_str()
        .ok_or_else(|| ApiError::Parse("missing merkle_root in block JSON".into()))?
        .to_string();

    let timestamp = json["timestamp"]
        .as_u64()
        .ok_or_else(|| ApiError::Parse("missing timestamp in block JSON".into()))?;

    Ok(BlockInfo {
        height,
        block_hash,
        merkle_root,
        timestamp,
    })
}

/// Simple HTTP GET that returns the response body as a string.
fn http_get_text(url: &str) -> Result<String, ApiError> {
    ureq::get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| ApiError::Http(format!("{}: {}", url, e)))?
        .into_string()
        .map_err(|e| ApiError::Http(format!("reading response from {}: {}", url, e)))
}

/// Convert a hex merkle root (big-endian display order from API) to
/// little-endian bytes (which is what the OTS proof chain produces).
///
/// Bitcoin's internal byte order is reversed from the display format.
/// The API returns "abc123..." in display order, but the proof chain
/// produces bytes in little-endian (reversed) order.
pub fn merkle_root_to_le_bytes(hex_be: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex_to_bytes(hex_be)
        .map_err(|e| ApiError::Parse(format!("bad merkle root hex: {}", e)))?;
    let mut le = bytes;
    le.reverse();
    Ok(le)
}

/// Parse a hex string into bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {}: {}", i, e))
        })
        .collect()
}
