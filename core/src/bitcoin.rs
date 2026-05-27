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
    pub previousblockhash: Option<String>, // for future chain validation
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

    // Phase 1 hardening: reject obviously spoofed or bogus blocks
    const MIN_HEIGHT: u64 = 300_000; // OTS usage started well after this height
    const MAX_FUTURE_SKEW_SECS: u64 = 2 * 3600;

    if height < MIN_HEIGHT {
        return Err(ApiError::Parse(format!(
            "block height {} is below minimum ({}); this looks like a spoofed response",
            height, MIN_HEIGHT
        )));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if timestamp > now + MAX_FUTURE_SKEW_SECS {
        return Err(ApiError::Parse(
            "block timestamp is in the future (more than 2h skew)".into(),
        ));
    }

    let previousblockhash = json["previousblockhash"]
        .as_str()
        .map(|s| s.to_string());

    Ok(BlockInfo {
        height,
        block_hash,
        merkle_root,
        timestamp,
        previousblockhash,
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

/// Fetch the current Bitcoin tip height — the height of the most
/// recently mined block. Combined with an anchored block's height
/// this gives an exact confirmation count, not a wall-clock estimate.
pub fn get_tip_height() -> Result<u64, ApiError> {
    get_tip_height_from("https://blockstream.info/api")
        .or_else(|_| get_tip_height_from("https://mempool.space/api"))
}

fn get_tip_height_from(base_url: &str) -> Result<u64, ApiError> {
    let url = format!("{}/blocks/tip/height", base_url);
    let body = http_get_text(&url)?;
    body.trim()
        .parse::<u64>()
        .map_err(|e| ApiError::Parse(format!("bad tip-height response: {}", e)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes_accepts_ascii_hex() {
        assert_eq!(hex_to_bytes("00ff42").unwrap(), vec![0x00, 0xff, 0x42]);
    }

    #[test]
    fn test_hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("abc").is_err());
    }

    #[test]
    fn test_hex_to_bytes_does_not_panic_on_utf8() {
        // 16 crab emojis = 64 bytes (even); passes the 64-char length
        // check the API caller uses, but is not hex. The previous
        // implementation panicked on `&hex[i..i+2]` slicing inside a
        // multi-byte code point.
        let crabby = "\u{1F980}".repeat(16);
        assert_eq!(crabby.len(), 64);
        let result = hex_to_bytes(&crabby);
        assert!(result.is_err(), "expected error, got {:?}", result);
    }

    #[test]
    fn test_hex_to_bytes_rejects_non_hex_ascii() {
        assert!(hex_to_bytes("zz").is_err());
        assert!(hex_to_bytes("0g").is_err());
    }

    #[test]
    fn test_merkle_root_le_reverses_bytes() {
        // "0102" big-endian → bytes [0x01, 0x02] → reversed [0x02, 0x01]
        assert_eq!(merkle_root_to_le_bytes("0102").unwrap(), vec![0x02, 0x01]);
    }
}

/// Parse a hex string into bytes.
///
/// Validates ASCII hex before slicing — a compromised Bitcoin API
/// returning a `merkle_root` with multi-byte UTF-8 characters would
/// otherwise panic on the `&hex[i..i+2]` slice landing in the middle
/// of a code point.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    if !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err("non-hex character in input".into());
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            // SAFETY: `pair` is two ASCII hex bytes, validated above.
            let s = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex: {}", e))
        })
        .collect()
}
