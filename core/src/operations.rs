/// Operation executors — apply proof-chain operations to a message.
///
/// Each operation transforms a byte vector (the "message") as it walks
/// down the proof tree. Hash operations produce fixed-size digests;
/// append/prepend concatenate data; reverse/hexlify transform in place.

use sha2::{Sha256, Digest};
use sha1::Sha1;
use ripemd::Ripemd160;

use crate::parser::{Operation, HashOp};

/// Apply a single operation to a message, returning the new message.
pub fn apply(op: &Operation, msg: &[u8]) -> Result<Vec<u8>, OpError> {
    match op {
        Operation::Append(data) => {
            let mut out = msg.to_vec();
            out.extend_from_slice(data);
            Ok(out)
        }
        Operation::Prepend(data) => {
            let mut out = data.clone();
            out.extend_from_slice(msg);
            Ok(out)
        }
        Operation::Sha256 => Ok(Sha256::digest(msg).to_vec()),
        Operation::Sha1 => Ok(Sha1::digest(msg).to_vec()),
        Operation::Ripemd160 => Ok(Ripemd160::digest(msg).to_vec()),
        Operation::Keccak256 => Err(OpError::UnsupportedOp("Keccak256")),
        Operation::Reverse => {
            let mut out = msg.to_vec();
            out.reverse();
            Ok(out)
        }
        Operation::Hexlify => {
            let hex_str = crate::parser::hex(msg);
            Ok(hex_str.into_bytes())
        }
    }
}

/// Hash file contents using the algorithm specified in the OTS header.
pub fn hash_file_contents(data: &[u8], hash_op: HashOp) -> Result<Vec<u8>, OpError> {
    match hash_op {
        HashOp::Sha256    => Ok(Sha256::digest(data).to_vec()),
        HashOp::Sha1      => Ok(Sha1::digest(data).to_vec()),
        HashOp::Ripemd160 => Ok(Ripemd160::digest(data).to_vec()),
        HashOp::Keccak256 => Err(OpError::UnsupportedOp("Keccak256")),
    }
}

#[derive(Debug)]
pub enum OpError {
    UnsupportedOp(&'static str),
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::UnsupportedOp(name) => {
                write!(f, "{} is not yet supported — add the sha3 crate if needed", name)
            }
        }
    }
}

impl std::error::Error for OpError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::hex;

    #[test]
    fn test_sha256_known_answer() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = apply(&Operation::Sha256, b"").unwrap();
        assert_eq!(hex(&result), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_hello_world() {
        // SHA256("Hello World!\n") — the digest stored in our fixture
        let result = hash_file_contents(b"Hello World!\n", HashOp::Sha256).unwrap();
        assert_eq!(hex(&result), "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340");
    }

    #[test]
    fn test_sha1_known_answer() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let result = apply(&Operation::Sha1, b"").unwrap();
        assert_eq!(hex(&result), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_ripemd160_known_answer() {
        // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let result = apply(&Operation::Ripemd160, b"").unwrap();
        assert_eq!(hex(&result), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    }

    #[test]
    fn test_append() {
        let result = apply(&Operation::Append(vec![0xCC, 0xDD]), &[0xAA, 0xBB]).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_prepend() {
        let result = apply(&Operation::Prepend(vec![0xCC, 0xDD]), &[0xAA, 0xBB]).unwrap();
        assert_eq!(result, vec![0xCC, 0xDD, 0xAA, 0xBB]);
    }

    #[test]
    fn test_reverse() {
        let result = apply(&Operation::Reverse, &[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(result, vec![0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_hexlify() {
        let result = apply(&Operation::Hexlify, &[0xab, 0xcd]).unwrap();
        // Should produce the ASCII bytes for "abcd"
        assert_eq!(result, b"abcd".to_vec());
    }

    #[test]
    fn test_keccak256_returns_error() {
        let result = apply(&Operation::Keccak256, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Keccak256"));
    }
}
