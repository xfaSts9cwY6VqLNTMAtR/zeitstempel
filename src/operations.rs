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
pub fn apply(op: &Operation, msg: &[u8]) -> Vec<u8> {
    match op {
        Operation::Append(data) => {
            let mut out = msg.to_vec();
            out.extend_from_slice(data);
            out
        }
        Operation::Prepend(data) => {
            let mut out = data.clone();
            out.extend_from_slice(msg);
            out
        }
        Operation::Sha256 => {
            Sha256::digest(msg).to_vec()
        }
        Operation::Sha1 => {
            Sha1::digest(msg).to_vec()
        }
        Operation::Ripemd160 => {
            Ripemd160::digest(msg).to_vec()
        }
        Operation::Keccak256 => {
            // Keccak256 is rare in OTS files. If we encounter it, we'd
            // need the `sha3` crate. For now, panic with a clear message.
            panic!("Keccak256 not yet supported — add the sha3 crate if needed")
        }
        Operation::Reverse => {
            let mut out = msg.to_vec();
            out.reverse();
            out
        }
        Operation::Hexlify => {
            // Convert each byte to its two-character lowercase hex representation.
            // The result is ASCII bytes, not a string.
            let hex_str = crate::parser::hex(msg);
            hex_str.into_bytes()
        }
    }
}

/// Hash file contents using the algorithm specified in the OTS header.
pub fn hash_file_contents(data: &[u8], hash_op: HashOp) -> Vec<u8> {
    match hash_op {
        HashOp::Sha256    => Sha256::digest(data).to_vec(),
        HashOp::Sha1      => Sha1::digest(data).to_vec(),
        HashOp::Ripemd160 => Ripemd160::digest(data).to_vec(),
        HashOp::Keccak256 => panic!("Keccak256 not yet supported"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::hex;

    #[test]
    fn test_sha256_known_answer() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = apply(&Operation::Sha256, b"");
        assert_eq!(hex(&result), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_hello_world() {
        // SHA256("Hello World!\n") — the digest stored in our fixture
        let result = hash_file_contents(b"Hello World!\n", HashOp::Sha256);
        assert_eq!(hex(&result), "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340");
    }

    #[test]
    fn test_sha1_known_answer() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let result = apply(&Operation::Sha1, b"");
        assert_eq!(hex(&result), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_ripemd160_known_answer() {
        // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let result = apply(&Operation::Ripemd160, b"");
        assert_eq!(hex(&result), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    }

    #[test]
    fn test_append() {
        let result = apply(&Operation::Append(vec![0xCC, 0xDD]), &[0xAA, 0xBB]);
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_prepend() {
        let result = apply(&Operation::Prepend(vec![0xCC, 0xDD]), &[0xAA, 0xBB]);
        assert_eq!(result, vec![0xCC, 0xDD, 0xAA, 0xBB]);
    }

    #[test]
    fn test_reverse() {
        let result = apply(&Operation::Reverse, &[0x01, 0x02, 0x03]);
        assert_eq!(result, vec![0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_hexlify() {
        let result = apply(&Operation::Hexlify, &[0xab, 0xcd]);
        // Should produce the ASCII bytes for "abcd"
        assert_eq!(result, b"abcd".to_vec());
    }
}
