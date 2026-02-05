/// Binary .ots format writer — the inverse of parser.rs.
///
/// Builds .ots proof files by writing the header, varuint-encoded
/// lengths, operation tags, and raw byte payloads into a Vec<u8>.

use crate::parser::{self, HashOp};

/// Write the 31-byte OTS magic header.
pub fn write_header(buf: &mut Vec<u8>) {
    buf.extend_from_slice(parser::HEADER_MAGIC);
}

/// Write a version number as a varuint.
pub fn write_varuint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80; // continuation bit
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Write a length-prefixed byte string (varuint length + raw bytes).
pub fn write_varbytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_varuint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Write the 1-byte tag for a hash operation.
pub fn write_hash_op(buf: &mut Vec<u8>, op: HashOp) {
    buf.push(match op {
        HashOp::Sha256    => parser::TAG_SHA256,
        HashOp::Sha1      => parser::TAG_SHA1,
        HashOp::Ripemd160 => parser::TAG_RIPEMD160,
        HashOp::Keccak256 => parser::TAG_KECCAK256,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varuint_roundtrip_single_byte() {
        // Values 0–127 should encode as a single byte
        for val in [0u64, 1, 42, 127] {
            let mut buf = Vec::new();
            write_varuint(&mut buf, val);

            // Parse back with the parser's decoder
            let mut p = crate::parser::tests_support::make_parser(&buf);
            assert_eq!(p.read_varuint().unwrap(), val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_varuint_roundtrip_multi_byte() {
        // 128, 300, and larger values need multiple bytes
        for val in [128u64, 300, 16384, 1_000_000, u64::MAX / 2] {
            let mut buf = Vec::new();
            write_varuint(&mut buf, val);

            let mut p = crate::parser::tests_support::make_parser(&buf);
            assert_eq!(p.read_varuint().unwrap(), val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_varuint_known_encodings() {
        // 0 → [0x00]
        let mut buf = Vec::new();
        write_varuint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        // 1 → [0x01]
        buf.clear();
        write_varuint(&mut buf, 1);
        assert_eq!(buf, vec![0x01]);

        // 128 → [0x80, 0x01]
        buf.clear();
        write_varuint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        // 300 → [0xAC, 0x02]
        buf.clear();
        write_varuint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_varbytes_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let mut buf = Vec::new();
        write_varbytes(&mut buf, &data);

        let mut p = crate::parser::tests_support::make_parser(&buf);
        assert_eq!(p.read_varbytes().unwrap(), data);
    }

    #[test]
    fn test_varbytes_empty() {
        let mut buf = Vec::new();
        write_varbytes(&mut buf, &[]);

        let mut p = crate::parser::tests_support::make_parser(&buf);
        assert_eq!(p.read_varbytes().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_header_bytes() {
        let mut buf = Vec::new();
        write_header(&mut buf);
        assert_eq!(buf.len(), 31);
        assert_eq!(&buf, parser::HEADER_MAGIC);
    }

    #[test]
    fn test_hash_op_tag() {
        let mut buf = Vec::new();
        write_hash_op(&mut buf, HashOp::Sha256);
        assert_eq!(buf, vec![0x08]);

        buf.clear();
        write_hash_op(&mut buf, HashOp::Sha1);
        assert_eq!(buf, vec![0x02]);

        buf.clear();
        write_hash_op(&mut buf, HashOp::Ripemd160);
        assert_eq!(buf, vec![0x03]);
    }
}
