/// Binary .ots format writer — the inverse of parser.rs.
///
/// Builds .ots proof files by writing the header, varuint-encoded
/// lengths, operation tags, and raw byte payloads into a Vec<u8>.

use crate::parser::{self, Attestation, HashOp, Operation, OtsFile, Timestamp};

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

/// Serialize a complete OtsFile back to its binary .ots format.
pub fn write_ots(ots: &OtsFile) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header + version 1
    write_header(&mut buf);
    write_varuint(&mut buf, 1);

    // Hash op + file digest
    write_hash_op(&mut buf, ots.hash_op);
    buf.extend_from_slice(&ots.file_digest);

    // Timestamp tree
    write_timestamp(&mut buf, &ots.timestamp);

    buf
}

/// Serialize a timestamp tree node.
///
/// Fork markers (`0xFF`) precede all branches except the last one.
/// Attestations are leaves; operations chain into child timestamps.
pub fn write_timestamp(buf: &mut Vec<u8>, ts: &Timestamp) {
    let total_branches = ts.attestations.len() + ts.ops.len();
    let mut branch_idx = 0;

    for att in &ts.attestations {
        if branch_idx < total_branches - 1 {
            buf.push(parser::TAG_FORK);
        }
        write_attestation(buf, att);
        branch_idx += 1;
    }

    for (op, child) in &ts.ops {
        if branch_idx < total_branches - 1 {
            buf.push(parser::TAG_FORK);
        }
        write_operation(buf, op);
        write_timestamp(buf, child);
        branch_idx += 1;
    }
}

/// Serialize a single operation.
pub fn write_operation(buf: &mut Vec<u8>, op: &Operation) {
    match op {
        Operation::Append(data) => {
            buf.push(parser::TAG_APPEND);
            write_varbytes(buf, data);
        }
        Operation::Prepend(data) => {
            buf.push(parser::TAG_PREPEND);
            write_varbytes(buf, data);
        }
        Operation::Sha256    => buf.push(parser::TAG_SHA256),
        Operation::Sha1      => buf.push(parser::TAG_SHA1),
        Operation::Ripemd160 => buf.push(parser::TAG_RIPEMD160),
        Operation::Keccak256 => buf.push(parser::TAG_KECCAK256),
        Operation::Reverse   => buf.push(parser::TAG_REVERSE),
        Operation::Hexlify   => buf.push(parser::TAG_HEXLIFY),
    }
}

/// Serialize an attestation: `0x00` marker + 8-byte type tag + varbytes payload.
pub fn write_attestation(buf: &mut Vec<u8>, att: &Attestation) {
    buf.push(parser::TAG_ATTESTATION);

    match att {
        Attestation::Bitcoin { height } => {
            buf.extend_from_slice(&parser::ATT_TAG_BITCOIN);
            let mut payload = Vec::new();
            write_varuint(&mut payload, *height);
            write_varbytes(buf, &payload);
        }
        Attestation::Litecoin { height } => {
            buf.extend_from_slice(&parser::ATT_TAG_LITECOIN);
            let mut payload = Vec::new();
            write_varuint(&mut payload, *height);
            write_varbytes(buf, &payload);
        }
        Attestation::Ethereum { height } => {
            buf.extend_from_slice(&parser::ATT_TAG_ETHEREUM);
            let mut payload = Vec::new();
            write_varuint(&mut payload, *height);
            write_varbytes(buf, &payload);
        }
        Attestation::Pending { uri } => {
            buf.extend_from_slice(&parser::ATT_TAG_PENDING);
            // The pending payload wraps the URI in an inner varbytes
            // (matching the reference python-opentimestamps format).
            let mut payload = Vec::new();
            write_varbytes(&mut payload, uri.as_bytes());
            write_varbytes(buf, &payload);
        }
        Attestation::Unknown { tag, payload } => {
            buf.extend_from_slice(tag);
            write_varbytes(buf, payload);
        }
    }
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

    #[test]
    fn test_write_ots_roundtrip_hello_world() {
        // Parse the fixture, serialize it back, parse again — should match
        let original = std::fs::read("tests/fixtures/hello-world.txt.ots")
            .expect("fixture file missing");
        let ots = parser::parse_ots(&original).expect("failed to parse");

        let serialized = write_ots(&ots);
        let reparsed = parser::parse_ots(&serialized).expect("failed to re-parse");

        // Same hash op, digest, and attestation count
        assert_eq!(ots.hash_op, reparsed.hash_op);
        assert_eq!(ots.file_digest, reparsed.file_digest);
        assert_eq!(
            parser::count_attestations(&ots.timestamp),
            parser::count_attestations(&reparsed.timestamp),
        );
    }

    #[test]
    fn test_write_ots_roundtrip_golden_pending() {
        // This fixture was created by the reference Python ots tool.
        // A byte-identical roundtrip proves our parser and writer both
        // handle the nested varbytes in pending attestations correctly.
        let original = std::fs::read("tests/fixtures/golden-pending.txt.ots")
            .expect("fixture file missing");
        let ots = parser::parse_ots(&original).expect("failed to parse");

        let serialized = write_ots(&ots);

        // Byte-identical output — the strongest roundtrip guarantee
        assert_eq!(
            serialized, original,
            "roundtrip of golden pending fixture should be byte-identical"
        );
    }
}
