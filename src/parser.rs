/// Binary .ots format parser — all byte-level parsing by hand.
///
/// The OpenTimestamps proof format is a compact binary tree:
///   [magic header][version][hash_op][file_digest][timestamp_tree]
///
/// The timestamp tree is recursive: operations chain together, `0xFF`
/// marks forks (multiple paths from one node), and attestations are
/// the leaves (Bitcoin block anchors, pending calendar URIs, etc.).

use std::fmt;

// ── Magic header (31 bytes) ────────────────────────────────────────
/// Every .ots file starts with these exact 31 bytes.
const HEADER_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

// ── Tag bytes for operations ───────────────────────────────────────
const TAG_APPEND:    u8 = 0xf0;
const TAG_PREPEND:   u8 = 0xf1;
const TAG_REVERSE:   u8 = 0xf2;
const TAG_HEXLIFY:   u8 = 0xf3;
const TAG_SHA1:      u8 = 0x02;
const TAG_RIPEMD160: u8 = 0x03;
const TAG_SHA256:    u8 = 0x08;
const TAG_KECCAK256: u8 = 0x67;

// ── Special markers ────────────────────────────────────────────────
const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK:        u8 = 0xff;

// ── Attestation type tags (8 bytes each) ───────────────────────────
const ATT_TAG_BITCOIN:  [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const ATT_TAG_LITECOIN: [u8; 8] = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];
const ATT_TAG_ETHEREUM: [u8; 8] = [0x30, 0xfe, 0x80, 0x87, 0xb5, 0xc7, 0xea, 0xd7];
const ATT_TAG_PENDING:  [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

// ── Data structures ────────────────────────────────────────────────

/// The top-level parsed .ots file.
#[derive(Debug)]
pub struct OtsFile {
    pub hash_op: HashOp,
    pub file_digest: Vec<u8>,
    pub timestamp: Timestamp,
}

/// Which hash algorithm was used to digest the original file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashOp {
    Sha256,
    Sha1,
    Ripemd160,
    Keccak256,
}

impl HashOp {
    /// Expected digest length in bytes for this hash.
    pub fn digest_len(self) -> usize {
        match self {
            HashOp::Sha256 | HashOp::Keccak256 => 32,
            HashOp::Sha1 => 20,
            HashOp::Ripemd160 => 20,
        }
    }
}

impl fmt::Display for HashOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashOp::Sha256    => write!(f, "SHA256"),
            HashOp::Sha1      => write!(f, "SHA1"),
            HashOp::Ripemd160 => write!(f, "RIPEMD160"),
            HashOp::Keccak256 => write!(f, "KECCAK256"),
        }
    }
}

/// A node in the timestamp proof tree.
///
/// Each node carries the current message (hash state), zero or more
/// attestations (leaf proofs), and zero or more (operation, child) pairs
/// representing further branches of the proof.
#[derive(Debug)]
pub struct Timestamp {
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Operation, Timestamp)>,
}

/// A single proof-chain operation.
#[derive(Debug, Clone)]
pub enum Operation {
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Sha256,
    Sha1,
    Ripemd160,
    Keccak256,
    Reverse,
    Hexlify,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Append(data)  => write!(f, "append({})", hex(data)),
            Operation::Prepend(data) => write!(f, "prepend({})", hex(data)),
            Operation::Sha256        => write!(f, "SHA256"),
            Operation::Sha1          => write!(f, "SHA1"),
            Operation::Ripemd160     => write!(f, "RIPEMD160"),
            Operation::Keccak256     => write!(f, "KECCAK256"),
            Operation::Reverse       => write!(f, "reverse"),
            Operation::Hexlify       => write!(f, "hexlify"),
        }
    }
}

/// A leaf attestation — the proof endpoint.
#[derive(Debug, Clone)]
pub enum Attestation {
    Bitcoin  { height: u64 },
    Litecoin { height: u64 },
    Ethereum { height: u64 },
    Pending  { uri: String },
    Unknown  { tag: [u8; 8], payload: Vec<u8> },
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Attestation::Bitcoin  { height } => write!(f, "Bitcoin block #{}", height),
            Attestation::Litecoin { height } => write!(f, "Litecoin block #{}", height),
            Attestation::Ethereum { height } => write!(f, "Ethereum block #{}", height),
            Attestation::Pending  { uri }    => write!(f, "Pending ({})", uri),
            Attestation::Unknown  { tag, .. } => write!(f, "Unknown attestation (tag: {})", hex(tag)),
        }
    }
}

// ── Parser state ───────────────────────────────────────────────────

/// A cursor over raw bytes with a position.
struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Parser { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn peek(&self) -> Result<u8, ParseError> {
        if self.pos < self.data.len() {
            Ok(self.data[self.pos])
        } else {
            Err(ParseError::UnexpectedEof("peek"))
        }
    }

    fn read_byte(&mut self) -> Result<u8, ParseError> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Ok(b)
        } else {
            Err(ParseError::UnexpectedEof("read_byte"))
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Ok(slice)
        } else {
            Err(ParseError::UnexpectedEof("read_bytes"))
        }
    }

    /// Read an unsigned LEB128 varint.
    ///
    /// Each byte contributes 7 data bits; the high bit signals whether
    /// more bytes follow. We cap at 9 bytes (63 bits) to stay in u64.
    fn read_varuint(&mut self) -> Result<u64, ParseError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_byte()?;
            let payload = (byte & 0x7F) as u64;

            // Overflow guard: 9 bytes × 7 bits = 63 bits max
            if shift >= 63 && payload > 1 {
                return Err(ParseError::InvalidData("varuint overflow"));
            }

            value |= payload << shift;
            shift += 7;

            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    /// Read a length-prefixed byte string (varuint length + raw bytes).
    fn read_varbytes(&mut self) -> Result<Vec<u8>, ParseError> {
        let len = self.read_varuint()? as usize;
        if len > 1_048_576 {
            return Err(ParseError::InvalidData("varbytes length > 1MB"));
        }
        Ok(self.read_bytes(len)?.to_vec())
    }
}

// ── Error type ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ParseError {
    BadMagic,
    UnsupportedVersion(u64),
    UnknownHashOp(u8),
    UnexpectedEof(&'static str),
    InvalidData(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BadMagic             => write!(f, "not a valid .ots file (bad magic header)"),
            ParseError::UnsupportedVersion(v) => write!(f, "unsupported .ots version: {}", v),
            ParseError::UnknownHashOp(b)     => write!(f, "unknown hash operation tag: 0x{:02x}", b),
            ParseError::UnexpectedEof(ctx)   => write!(f, "unexpected end of file in {}", ctx),
            ParseError::InvalidData(msg)     => write!(f, "invalid data: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

// ── Public API ─────────────────────────────────────────────────────

/// Parse an .ots file from raw bytes.
pub fn parse_ots(data: &[u8]) -> Result<OtsFile, ParseError> {
    let mut p = Parser::new(data);

    // 1. Validate the 31-byte magic header
    let header = p.read_bytes(HEADER_MAGIC.len())?;
    if header != HEADER_MAGIC {
        return Err(ParseError::BadMagic);
    }

    // 2. Read version (must be 1)
    let version = p.read_varuint()?;
    if version != 1 {
        return Err(ParseError::UnsupportedVersion(version));
    }

    // 3. Read the hash operation used on the original file
    let hash_op = parse_hash_op(p.read_byte()?)?;

    // 4. Read the file digest (length determined by hash)
    let digest_len = hash_op.digest_len();
    let file_digest = p.read_bytes(digest_len)?.to_vec();

    // 5. Parse the recursive timestamp tree
    let timestamp = parse_timestamp(&mut p, &file_digest)?;

    Ok(OtsFile { hash_op, file_digest, timestamp })
}

// ── Internal parsing helpers ───────────────────────────────────────

fn parse_hash_op(tag: u8) -> Result<HashOp, ParseError> {
    match tag {
        TAG_SHA256    => Ok(HashOp::Sha256),
        TAG_SHA1      => Ok(HashOp::Sha1),
        TAG_RIPEMD160 => Ok(HashOp::Ripemd160),
        TAG_KECCAK256 => Ok(HashOp::Keccak256),
        other         => Err(ParseError::UnknownHashOp(other)),
    }
}

/// Parse a timestamp node recursively.
///
/// A timestamp is a sequence of:
///   - `0xFF` forks: parse another timestamp from the same message
///   - `0x00` attestation: leaf node
///   - operation bytes: chain an operation, then parse child timestamp
///
/// Forks come first (each `0xFF` means "another branch starts here"),
/// then the final branch is the implicit continuation (no `0xFF` prefix).
fn parse_timestamp(p: &mut Parser, msg: &[u8]) -> Result<Timestamp, ParseError> {
    let mut attestations = Vec::new();
    let mut ops = Vec::new();

    // Consume fork markers — each one spawns a sibling branch
    while p.remaining() > 0 && p.peek()? == TAG_FORK {
        p.read_byte()?; // consume the 0xFF
        parse_timestamp_branch(p, msg, &mut attestations, &mut ops)?;
    }

    // Parse the final (non-forked) branch
    if p.remaining() > 0 {
        parse_timestamp_branch(p, msg, &mut attestations, &mut ops)?;
    }

    Ok(Timestamp { attestations, ops })
}

/// Parse one branch of a timestamp: either an attestation or an operation chain.
fn parse_timestamp_branch(
    p: &mut Parser,
    msg: &[u8],
    attestations: &mut Vec<Attestation>,
    ops: &mut Vec<(Operation, Timestamp)>,
) -> Result<(), ParseError> {
    let tag = p.peek()?;

    if tag == TAG_ATTESTATION {
        p.read_byte()?; // consume 0x00
        let att = parse_attestation(p)?;
        attestations.push(att);
    } else {
        let op = parse_operation(p)?;
        let new_msg = crate::operations::apply(&op, msg);
        let child = parse_timestamp(p, &new_msg)?;
        ops.push((op, child));
    }

    Ok(())
}

/// Parse a single operation from the byte stream.
fn parse_operation(p: &mut Parser) -> Result<Operation, ParseError> {
    let tag = p.read_byte()?;
    match tag {
        TAG_APPEND    => Ok(Operation::Append(p.read_varbytes()?)),
        TAG_PREPEND   => Ok(Operation::Prepend(p.read_varbytes()?)),
        TAG_REVERSE   => Ok(Operation::Reverse),
        TAG_HEXLIFY   => Ok(Operation::Hexlify),
        TAG_SHA256    => Ok(Operation::Sha256),
        TAG_SHA1      => Ok(Operation::Sha1),
        TAG_RIPEMD160 => Ok(Operation::Ripemd160),
        TAG_KECCAK256 => Ok(Operation::Keccak256),
        other         => Err(ParseError::InvalidData(
            // We can't format a dynamic string here without alloc trickery,
            // so just report it as an unknown op tag generically.
            if other < 0x10 { "unknown low operation tag" }
            else { "unknown operation tag" }
        )),
    }
}

/// Parse an attestation (after the 0x00 marker has been consumed).
///
/// Format: 8-byte type tag + varbytes payload.
fn parse_attestation(p: &mut Parser) -> Result<Attestation, ParseError> {
    let mut tag = [0u8; 8];
    tag.copy_from_slice(p.read_bytes(8)?);

    let payload = p.read_varbytes()?;

    if tag == ATT_TAG_BITCOIN {
        let height = read_varuint_from_slice(&payload)?;
        Ok(Attestation::Bitcoin { height })
    } else if tag == ATT_TAG_LITECOIN {
        let height = read_varuint_from_slice(&payload)?;
        Ok(Attestation::Litecoin { height })
    } else if tag == ATT_TAG_ETHEREUM {
        let height = read_varuint_from_slice(&payload)?;
        Ok(Attestation::Ethereum { height })
    } else if tag == ATT_TAG_PENDING {
        let uri = String::from_utf8(payload)
            .map_err(|_| ParseError::InvalidData("pending attestation URI is not valid UTF-8"))?;
        Ok(Attestation::Pending { uri })
    } else {
        Ok(Attestation::Unknown { tag, payload })
    }
}

/// Read a varuint from a byte slice (used for attestation payloads).
fn read_varuint_from_slice(data: &[u8]) -> Result<u64, ParseError> {
    let mut p = Parser::new(data);
    p.read_varuint()
}

// ── Display helpers ────────────────────────────────────────────────

/// Format bytes as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pretty-print the proof structure (for --info mode).
pub fn print_info(ots: &OtsFile) {
    println!("File hash: {} ({})", hex(&ots.file_digest), ots.hash_op);
    println!();
    print_timestamp(&ots.timestamp, 0);
}

fn print_timestamp(ts: &Timestamp, depth: usize) {
    let indent = "  ".repeat(depth);

    for att in &ts.attestations {
        println!("{}{}", indent, att);
    }

    for (op, child) in &ts.ops {
        println!("{}-> {}", indent, op);
        print_timestamp(child, depth + 1);
    }
}

/// Count total attestations in a timestamp tree (for testing).
pub fn count_attestations(ts: &Timestamp) -> usize {
    let mut count = ts.attestations.len();
    for (_, child) in &ts.ops {
        count += count_attestations(child);
    }
    count
}

// ── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varuint_single_byte() {
        // Values 0-127 are encoded as a single byte
        let mut p = Parser::new(&[0x00]);
        assert_eq!(p.read_varuint().unwrap(), 0);

        let mut p = Parser::new(&[0x01]);
        assert_eq!(p.read_varuint().unwrap(), 1);

        let mut p = Parser::new(&[0x7F]);
        assert_eq!(p.read_varuint().unwrap(), 127);
    }

    #[test]
    fn test_varuint_multi_byte() {
        // 128 = 0b10000000 → encoded as [0x80, 0x01]
        // First byte: 0x80 = 0b10000000 → 7 data bits = 0, continuation = 1
        // Second byte: 0x01 = 0b00000001 → 7 data bits = 1, continuation = 0
        // Result: 0 | (1 << 7) = 128
        let mut p = Parser::new(&[0x80, 0x01]);
        assert_eq!(p.read_varuint().unwrap(), 128);

        // 300 = 0b100101100 → [0xAC, 0x02]
        let mut p = Parser::new(&[0xAC, 0x02]);
        assert_eq!(p.read_varuint().unwrap(), 300);
    }

    #[test]
    fn test_varbytes() {
        // 3 bytes of data: [0xAA, 0xBB, 0xCC]
        let mut p = Parser::new(&[0x03, 0xAA, 0xBB, 0xCC]);
        let bytes = p.read_varbytes().unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_varbytes_empty() {
        let mut p = Parser::new(&[0x00]);
        let bytes = p.read_varbytes().unwrap();
        assert_eq!(bytes, Vec::<u8>::new());
    }

    #[test]
    fn test_hash_op_parsing() {
        assert_eq!(parse_hash_op(0x08).unwrap(), HashOp::Sha256);
        assert_eq!(parse_hash_op(0x02).unwrap(), HashOp::Sha1);
        assert_eq!(parse_hash_op(0x03).unwrap(), HashOp::Ripemd160);
        assert_eq!(parse_hash_op(0x67).unwrap(), HashOp::Keccak256);
        assert!(parse_hash_op(0x42).is_err());
    }

    #[test]
    fn test_hash_op_digest_len() {
        assert_eq!(HashOp::Sha256.digest_len(), 32);
        assert_eq!(HashOp::Sha1.digest_len(), 20);
        assert_eq!(HashOp::Ripemd160.digest_len(), 20);
        assert_eq!(HashOp::Keccak256.digest_len(), 32);
    }

    #[test]
    fn test_hex_formatting() {
        assert_eq!(hex(&[0x00, 0xff, 0x42]), "00ff42");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn test_bad_magic_too_short() {
        // Shorter than the 31-byte header → UnexpectedEof
        let data = b"not an ots file at all";
        assert!(parse_ots(data).is_err());
    }

    #[test]
    fn test_bad_magic_wrong_header() {
        // Exactly 31 bytes but wrong content → BadMagic
        let data = b"0123456789abcdef0123456789abcde";
        assert!(matches!(parse_ots(data), Err(ParseError::BadMagic)));
    }

    #[test]
    fn test_parse_hello_world_fixture() {
        let data = std::fs::read("tests/fixtures/hello-world.txt.ots")
            .expect("fixture file missing — run from project root");
        let ots = parse_ots(&data).expect("failed to parse hello-world.txt.ots");

        // Should be SHA256
        assert_eq!(ots.hash_op, HashOp::Sha256);

        // Digest should be 32 bytes
        assert_eq!(ots.file_digest.len(), 32);

        // Known digest of "Hello World!\n" with SHA256
        assert_eq!(
            hex(&ots.file_digest),
            "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"
        );

        // Should have exactly 1 Bitcoin attestation
        assert_eq!(count_attestations(&ots.timestamp), 1);

        // Find the Bitcoin attestation
        fn find_bitcoin(ts: &Timestamp) -> Option<u64> {
            for att in &ts.attestations {
                if let Attestation::Bitcoin { height } = att {
                    return Some(*height);
                }
            }
            for (_, child) in &ts.ops {
                if let Some(h) = find_bitcoin(child) {
                    return Some(h);
                }
            }
            None
        }

        assert_eq!(find_bitcoin(&ots.timestamp), Some(358391));
    }
}
