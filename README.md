# zeitstempel

Standalone OpenTimestamps CLI written in Rust. Parses the binary `.ots` proof format by hand, replays hash operations, and checks results against the Bitcoin blockchain via public APIs. Compiles to a single portable binary.

*Zeitstempel* is German for "timestamp".

**No `opentimestamps` library** — the binary parser, LEB128 decoder, timestamp tree walker, and operation replay engine are all written from scratch.

## Usage

```bash
# Verify a file against its .ots proof
zeitstempel verify hello-world.txt hello-world.txt.ots

# Display proof structure without network access
zeitstempel info proof.ots

# Show help
zeitstempel --help
```

## Output Examples

Successful verification:
```
  Verified! Data existed before Bitcoin block #358391
  Block time: 2015-05-28 15:41:18 UTC
  Block hash: 000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319
  Merkle root match confirmed
```

Proof info:
```
File hash: 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340 (SHA256)

-> RIPEMD160
  -> prepend(0100000001e482f9d3...)
    -> append(88ac00000000)
      -> SHA256
        -> SHA256
          ...
            Bitcoin block #358391
```

## Build

```bash
cargo build --release
# Binary at: target/release/zeitstempel
```

## Test

```bash
cargo test
```

Tests include:
- LEB128 varuint encoding/decoding
- Known-answer hash tests (SHA256, SHA1, RIPEMD160)
- Operation tests (append, prepend, reverse, hexlify)
- Parser tests against real .ots fixtures
- Full Bitcoin verification (requires network)

## Architecture

```
src/
  main.rs        CLI entry point, subcommand routing, output formatting
  parser.rs      Binary .ots format parser (magic, LEB128, tree walking)
  operations.rs  Hash/append/prepend operation executors
  verify.rs      Verification logic (replay ops, check against blockchain)
  bitcoin.rs     Blockstream.info API client (mempool.space fallback)
```

### What we wrote from scratch (the educational core)
- Binary .ots format parser
- LEB128 varuint decoder
- Timestamp tree walker
- Attestation parser (Bitcoin, Litecoin, Ethereum, Pending)
- Operation replay engine
- UTC timestamp formatter

### What we use crates for
- `sha2`, `sha1`, `ripemd` — Cryptographic hash functions
- `ureq` — Minimal HTTP client (Rust has no stdlib HTTP)
- `serde_json` — JSON parsing for Bitcoin API responses

## Supported Features

- Bitcoin attestation verification
- Pending calendar attestation reporting
- Litecoin/Ethereum attestation detection (reported, not verified)
- SHA256, SHA1, RIPEMD160 hash operations
- Append, prepend, reverse, hexlify operations
- Proof tree forks (multiple attestation paths)
- API fallback: Blockstream.info -> mempool.space

## License

MIT
