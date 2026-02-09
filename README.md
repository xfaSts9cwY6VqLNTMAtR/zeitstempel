# zeitstempel

A command-line tool that proves when a file existed by anchoring it to the Bitcoin blockchain, using the [OpenTimestamps](https://opentimestamps.org/) protocol. You can create timestamps, upgrade them once Bitcoin confirms them, and verify them later — all from a single binary.

*Zeitstempel* is German for "timestamp".

## About

[OpenTimestamps](https://opentimestamps.org/) lets you prove that a file existed at a certain point in time, without trusting any single party. It works by hashing your file and embedding that hash in a Bitcoin transaction. Because Bitcoin blocks are irreversible and publicly auditable, this creates a tamper-proof record of when the file existed.

zeitstempel handles the full lifecycle: stamping (submitting your file's hash to calendar servers), upgrading (fetching the completed Bitcoin proof once the blockchain confirms it), and verifying (replaying the proof chain and checking it against a real Bitcoin block header).

Written in Rust, compiles to a single portable binary. The binary `.ots` format parser, serializer, tree walker, and operation replay engine are all written from scratch — no `opentimestamps` library dependency.

## Usage

```bash
# Create an .ots timestamp proof
zeitstempel stamp document.pdf

# Upgrade a pending proof once the calendar has anchored it to Bitcoin
zeitstempel upgrade document.pdf.ots

# ...or wait (polls every 3 minutes until complete)
zeitstempel upgrade --wait document.pdf.ots

# Verify a file against its .ots proof
zeitstempel verify document.pdf document.pdf.ots

# Display proof structure without network access
zeitstempel info document.pdf.ots

# Show help
zeitstempel --help
```

## Workflow

The typical lifecycle of a timestamp:

1. **Stamp** — `zeitstempel stamp file.pdf` hashes the file, submits the digest to OpenTimestamps calendar servers, and writes a `.ots` proof. The proof is *pending* at this point.
2. **Upgrade** — After a few hours (1-3 Bitcoin blocks), the calendar server has anchored your timestamp to the blockchain. Run `zeitstempel upgrade file.pdf.ots` to fetch the completed proof chain and replace the pending attestation.
3. **Verify** — `zeitstempel verify file.pdf file.pdf.ots` replays the hash operations, checks the result against a Bitcoin block header, and confirms the file existed before that block.

## Output Examples

Successful verification:
```
  Verified! Data existed before Bitcoin block #358391
  Block time: 2015-05-28 15:41:18 UTC
  Block hash: 000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319
  Merkle root match confirmed
```

Upgrade (still pending):
```
Still pending — 2 attestation(s) not yet anchored to Bitcoin.
This typically takes a few hours (1-3 Bitcoin blocks).
Try again later, or use `--wait` to let zeitstempel poll until complete.
```

Proof info (ASCII art tree):
```
File hash: 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340 (SHA256)
│
└── RIPEMD160
    └── prepend(0100000001e482f9d3...)
        └── append(88ac00000000)
            └── SHA256
                └── SHA256
                    └── prepend(a987f716...)
                        └── ...
                            └── Bitcoin block #358391
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
  parser.rs      Binary .ots format parser (magic, LEB128, tree walking, ASCII art)
  writer.rs      Binary .ots format serializer (inverse of parser)
  operations.rs  Hash/append/prepend operation executors
  stamp.rs       Stamp logic (hash file, submit to calendar servers)
  upgrade.rs     Upgrade logic (fetch completed proofs, replace pending)
  verify.rs      Verification logic (replay ops, check against blockchain)
  bitcoin.rs     Blockstream.info API client (mempool.space fallback)
```

### What we wrote from scratch (the educational core)
- Binary .ots format parser and serializer
- LEB128 varuint encoder/decoder
- Timestamp tree walker (for verify, upgrade, and info) with ASCII art rendering
- Attestation parser (Bitcoin, Litecoin, Ethereum, Pending)
- Operation replay engine
- Calendar server interaction (stamp + upgrade)
- UTC timestamp formatter

### What we use crates for
- `sha2`, `sha1`, `ripemd` — Cryptographic hash functions
- `ureq` — Minimal HTTP client (Rust has no stdlib HTTP)
- `serde_json` — JSON parsing for Bitcoin API responses

## Supported Features

- Stamp files via OpenTimestamps calendar servers
- Upgrade pending proofs to Bitcoin-anchored (with `--wait` polling mode)
- Bitcoin attestation verification
- Pending calendar attestation reporting
- Litecoin/Ethereum proofs are recognized and displayed, but not verified (no API client for those chains)
- SHA256, SHA1, RIPEMD160 hash operations
- Append, prepend, reverse, hexlify operations
- Proof tree forks (multiple attestation paths)
- API fallback: Blockstream.info -> mempool.space

## See also

**[zeitstempel-react](https://github.com/xfaSts9cwY6VqLNTMAtR/zeitstempel-react)** -- a TypeScript port of the same core engine, usable as a library in browsers and Node.js. Includes optional React components for verification UI. Same stamp/upgrade/verify lifecycle, same `.ots` format, same calendar servers.

## License

MIT
