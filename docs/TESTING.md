# Testing Guide

## Quick Start

```bash
# Prerequisites: Rust 1.75+, project builds successfully
cargo build --workspace

# Run all tests
cargo test --workspace

# Run with detailed output
cargo test --workspace -- --nocapture

# Run specific package
cargo test -p securecomm-shared
cargo test -p securecomm-server
```

## Running Specific Tests

```bash
# By test file
cargo test --package securecomm-shared --test crypto_tests
cargo test --package securecomm-shared --test protocol_tests
cargo test --package securecomm-shared --test edge_case_tests
cargo test --package securecomm-server --test database_tests

# By test name pattern
cargo test sender_keys
cargo test padding
cargo test voice
```

## Test Organization

```
shared/
├── src/
│   └── sender_keys.rs         # Inline tests: chain ratchet, voice encrypt/decrypt
└── tests/
    ├── crypto_tests.rs        # Identity, X3DH, Double Ratchet, padding, BIP39, SSS
    ├── protocol_tests.rs      # MessagePack serialization, protocol messages
    └── edge_case_tests.rs     # Error handling, boundaries, fuzzing

server/
└── tests/
    ├── database_tests.rs      # User storage, offline messages, channels, history
    └── config_tests.rs        # Configuration parsing, defaults
```

## Test Categories

| Category | Count | Purpose |
|----------|-------|---------|
| Crypto primitives | ~50 | Identity, X3DH, Ratchet, Sender Keys, padding |
| Sender Keys | 8 | Chain ratchet, voice encrypt/decrypt, rotation, isolation |
| Protocol | 14 | MessagePack serialization, message formats |
| Edge cases | 13 | Error handling, boundaries, fuzzing |
| Database | 9 | CRUD, channels, history, concurrency |
| Config | 6 | Environment variables, defaults |

## Security-Critical Tests

All cryptographic paths have dedicated tests:

- **Sender Key chain ratchet**: deterministic derivation, encrypt/decrypt, out-of-order, rotation
- **Voice encryption isolation**: 1000 voice frames do NOT advance the text chain (prevents desync)
- **Voice encrypt/decrypt**: stable key, seq-based nonces, correct wire format
- **Size masking**: all 14 buckets (512B - 4MB), randomness verification
- **X3DH handshake**: pre-key bundles, signature verification, invalid rejection
- **Double Ratchet**: forward secrecy, key rotation, message ordering
- **BIP39**: mnemonic generation, validation, seed derivation

## Coverage

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate HTML report
cargo tarpaulin --workspace --out Html --timeout 120

# Console output
cargo tarpaulin --workspace --out Stdout
```

### Estimated Coverage

| Module | Est. Coverage |
|--------|---------------|
| `shared/src/padding.rs` | ~90% |
| `shared/src/sender_keys.rs` | ~85% |
| `shared/src/keys.rs` | ~85% |
| `shared/src/sss.rs` | ~80% |
| `shared/src/recovery.rs` | ~75% |
| `shared/src/x3dh.rs` | ~70% |
| `shared/src/ratchet.rs` | ~65% |
| `server/src/database.rs` | ~70% |

## Debugging Tests

```bash
# Show stdout for passing tests
cargo test --workspace -- --nocapture

# Full backtrace
RUST_BACKTRACE=full cargo test test_name

# Debug logging
RUST_LOG=debug cargo test --workspace

# Sequential execution (avoids DB locks)
cargo test --workspace -- --test-threads=1
```

## Performance Baselines

Tests verify these targets:

| Operation | Target |
|-----------|--------|
| Padding | < 100us |
| MessagePack serialize | < 10us |
| DB write | < 5ms |
| DB query (100 msgs) | < 50ms |
| Key generation | < 10ms |
