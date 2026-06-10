# Architecture

Origin is a minimal digital provenance protocol. The entire system is two Rust crates:

## Crate Layout

```
origin/
├── origin-core/          # Library crate — protocol logic
│   ├── src/
│   │   ├── lib.rs        # Public API, re-exports, verify_consistency()
│   │   ├── statement.rs  # Parser, canonical body, sign/verify
│   │   ├── crypto.rs     # Ed25519 key types, sign, verify, generate
│   │   ├── hash.rs       # SHA-256 hashing (hash_bytes, hash_hex, hash_file)
│   │   ├── error.rs      # Error types (Format, Crypto, HashMismatch, Io)
│   │   └── audit.rs      # Human-readable statement dump
│   └── tests/            # 87 integration + proptest
│       ├── deterministic.rs  # Determinism guarantees
│       ├── adversarial.rs    # Attack scenarios
│       ├── negative.rs       # Malformed input parsing
│       └── tamper.rs         # Tamper detection
│
├── origin-cli/           # CLI binary — clap-based commands
│   └── src/main.rs       # hash, keygen, sign, verify, audit
│
├── docs/                 # Protocol documentation
├── examples/             # Shell scripts for signing workflows
├── completions/          # Shell completion files
└── .github/workflows/   # CI + release automation
```

## Data Flow

```
Sign:
  artifact ──► SHA-256 ──► hash ──┐
  secret key ──► Ed25519 ──► sig ──┤
  timestamp   ─────────────────────┤
  parent hash (optional) ──────────┤
                                   ▼
                            provenance statement (.origin)

Verify:
  .origin file ──► parse ──► extract hash + key + sig
  artifact ──► SHA-256 ──► compare hash ──► verify Ed25519 sig
```

## Key Design Decisions

- **Single primitive**: One statement type (provenance), one crypto (Ed25519), one encoding (text)
- **Offline-first**: No network, no database, no blockchain, no identity
- **Deterministic**: Same inputs always produce the same output (no random nonces)
- **Canonical body**: Only origin, type, [parent], hash, key are signed — timestamp and sig are excluded

See [docs/adr/README.md](docs/adr/README.md) for all architecture decision records.
