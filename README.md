# Origin

Cryptographic provenance for digital artifacts.

## Status: Experimental Alpha

This project is under active design review. The protocol primitive is still
being evaluated. Do not use for production decisions.

## What

Origin produces **signed provenance statements** — 5-line text files that
bind a public key, a timestamp, and an artifact hash cryptographically:

```
origin: v1
hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
time: 1717776000
key: 71RZ3zdJoLcAjfPiis7oxnM3K6IfHpNUrf4Da493VAY=
sig: XyZ9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6...
```

Anyone can verify a statement against an artifact with zero infrastructure
and zero network access. The protocol is offline-first, deterministic, and
self-contained.

## Quickstart

```bash
# Compute an artifact hash
origin hash myfile.tar.gz

# Generate a key pair
origin keygen

# Sign an artifact (creates myfile.origin)
origin sign myfile.tar.gz --key origin-secret.key

# Verify a statement
origin verify myfile.origin myfile.tar.gz

# Audit a statement
origin audit myfile.origin
```

## Commands

| Command | Purpose |
|---|---|
| `origin hash <path>` | Print SHA-256 hash of a file |
| `origin keygen` | Generate Ed25519 key pair |
| `origin sign <path> --key <file>` | Create a provenance statement |
| `origin verify <stmt> <artifact>` | Verify a statement |
| `origin audit <stmt>` | Display statement fields |

## Protocol

See [RFC-0001.md](RFC-0001.md) for the full protocol specification.

## Design

- **One primitive**: signed provenance statement (hash + pubkey + timestamp + sig)
- **No network**: creation and verification are offline
- **No blockchain**: statements are files
- **No database**: the statement is the record
- **No identity system**: the public key is the identity
- **No metadata**: cryptographic only — no notes, tags, or labels

## Non-goals

| Not included | Why |
|---|---|
| Blockchain | Not a ledger |
| Token / cryptocurrency | Not economic |
| Identity verification | Not an identity system |
| Key distribution | Verifier supplies the key |
| Timestamp authority | Timestamps are self-asserted |
| Revocation | Statements are immutable |
| Encryption | Statements are public by design |

## Security

- **Signatures**: Ed25519 via `ed25519-dalek` (audited, constant-time)
- **Hashing**: SHA-256
- **Key erasure**: Secret key zeroized on drop
- **Parser**: Strict validation — no BOM, no CR, no control chars, no null bytes

See [THREAT_MODEL.md](THREAT_MODEL.md) and [TRUST_MODEL.md](TRUST_MODEL.md).

## Build

```bash
cargo build --release
```

Requires Rust 1.85+.

## License

MIT
