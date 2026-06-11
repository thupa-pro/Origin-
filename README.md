# Origin Protocol — Layer 1

Origin is a cryptographic provenance protocol. It lets a signer issue a statement that cryptographically binds a public key, a timestamp, and a digital artifact hash. Anyone can verify that statement independently, with zero infrastructure and zero network access.

**This is Layer 1 (Proof of Origin).** It is the only protocol layer. Everything else (rulebooks, compliance, payments, identity management) is a separate service built on top.

## Quick Start

```bash
# Generate a key pair
cargo run -- generate-key

# Sign an artifact
cargo run -- sign photo.jpg --key origin-secret.key

# Verify
cargo run -- verify photo.jpg --origin photo.jpg.origin

# Bind an identity to a key
cargo run -- id --identity "alice@example.com" --key origin-secret.key
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | VERIFIED / success |
| 1 | FAILED / error |
| 2 | UNATTESTED — no provenance file exists |

## Protocol

One format, one primitive. Full spec in [RFC-0001.md](RFC-0001.md).

```
origin: v1
hash: sha256:<64 hex chars>
time: <unix timestamp>
key: <44 base64url chars>
sig: <88 base64url chars>
```

## Architecture

Origin is **1 protocol + N services**. This repo contains the protocol only.

| Layer | What | Status |
|-------|------|--------|
| L1 | Proof of Origin (this crate) | ✅ v1.0.0 |
| L2–L5 | Rulebooks, compliance, payments, identity | Separate services |

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the system design.

## License

MIT
