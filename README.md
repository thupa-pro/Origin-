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

### Binary Format (256 bytes)

For embedded use (EXIF, HTTP headers, QR codes), the statement also has a fixed-width 256-byte binary encoding:

```
Offset  Size  Field
────────────────────
  0      1    version       (0x01)
  1      1    reserved      (0x00)
  2      8    timestamp     (big-endian u64)
  10     32   hash          (SHA-256)
  42     32   pubkey        (Ed25519)
  74     64   signature     (Ed25519 R ‖ S)
  138    118  reserved      (zero-filled)
────────────────────
        256   total
```

See [LAYOUT.md](docs/LAYOUT.md) for the full spec. Zero-allocation verification via `bytemuck`.

### TypeScript / WASM SDK

The core library compiles to `wasm32-unknown-unknown` with zero imports. A thin TypeScript SDK wraps the WASM binary:

```typescript
import { verify, sign } from "origin-sdk";

const statement = await sign(secretKey, artifact, Date.now());
const valid = await verify(statement, artifact);
```

Located in [`sdk/typescript/`](sdk/typescript/).

### `no_std` + `alloc`

`origin-core` is `#![no_std]` with `extern crate alloc`. It runs on embedded targets and WASM without a standard library. The `std` feature (default) enables OS entropy and file I/O.

## Architecture

Origin is **1 protocol + N services**. This repo contains the protocol only.

| Layer | What | Status |
|-------|------|--------|
| L1 | Proof of Origin (this crate) | ✅ v1.0.0 |
| L1 | WASM C-FFI (origin_verify, origin_sign) | ✅ |
| L1 | TypeScript SDK | ✅ |
| L2–L5 | Rulebooks, compliance, payments, identity | Separate services |

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design, [LAYOUT.md](docs/LAYOUT.md) for binary format, [IDENTITY.md](docs/IDENTITY.md) for identity binding.

## Crate Structure

```
origin-core/          # L1 library (no_std + alloc)
├── src/
│   ├── lib.rs        # Crate root, pub re-exports
│   ├── binary.rs     # 256-byte fixed-width binary layout (bytemuck)
│   ├── crypto.rs     # Ed25519 keygen, sign, verify
│   ├── error.rs      # Error types (manual Display, no thiserror)
│   ├── hash.rs       # SHA-256 hashing
│   ├── statement.rs  # .origin text format parser, builder
│   ├── audit.rs      # Human-readable statement display
│   └── wasm_api.rs   # C-FFI exports for WASM target
└── tests/
    └── negative.rs   # 23 integration tests

origin-cli/           # L1 CLI binary
sdk/typescript/       # TypeScript SDK wrapping origin-core.wasm
```

> Copyright (c) 2026 Origin Protocol. MIT licensed.

## License

MIT
