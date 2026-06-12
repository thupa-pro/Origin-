# Binary Layout — 256-Byte Proof of Origin

The binary format is a fixed-width 256-byte structure used for embedded provenance (EXIF, HTTP headers, QR codes, binary containers). It is a lossless representation of the text `.origin` format.

## Layout

```
Offset  Size  Field
────────────────────
  0      1    version       (0x01)
  1      9    reserved      (zero-filled; first 2 bytes = LE u16 flags)
  10     8    timestamp     (little-endian u64, unix epoch seconds)
  18     32   hash          (SHA-256 of artifact)
  50     32   pubkey        (Ed25519 compressed public key)
  82     64   signature     (Ed25519 R ‖ S)
  146    110  reserved2     (zero-filled)
────────────────────
        256   total
```

## Rust Representation

```rust
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProofOfOrigin {
    pub version: u8,        // 0x01
    pub reserved: [u8; 9],  // zero-filled; [0..2] = LE u16 flags
    pub timestamp: [u8; 8], // little-endian
    pub hash: [u8; 32],
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub reserved2: [u8; 110],
}
```

## Field Constraints

| Field | Constraint |
|-------|-----------|
| `version` | Must be `0x01`. Any other value is rejected. |
| `reserved` | All 9 bytes must be zero. The first 2 bytes encode a LE u16 flags word for future use. |
| `timestamp` | Decoded as little-endian `u64`. Must be ≤ 253402300799 (year 9999). |
| `hash` | Any 32 bytes. Interpreted as SHA-256. |
| `pubkey` | Any 32 bytes except the Ed25519 identity point (all zeros). |
| `signature` | Any 64 bytes. Passed directly to Ed25519 verification. |
| `reserved2` | All 110 bytes must be zero. Rejected otherwise. |

## Zero-Allocation Verification

Verification reads directly from a `&[u8; 256]`:

```rust
let poo: &ProofOfOrigin = bytemuck::try_from_bytes(poo_bytes)?;
let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&poo.pubkey)?;
let canonical = build_canonical(poo);  // first 4 fields, no trailing newline
let sig = ed25519_dalek::Signature::from_bytes(&poo.signature);
pubkey.verify(&canonical, &sig)?;
```

No heap allocation, no parsing, no intermediate representations.

## Round-Trip with Text Format

The binary format converts losslessly to and from the text `.origin` format:

```
Text .origin                    Binary 256 bytes
─────────────────────────       ────────────────
origin: v1                  →   version = 0x01
hash: sha256:<hex>          →   hash bytes
time: <decimal>             →   timestamp big-endian
key: <base64url>            →   pubkey bytes
sig: <base64url>            →   signature bytes
```

## Reserved Fields

The reserved fields (`reserved` and `reserved2`) are for future protocol extensions:

- `reserved` (1 byte): Reserved for future use. Must be `0x00`.
- `reserved2` (118 bytes): Future field additions. Must be zero in this version.

Applications MUST reject non-zero reserved bytes to ensure forward compatibility.

> Copyright (c) 2026 Origin Protocol. MIT licensed.
