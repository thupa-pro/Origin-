# Binary Layout — 256-Byte Proof of Origin

The binary format is a fixed-width 256-byte structure used for embedded provenance
(EXIF, HTTP headers, QR codes, binary containers). It is a lossless representation
of the text `.origin` format.

## Layout

```
Offset  Size  Field                       Description
─────────────────────────────────────────────────────────────────────
  0      1    version                     Protocol version, always 0x01
  1-32   32   public_key                  Raw Ed25519 public key (NOT key_id)
  33-36   4   timestamp                   Big-endian u32 UNIX epoch seconds (UTC)
  37-52  16   tool_hash                   SHA-256(UTF-8 tool string)[0..15]
  53-84  32   content_hash                SHA-256(canonical artifact bytes)
  85-100 16   perceptual_hash             pHash(8 bytes) || SHA-256(content || pHash)[0..7]
  101-132 32  semantic_hash               SimHash (32 zero bytes if semantic_model_ver = 0)
  133-164 32  policy_hash                 Policy commitment hash
  165-180 16  parent_poo_hash             SHA-256(parent PoO)[0..15] (zero-filled if non-derivative)
  181     1    semantic_model_ver          0x00 if no semantic hash
  182-189 8    reserved                   Zero-filled (future use)
  190-191 2    flags                      Big-endian u16 bitmask
  192-255 64   signature                  Ed25519ph signature over bytes 0–191
─────────────────────────────────────────────────────────────────────
                                   256   total
```

## Signature Modes

### Single-Author (default)

When the `MULTI_AUTHOR` flag is NOT set, the signature field (bytes 192–255)
contains a standard 64-byte Ed25519ph (pre-hash) signature.

The signature covers exactly **bytes 0–191** (192 bytes: all fields except the
signature itself). The SHA-512 pre-hash is computed over this 192-byte prefix
with context `"Origin-Network-v1"` per RFC 8032 §5.1.

### Multi-Author (BLS aggregate)

When the `MULTI_AUTHOR` flag (0x0010) is set, the signature field contains a
48-byte BLS aggregate signature (BLS12-381, min-sig variant) followed by 16
zero padding bytes:

| Offset | Size | Field |
|--------|------|-------|
| 192–239 | 48  | BLS aggregate signature (G1 point) |
| 240–255 | 16  | Zero padding (must be zero) |

Verification requires the set of all signers' BLS public keys (96 bytes each,
G2 points), aggregated via `blst::min_sig::AggregatePublicKey`. The aggregate
signature is verified against the same 192-byte prefix and the aggregated
public key using DST `"ORIGIN_BLS_SIG_V1"`.

## Rust Representation

```rust
#[repr(C, packed)]
pub struct ProofOfOrigin {
    pub version: u8,
    pub public_key: [u8; 32],
    pub timestamp: [u8; 4],
    pub tool_hash: [u8; 16],
    pub content_hash: [u8; 32],
    pub perceptual_hash: [u8; 16],
    pub semantic_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub parent_poo_hash: [u8; 16],
    pub semantic_model_ver: u8,
    pub reserved: [u8; 8],
    pub flags_be: [u8; 2],
    pub signature: [u8; 64],
}
```

## Field Constraints

| Field | Constraint |
|-------|------------|
| `version` | Must be `0x01`. Other values accepted best-effort (E006 warning). |
| `public_key` | Any 32 bytes except the Ed25519 identity point (all zeros). |
| `timestamp` | Decoded as big-endian `u32`. UNIX epoch seconds (UTC). |
| `tool_hash` | SHA-256(tool_string)[0..15]. |
| `content_hash` | SHA-256(artifact bytes). |
| `perceptual_hash` | Bytes 0–7: 64-bit pHash (big-endian). Bytes 8–15: SHA-256(content_hash ‖ pHash)[0..8]. |
| `semantic_hash` | 256-bit SimHash, or all zeros when `semantic_model_ver` = 0. |
| `policy_hash` | SHA-256(policy document). |
| `parent_poo_hash` | SHA-256(parent PoO)[0..15], or all zeros for non-derivatives. |
| `semantic_model_ver` | `0x00` if no semantic hash; upper nibble = major version, lower = minor. |
| `reserved` | All 8 bytes must be zero. Rejected otherwise. |
| `flags` | Big-endian `u16`. Bits 8–15 must be zero in v1. |
| `signature` | 64-byte Ed25519ph (pre-hash) signature. |

## Flag Bitmask Definitions

| Bit | Constant | Meaning |
|-----|----------|---------|
| 0x0001 | `HW_ATTESTED` | Signature created inside a TEE |
| 0x0002 | `REVOCABLE` | Creator permits IVG-based revocation |
| 0x0004 | `ZK_READY` | ZK proof available for this artifact |
| 0x0008 | `PQ_READY` | ML-DSA key registered for post-quantum migration |
| 0x0010 | `MULTI_AUTHOR` | BLS aggregate signature (48-byte BLS sig + 16 zero bytes) |
| 0x0020 | `PRIVATE_POLICY` | Policy content is encrypted |
| 0x0040 | `OFFLINE_BUNDLE` | Offline bundle available for this artifact |
| 0x0080 | `AI_GENERATED` | Human Content Score < 0.5 |

> **Note on `AI_GENERATED` (0x0080):** The automatic triggering of this flag
> based on HCS (Human Content Score) < 0.5 is a **service-layer concern**,
> not enforced at the L1 protocol core. The L1 core stores the flag as given
> by the caller. HCS computation and automatic flag setting should be
> implemented in the application layer (e.g., origin-cli, origin-sdk).

## Zero-Allocation Verification

Verification reads directly from a `&[u8; 256]` using `bytemuck::try_from_bytes`:

```rust
let poo: &ProofOfOrigin = bytemuck::try_from_bytes(poo_bytes)?;
let prefix = poo.signed_prefix(); // bytes 0..191
let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&poo.public_key)?;
let sig = ed25519_dalek::ed25519::Signature::from_bytes(&poo.signature);
pubkey.verify_prehashed(sha512(&prefix), Some(b"Origin-Network-v1"), &sig)?;
```

No heap allocation, no parsing, no intermediate representations.

## Round-Trip with Text Format

The binary format converts losslessly to and from the text `.origin` format:

```
Text .origin                    Binary 256 bytes
─────────────────────────       ────────────────
origin: v1                  →   version = 0x01
hash: sha256:<hex>          →   content_hash
time: <decimal>             →   timestamp big-endian
key: <base64url>            →   public_key bytes
sig: <base64url>            →   signature bytes
```

Additional binary fields (tool_hash, perceptual_hash, semantic_hash, policy_hash,
parent_poo_hash, semantic_model_ver, reserved, flags) have no direct text
representation and are set to defaults on round-trip conversion.

## Reserved Fields

The `reserved` field (8 bytes at offsets 182–189) is for future protocol extensions.
Applications MUST reject non-zero reserved bytes to ensure forward compatibility.

## Design Rationale

The original specification draft defined a candidate layout that summed to 295 bytes
while claiming a 256-byte total. The RESERVED field was reduced from 47 to 8 bytes
to satisfy the fixed 256-byte constraint required for QR Code Version 10 embedding
(344 base64url characters fits within QR V10's 429-character capacity).

> Copyright (c) 2026 Origin Protocol. MIT licensed.
