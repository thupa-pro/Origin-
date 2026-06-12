# Changelog

## 1.0.0 — 2026-06-12 — L1 Omega Masterpiece

### New
- **Embedding engine** (`origin-embed`): JPEG (APP15 marker), PNG (iTXt chunk), MP3 (ID3v2 TXXX frame), PDF (incremental update) — binary-level splicing, zero re-encode
- **Adversarial perceptual resilience**: JPEG q=75/50/25 compression tests, FGSM ±5 noise tests
- **50GB sparse file streaming**: OOM-proof hashing via `BufReader` + streaming SHA-256
- **Structural fuzzing**: 100K random PoO arrays, 10K malformed statements — zero panics
- **Zero-allocation proof**: 1M serialization roundtrips with heap-alloc verification
- **SIGINT atomic swap test**: tempfile + rename pattern verified crash-safe
- **WASM/Node.js SDK tests**: alloc, sign, verify, tamper rejection

### Fixed
- `statement.rs:validate_base64url` — decoded byte length not checked, causing `copy_from_slice` panic on corrupted input
- `binary.rs:from_bytes` — rejected non-zero `reserved[0..2]` (flags bytes), contradicting spec

### Changed
- pHash uses fixed-point integer DCT (Q12.19) — bit-identical across ARM, x86, WASM
- SimHash uses deterministic ChaCha20Rng (not random projection from `f32` truncation)
- All crypto comparisons use `subtle::ConstantTimeEq`
- CLI uses `miette` diagnostics, `tempfile` atomic writes, streaming artifact I/O
- Workspace restructured: all crates under `crates/`, SDK under `packages/`

### Security
- Welch t-test: timing side-channel confirmed absent (t=0.424, df=1945)
- Ed25519 `verify_strict` — signature malleability defeated (non-canonical S rejected)
- Deterministic nonces (RFC 8032) — Bellcore attack immune
- `ZeroizeOnDrop` + `Zeroizing` on `SecretKey`
- 67M+ fuzz iterations on `base64_decode`
