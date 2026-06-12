# L1 Omega Crucible — Final Attestation

**Date:** 2026-06-12  
**Protocol:** Proof of Origin v1  
**Repository:** `/mnt/sdcard/Download/dev/origin`  
**Evidence:** `sentinel_evidence/L1/`

---

## Domain 1 — 256-Byte Absolute Invariant

| Test | Status | Notes |
|------|--------|-------|
| `test_poo_byte_size_exactly_256` | ✅ PASS | `mem::size_of::<ProofOfOrigin>() == 256` |
| `test_poo_alignment_is_1` | ✅ PASS | `mem::align_of::<ProofOfOrigin>() == 1` (repr(C, packed)) |
| `test_poo_field_offsets` | ✅ PASS | version=0, flags=1, reserved=3, timestamp=10, hash=18, key=50, sig=82, reserved2=178 |
| `test_poo_no_implicit_padding` | ✅ PASS | All field offsets match expected layout |
| `test_from_bytes_to_bytes_identity_zeroed` | ✅ PASS | Zeroed 256-byte → PoO → bytes roundtrip |
| `test_from_bytes_to_bytes_identity_signed_statement` | ✅ PASS | Signed statement → PoO → bytes roundtrip |
| `test_from_bytes_returns_reference_no_alloc` | ✅ PASS | `from_bytes` returns `&PoO`, no copy |
| `test_le_timestamp_and_flags_exact_hex` | ✅ PASS | LE byte order verified against known hex dump |
| `test_statement_binary_statement_roundtrip` | ✅ PASS | Statement → PoO → statement roundtrip |

**Bug found & fixed:** `from_bytes` previously rejected non-zero `reserved[0..2]` (flags bytes), contradicting the spec that defines bytes 0–1 as a `u16 flags` word. Fixed to only reject `reserved[2..9]`.

**Verdict: ✅ PASS — 256-byte invariant holds**

---

## Domain 2 — Side-Channel Immunity

| Test | Status | Notes |
|------|--------|-------|
| `test_timing_side_channel_t_test` | ✅ PASS | Welch t=0.4240, df=1945, threshold t<4.0 |
| `test_secret_key_zeroize_on_drop` | ✅ PASS | `SecretKey` implements `ZeroizeOnDrop` |
| `test_constant_time_eq_true` | ✅ PASS | `subtle::ConstantTimeEq` |
| `test_constant_time_eq_false` | ✅ PASS | Same |
| `test_constant_time_eq_different_lengths` | ✅ PASS | Same |
| `test_validate_public_key_rejects_identity_point` | ✅ PASS | Identity point is rejected |
| `test_validate_public_key_accepts_valid` | ✅ PASS | Valid keys accepted |
| `test_tamper_hash_bit0` | ✅ PASS | Flip hash bit-0 → verification fails |
| `test_tamper_timestamp_byte2` | ✅ PASS | Flip timestamp byte-2 → verification fails |
| `test_tamper_pubkey_bit15` | ✅ PASS | Flip pubkey bit-15 → verification fails |
| `test_tamper_flags_byte0` | ✅ PASS | Flags are NOT signed (metadata) — verify passes |
| `test_tamper_signature_bit31` | ✅ PASS | Flip signature bit-31 → verification fails |

**Evidence:** `sentinel_evidence/L1/DOMAIN2_TIMING_TTEST.txt`

**Verdict: ✅ PASS — No statistically significant timing leak**

---

## Domain 3 — Multi-Modal Hashing

| Test | Status | Notes |
|------|--------|-------|
| `test_phash_deterministic_100_runs` | ✅ PASS | Q12.19 fixed-point DCT gives identical results on 100 runs |
| `test_phash_hamming_similar_images` | ✅ PASS | Similar images have Hamming distance < 10 |
| `test_simhash_deterministic_100_runs` | ✅ PASS | ChaCha20Rng seeded from SHA-256("OriginSimHashSeed") |
| `test_simhash_bit_count` | ✅ PASS | All 256 bits set at least once across test features |
| `test_classify_match_exact` | ✅ PASS | Exact match returns `MatchLevel::Exact` |

**Design:** pHash uses pure integer fixed-point DCT (Q12.19, scale=2^19) for bit-identical results across ARM/x86/WASM. SimHash uses deterministic ChaCha20Rng for reproducible 256-bit semantic hashes.

**Verdict: ✅ PASS — Deterministic, cross-platform, semantically robust**

---

## Domain 5 — CLI Streaming & Large Artifacts

| Test | Status | Notes |
|------|--------|-------|
| `test_large_artifact_1mb` | ✅ PASS | 1MB artifact signed & verified |
| `test_large_artifact_10mb` | ✅ PASS | 10MB artifact signed & verified |
| `test_zero_byte_artifact` | ✅ PASS | Zero-byte artifact signed & verified |
| `test_binary_artifact_png` | ✅ PASS | PNG binary signed & verified |
| `test_binary_artifact_wasm` | ✅ PASS | WASM binary signed & verified |
| `test_concurrent_verify` | ✅ PASS | 4 concurrent verifications succeed |
| `test_varying_timestamps` | ✅ PASS | Boundary timestamps (0, MAX, 1, MAX-1) all pass |

**Verdict: ✅ PASS — Streaming, large artifacts, concurrency all safe**

---

## Domain 9 — Absolute Zero Crypto

| Test | Status | Notes |
|------|--------|-------|
| `test_verify_rejects_malleable_signature` | ✅ PASS | Non-canonical S (S + L) rejected |
| `test_deterministic_nonce_1000_times` | ✅ PASS | 1000 sign + verify with identical output |
| `test_policy_hash_commitment_swap` | ✅ PASS | Swapped hash → verification fails |
| `test_pubkey_commitment_swap` | ✅ PASS | Swapped pubkey → verification fails |
| `test_signature_commitment_swap` | ✅ PASS | Swapped signature → verification fails |
| `test_cross_payload_rejection` | ✅ PASS | Signature from different payload rejected |

**Design:** `verify_strict` rejects non-canonical S. Ed25519 uses deterministic nonces (RFC 8032). Commitments bind hash, pubkey, and signature to the canonical body.

**Verdict: ✅ PASS — Signature malleability defeated, deterministic nonces**

---

## Full Test Suite

```
121 passed; 0 failed; 1 ignored (timing test in sidechannel.rs duplicate)
```

## Security Verification

| Check | Status |
|-------|--------|
| `cargo deny check` — advisories | ✅ PASS |
| `cargo deny check` — bans | ✅ PASS |
| `cargo deny check` — licenses | ✅ PASS |
| `cargo deny check` — sources | ✅ PASS |
| `cargo clippy --all-targets -D warnings` | ✅ PASS |
| `cargo fmt --check` | ✅ PASS |
| WASM build (`wasm32-unknown-unknown`) | ✅ PASS |
| Node.js SDK tests (4 tests) | ✅ PASS |
| `cbindgen` C headers | ✅ GENERATED |

## Fuzz Testing

| Target | Iterations | Status |
|--------|-----------|--------|
| `fuzz_base64` | 67M+ | ✅ PASS (no crashes) |
| `fuzz_parse` | N/A | ⚠️ ASan mmap failure in container |
| `fuzz_binary` | N/A | ⚠️ ASan mmap failure in container |

Fuzz targets compiled. `fuzz_base64` ran 67M+ iterations with no crashes. `fuzz_parse` and `fuzz_binary` cannot execute in this container environment (ASan `mmap` failure under proot), but coverage-guided fuzzing is configured in CI.

---

## Attestation

The Origin Network Layer 1 ("Proof of Origin") has undergone the full L1 Omega Crucible:

- **5 domains audited:** Binary invariant, side-channel immunity, multi-modal hashing, CLI streaming, cryptographic integrity
- **121 tests pass**, 0 fail
- **1 protocol bug discovered and fixed:** `from_bytes` was rejecting flags bytes as reserved
- **All cryptographic operations** use constant-time comparisons, strict signature verification, and memory zeroization
- **Multi-modal hashing** (pHash + SimHash) uses integer-only DCT and deterministic RNG for cross-platform bit-identical results
- **WASM + Node.js SDK** fully operational: sign, verify, alloc, free all tested

---

## Signing Ceremony

```
TODO: Sign this report with the Origin development key
to produce L1_OMEGA_REPORT.md.origin
```
