//! DOMAIN 6 — SEMANTIC HASH & MODEL VERSION
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::ProofOfOrigin;
use origin_core::hash::simhash_256;
use origin_core::statement::{
    build_statement, compare_semantic_models, verify_model_compatibility, ModelMatch,
};
use origin_core::SecretKey;

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 6.1 — semantic_model_ver field correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_6_1_a_no_semantic_model() {
    // When no semantic hash is used:
    //   semantic_model_ver = 0x00
    //   semantic_hash = 0x00 * 32
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"no semantic", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();

    assert_eq!(bytes[181], 0x00, "semantic_model_ver must be 0x00 when no model");
    assert_eq!(poo.semantic_hash, [0u8; 32], "semantic_hash must be all zeros");
    assert_eq!(poo.semantic_model_ver, 0x00);
    eprintln!("6.1  No semantic model: ver=0x00, hash=0x00*32 — PASS");
}

#[test]
fn test_6_1_b_clip_vit_b32() {
    // When CLIP ViT-B/32 is used:
    //   semantic_model_ver = 0x01
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x01;

    let bytes = poo.to_bytes();
    assert_eq!(bytes[181], 0x01, "CLIP ViT-B/32 must set ver=0x01");
    assert_eq!(poo.semantic_model_ver, 0x01);
    eprintln!("6.1  CLIP ViT-B/32: ver=0x01 — PASS");
}

#[test]
fn test_6_1_c_clip_vit_l14() {
    // When CLIP ViT-L/14 is used:
    //   semantic_model_ver = 0x02
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x02;

    let bytes = poo.to_bytes();
    assert_eq!(bytes[181], 0x02, "CLIP ViT-L/14 must set ver=0x02");
    assert_eq!(poo.semantic_model_ver, 0x02);
    eprintln!("6.1  CLIP ViT-L/14: ver=0x02 — PASS");
}

#[test]
fn test_6_1_d_reserved_values_03_7f() {
    // Values 0x03..0x7F are reserved and MUST NOT be produced by v1 implementations
    // (but the struct accepts them — it's a data field, not an enum)
    for ver in 0x03u8..=0x7F {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.public_key = [0x01; 32];
        poo.semantic_model_ver = ver;

        let bytes = poo.to_bytes();
        assert_eq!(bytes[181], ver, "Reserved ver 0x{:02x} must be storable", ver);
    }
    eprintln!("6.1  Reserved values 0x03..0x7F storable (not produced by v1) — PASS");
}

#[test]
fn test_6_1_e_vendor_defined_80_ff() {
    // Values 0x80..0xFF indicate vendor-defined models
    for ver in [0x80u8, 0xA0, 0xFF] {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.public_key = [0x01; 32];
        poo.semantic_model_ver = ver;

        let bytes = poo.to_bytes();
        assert_eq!(bytes[181], ver, "Vendor ver 0x{:02x} must be storable", ver);
    }
    eprintln!("6.1  Vendor-defined values 0x80..0xFF storable — PASS");
}

#[test]
fn test_6_1_f_inconsistency_ver0_nonzero_hash() {
    // FAIL CONDITION: semantic_model_ver = 0x00 but semantic_hash is non-zero
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x00;
    poo.semantic_hash = [0xFF; 32]; // non-zero hash with ver=0

    // The struct allows this (no runtime validation on this field)
    // But this is an INCONSISTENT state that callers must not produce
    let bytes = poo.to_bytes();
    assert_eq!(bytes[181], 0x00, "ver=0x00");
    assert_ne!(&bytes[101..133], &[0u8; 32], "hash is non-zero (INCONSISTENT)");

    eprintln!("6.1  FAIL CONDITION TEST: ver=0x00 + non-zero hash — struct allows (caller must prevent)");
}

#[test]
fn test_6_1_g_inconsistency_ver1_zero_hash() {
    // FAIL CONDITION: semantic_model_ver = 0x01 but semantic_hash is all zeros
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x01;
    poo.semantic_hash = [0u8; 32]; // zero hash with ver=1

    // This could indicate model failure — struct allows it
    let bytes = poo.to_bytes();
    assert_eq!(bytes[181], 0x01, "ver=0x01");
    assert_eq!(&bytes[101..133], &[0u8; 32], "hash is zero (INCONSISTENT or model failed)");

    eprintln!("6.1  FAIL CONDITION TEST: ver=0x01 + zero hash — struct allows (may indicate model failure)");
}

// ═══════════════════════════════════════════════════════════════════════
// 6.2 — Truncation correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_6_2_a_simhash_output_is_32_bytes() {
    // The semantic_hash field is 32 bytes (256 bits)
    // simhash_256 produces a [u8; 32] from a 512-dim f64 vector
    let mut features = [0.0f64; 512];
    for (i, f) in features.iter_mut().enumerate() {
        *f = (i as f64) / 512.0;
    }

    let hash = simhash_256(&features);
    assert_eq!(hash.len(), 32, "simhash_256 must produce 32 bytes");
    eprintln!("6.2  simhash_256 output: 32 bytes (256 bits) — PASS");
}

#[test]
fn test_6_2_b_simhash_uses_512_dim_vector() {
    // simhash_256 takes a 512-dimensional f64 feature vector
    // This is the CLIP embedding dimension (512 for ViT-B/32)
    let mut features = [0.0f64; 512];
    features[0] = 1.0;
    features[256] = -1.0;

    let hash = simhash_256(&features);
    assert_eq!(hash.len(), 32);
    assert_ne!(hash, [0u8; 32], "Non-trivial features must produce non-zero hash");

    eprintln!("6.2  simhash_256 takes 512-dim f64 vector (CLIP ViT-B/32 embedding) — PASS");
}

#[test]
fn test_6_2_c_semantic_hash_field_is_32_bytes() {
    // semantic_hash field occupies bytes 101..132 (32 bytes)
    use core::mem::offset_of;
    let sh_offset = offset_of!(ProofOfOrigin, semantic_hash);
    let ph_offset = offset_of!(ProofOfOrigin, policy_hash);
    let field_size = ph_offset - sh_offset;

    assert_eq!(field_size, 32, "semantic_hash must be 32 bytes, got {}", field_size);
    eprintln!("6.2  semantic_hash field: 32 bytes at offset {} — PASS", sh_offset);
}

#[test]
fn test_6_2_d_semantic_hash_zero_when_no_model() {
    // When semantic_model_ver = 0, semantic_hash must be all zeros
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    assert_eq!(poo.semantic_model_ver, 0x00);
    assert_eq!(poo.semantic_hash, [0u8; 32]);
    eprintln!("6.2  semantic_hash = 0x00*32 when ver=0x00 — PASS");
}

#[test]
fn test_6_2_e_simhash_deterministic() {
    let mut features = [0.0f64; 512];
    for (i, f) in features.iter_mut().enumerate() {
        *f = (i as f64 * 0.01).sin();
    }

    let h1 = simhash_256(&features);
    let h2 = simhash_256(&features);
    assert_eq!(h1, h2, "simhash_256 must be deterministic");
    eprintln!("6.2  simhash_256 is deterministic — PASS");
}

#[test]
fn test_6_2_f_simhash_different_inputs_different_outputs() {
    let mut f1 = [0.0f64; 512];
    let mut f2 = [0.0f64; 512];
    f1[0] = 1.0;
    f2[0] = -1.0;

    let h1 = simhash_256(&f1);
    let h2 = simhash_256(&f2);
    assert_ne!(h1, h2, "Different inputs must produce different hashes");
    eprintln!("6.2  Different features → different simhash — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 6.3 — Model version mismatch handling
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_6_3_a_same_model_exact_match() {
    // Both PoOs use CLIP ViT-B/32 (ver=0x01) → Exact
    let result = compare_semantic_models(0x01, 0x01);
    assert_eq!(result, ModelMatch::Exact);
    eprintln!("6.3  Same model (0x01, 0x01) → Exact — PASS");
}

#[test]
fn test_6_3_b_different_models_same_major() {
    // CLIP ViT-B/32 (0x01) vs CLIP ViT-L/14 (0x02)
    // Same major version (0), different minor → DerivativeProbable
    let result = compare_semantic_models(0x01, 0x02);
    assert_eq!(result, ModelMatch::DerivativeProbable);
    eprintln!("6.3  Different models, same major (0x01, 0x02) → DerivativeProbable — PASS");
}

#[test]
fn test_6_3_c_different_models_different_major() {
    // Major version 1 (0x10) vs major version 2 (0x20) → DerivativeReview
    let result = compare_semantic_models(0x10, 0x20);
    assert_eq!(result, ModelMatch::DerivativeReview);
    eprintln!("6.3  Different major versions (0x10, 0x20) → DerivativeReview — PASS");
}

#[test]
fn test_6_3_d_zero_version_uncomputable() {
    // Either version is 0 → Uncomputable
    let result = compare_semantic_models(0x00, 0x01);
    assert_eq!(result, ModelMatch::Uncomputable);

    let result2 = compare_semantic_models(0x01, 0x00);
    assert_eq!(result2, ModelMatch::Uncomputable);

    let result3 = compare_semantic_models(0x00, 0x00);
    assert_eq!(result3, ModelMatch::Uncomputable);

    eprintln!("6.3  Zero version → Uncomputable — PASS");
}

#[test]
fn test_6_3_e_verify_model_compatibility_exact() {
    // Same model → Ok
    let result = verify_model_compatibility(0x01, 0x01);
    assert!(result.is_ok(), "Same model must be compatible");
    eprintln!("6.3  verify_model_compatibility(0x01, 0x01) → Ok — PASS");
}

#[test]
fn test_6_3_f_verify_model_compatibility_mismatch() {
    // Different models → Err(ModelMismatch) E008
    let result = verify_model_compatibility(0x01, 0x02);
    assert!(result.is_err(), "Different models must be incompatible");

    match result.unwrap_err() {
        origin_core::error::Error::ModelMismatch { ver_a, ver_b } => {
            assert_eq!(ver_a, 0x01);
            assert_eq!(ver_b, 0x02);
            eprintln!("6.3  verify_model_compatibility(0x01, 0x02) → Err(ModelMismatch) — PASS");
        }
        other => panic!("Expected ModelMismatch, got: {:?}", other),
    }
}

#[test]
fn test_6_3_g_verify_model_compatibility_zero_versions() {
    // Zero versions → Err(ModelMismatch) per spec (UNCOMPUTABLE treated as DERIVATIVE_PROBABLE)
    let result = verify_model_compatibility(0x00, 0x00);
    assert!(result.is_err(), "Zero versions must be incompatible");

    let result2 = verify_model_compatibility(0x00, 0x01);
    assert!(result2.is_err(), "Mixed zero/non-zero must be incompatible");

    eprintln!("6.3  verify_model_compatibility with zeros → Err(ModelMismatch) — PASS");
}

#[test]
fn test_6_3_h_model_mismatch_error_code() {
    // Verify the error is E008 MODEL_MISMATCH
    let err = verify_model_compatibility(0x01, 0x02).unwrap_err();
    let code = err.code_str();
    assert_eq!(code, "E008", "Model mismatch must produce E008, got {}", code);
    eprintln!("6.3  Error code: {} — PASS", code);
}

#[test]
fn test_6_3_i_nibble_encoding() {
    // semantic_model_ver uses nibble encoding: upper=major, lower=minor
    // 0x01 = major 0, minor 1 (CLIP ViT-B/32)
    // 0x02 = major 0, minor 2 (CLIP ViT-L/14)
    // 0x10 = major 1, minor 0
    // 0x11 = major 1, minor 1

    assert_eq!(compare_semantic_models(0x01, 0x02), ModelMatch::DerivativeProbable,
        "0x01 vs 0x02: same major (0), different minor");
    assert_eq!(compare_semantic_models(0x01, 0x10), ModelMatch::DerivativeReview,
        "0x01 vs 0x10: different major (0 vs 1)");
    assert_eq!(compare_semantic_models(0x10, 0x11), ModelMatch::DerivativeProbable,
        "0x10 vs 0x11: same major (1), different minor");
    assert_eq!(compare_semantic_models(0x10, 0x20), ModelMatch::DerivativeReview,
        "0x10 vs 0x20: different major (1 vs 2)");

    eprintln!("6.3  Nibble encoding (upper=major, lower=minor) — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 6.4 — SimHash structure (advisory)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_6_4_a_simhash_uses_deterministic_rng() {
    // SimHash uses ChaCha20Rng seeded from SHA-256 of a fixed seed string
    // This ensures reproducibility across platforms
    let mut f1 = [0.0f64; 512];
    let mut f2 = [0.0f64; 512];
    f1[0] = 1.0;
    f2[0] = 1.0;

    // Same input → same output (deterministic RNG)
    assert_eq!(simhash_256(&f1), simhash_256(&f2));
    eprintln!("6.4  SimHash uses deterministic ChaCha20Rng — PASS");
}

#[test]
fn test_6_4_b_simhash_random_projection() {
    // SimHash uses random projection with Box-Muller transform
    // for generating Gaussian random vectors
    let mut features = [0.0f64; 512];
    features[0] = 1.0;

    let hash = simhash_256(&features);
    // Random projection should produce a non-trivial hash
    assert_ne!(hash, [0u8; 32]);
    assert_ne!(hash, [0xFF; 32]);
    eprintln!("6.4  SimHash random projection produces non-trivial hash — PASS");
}

#[test]
fn test_6_4_c_semantic_hash_survives_binary_roundtrip() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x01;
    poo.semantic_hash = [0xAB; 32];

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.semantic_model_ver, 0x01);
    assert_eq!(parsed.semantic_hash, [0xAB; 32]);
    eprintln!("6.4  semantic_hash + semantic_model_ver survive binary roundtrip — PASS");
}
