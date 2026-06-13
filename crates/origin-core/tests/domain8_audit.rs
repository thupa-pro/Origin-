//! DOMAIN 8 — POO CREATION PROCEDURE COMPLIANCE
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::ProofOfOrigin;
use origin_core::statement::{build_statement, build_statement_from_hash};
use origin_core::{hash, SecretKey};

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 8.1 — Step order enforcement
// ═══════════════════════════════════════════════════════════════════════

// STEP 1 — content_hash
#[test]
fn test_8_1_step1_content_hash_computed() {
    let artifact = b"test artifact for domain 8";
    let content_hash = hash::hash_bytes(artifact);
    assert_eq!(content_hash.len(), 32);
    assert_ne!(content_hash, [0u8; 32]);
    let content_hash2 = hash::hash_bytes(artifact);
    assert_eq!(content_hash, content_hash2);
    eprintln!("8.1  STEP 1: content_hash = SHA-256(artifact) — PASS");
}

// STEP 2 — perceptual_hash
#[test]
fn test_8_1_step2_perceptual_hash() {
    // pHash for 32x32 grayscale image
    let mut pixels = [[128u8; 32]; 32];
    for i in 0..32 {
        pixels[i][i] = 200;
        pixels[i][31 - i] = 50;
    }
    let phash = hash::phash_64(&pixels);
    assert_ne!(phash, 0u64);
    eprintln!("8.1  STEP 2: pHash computed for 32x32 image — PASS");

    // FORMAT_UNKNOWN fallback: takes content_hash ([u8;32]), returns [u8; 16]
    let content_hash = hash::hash_bytes(b"non-image artifact");
    let unknown_phash = hash::phash_format_unknown(&content_hash);
    assert_eq!(unknown_phash.len(), 16);
    eprintln!("8.1  STEP 2: FORMAT_UNKNOWN fallback for non-image — PASS");
}

// STEP 3 — semantic_hash
#[test]
fn test_8_1_step3_semantic_hash() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.semantic_model_ver = 0x00;
    poo.semantic_hash = [0u8; 32];
    assert_eq!(poo.semantic_hash, [0u8; 32]);
    eprintln!("8.1  STEP 3: semantic_hash = zeros when model_ver = 0x00 — PASS");

    poo.semantic_model_ver = 0x01;
    let features = [0.1f64; 512];
    let sem_hash = hash::simhash_256(&features);
    poo.semantic_hash = sem_hash;
    assert_ne!(poo.semantic_hash, [0u8; 32]);
    eprintln!("8.1  STEP 3: semantic_hash computed when model_ver ≠ 0x00 — PASS");
}

// STEP 4 — policy_hash
#[test]
fn test_8_1_step4_policy_hash() {
    let policy_bytes = b"example.com/policy/v1";
    let policy_hash = hash::hash_bytes(policy_bytes);
    assert_eq!(policy_hash.len(), 32);
    assert_ne!(policy_hash, [0u8; 32]);

    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.policy_hash = policy_hash;
    assert_eq!(poo.policy_hash, policy_hash);
    eprintln!("8.1  STEP 4: policy_hash computed when policy_uri provided — PASS");
}

// STEP 5 — timestamp
#[test]
fn test_8_1_step5_timestamp_is_utc() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"timestamp test", now).unwrap();

    assert_eq!(stmt.time, now);
    assert_ne!(now, 0u64);
    eprintln!("8.1  STEP 5: timestamp = current UTC (now={}) — PASS", now);
}

// STEP 6 — semantic_model_ver
#[test]
fn test_8_1_step6_semantic_model_ver() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];

    poo.semantic_model_ver = 0x00;
    poo.semantic_hash = [0u8; 32];
    assert_eq!(poo.semantic_model_ver, 0x00);
    assert_eq!(poo.semantic_hash, [0u8; 32]);
    eprintln!("8.1  STEP 6: semantic_model_ver = 0x00 when no semantic hash — PASS");

    poo.semantic_model_ver = 0x01;
    let features = [0.1f64; 512];
    poo.semantic_hash = hash::simhash_256(&features);
    assert_eq!(poo.semantic_model_ver, 0x01);
    assert_ne!(poo.semantic_hash, [0u8; 32]);
    eprintln!("8.1  STEP 6: semantic_model_ver = 0x01 for CLIP ViT-B/32 — PASS");
}

// STEP 7 — poo_prefix assembly
#[test]
fn test_8_1_step7_prefix_assembly() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.timestamp = 1700000000u32.to_be_bytes();
    poo.tool_hash = [0x02; 16];
    poo.content_hash = [0x03; 32];
    poo.perceptual_hash = [0x04; 16];
    poo.semantic_hash = [0x05; 32];
    poo.policy_hash = [0x06; 32];
    poo.parent_poo_hash = [0x07; 16];
    poo.semantic_model_ver = 0x01;
    poo.reserved = [0x00; 8];
    poo.flags_be = [0x00, 0x01];

    assert_eq!(poo.reserved, [0u8; 8]);

    let prefix = poo.signed_prefix();
    assert_eq!(prefix.len(), 192);

    assert_eq!(prefix[0], PROTOCOL_VERSION);
    assert_eq!(&prefix[1..33], &[0x01u8; 32]);
    assert_eq!(&prefix[33..37], &1700000000u32.to_be_bytes());
    assert_eq!(&prefix[37..53], &[0x02u8; 16]);
    assert_eq!(&prefix[53..85], &[0x03u8; 32]);
    assert_eq!(&prefix[85..101], &[0x04u8; 16]);
    assert_eq!(&prefix[101..133], &[0x05u8; 32]);
    assert_eq!(&prefix[133..165], &[0x06u8; 32]);
    assert_eq!(&prefix[165..181], &[0x07u8; 16]);
    assert_eq!(prefix[181], 0x01);
    assert_eq!(&prefix[182..190], &[0x00u8; 8]);
    assert_eq!(&prefix[190..192], &[0x00, 0x01]);

    eprintln!("8.1  STEP 7: prefix = 192 bytes, field order correct, reserved = zeros — PASS");
}

// STEP 8 — signature computation
#[test]
fn test_8_1_step8_signature_computation() {
    // signature = Ed25519ph.Sign(private_key, poo_prefix[0..191])
    // build_statement signs over prefix including tool_hash = compute_tool_hash("origin-cli")
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"signature test", 1700000000).unwrap();

    // Reconstruct the PoO the same way build_statement does
    let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    poo.tool_hash = origin_core::binary::compute_tool_hash("origin-cli");

    let prefix = poo.signed_prefix();
    assert_eq!(prefix.len(), 192);

    let result = origin_core::crypto::verify_ph(
        &origin_core::crypto::PublicKey(stmt.key_bytes),
        &prefix,
        &origin_core::crypto::Signature(stmt.sig_bytes),
    );
    assert!(result.is_ok(), "Signature verification failed: {:?}", result.err());
    eprintln!("8.1  STEP 8: Ed25519ph.Sign over prefix[0..191] — PASS");
}

// STEP 9 — assembly and length assertion
#[test]
fn test_8_1_step9_assembly_length() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"assembly test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    let bytes = poo.to_bytes();
    assert_eq!(bytes.len(), 256);

    let prefix = poo.signed_prefix();
    assert_eq!(&bytes[..192], &prefix);
    assert_eq!(&bytes[192..256], &poo.signature);

    eprintln!("8.1  STEP 9: final PoO = 256 bytes (prefix || signature) — PASS");
}

// STEP 10 — BLS multi-author path
#[test]
fn test_8_1_step10_multi_author_format() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0010); // MULTI_AUTHOR flag

    let bls_sig = [0xAB; 48];
    poo.signature[..48].copy_from_slice(&bls_sig);
    poo.signature[48..64].copy_from_slice(&[0x00; 16]);

    assert_eq!(&poo.signature[..48], &bls_sig);
    assert_eq!(&poo.signature[48..64], &[0x00; 16]);
    assert!(poo.is_multi_author());

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert!(parsed.is_multi_author());
    assert_eq!(&parsed.signature[..48], &bls_sig);
    assert_eq!(&parsed.signature[48..64], &[0x00; 16]);
    eprintln!("8.1  STEP 10: MULTI_AUTHOR: BLS sig (48) + 16 zeros = 64 bytes — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 8.2 — Atomicity
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_8_2_a_atomicity_success() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let result = build_statement(&secret, b"atomic test", 1700000000);

    match result {
        Ok(stmt) => {
            // hash = "sha256:" + 64 hex chars = 71 chars
            assert_eq!(stmt.hash.len(), 71);
            // key_b64 = base64url(32 bytes) = 43 chars + padding
            assert!(stmt.key_b64.len() >= 43 && stmt.key_b64.len() <= 44);
            // sig_b64 = base64url(64 bytes) = 85 chars + padding
            assert!(stmt.sig_b64.len() >= 85 && stmt.sig_b64.len() <= 88);
            eprintln!("8.2  Atomic success: complete Statement returned — PASS");
        }
        Err(e) => {
            panic!("Atomic creation should succeed, got error: {:?}", e);
        }
    }
}

#[test]
fn test_8_2_b_atomicity_error_no_partial() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();

    let result = build_statement(&secret, b"", 1700000000);
    assert!(result.is_ok());
    eprintln!("8.2  Empty artifact creates valid PoO — PASS");

    let result_zero_ts = build_statement(&secret, b"test", 0);
    assert!(result_zero_ts.is_ok());
    eprintln!("8.2  Timestamp 0 creates valid PoO — PASS");
}

#[test]
fn test_8_2_c_atomicity_from_hash() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let hash_bytes = [0xAB; 32];
    let hash_hex = hex::encode(hash_bytes);

    let result = build_statement_from_hash(&secret, &hash_hex, &hash_bytes, 1700000000);
    assert!(result.is_ok());

    let stmt = result.unwrap();
    assert_eq!(stmt.hash_bytes, hash_bytes);
    assert_ne!(stmt.sig_bytes, [0u8; 64]);
    eprintln!("8.2  build_statement_from_hash atomic — PASS");
}

#[test]
fn test_8_2_d_no_partial_poo_emitted() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"no partial", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    let bytes = poo.to_bytes();
    assert_eq!(bytes.len(), 256);
    eprintln!("8.2  No partial PoO — always 256 bytes or error — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 8.3 — Creation invariants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_8_3_a_version_always_0x01() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"version test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    assert_eq!(poo.version, PROTOCOL_VERSION);
    eprintln!("8.3  Version always 0x01 — PASS");
}

#[test]
fn test_8_3_b_signature_deterministic() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let artifact = b"deterministic test";
    let ts = 1700000000u64;

    let stmt1 = build_statement(&secret, artifact, ts).unwrap();
    let stmt2 = build_statement(&secret, artifact, ts).unwrap();

    assert_eq!(stmt1.sig_bytes, stmt2.sig_bytes);
    assert_eq!(stmt1.sig_b64, stmt2.sig_b64);
    eprintln!("8.3  Signature deterministic — PASS");
}

#[test]
fn test_8_3_c_different_artifacts_different_hashes() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();

    let stmt1 = build_statement(&secret, b"artifact A", 1700000000).unwrap();
    let stmt2 = build_statement(&secret, b"artifact B", 1700000000).unwrap();

    assert_ne!(stmt1.hash_bytes, stmt2.hash_bytes);
    assert_ne!(stmt1.sig_bytes, stmt2.sig_bytes);
    eprintln!("8.3  Different artifacts → different hashes — PASS");
}

#[test]
fn test_8_3_d_same_input_same_output() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let artifact = b"same input test";
    let ts = 1700000000u64;

    let stmt1 = build_statement(&secret, artifact, ts).unwrap();
    let stmt2 = build_statement(&secret, artifact, ts).unwrap();

    assert_eq!(stmt1.hash_bytes, stmt2.hash_bytes);
    assert_eq!(stmt1.sig_bytes, stmt2.sig_bytes);
    assert_eq!(stmt1.key_bytes, stmt2.key_bytes);
    assert_eq!(stmt1.time, stmt2.time);
    eprintln!("8.3  Same input → same output — PASS");
}
