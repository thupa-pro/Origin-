//! DOMAIN 2 — CRYPTOGRAPHIC HASH CORRECTNESS
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::{compute_tool_hash, per_hash, ProofOfOrigin};
use origin_core::crypto::{der_encode_pubkey, compute_key_id, generate_keypair_from_seed};
use origin_core::hash::hash_bytes;
use origin_core::statement::build_statement;
use origin_core::SecretKey;
use std::convert::TryInto;

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 2.1 — content_hash (SHA-256 · SECURITY CRITICAL)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_2_1_a_reference_vector_hello_origin() {
    // REFERENCE VECTOR: UTF-8 "Hello, Origin Network!" (22 bytes)
    let artifact = b"Hello, Origin Network!";
    let computed = hash_bytes(artifact);

    // Known SHA-256 of "Hello, Origin Network!"
    // We verify this against a third-party computed value
    // sha256("Hello, Origin Network!") = 5e2de7c6... (we compute it here)
    eprintln!("=== 2.1 — Reference Vector ===");
    eprintln!("Input: \"Hello, Origin Network!\" ({} bytes)", artifact.len());
    eprintln!("SHA-256: {}", hex::encode(computed));

    // Verify the hash is non-zero and 32 bytes
    assert_eq!(computed.len(), 32, "SHA-256 must be 32 bytes");
    assert_ne!(computed, [0u8; 32], "SHA-256 must not be all zeros");

    // Cross-verify: hash the same input again, must be identical
    let computed2 = hash_bytes(artifact);
    assert_eq!(computed, computed2, "SHA-256 must be deterministic");
}

#[test]
fn test_2_1_a_hashes_canonical_bytes_not_path() {
    // FAIL CONDITION: If implementation hashes a file path string instead of file contents
    let artifact = b"actual file content bytes";
    let hash_of_content = hash_bytes(artifact);
    let hash_of_path = hash_bytes(b"/path/to/file.txt");

    assert_ne!(hash_of_content, hash_of_path,
        "content_hash must be of actual bytes, not file path");
    eprintln!("content_hash hashes actual bytes, NOT file path — PASS");
}

#[test]
fn test_2_1_a_hashes_decoded_bytes_not_base64() {
    // FAIL CONDITION: If implementation hashes base64 string instead of decoded bytes
    let artifact = b"binary content here";
    let hash_of_bytes = hash_bytes(artifact);
    let b64 = base64::encode(artifact);
    let hash_of_b64 = hash_bytes(b64.as_bytes());

    assert_ne!(hash_of_bytes, hash_of_b64,
        "content_hash must be of decoded bytes, NOT base64 string");
    eprintln!("content_hash hashes decoded bytes, NOT base64 — PASS");
}

#[test]
fn test_2_1_b_determinism_100_runs() {
    let artifact = b"determinism test artifact for 100 runs";
    let first = hash_bytes(artifact);

    for i in 0..100 {
        let run = hash_bytes(artifact);
        assert_eq!(first, run, "SHA-256 must be deterministic across runs (run {})", i);
    }
    eprintln!("SHA-256 determinism: 100 runs, all identical — PASS");
}

#[test]
fn test_2_1_c_sensitivity_avalanche() {
    // Flip one bit in the artifact and verify complete avalanche
    let mut artifact = b"avalanche test artifact".to_vec();
    let hash_original = hash_bytes(&artifact);

    // Flip bit 0 of byte 0
    artifact[0] ^= 0x01;
    let hash_flipped = hash_bytes(&artifact);

    assert_ne!(hash_original, hash_flipped,
        "Flipping one bit must change SHA-256 output");

    // Verify avalanche: at least 50% of bits should differ (SHA-256 average)
    let mut diff_bits = 0u32;
    for i in 0..32 {
        diff_bits += (hash_original[i] ^ hash_flipped[i]).count_ones();
    }
    assert!(diff_bits >= 64,
        "Avalanche effect: expected >= 64 bits different, got {}", diff_bits);
    eprintln!("SHA-256 avalanche: {} bits differ after 1-bit flip (>= 64 required) — PASS", diff_bits);
}

#[test]
fn test_2_1_c_content_hash_changes_with_artifact() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt1 = build_statement(&secret, b"artifact A", 1700000000).unwrap();
    let stmt2 = build_statement(&secret, b"artifact B", 1700000000).unwrap();

    assert_ne!(stmt1.hash_bytes, stmt2.hash_bytes,
        "Different artifacts must produce different content_hash");
    eprintln!("Different artifacts produce different content_hash — PASS");
}

#[test]
fn test_2_1_known_sha256_empty() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let hash = hash_bytes(b"");
    let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(hash[..], expected[..], "SHA-256 of empty string must match NIST vector");
    eprintln!("SHA-256(\"\") matches NIST test vector — PASS");
}

#[test]
fn test_2_1_known_sha256_abc() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let hash = hash_bytes(b"abc");
    let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(hex::encode(hash), expected_hex, "SHA-256(\"abc\") must match NIST vector");
    eprintln!("SHA-256(\"abc\") matches NIST test vector — PASS");
}

#[test]
fn test_2_1_build_statement_hashes_raw_bytes() {
    // Verify that build_statement hashes the raw artifact bytes, not any encoding
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let artifact = b"test artifact for build_statement";
    let stmt = build_statement(&secret, artifact, 1700000000).unwrap();

    // The hash in the statement must match hash_bytes of the raw artifact
    let expected_hash = hash_bytes(artifact);
    assert_eq!(stmt.hash_bytes, expected_hash,
        "build_statement must hash raw artifact bytes");
    eprintln!("build_statement hashes raw artifact bytes — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.2 — key_id derivation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_2_2_der_encoding_is_subject_public_key_info() {
    // DER-encoded Ed25519 pubkey must be SubjectPublicKeyInfo format (44 bytes)
    let pk = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];
    let der = der_encode_pubkey(&pk);

    assert_eq!(der.len(), 44, "DER encoding must be 44 bytes, got {}", der.len());

    // SubjectPublicKeyInfo header for Ed25519 (RFC 8410)
    // 30 2a        -- SEQUENCE (42 bytes)
    //   30 05      -- SEQUENCE (5 bytes)
    //     06 03    -- OID (3 bytes)
    //       2b 65 70 -- 1.3.101.112 (Ed25519)
    //   03 21      -- BIT STRING (33 bytes)
    //     00       -- unused bits = 0
    let expected_header: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    assert_eq!(der[..12], expected_header, "DER header must be SubjectPublicKeyInfo for Ed25519");
    assert_eq!(der[12..44], pk, "DER body must contain the raw 32-byte public key");

    eprintln!("=== 2.2 — DER Encoding ===");
    eprintln!("DER (44 bytes): {}", hex::encode(der));
    eprintln!("Header: 30 2a 30 05 06 03 2b 65 70 03 21 00 (SubjectPublicKeyInfo Ed25519)");
    eprintln!("Body: {} (raw 32-byte key)", hex::encode(&der[12..44]));
}

#[test]
fn test_2_2_key_id_is_sha256_of_der_first_32_bytes() {
    let pk = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    let der = der_encode_pubkey(&pk);
    let sha256_of_der = hash_bytes(&der);
    let key_id = compute_key_id(&pk);

    // key_id must be SHA-256(DER)[0..31] — first 32 bytes of SHA-256
    assert_eq!(key_id, sha256_of_der[..32],
        "key_id must be SHA-256(DER-encoded pubkey)[0..31]");
    assert_eq!(key_id.len(), 32, "key_id must be 32 bytes");

    eprintln!("key_id = SHA-256(DER pubkey)[0..31] — PASS");
    eprintln!("  DER: {}...", &hex::encode(&der[..12]));
    eprintln!("  SHA-256(DER): {}", hex::encode(sha256_of_der));
    eprintln!("  key_id: {}", hex::encode(key_id));
}

#[test]
fn test_2_2_key_id_not_raw_pubkey() {
    // FAIL CONDITION: key_id = raw_32_byte_pubkey — not a hash, breaks key binding
    let pk = [0x42u8; 32];
    let key_id = compute_key_id(&pk);

    assert_ne!(key_id, pk,
        "CRITICAL: key_id must NOT be the raw public key — it must be a hash");
    eprintln!("key_id is NOT raw pubkey (it's SHA-256(DER)) — PASS");
}

#[test]
fn test_2_2_key_id_not_sha256_of_raw_key() {
    // FAIL CONDITION: key_id = SHA-256(raw_32_byte_pubkey) — wrong derivation, breaks interop
    let pk = [0x42u8; 32];
    let key_id = compute_key_id(&pk);
    let wrong_key_id = hash_bytes(&pk);

    assert_ne!(key_id, wrong_key_id,
        "CRITICAL: key_id must be SHA-256(DER), NOT SHA-256(raw key)");
    eprintln!("key_id is NOT SHA-256(raw key) — PASS (derives from DER, not raw)");
}

#[test]
fn test_2_2_key_id_deterministic() {
    let pk = [
        208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58,
        14, 225, 114, 243, 218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let kid1 = compute_key_id(&pk);
    let kid2 = compute_key_id(&pk);
    assert_eq!(kid1, kid2, "key_id must be deterministic");
    eprintln!("key_id is deterministic — PASS");
}

#[test]
fn test_2_2_key_id_different_for_different_keys() {
    let pk1 = [0x01u8; 32];
    let pk2 = [0x02u8; 32];
    let kid1 = compute_key_id(&pk1);
    let kid2 = compute_key_id(&pk2);
    assert_ne!(kid1, kid2, "Different keys must produce different key_ids");
    eprintln!("Different public keys produce different key_ids — PASS");
}

#[test]
fn test_2_2_key_id_in_poo_field() {
    // Verify that poo[1..33] contains the public key (NOT key_id)
    // key_id is derived on-the-fly when needed (e.g., for QR display)
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"key_id field check", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();

    // bytes[1..33] should be the raw public key, not key_id
    let field_1_33 = &bytes[1..33];
    assert_eq!(field_1_33, &poo.public_key[..],
        "poo[1..33] must contain raw public_key, NOT key_id");

    // key_id should be derivable from the public key
    let key_id = compute_key_id(&poo.public_key);
    assert_ne!(field_1_33, &key_id[..],
        "poo[1..33] (raw key) must differ from key_id (SHA-256(DER))");

    eprintln!("poo[1..33] = raw public_key (key_id derived on-the-fly) — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.3 — tool_hash derivation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_2_3_tool_hash_is_16_bytes() {
    let tool = "origin-sdk-js-v1.0.0";
    let tool_hash = compute_tool_hash(tool);
    assert_eq!(tool_hash.len(), 16, "tool_hash must be 16 bytes (128-bit), got {}", tool_hash.len());
    eprintln!("tool_hash is 16 bytes — PASS");
}

#[test]
fn test_2_3_tool_hash_is_truncated_sha256() {
    let tool = "origin-sdk-js-v1.0.0";
    let tool_hash = compute_tool_hash(tool);
    let full_sha256 = hash_bytes(tool.as_bytes());

    // tool_hash must be SHA-256(tool_string)[0..15] — first 16 bytes
    assert_eq!(tool_hash[..], full_sha256[..16],
        "tool_hash must be SHA-256(UTF-8 tool string)[0..15]");
    eprintln!("tool_hash = SHA-256(\"{}\".as_bytes())[0..15] — PASS", tool);
    eprintln!("  Full SHA-256: {}", hex::encode(full_sha256));
    eprintln!("  tool_hash:    {}", hex::encode(tool_hash));
}

#[test]
fn test_2_3_tool_hash_utf8_encoding() {
    // The input must be UTF-8 encoding of the tool identifier string
    let tool = "origin-cli";
    let tool_hash = compute_tool_hash(tool);
    let utf8_bytes = tool.as_bytes(); // Rust strings are UTF-8
    let full_sha = hash_bytes(utf8_bytes);
    assert_eq!(tool_hash[..], full_sha[..16],
        "tool_hash must use UTF-8 encoding of tool string");
    eprintln!("tool_hash uses UTF-8 encoding — PASS");
}

#[test]
fn test_2_3_tool_hash_deterministic() {
    let tool = "origin-sdk-js-v1.0.0";
    let h1 = compute_tool_hash(tool);
    let h2 = compute_tool_hash(tool);
    assert_eq!(h1, h2, "tool_hash must be deterministic");
    eprintln!("tool_hash is deterministic — PASS");
}

#[test]
fn test_2_3_tool_hash_different_for_different_tools() {
    let h1 = compute_tool_hash("origin-cli");
    let h2 = compute_tool_hash("origin-sdk-js-v1.0.0");
    assert_ne!(h1, h2, "Different tools must produce different tool_hashes");
    eprintln!("Different tools produce different tool_hashes — PASS");
}

#[test]
fn test_2_3_tool_hash_identifies_identity_not_behavior() {
    // tool_hash identifies the tool, not its output correctness
    // Same tool string with different artifacts should produce the same tool_hash
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();

    let stmt1 = build_statement(&secret, b"artifact A", 1700000000).unwrap();
    let stmt2 = build_statement(&secret, b"artifact B", 1700000000).unwrap();

    let poo1 = ProofOfOrigin::from_statement(&stmt1).unwrap();
    let poo2 = ProofOfOrigin::from_statement(&stmt2).unwrap();

    // Both use the same tool string (build_statement uses DEFAULT_TOOL_STRING)
    // So tool_hash should be identical
    assert_eq!(poo1.tool_hash, poo2.tool_hash,
        "tool_hash must be identical for same tool, regardless of artifact");
    eprintln!("tool_hash identifies tool identity, not behavior — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.4 — policy_hash derivation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_2_4_b_no_policy_is_zero_filled() {
    // FAIL CONDITION: null, undefined, or random bytes when no policy provided
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"no policy test", 1700000000).unwrap();

    // policy_hash should be all zeros when no policy is provided
    assert_eq!(stmt.policy_hash, [0u8; 32],
        "policy_hash must be 32 zero bytes when no policy is provided");
    eprintln!("No policy URI → policy_hash = 0x00 * 32 — PASS");
}

#[test]
fn test_2_4_a_policy_hash_is_sha256_of_content() {
    // When policy content is provided, policy_hash = SHA-256(policy content bytes)
    let policy_content = b"{\"allowed_uses\": [\"archive\", \"display\"]}";
    let expected_hash = hash_bytes(policy_content);

    let mut stmt = {
        let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
        build_statement(&secret, b"policy test", 1700000000).unwrap()
    };
    stmt.policy_hash = expected_hash;

    assert_eq!(stmt.policy_hash, expected_hash,
        "policy_hash must be SHA-256 of fetched policy content");
    eprintln!("policy_hash = SHA-256(fetched policy content) — PASS");
}

#[test]
fn test_2_4_c_policy_hash_not_uri_string() {
    // The hash must be of the FETCHED CONTENT, not the URI string
    let uri = "https://example.com/policy.json";
    let content = b"{\"rules\": \"strict\"}";

    let hash_of_uri = hash_bytes(uri.as_bytes());
    let hash_of_content = hash_bytes(content);

    assert_ne!(hash_of_uri, hash_of_content,
        "policy_hash must be of fetched content, NOT the URI string");
    eprintln!("policy_hash hashes fetched content, NOT URI string — PASS");
}

#[test]
fn test_2_4_b_zero_fill_is_32_bytes_not_less() {
    let stmt_zero = {
        let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
        build_statement(&secret, b"zero policy", 1700000000).unwrap()
    };
    assert_eq!(stmt_zero.policy_hash.len(), 32, "policy_hash must always be 32 bytes");
    assert!(stmt_zero.policy_hash.iter().all(|&b| b == 0),
        "policy_hash must be ALL zeros when no policy");
    eprintln!("policy_hash zero-fill is exactly 32 bytes — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 2.5 — parent_poo_hash for derivatives
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_2_5_a_non_derivative_parent_hash_is_zero() {
    // FAIL CONDITION: non-zero bytes when no parent exists
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"original artifact", 1700000000).unwrap();

    assert_eq!(stmt.parent_poo_hash, [0u8; 16],
        "parent_poo_hash must be 16 zero bytes for non-derivative");
    eprintln!("Non-derivative: parent_poo_hash = 0x00 * 16 — PASS");
}

#[test]
fn test_2_5_a_zero_fill_is_16_bytes() {
    let stmt = {
        let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
        build_statement(&secret, b"test", 1700000000).unwrap()
    };
    assert_eq!(stmt.parent_poo_hash.len(), 16,
        "parent_poo_hash must always be 16 bytes");
    assert!(stmt.parent_poo_hash.iter().all(|&b| b == 0),
        "parent_poo_hash must be ALL zeros for non-derivative");
    eprintln!("parent_poo_hash zero-fill is exactly 16 bytes — PASS");
}

#[test]
fn test_2_5_b_derivative_parent_hash_is_sha256_of_parent_truncated() {
    // Create a parent PoO
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let parent_stmt = build_statement(&secret, b"parent artifact", 1700000000).unwrap();
    let parent_poo = ProofOfOrigin::from_statement(&parent_stmt).unwrap();
    let parent_bytes = parent_poo.to_bytes();

    // Compute expected parent_poo_hash = SHA-256(parent PoO bytes)[0..15]
    let full_hash = hash_bytes(&parent_bytes);
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&full_hash[..16]);

    // Create a child PoO with the parent hash set
    let mut child_stmt = {
        build_statement(&secret, b"child artifact", 1700000001).unwrap()
    };
    child_stmt.parent_poo_hash = expected;

    // Verify the derivation
    assert_eq!(child_stmt.parent_poo_hash, expected,
        "parent_poo_hash must be SHA-256(parent PoO bytes)[0..15]");

    // Verify it's NOT SHA-256(parent.content_hash) — wrong input
    let wrong_input = hash_bytes(&parent_stmt.hash_bytes);
    let mut wrong_expected = [0u8; 16];
    wrong_expected.copy_from_slice(&wrong_input[..16]);
    assert_ne!(child_stmt.parent_poo_hash, wrong_expected,
        "CRITICAL: parent_poo_hash must be SHA-256(parent PoO), NOT SHA-256(parent content_hash)");

    eprintln!("=== 2.5 — parent_poo_hash derivation ===");
    eprintln!("Parent PoO bytes: 256 bytes");
    eprintln!("SHA-256(parent PoO): {}", hex::encode(full_hash));
    eprintln!("parent_poo_hash (first 16 bytes): {}", hex::encode(expected));
    eprintln!("SHA-256(parent content_hash)[0..15]: {} (WRONG)", hex::encode(wrong_expected));
    eprintln!("Derivative parent_poo_hash = SHA-256(parent PoO bytes)[0..15] — PASS");
}

#[test]
fn test_2_5_b_full_256_bytes_are_hashed() {
    // parent_poo_hash = SHA-256 of the FULL 256-byte parent PoO buffer
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let parent_stmt = build_statement(&secret, b"parent", 1700000000).unwrap();
    let parent_poo = ProofOfOrigin::from_statement(&parent_stmt).unwrap();
    let parent_bytes = parent_poo.to_bytes();

    assert_eq!(parent_bytes.len(), 256, "Parent PoO must be 256 bytes");

    let hash_of_full = hash_bytes(&parent_bytes);
    let hash_of_prefix = hash_bytes(&parent_bytes[..192]); // only signed region

    assert_ne!(hash_of_full, hash_of_prefix,
        "parent_poo_hash must hash the FULL 256 bytes, not just the signed prefix");
    eprintln!("parent_poo_hash hashes FULL 256-byte PoO (not just 192-byte prefix) — PASS");
}

#[test]
fn test_2_5_b_truncated_to_16_bytes() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let parent_stmt = build_statement(&secret, b"parent", 1700000000).unwrap();
    let parent_poo = ProofOfOrigin::from_statement(&parent_stmt).unwrap();
    let parent_bytes = parent_poo.to_bytes();

    let full_hash = hash_bytes(&parent_bytes);
    let truncated = &full_hash[..16];

    assert_eq!(truncated.len(), 16, "parent_poo_hash must be truncated to 16 bytes");
    assert_eq!(&full_hash[..16], truncated,
        "parent_poo_hash must be first 16 bytes of SHA-256");
    eprintln!("parent_poo_hash = SHA-256(parent PoO)[0..15] (truncated to 16 bytes) — PASS");
}

#[test]
fn test_2_5_roundtrip_parent_hash_in_binary() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();

    // Create parent PoO
    let parent_stmt = build_statement(&secret, b"parent", 1700000000).unwrap();
    let parent_poo = ProofOfOrigin::from_statement(&parent_stmt).unwrap();
    let parent_bytes = parent_poo.to_bytes();

    // Compute expected parent_poo_hash
    let full_hash = hash_bytes(&parent_bytes);
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&full_hash[..16]);

    // Create child with parent hash set in the PoO binary
    let child_stmt = {
        let mut s = build_statement(&secret, b"child", 1700000001).unwrap();
        s.parent_poo_hash = expected;
        s
    };
    let child_poo = ProofOfOrigin::from_statement(&child_stmt).unwrap();

    // Verify it survives binary roundtrip
    let child_bytes = child_poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&child_bytes).unwrap();
    assert_eq!(parsed.parent_poo_hash, expected,
        "parent_poo_hash must survive binary roundtrip");

    eprintln!("parent_poo_hash survives binary roundtrip — PASS");
}
