// SPDX-License-Identifier: MIT
// OMEGA CRUCIBLE — Domain 9: The "Absolute Zero" Cryptographic Vectors

use origin_core::crypto::{SecretKey, Signature, generate_keypair_from_seed, sign, verify, compute_key_id};
use origin_core::binary::ProofOfOrigin;
use origin_core::hash::hash_bytes;
use origin_core::statement::{build_statement, verify_statement};

// 9.1 ED25519 SIGNATURE MALLEABILITY — Canonical S Check
#[test]
fn test_verify_rejects_malleable_signature() {
    // Create a valid signature
    let secret = SecretKey::from_bytes(&[0xDD; 32]).unwrap();
    let public = {
        let kp = generate_keypair_from_seed(&secret.0);
        kp.public
    };
    let msg = b"malleability-test-message";
    let sig = sign(&secret, msg);

    // The curve order L for Ed25519
    let l_bytes: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5,
        0xd3, 0xed,
    ];

    // The signature is (R_bytes || S_bytes). S is in bytes 32..64.
    // Add L to S to create a non-canonical but equivalent signature.
    let sig_bytes = sig.0;
    let r_bytes = &sig_bytes[..32];

    let s_bytes = &sig_bytes[32..64];
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(s_bytes);

    // Compute S + L (modulo 2^252 + ...)
    let mut carry = 0u16;
    let mut malleable_s = [0u8; 32];
    for i in 0..32 {
        let sum = s_arr[i] as u16 + l_bytes[i] as u16 + carry;
        malleable_s[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }

    // Construct the malleable signature (R || S+L)
    let mut malleable_sig_bytes = [0u8; 64];
    malleable_sig_bytes[..32].copy_from_slice(r_bytes);
    malleable_sig_bytes[32..64].copy_from_slice(&malleable_s);

    // This non-canonical S should be rejected by verify_strict
    let malleable_sig = Signature(malleable_sig_bytes);
    let result = verify(&public, msg, &malleable_sig);
    assert!(
        result.is_err(),
        "Non-canonical S must be rejected (malleability protection)"
    );
}

// 9.3 NONCE REUSE — Deterministic Signatures (Bellcore Attack Immunity)
#[test]
fn test_deterministic_nonce_1000_times() {
    let secret = SecretKey::from_bytes(&[0xAA; 32]).unwrap();
    let payload = b"deterministic-nonce-test-payload";
    let stmt1 = build_statement(&secret, payload, 1000000).unwrap();

    for i in 0..1000 {
        let stmt = build_statement(&secret, payload, 1000000).unwrap();
        assert_eq!(
            stmt.sig_bytes, stmt1.sig_bytes,
            "Ed25519 signatures must be deterministic (RFC 6979). Iteration {} produced different sig.",
            i
        );
    }
}

// 9.4 THE "POISONED POLICY" COMMITMENT SWAP
#[test]
fn test_policy_hash_commitment_swap() {
    // The PoO signs the canonical body: origin + hash + time + key
    // The signature covers all four fields.
    // If an attacker replaces any of these, verification must fail.

    let secret = SecretKey::from_bytes(&[0xBB; 32]).unwrap();
    let payload = b"policy-commitment-test";
    let stmt = build_statement(&secret, payload, 2000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let mut bytes = poo.to_bytes();

    // Swap the content_hash field (bytes 53..85) with a different hash
    let fake_hash = hash_bytes(b"different-payload");
    bytes[53..85].copy_from_slice(&fake_hash);

    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let parsed_stmt = parsed.to_statement().unwrap();
    let result = verify_statement(&parsed_stmt, payload);
    assert!(
        result.is_err(),
        "Hash commitment swap must be detected by verification"
    );
}

#[test]
fn test_pubkey_commitment_swap() {
    let secret1 = SecretKey::from_bytes(&[0xCC; 32]).unwrap();
    let secret2 = SecretKey::from_bytes(&[0xDD; 32]).unwrap();
    let payload = b"pubkey-commitment-test";
    let stmt = build_statement(&secret1, payload, 3000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let mut bytes = poo.to_bytes();

    // Swap the public_key field with a different key's public_key
    let kp2 = generate_keypair_from_seed(&secret2.0);
    bytes[1..33].copy_from_slice(&kp2.public.0);

    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let parsed_stmt = parsed.to_statement().unwrap();
    let result = verify_statement(&parsed_stmt, payload);
    assert!(
        result.is_err(),
        "Public key commitment swap must be detected by verification"
    );
}

// Verify that the signature field is also committed (can't swap signature from another statement)
#[test]
fn test_signature_commitment_swap() {
    let secret1 = SecretKey::from_bytes(&[0x11; 32]).unwrap();
    let secret2 = SecretKey::from_bytes(&[0x22; 32]).unwrap();
    let payload = b"sig-commitment-test";

    let stmt1 = build_statement(&secret1, payload, 4000000).unwrap();
    let stmt2 = build_statement(&secret2, b"different-data", 4000000).unwrap();
    let poo2 = ProofOfOrigin::from_statement(&stmt2).unwrap();
    let mut bytes = poo2.to_bytes();

    // Replace signature in poo2 bytes with signature from stmt1
    bytes[192..256].copy_from_slice(&stmt1.sig_bytes);

    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let parsed_stmt = parsed.to_statement().unwrap();
    let result = verify_statement(&parsed_stmt, b"different-data");
    assert!(
        result.is_err(),
        "Signature commitment swap must be detected by verification"
    );
}

// Verify that a statement signed for payload A fails for payload B
#[test]
fn test_cross_payload_rejection() {
    let secret = SecretKey::from_bytes(&[0xEE; 32]).unwrap();
    let stmt = build_statement(&secret, b"payload-a", 5000000).unwrap();
    assert!(verify_statement(&stmt, b"payload-a").is_ok());
    assert!(verify_statement(&stmt, b"payload-b").is_err());
}
