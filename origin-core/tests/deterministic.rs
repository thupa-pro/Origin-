use origin_core::{build_statement, encode_statement, generate_keypair_from_seed, hash};

#[test]
fn test_deterministic_hash() {
    let data = b"hello world";
    let h1 = hash::hash_hex(data);
    let h2 = hash::hash_hex(data);
    assert_eq!(h1, h2, "hash must be deterministic");
}

#[test]
fn test_deterministic_signing() {
    let seed = [42u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"deterministic test artifact";
    let ts = 1717776000;

    let stmt1 = build_statement(&secret, data, ts, None).unwrap();
    let stmt2 = build_statement(&secret, data, ts, None).unwrap();

    let enc1 = encode_statement(&stmt1);
    let enc2 = encode_statement(&stmt2);
    assert_eq!(enc1, enc2, "signing must be deterministic");
}

#[test]
fn test_deterministic_signing_with_parent() {
    let seed = [42u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"child artifact";
    let ts = 1717776001;

    let stmt1 = build_statement(&secret, data, ts, Some("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")).unwrap();
    let stmt2 = build_statement(&secret, data, ts, Some("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")).unwrap();

    let enc1 = encode_statement(&stmt1);
    let enc2 = encode_statement(&stmt2);
    assert_eq!(enc1, enc2, "signing with parent must be deterministic");
}

#[test]
fn test_deterministic_verification() {
    let seed = [42u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"deterministic verification test";
    let ts = 1717776000;

    let stmt = build_statement(&secret, data, ts, None).unwrap();
    let encoded = encode_statement(&stmt);

    let r1 = origin_core::verify_bytes(&encoded, data);
    let r2 = origin_core::verify_bytes(&encoded, data);
    assert!(r1.is_ok(), "first verification must pass");
    assert!(r2.is_ok(), "second verification must pass");
}

#[test]
fn test_deterministic_key_generation() {
    let seed = [99u8; 32];
    let pair1 = generate_keypair_from_seed(&seed);
    let pair2 = generate_keypair_from_seed(&seed);

    assert_eq!(pair1.public, pair2.public, "public keys from same seed must match");
    assert_eq!(pair1.secret.0, pair2.secret.0, "secret keys from same seed must match");
}

#[test]
fn test_deterministic_canonical_body() {
    let seed = [1u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"canonical test";
    let ts = 0;

    let stmt = build_statement(&secret, data, ts, None).unwrap();
    let body1 = stmt.canonical_body();
    let body2 = stmt.canonical_body();

    assert_eq!(body1, body2, "canonical body must be deterministic");
    assert!(!body1.ends_with(b"\n"), "canonical body must not have trailing newline");
    let body_str = String::from_utf8_lossy(&body1);
    assert!(!body_str.contains("sig:"), "canonical body must not include signature");
    assert!(!body_str.contains("time:"), "canonical body must not include timestamp (advisory)");
}

#[test]
fn test_deterministic_canonical_body_with_parent() {
    let seed = [1u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"canonical parent test";
    let ts = 0;

    let stmt = build_statement(&secret, data, ts, Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).unwrap();
    let body = stmt.canonical_body();
    let body_str = String::from_utf8_lossy(&body);

    assert!(body_str.contains("parent:"), "canonical body must include parent when present");
    assert!(!body_str.contains("time:"), "canonical body must not include timestamp");
    assert!(!body_str.contains("sig:"), "canonical body must not include signature");
}
