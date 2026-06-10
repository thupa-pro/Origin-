use origin_core::{Statement, base64_encode, build_statement, verify_consistency};

/// Timestamp is now advisory — changing it does NOT break verification.
#[test]
fn test_timestamp_advisory() {
    let seed = [99u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"important artifact v1.0";
    let original_ts = 1717776000;

    let stmt = build_statement(&secret, data, original_ts, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    assert!(verify_consistency(&encoded, data).is_ok(), "original must verify");

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("time: 1717776000", "time: 1717776001");
    let result = verify_consistency(tampered.as_bytes(), data);
    assert!(
        result.is_ok(),
        "timestamp is advisory — changing it must NOT break verification"
    );
}

/// Changing origin still breaks verification (signed field).
#[test]
fn test_origin_replay_attack() {
    let seed = [99u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"test";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);
    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("origin: v1", "origin: v2");

    let result = verify_consistency(tampered.as_bytes(), data);
    assert!(result.is_err(), "origin change must fail");
}

/// Adversary tries to claim a statement is for a different artifact.
#[test]
fn test_artifact_replay_attack() {
    let seed = [99u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data1 = b"version 1.0";
    let data2 = b"version 2.0 (malicious)";

    let stmt = build_statement(&secret, data1, 1717776000, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let result = verify_consistency(&encoded, data2);
    assert!(result.is_err(), "replay across artifacts must fail");
}

/// Adversary modifies signed fields — all must fail.
#[test]
fn test_malformed_statement_preserving_sig() {
    let seed = [1u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();

    let attacks = vec![
        text.replace("origin: v1", "origin: v2"),
        text.replace(
            "hash: ",
            "hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        text.replace("type: provenance", "type: provenance2"),
    ];

    for tampered in attacks {
        let result = verify_consistency(tampered.as_bytes(), data);
        assert!(result.is_err(), "malformed statement must fail");
    }
}

/// Adversary swaps the key line with a different public key.
#[test]
fn test_pubkey_swap_attack() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    let secret1 = origin_core::SecretKey::from_bytes(&seed1).unwrap();
    let data = b"artifact";

    let stmt = build_statement(&secret1, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);
    let text = String::from_utf8(encoded).unwrap();

    let pair2 = origin_core::generate_keypair_from_seed(&seed2);
    let pk2_b64 = base64_encode(pair2.public.as_bytes());

    let lines: Vec<&str> = text.lines().collect();
    let old_key_line = lines[4];
    let new_key_line = format!("key: {}", pk2_b64);
    let tampered = text.replace(old_key_line, &new_key_line);

    let result = verify_consistency(tampered.as_bytes(), data);
    assert!(result.is_err(), "pubkey swap must fail");
}

/// Oversized statement.
#[test]
fn test_oversized_statement() {
    let large_key = vec![b'A'; 1000];
    let mut content = b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: ".to_vec();
    content.extend_from_slice(&large_key);
    content.extend_from_slice(b"\nsig: ");
    content.extend_from_slice(&large_key);
    content.push(b'\n');

    let result = Statement::parse(&content);
    assert!(result.is_err(), "oversized key must fail");
}

/// Non-canonical timestamps still fail parse.
#[test]
fn test_non_canonical_timestamp() {
    let seed = [5u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);
    let text = String::from_utf8(encoded).unwrap();

    let attacks = vec![
        text.replace("time: 100", "time: 0100"),
        text.replace("time: 100", "time: +100"),
        text.replace("time: 100", "time: 100 "),
    ];

    for tampered in attacks {
        let result = Statement::parse(tampered.as_bytes());
        assert!(result.is_err(), "non-canonical timestamp must fail parse");
    }
}

/// Unicode control character injection.
#[test]
fn test_unicode_attack() {
    let seed = [7u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("origin: v1", "origin: v\u{0000}1");
    let result = Statement::parse(tampered.as_bytes());
    assert!(result.is_err(), "unicode null must fail");
}

/// Verify canonical body integrity (without parent).
#[test]
fn test_canonical_body_integrity() {
    let seed = [8u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";

    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    // Canonical body is origin + type + hash + key (no time, no sig)
    let text = String::from_utf8(encoded).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let expected_canonical = format!("{}\n{}\n{}\n{}", lines[0], lines[1], lines[2], lines[4]);

    assert_eq!(
        String::from_utf8(stmt.canonical_body()).unwrap(),
        expected_canonical,
        "canonical body must be origin, type, hash, key with no trailing newline"
    );
}

/// Verify canonical body integrity (with parent).
#[test]
fn test_canonical_body_integrity_with_parent() {
    let seed = [8u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";

    let stmt = build_statement(
        &secret,
        data,
        100,
        Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    )
    .unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    // With parent: [origin, type, parent, hash, time, key, sig]
    let expected_canonical = format!("{}\n{}\n{}\n{}\n{}", lines[0], lines[1], lines[2], lines[3], lines[5]);

    assert_eq!(
        String::from_utf8(stmt.canonical_body()).unwrap(),
        expected_canonical,
        "canonical body with parent must include parent"
    );
}

/// Parent hash in canonical body — changing parent invalidates sig.
#[test]
fn test_parent_tamper_attack() {
    let seed = [10u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"child";

    let stmt = build_statement(
        &secret,
        data,
        100,
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    .unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );

    let result = verify_consistency(tampered.as_bytes(), data);
    assert!(result.is_err(), "tampered parent must fail verification");
}

/// Changing type from provenance to something else breaks verification.
#[test]
fn test_type_field_tamper() {
    let seed = [11u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("type: provenance", "type: provenance2");

    let result = verify_consistency(tampered.as_bytes(), data);
    assert!(result.is_err(), "tampered type must fail");
}

/// Verify error types.
#[test]
fn test_verification_error_types() {
    let seed = [9u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let data = b"error type test";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let r = verify_consistency(&encoded, b"wrong data");
    assert!(
        matches!(r, Err(origin_core::Error::HashMismatch { .. })),
        "expected HashMismatch error, got {:?}",
        r
    );

    let mut tampered = encoded.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    let _ = verify_consistency(&tampered, data);
}

/// Verify with trusted key using consistent API.
#[test]
fn test_verify_trusted_key_roundtrip() {
    use origin_core::verify;
    let seed = [13u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let trusted = origin_core::generate_keypair_from_seed(&seed).public.0;
    let stmt = build_statement(&secret, b"trusted test", 100, None).unwrap();
    let enc = origin_core::encode_statement(&stmt);
    assert!(verify(&enc, b"trusted test", &trusted).is_ok());
}


