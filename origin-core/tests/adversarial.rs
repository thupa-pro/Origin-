use origin_core::{base64_encode, build_statement, verify_bytes, SecretKey, Statement};

/// Adversary replays a statement with a modified timestamp.
#[test]
fn test_timestamp_replay_attack() {
    let seed = [99u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"important artifact v1.0";
    let original_ts = 1717776000;

    let stmt = build_statement(&secret, data, original_ts).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    assert!(verify_bytes(&encoded, data).is_ok(), "original must verify");

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("time: 1717776000", "time: 1717776001");
    let result = verify_bytes(tampered.as_bytes(), data);
    assert!(result.is_err(), "timestamp replay must fail");
}

/// Adversary tries to claim a statement is for a different artifact.
#[test]
fn test_artifact_replay_attack() {
    let seed = [99u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data1 = b"version 1.0";
    let data2 = b"version 2.0 (malicious)";

    let stmt = build_statement(&secret, data1, 1717776000).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let result = verify_bytes(&encoded, data2);
    assert!(result.is_err(), "replay across artifacts must fail");
}

/// Adversary modifies the statement but keeps the same signature field.
#[test]
fn test_malformed_statement_preserving_sig() {
    let seed = [1u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();

    let attacks = vec![
        text.replace("origin: v1", "origin: v2"),
        text.replace("time: 100", "time: 999999999999"),
        text.replace(
            "hash: ",
            "hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ];

    for tampered in attacks {
        let result = verify_bytes(tampered.as_bytes(), data);
        assert!(result.is_err(), "malformed statement must fail");
    }
}

/// Adversary swaps the key line with a different public key.
#[test]
fn test_pubkey_swap_attack() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    let secret1 = SecretKey::from_bytes(&seed1).unwrap();
    let data = b"artifact";

    let stmt = build_statement(&secret1, data, 100).unwrap();
    let encoded = origin_core::encode_statement(&stmt);
    let text = String::from_utf8(encoded).unwrap();

    let pair2 = origin_core::generate_keypair_from_seed(&seed2);
    let pk2_b64 = base64_encode(pair2.public.as_bytes());

    let lines: Vec<&str> = text.lines().collect();
    let old_key_line = lines[3];
    let new_key_line = format!("key: {}", pk2_b64);
    let tampered = text.replace(old_key_line, &new_key_line);

    let result = verify_bytes(tampered.as_bytes(), data);
    assert!(result.is_err(), "pubkey swap must fail");
}

/// Adversary provides an extremely large statement.
#[test]
fn test_oversized_statement() {
    let large_key = vec!['A' as u8; 1000];
    let mut content = b"origin: v1\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: ".to_vec();
    content.extend_from_slice(&large_key);
    content.extend_from_slice(b"\nsig: ");
    content.extend_from_slice(&large_key);
    content.push(b'\n');

    let result = Statement::parse(&content);
    assert!(result.is_err(), "oversized key must fail");
}

/// Adversary provides non-canonical but semantically equivalent timestamps.
#[test]
fn test_non_canonical_timestamp() {
    let seed = [5u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100).unwrap();
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

/// Adversary tries Unicode control character injection.
#[test]
fn test_unicode_attack() {
    let seed = [7u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";
    let stmt = build_statement(&secret, data, 100).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let tampered = text.replace("origin: v1", "origin: v\u{0000}1");
    let result = Statement::parse(tampered.as_bytes());
    assert!(result.is_err(), "unicode null must fail");
}

/// Verify canonical body integrity.
#[test]
fn test_canonical_body_integrity() {
    let seed = [8u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"artifact";

    let stmt = build_statement(&secret, data, 100).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let text = String::from_utf8(encoded).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let expected_canonical = format!("{}\n{}\n{}\n{}", lines[0], lines[1], lines[2], lines[3]);

    assert_eq!(
        String::from_utf8(stmt.canonical_body()).unwrap(),
        expected_canonical,
        "canonical body must be exactly lines 1-4 with no trailing newline"
    );
}

/// Verify error types.
#[test]
fn test_verification_error_types() {
    let seed = [9u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"error type test";
    let stmt = build_statement(&secret, data, 100).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    let r = verify_bytes(&encoded, b"wrong data");
    match r {
        Err(origin_core::Error::HashMismatch { .. }) => {}
        other => panic!("expected HashMismatch error, got {:?}", other),
    }

    let mut tampered = encoded.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    let _ = verify_bytes(&tampered, data);
}
