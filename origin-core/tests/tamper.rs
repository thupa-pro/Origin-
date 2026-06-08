use origin_core::{build_statement, encode_statement, SecretKey};

fn make_test_statement() -> (Vec<u8>, Vec<u8>) {
    let seed = [42u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = b"tamper test artifact";
    let ts = 1717776000;
    let stmt = build_statement(&secret, data, ts, None).unwrap();
    let encoded = encode_statement(&stmt);
    (encoded, data.to_vec())
}

/// Tamper with the hash line — must fail verification.
#[test]
fn test_tamper_hash() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.replace(
        "hash: sha256:",
        "hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "tampered hash must fail verification");
}

/// Tamper with the signature — must fail verification.
#[test]
fn test_tamper_signature() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.trim_end_matches('\n');
    let tampered = tampered.strip_suffix('=').unwrap_or(tampered).to_owned() + "A\n";
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "tampered signature must fail verification");
}

/// Tamper with the timestamp — now advisory, does NOT break verification.
#[test]
fn test_tamper_timestamp_advisory() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.replace("time: 1717776000", "time: 1717776001");
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_ok(), "timestamp is advisory — changing it must NOT break verification");
}

/// Tamper with the public key — must fail verification.
#[test]
fn test_tamper_pubkey() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.replace(
        &text.lines().nth(3).unwrap()[..10],
        "AAAAAAAAAA",
    );
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "tampered pubkey must fail verification");
}

/// Tamper with the protocol version — must fail verification.
#[test]
fn test_tamper_origin() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.replace("origin: v1", "origin: v2");
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "tampered origin must fail verification");
}

/// Completely replace the artifact — must fail verification.
#[test]
fn test_wrong_artifact() {
    let (stmt, _) = make_test_statement();
    let wrong_artifact = b"this is not the original artifact";
    let result = origin_core::verify_bytes(&stmt, wrong_artifact);
    assert!(result.is_err(), "wrong artifact must fail verification");
}

/// Verify with empty artifact.
#[test]
fn test_empty_artifact() {
    let seed = [1u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let stmt = build_statement(&secret, b"", 0, None).unwrap();
    let enc = encode_statement(&stmt);
    let result = origin_core::verify_bytes(&enc, b"");
    assert!(result.is_ok(), "empty artifact must verify correctly");
    let result2 = origin_core::verify_bytes(&enc, b"x");
    assert!(result2.is_err(), "non-empty artifact must fail against empty-artifact statement");
}

/// Reorder lines in the statement.
#[test]
fn test_reordered_lines() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(0, 1);
    let tampered = lines.join("\n") + "\n";
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "reordered lines must fail");
}

/// Add trailing content after the signature line.
#[test]
fn test_trailing_content() {
    let (stmt, art) = make_test_statement();
    let text = String::from_utf8(stmt).unwrap();
    let tampered = text.trim_end_matches('\n').to_string() + "\nextra: garbage\n";
    let result = origin_core::verify_bytes(tampered.as_bytes(), &art);
    assert!(result.is_err(), "extra lines must fail");
}
