// SPDX-License-Identifier: MIT

use origin_core::crypto::{self, PublicKey, SecretKey};
use origin_core::error::Error;
use origin_core::statement::{Statement, build_statement, encode_statement, verify_statement};

fn valid_statement_bytes() -> Vec<u8> {
    let hash = origin_core::hash::hash_hex(b"");
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    format!(
        "origin: v1\nhash: sha256:{}\ntime: 0\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        hash, zero_sig
    )
    .into_bytes()
}

// ─── Part A2: Identity point rejection ──────────────────────────

#[test]
fn test_identity_point_key_rejected() {
    let zero_key = [0u8; 32];
    let result = PublicKey::from_bytes(&zero_key);
    assert!(
        matches!(result, Err(Error::Crypto(ref msg)) if msg.contains("identity point")),
        "expected Crypto error about identity point, got {:?}",
        result
    );
}

#[test]
fn test_identity_point_rejected_in_parse() {
    let hash = origin_core::hash::hash_hex(b"hello");
    let zero_key = origin_core::base64_encode(&[0u8; 32]);
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: sha256:{}\ntime: 0\nkey: {}\nsig: {}\n",
        hash, zero_key, zero_sig
    );
    let result = Statement::parse(data.as_bytes());
    assert!(
        matches!(result, Err(Error::Crypto(ref msg)) if msg.contains("identity point")),
        "expected Crypto error about identity point, got: {:?}",
        result
    );
}

// ─── Part A3: Trailing content rejection ────────────────────────

#[test]
fn test_trailing_content_rejected() {
    let valid = valid_statement_bytes();
    assert!(Statement::parse(&valid).is_ok());

    let mut extra = valid.clone();
    extra.extend_from_slice(b"extra: garbage\n");
    let result = Statement::parse(&extra);
    assert!(
        matches!(result, Err(Error::TrailingContent(_))),
        "expected TrailingContent error, got: {:?}",
        result
    );
}

// ─── Statement parsing ──────────────────────────────────────────

#[test]
fn test_parse_valid_statement() {
    let data = valid_statement_bytes();
    let stmt = Statement::parse(&data);
    assert!(stmt.is_ok(), "expected Ok, got: {:?}", stmt);
    let s = stmt.unwrap();
    assert_eq!(s.origin, "v1");
    assert_eq!(s.time, 0);
    assert_eq!(s.key_b64.len(), 44);
    assert_eq!(s.sig_b64.len(), 88);
}

#[test]
fn test_parse_rejects_bom() {
    let mut data = b"\xef\xbb\xbf".to_vec();
    data.extend_from_slice(&valid_statement_bytes());
    assert!(matches!(Statement::parse(&data), Err(Error::Format(_))));
}

#[test]
fn test_parse_rejects_cr() {
    let good = String::from_utf8(valid_statement_bytes()).unwrap();
    let data = good.replace('\n', "\r\n");
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_null() {
    let hash = origin_core::hash::hash_hex(b"");
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: sha256:{}\ntime: 0\nkey: 1z52VZr\x00_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        hash, zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_missing_trailing_newline() {
    let mut data = valid_statement_bytes();
    data.pop(); // remove trailing \n
    assert!(matches!(Statement::parse(&data), Err(Error::Format(_))));
}

#[test]
fn test_parse_rejects_extra_lines() {
    let mut data = valid_statement_bytes();
    data.extend_from_slice(b"extra: bad\n");
    assert!(matches!(
        Statement::parse(&data),
        Err(Error::TrailingContent(_))
    ));
}

#[test]
fn test_parse_rejects_fewer_lines() {
    let data = b"origin: v1\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\n";
    assert!(matches!(Statement::parse(data), Err(Error::Format(_))));
}

#[test]
fn test_parse_rejects_bad_protocol_version() {
    let hash = origin_core::hash::hash_hex(b"");
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v2\nhash: sha256:{}\ntime: 0\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        hash, zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_bad_hash_prefix() {
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_uppercase_hex() {
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\ntime: 0\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_bad_timestamp() {
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: -1\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

#[test]
fn test_parse_rejects_leading_zero_timestamp() {
    let zero_sig = origin_core::base64_encode(&[0u8; 64]);
    let data = format!(
        "origin: v1\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 01\nkey: 1z52VZr_uqMZbHE2ju4TL2I9N1mbcBqYi7JGrO8UcQY=\nsig: {}\n",
        zero_sig
    );
    assert!(matches!(
        Statement::parse(data.as_bytes()),
        Err(Error::Format(_))
    ));
}

// ─── Public key validation ──────────────────────────────────────

#[test]
fn test_key_length_rejected() {
    assert!(PublicKey::from_bytes(&[0u8; 31]).is_err());
    assert!(PublicKey::from_bytes(&[0u8; 33]).is_err());
}

#[test]
fn test_valid_public_key_accepted() {
    let good = [
        208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    assert!(PublicKey::from_bytes(&good).is_ok());
}

// ─── Sign / verify round-trips ──────────────────────────────────

#[test]
fn test_sign_verify_roundtrip() {
    let data = b"Hello, Origin!";
    let secret = SecretKey::from_bytes(&[1u8; 32]).unwrap();
    let stmt = build_statement(&secret, data, 100).unwrap();
    assert!(verify_statement(&stmt, data).is_ok());
}

#[test]
fn test_sign_verify_wrong_data() {
    let secret = SecretKey::from_bytes(&[2u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"original data", 200).unwrap();
    let result = verify_statement(&stmt, b"tampered data");
    assert!(matches!(result, Err(Error::HashMismatch { .. })));
}

#[test]
fn test_sign_verify_wrong_key() {
    let secret = SecretKey::from_bytes(&[3u8; 32]).unwrap();
    let wrong_secret = SecretKey::from_bytes(&[4u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"some data", 300).unwrap();

    let canonical = stmt.canonical_body();
    let sig = crypto::sign(&wrong_secret, &canonical);
    let sig_b64 = origin_core::base64_encode(&sig.0);

    let raw_lines = vec![
        format!("origin: {}", stmt.origin),
        format!("hash: {}", stmt.hash),
        format!("time: {}", stmt.time),
        format!("key: {}", stmt.key_b64),
        format!("sig: {}", sig_b64),
    ];

    let tampered = Statement {
        origin: stmt.origin.clone(),
        hash: stmt.hash.clone(),
        hash_bytes: stmt.hash_bytes,
        time: stmt.time,
        key_b64: stmt.key_b64.clone(),
        key_bytes: stmt.key_bytes,
        sig_b64,
        sig_bytes: sig.0,
        raw_lines,
    };
    let result = verify_statement(&tampered, b"some data");
    assert!(
        matches!(result, Err(Error::Crypto(_))),
        "expected Crypto error, got: {:?}",
        result
    );
}

// ─── Encode / decode round-trip ────────────────────────────────

#[test]
fn test_encode_decode_statement() {
    let secret = SecretKey::from_bytes(&[5u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"test artifact", 400).unwrap();
    let encoded = encode_statement(&stmt);
    let parsed = Statement::parse(&encoded).unwrap();
    assert_eq!(stmt.hash, parsed.hash);
    assert_eq!(stmt.time, parsed.time);
    assert_eq!(stmt.key_b64, parsed.key_b64);
    assert_eq!(stmt.sig_b64, parsed.sig_b64);
    assert!(verify_statement(&parsed, b"test artifact").is_ok());
}

// ─── Canonical body invariants ─────────────────────────────────

#[test]
fn test_canonical_body_no_trailing_newline() {
    let secret = SecretKey::from_bytes(&[6u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"test", 500).unwrap();
    let text = String::from_utf8(stmt.canonical_body()).unwrap();
    assert!(
        !text.ends_with('\n'),
        "canonical body must not end with newline"
    );
    assert_eq!(text.matches('\n').count(), 3);
}

#[test]
fn test_build_statement_key_matches() {
    let seed = [7u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let stmt = build_statement(&secret, b"data", 600).unwrap();
    let kp = crypto::generate_keypair_from_seed(&seed);
    assert_eq!(stmt.key_b64, origin_core::base64_encode(&kp.public.0));
}
