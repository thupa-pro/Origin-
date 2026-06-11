// SPDX-License-Identifier: MIT

use origin_core::crypto::SecretKey;
use origin_core::statement::{build_statement, encode_statement, verify_statement, Statement};
use origin_core::verify_bytes;

// ─── Zero-byte artifact ──────────────────────────────────────────

#[test]
fn test_zero_byte_artifact() {
    let secret = SecretKey::from_bytes(&[10u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"", 0).unwrap();
    assert!(verify_statement(&stmt, b"").is_ok());
    assert!(verify_statement(&stmt, b"x").is_err());
}

// ─── Large artifact (1 MB) ───────────────────────────────────────

#[test]
fn test_large_artifact_1mb() {
    let artifact = vec![0xABu8; 1_000_000];
    let secret = SecretKey::from_bytes(&[11u8; 32]).unwrap();
    let stmt = build_statement(&secret, &artifact, 100).unwrap();
    assert!(verify_statement(&stmt, &artifact).is_ok());
}

// ─── 10 MB artifact (checks no OOM / timeout crash) ──────────────

#[test]
fn test_large_artifact_10mb() {
    let artifact = vec![0xBCu8; 10_000_000];
    let secret = SecretKey::from_bytes(&[12u8; 32]).unwrap();
    let stmt = build_statement(&secret, &artifact, 200).unwrap();
    assert!(verify_statement(&stmt, &artifact).is_ok());
}

// ─── Binary artifact (PNG-like header) ───────────────────────────

#[test]
fn test_binary_artifact_png() {
    let png_header: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let artifact: Vec<u8> = png_header.into_iter().chain(std::iter::repeat_n(0xFF, 1024)).collect();
    let secret = SecretKey::from_bytes(&[13u8; 32]).unwrap();
    let stmt = build_statement(&secret, &artifact, 300).unwrap();
    assert!(verify_statement(&stmt, &artifact).is_ok());
}

// ─── WASM binary artifact ────────────────────────────────────────

#[test]
fn test_binary_artifact_wasm() {
    let wasm_magic: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6D]; // \0asm
    let artifact: Vec<u8> = wasm_magic.into_iter().chain(std::iter::repeat_n(0x00, 4096)).collect();
    let secret = SecretKey::from_bytes(&[14u8; 32]).unwrap();
    let stmt = build_statement(&secret, &artifact, 400).unwrap();
    assert!(verify_statement(&stmt, &artifact).is_ok());
}

// ─── Roundtrip across varying timestamps ─────────────────────────

#[test]
fn test_varying_timestamps() {
    let secret = SecretKey::from_bytes(&[15u8; 32]).unwrap();
    let artifact = b"timestamp test";
    for ts in [0u64, 1, 1_000_000, 253402300799] {
        let stmt = build_statement(&secret, artifact, ts).unwrap();
        assert_eq!(stmt.time, ts);
        assert!(verify_statement(&stmt, artifact).is_ok());
    }
}

// ─── Roundtrip text → binary → text ─────────────────────────────

#[test]
fn test_text_binary_text_roundtrip() {
    let secret = SecretKey::from_bytes(&[16u8; 32]).unwrap();
    let artifact = b"roundtrip test";
    let stmt1 = build_statement(&secret, artifact, 500).unwrap();
    let enc = encode_statement(&stmt1);
    let parsed = Statement::parse(&enc).unwrap();

    // Text roundtrip: original and parsed must have same fields
    assert_eq!(stmt1.hash, parsed.hash);
    assert_eq!(stmt1.time, parsed.time);
    assert_eq!(stmt1.key_b64, parsed.key_b64);
    assert_eq!(stmt1.sig_b64, parsed.sig_b64);

    // Binary roundtrip
    let poo = origin_core::ProofOfOrigin::from_statement(&parsed).unwrap();
    let stmt2 = poo.to_statement().unwrap();
    assert_eq!(parsed.hash, stmt2.hash);
    assert_eq!(parsed.time, stmt2.time);
    assert_eq!(parsed.key_b64, stmt2.key_b64);
    assert_eq!(parsed.sig_b64, stmt2.sig_b64);

    // Re-verify
    assert!(verify_statement(&stmt2, artifact).is_ok());
}

// ─── Concurrent verification ─────────────────────────────────────

#[test]
fn test_concurrent_verify() {
    use std::thread;

    let secret = SecretKey::from_bytes(&[17u8; 32]).unwrap();
    let artifact = b"concurrent test data";
    let stmt = build_statement(&secret, artifact, 600).unwrap();
    let encoded = encode_statement(&stmt);

    let mut handles = vec![];
    for i in 0..8 {
        let enc = encoded.clone();
        let art = artifact.to_vec();
        handles.push(thread::spawn(move || {
            if i % 2 == 0 {
                verify_bytes(&enc, &art).unwrap();
            } else {
                let s = Statement::parse(&enc).unwrap();
                verify_statement(&s, &art).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── Malformed UTF-8 in statement ────────────────────────────────

#[test]
fn test_malformed_utf8_statement() {
    // Invalid UTF-8 continuation byte
    let bad = vec![0x6F, 0x72, 0x69, 0x67, 0x69, 0x6E, 0x3A, 0x20, 0x76, 0x31, 0x0A, 0x80];
    assert!(Statement::parse(&bad).is_err());

    // Truncated multi-byte character
    let bad2 = vec![0x6F, 0x72, 0x69, 0x67, 0x69, 0x6E, 0x3A, 0x20, 0x76, 0x31, 0xC3];
    assert!(Statement::parse(&bad2).is_err());
}

// ─── Reject statement with trailing NUL bytes ────────────────────

#[test]
fn test_trailing_nul_rejected() {
    let secret = SecretKey::from_bytes(&[18u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"nul test", 700).unwrap();
    let mut enc = encode_statement(&stmt);
    enc.push(0);
    assert!(Statement::parse(&enc).is_err());
}

// ─── verify_bytes convenience function ───────────────────────────

#[test]
fn test_verify_bytes_ok() {
    let secret = SecretKey::from_bytes(&[19u8; 32]).unwrap();
    let art = b"hello from verify_bytes";
    let stmt = build_statement(&secret, art, 800).unwrap();
    let enc = encode_statement(&stmt);
    assert!(verify_bytes(&enc, art).is_ok());
    assert!(verify_bytes(&enc, b"wrong").is_err());
}
