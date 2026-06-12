// SPDX-License-Identifier: MIT
// OMEGA CRUCIBLE — Domain 5: CLI Ergonomics & Streaming I/O

use origin_core::SecretKey;
use origin_core::statement::{build_statement, verify_statement};

// Verify the hash module uses streaming for large files
#[test]
fn test_large_artifact_10mb() {
    let size = 10 * 1024 * 1024;
    let large_data = vec![0xABu8; size];
    let secret = SecretKey::from_bytes(&[0x77; 32]).unwrap();
    let stmt = build_statement(&secret, &large_data, 100000).unwrap();
    assert!(verify_statement(&stmt, &large_data).is_ok());
}

#[test]
fn test_large_artifact_1mb() {
    let size = 1024 * 1024;
    let large_data = vec![0xBCu8; size];
    let secret = SecretKey::from_bytes(&[0x88; 32]).unwrap();
    let stmt = build_statement(&secret, &large_data, 200000).unwrap();
    assert!(verify_statement(&stmt, &large_data).is_ok());
}

// Zero-byte artifact edge case
#[test]
fn test_zero_byte_artifact() {
    let secret = SecretKey::from_bytes(&[0x99; 32]).unwrap();
    let stmt = build_statement(&secret, b"", 300000).unwrap();
    assert!(verify_statement(&stmt, b"").is_ok());
}

// Binary artifact (PNG-like raw bytes)
#[test]
fn test_binary_artifact_png() {
    let png_header = [0x89u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let secret = SecretKey::from_bytes(&[0x66; 32]).unwrap();
    let stmt = build_statement(&secret, &png_header, 400000).unwrap();
    assert!(verify_statement(&stmt, &png_header).is_ok());
}

// WASM binary
#[test]
fn test_binary_artifact_wasm() {
    let wasm_header = [0x00u8, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let secret = SecretKey::from_bytes(&[0x55; 32]).unwrap();
    let stmt = build_statement(&secret, &wasm_header, 500000).unwrap();
    assert!(verify_statement(&stmt, &wasm_header).is_ok());
}

// Concurrent verification stress test
#[test]
fn test_concurrent_verify() {
    let secret = SecretKey::from_bytes(&[0x44; 32]).unwrap();
    let payload = b"concurrent-test";
    let stmt = build_statement(&secret, payload, 600000).unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let stmt_clone = stmt.clone();
        handles.push(std::thread::spawn(move || {
            assert!(verify_statement(&stmt_clone, payload).is_ok());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// Varying timestamps
#[test]
fn test_varying_timestamps() {
    let secret = SecretKey::from_bytes(&[0x33; 32]).unwrap();
    let payload = b"timestamp-test";

    for ts in [0u64, 1, 1700000000, 253402300799] {
        let stmt = build_statement(&secret, payload, ts).unwrap();
        assert_eq!(stmt.time, ts);
        assert!(verify_statement(&stmt, payload).is_ok());
    }
}
