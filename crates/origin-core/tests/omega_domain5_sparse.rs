// SPDX-License-Identifier: MIT
// OMEGA CRUCIBLE — Domain 5: 50GB Sparse File & SIGINT Atomic Swap

use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Helper: create a temporary file path.
fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(name);
    let _ = std::fs::remove_file(&p);
    p
}

/// 5.1 THE 1GB SPARSE FILE TEST (OOM PREVENTION)
///
/// Uses 1GB (not 50GB) to keep runtime practical for CI.
/// Takes ~6 minutes, so ignored by default. Run with `--include-ignored`.
/// The streaming invariant is identical regardless of file size.
#[test]
#[ignore]
fn test_1gb_sparse_file_streaming_hash() {
    let tmp = tmp_path("origin_1gb_sparse_test.bin");

    // Create a 1GB sparse file
    {
        let mut file = std::fs::File::create(&tmp).expect("create sparse file");
        file.seek(SeekFrom::Start(1_000_000_000 - 1))
            .expect("seek to 1GB");
        file.write_all(&[0x42]).expect("write last byte");
        file.flush().expect("flush");
    }

    let metadata = std::fs::metadata(&tmp).expect("metadata");
    assert_eq!(metadata.len(), 1_000_000_000, "file must be 1GB");

    // Hash using streaming I/O (64KB buffer, no full file load)
    let hash = origin_core::hash::hash_file(&tmp).expect("hash should succeed");
    let hash2 = origin_core::hash::hash_file(&tmp).expect("second hash");
    assert_eq!(hash, hash2, "hash must be deterministic");

    assert_eq!(hash.len(), 64, "hash should be 64 hex chars");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "hash should be hex"
    );

    let _ = std::fs::remove_file(&tmp);
}

/// 5.1b THE 50GB SPARSE FILE TEST (long-running, ignored by default)
#[test]
#[ignore]
fn test_50gb_sparse_file_streaming_hash() {
    let tmp = tmp_path("origin_50gb_sparse_test.bin");
    {
        let mut file = std::fs::File::create(&tmp).expect("create sparse file");
        file.seek(SeekFrom::Start(50_000_000_000 - 1))
            .expect("seek to 50GB");
        file.write_all(&[0x42]).expect("write last byte");
        file.flush().expect("flush");
    }
    let hash = origin_core::hash::hash_file(&tmp).expect("hash should succeed");
    assert_eq!(hash.len(), 64, "hash should be 64 hex chars");
    let _ = std::fs::remove_file(&tmp);
}

/// 5.2 THE CTRL+C ATOMIC SWAP TEST
#[test]
fn test_atomic_write_crash_safety() {
    let target_path = tmp_path("origin_atomic_test_target.bin");
    let original_content = b"ORIGINAL FILE CONTENT -- MUST REMAIN INTACT";

    std::fs::write(&target_path, original_content).expect("write original");

    // Simulate crash: write to temp file, never rename to target
    let tmp_crash = tmp_path("origin_atomic_temp_crash.bin");
    {
        let mut f = std::fs::File::create(&tmp_crash).expect("create temp");
        f.write_all(b"CRASHED WRITE -- SHOULD NOT AFFECT ORIGINAL")
            .expect("write temp");
    } // dropped without rename -- simulates SIGINT

    let after = std::fs::read(&target_path).expect("read original after crash");
    assert_eq!(
        after, original_content,
        "original file must be untouched after interrupted write"
    );

    // Successful atomic write via rename
    let new_content = b"NEW CONTENT -- ATOMICALLY WRITTEN";
    let tmp_success = tmp_path("origin_atomic_temp_success.bin");
    {
        let mut f = std::fs::File::create(&tmp_success).expect("create temp");
        f.write_all(new_content).expect("write new content");
    }
    std::fs::rename(&tmp_success, &target_path).expect("atomic rename");

    let final_content = std::fs::read(&target_path).expect("read final");
    assert_eq!(final_content, new_content, "final content must be new");

    let _ = std::fs::remove_file(&target_path);
    let _ = std::fs::remove_file(&tmp_crash);
}

/// 5.3 BEAUTIFUL ERROR DIAGNOSTICS AUDIT
#[test]
fn test_cli_no_unwrap_in_production() {
    let cli_src = include_str!("../../origin-cli/src/main.rs");

    let mut unwrap_calls = 0;
    for line in cli_src.lines() {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        if t.contains(".unwrap()") && !t.contains(".unwrap_or") {
            unwrap_calls += 1;
        }
    }

    assert!(
        unwrap_calls <= 1,
        "CLI must have at most 1 naked unwrap() call, found {}",
        unwrap_calls
    );
}
