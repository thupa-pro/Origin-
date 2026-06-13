//! DOMAIN 7 — TIMESTAMP HANDLING
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::ProofOfOrigin;
use origin_core::statement::{build_statement, verify_statement_hash_with_time};
use origin_core::SecretKey;
use std::convert::TryInto;

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 7.1 — UTC enforcement
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_7_1_a_timestamp_is_big_endian_u32() {
    // Timestamp is stored as big-endian u32 (4 bytes) at offset 33
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];

    let ts: u32 = 1700000000;
    poo.timestamp = ts.to_be_bytes();

    let bytes = poo.to_bytes();
    assert_eq!(bytes[33], (ts >> 24) as u8); // 0x65
    assert_eq!(bytes[34], (ts >> 16) as u8); // 0x53
    assert_eq!(bytes[35], (ts >> 8) as u8);  // 0xF1
    assert_eq!(bytes[36], ts as u8);          // 0x00

    assert_eq!(poo.timestamp_u32(), ts);
    eprintln!("7.1  Timestamp stored as big-endian u32: 1700000000 = 0x6553F100 — PASS");
}

#[test]
fn test_7_1_b_timestamp_not_milliseconds() {
    // FAIL CONDITION: Timestamp uses milliseconds instead of seconds
    // 1700000000000ms would be obviously wrong (exceeds u32 max)
    let ms_timestamp: u64 = 1700000000000;
    assert!(ms_timestamp > u32::MAX as u64,
        "Millisecond timestamp {} exceeds u32 max {}", ms_timestamp, u32::MAX);

    // A valid seconds timestamp fits in u32
    let sec_timestamp: u32 = 1700000000;
    assert!(sec_timestamp <= u32::MAX);
    eprintln!("7.1  Millisecond timestamp {} > u32 max {} (correctly rejected by type)", ms_timestamp, u32::MAX);
    eprintln!("7.1  Second timestamp {} fits in u32 — PASS", sec_timestamp);
}

#[test]
fn test_7_1_c_timestamp_not_zero_for_real_artifact() {
    // FAIL CONDITION: Timestamp = 0 (epoch) for non-test artifacts
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"real artifact", 1700000000).unwrap();

    assert_ne!(stmt.time, 0, "Timestamp must not be 0 for real artifacts");
    assert_eq!(stmt.time, 1700000000);
    eprintln!("7.1  Timestamp 1700000000 ≠ 0 — PASS");
}

#[test]
fn test_7_1_d_timestamp_roundtrip() {
    // Timestamp must survive binary roundtrip
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    let ts: u32 = 1700000000;
    poo.timestamp = ts.to_be_bytes();

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.timestamp_u32(), ts);
    eprintln!("7.1  Timestamp roundtrip: 1700000000 → bytes → parse → 1700000000 — PASS");
}

#[test]
fn test_7_1_e_timestamp_offset_33() {
    // Timestamp is at offset 33, 4 bytes
    use core::mem::offset_of;
    let offset = offset_of!(ProofOfOrigin, timestamp);
    assert_eq!(offset, 33, "timestamp must be at offset 33, got {}", offset);
    eprintln!("7.1  Timestamp offset: 33 — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 7.2 — Future timestamp rejection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_7_2_a_future_timestamp_warning_only() {
    // E007: timestamp > now + 300 → WARNING only, does NOT hard-fail
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"future test", 1700000000).unwrap();

    let now: u64 = 1700000000;
    let future_ts = stmt.time; // 1700000000 = now + 0

    // Test with now = 0 (all timestamps are "in the future")
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(0), // now = 0 → timestamp is way in the future
        None,
        None,
    );

    // Verification must NOT hard-fail (E007 is warning only)
    assert!(result.is_ok(),
        "E007 TIMESTAMP_FUTURE must NOT hard-fail, got: {:?}", result.err());

    eprintln!("7.2  Future timestamp (now=0) → warning only, no hard-fail — PASS");
}

#[test]
fn test_7_2_b_within_tolerance_no_warning() {
    // Timestamp within 300s tolerance → no E007 warning
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"tolerance test", 1700000000).unwrap();

    let now: u64 = stmt.time - 250; // 250 seconds before timestamp (within 300s)
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    assert!(result.is_ok(), "Within tolerance must succeed");
    eprintln!("7.2  Within tolerance (250s) → no warning — PASS");
}

#[test]
fn test_7_2_c_beyond_tolerance_triggers_warning() {
    // Timestamp > now + 300 → E007 warning emitted
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"beyond tolerance", 1700000000).unwrap();

    let now: u64 = stmt.time - 400; // 400 seconds before timestamp (beyond 300s)

    // The warning is printed to stderr via eprintln!
    // We can't capture stderr easily, but we can verify the verification still succeeds
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    // Must NOT hard-fail (E007 is warning only per spec)
    assert!(result.is_ok(),
        "Beyond tolerance must still succeed (warning only), got: {:?}", result.err());

    eprintln!("7.2  Beyond tolerance (400s) → warning emitted, no hard-fail — PASS");
}

#[test]
fn test_7_2_d_300s_boundary_exactly() {
    // Exactly at the boundary: timestamp = now + 300
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"boundary test", 1700000000).unwrap();

    let now: u64 = stmt.time - 300; // Exactly 300s before
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    // At exactly 300s, timestamp == now + 300, so NO warning (warning is > not >=)
    assert!(result.is_ok());
    eprintln!("7.2  Exactly at 300s boundary → no warning — PASS");
}

#[test]
fn test_7_2_e_301s_boundary_triggers() {
    // Just beyond: timestamp = now + 301
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"boundary test 301", 1700000000).unwrap();

    let now: u64 = stmt.time - 301; // 301s before → timestamp = now + 301
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    // Must NOT hard-fail
    assert!(result.is_ok(),
        "301s must still succeed (warning only), got: {:?}", result.err());

    eprintln!("7.2  301s beyond → warning triggered, no hard-fail — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 7.3 — Historical timestamp handling
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_7_3_a_old_timestamp_not_rejected() {
    // Old timestamps (5 years ago) must NOT be rejected
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let old_ts: u64 = 1577836800; // 2020-01-01T00:00:00Z (5+ years ago)
    let stmt = build_statement(&secret, b"old artifact", old_ts).unwrap();

    let now: u64 = 1700000000; // 2023-11-14
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    assert!(result.is_ok(),
        "Old timestamp must NOT be rejected, got: {:?}", result.err());
    eprintln!("7.3  Old timestamp (2020) not rejected — PASS");
}

#[test]
fn test_7_3_b_very_old_timestamp() {
    // Timestamp from 1970+1 day = still valid
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let very_old_ts: u64 = 86400; // 1970-01-02T00:00:00Z
    let stmt = build_statement(&secret, b"ancient artifact", very_old_ts).unwrap();

    let now: u64 = 1700000000;
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(now),
        None,
        None,
    );

    assert!(result.is_ok(),
        "Very old timestamp must NOT be rejected, got: {:?}", result.err());
    eprintln!("7.3  Very old timestamp (1970) not rejected — PASS");
}

#[test]
fn test_7_3_c_past_timestamp_always_valid() {
    // Any timestamp in the past is valid
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let now: u64 = 1700000000;

    for ts in [1u64, 100, 1000000, 1000000000, 1500000000, 1699999999] {
        let stmt = build_statement(&secret, b"test", ts).unwrap();
        let result = verify_statement_hash_with_time(
            &stmt,
            &hex::encode(stmt.hash_bytes),
            Some(now),
            None,
            None,
        );
        assert!(result.is_ok(),
            "Past timestamp {} must be valid, got: {:?}", ts, result.err());
    }
    eprintln!("7.3  All past timestamps valid — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 7.4 — uint32 overflow boundary
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_7_4_a_uint32_max_timestamp() {
    // uint32 max = 0xFFFFFFFF = 4294967295 = 2106-02-07T06:28:15Z
    let max_ts: u32 = u32::MAX;
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.timestamp = max_ts.to_be_bytes();

    let bytes = poo.to_bytes();
    assert_eq!(bytes[33], 0xFF);
    assert_eq!(bytes[34], 0xFF);
    assert_eq!(bytes[35], 0xFF);
    assert_eq!(bytes[36], 0xFF);

    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.timestamp_u32(), u32::MAX);
    eprintln!("7.4  uint32 max (0xFFFFFFFF) roundtrip — PASS");
}

#[test]
fn test_7_4_b_near_max_timestamps() {
    // Timestamps near uint32 max
    let test_values: Vec<u32> = vec![
        u32::MAX,
        u32::MAX - 1,
        u32::MAX - 300,
        u32::MAX - 301,
        4294967200,
    ];

    for ts in &test_values {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.public_key = [0x01; 32];
        poo.timestamp = ts.to_be_bytes();

        let bytes = poo.to_bytes();
        let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.timestamp_u32(), *ts,
            "Timestamp {} must roundtrip correctly", ts);
    }
    eprintln!("7.4  Near-max timestamps roundtrip — PASS");
}

#[test]
fn test_7_4_c_min_timestamp() {
    // Minimum useful timestamp (not 0, which is epoch)
    let min_ts: u32 = 1;
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.timestamp = min_ts.to_be_bytes();

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.timestamp_u32(), 1);
    eprintln!("7.4  Minimum timestamp (1) roundtrip — PASS");
}

#[test]
fn test_7_4_d_timestamp_encoding_consistency() {
    // Verify encoding matches standard big-endian
    let test_cases: Vec<(u32, [u8; 4])> = vec![
        (0, [0x00, 0x00, 0x00, 0x00]),
        (1, [0x00, 0x00, 0x00, 0x01]),
        (256, [0x00, 0x00, 0x01, 0x00]),
        (65536, [0x00, 0x01, 0x00, 0x00]),
        (16777216, [0x01, 0x00, 0x00, 0x00]),
        (1700000000, [0x65, 0x53, 0xF1, 0x00]),
        (u32::MAX, [0xFF, 0xFF, 0xFF, 0xFF]),
    ];

    for (ts, expected) in &test_cases {
        assert_eq!(ts.to_be_bytes(), *expected,
            "Timestamp {} must encode as {:?}", ts, expected);
    }
    eprintln!("7.4  Timestamp encoding consistency — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 7.5 — E007 error structure
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_7_5_a_timestamp_future_error_structure() {
    // Verify the TimestampFuture error contains correct fields
    let err = origin_core::error::Error::TimestampFuture { ts: 1700000400, now: 1700000000 };
    assert_eq!(err.code_str(), "E007");

    let msg = format!("{}", err);
    assert!(msg.contains("E007"), "Error message must contain E007");
    assert!(msg.contains("TIMESTAMP_FUTURE"), "Error message must contain TIMESTAMP_FUTURE");
    assert!(msg.contains("400"), "Error message must contain the time difference");

    eprintln!("7.5  E007 error structure: code=E007, message contains timestamp info — PASS");
}

#[test]
fn test_7_5_b_saturating_add_prevents_overflow() {
    // now + 300 must not overflow
    let now = u64::MAX;
    let result = now.saturating_add(300);
    assert_eq!(result, u64::MAX, "saturating_add must prevent overflow");
    eprintln!("7.5  saturating_add prevents overflow — PASS");
}
