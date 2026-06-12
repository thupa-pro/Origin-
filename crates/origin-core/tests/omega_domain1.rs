// SPDX-License-Identifier: MIT
// OMEGA CRUCIBLE — Domain 1: 256-Byte Absolute Invariant & Memory Layout

use bytemuck::Zeroable;
use core::mem::{align_of, offset_of, size_of};
use origin_core::SecretKey;
use origin_core::binary::ProofOfOrigin;
use origin_core::statement::build_statement;

// 1.1 COMPILE-TIME SIZE & OFFSET PROOF
#[test]
fn test_poo_byte_size_exactly_256() {
    assert_eq!(size_of::<ProofOfOrigin>(), 256);
}

#[test]
fn test_poo_alignment_is_1() {
    assert_eq!(align_of::<ProofOfOrigin>(), 1);
}

#[test]
fn test_poo_field_offsets() {
    // Verify every field offset matches the spec
    assert_eq!(offset_of!(ProofOfOrigin, version), 0);
    assert_eq!(offset_of!(ProofOfOrigin, reserved), 1);
    assert_eq!(offset_of!(ProofOfOrigin, timestamp), 10);
    assert_eq!(offset_of!(ProofOfOrigin, hash), 18);
    assert_eq!(offset_of!(ProofOfOrigin, pubkey), 50);
    assert_eq!(offset_of!(ProofOfOrigin, signature), 82);
    assert_eq!(offset_of!(ProofOfOrigin, reserved2), 146);

    // reserved is exactly 9 bytes
    assert_eq!(size_of::<[u8; 9]>(), 9);

    // Verify field sizes
    assert_eq!(size_of::<u8>(), 1);
    assert_eq!(size_of::<[u8; 9]>(), 9);
    assert_eq!(size_of::<[u8; 8]>(), 8);
    assert_eq!(size_of::<[u8; 32]>(), 32);
    assert_eq!(size_of::<[u8; 64]>(), 64);
    assert_eq!(size_of::<[u8; 110]>(), 110);

    // Sum check: 1 + 9 + 8 + 32 + 32 + 64 + 110 = 256
    assert_eq!(1 + 9 + 8 + 32 + 32 + 64 + 110, 256);
}

#[test]
fn test_poo_no_implicit_padding() {
    // The struct is #[repr(C, packed)], so fields are tightly packed.
    // Verify that the offset of reserved2 (which starts at 146) plus its size (110) equals 256.
    let poo = ProofOfOrigin::zeroed();
    let base = &poo as *const ProofOfOrigin as usize;
    let reserved2_ptr = &poo.reserved2 as *const [u8; 110] as usize;
    assert_eq!(reserved2_ptr - base, 146);
    assert_eq!(reserved2_ptr + 110 - base, 256);
}

// 1.2 ZERO-ALLOCATION SERIALIZATION
#[test]
fn test_from_bytes_returns_reference_no_alloc() {
    // from_bytes returns a &ProofOfOrigin, not an owned copy.
    // This is a zero-allocation operation.
    let mut bytes = [0u8; 256];
    bytes[0] = 0x01; // valid version
    // Set a valid pubkey (non-identity point)
    bytes[50] = 208;
    bytes[51] = 90;
    bytes[52] = 152;
    bytes[53] = 1;
    bytes[54] = 130;
    bytes[55] = 177;
    bytes[56] = 10;
    bytes[57] = 183;
    bytes[58] = 213;
    bytes[59] = 75;
    bytes[60] = 254;
    bytes[61] = 211;
    bytes[62] = 201;
    bytes[63] = 100;
    bytes[64] = 7;
    bytes[65] = 58;
    bytes[66] = 14;
    bytes[67] = 225;
    bytes[68] = 114;
    bytes[69] = 243;
    bytes[70] = 218;
    bytes[71] = 162;
    bytes[72] = 38;
    bytes[73] = 53;
    bytes[74] = 175;
    bytes[75] = 2;
    bytes[76] = 26;
    bytes[77] = 104;
    bytes[78] = 247;
    bytes[79] = 7;
    bytes[80] = 81;
    bytes[81] = 26;

    let poo = ProofOfOrigin::from_bytes(&bytes).unwrap();
    // Verify it's a reference to the original bytes (zero-copy)
    let poo_addr = poo as *const ProofOfOrigin as usize;
    let bytes_addr = &bytes as *const [u8; 256] as usize;
    assert_eq!(
        poo_addr, bytes_addr,
        "from_bytes must return reference to input"
    );
}

// 1.3 CROSS-PLATFORM ENDIANNESS DETERMINISM
#[test]
fn test_le_timestamp_and_flags_exact_hex() {
    // Domain 1.3: timestamp=1700000000, flags=0x1234
    // Expected hex dump of the first 18 bytes:
    // [0]   version:     0x01
    // [1-2] flags (LE):  0x34, 0x12  (flags=0x1234 stored as LE u16)
    // [3-9] reserved:    0x00 x7
    // [10-17] timestamp: 0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00 (LE u64)
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = 0x01;
    poo.set_flags(0x1234);
    poo.timestamp = 1700000000u64.to_le_bytes();

    let bytes = poo.to_bytes();

    // version
    assert_eq!(bytes[0], 0x01, "version byte");
    // flags LE: 0x1234 → [0x34, 0x12]
    assert_eq!(bytes[1], 0x34, "flags byte 0 (LE low)");
    assert_eq!(bytes[2], 0x12, "flags byte 1 (LE high)");
    // reserved [3..9] = zeros
    for (i, &byte) in bytes[3..10].iter().enumerate() {
        assert_eq!(byte, 0x00, "reserved byte {} must be zero", i + 3);
    }
    // timestamp LE: 1700000000 = 0x6553F100
    // LE: 0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00
    assert_eq!(bytes[10], 0x00, "ts byte 0 (LE low)");
    assert_eq!(bytes[11], 0xF1, "ts byte 1");
    assert_eq!(bytes[12], 0x53, "ts byte 2");
    assert_eq!(bytes[13], 0x65, "ts byte 3");
    assert_eq!(bytes[14], 0x00, "ts byte 4");
    assert_eq!(bytes[15], 0x00, "ts byte 5");
    assert_eq!(bytes[16], 0x00, "ts byte 6");
    assert_eq!(bytes[17], 0x00, "ts byte 7 (LE high)");
}

// 1.4 SERIALIZATION IDENTITY (PROPERTY-BASED)
#[test]
fn test_from_bytes_to_bytes_identity_zeroed() {
    // Use a properly formed PoO with valid version and pubkey
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = 0x01;
    let valid_pk: [u8; 32] = [
        208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    poo.pubkey = valid_pk;
    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, poo.version);
    assert_eq!(parsed.timestamp, poo.timestamp);
    assert_eq!(parsed.hash, poo.hash);
    assert_eq!(parsed.pubkey, poo.pubkey);
    assert_eq!(parsed.signature, poo.signature);
    assert_eq!(parsed.reserved, poo.reserved);
    assert_eq!(parsed.reserved2, poo.reserved2);
}

#[test]
fn test_from_bytes_to_bytes_identity_signed_statement() {
    let secret = SecretKey::from_bytes(&[0xAB; 32]).unwrap();
    let stmt = build_statement(&secret, b"omega-crucible-domain-1", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, 0x01);
    assert_eq!(parsed.timestamp_u64(), 1700000000);
    assert_eq!(parsed.hash, stmt.hash_bytes);
    assert_eq!(parsed.pubkey, stmt.key_bytes);
    assert_eq!(parsed.signature, stmt.sig_bytes);
}

#[test]
fn test_statement_binary_statement_roundtrip() {
    let secret = SecretKey::from_bytes(&[0x42; 32]).unwrap();
    let stmt = build_statement(&secret, b"roundtrip-test", 1234567890).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();
    let parsed_poo = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let parsed_stmt = parsed_poo.to_statement().unwrap();
    assert_eq!(stmt.hash, parsed_stmt.hash);
    assert_eq!(stmt.time, parsed_stmt.time);
    assert_eq!(stmt.key_b64, parsed_stmt.key_b64);
    assert_eq!(stmt.sig_b64, parsed_stmt.sig_b64);
}
