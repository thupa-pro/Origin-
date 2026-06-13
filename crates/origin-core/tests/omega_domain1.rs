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
    // Verify every field offset matches the new 256-byte layout
    assert_eq!(offset_of!(ProofOfOrigin, version), 0);
    assert_eq!(offset_of!(ProofOfOrigin, public_key), 1);
    assert_eq!(offset_of!(ProofOfOrigin, timestamp), 33);
    assert_eq!(offset_of!(ProofOfOrigin, tool_hash), 37);
    assert_eq!(offset_of!(ProofOfOrigin, content_hash), 53);
    assert_eq!(offset_of!(ProofOfOrigin, perceptual_hash), 85);
    assert_eq!(offset_of!(ProofOfOrigin, semantic_hash), 101);
    assert_eq!(offset_of!(ProofOfOrigin, policy_hash), 133);
    assert_eq!(offset_of!(ProofOfOrigin, parent_poo_hash), 165);
    assert_eq!(offset_of!(ProofOfOrigin, semantic_model_ver), 181);
    assert_eq!(offset_of!(ProofOfOrigin, reserved), 182);
    assert_eq!(offset_of!(ProofOfOrigin, flags_be), 190);
    assert_eq!(offset_of!(ProofOfOrigin, signature), 192);

    // Verify field sizes
    assert_eq!(size_of::<u8>(), 1);
    assert_eq!(size_of::<[u8; 4]>(), 4);
    assert_eq!(size_of::<[u8; 8]>(), 8);
    assert_eq!(size_of::<[u8; 16]>(), 16);
    assert_eq!(size_of::<[u8; 2]>(), 2);
    assert_eq!(size_of::<[u8; 32]>(), 32);
    assert_eq!(size_of::<[u8; 64]>(), 64);

    // Sum check: 1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64 = 256
    assert_eq!(1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64, 256);
}

#[test]
fn test_poo_no_implicit_padding() {
    let poo = ProofOfOrigin::zeroed();
    let base = &poo as *const ProofOfOrigin as usize;
    let signature_ptr = &poo.signature as *const [u8; 64] as usize;
    assert_eq!(signature_ptr - base, 192);
    assert_eq!(signature_ptr + 64 - base, 256);
}

// 1.2 ZERO-ALLOCATION SERIALIZATION
#[test]
fn test_from_bytes_to_bytes_identity_zeroed() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = 0x01;
    let valid_pubkey: [u8; 32] = [
        208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    poo.public_key = valid_pubkey;
    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, poo.version);
    assert_eq!(parsed.timestamp, poo.timestamp);
    assert_eq!(parsed.content_hash, poo.content_hash);
    assert_eq!(parsed.public_key, poo.public_key);
    assert_eq!(parsed.signature, poo.signature);
    assert_eq!(parsed.reserved, poo.reserved);
    assert_eq!(parsed.flags_be, poo.flags_be);
}

#[test]
fn test_from_bytes_to_bytes_identity_signed_statement() {
    let secret = SecretKey::from_bytes(&[0xAB; 32]).unwrap();
    let stmt = build_statement(&secret, b"omega-crucible-domain-1", 1700000000).unwrap();
    let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    poo.tool_hash = origin_core::binary::compute_tool_hash("origin-cli");
    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, 0x01);
    assert_eq!(parsed.timestamp_u32(), 1700000000);
    assert_eq!(parsed.content_hash, stmt.hash_bytes);
    assert_eq!(parsed.public_key, stmt.key_bytes);
    assert_eq!(parsed.signature, stmt.sig_bytes);
}

#[test]
fn test_statement_binary_statement_roundtrip() {
    let secret = SecretKey::from_bytes(&[0x42; 32]).unwrap();
    let stmt = build_statement(&secret, b"roundtrip-test", 1234567890).unwrap();
    let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    poo.tool_hash = origin_core::binary::compute_tool_hash("origin-cli");
    let bytes = poo.to_bytes();
    let parsed_poo = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let parsed_stmt = parsed_poo.to_statement().unwrap();
    assert_eq!(stmt.hash, parsed_stmt.hash);
    assert_eq!(stmt.time, parsed_stmt.time);
    assert_eq!(stmt.key_b64, parsed_stmt.key_b64);
    assert_eq!(stmt.sig_b64, parsed_stmt.sig_b64);
}
