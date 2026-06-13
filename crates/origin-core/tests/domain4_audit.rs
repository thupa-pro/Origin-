//! DOMAIN 4 — FLAGS BITMASK CORRECTNESS
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1
//!
//! All 8 flags defined in §6.1.2 are implemented and tested.

use origin_core::binary::ProofOfOrigin;
use origin_core::statement::build_statement;
use origin_core::SecretKey;

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 4.1 — Bit definitions (ALL 8 FLAGS)
// ═══════════════════════════════════════════════════════════════════════
//
// FLAG_HW_ATTESTED:   0x0001  (bit 0) — Signature created inside a TEE
// FLAG_REVOCABLE:     0x0002  (bit 1) — Creator permits IVG-based revocation
// FLAG_ZK_READY:      0x0004  (bit 2) — ZK proof available
// FLAG_PQ_READY:      0x0008  (bit 3) — ML-DSA key registered
// FLAG_MULTI_AUTHOR:  0x0010  (bit 4) — BLS aggregate signature
// FLAG_PRIVATE_POLICY:0x0020  (bit 5) — Policy content encrypted
// FLAG_OFFLINE_BUNDLE:0x0040  (bit 6) — Offline bundle available
// FLAG_AI_GENERATED:  0x0080  (bit 7) — Human Content Score < 0.5

#[test]
fn test_4_1_a_hw_attested_0x0001() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0001);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0001, 0x0001);
    assert!(poo.is_hw_attested());
    eprintln!("4.1  HW_ATTESTED   0x0001  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_b_revocable_0x0002() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0002);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0002, 0x0002);
    assert!(poo.is_revocable());
    eprintln!("4.1  REVOCABLE     0x0002  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_c_zk_ready_0x0004() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0004);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0004, 0x0004);
    assert!(poo.is_zk_ready());
    eprintln!("4.1  ZK_READY      0x0004  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_d_pq_ready_0x0008() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0008);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0008, 0x0008);
    assert!(poo.is_pq_ready());
    eprintln!("4.1  PQ_READY      0x0008  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_e_multi_author_0x0010() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0010);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0010, 0x0010);
    assert!(poo.is_multi_author());
    eprintln!("4.1  MULTI_AUTHOR  0x0010  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_f_private_policy_0x0020() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0020);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0020, 0x0020);
    assert!(poo.is_private_policy());
    eprintln!("4.1  PRIVATE_POLICY 0x0020  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_g_offline_bundle_0x0040() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0040);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0040, 0x0040);
    assert!(poo.is_offline_bundle());
    eprintln!("4.1  OFFLINE_BUNDLE 0x0040  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_h_ai_generated_0x0080() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0080);

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);

    assert_eq!(flags & 0x0080, 0x0080);
    assert!(poo.is_ai_generated());
    eprintln!("4.1  AI_GENERATED  0x0080  flags=0x{:04x} — PASS", flags);
}

#[test]
fn test_4_1_i_all_flags_independently_settable() {
    let flags_to_test = [
        (0x0001, "HW_ATTESTED"),
        (0x0002, "REVOCABLE"),
        (0x0004, "ZK_READY"),
        (0x0008, "PQ_READY"),
        (0x0010, "MULTI_AUTHOR"),
        (0x0020, "PRIVATE_POLICY"),
        (0x0040, "OFFLINE_BUNDLE"),
        (0x0080, "AI_GENERATED"),
    ];

    for (flag, name) in &flags_to_test {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.public_key = [0x01; 32];
        poo.set_flags(*flag);

        let bytes = poo.to_bytes();
        let actual = u16::from_be_bytes([bytes[190], bytes[191]]);
        assert_eq!(actual, *flag,
            "{} (0x{:04x}) must be the only flag set, got 0x{:04x}", name, flag, actual);

        assert!(poo.has_flag(*flag), "{} helper must return true", name);

        // Verify clearing
        let mut poo2 = poo;
        poo2.set_flags(0x0000);
        assert!(!poo2.has_flag(*flag), "{} must be clearable", name);
    }
    eprintln!("4.1  All 8 flags independently settable and clearable — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 4.2 — Reserved bits (8..15 must be zero in v1)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_4_2_a_reserved_bits_rejected() {
    let mut bytes = [0u8; 256];
    bytes[0] = PROTOCOL_VERSION;
    bytes[1] = 0x01;

    // Set bit 8 (reserved)
    bytes[190] = 0x01;
    bytes[191] = 0x00;

    let result = ProofOfOrigin::from_bytes(&bytes);
    assert!(result.is_err(), "Reserved bit 8 must be rejected");
    eprintln!("4.2  Reserved bit 8 rejected: PASS");
}

#[test]
fn test_4_2_b_reserved_bits_mask() {
    let test_values: [(u16, &str); 8] = [
        (0x0100, "bit 8"),
        (0x0200, "bit 9"),
        (0x0400, "bit 10"),
        (0x0800, "bit 11"),
        (0x1000, "bit 12"),
        (0x2000, "bit 13"),
        (0x4000, "bit 14"),
        (0x8000, "bit 15"),
    ];

    for (val, name) in &test_values {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01;
        let flag_be = (*val).to_be_bytes();
        bytes[190] = flag_be[0];
        bytes[191] = flag_be[1];

        let result = ProofOfOrigin::from_bytes(&bytes);
        assert!(result.is_err(),
            "Reserved {} (0x{:04x}) must be rejected", name, val);
    }
    eprintln!("4.2  All 8 reserved bits (8-15) rejected — PASS");
}

#[test]
fn test_4_2_c_valid_flags_pass() {
    // All combinations of 8 flags = 2^8 = 256 combinations
    // Test a representative set including all individual flags and key combinations
    let valid_flags: Vec<u16> = vec![
        0x0000, 0x0001, 0x0002, 0x0004, 0x0008,
        0x0010, 0x0020, 0x0040, 0x0080,
        0x0003, 0x0007, 0x000F, 0x0011, 0x001F,
        0x0081, 0x0093, 0x00FF, // All 8 flags
    ];

    for flags in &valid_flags {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01;
        let flag_be = flags.to_be_bytes();
        bytes[190] = flag_be[0];
        bytes[191] = flag_be[1];

        let result = ProofOfOrigin::from_bytes(&bytes);
        assert!(result.is_ok(),
            "Valid flags 0x{:04x} must be accepted, got error: {:?}",
            flags, result.err());
    }
    eprintln!("4.2  All valid flag combinations accepted — PASS");
}

#[test]
fn test_4_2_d_reserved_bits_not_in_signed_region() {
    use core::mem::offset_of;
    let flags_offset = offset_of!(ProofOfOrigin, flags_be);
    assert!(flags_offset < 192,
        "flags at offset {} must be inside signed region (< 192)", flags_offset);
    eprintln!("4.2  Flags at offset {} — inside signed region (< 192) — PASS", flags_offset);
}

// ═══════════════════════════════════════════════════════════════════════
// 4.3 — Flag combinations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_4_3_a_multi_author_and_hw_attested() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0011); // HW_ATTESTED | MULTI_AUTHOR

    assert!(poo.is_hw_attested());
    assert!(poo.is_multi_author());
    assert!(!poo.is_revocable());
    assert!(!poo.is_ai_generated());

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);
    assert_eq!(flags, 0x0011);
    eprintln!("4.3  MULTI_AUTHOR | HW_ATTESTED = 0x0011 — PASS");
}

#[test]
fn test_4_3_b_all_flags_combined() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x00FF); // All 8 flags

    assert!(poo.is_hw_attested());
    assert!(poo.is_revocable());
    assert!(poo.is_zk_ready());
    assert!(poo.is_pq_ready());
    assert!(poo.is_multi_author());
    assert!(poo.is_private_policy());
    assert!(poo.is_offline_bundle());
    assert!(poo.is_ai_generated());

    let bytes = poo.to_bytes();
    let flags = u16::from_be_bytes([bytes[190], bytes[191]]);
    assert_eq!(flags, 0x00FF);
    eprintln!("4.3  All 8 flags combined = 0x00FF — PASS");
}

#[test]
fn test_4_3_c_flag_roundtrip() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x00FF);

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.flags(), 0x00FF);
    eprintln!("4.3  Flags survive binary roundtrip — PASS");
}

#[test]
fn test_4_3_d_no_mutual_exclusions_enforced() {
    // The spec defines no mutual exclusions. Verify all 8 flags can coexist.
    let flag_values = [
        0x0001, 0x0002, 0x0004, 0x0008,
        0x0010, 0x0020, 0x0040, 0x0080,
    ];

    // Test all 2^8 = 256 combinations
    for mask in 0u16..256 {
        let mut flags = 0u16;
        for (i, &flag) in flag_values.iter().enumerate() {
            if mask & (1 << i) != 0 {
                flags |= flag;
            }
        }

        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01;
        let flag_be = flags.to_be_bytes();
        bytes[190] = flag_be[0];
        bytes[191] = flag_be[1];

        let result = ProofOfOrigin::from_bytes(&bytes);
        assert!(result.is_ok(),
            "Flag combination 0x{:04x} (mask={}) must be accepted",
            flags, mask);
    }
    eprintln!("4.3  All 256 flag combinations accepted (no mutual exclusions) — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 4.4 — AI_GENERATED flag trigger
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_4_4_a_ai_generated_is_caller_controlled() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"ai test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    assert!(!poo.is_ai_generated(),
        "build_statement must NOT auto-set AI_GENERATED");
    eprintln!("4.4  AI_GENERATED is caller-controlled — PASS");
}

#[test]
fn test_4_4_b_ai_generated_can_be_set() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0080);
    assert!(poo.is_ai_generated());
    eprintln!("4.4  AI_GENERATED can be set — PASS");
}

#[test]
fn test_4_4_c_ai_generated_can_be_cleared() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0080);
    assert!(poo.is_ai_generated());

    poo.set_flags(0x0000);
    assert!(!poo.is_ai_generated());
    eprintln!("4.4  AI_GENERATED can be cleared — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// Additional flag checks
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_4_e_flag_offset_is_190() {
    use core::mem::offset_of;
    let offset = offset_of!(ProofOfOrigin, flags_be);
    assert_eq!(offset, 190);
    eprintln!("4.E  flags offset = 190 — PASS");
}

#[test]
fn test_4_f_flags_are_big_endian() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x00FF);

    let bytes = poo.to_bytes();
    assert_eq!(bytes[190], 0x00);
    assert_eq!(bytes[191], 0xFF);

    let decoded = u16::from_be_bytes([bytes[190], bytes[191]]);
    assert_eq!(decoded, 0x00FF);
    eprintln!("4.F  Flags stored big-endian — PASS");
}

#[test]
fn test_4_g_zero_flags_accepted() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0000);

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.flags(), 0x0000);
    assert!(!parsed.is_hw_attested());
    assert!(!parsed.is_revocable());
    assert!(!parsed.is_zk_ready());
    assert!(!parsed.is_pq_ready());
    assert!(!parsed.is_multi_author());
    assert!(!parsed.is_private_policy());
    assert!(!parsed.is_offline_bundle());
    assert!(!parsed.is_ai_generated());
    eprintln!("4.G  Zero flags (0x0000) accepted — PASS");
}

#[test]
fn test_4_h_flags_byte_layout_in_256() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x00FF);

    let bytes = poo.to_bytes();
    assert_eq!(bytes[190], 0x00);
    assert_eq!(bytes[191], 0xFF);

    let sum = 1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64;
    assert_eq!(sum, 256);
    eprintln!("4.H  Flags at bytes 190-191 in 256-byte buffer — PASS");
}
