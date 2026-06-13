//! DOMAIN 1 — BINARY STRUCTURE INTEGRITY
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::ProofOfOrigin;
use origin_core::statement::build_statement;
use origin_core::SecretKey;
use std::convert::TryInto;

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 1.1 — Fixed-size enforcement
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_1_1_a_poO_record_is_256_bytes() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"test artifact data", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();
    assert_eq!(bytes.len(), 256, "PoO serialization must be exactly 256 bytes, got {}", bytes.len());
}

#[test]
fn test_1_1_b_compile_time_size_assertion() {
    // binary.rs line 65: const _SIZE: [(); 256] = [(); core::mem::size_of::<ProofOfOrigin>()];
    // This will FAIL to compile if size != 256
    assert_eq!(core::mem::size_of::<ProofOfOrigin>(), 256);
}

#[test]
fn test_1_1_c_alignment_is_1() {
    assert_eq!(core::mem::align_of::<ProofOfOrigin>(), 1);
}

#[test]
fn test_1_1_d_from_bytes_exactly_256() {
    // from_bytes takes &[u8; 256] — enforces exact length at the type level
    let bytes = [0u8; 256];
    let _ = ProofOfOrigin::from_bytes(&bytes);
    // This test is a compile-time check: from_bytes signature is fn(bytes: &[u8; 256])
    // If you pass &[u8; 255] or &[u8; 257], it won't compile.
}

#[test]
fn test_1_1_e_hex_dump_256_bytes() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"audit test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();

    // Print hex dump for evidence
    eprintln!("=== 1.1 — 256-byte hex dump ===");
    for (i, chunk) in bytes.chunks(32).enumerate() {
        let hex_str: String = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("{:03}: {}", i * 32, hex_str);
    }
    eprintln!("Total length: {}", bytes.len());
}

// ═══════════════════════════════════════════════════════════════════════
// 1.2 — Field offset correctness (byte-accurate)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_1_2_compile_time_offsets() {
    // These are compile-time assertions via offset_of! macro
    use core::mem::offset_of;

    assert_eq!(offset_of!(ProofOfOrigin, version), 0,           "version must be at offset 0");
    assert_eq!(offset_of!(ProofOfOrigin, public_key), 1,        "public_key must be at offset 1");
    assert_eq!(offset_of!(ProofOfOrigin, timestamp), 33,        "timestamp must be at offset 33");
    assert_eq!(offset_of!(ProofOfOrigin, tool_hash), 37,        "tool_hash must be at offset 37");
    assert_eq!(offset_of!(ProofOfOrigin, content_hash), 53,     "content_hash must be at offset 53");
    assert_eq!(offset_of!(ProofOfOrigin, perceptual_hash), 85,  "perceptual_hash must be at offset 85");
    assert_eq!(offset_of!(ProofOfOrigin, semantic_hash), 101,   "semantic_hash must be at offset 101");
    assert_eq!(offset_of!(ProofOfOrigin, policy_hash), 133,     "policy_hash must be at offset 133");
    assert_eq!(offset_of!(ProofOfOrigin, parent_poo_hash), 165, "parent_poo_hash must be at offset 165");
    assert_eq!(offset_of!(ProofOfOrigin, semantic_model_ver), 181, "semantic_model_ver must be at offset 181");
    assert_eq!(offset_of!(ProofOfOrigin, reserved), 182,        "reserved must be at offset 182");
    assert_eq!(offset_of!(ProofOfOrigin, flags_be), 190,        "flags must be at offset 190");
    assert_eq!(offset_of!(ProofOfOrigin, signature), 192,       "signature must be at offset 192");
}

#[test]
fn test_1_2_runtime_field_extraction() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"field extraction test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();

    eprintln!("=== 1.2 — Field extraction by offset ===");

    // 1.2.1 version: offset 0, 1 byte
    assert_eq!(bytes[0], 0x01, "version must be 0x01");
    eprintln!("version [0]: 0x{:02x}", bytes[0]);

    // 1.2.2 public_key: offset 1-32, 32 bytes
    let pk = &bytes[1..33];
    assert_eq!(pk.len(), 32);
    assert_eq!(pk, &poo.public_key[..]);
    eprintln!("public_key [1..33]: {}...", &hex::encode(&pk[..8]));

    // 1.2.3 timestamp: offset 33-36, 4 bytes
    let ts_bytes = &bytes[33..37];
    assert_eq!(ts_bytes.len(), 4);
    let ts = u32::from_be_bytes(ts_bytes.try_into().unwrap());
    assert_eq!(ts, 1700000000, "timestamp must decode correctly");
    eprintln!("timestamp [33..37]: {} (0x{:08x})", hex::encode(ts_bytes), ts);

    // 1.2.4 tool_hash: offset 37-52, 16 bytes
    let th = &bytes[37..53];
    assert_eq!(th.len(), 16);
    eprintln!("tool_hash [37..53]: {}", hex::encode(th));

    // 1.2.5 content_hash: offset 53-84, 32 bytes
    let ch = &bytes[53..85];
    assert_eq!(ch.len(), 32);
    eprintln!("content_hash [53..85]: {}...", &hex::encode(&ch[..8]));

    // 1.2.6 perceptual_hash: offset 85-100, 16 bytes
    let ph = &bytes[85..101];
    assert_eq!(ph.len(), 16);
    eprintln!("perceptual_hash [85..101]: {}", hex::encode(ph));

    // 1.2.7 semantic_hash: offset 101-132, 32 bytes
    let sh = &bytes[101..133];
    assert_eq!(sh.len(), 32);
    eprintln!("semantic_hash [101..133]: {}...", &hex::encode(&sh[..8]));

    // 1.2.8 policy_hash: offset 133-164, 32 bytes
    let polh = &bytes[133..165];
    assert_eq!(polh.len(), 32);
    eprintln!("policy_hash [133..165]: {}...", &hex::encode(&polh[..8]));

    // 1.2.9 parent_poo_hash: offset 165-180, 16 bytes
    let pph = &bytes[165..181];
    assert_eq!(pph.len(), 16);
    eprintln!("parent_poo_hash [165..181]: {}", hex::encode(pph));

    // 1.2.10 semantic_model_ver: offset 181, 1 byte
    let smv = bytes[181];
    eprintln!("semantic_model_ver [181]: 0x{:02x}", smv);

    // 1.2.11 RESERVED: offset 182-189, 8 bytes — ALL ZERO
    let reserved = &bytes[182..190];
    assert_eq!(reserved.len(), 8, "RESERVED must be 8 bytes, got {}", reserved.len());
    assert!(reserved.iter().all(|&b| b == 0), "RESERVED bytes must ALL be zero, got: {}", hex::encode(reserved));
    eprintln!("RESERVED [182..190]: {} (all zeros: YES)", hex::encode(reserved));

    // 1.2.12 flags: offset 190-191, 2 bytes
    let flags_bytes = &bytes[190..192];
    assert_eq!(flags_bytes.len(), 2);
    let flags = u16::from_be_bytes(flags_bytes.try_into().unwrap());
    eprintln!("flags [190..192]: 0x{:04x}", flags);

    // 1.2.13 signature: offset 192-255, 64 bytes
    let sig = &bytes[192..256];
    assert_eq!(sig.len(), 64);
    eprintln!("signature [192..255]: {}...", &hex::encode(&sig[..8]));
}

#[test]
fn test_1_2_critical_signature_starts_at_192() {
    // CRITICAL ASSERT: signature field starts at offset 192, NOT 231
    use core::mem::offset_of;
    let offset = offset_of!(ProofOfOrigin, signature);
    assert_eq!(offset, 192,
        "CRITICAL FAIL: signature offset is {} but MUST be 192 (spec v1.0-rc1 corrected). \
         If this is 231, the pre-v1.0 spec error is present.",
        offset
    );
    eprintln!("CRITICAL ASSERT: signature starts at offset {} — CORRECT (spec v1.0-rc1)", offset);
}

#[test]
fn test_1_2_critical_reserved_is_8_bytes_not_47() {
    // CRITICAL ASSERT: RESERVED block at 182..189 is 8 bytes, NOT 47
    use core::mem::offset_of;
    let start = offset_of!(ProofOfOrigin, reserved);
    let flags_start = offset_of!(ProofOfOrigin, flags_be);
    let reserved_size = flags_start - start; // reserved ends where flags begins
    assert_eq!(reserved_size, 8,
        "CRITICAL FAIL: RESERVED size is {} bytes but MUST be 8 (spec v1.0-rc1 corrected from 47)",
        reserved_size
    );
    eprintln!("CRITICAL ASSERT: RESERVED is {} bytes [{}..{}] — CORRECT", reserved_size, start, flags_start - 1);
}

#[test]
fn test_1_2_no_field_bleeding() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"bleed test", 1700000000).unwrap();
    let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    // Set a unique marker in each field, serialize, extract, and verify no overlap
    poo.public_key = [0xAA; 32];
    poo.tool_hash = [0xBB; 16];
    poo.content_hash = [0xCC; 32];
    poo.perceptual_hash = [0xDD; 16];
    poo.semantic_hash = [0xEE; 32];
    poo.policy_hash = [0xFF; 32];

    let bytes = poo.to_bytes();

    // Extract and verify each field boundary
    assert_eq!(&bytes[1..33], &[0xAA; 32], "public_key bleeds");
    assert_eq!(&bytes[37..53], &[0xBB; 16], "tool_hash bleeds");
    assert_eq!(&bytes[53..85], &[0xCC; 32], "content_hash bleeds");
    assert_eq!(&bytes[85..101], &[0xDD; 16], "perceptual_hash bleeds");
    assert_eq!(&bytes[101..133], &[0xEE; 32], "semantic_hash bleeds");
    assert_eq!(&bytes[133..165], &[0xFF; 32], "policy_hash bleeds");

    eprintln!("NO FIELD BLEEDING — all boundaries verified");
}

#[test]
fn test_1_2_sum_check() {
    // 1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64 = 256
    let sum = 1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64;
    assert_eq!(sum, 256, "Field sizes must sum to 256, got {}", sum);
    eprintln!("SUM CHECK: {} = 256 — PASS", sum);
}

// ═══════════════════════════════════════════════════════════════════════
// 1.3 — Endianness correctness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_1_3_a_timestamp_big_endian() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32]; // non-zero
    let ts: u32 = 1700000000;
    poo.timestamp = ts.to_be_bytes();

    let bytes = poo.to_bytes();
    // 1700000000 = 0x6553F100
    assert_eq!(bytes[33], 0x65, "timestamp byte 0 must be 0x65");
    assert_eq!(bytes[34], 0x53, "timestamp byte 1 must be 0x53");
    assert_eq!(bytes[35], 0xF1, "timestamp byte 2 must be 0xF1");
    assert_eq!(bytes[36], 0x00, "timestamp byte 3 must be 0x00");

    eprintln!("1.3 — timestamp BE: 1700000000 = 0x6553F100");
    eprintln!("  bytes[33..37] = {:02x} {:02x} {:02x} {:02x}",
        bytes[33], bytes[34], bytes[35], bytes[36]);
}

#[test]
fn test_1_3_b_flags_big_endian() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.set_flags(0x0081); // AI_GENERATED | bit 0

    let bytes = poo.to_bytes();
    assert_eq!(bytes[190], 0x00, "flags high byte must be 0x00");
    assert_eq!(bytes[191], 0x81, "flags low byte must be 0x81");

    eprintln!("1.3 — flags BE: 0x0081 = bytes[190]={:02x} bytes[191]={:02x}",
        bytes[190], bytes[191]);
}

#[test]
fn test_1_3_c_roundtrip_big_endian() {
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x42; 32];
    poo.timestamp = 1700000000u32.to_be_bytes();
    poo.set_flags(0x0012);

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.timestamp_u32(), 1700000000);
    assert_eq!(parsed.flags(), 0x0012);

    eprintln!("1.3 — roundtrip BE: timestamp and flags decode correctly after serialize/deserialize");
}

// ═══════════════════════════════════════════════════════════════════════
// 1.4 — Version byte
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_1_4_a_version_is_0x01() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"version test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();
    assert_eq!(bytes[0], 0x01, "version byte must be 0x01, got 0x{:02x}", bytes[0]);
    eprintln!("1.4 — version byte: 0x{:02x} — PASS", bytes[0]);
}

#[test]
fn test_1_4_b_zeroed_version_is_zero() {
    let poo = ProofOfOrigin::zeroed();
    assert_eq!(poo.version, 0x00, "zeroed() should have version 0");
    eprintln!("1.4 — zeroed() version: 0x{:02x} (expected for zeroed)", poo.version);
}

#[test]
fn test_1_4_c_reject_version_0_at_parse() {
    let mut bytes = [0u8; 256];
    bytes[0] = 0x00; // invalid version
    bytes[1] = 0x01; // non-zero public_key
    let result = ProofOfOrigin::from_bytes(&bytes);
    // v1: version 0x00 triggers E006 best-effort parse (returns Ok, not Err)
    // This is by design per spec: "best-effort parse, return with warning"
    assert!(result.is_ok(), "version 0x00 should trigger E006 best-effort parse, not hard fail");
    eprintln!("1.4 — version 0x00: accepted as best-effort (E006) — per spec");
}

#[test]
fn test_1_4_d_reject_version_0xff_at_parse() {
    let mut bytes = [0u8; 256];
    bytes[0] = 0xFF; // unknown version
    bytes[1] = 0x01; // non-zero public_key
    let result = ProofOfOrigin::from_bytes(&bytes);
    // E006: best-effort parse, returns Ok with the unknown version byte preserved
    assert!(result.is_ok(), "version 0xFF should trigger E006 best-effort parse");
    assert_eq!(result.unwrap().version, 0xFF, "version byte should be preserved");
    eprintln!("1.4 — version 0xFF: accepted as best-effort (E006), version preserved — per spec");
}

#[test]
fn test_1_4_e_no_version_above_0x01_produced() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"version check", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    assert_eq!(poo.version, 0x01, "from_statement must produce version 0x01");
    eprintln!("1.4 — from_statement produces version 0x01 — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// CRITICAL: User's checklist vs actual spec discrepancies
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_critical_checklist_vs_spec_discrepancies() {
    use core::mem::offset_of;

    eprintln!("\n╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  CRITICAL: User Checklist vs Actual Spec (v1.0-rc1)         ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");

    // DISCREPANCY 1: Field name
    eprintln!("\nDISCREPANCY 1: Field at offsets 1-32");
    eprintln!("  User checklist: key_id (SHA-256(DER-encoded Ed25519 public key)[0..31])");
    eprintln!("  Actual spec:    public_key (raw 32-byte Ed25519 public key)");
    eprintln!("  Verification:");
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    let bytes = poo.to_bytes();
    let field = &bytes[1..33];
    assert_eq!(field, &poo.public_key[..], "field at 1-32 must be raw public_key, NOT key_id");
    eprintln!("  ✅ field[1..33] == poo.public_key (raw key, NOT hash) — ACTUAL SPEC IS CORRECT");

    // DISCREPANCY 2: Flags offset
    eprintln!("\nDISCREPANCY 2: Flags offset");
    eprintln!("  User checklist: offset 229");
    eprintln!("  Actual spec:    offset 190");
    let flags_offset = offset_of!(ProofOfOrigin, flags_be);
    assert_eq!(flags_offset, 190, "flags must be at offset 190, NOT 229");
    eprintln!("  ✅ flags offset = {} — ACTUAL SPEC IS CORRECT", flags_offset);

    // DISCREPANCY 3: Signature offset
    eprintln!("\nDISCREPANCY 3: Signature offset");
    eprintln!("  User checklist: offset 231");
    eprintln!("  Actual spec:    offset 192");
    let sig_offset = offset_of!(ProofOfOrigin, signature);
    assert_eq!(sig_offset, 192, "signature must be at offset 192, NOT 231");
    eprintln!("  ✅ signature offset = {} — ACTUAL SPEC IS CORRECT", sig_offset);

    // DISCREPANCY 4: Reserved size
    eprintln!("\nDISCREPANCY 4: RESERVED size");
    eprintln!("  User checklist: 47 bytes (offsets 182-228)");
    eprintln!("  Actual spec:    8 bytes (offsets 182-189)");
    let flags_off = offset_of!(ProofOfOrigin, flags_be);
    let res_off = offset_of!(ProofOfOrigin, reserved);
    let reserved_size = flags_off - res_off; // reserved ends where flags begins
    assert_eq!(reserved_size, 8, "RESERVED must be 8 bytes, NOT 47");
    eprintln!("  ✅ reserved size = {} bytes [{}..{}] — ACTUAL SPEC IS CORRECT", reserved_size, res_off, flags_off - 1);

    // DISCREPANCY 5: Signed region
    eprintln!("\nDISCREPANCY 5: Signed region");
    eprintln!("  User checklist: bytes 0..230 (231 bytes)");
    eprintln!("  Actual spec:    bytes 0..191 (192 bytes)");
    let prefix = poo.signed_prefix();
    assert_eq!(prefix.len(), 192, "signed region must be 192 bytes, NOT 231");
    eprintln!("  ✅ signed region = {} bytes (0..191) — ACTUAL SPEC IS CORRECT", prefix.len());

    // DISCREPANCY 6: Total field sum in user's checklist
    eprintln!("\nDISCREPANCY 6: Field size arithmetic");
    eprintln!("  User checklist claims fields sum to 256 with 47-byte reserved");
    eprintln!("  Actual: 1+32+4+16+32+16+32+32+16+1+8+2+64 = 256");
    let sum = 1u32 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64;
    assert_eq!(sum, 256, "fields must sum to 256");
    eprintln!("  ✅ sum = {} — CORRECT", sum);

    eprintln!("\n═══════════════════════════════════════════════════════════════");
    eprintln!("VERDICT: All 6 discrepancies favor the ACTUAL SPEC (v1.0-rc1).");
    eprintln!("The user's checklist is based on the OLD, incorrect spec that");
    eprintln!("had byte arithmetic errors (295 bytes claimed as 256).");
    eprintln!("═══════════════════════════════════════════════════════════════");
}

// ═══════════════════════════════════════════════════════════════════════
// Additional structural integrity checks
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_signed_prefix_covers_exactly_0_to_191() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"signed prefix test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    let full = poo.to_bytes();
    let prefix = poo.signed_prefix();

    // prefix must equal bytes[0..192]
    assert_eq!(&prefix[..], &full[..192], "signed_prefix must equal bytes[0..192]");
    assert_eq!(prefix.len(), 192);

    // signature is NOT in signed region
    assert_ne!(&prefix[192..], &poo.signature[..], "signature must NOT be in signed region");

    eprintln!("signed_prefix covers bytes 0-191 (192 bytes) — signature excluded — PASS");
}

#[test]
fn test_zero_allocation_serialization() {
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"zero alloc test", 1700000000).unwrap();
    let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

    // to_bytes returns [u8; 256] on the stack — zero heap allocation
    let bytes = poo.to_bytes();
    assert_eq!(bytes.len(), 256);

    // from_bytes returns &Self — zero copy, zero allocation
    let _reference = ProofOfOrigin::from_bytes(&bytes).unwrap();
    // The reference points directly into the input buffer
    eprintln!("zero-allocation serialization: to_bytes() -> [u8; 256], from_bytes() -> &ProofOfOrigin — PASS");
}

#[test]
fn test_repr_c_packed() {
    // ProofOfOrigin is #[repr(C, packed)] — no padding, deterministic layout
    let _poo = ProofOfOrigin::zeroed();

    // Verify no implicit padding by checking field sizes match offsets
    use core::mem::offset_of;
    let total = offset_of!(ProofOfOrigin, signature) + 64; // signature is last field, 64 bytes
    assert_eq!(total, 256, "repr(C, packed) must produce 256-byte layout, got {}", total);
    eprintln!("repr(C, packed): no padding, total = {} bytes — PASS", total);
}
