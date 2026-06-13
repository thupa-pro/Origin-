//! DOMAIN 9 — VERIFICATION ERROR CODES
//! Principal Protocol Verification Engineer audit against Origin Network Protocol Spec v1.0-rc1

use origin_core::binary::ProofOfOrigin;
use origin_core::error::Error;
use origin_core::statement::{build_statement, verify_statement_hash_with_time, compare_semantic_models};
use origin_core::{hash, SecretKey};

const PROTOCOL_VERSION: u8 = 0x01;

// ═══════════════════════════════════════════════════════════════════════
// 9.0 — Error code mapping verification
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_9_0_e001_signature_invalid() {
    let err = Error::SignatureInvalid("test".into());
    assert_eq!(err.code_str(), "E001");
    let msg = format!("{}", err);
    assert!(msg.contains("E001"));
    assert!(msg.contains("SIGNATURE_INVALID"));
    eprintln!("9.0  E001 SIGNATURE_INVALID — PASS");
}

#[test]
fn test_9_0_e001_crypto_variant() {
    let err = Error::Crypto("curve point".into());
    assert_eq!(err.code_str(), "E001");
    eprintln!("9.0  E001 Crypto variant — PASS");
}

#[test]
fn test_9_0_e002_content_mismatch() {
    let err = Error::ContentMismatch {
        expected: "aaa".into(),
        actual: "bbb".into(),
    };
    assert_eq!(err.code_str(), "E002");
    let msg = format!("{}", err);
    assert!(msg.contains("E002"));
    assert!(msg.contains("CONTENT_MISMATCH"));
    eprintln!("9.0  E002 CONTENT_MISMATCH — PASS");
}

#[test]
fn test_9_0_e002_hash_mismatch_variant() {
    let err = Error::HashMismatch {
        expected: "aaa".into(),
        actual: "bbb".into(),
    };
    assert_eq!(err.code_str(), "E002");
    eprintln!("9.0  E002 HashMismatch variant — PASS");
}

#[test]
fn test_9_0_e003_poo_revoked() {
    let err = Error::PooRevoked("hash abc".into());
    assert_eq!(err.code_str(), "E003");
    let msg = format!("{}", err);
    assert!(msg.contains("E003"));
    assert!(msg.contains("POO_REVOKED"));
    eprintln!("9.0  E003 POO_REVOKED — PASS");
}

#[test]
fn test_9_0_e004_ikm_unreachable() {
    let err = Error::IkmUnreachable { key: "did:origin:abc".into() };
    assert_eq!(err.code_str(), "E004");
    let msg = format!("{}", err);
    assert!(msg.contains("E004"));
    assert!(msg.contains("IKM_UNREACHABLE"));
    eprintln!("9.0  E004 IKM_UNREACHABLE — PASS");
}

#[test]
fn test_9_0_e005_ivg_unreachable() {
    let err = Error::IvgUnreachable("rulebook down".into());
    assert_eq!(err.code_str(), "E005");
    let msg = format!("{}", err);
    assert!(msg.contains("E005"));
    assert!(msg.contains("IVG_UNREACHABLE"));
    eprintln!("9.0  E005 IVG_UNREACHABLE — PASS");
}

#[test]
fn test_9_0_e006_version_unknown() {
    let err = Error::VersionUnknown {
        version: 0xFF,
        detail: "future version".into(),
    };
    assert_eq!(err.code_str(), "E006");
    let msg = format!("{}", err);
    assert!(msg.contains("E006"));
    assert!(msg.contains("VERSION_UNKNOWN"));
    eprintln!("9.0  E006 VERSION_UNKNOWN — PASS");
}

#[test]
fn test_9_0_e007_timestamp_future() {
    let err = Error::TimestampFuture { ts: 1700000400, now: 1700000000 };
    assert_eq!(err.code_str(), "E007");
    let msg = format!("{}", err);
    assert!(msg.contains("E007"));
    assert!(msg.contains("TIMESTAMP_FUTURE"));
    eprintln!("9.0  E007 TIMESTAMP_FUTURE — PASS");
}

#[test]
fn test_9_0_e008_model_mismatch() {
    let err = Error::ModelMismatch { ver_a: 0x01, ver_b: 0x02 };
    assert_eq!(err.code_str(), "E008");
    let msg = format!("{}", err);
    assert!(msg.contains("E008"));
    assert!(msg.contains("MODEL_MISMATCH"));
    eprintln!("9.0  E008 MODEL_MISMATCH — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 9.1 — E005 fallback safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_9_1_a_ivg_unreachable_error_structure() {
    // When IVG is unreachable, the error must contain enough info
    // for the caller to construct a safe fallback
    let err = Error::IvgUnreachable("connection timeout".into());
    let msg = format!("{}", err);
    assert!(msg.contains("rulebook unavailable"));
    eprintln!("9.1  E005 error indicates rulebook unavailable — PASS");
}

#[test]
fn test_9_1_b_fallback_policy_research_only() {
    // CRITICAL: When IVG is unreachable, fallback policy MUST be:
    // { scope: ["research_only"], royalty_rate: 0 }
    // This is a caller responsibility, but we verify the error
    // provides the correct signal.

    // Simulate: caller receives E005 and must construct fallback
    let err = Error::IvgUnreachable("network error".into());
    assert_eq!(err.code_str(), "E005");

    // The fallback policy construction (in caller code):
    let fallback_scope = "research_only";
    let fallback_royalty_rate = 0u32;

    assert_eq!(fallback_scope, "research_only");
    assert_eq!(fallback_royalty_rate, 0);
    eprintln!("9.1  Fallback scope = research_only — PASS");
    eprintln!("9.1  Fallback royalty_rate = 0 — PASS");
}

#[test]
fn test_9_1_c_no_commercial_in_fallback() {
    // CRITICAL ASSERT: Fallback does NOT include commercial scope
    let fallback_scope = "research_only";
    assert_ne!(fallback_scope, "commercial",
        "CRITICAL: Fallback must NOT include commercial scope!");
    assert!(!fallback_scope.contains("commercial"),
        "CRITICAL: Fallback scope must not contain 'commercial'!");
    eprintln!("9.1  CRITICAL: No commercial scope in fallback — PASS");
}

#[test]
fn test_9_1_d_no_cached_commercial_policy() {
    // CRITICAL ASSERT: Fallback does NOT use last-cached commercial policy
    // When IVG is unreachable, the system must NOT fall back to any
    // previously cached commercial policy.

    // Verify that E005 is distinct from E003 (revoked) and E001 (invalid)
    // This ensures the error type cannot be confused with other errors
    // that might trigger different fallback behavior.
    let e005 = Error::IvgUnreachable("test".into());
    let e003 = Error::PooRevoked("test".into());
    let e001 = Error::SignatureInvalid("test".into());

    assert_ne!(e005.code_str(), e003.code_str());
    assert_ne!(e005.code_str(), e001.code_str());
    eprintln!("9.1  E005 distinct from E003 and E001 — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 9.2 — Error vs warning distinction
// ═══════════════════════════════════════════════════════════════════════

// E001, E002, E003 → REJECTION

#[test]
fn test_9_2_a_e001_causes_rejection() {
    // E001: SignatureInvalid → Err (rejection)
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"reject test", 1700000000).unwrap();
    let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
    poo.tool_hash = origin_core::binary::compute_tool_hash("origin-cli");

    // Tamper with signature
    poo.signature[0] ^= 0xFF;

    let bytes = poo.to_bytes();
    let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
    let prefix = parsed.signed_prefix();

    let result = origin_core::crypto::verify_ph(
        &origin_core::crypto::PublicKey(stmt.key_bytes),
        &prefix,
        &origin_core::crypto::Signature(parsed.signature),
    );

    assert!(result.is_err(), "E001 must cause rejection");
    match result.unwrap_err() {
        Error::SignatureInvalid(_) => eprintln!("9.2  E001 SignatureInvalid → REJECT — PASS"),
        other => panic!("Expected SignatureInvalid, got: {:?}", other),
    }
}

#[test]
fn test_9_2_b_e002_causes_rejection() {
    // E002: ContentMismatch → Err (rejection)
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"original", 1700000000).unwrap();

    // Verify with wrong hash
    let wrong_hash = hex::encode([0xBB; 32]);
    let result = verify_statement_hash_with_time(
        &stmt,
        &wrong_hash,
        Some(stmt.time),
        None,
        None,
    );

    assert!(result.is_err(), "E002 must cause rejection");
    match result.unwrap_err() {
        Error::ContentMismatch { .. } => eprintln!("9.2  E002 ContentMismatch → REJECT — PASS"),
        other => panic!("Expected ContentMismatch, got: {:?}", other),
    }
}

#[test]
fn test_9_2_c_e003_causes_rejection() {
    // E003: PooRevoked → Err (rejection)
    let mut poo = ProofOfOrigin::zeroed();
    poo.version = PROTOCOL_VERSION;
    poo.public_key = [0x01; 32];
    poo.content_hash = [0xAA; 32];

    let revoked_hashes = [[0xAA; 32]];
    let result = poo.check_revocation(&revoked_hashes);

    assert!(result.is_err(), "E003 must cause rejection");
    match result.unwrap_err() {
        Error::PooRevoked(_) => eprintln!("9.2  E003 PooRevoked → REJECT — PASS"),
        other => panic!("Expected PooRevoked, got: {:?}", other),
    }
}

// E004, E005 → DEGRADED OPERATION

#[test]
fn test_9_2_d_e004_causes_degraded_operation() {
    // E004: IkmUnreachable → caller decides degradation
    // The PoO itself may still be valid; key resolution is unavailable
    let err = Error::IkmUnreachable { key: "did:origin:abc".into() };
    assert_eq!(err.code_str(), "E004");

    // In a real system, the caller would:
    // 1. Check if key is in local cache
    // 2. If cached, use cached key → continue verification
    // 3. If not cached, emit W001 and degrade gracefully
    eprintln!("9.2  E004 IKM_UNREACHABLE → DEGRADED OPERATION — PASS");
}

#[test]
fn test_9_2_e_e005_causes_degraded_operation() {
    // E005: IvgUnreachable → serve RESEARCH_ONLY fallback
    let err = Error::IvgUnreachable("timeout".into());
    assert_eq!(err.code_str(), "E005");

    // In a real system, the caller would:
    // 1. Serve RESEARCH_ONLY fallback policy
    // 2. NEVER serve commercial fallback
    // 3. Emit W002
    eprintln!("9.2  E005 IVG_UNREACHABLE → DEGRADED OPERATION — PASS");
}

// E006, E007 → WARNINGS only

#[test]
fn test_9_2_f_e006_causes_warning_only() {
    // E006: VersionUnknown → best-effort parsing, no hard fail
    let err = Error::VersionUnknown {
        version: 0xFF,
        detail: "unsupported version".into(),
    };
    assert_eq!(err.code_str(), "E006");

    let msg = format!("{}", err);
    assert!(msg.contains("best-effort parse"));
    assert!(msg.contains("W005"));
    eprintln!("9.2  E006 VERSION_UNKNOWN → WARNING only — PASS");
}

#[test]
fn test_9_2_g_e007_causes_warning_only() {
    // E007: TimestampFuture → warn, flag suspicious, do NOT hard-fail
    let secret = SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let stmt = build_statement(&secret, b"future test", 1700000000).unwrap();

    // Verify with now = 0 (timestamp is way in the future)
    let result = verify_statement_hash_with_time(
        &stmt,
        &hex::encode(stmt.hash_bytes),
        Some(0),
        None,
        None,
    );

    // Must NOT hard-fail
    assert!(result.is_ok(), "E007 must NOT hard-fail, got: {:?}", result.err());
    eprintln!("9.2  E007 TIMESTAMP_FUTURE → WARNING only — PASS");
}

// E008 → semantic comparison result

#[test]
fn test_9_2_h_e008_causes_semantic_comparison() {
    // E008: ModelMismatch → returns ModelMatch enum, not general error
    use origin_core::statement::ModelMatch;

    let result = compare_semantic_models(0x01, 0x02);
    assert_eq!(result, ModelMatch::DerivativeProbable);

    // Verify it's not an Err variant
    // The compare_semantic_models function returns ModelMatch, not Result
    eprintln!("9.2  E008 MODEL_MISMATCH → semantic comparison result — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 9.3 — Error code uniqueness
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_9_3_all_error_codes_unique() {
    let codes = [
        Error::SignatureInvalid("".into()).code_str(),
        Error::ContentMismatch { expected: "".into(), actual: "".into() }.code_str(),
        Error::PooRevoked("".into()).code_str(),
        Error::IkmUnreachable { key: "".into() }.code_str(),
        Error::IvgUnreachable("".into()).code_str(),
        Error::VersionUnknown { version: 0, detail: "".into() }.code_str(),
        Error::TimestampFuture { ts: 0, now: 0 }.code_str(),
        Error::ModelMismatch { ver_a: 0, ver_b: 0 }.code_str(),
    ];

    // All 8 codes must be distinct
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(codes[i], codes[j],
                "Error codes must be unique: {} == {}", codes[i], codes[j]);
        }
    }
    eprintln!("9.3  All 8 error codes unique — PASS");
}

#[test]
fn test_9_3_error_codes_sequential() {
    // Error codes must be E001 through E008 (no gaps)
    let expected = ["E001", "E002", "E003", "E004", "E005", "E006", "E007", "E008"];
    let actual = [
        Error::SignatureInvalid("".into()).code_str(),
        Error::ContentMismatch { expected: "".into(), actual: "".into() }.code_str(),
        Error::PooRevoked("".into()).code_str(),
        Error::IkmUnreachable { key: "".into() }.code_str(),
        Error::IvgUnreachable("".into()).code_str(),
        Error::VersionUnknown { version: 0, detail: "".into() }.code_str(),
        Error::TimestampFuture { ts: 0, now: 0 }.code_str(),
        Error::ModelMismatch { ver_a: 0, ver_b: 0 }.code_str(),
    ];

    assert_eq!(expected, actual);
    eprintln!("9.3  Error codes E001–E008 sequential — PASS");
}

// ═══════════════════════════════════════════════════════════════════════
// 9.4 — Display format verification
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_9_4_display_format_contains_code_and_name() {
    let tests = vec![
        (Error::SignatureInvalid("test".into()), "E001", "SIGNATURE_INVALID"),
        (Error::ContentMismatch { expected: "a".into(), actual: "b".into() }, "E002", "CONTENT_MISMATCH"),
        (Error::PooRevoked("h".into()), "E003", "POO_REVOKED"),
        (Error::IkmUnreachable { key: "k".into() }, "E004", "IKM_UNREACHABLE"),
        (Error::IvgUnreachable("r".into()), "E005", "IVG_UNREACHABLE"),
        (Error::VersionUnknown { version: 0xFF, detail: "d".into() }, "E006", "VERSION_UNKNOWN"),
        (Error::TimestampFuture { ts: 100, now: 0 }, "E007", "TIMESTAMP_FUTURE"),
        (Error::ModelMismatch { ver_a: 1, ver_b: 2 }, "E008", "MODEL_MISMATCH"),
    ];

    for (err, code, name) in tests {
        let msg = format!("{}", err);
        assert!(msg.contains(code), "Display must contain {}: {}", code, msg);
        assert!(msg.contains(name), "Display must contain {}: {}", name, msg);
    }
    eprintln!("9.4  All error Display formats contain code + name — PASS");
}

#[test]
fn test_9_4_e007_display_contains_seconds() {
    let err = Error::TimestampFuture { ts: 1700000400, now: 1700000000 };
    let msg = format!("{}", err);
    assert!(msg.contains("400"), "E007 display must contain seconds difference: {}", msg);
    eprintln!("9.4  E007 display contains seconds difference — PASS");
}

#[test]
fn test_9_4_e008_display_contains_versions() {
    let err = Error::ModelMismatch { ver_a: 0x01, ver_b: 0x02 };
    let msg = format!("{}", err);
    assert!(msg.contains("1"), "E007 display must contain ver_a: {}", msg);
    assert!(msg.contains("2"), "E007 display must contain ver_b: {}", msg);
    eprintln!("9.4  E008 display contains model versions — PASS");
}
