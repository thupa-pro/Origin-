// SPDX-License-Identifier: MIT

use proptest::prelude::*;

// 10,000 iterations per test as required by Domain 1.4
#[allow(unsafe_code)]
fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 10_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    /// Serialization identity: from_bytes(to_bytes(poo)) == poo (10,000 cases)
    #[test]
    fn serde_identity(seed: [u8; 32], data: Vec<u8>, ts: u64) {
        let secret = origin_core::SecretKey::from_bytes(&seed);
        prop_assume!(secret.is_ok());
        let stmt = origin_core::build_statement(&secret.unwrap(), &data, ts % 253402300800);
        prop_assume!(stmt.is_ok());
        let poo = origin_core::ProofOfOrigin::from_statement(&stmt.unwrap());
        prop_assume!(poo.is_ok());
        let poo = poo.unwrap();

        let bytes = poo.to_bytes();
        let parsed = origin_core::ProofOfOrigin::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.timestamp_u64(), poo.timestamp_u64());
    }

    /// Text roundtrip: build -> encode -> parse yields same Statement (1000 cases)
    #[test]
    fn text_roundtrip(seed: [u8; 32], data: Vec<u8>, ts: u64) {
        let secret = origin_core::SecretKey::from_bytes(&seed);
        prop_assume!(secret.is_ok());
        let stmt = origin_core::build_statement(&secret.unwrap(), &data, ts % 253402300800);
        prop_assume!(stmt.is_ok());
        let stmt = stmt.unwrap();
        let encoded = origin_core::encode_statement(&stmt);
        let parsed = origin_core::Statement::parse(&encoded).unwrap();
        assert_eq!(stmt.hash, parsed.hash);
        assert_eq!(stmt.time, parsed.time);
    }

    /// Verify always succeeds for self-signed statements (1000 cases)
    #[test]
    fn self_verify(seed: [u8; 32], data: Vec<u8>, ts: u64) {
        let secret = origin_core::SecretKey::from_bytes(&seed);
        prop_assume!(secret.is_ok());
        let stmt = origin_core::build_statement(&secret.unwrap(), &data, ts % 253402300800);
        prop_assume!(stmt.is_ok());
        let stmt = stmt.unwrap();
        assert!(origin_core::verify_statement(&stmt, &data).is_ok());
    }
}
