use origin_core::{
    SecretKey, build_statement, encode_statement, generate_keypair_from_seed, verify, verify_chain,
    verify_chain_consistency, verify_consistency,
};
use proptest::prelude::*;
use test_strategy::proptest;

fn arb_artifact() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256).no_shrink()
}

fn arb_timestamp() -> impl Strategy<Value = u64> {
    0u64..253402300799u64
}

fn arb_parent_hash() -> impl Strategy<Value = Option<String>> {
    prop::option::of("[a-f0-9]{64}".prop_map(|hex| format!("sha256:{}", hex)).no_shrink())
}

fn arb_secret() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_map(|seed| SecretKey::from_bytes(&seed).unwrap())
}

#[proptest]
fn roundtrip_verify_consistency(
    #[strategy(arb_secret())] secret: SecretKey,
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc = encode_statement(&stmt);
    prop_assert!(verify_consistency(&enc, &artifact).is_ok());
}

#[proptest]
fn roundtrip_verify_trusted_key(
    #[strategy(any::<[u8; 32]>())] seed: [u8; 32],
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let trusted = generate_keypair_from_seed(&seed).public.0;
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc = encode_statement(&stmt);
    prop_assert!(verify(&enc, &artifact, &trusted).is_ok());
}

#[proptest]
fn verify_consistency_rejects_wrong_artifact(
    #[strategy(arb_secret())] secret: SecretKey,
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_artifact())] wrong_artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    prop_assume!(artifact != wrong_artifact);
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc = encode_statement(&stmt);
    prop_assert!(verify_consistency(&enc, &wrong_artifact).is_err());
}

#[proptest]
fn verify_rejects_wrong_key(
    #[strategy(any::<[u8; 32]>())] seed: [u8; 32],
    #[strategy(any::<[u8; 32]>())] wrong_seed: [u8; 32],
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    prop_assume!(seed != wrong_seed);
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let wrong_key = generate_keypair_from_seed(&wrong_seed).public.0;
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc = encode_statement(&stmt);
    let result = verify(&enc, &artifact, &wrong_key);
    prop_assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    prop_assert!(err.contains("Public key mismatch"));
}

#[proptest]
fn determinism(
    #[strategy(arb_secret())] secret: SecretKey,
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    let stmt1 = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let stmt2 = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc1 = encode_statement(&stmt1);
    let enc2 = encode_statement(&stmt2);
    prop_assert_eq!(enc1, enc2);
}

#[proptest]
fn verify_chain_roundtrip(
    #[strategy(any::<[u8; 32]>())] seed: [u8; 32],
    #[strategy(arb_artifact())] parent_art: Vec<u8>,
    #[strategy(arb_artifact())] child_art: Vec<u8>,
    #[strategy(arb_timestamp())] parent_ts: u64,
    #[strategy(arb_timestamp())] child_ts: u64,
) {
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let trusted = generate_keypair_from_seed(&seed).public.0;
    let parent = build_statement(&secret, &parent_art, parent_ts, None).unwrap();
    let p_enc = encode_statement(&parent);
    let child = build_statement(&secret, &child_art, child_ts, Some(&parent.hash)).unwrap();
    let c_enc = encode_statement(&child);
    prop_assert!(verify_chain(&c_enc, &child_art, Some(&p_enc), Some(&parent_art), &trusted).is_ok());
    prop_assert!(verify_chain_consistency(&c_enc, &child_art, Some(&p_enc), Some(&parent_art)).is_ok());
}

#[proptest]
fn timestamp_advisory(
    #[strategy(arb_secret())] secret: SecretKey,
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_timestamp())] new_ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    prop_assume!(ts != new_ts);
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let enc = encode_statement(&stmt);
    let text = String::from_utf8(enc).unwrap();
    let tampered = text.replace(&format!("time: {}", ts), &format!("time: {}", new_ts));
    prop_assert!(verify_consistency(tampered.as_bytes(), &artifact).is_ok());
}

#[proptest]
fn canonical_body_excludes_time_and_sig(
    #[strategy(arb_secret())] secret: SecretKey,
    #[strategy(arb_artifact())] artifact: Vec<u8>,
    #[strategy(arb_timestamp())] ts: u64,
    #[strategy(arb_parent_hash())] parent: Option<String>,
) {
    let stmt = build_statement(&secret, &artifact, ts, parent.as_deref()).unwrap();
    let body = String::from_utf8(stmt.canonical_body()).unwrap();
    prop_assert!(!body.contains("time:"));
    prop_assert!(!body.contains("sig:"));
    prop_assert!(body.contains("origin:"));
    prop_assert!(body.contains("type:"));
    prop_assert!(body.contains("hash:"));
    prop_assert!(body.contains("key:"));
    if parent.is_some() {
        prop_assert!(body.contains("parent:"));
    }
}
