use origin_core::{
    build_statement, encode_statement, generate_keypair_from_seed,
    verify, verify_chain, SecretKey,
};

fn make_secret(seed_byte: u8) -> SecretKey {
    let seed = [seed_byte; 32];
    SecretKey::from_bytes(&seed).unwrap()
}

fn trusted_key(seed_byte: u8) -> [u8; 32] {
    let pair = generate_keypair_from_seed(&[seed_byte; 32]);
    pair.public.0
}

#[test]
fn test_verify_correct_key() {
    let secret = make_secret(42);
    let tk = trusted_key(42);
    let data = b"test artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = encode_statement(&stmt);

    let result = verify(&encoded, data, &tk);
    assert!(result.is_ok(), "correct trusted key must verify");
}

#[test]
fn test_verify_wrong_key() {
    let secret = make_secret(42);
    let wrong = trusted_key(99);
    let data = b"test artifact";
    let stmt = build_statement(&secret, data, 100, None).unwrap();
    let encoded = encode_statement(&stmt);

    let result = verify(&encoded, data, &wrong);
    assert!(result.is_err(), "wrong trusted key must fail");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("Public key mismatch"), "error must mention key mismatch: {}", err);
}

#[test]
fn test_verify_chain_correct() {
    let secret = make_secret(42);
    let tk = trusted_key(42);
    let parent_art = b"parent";
    let child_art = b"child";

    let parent = build_statement(&secret, parent_art, 100, None).unwrap();
    let parent_enc = encode_statement(&parent);

    let child = build_statement(&secret, child_art, 200, Some(&parent.hash)).unwrap();
    let child_enc = encode_statement(&child);

    let result = verify_chain(
        &child_enc, child_art,
        Some(&parent_enc), Some(parent_art),
        &tk,
    );
    assert!(result.is_ok(), "chain with correct key must verify: {:?}", result);
}

#[test]
fn test_verify_chain_wrong_child_key() {
    let secret_parent = make_secret(42);
    let secret_child = make_secret(99);
    let tk = trusted_key(42);
    let parent_art = b"parent";
    let child_art = b"child";

    let parent = build_statement(&secret_parent, parent_art, 100, None).unwrap();
    let parent_enc = encode_statement(&parent);

    let child = build_statement(&secret_child, child_art, 200, Some(&parent.hash)).unwrap();
    let child_enc = encode_statement(&child);

    let result = verify_chain(
        &child_enc, child_art,
        Some(&parent_enc), Some(parent_art),
        &tk,
    );
    assert!(result.is_err(), "child with different key must fail");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("Public key mismatch"), "error must mention key mismatch: {}", err);
}

#[test]
fn test_verify_chain_wrong_parent_key() {
    let secret_parent = make_secret(99);
    let secret_child = make_secret(42);
    let tk = trusted_key(42);
    let parent_art = b"parent";
    let child_art = b"child";

    let parent = build_statement(&secret_parent, parent_art, 100, None).unwrap();
    let parent_enc = encode_statement(&parent);

    let child = build_statement(&secret_child, child_art, 200, Some(&parent.hash)).unwrap();
    let child_enc = encode_statement(&child);

    let result = verify_chain(
        &child_enc, child_art,
        Some(&parent_enc), Some(parent_art),
        &tk,
    );
    assert!(result.is_err(), "parent with different key must fail: {:?}", result);
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("Public key mismatch"), "error must mention key mismatch: {}", err);
}
