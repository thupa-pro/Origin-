use origin_core::{SecretKey, base64_encode, crypto, generate_keypair_from_seed, hash};

fn make_secret(seed_byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed_byte; 32]).unwrap()
}

/// Prove that (hash, key, sig) alone — no origin, type, parent, or time —
/// is sufficient for "key K signed artifact A".
#[test]
fn test_primitive_sufficient() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"test artifact");
    let hash_str = format!("sha256:{}", h);

    let canonical = format!("hash: {}\nkey: {}", hash_str, public_b64).into_bytes();
    let sig = crypto::sign(&secret, &canonical);
    let result = crypto::verify(&pair.public, &canonical, &sig);

    assert!(result.is_ok(), "minimal (hash, key, sig) must be sufficient");
}

/// Prove that hash is necessary — changing it breaks the binding.
#[test]
fn test_primitive_hash_necessary() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"test artifact");
    let hash_str = format!("sha256:{}", h);

    let canonical = format!("hash: {}\nkey: {}", hash_str, public_b64).into_bytes();
    let sig = crypto::sign(&secret, &canonical);

    let wrong_hash = format!("sha256:{}", hash::hash_hex(b"wrong artifact"));
    let wrong_canonical = format!("hash: {}\nkey: {}", wrong_hash, public_b64).into_bytes();
    let result = crypto::verify(&pair.public, &wrong_canonical, &sig);

    assert!(result.is_err(), "wrong hash must fail — hash is necessary");
}

/// Prove that key is necessary — changing it breaks the binding.
#[test]
fn test_primitive_key_necessary() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"test artifact");
    let hash_str = format!("sha256:{}", h);

    let canonical = format!("hash: {}\nkey: {}", hash_str, public_b64).into_bytes();
    let sig = crypto::sign(&secret, &canonical);

    let wrong_pair = generate_keypair_from_seed(&[99; 32]);
    let result = crypto::verify(&wrong_pair.public, &canonical, &sig);

    assert!(result.is_err(), "wrong key must fail — key is necessary");
}

/// Prove that signature is necessary — tampering with it breaks the binding.
#[test]
fn test_primitive_sig_necessary() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"test artifact");
    let hash_str = format!("sha256:{}", h);

    let canonical = format!("hash: {}\nkey: {}", hash_str, public_b64).into_bytes();
    let mut sig = crypto::sign(&secret, &canonical);
    sig.0[0] ^= 1;

    let result = crypto::verify(&pair.public, &canonical, &sig);

    assert!(result.is_err(), "tampered sig must fail — sig is necessary");
}

/// Prove that origin is not part of the core primitive —
/// any origin value still produces a valid binding.
#[test]
fn test_origin_not_primitive() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"artifact");
    let hash_str = format!("sha256:{}", h);

    for origin_val in ["v0", "v2", "custom", ""] {
        let canonical = format!("origin: {}\nhash: {}\nkey: {}", origin_val, hash_str, public_b64).into_bytes();
        let sig = crypto::sign(&secret, &canonical);
        let result = crypto::verify(&pair.public, &canonical, &sig);
        assert!(result.is_ok(), "origin '{}' must still produce valid binding", origin_val);
    }
}

/// Prove that type is not part of the core primitive —
/// any type value still produces a valid binding.
#[test]
fn test_type_not_primitive() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"artifact");
    let hash_str = format!("sha256:{}", h);

    for type_val in ["provenance", "attestation", "sbom", "custom", ""] {
        let canonical = format!("type: {}\nhash: {}\nkey: {}", type_val, hash_str, public_b64).into_bytes();
        let sig = crypto::sign(&secret, &canonical);
        let result = crypto::verify(&pair.public, &canonical, &sig);
        assert!(result.is_ok(), "type '{}' must still produce valid binding", type_val);
    }
}

/// Prove that parent is not part of the core primitive —
/// with or without parent, the binding stands.
#[test]
fn test_parent_not_primitive() {
    let secret = make_secret(42);
    let pair = generate_keypair_from_seed(&[42; 32]);
    let public_b64 = base64_encode(pair.public.as_bytes());
    let h = hash::hash_hex(b"artifact");
    let hash_str = format!("sha256:{}", h);

    let parent_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let canonical = format!("parent: {}\nhash: {}\nkey: {}", parent_hash, hash_str, public_b64).into_bytes();
    let sig = crypto::sign(&secret, &canonical);
    let result = crypto::verify(&pair.public, &canonical, &sig);
    assert!(result.is_ok(), "with parent must still produce valid binding");

    let canonical2 = format!("hash: {}\nkey: {}", hash_str, public_b64).into_bytes();
    let sig2 = crypto::sign(&secret, &canonical2);
    let result2 = crypto::verify(&pair.public, &canonical2, &sig2);
    assert!(result2.is_ok(), "without parent must still produce valid binding");
}
