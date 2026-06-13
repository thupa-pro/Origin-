// SPDX-License-Identifier: MIT

use alloc::string::ToString;

use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

#[derive(Clone)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::Error::Crypto(
                "secret key must be 32 bytes".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(SecretKey(key))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::Error::Crypto(
                "public key must be 32 bytes".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        validate_public_key(&key)?;
        Ok(PublicKey(key))
    }
}

pub fn validate_public_key(pk: &[u8; 32]) -> crate::error::Result<()> {
    let zero = [0u8; 32];
    if pk.ct_eq(&zero).into() {
        return Err(crate::error::Error::Crypto(
            "invalid public key: identity point (all zeros)".into(),
        ));
    }
    Ok(())
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() != 64 {
            return Err(crate::error::Error::Crypto(
                "signature must be 64 bytes".into(),
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(bytes);
        Ok(Signature(sig))
    }
}

pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    let dalek_pair = ed25519_dalek::SigningKey::from_bytes(seed);
    let public = dalek_pair.verifying_key();
    Keypair {
        secret: SecretKey(*seed),
        public: PublicKey(public.to_bytes()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_keypair() -> Keypair {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS entropy unavailable");
    generate_keypair_from_seed(&seed)
}

/// Ed25519ph (pre-hashing) signing per RFC 8032 §5.1.
/// Hashes the message with SHA-512 first, then signs the hash.
pub fn sign_ph(secret: &SecretKey, message: &[u8]) -> Signature {
    use sha2::Digest;
    let mut prehash = sha2::Sha512::new();
    prehash.update(message);
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let dalek_sig = dalek_key
        .sign_prehashed(prehash, Some(b"Origin-Network-v1"))
        .expect("sign_prehashed");
    Signature(dalek_sig.to_bytes())
}

/// Ed25519ph verification (pre-hashing variant).
pub fn verify_ph(public: &PublicKey, message: &[u8], sig: &Signature) -> crate::error::Result<()> {
    use sha2::Digest;
    let dalek_pub = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|e| crate::error::Error::SignatureInvalid(e.to_string()))?;
    let mut prehash = sha2::Sha512::new();
    prehash.update(message);
    let dalek_sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig.0);
    dalek_pub
        .verify_prehashed(prehash, Some(b"Origin-Network-v1"), &dalek_sig)
        .map_err(|e| crate::error::Error::SignatureInvalid(e.to_string()))
}

/// Legacy plain Ed25519 sign (for backward compat during transition).
pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let dalek_sig = dalek_key.sign(message);
    Signature(dalek_sig.to_bytes())
}

/// Legacy plain Ed25519 verify.
pub fn verify(public: &PublicKey, message: &[u8], sig: &Signature) -> crate::error::Result<()> {
    let dalek_pub = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))?;
    let dalek_sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig.0);
    dalek_pub
        .verify_strict(message, &dalek_sig)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

/// DER-encode an Ed25519 public key (32-byte raw compressed form).
pub fn der_encode_pubkey(pubkey: &[u8; 32]) -> [u8; 44] {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    der[12..44].copy_from_slice(pubkey);
    der
}

/// Compute key_id = SHA-256(DER-encoded Ed25519 public key)[0..31].
/// This enables fully offline self-verification per spec check 9.2.
pub fn compute_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let der = der_encode_pubkey(public_key);
    crate::hash::hash_bytes(&der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_public_key_rejects_identity_point() {
        let result = validate_public_key(&[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identity point"));
    }

    #[test]
    fn test_validate_public_key_accepts_valid() {
        let pk = [
            208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        assert!(validate_public_key(&pk).is_ok());
    }

    #[test]
    fn test_generate_keypair_from_seed_deterministic() {
        let seed = [42u8; 32];
        let kp1 = generate_keypair_from_seed(&seed);
        let kp2 = generate_keypair_from_seed(&seed);
        assert_eq!(kp1.public.0, kp2.public.0);
        assert_eq!(kp1.secret.0, kp2.secret.0);
    }

    #[test]
    fn test_ed25519ph_sign_verify() {
        let seed = [1u8; 32];
        let kp = generate_keypair_from_seed(&seed);
        let msg = b"test message for Ed25519ph";
        let sig = sign_ph(&kp.secret, msg);
        assert!(verify_ph(&kp.public, msg, &sig).is_ok());
    }

    #[test]
    fn test_ed25519ph_rejects_wrong_message() {
        let seed = [2u8; 32];
        let kp = generate_keypair_from_seed(&seed);
        let sig = sign_ph(&kp.secret, b"correct");
        assert!(verify_ph(&kp.public, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_ed25519ph_deterministic() {
        let seed = [3u8; 32];
        let kp = generate_keypair_from_seed(&seed);
        let sig1 = sign_ph(&kp.secret, b"deterministic");
        let sig2 = sign_ph(&kp.secret, b"deterministic");
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_der_encode_pubkey() {
        let pk = [
            208, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 162, 38, 53, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let der = der_encode_pubkey(&pk);
        assert_eq!(der.len(), 44);
        assert_eq!(
            der[..12],
            [
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
            ]
        );
        assert_eq!(der[12..44], pk);
    }

    #[test]
    fn test_public_key_rfc_test_vector() {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&[0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60]);
        seed[8..16].copy_from_slice(&[0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4]);
        seed[16..24].copy_from_slice(&[0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19]);
        seed[24..32].copy_from_slice(&[0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60]);
        let kp = generate_keypair_from_seed(&seed);
        let expected: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        assert_eq!(kp.public.0, expected);
    }

    #[test]
    fn test_sign_verify_deterministic() {
        let seed = [1u8; 32];
        let kp = generate_keypair_from_seed(&seed);
        let msg = b"test message";
        let sig = sign(&kp.secret, msg);
        assert!(verify(&kp.public, msg, &sig).is_ok());
    }

    #[test]
    fn test_sign_verify_rejects_wrong_message() {
        let seed = [2u8; 32];
        let kp = generate_keypair_from_seed(&seed);
        let sig = sign(&kp.secret, b"correct");
        assert!(verify(&kp.public, b"wrong", &sig).is_err());
    }
}
