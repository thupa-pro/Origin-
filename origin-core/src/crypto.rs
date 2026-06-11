// SPDX-License-Identifier: MIT

//! Ed25519 cryptographic operations for the Origin protocol.
//!
//! Provides key types ([`Keypair`], [`SecretKey`], [`PublicKey`], [`Signature`])
//! and functions for key generation, signing, and verification.

use alloc::string::ToString;

use zeroize::ZeroizeOnDrop;

/// A Ed25519 key pair consisting of a [`SecretKey`] and [`PublicKey`].
#[derive(Clone)]
pub struct Keypair {
    /// The secret (private) key.
    pub secret: SecretKey,
    /// The public key.
    pub public: PublicKey,
}

/// A 32-byte Ed25519 secret key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

/// A 32-byte Ed25519 public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

/// A 64-byte Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl SecretKey {
    /// Create a [`SecretKey`] from a 32-byte slice, rejecting wrong lengths.
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
    /// Create a [`PublicKey`] from a 32-byte slice, validating against the identity point.
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

/// Reject the identity point (all-zero public key).
pub fn validate_public_key(pk: &[u8; 32]) -> crate::error::Result<()> {
    if pk.iter().all(|&b| b == 0) {
        return Err(crate::error::Error::Crypto(
            "invalid public key: identity point (all zeros)".into(),
        ));
    }
    Ok(())
}

impl Signature {
    /// Create a [`Signature`] from a 64-byte slice, rejecting wrong lengths.
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

/// Generate a key pair from a seed. Available in all configurations.
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    let dalek_pair = ed25519_dalek::SigningKey::from_bytes(seed);
    let public = dalek_pair.verifying_key();
    Keypair {
        secret: SecretKey(*seed),
        public: PublicKey(public.to_bytes()),
    }
}

/// Generate a key pair with OS entropy. Not available on WASM
/// (use JS crypto.getRandomValues + generate_keypair_from_seed instead).
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_keypair() -> Keypair {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS entropy unavailable");
    generate_keypair_from_seed(&seed)
}

/// Sign a message with the given [`SecretKey`], producing a [`Signature`].
pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let dalek_sig = dalek_key.sign(message);
    Signature(dalek_sig.to_bytes())
}

/// Verify a [`Signature`] against a message and [`PublicKey`].
pub fn verify(public: &PublicKey, message: &[u8], sig: &Signature) -> crate::error::Result<()> {
    use ed25519_dalek::Verifier;
    let dalek_pub = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))?;
    let dalek_sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig.0);
    dalek_pub
        .verify(message, &dalek_sig)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))
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
}
