use alloc::string::ToString;

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

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let dalek_sig = dalek_key.sign(message);
    Signature(dalek_sig.to_bytes())
}

pub fn verify(public: &PublicKey, message: &[u8], sig: &Signature) -> crate::error::Result<()> {
    use ed25519_dalek::Verifier;
    let dalek_pub = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))?;
    let dalek_sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig.0);
    dalek_pub
        .verify(message, &dalek_sig)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))
}
