use zeroize::{Zeroize, ZeroizeOnDrop};

/// An Ed25519 keypair (secret + public).
#[derive(Clone)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret.0.zeroize();
    }
}

/// An Ed25519 secret key (32 bytes, the seed per RFC 8032).
///
/// The memory is zeroed on drop via `ZeroizeOnDrop`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl SecretKey {
    /// Create a SecretKey from a 32-byte slice. Returns an error if length != 32.
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
    /// Create a PublicKey from a 32-byte slice. Returns an error if length != 32.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() != 32 {
            return Err(crate::error::Error::Crypto(
                "public key must be 32 bytes".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(PublicKey(key))
    }

    /// Return a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Signature {
    /// Create a Signature from a 64-byte slice. Returns an error if length != 64.
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

/// Generate a new Ed25519 keypair using OS entropy.
pub fn generate_keypair() -> Keypair {
    let mut seed = [0u8; 32];
    use rand::rngs::OsRng;
    use rand::TryRngCore;
    OsRng.try_fill_bytes(&mut seed).expect("OsRng failure");
    generate_keypair_from_seed(&seed)
}

/// Generate an Ed25519 keypair deterministically from a 32-byte seed.
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Keypair {
    let dalek_pair = ed25519_dalek::SigningKey::from_bytes(seed);
    let public = dalek_pair.verifying_key();
    Keypair {
        secret: SecretKey(*seed),
        public: PublicKey(public.to_bytes()),
    }
}

/// Sign a message with an Ed25519 secret key.
///
/// The signature is deterministic (RFC 8032 — no random nonces).
pub fn sign(secret: &SecretKey, message: &[u8]) -> Signature {
    use ed25519_dalek::Signer as _;
    let dalek_key = ed25519_dalek::SigningKey::from_bytes(&secret.0);
    let dalek_sig = dalek_key.sign(message);
    Signature(dalek_sig.to_bytes())
}

/// Verify an Ed25519 signature on a message.
pub fn verify(
    public: &PublicKey,
    message: &[u8],
    sig: &Signature,
) -> crate::error::Result<()> {
    use ed25519_dalek::Verifier as _;
    let dalek_pub = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))?;
    let dalek_sig = ed25519_dalek::ed25519::Signature::from_bytes(&sig.0);
    dalek_pub
        .verify(message, &dalek_sig)
        .map_err(|e| crate::error::Error::Crypto(e.to_string()))
}
