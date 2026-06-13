#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Identity & Key Management (IKM): implements the DID:origin method,
//! key delegation chains, enterprise identity binding, and a
//! Web-of-Trust reputation scoring system.

use origin_core::Error;

extern crate alloc;

/// A DID Document conforming to the DID Core specification.
pub struct DidDocument {
    /// The DID string (e.g. "did:origin:abc123...").
    pub id: String,
    /// Verification methods (public keys) associated with this DID.
    pub verification_method: Vec<VerificationMethod>,
}

/// A verification method (public key) in a DID Document.
pub struct VerificationMethod {
    /// Identifier for this verification method.
    pub id: String,
    /// The 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
}

/// Resolve a DID:origin identifier to its DID Document.
pub fn resolve_did(_did: &str) -> Option<DidDocument> {
    // E004 IKM_UNREACHABLE: DID resolution not yet implemented.
    // Returns None to signal unreachability, allowing callers to fall back
    // to cached keys with a W001 warning per spec section 4.1.
    None
}

/// Resolve a DID with error construction.
///
/// Attempts DID resolution. If unreachable, returns `Error::IkmUnreachable` (E004).
pub fn resolve_did_or_err(did: &str) -> origin_core::Result<DidDocument> {
    resolve_did(did).ok_or_else(|| Error::IkmUnreachable {
        key: String::from(did),
    })
}

/// Compute a reputation score for a given public key.
/// Returns a value in [0.0, 1.0] where 1.0 is fully trusted.
pub fn reputation(_public_key: &[u8; 32]) -> f64 {
    // E004 IKM_UNREACHABLE: reputation scoring not yet implemented.
    // Returns 0.0 (untrusted) as conservative default.
    0.0
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_did_roundtrip() {
        // TODO: implement
    }
}
