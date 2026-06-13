// SPDX-License-Identifier: MIT

//! C2PA Content Hash Mapping
//!
//! Maps between C2PA (Content Provenance and Authenticity) hash.data format
//! and Origin Protocol content_hash format. This enables interoperability
//! between C2PA-enabled tools and the Origin Protocol.
//!
//! # C2PA Hash Format
//!
//! C2PA uses a `hash.data` structure with:
//! - Algorithm identifier (e.g., "sha256")
//! - Hash value (variable length, typically 32 bytes for SHA-256)
//!
//! # Origin Protocol Hash Format
//!
//! Origin Protocol uses a fixed 32-byte SHA-256 hash stored in the
//! `content_hash` field of the 256-byte Proof of Origin.

use crate::error::{Error, Result};
use crate::hash::hash_bytes;

/// C2PA hash algorithm identifiers
pub const C2PA_ALGO_SHA256: &str = "sha256";
pub const C2PA_ALGO_SHA384: &str = "sha384";
pub const C2PA_ALGO_SHA512: &str = "sha512";

/// A parsed C2PA hash.data structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2paHash {
    /// Algorithm identifier (e.g., "sha256")
    pub algorithm: alloc::string::String,
    /// Raw hash bytes
    pub hash: alloc::vec::Vec<u8>,
}

impl C2paHash {
    /// Parse a C2PA hash from algorithm string and hash bytes
    pub fn new(algorithm: &str, hash: &[u8]) -> Self {
        Self {
            algorithm: algorithm.to_string(),
            hash: hash.to_vec(),
        }
    }

    /// Parse a C2PA hash from a JUMBF-style hash.data box
    ///
    /// Format: algorithm_id (null-terminated) || hash_bytes
    pub fn from_hash_data(data: &[u8]) -> Result<Self> {
        // Find null terminator for algorithm string
        let algo_end = data.iter().position(|&b| b == 0).ok_or_else(|| {
            Error::Format("C2PA hash.data: missing null terminator for algorithm".into())
        })?;

        let algorithm = core::str::from_utf8(&data[..algo_end]).map_err(|_| {
            Error::Format("C2PA hash.data: invalid UTF-8 in algorithm".into())
        })?;

        let hash = &data[algo_end + 1..];
        if hash.is_empty() {
            return Err(Error::Format("C2PA hash.data: empty hash value".into()));
        }

        Ok(Self {
            algorithm: algorithm.to_string(),
            hash: hash.to_vec(),
        })
    }

    /// Serialize to JUMBF-style hash.data format
    pub fn to_hash_data(&self) -> alloc::vec::Vec<u8> {
        let mut data = alloc::vec::Vec::with_capacity(self.algorithm.len() + 1 + self.hash.len());
        data.extend_from_slice(self.algorithm.as_bytes());
        data.push(0); // null terminator
        data.extend_from_slice(&self.hash);
        data
    }
}

/// Map a C2PA hash to Origin content_hash format.
///
/// # Behavior
/// - If C2PA hash is exactly 32 bytes (SHA-256), returns it directly
/// - If C2PA hash is shorter than 32 bytes, pads with zeros on the right
/// - If C2PA hash is longer than 32 bytes, truncates to 32 bytes
/// - If algorithm is not SHA-256, hashes the C2PA hash bytes with SHA-256
///
/// # Returns
/// A 32-byte Origin content_hash suitable for `ProofOfOrigin::content_hash`
pub fn c2pa_hash_to_origin(c2pa_hash: &C2paHash) -> [u8; 32] {
    // For SHA-256 hashes, use direct mapping
    if c2pa_hash.algorithm == C2PA_ALGO_SHA256 && c2pa_hash.hash.len() == 32 {
        let mut result = [0u8; 32];
        result.copy_from_slice(&c2pa_hash.hash);
        return result;
    }

    // For other algorithms or non-standard lengths, hash the C2PA hash bytes
    // This ensures a consistent 32-byte output regardless of input format
    let mut combined = alloc::vec::Vec::with_capacity(c2pa_hash.algorithm.len() + c2pa_hash.hash.len());
    combined.extend_from_slice(c2pa_hash.algorithm.as_bytes());
    combined.extend_from_slice(&c2pa_hash.hash);
    hash_bytes(&combined)
}

/// Map an Origin content_hash to C2PA hash.data format.
///
/// Returns a C2PA hash with algorithm "sha256" and the 32-byte hash value.
pub fn origin_hash_to_c2pa(origin_hash: &[u8; 32]) -> C2paHash {
    C2paHash {
        algorithm: C2PA_ALGO_SHA256.to_string(),
        hash: origin_hash.to_vec(),
    }
}

/// Check if a C2PA hash is compatible with an Origin content_hash.
///
/// Two hashes are compatible if:
/// 1. They represent the same SHA-256 hash value, OR
/// 2. The C2PA hash can be mapped to the Origin hash via `c2pa_hash_to_origin`
pub fn verify_c2pa_compatibility(origin_hash: &[u8; 32], c2pa_hash: &C2paHash) -> bool {
    let mapped = c2pa_hash_to_origin(c2pa_hash);
    mapped == *origin_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2pa_hash_to_origin_sha256() {
        let hash_bytes = [0xAB; 32];
        let c2pa = C2paHash::new(C2PA_ALGO_SHA256, &hash_bytes);
        let origin = c2pa_hash_to_origin(&c2pa);
        assert_eq!(origin, hash_bytes);
    }

    #[test]
    fn test_c2pa_hash_to_origin_sha384() {
        // SHA-384 produces 48 bytes, should be hashed to 32 bytes
        let hash_bytes = [0xCD; 48];
        let c2pa = C2paHash::new(C2PA_ALGO_SHA384, &hash_bytes);
        let origin = c2pa_hash_to_origin(&c2pa);
        assert_ne!(origin, [0u8; 32]); // Should not be all zeros
        assert_ne!(origin, [0xCD; 32]); // Should not be raw bytes
    }

    #[test]
    fn test_c2pa_hash_to_origin_short() {
        // Short SHA-256 hash (non-32 bytes) gets hashed for consistency
        let hash_bytes = [0xEF; 16];
        let c2pa = C2paHash::new(C2PA_ALGO_SHA256, &hash_bytes);
        let origin = c2pa_hash_to_origin(&c2pa);
        // Result is SHA-256("sha256" || [0xEF; 16]), not direct padding
        assert_ne!(origin, [0u8; 32]);
        assert_ne!(origin, [0xEF; 32]);
        // Verify determinism
        let origin2 = c2pa_hash_to_origin(&c2pa);
        assert_eq!(origin, origin2);
    }

    #[test]
    fn test_c2pa_hash_to_origin_long() {
        // Long SHA-256 hash (non-32 bytes) gets hashed for consistency
        let hash_bytes = [0x12; 64];
        let c2pa = C2paHash::new(C2PA_ALGO_SHA256, &hash_bytes);
        let origin = c2pa_hash_to_origin(&c2pa);
        // Result is SHA-256("sha256" || [0x12; 64]), not direct truncation
        assert_ne!(origin, [0u8; 32]);
        assert_ne!(origin, [0x12; 32]);
        // Verify determinism
        let origin2 = c2pa_hash_to_origin(&c2pa);
        assert_eq!(origin, origin2);
    }

    #[test]
    fn test_origin_hash_to_c2pa() {
        let origin_hash = [0xAB; 32];
        let c2pa = origin_hash_to_c2pa(&origin_hash);
        assert_eq!(c2pa.algorithm, C2PA_ALGO_SHA256);
        assert_eq!(c2pa.hash, origin_hash);
    }

    #[test]
    fn test_c2pa_compatibility_match() {
        let origin_hash = [0xAB; 32];
        let c2pa = origin_hash_to_c2pa(&origin_hash);
        assert!(verify_c2pa_compatibility(&origin_hash, &c2pa));
    }

    #[test]
    fn test_c2pa_compatibility_mismatch() {
        let origin_hash = [0xAB; 32];
        let c2pa = C2paHash::new(C2PA_ALGO_SHA256, &[0xCD; 32]);
        assert!(!verify_c2pa_compatibility(&origin_hash, &c2pa));
    }

    #[test]
    fn test_from_hash_data_roundtrip() {
        let original = C2paHash::new(C2PA_ALGO_SHA256, &[0xAB; 32]);
        let data = original.to_hash_data();
        let parsed = C2paHash::from_hash_data(&data).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_hash_data_missing_null() {
        let data = b"sha256"; // No null terminator
        assert!(C2paHash::from_hash_data(data).is_err());
    }

    #[test]
    fn test_from_hash_data_empty_hash() {
        let data = b"sha256\0"; // Null but no hash
        assert!(C2paHash::from_hash_data(data).is_err());
    }

    #[test]
    fn test_from_hash_data_invalid_utf8() {
        let data = b"\xff\xfe\0\xab\xcd"; // Invalid UTF-8
        assert!(C2paHash::from_hash_data(data).is_err());
    }
}
