use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;

use crate::error::Result;

/// Supported hash algorithms for the `hash:` field.
///
/// The algorithm is encoded as a prefix in the hash string:
/// - `sha256:` — SHA-256 (32 bytes / 64 hex chars)
/// - `sha384:` — SHA-384 (48 bytes / 96 hex chars)
/// - `sha512:` — SHA-512 (64 bytes / 128 hex chars)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha384 => write!(f, "sha384"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
        }
    }
}

/// All hash algorithm prefixes accepted by the parser.
pub const ALLOWED_HASH_ALGORITHMS: &[&str] = &["sha256", "sha384", "sha512"];

/// Hash data with the given algorithm.
///
/// Returns `(hex_digest, raw_bytes)`.
pub fn hash_data(data: &[u8], alg: &HashAlgorithm) -> (String, Vec<u8>) {
    match alg {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let result = hasher.finalize();
            let bytes = result.to_vec();
            (hex::encode(&bytes), bytes)
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            let result = hasher.finalize();
            let bytes = result.to_vec();
            (hex::encode(&bytes), bytes)
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            let result = hasher.finalize();
            let bytes = result.to_vec();
            (hex::encode(&bytes), bytes)
        }
    }
}

/// SHA-256 hash of data, returned as 32 raw bytes.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// SHA-256 hash of data, returned as lowercase hex string.
pub fn hash_hex(data: &[u8]) -> String {
    hash_data(data, &HashAlgorithm::Sha256).0
}

/// SHA-256 hash of a file, returned as lowercase hex string.
pub fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(hash_hex(&data))
}
