use sha2::{Digest, Sha256};

use crate::error::Result;

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
    hex::encode(hash_bytes(data))
}

/// SHA-256 hash of a file, returned as lowercase hex string.
pub fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(hash_hex(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_file_not_found() {
        let err = hash_file(std::path::Path::new("/nonexistent/file.bin")).unwrap_err();
        assert!(err.to_string().contains("I/O error"));
    }
}
