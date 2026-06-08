use sha2::{Digest, Sha256};

use crate::error::Result;

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash_bytes(data))
}

pub fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(hash_hex(&data))
}
