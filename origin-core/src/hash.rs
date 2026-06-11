use sha2::{Digest, Sha256};

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn hash_hex(data: &[u8]) -> alloc::string::String {
    hex::encode(hash_bytes(data))
}

#[cfg(feature = "std")]
pub fn hash_file(path: &std::path::Path) -> crate::error::Result<alloc::string::String> {
    let data = std::fs::read(path)?;
    Ok(hash_hex(&data))
}
