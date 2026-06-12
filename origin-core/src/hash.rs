// SPDX-License-Identifier: MIT

//! SHA-256 hashing utilities for the Origin provenance library.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of the given byte slice.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the SHA-256 hash and return it as a hex-encoded string.
pub fn hash_hex(data: &[u8]) -> alloc::string::String {
    hex::encode(hash_bytes(data))
}

/// Compute the SHA-256 hash of a reader incrementally (requires the `std` feature).
///
/// Streams data through a `BufReader` to avoid loading the entire file into memory.
/// Peak RSS is bounded by the buffer size regardless of file size.
#[cfg(feature = "std")]
pub fn hash_reader(mut reader: impl std::io::Read) -> crate::error::Result<[u8; 32]> {
    use sha2::digest::Digest as _;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Compute the SHA-256 hash of a file at the given path (requires the `std` feature).
///
/// Streams the file instead of loading it entirely into memory.
#[cfg(feature = "std")]
pub fn hash_file(path: &std::path::Path) -> crate::error::Result<alloc::string::String> {
    let file = std::fs::File::open(path).map_err(|e| crate::error::Error::Io(e.to_string()))?;
    let reader = std::io::BufReader::with_capacity(65536, file);
    let hash = hash_reader(reader)?;
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_known_empty() {
        let hash = hash_bytes(b"");
        assert_eq!(
            hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn test_hash_hex_known() {
        assert_eq!(
            hash_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hash_file_streaming_matches_slice() {
        let data = b"streaming test data for hash verification";
        let dir = std::env::temp_dir();
        let path = dir.join("origin_hash_stream_test");
        std::fs::write(&path, data).unwrap();
        let file_hash = hash_file(&path).unwrap();
        let slice_hash = hash_hex(data);
        assert_eq!(file_hash, slice_hash);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hash_reader_matches_hash_bytes() {
        let data = b"hello hash_reader test";
        let reader = std::io::Cursor::new(data);
        let hash1 = hash_reader(reader).unwrap();
        let hash2 = hash_bytes(data);
        assert_eq!(hash1, hash2);
    }
}
