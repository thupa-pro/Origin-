use alloc::format;

use crate::crypto;
use crate::error::{Error, Result};
use crate::statement::Statement;

pub use layout::ProofOfOrigin;

mod layout {
    /// 256-byte fixed-width binary representation of a Proof of Origin.
    ///
    /// Layout:
    ///   [0]    version: u8           = 0x01
    ///   [1]    reserved: u8          = 0x00
    ///   [2..10]  timestamp: [u8; 8]  big-endian u64
    ///   [10..42] hash: [u8; 32]      SHA-256
    ///   [42..74] pubkey: [u8; 32]    Ed25519 public key
    ///   [74..138] signature: [u8; 64] Ed25519
    ///   [138..256] reserved2: [u8; 118] zeros
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct ProofOfOrigin {
        pub version: u8,
        pub reserved: u8,
        pub timestamp: [u8; 8],
        pub hash: [u8; 32],
        pub pubkey: [u8; 32],
        pub signature: [u8; 64],
        pub reserved2: [u8; 118],
    }

    const _SIZE: [(); 256] = [(); core::mem::size_of::<ProofOfOrigin>()];
}

// SAFETY: All fields are [u8; N] which are trivially Pod + Zeroable.
#[allow(unsafe_code)]
unsafe impl bytemuck::Zeroable for ProofOfOrigin {}
#[allow(unsafe_code)]
unsafe impl bytemuck::Pod for ProofOfOrigin {}

const PROTOCOL_VERSION: u8 = 0x01;
const MAX_TIMESTAMP: u64 = 253402300799;

impl ProofOfOrigin {
    /// Parse from a raw 256-byte slice. Zero-allocation.
    pub fn from_bytes(bytes: &[u8; 256]) -> Result<&Self> {
        let poo: &Self = bytemuck::try_from_bytes(bytes).map_err(|_| {
            Error::Format("invalid binary proof size (expected 256)".into())
        })?;

        if poo.version != PROTOCOL_VERSION {
            return Err(Error::Format(format!(
                "version must be 0x{:02x}, got 0x{:02x}",
                PROTOCOL_VERSION, poo.version
            )));
        }

        if poo.reserved != 0 {
            return Err(Error::Format(format!(
                "reserved byte must be 0x00, got 0x{:02x}",
                poo.reserved
            )));
        }

        if poo.reserved2.iter().any(|&b| b != 0) {
            return Err(Error::Format(
                "reserved2 field must be zero-filled".into(),
            ));
        }

        let ts = u64::from_be_bytes(poo.timestamp);
        if ts > MAX_TIMESTAMP {
            return Err(Error::Format(format!(
                "timestamp {} exceeds maximum {}",
                ts, MAX_TIMESTAMP
            )));
        }

        crypto::validate_public_key(&poo.pubkey)?;

        Ok(poo)
    }

    /// Decode the timestamp as a u64 (big-endian).
    pub fn timestamp_u64(&self) -> u64 {
        u64::from_be_bytes(self.timestamp)
    }

    /// Build from a Statement (text format). Allocates the 256-byte array.
    pub fn from_statement(stmt: &Statement) -> Result<Self> {
        let mut poo = Self::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.reserved = 0;
        poo.timestamp = stmt.time.to_be_bytes();
        poo.hash = stmt.hash_bytes;
        poo.pubkey = stmt.key_bytes;
        poo.signature = stmt.sig_bytes;
        // reserved2 already zeroed
        Ok(poo)
    }

    /// Convert to a Statement (text format). Allocates strings.
    pub fn to_statement(&self) -> Result<Statement> {
        let ts = self.timestamp_u64();
        let hash_hex = alloc::format!("sha256:{}", hex::encode(self.hash));
        let pub_b64 = crate::base64_encode(&self.pubkey);
        let sig_b64 = crate::base64_encode(&self.signature);

        let raw_lines = alloc::vec![
            alloc::format!("origin: v1"),
            alloc::format!("hash: {}", hash_hex),
            alloc::format!("time: {}", ts),
            alloc::format!("key: {}", pub_b64),
            alloc::format!("sig: {}", sig_b64),
        ];

        Ok(Statement {
            origin: alloc::string::String::from("v1"),
            hash: hash_hex,
            hash_bytes: self.hash,
            time: ts,
            key_b64: pub_b64,
            key_bytes: self.pubkey,
            sig_b64,
            sig_bytes: self.signature,
            raw_lines,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 256] {
        bytemuck::bytes_of(self).try_into().unwrap()
    }

    /// Create a zeroed instance.
    fn zeroed() -> Self {
        Self {
            version: 0,
            reserved: 0,
            timestamp: [0u8; 8],
            hash: [0u8; 32],
            pubkey: [0u8; 32],
            signature: [0u8; 64],
            reserved2: [0u8; 118],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::build_statement;
    use crate::SecretKey;

    #[test]
    fn test_binary_roundtrip() {
        let secret = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let stmt = build_statement(&secret, b"test data", 12345).unwrap();
        let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

        let bytes = poo.to_bytes();
        let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.timestamp_u64(), 12345);
        assert_eq!(parsed.hash, stmt.hash_bytes);
        assert_eq!(parsed.pubkey, stmt.key_bytes);
        assert_eq!(parsed.signature, stmt.sig_bytes);

        let roundtrip = parsed.to_statement().unwrap();
        assert_eq!(roundtrip.hash, stmt.hash);
        assert_eq!(roundtrip.time, stmt.time);
        assert_eq!(roundtrip.key_b64, stmt.key_b64);
        assert_eq!(roundtrip.sig_b64, stmt.sig_b64);
    }

    #[test]
    fn test_binary_rejects_invalid_version() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0x02;
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_nonzero_reserved() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01;
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_bad_timestamp() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[2..10].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_zero_pubkey() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        // pubkey at offset 42 is already zeros → identity point
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_nonzero_reserved2() {
        let secret = SecretKey::from_bytes(&[2u8; 32]).unwrap();
        let stmt = build_statement(&secret, b"x", 0).unwrap();
        let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
        poo.reserved2[0] = 1;
        let bytes = poo.to_bytes();
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_size() {
        assert_eq!(core::mem::size_of::<ProofOfOrigin>(), 256);
    }
}
