// SPDX-License-Identifier: MIT

//! Binary (packed, 256-byte) serialization of a Proof of Origin.
//!
//! Re-exports [`ProofOfOrigin`] from a private `layout` module and provides
//! construction, parsing, and conversion methods.

use alloc::format;

use crate::crypto;
use crate::error::{Error, Result};
use crate::statement::Statement;

/// 256-byte fixed-width binary representation of a Proof of Origin.
pub use layout::ProofOfOrigin;

mod layout {
    /// 256-byte fixed-width binary representation of a Proof of Origin.
    ///
    /// Layout (all multi-byte fields are Little-Endian):
    ///   [0]      version: u8           = 0x01
    ///   [1..10)  reserved: [u8; 9]     = zeros (bytes 0-1 = LE u16 flags)
    ///   [10..18) timestamp: [u8; 8]    little-endian u64
    ///   [18..50) hash: [u8; 32]        SHA-256
    ///   [50..82) pubkey: [u8; 32]      Ed25519 public key
    ///   [82..146] signature: [u8; 64]  Ed25519
    ///   [146..256] reserved2: [u8; 110] zeros
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct ProofOfOrigin {
        /// Protocol version byte (must be `0x01`).
        pub version: u8,
        /// Reserved bytes, must be zero-filled.
        /// First 2 bytes can be interpreted as a little-endian u16 flags word.
        pub reserved: [u8; 9],
        /// Unix timestamp encoded as little-endian u64.
        pub timestamp: [u8; 8],
        /// SHA-256 hash (32 bytes).
        pub hash: [u8; 32],
        /// Ed25519 public key (32 bytes).
        pub pubkey: [u8; 32],
        /// Ed25519 signature (64 bytes).
        pub signature: [u8; 64],
        /// Reserved padding, must be zero-filled (110 bytes).
        pub reserved2: [u8; 110],
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
        let poo: &Self = bytemuck::try_from_bytes(bytes)
            .map_err(|_| Error::Format("invalid binary proof size (expected 256)".into()))?;

        if poo.version != PROTOCOL_VERSION {
            return Err(Error::Format(format!(
                "version must be 0x{:02x}, got 0x{:02x}",
                PROTOCOL_VERSION, poo.version
            )));
        }

        // Reserved bytes 0-1 are the flags word (allowed to be non-zero).
        // Bytes 2-9 must be zero-filled for future expansion.
        if poo.reserved[2..].iter().any(|&b| b != 0) {
            return Err(Error::Format(
                "reserved padding (bytes 2-8) must be zero-filled".into(),
            ));
        }

        if poo.reserved2.iter().any(|&b| b != 0) {
            return Err(Error::Format("reserved2 field must be zero-filled".into()));
        }

        let ts = u64::from_le_bytes(poo.timestamp);
        if ts > MAX_TIMESTAMP {
            return Err(Error::Format(format!(
                "timestamp {} exceeds maximum {}",
                ts, MAX_TIMESTAMP
            )));
        }

        crypto::validate_public_key(&poo.pubkey)?;

        Ok(poo)
    }

    /// Decode the timestamp as a u64 (little-endian).
    pub fn timestamp_u64(&self) -> u64 {
        u64::from_le_bytes(self.timestamp)
    }

    /// Decode the flags word (first 2 bytes of reserved as LE u16).
    pub fn flags(&self) -> u16 {
        u16::from_le_bytes([self.reserved[0], self.reserved[1]])
    }

    /// Set the flags word (first 2 bytes of reserved).
    pub fn set_flags(&mut self, flags: u16) {
        let [lo, hi] = flags.to_le_bytes();
        self.reserved[0] = lo;
        self.reserved[1] = hi;
    }

    /// Build from a Statement (text format). Allocates the 256-byte array.
    pub fn from_statement(stmt: &Statement) -> Result<Self> {
        let mut poo = Self::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.timestamp = stmt.time.to_le_bytes();
        poo.hash = stmt.hash_bytes;
        poo.pubkey = stmt.key_bytes;
        poo.signature = stmt.sig_bytes;
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
            reserved: [0u8; 9],
            timestamp: [0u8; 8],
            hash: [0u8; 32],
            pubkey: [0u8; 32],
            signature: [0u8; 64],
            reserved2: [0u8; 110],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;
    use crate::statement::build_statement;

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
        bytes[1] = 0x01; // first byte of 9-byte reserved
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_bad_timestamp() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        // timestamp at offset [10..18], LE bytes max u64
        bytes[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_binary_rejects_zero_pubkey() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        // pubkey at offset [50..82] is already zeros → identity point
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

    #[test]
    fn test_binary_alignment() {
        assert_eq!(core::mem::align_of::<ProofOfOrigin>(), 1);
    }

    #[test]
    fn test_flags_roundtrip() {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        assert_eq!(poo.flags(), 0);
        poo.set_flags(0x1234);
        assert_eq!(poo.flags(), 0x1234);
        // Ensure other reserved bytes remain zero
        assert_eq!(poo.reserved[2..], [0u8; 7]);
    }

    #[test]
    fn test_le_timestamp_hex() {
        // Domain 1.3: timestamp=1700000000, flags=0x1234
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.timestamp = 1700000000u64.to_le_bytes();
        poo.set_flags(0x1234);
        let bytes = poo.to_bytes();
        // version should be 0x01
        assert_eq!(bytes[0], 0x01);
        // flags (first 2 of reserved) should be 0x34, 0x12 (LE)
        assert_eq!(bytes[1], 0x34);
        assert_eq!(bytes[2], 0x12);
        // timestamp should be LE: 1700000000 = 0x6553F100
        // LE: 00 F1 53 65 00 00 00 00
        assert_eq!(bytes[10], 0x00);
        assert_eq!(bytes[11], 0xF1);
        assert_eq!(bytes[12], 0x53);
        assert_eq!(bytes[13], 0x65);
        assert_eq!(bytes[14], 0x00);
        assert_eq!(bytes[15], 0x00);
        assert_eq!(bytes[16], 0x00);
        assert_eq!(bytes[17], 0x00);
    }

    #[test]
    fn test_from_bytes_accepts_flags() {
        // Bytes 0-1 of reserved are flags and may be non-zero
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        // Set valid pubkey
        bytes[50] = 208;
        bytes[51] = 90;
        bytes[52] = 152;
        bytes[53] = 1;
        bytes[54] = 130;
        bytes[55] = 177;
        bytes[56] = 10;
        bytes[57] = 183;
        bytes[58] = 213;
        bytes[59] = 75;
        bytes[60] = 254;
        bytes[61] = 211;
        bytes[62] = 201;
        bytes[63] = 100;
        bytes[64] = 7;
        bytes[65] = 58;
        bytes[66] = 14;
        bytes[67] = 225;
        bytes[68] = 114;
        bytes[69] = 243;
        bytes[70] = 218;
        bytes[71] = 162;
        bytes[72] = 38;
        bytes[73] = 53;
        bytes[74] = 175;
        bytes[75] = 2;
        bytes[76] = 26;
        bytes[77] = 104;
        bytes[78] = 247;
        bytes[79] = 7;
        bytes[80] = 81;
        bytes[81] = 26;
        bytes[1] = 0x34; // flags byte 0
        bytes[2] = 0x12; // flags byte 1
        assert!(
            ProofOfOrigin::from_bytes(&bytes).is_ok(),
            "flags bytes should be accepted"
        );
    }

    #[test]
    fn test_from_bytes_rejects_nonzero_reserved_padding() {
        // Bytes 2-8 of reserved must be zero
        for i in 2..9 {
            let mut bytes = [0u8; 256];
            bytes[0] = PROTOCOL_VERSION;
            // Set valid pubkey
            bytes[50] = 208;
            bytes[51] = 90;
            bytes[52] = 152;
            bytes[53] = 1;
            bytes[54] = 130;
            bytes[55] = 177;
            bytes[56] = 10;
            bytes[57] = 183;
            bytes[58] = 213;
            bytes[59] = 75;
            bytes[60] = 254;
            bytes[61] = 211;
            bytes[62] = 201;
            bytes[63] = 100;
            bytes[64] = 7;
            bytes[65] = 58;
            bytes[66] = 14;
            bytes[67] = 225;
            bytes[68] = 114;
            bytes[69] = 243;
            bytes[70] = 218;
            bytes[71] = 162;
            bytes[72] = 38;
            bytes[73] = 53;
            bytes[74] = 175;
            bytes[75] = 2;
            bytes[76] = 26;
            bytes[77] = 104;
            bytes[78] = 247;
            bytes[79] = 7;
            bytes[80] = 81;
            bytes[81] = 26;
            bytes[1 + i] = 0xFF;
            assert!(
                ProofOfOrigin::from_bytes(&bytes).is_err(),
                "reserved padding byte {} should be rejected",
                i
            );
        }
    }

    #[test]
    fn test_reserved_is_exactly_9_bytes() {
        assert_eq!(
            core::mem::size_of::<[u8; 9]>(),
            core::mem::size_of_val(&ProofOfOrigin::zeroed().reserved)
        );
    }
}
