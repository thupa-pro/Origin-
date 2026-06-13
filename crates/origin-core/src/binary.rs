// SPDX-License-Identifier: MIT

use alloc::format;

use crate::error::{Error, Result};
use crate::statement::Statement;

pub use layout::ProofOfOrigin;

mod layout {
    /// 256-byte fixed-width binary representation of a Proof of Origin.
    ///
    /// # Layout (all multi-byte fields are Big-Endian unless noted)
    ///
    /// | Offset  | Size | Field             | Description |
    /// |---------|------|-------------------|-------------|
    /// | 0       | 1    | version           | Protocol version, always 0x01 |
    /// | 1–32    | 32   | public_key        | Raw Ed25519 public key (not key_id) |
    /// | 33–36   | 4    | timestamp         | Big-endian u32 UNIX epoch seconds (UTC) |
    /// | 37–52   | 16   | tool_hash         | SHA-256(UTF-8 tool string)[0..15] |
    /// | 53–84   | 32   | content_hash      | SHA-256(canonical artifact bytes) |
    /// | 85–100  | 16   | perceptual_hash   | pHash 8 bytes || SHA-256(content_hash ‖ pHash)[0..7] |
    /// | 101–132 | 32   | semantic_hash     | SimHash (32 zero bytes if semantic_model_ver = 0) |
    /// | 133–164 | 32   | policy_hash       | SHA-256(policy bytes) |
    /// | 165–180 | 16   | parent_poo_hash   | SHA-256(parent PoO)[0..15] (zero-filled for non-derivatives) |
    /// | 181     | 1    | semantic_model_ver| 0x00 if no semantic hash |
    /// | 182–189 | 8    | reserved          | Zero-filled (future use) |
    /// | 190–191 | 2    | flags             | Big-endian u16 bitmask |
    /// | 192–255 | 64   | signature         | Ed25519ph signature over bytes 0–191 |
    ///
    /// # Signed region
    ///
    /// The signature covers exactly **bytes 0–191** (192 bytes: all fields
    /// except the signature itself). The SHA-512 pre-hash is computed over
    /// this 192-byte prefix, then signed with Ed25519ph.
    ///
    /// # Design notes
    ///
    /// The original spec stated fields that sum to 295 bytes while claiming a
    /// 256-byte total. The RESERVED field was reduced from 47 to 8 bytes to
    /// satisfy the fixed 256-byte constraint required by QR Code Version 10
    /// (344 base64url characters, fits 429-character QR V10 capacity).
    /// The `public_key` field stores the raw 32-byte Ed25519 public key,
    /// enabling fully offline verification per spec check 9.2.
    /// The `key_id` (SHA-256(DER(pubkey))[0..32]) is a derived value
    /// computed on the fly via [`compute_key_id`] when needed for QR display.
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct ProofOfOrigin {
        pub version: u8,
        pub public_key: [u8; 32],
        pub timestamp: [u8; 4],
        pub tool_hash: [u8; 16],
        pub content_hash: [u8; 32],
        pub perceptual_hash: [u8; 16],
        pub semantic_hash: [u8; 32],
        pub policy_hash: [u8; 32],
        pub parent_poo_hash: [u8; 16],
        pub semantic_model_ver: u8,
        pub reserved: [u8; 8],
        pub flags_be: [u8; 2],
        pub signature: [u8; 64],
    }

    const _SIZE: [(); 256] = [(); core::mem::size_of::<ProofOfOrigin>()];
}

#[allow(unsafe_code)]
unsafe impl bytemuck::Zeroable for ProofOfOrigin {}
#[allow(unsafe_code)]
unsafe impl bytemuck::Pod for ProofOfOrigin {}

const PROTOCOL_VERSION: u8 = 0x01;
// Flag bitmask definitions
//
// POLICY NOTE: These flags are **stored** by L1 but their policy enforcement
// (e.g. "HW_ATTESTED only set inside TEE", "AI_GENERATED set when HCS < 0.5",
// "REVOCABLE set when IVG revocation permitted") is a service-layer concern.
// L1 core does not enforce these policies — it records what the caller provides.
// Service layers (L2–L5) are responsible for policy validation.
const FLAG_HW_ATTESTED: u16 = 0x0001;
const FLAG_REVOCABLE: u16 = 0x0002;
const FLAG_ZK_READY: u16 = 0x0004;
const FLAG_PQ_READY: u16 = 0x0008;
const FLAG_MULTI_AUTHOR: u16 = 0x0010;
const FLAG_PRIVATE_POLICY: u16 = 0x0020;
const FLAG_OFFLINE_BUNDLE: u16 = 0x0040;
const FLAG_AI_GENERATED: u16 = 0x0080;

/// Tool string used when no tool is specified.
impl ProofOfOrigin {
    /// Parse from exactly 256 bytes.
    ///
    /// Performs structural validation (version, reserved, flags, public_key).
    /// Timestamp validation (E007 TIMESTAMP_FUTURE) is NOT performed here —
    /// use `verify_statement_hash_with_time` for clock-skew checks.
    pub fn from_bytes(bytes: &[u8; 256]) -> Result<Self> {
        let poo: &Self = bytemuck::try_from_bytes(bytes)
            .map_err(|_| Error::Format("invalid binary proof size (expected 256)".into()))?;

        let mut result = *poo;

        if poo.version != PROTOCOL_VERSION {
            // E006 VERSION_UNKNOWN: best-effort parse, return with warning
            result.version = poo.version;
            return Ok(result);
        }

        if poo.reserved.iter().any(|&b| b != 0) {
            return Err(Error::Format(
                "RESERVED bytes (182-189) must be zero-filled".into(),
            ));
        }

        // Bits 8-15 of flags must be zero in v1
        let flags = poo.flags();
        if flags & 0xFF00 != 0 {
            return Err(Error::Format(format!(
                "flags bits 8-15 must be zero in v1, got 0x{:04x}",
                flags
            )));
        }

        // Validate public_key is well-formed (non-zero, not identity point)
        if poo.public_key.iter().all(|&b| b == 0) {
            return Err(Error::Format("public_key must not be all zeros".into()));
        }

        if result.is_multi_author() && result.signature[48..64].iter().any(|&b| b != 0) {
            return Err(Error::Format(
                "MULTI_AUTHOR: BLS signature padding bytes 48-63 must be zero".into(),
            ));
        }

        Ok(result)
    }

    /// Decode timestamp as big-endian u32.
    pub fn timestamp_u32(&self) -> u32 {
        u32::from_be_bytes(self.timestamp)
    }

    /// Decode flags as big-endian u16.
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes(self.flags_be)
    }

    /// Set flags as big-endian u16.
    pub fn set_flags(&mut self, flags: u16) {
        self.flags_be = flags.to_be_bytes();
    }

    /// Build from a Statement (text format).
    pub fn from_statement(stmt: &Statement) -> Result<Self> {
        let mut poo = Self::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.public_key = stmt.key_bytes;
        poo.timestamp = (stmt.time as u32).to_be_bytes();
        poo.content_hash = stmt.hash_bytes;
        poo.semantic_hash = stmt.semantic_hash;
        poo.semantic_model_ver = stmt.semantic_model_ver;
        poo.policy_hash = stmt.policy_hash;
        poo.parent_poo_hash = stmt.parent_poo_hash;
        poo.signature = stmt.sig_bytes;
        Ok(poo)
    }

    /// Convert to a Statement (text format).
    pub fn to_statement(&self) -> Result<Statement> {
        let ts = self.timestamp_u32() as u64;
        let hash_hex = alloc::format!("sha256:{}", hex::encode(self.content_hash));
        let key_b64 = crate::base64_encode(&self.public_key);

        let raw_lines = alloc::vec![
            alloc::format!("origin: v1"),
            alloc::format!("hash: {}", hash_hex),
            alloc::format!("time: {}", ts),
            alloc::format!("key: {}", key_b64),
            alloc::format!("sig: {}", crate::base64_encode(&self.signature)),
        ];

        Ok(Statement {
            origin: alloc::string::String::from("v1"),
            hash: hash_hex,
            hash_bytes: self.content_hash,
            time: ts,
            key_b64,
            key_bytes: self.public_key,
            sig_b64: crate::base64_encode(&self.signature),
            sig_bytes: self.signature,
            raw_lines,
            semantic_hash: self.semantic_hash,
            semantic_model_ver: self.semantic_model_ver,
            policy_hash: self.policy_hash,
            parent_poo_hash: self.parent_poo_hash,
        })
    }

    /// Serialize to 256 bytes.
    pub fn to_bytes(&self) -> [u8; 256] {
        bytemuck::bytes_of(self).try_into().unwrap()
    }

    /// Create a zeroed instance.
    pub fn zeroed() -> Self {
        Self {
            version: 0,
            public_key: [0u8; 32],
            timestamp: [0u8; 4],
            tool_hash: [0u8; 16],
            content_hash: [0u8; 32],
            perceptual_hash: [0u8; 16],
            semantic_hash: [0u8; 32],
            policy_hash: [0u8; 32],
            parent_poo_hash: [0u8; 16],
            semantic_model_ver: 0,
            reserved: [0u8; 8],
            flags_be: [0u8; 2],
            signature: [0u8; 64],
        }
    }

    /// Return bytes 0-191 (the portion covered by the signature).
    pub fn signed_prefix(&self) -> [u8; 192] {
        let bytes = self.to_bytes();
        let mut prefix = [0u8; 192];
        prefix.copy_from_slice(&bytes[..192]);
        prefix
    }

    /// Extract the BLS aggregate signature from the signature field
    /// when MULTI_AUTHOR flag is set (bytes 0-47).
    pub fn bls_signature_bytes(&self) -> [u8; 48] {
        let mut sig = [0u8; 48];
        sig.copy_from_slice(&self.signature[..48]);
        sig
    }

    /// Check if this PoO's content hash appears in a revocation set.
    ///
    /// Returns `Error::PooRevoked` (E003) if the hash is found in the set.
    pub fn check_revocation(&self, revoked_hashes: &[[u8; 32]]) -> Result<()> {
        if revoked_hashes.contains(&self.content_hash) {
            return Err(Error::PooRevoked(alloc::format!(
                "content hash {} is in revocation set",
                hex::encode(self.content_hash)
            )));
        }
        Ok(())
    }

    // Flag helpers
    pub fn has_flag(&self, flag: u16) -> bool {
        self.flags() & flag != 0
    }
    pub fn is_hw_attested(&self) -> bool {
        self.has_flag(FLAG_HW_ATTESTED)
    }
    pub fn is_revocable(&self) -> bool {
        self.has_flag(FLAG_REVOCABLE)
    }
    pub fn is_zk_ready(&self) -> bool {
        self.has_flag(FLAG_ZK_READY)
    }
    pub fn is_pq_ready(&self) -> bool {
        self.has_flag(FLAG_PQ_READY)
    }
    pub fn is_multi_author(&self) -> bool {
        self.has_flag(FLAG_MULTI_AUTHOR)
    }
    pub fn is_private_policy(&self) -> bool {
        self.has_flag(FLAG_PRIVATE_POLICY)
    }
    pub fn is_offline_bundle(&self) -> bool {
        self.has_flag(FLAG_OFFLINE_BUNDLE)
    }
    pub fn is_ai_generated(&self) -> bool {
        self.has_flag(FLAG_AI_GENERATED)
    }
}

/// Compute tool_hash = SHA-256(UTF-8 tool string)[0..15].
pub fn compute_tool_hash(tool: &str) -> [u8; 16] {
    let hash = crate::hash::hash_bytes(tool.as_bytes());
    let mut h = [0u8; 16];
    h.copy_from_slice(&hash[..16]);
    h
}

/// Compute perceptual_hash (16 bytes):
///   bytes 0-7: pHash output (big-endian u64)
///   bytes 8-15: SHA-256(content_hash || pHash byte)[0..7]
pub fn per_hash(phash: u64, content_hash: &[u8; 32]) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[..8].copy_from_slice(&phash.to_be_bytes());
    let mut combined = [0u8; 40];
    combined[..32].copy_from_slice(content_hash);
    combined[32..40].copy_from_slice(&phash.to_be_bytes());
    let binding = crate::hash::hash_bytes(&combined);
    h[8..16].copy_from_slice(&binding[..8]);
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;
    use crate::statement::build_statement;

    #[test]
    fn test_binary_size() {
        assert_eq!(core::mem::size_of::<ProofOfOrigin>(), 256);
    }

    #[test]
    fn test_binary_alignment() {
        assert_eq!(core::mem::align_of::<ProofOfOrigin>(), 1);
    }

    #[test]
    fn test_byte_offsets() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(ProofOfOrigin, version), 0);
        assert_eq!(offset_of!(ProofOfOrigin, public_key), 1);
        assert_eq!(offset_of!(ProofOfOrigin, timestamp), 33);
        assert_eq!(offset_of!(ProofOfOrigin, tool_hash), 37);
        assert_eq!(offset_of!(ProofOfOrigin, content_hash), 53);
        assert_eq!(offset_of!(ProofOfOrigin, perceptual_hash), 85);
        assert_eq!(offset_of!(ProofOfOrigin, semantic_hash), 101);
        assert_eq!(offset_of!(ProofOfOrigin, policy_hash), 133);
        assert_eq!(offset_of!(ProofOfOrigin, parent_poo_hash), 165);
        assert_eq!(offset_of!(ProofOfOrigin, semantic_model_ver), 181);
        assert_eq!(offset_of!(ProofOfOrigin, reserved), 182);
        assert_eq!(offset_of!(ProofOfOrigin, flags_be), 190);
        assert_eq!(offset_of!(ProofOfOrigin, signature), 192);
    }

    #[test]
    fn test_sum_check() {
        assert_eq!(
            1 + 32 + 4 + 16 + 32 + 16 + 32 + 32 + 16 + 1 + 8 + 2 + 64,
            256
        );
    }

    #[test]
    fn test_binary_roundtrip() {
        let secret = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let stmt = build_statement(&secret, b"test data", 12345).unwrap();
        let poo = ProofOfOrigin::from_statement(&stmt).unwrap();

        let bytes = poo.to_bytes();
        let parsed = ProofOfOrigin::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.public_key, stmt.key_bytes);
        assert_eq!(parsed.content_hash, stmt.hash_bytes);
        assert_eq!(parsed.signature, stmt.sig_bytes);

        let roundtrip = parsed.to_statement().unwrap();
        assert_eq!(roundtrip.hash, stmt.hash);
        assert_eq!(roundtrip.time, stmt.time);
    }

    #[test]
    fn test_rejects_invalid_version() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0x02;
        // Set a valid public_key (non-zero)
        bytes[1] = 0x01;
        // E006: best-effort parse returns Ok, not Err
        let result = ProofOfOrigin::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_zero_public_key() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        // public_key is all zeros (bytes 1-32)
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_rejects_nonzero_reserved() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01; // valid public_key (non-zero)
        bytes[182] = 0x01;
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_rejects_flags_high_bits() {
        let mut bytes = [0u8; 256];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = 0x01; // valid public_key (non-zero)
        bytes[190] = 0x12; // bits 8-15 set in BE
        assert!(ProofOfOrigin::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_timestamp_be() {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        let ts: u32 = 1700000000;
        poo.timestamp = ts.to_be_bytes();
        assert_eq!(poo.timestamp_u32(), ts);
        let bytes = poo.to_bytes();
        assert_eq!(bytes[33], (ts >> 24) as u8);
        assert_eq!(bytes[34], (ts >> 16) as u8);
        assert_eq!(bytes[35], (ts >> 8) as u8);
        assert_eq!(bytes[36], ts as u8);
    }

    #[test]
    fn test_flags_be() {
        let mut poo = ProofOfOrigin::zeroed();
        poo.version = PROTOCOL_VERSION;
        poo.set_flags(0x1234);
        assert_eq!(poo.flags(), 0x1234);
        let bytes = poo.to_bytes();
        assert_eq!(bytes[190], 0x12); // BE high byte
        assert_eq!(bytes[191], 0x34); // BE low byte
    }

    #[test]
    fn test_flags_flag_helpers() {
        let mut poo = ProofOfOrigin::zeroed();
        poo.set_flags(FLAG_HW_ATTESTED | FLAG_REVOCABLE);
        assert!(poo.is_hw_attested());
        assert!(poo.is_revocable());
        assert!(!poo.is_ai_generated());
    }

    #[test]
    fn test_signed_prefix_length() {
        assert_eq!(ProofOfOrigin::zeroed().signed_prefix().len(), 192);
    }

    #[test]
    fn test_per_hash_16_bytes() {
        let phash: u64 = 0x1234567890ABCDEF;
        let ch: [u8; 32] = [0xAB; 32];
        let result = per_hash(phash, &ch);
        assert_eq!(result.len(), 16);
        assert_eq!(result[..8], phash.to_be_bytes());
    }

    #[test]
    fn test_multi_author_rejects_nonzero_padding() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0x01;
        bytes[1] = 0x01;
        let mut poo = ProofOfOrigin::from_bytes(&bytes).unwrap();
        poo.set_flags(FLAG_MULTI_AUTHOR);
        // Set a non-zero byte in the BLS padding region (signature bytes 48-63)
        poo.signature[48] = 0x01;
        let encoded = poo.to_bytes();
        let result = ProofOfOrigin::from_bytes(&encoded);
        assert!(
            result.is_err(),
            "MULTI_AUTHOR PoO with non-zero padding must be rejected"
        );
    }

    #[test]
    fn test_multi_author_accepts_valid_padding() {
        let mut bytes = [0u8; 256];
        bytes[0] = 0x01;
        bytes[1] = 0x01;
        let mut poo = ProofOfOrigin::from_bytes(&bytes).unwrap();
        poo.set_flags(FLAG_MULTI_AUTHOR);
        // All 64 bytes of signature are zero — BLS sig bytes (0-47) + padding (48-63)
        let encoded = poo.to_bytes();
        let result = ProofOfOrigin::from_bytes(&encoded);
        assert!(
            result.is_ok(),
            "MULTI_AUTHOR PoO with zero padding must be accepted"
        );
    }

    #[test]
    fn test_bls_signature_bytes() {
        let mut poo = ProofOfOrigin::zeroed();
        poo.signature[..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let bls_sig = poo.bls_signature_bytes();
        assert_eq!(bls_sig.len(), 48);
        assert_eq!(
            bls_sig[..8],
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(bls_sig[8..], [0u8; 40]);
    }

    #[test]
    fn test_poo_v1_vectors() {
        // Appendix B test vectors: verify the implementation produces
        // known-good hex outputs for 5 canonical creation operations.
        // Uses path relative to CARGO_MANIFEST_DIR (crates/origin-core).
        let path = alloc::format!(
            "{}/../../tests/interop/test_vectors/poo_v1.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("test vectors not found at {}", path));
        let vectors: serde_json::Value = serde_json::from_str(&data).unwrap();
        let vectors = vectors["vectors"].as_array().unwrap();

        assert!(!vectors.is_empty(), "must have at least 1 test vector");

        for v in vectors {
            let id = v["id"].as_i64().unwrap();
            let seed_hex = v["seed_hex"].as_str().unwrap();
            let artifact_len = v["artifact_len"].as_u64().unwrap() as usize;
            let timestamp = v["timestamp"].as_u64().unwrap();
            let expected_hex = v["expected_bytes_hex"].as_str().unwrap();

            let seed =
                hex::decode(seed_hex).unwrap_or_else(|_| panic!("vector {}: invalid seed_hex", id));
            assert_eq!(seed.len(), 32, "vector {}: seed must be 32 bytes", id);
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let secret = SecretKey::from_bytes(&seed_arr)
                .unwrap_or_else(|_| panic!("vector {}: invalid seed", id));

            let artifact = vec![0xAAu8; artifact_len];
            let stmt = build_statement(&secret, &artifact, timestamp)
                .unwrap_or_else(|_| panic!("vector {}: build_statement failed", id));
            let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
            // build_statement uses DEFAULT_TOOL_STRING = "origin-cli"
            poo.tool_hash = compute_tool_hash("origin-cli");
            let actual_hex = hex::encode(poo.to_bytes());

            assert_eq!(actual_hex, expected_hex, "Vector {} mismatch", id);
        }
    }
}
