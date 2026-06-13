// SPDX-License-Identifier: MIT

//! HTTP Origin-Provenance Header
//!
//! Provides encoding and decoding for the `Origin-Provenance` HTTP header,
//! which carries a 256-byte Proof of Origin in base64url format.
//!
//! # Header Format
//!
//! ```text
//! Origin-Provenance: <base64url-encoded 256-byte PoO>
//! ```
//!
//! Example:
//! ```text
//! Origin-Provenance: AYqo4910CfGV_bLbLTy110ympwn7H5QSG7N0iAG1D29c...
//! ```
//!
//! # Verification
//!
//! To verify an artifact against an HTTP header:
//! 1. Decode the `Origin-Provenance` header value
//! 2. Verify the signature against the public key in the PoO
//! 3. Verify the content hash matches the artifact bytes

use alloc::string::String;

use crate::Verdict;
use crate::binary::ProofOfOrigin;
use crate::error::{Error, Result};
use crate::hash;
use crate::statement::{Statement, verify_statement_hash_with_time};

/// HTTP header name for Origin Provenance
pub const ORIGIN_PROVENANCE_HEADER: &str = "Origin-Provenance";

/// Maximum size of the header value (base64url-encoded 256 bytes ≈ 342 chars)
pub const MAX_HEADER_LENGTH: usize = 344;

/// Encode a Proof of Origin as an HTTP header value.
///
/// Returns a base64url-encoded string suitable for the `Origin-Provenance` header.
pub fn encode_origin_header(poo: &ProofOfOrigin) -> String {
    let bytes = poo.to_bytes();
    crate::base64_encode(&bytes)
}

/// Decode an HTTP header value into a Proof of Origin.
///
/// # Errors
/// - `Error::Format` if the header value is not valid base64url
/// - `Error::Format` if the decoded bytes are not exactly 256 bytes
/// - `Error::Format` if the PoO fails structural validation
pub fn decode_origin_header(header_value: &str) -> Result<ProofOfOrigin> {
    // Validate header length
    if header_value.len() > MAX_HEADER_LENGTH {
        return Err(Error::Format(alloc::format!(
            "Origin-Provenance header too long: {} chars (max {})",
            header_value.len(),
            MAX_HEADER_LENGTH
        )));
    }

    // Decode base64url
    let bytes = crate::base64_decode(header_value).map_err(|e| {
        Error::Format(alloc::format!(
            "invalid base64url in Origin-Provenance: {}",
            e
        ))
    })?;

    // Validate length
    if bytes.len() != 256 {
        return Err(Error::Format(alloc::format!(
            "Origin-Provenance decoded to {} bytes (expected 256)",
            bytes.len()
        )));
    }

    // Parse as ProofOfOrigin
    let mut arr = [0u8; 256];
    arr.copy_from_slice(&bytes);
    ProofOfOrigin::from_bytes(&arr)
}

/// Verify an artifact against an Origin-Provenance HTTP header.
///
/// This performs full verification:
/// 1. Decodes the header value
/// 2. Verifies the Ed25519ph signature
/// 3. Verifies the content hash matches the artifact
///
/// # Arguments
/// * `header_value` - The raw HTTP header value (base64url-encoded PoO)
/// * `artifact_bytes` - The artifact content to verify against
///
/// # Returns
/// `Ok(())` if verification succeeds, or an error with the appropriate error code.
pub fn verify_http_origin(header_value: &str, artifact_bytes: &[u8]) -> Verdict {
    let poo = decode_origin_header(header_value)?;

    // Convert to Statement for verification
    let stmt = poo_to_statement(&poo)?;

    // Compute artifact hash
    let actual_hash = hash::hash_hex(artifact_bytes);

    // Verify signature and content hash
    verify_statement_hash_with_time(&stmt, &actual_hash, None, None, None)
}

/// Verify an HTTP header with optional clock-skew check.
pub fn verify_http_origin_with_time(
    header_value: &str,
    artifact_bytes: &[u8],
    now: Option<u64>,
) -> Verdict {
    let poo = decode_origin_header(header_value)?;
    let stmt = poo_to_statement(&poo)?;
    let actual_hash = hash::hash_hex(artifact_bytes);
    verify_statement_hash_with_time(&stmt, &actual_hash, now, None, None)
}

/// Extract the public key from an Origin-Provenance header.
///
/// Returns the 32-byte Ed25519 public key from the PoO.
pub fn extract_public_key(header_value: &str) -> Result<[u8; 32]> {
    let poo = decode_origin_header(header_value)?;
    Ok(poo.public_key)
}

/// Extract the content hash from an Origin-Provenance header.
///
/// Returns the 32-byte SHA-256 content hash from the PoO.
pub fn extract_content_hash(header_value: &str) -> Result<[u8; 32]> {
    let poo = decode_origin_header(header_value)?;
    Ok(poo.content_hash)
}

/// Convert a Proof of Origin to a Statement for verification.
fn poo_to_statement(poo: &ProofOfOrigin) -> Result<Statement> {
    // Build statement lines matching the PoO fields
    let key_b64 = crate::base64_encode(&poo.public_key);
    let sig_b64 = crate::base64_encode(&poo.signature);
    let hash_hex = alloc::format!("sha256:{}", hex::encode(poo.content_hash));

    let raw_lines = alloc::vec![
        alloc::format!("origin: v1"),
        alloc::format!("hash: {}", hash_hex),
        alloc::format!("time: {}", poo.timestamp_u32()),
        alloc::format!("key: {}", key_b64),
        alloc::format!("sig: {}", sig_b64),
    ];

    Ok(Statement {
        origin: alloc::string::String::from("v1"),
        hash: hash_hex.clone(),
        hash_bytes: poo.content_hash,
        time: poo.timestamp_u32() as u64,
        key_b64,
        key_bytes: poo.public_key,
        sig_b64,
        sig_bytes: poo.signature,
        raw_lines,
        semantic_hash: poo.semantic_hash,
        semantic_model_ver: poo.semantic_model_ver,
        policy_hash: poo.policy_hash,
        parent_poo_hash: poo.parent_poo_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretKey, build_statement};

    fn make_test_poo() -> ProofOfOrigin {
        let secret = SecretKey::from_bytes(&[0x42; 32]).unwrap();
        let stmt = build_statement(&secret, b"test artifact", 1700000000).unwrap();
        let mut poo = ProofOfOrigin::from_statement(&stmt).unwrap();
        poo.tool_hash = crate::binary::compute_tool_hash("origin-cli");
        poo
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        let decoded = decode_origin_header(&header).unwrap();
        assert_eq!(poo.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn test_decode_invalid_base64() {
        let result = decode_origin_header("not-valid-base64!!!@#$%");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_wrong_length() {
        // Encode only 100 bytes instead of 256
        let short_bytes = [0u8; 100];
        let header = crate::base64_encode(&short_bytes);
        let result = decode_origin_header(&header);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty_header() {
        let result = decode_origin_header("");
        assert!(result.is_err());
    }

    #[test]
    fn test_header_too_long() {
        let long_header = "A".repeat(MAX_HEADER_LENGTH + 1);
        let result = decode_origin_header(&long_header);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_http_origin_success() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        let artifact = b"test artifact";
        let result = verify_http_origin(&header, artifact);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_http_origin_wrong_artifact() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        let result = verify_http_origin(&header, b"wrong artifact");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_public_key() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        let key = extract_public_key(&header).unwrap();
        assert_eq!(key, poo.public_key);
    }

    #[test]
    fn test_extract_content_hash() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        let hash = extract_content_hash(&header).unwrap();
        assert_eq!(hash, poo.content_hash);
    }

    #[test]
    fn test_header_name_constant() {
        assert_eq!(ORIGIN_PROVENANCE_HEADER, "Origin-Provenance");
    }

    #[test]
    fn test_header_length_fits_qr_v10() {
        let poo = make_test_poo();
        let header = encode_origin_header(&poo);
        // QR Version 10 capacity is 429 alphanumeric characters
        // base64url is 4/3 expansion: 256 * 4/3 ≈ 341 chars
        assert!(
            header.len() <= 429,
            "Header length {} exceeds QR V10 capacity 429",
            header.len()
        );
    }
}
