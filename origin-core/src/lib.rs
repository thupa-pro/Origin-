/// Cryptographic provenance for digital artifacts.
///
/// Origin is the smallest possible protocol for cryptographically verifiable
/// digital provenance. It binds an artifact hash, a public key, and a
/// timestamp into a self-contained signed statement.
///
/// # Quickstart
///
/// ```rust,ignore
/// use origin_core::{build_statement, encode_statement, verify_bytes, SecretKey};
///
/// // Generate a key from a seed (deterministic for testing)
/// let seed = [42u8; 32];
/// let secret = SecretKey::from_bytes(&seed).unwrap();
///
/// // Sign an artifact
/// let artifact = b"hello world";
/// let stmt = build_statement(&secret, artifact, 1717776000, None).unwrap();
/// let encoded = encode_statement(&stmt);
///
/// // Verify
/// assert!(verify_bytes(&encoded, artifact).is_ok());
///
/// // Verify with trusted key (recommended)
/// use origin_core::generate_keypair_from_seed;
/// let trusted = generate_keypair_from_seed(&seed).public.0;
/// assert!(origin_core::verify_against_key(&encoded, artifact, &trusted).is_ok());
/// ```
///
/// # Protocol
///
/// See RFC-0001.md for the full protocol specification.
pub mod audit;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod statement;

pub use crypto::{generate_keypair, generate_keypair_from_seed, Keypair, PublicKey, SecretKey, Signature};
pub use error::{Error, Result};
pub use hash::hash_bytes;
pub use statement::{
    build_statement, build_statement_with_algorithm, encode_statement,
    verify_statement, verify_against_key, verify_chain, verify_chain_against_key, Statement,
};

/// Convenience type alias for verification results.
pub type Verdict = std::result::Result<(), Error>;

/// Verify a provenance statement against artifact bytes.
///
/// This is the main entry point for verification. It parses the statement,
/// reconstructs the canonical body, validates the hash, and verifies the
/// Ed25519 signature in one call.
///
/// # Arguments
///
/// * `statement_bytes` — The complete `.origin` file content
/// * `artifact_bytes` — The artifact bytes to verify against
///
/// # Returns
///
/// * `Ok(())` — The statement is cryptographically valid for the artifact
/// * `Err(Error)` — Parsing or verification failed (see error variant)
///
/// # Example
///
/// ```rust,ignore
/// let stmt = std::fs::read("file.tar.gz.origin").unwrap();
/// let art = std::fs::read("file.tar.gz").unwrap();
/// match origin_core::verify_bytes(&stmt, &art) {
///     Ok(()) => println!("VERIFIED"),
///     Err(e) => println!("FAILED: {}", e),
/// }
/// ```
pub fn verify_bytes(statement_bytes: &[u8], artifact_bytes: &[u8]) -> Verdict {
    if (artifact_bytes.len() as u64) > MAX_ARTIFACT_SIZE {
        return Err(Error::Format(format!(
            "artifact too large ({} bytes, max {})",
            artifact_bytes.len(),
            MAX_ARTIFACT_SIZE
        )));
    }
    let stmt = statement::Statement::parse(statement_bytes)?;
    verify_statement(&stmt, artifact_bytes)
}

use base64::Engine as _;

/// Encode bytes as base64url (RFC 4648 §5, with padding).
///
/// Uses the URL-safe alphabet (no `+` or `/`, uses `-` and `_` instead).
pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.encode(bytes)
}

/// Maximum artifact size in bytes (2 GiB).
///
/// Artifacts larger than this are rejected by `verify_bytes` and
/// `build_statement` to prevent memory exhaustion.
pub const MAX_ARTIFACT_SIZE: u64 = 2_147_483_648;

/// Decode base64url (RFC 4648 §5, with padding).
///
/// Uses the URL-safe alphabet only (no `+` or `/`).
pub fn base64url_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.decode(s)
}

/// Decode base64url (deprecated, use `base64url_decode` instead).
#[deprecated(since = "1.1.2", note = "use base64url_decode instead")]
pub fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64url_decode(s)
}
