// SPDX-License-Identifier: MIT
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

//! Core types, functions, and re-exports for the Origin provenance library.

extern crate alloc;

/// Audit trail types and verification.
pub mod audit;
/// Binary serialization and deserialization.
pub mod binary;
/// Cryptographic key generation, signing, and verification.
pub mod crypto;
/// Error types and results.
pub mod error;
/// SHA-256 hashing utilities.
pub mod hash;
/// Statement parsing, building, and verification.
pub mod statement;
#[cfg(target_arch = "wasm32")]
/// WebAssembly API bindings.
pub mod wasm_api;

/// Re-export [`ProofOfOrigin`] from the `binary` module.
pub use binary::ProofOfOrigin;
#[cfg(not(target_arch = "wasm32"))]
/// Re-export [`generate_keypair`] from the `crypto` module.
pub use crypto::generate_keypair;
/// Re-export cryptographic key and signature types.
pub use crypto::{
    Keypair, PublicKey, SecretKey, Signature, constant_time_eq, generate_keypair_from_seed,
    validate_public_key,
};
/// Re-export [`Error`] and [`Result`] from the `error` module.
pub use error::{Error, Result};
/// Re-export [`hash_bytes`] from the `hash` module.
pub use hash::hash_bytes;
/// Re-export statement types and functions.
pub use hash::hash_reader;
pub use statement::{
    Statement, build_statement, build_statement_from_hash, encode_statement, verify_statement,
    verify_statement_hash,
};

/// A specialized [`Result`] type for verification operations.
pub type Verdict = core::result::Result<(), Error>;

/// Parse a statement from raw bytes and verify it against the given artifact.
pub fn verify_bytes(statement_bytes: &[u8], artifact_bytes: &[u8]) -> Verdict {
    let stmt = statement::Statement::parse(statement_bytes)?;
    verify_statement(&stmt, artifact_bytes)
}

/// Encode bytes as a URL-safe base64 string.
pub fn base64_encode(bytes: &[u8]) -> alloc::string::String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.encode(bytes)
}

/// Decode a URL-safe base64 string into raw bytes.
pub fn base64_decode(s: &str) -> core::result::Result<alloc::vec::Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.decode(s)
}
