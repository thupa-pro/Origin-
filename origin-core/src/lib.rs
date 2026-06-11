#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod audit;
pub mod binary;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod statement;
#[cfg(target_arch = "wasm32")]
pub mod wasm_api;

pub use binary::ProofOfOrigin;
#[cfg(not(target_arch = "wasm32"))]
pub use crypto::generate_keypair;
pub use crypto::{
    generate_keypair_from_seed, validate_public_key, Keypair, PublicKey, SecretKey, Signature,
};
pub use error::{Error, Result};
pub use hash::hash_bytes;
pub use statement::{build_statement, encode_statement, verify_statement, Statement};

pub type Verdict = core::result::Result<(), Error>;

pub fn verify_bytes(statement_bytes: &[u8], artifact_bytes: &[u8]) -> Verdict {
    let stmt = statement::Statement::parse(statement_bytes)?;
    verify_statement(&stmt, artifact_bytes)
}

pub fn base64_encode(bytes: &[u8]) -> alloc::string::String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.encode(bytes)
}

pub fn base64_decode(s: &str) -> core::result::Result<alloc::vec::Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.decode(s)
}
