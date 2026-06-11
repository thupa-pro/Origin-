pub mod audit;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod statement;

pub use crypto::{
    Keypair, PublicKey, SecretKey, Signature, generate_keypair, generate_keypair_from_seed,
    validate_public_key,
};
pub use error::{Error, Result};
pub use hash::hash_bytes;
pub use statement::{Statement, build_statement, encode_statement, verify_statement};

pub type Verdict = std::result::Result<(), Error>;

pub fn verify_bytes(statement_bytes: &[u8], artifact_bytes: &[u8]) -> Verdict {
    let stmt = statement::Statement::parse(statement_bytes)?;
    verify_statement(&stmt, artifact_bytes)
}

pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.encode(bytes)
}

pub fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.decode(s)
}
