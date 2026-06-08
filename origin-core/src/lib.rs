pub mod audit;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod statement;

pub use crypto::{generate_keypair, generate_keypair_from_seed, Keypair, PublicKey, SecretKey, Signature};
pub use error::{Error, Result};
pub use hash::hash_bytes;
pub use statement::{
    build_revocation_statement, build_statement, encode_statement, verify_revocation,
    verify_statement, Statement, StatementBody, StatementType,
};

pub type Verdict = std::result::Result<(), Error>;

pub fn verify_bytes(statement_bytes: &[u8], artifact_bytes: &[u8]) -> Verdict {
    let stmt = statement::Statement::parse(statement_bytes)?;
    verify_statement(&stmt, artifact_bytes)
}

use base64::Engine as _;

pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.encode(bytes)
}

pub fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::URL_SAFE;
    URL_SAFE.decode(s)
}
