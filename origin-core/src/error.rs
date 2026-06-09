use thiserror::Error;

/// Errors that can occur during parsing, signing, or verification of
/// provenance statements.
///
/// All error variants implement `Display` and `std::error::Error`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A general error message (catch-all for non-categorized errors).
    #[error("{0}")]
    Message(String),

    /// The statement is malformed — wrong line count, bad field format,
    /// invalid base64url, out-of-range timestamp, etc.
    #[error("Invalid statement: {0}")]
    Format(String),

    /// A cryptographic operation failed (key invalid, signature invalid, etc.).
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// The artifact hash does not match the hash in the statement.
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// An I/O error occurred (file not found, permission denied, etc.).
    #[error("I/O error: {0}")]
    Io(String),

    /// The statement's parent field does not match the hash of the parent statement.
    #[error("Parent hash mismatch: child parent field is {child_parent}, but actual parent hash is {actual_parent}")]
    ParentMismatch { child_parent: String, actual_parent: String },

    /// The statement has a parent field but no parent statement was provided.
    #[error("Statement has a parent field but no parent statement was provided")]
    MissingParent,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Format(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
