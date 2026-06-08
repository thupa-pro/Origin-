use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("Invalid statement: {0}")]
    Format(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("I/O error: {0}")]
    Io(String),
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
