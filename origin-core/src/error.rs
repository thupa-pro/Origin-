use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Message(alloc::string::String),
    Format(alloc::string::String),
    Crypto(alloc::string::String),
    HashMismatch {
        expected: alloc::string::String,
        actual: alloc::string::String,
    },
    Io(alloc::string::String),
    Unattested(alloc::string::String),
    TrailingContent(alloc::string::String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::Format(msg) => write!(f, "Invalid statement: {}", msg),
            Error::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::HashMismatch { expected, actual } => {
                write!(f, "Hash mismatch: expected {}, got {}", expected, actual)
            }
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::Unattested(msg) => write!(f, "No provenance found: {}", msg),
            Error::TrailingContent(msg) => {
                write!(f, "Trailing content after final line: {}", msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Format(alloc::format!("base64 decode: {}", e))
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
