// SPDX-License-Identifier: MIT

//! Error types and results for the Origin provenance library.

use core::fmt;

/// Errors that can occur during provenance statement operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A generic error message.
    Message(alloc::string::String),
    /// An error in statement format or parsing.
    Format(alloc::string::String),
    /// A cryptographic operation error.
    Crypto(alloc::string::String),
    /// A hash mismatch between expected and actual values.
    HashMismatch {
        /// The expected hash value.
        expected: alloc::string::String,
        /// The actual computed hash value.
        actual: alloc::string::String,
    },
    /// An I/O error (available with the `std` feature).
    Io(alloc::string::String),
    /// No provenance found for the given artifact.
    Unattested(alloc::string::String),
    /// Trailing content found after the final statement line.
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

/// A specialized [`Result`] type for the Origin provenance library.
pub type Result<T> = core::result::Result<T, Error>;
