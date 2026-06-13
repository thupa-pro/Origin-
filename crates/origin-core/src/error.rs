// SPDX-License-Identifier: MIT

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    E001 = 1,
    E002 = 2,
    E003 = 3,
    E004 = 4,
    E005 = 5,
    E006 = 6,
    E007 = 7,
    E008 = 8,
}

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
    SignatureInvalid(alloc::string::String),
    ContentMismatch {
        expected: alloc::string::String,
        actual: alloc::string::String,
    },
    PooRevoked(alloc::string::String),
    IkmUnreachable {
        key: alloc::string::String,
    },
    IvgUnreachable(alloc::string::String),
    VersionUnknown {
        version: u8,
        detail: alloc::string::String,
    },
    TimestampFuture {
        ts: u64,
        now: u64,
    },
    ModelMismatch {
        ver_a: u8,
        ver_b: u8,
    },
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Crypto(_) | Error::SignatureInvalid(_) => ErrorCode::E001,
            Error::HashMismatch { .. } | Error::ContentMismatch { .. } => ErrorCode::E002,
            Error::PooRevoked(_) => ErrorCode::E003,
            Error::IkmUnreachable { .. } => ErrorCode::E004,
            Error::IvgUnreachable(_) => ErrorCode::E005,
            Error::VersionUnknown { .. } => ErrorCode::E006,
            Error::TimestampFuture { .. } => ErrorCode::E007,
            Error::ModelMismatch { .. } => ErrorCode::E008,
            _ => panic!("no error code for {:?}", self),
        }
    }

    pub fn code_str(&self) -> &'static str {
        match self {
            Error::Crypto(_) | Error::SignatureInvalid(_) => "E001",
            Error::HashMismatch { .. } | Error::ContentMismatch { .. } => "E002",
            Error::PooRevoked(_) => "E003",
            Error::IkmUnreachable { .. } => "E004",
            Error::IvgUnreachable(_) => "E005",
            Error::VersionUnknown { .. } => "E006",
            Error::TimestampFuture { .. } => "E007",
            Error::ModelMismatch { .. } => "E008",
            _ => "E000",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::Format(msg) => write!(f, "E006 {}: Invalid statement: {}", self.code_str(), msg),
            Error::Crypto(msg) => write!(f, "E001 SIGNATURE_INVALID: {}", msg),
            Error::SignatureInvalid(msg) => write!(f, "E001 SIGNATURE_INVALID: {}", msg),
            Error::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "E002 CONTENT_MISMATCH: Hash mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Error::ContentMismatch { expected, actual } => {
                write!(
                    f,
                    "E002 CONTENT_MISMATCH: expected {}, got {}",
                    expected, actual
                )
            }
            Error::PooRevoked(msg) => write!(f, "E003 POO_REVOKED: {}", msg),
            Error::IkmUnreachable { key } => {
                write!(
                    f,
                    "E004 IKM_UNREACHABLE: cannot resolve key {} — key resolution unavailable in current deployment",
                    key
                )
            }
            Error::IvgUnreachable(msg) => {
                write!(f, "E005 IVG_UNREACHABLE: rulebook unavailable: {}", msg)
            }
            Error::VersionUnknown { version, detail } => {
                write!(
                    f,
                    "E006 VERSION_UNKNOWN: version=0x{:02x}, best-effort parse with W005 warning: {}",
                    version, detail
                )
            }
            Error::TimestampFuture { ts, now } => {
                write!(
                    f,
                    "E007 TIMESTAMP_FUTURE: timestamp {} is {}s in the future (clock skew tolerated, warning only)",
                    ts,
                    ts.saturating_sub(*now)
                )
            }
            Error::ModelMismatch { ver_a, ver_b } => {
                write!(
                    f,
                    "E008 MODEL_MISMATCH: semantic model version {} vs {}, MATCH_UNCOMPUTABLE — treated as DERIVATIVE_PROBABLE",
                    ver_a, ver_b
                )
            }
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::Unattested(msg) => write!(f, "No provenance found: {}", msg),
            Error::TrailingContent(msg) => write!(f, "Trailing content after final line: {}", msg),
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
