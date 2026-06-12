#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Steganographic embedding and extraction of .origin statements into
//! common media formats: JPEG (APP15 marker), PNG (iTXt chunk),
//! MP3 (ID3v2 TXXX frame), PDF (metadata stream).
//!
//! All operations use binary-level splicing — files are never
//! decoded/re-encoded. The 256-byte ProofOfOrigin is embedded as-is
//! for JPEG/MP3/PDF, and base64-encoded for PNG iTXt (text field).

mod jpeg;
mod mp3;
mod pdf;
mod png;

/// Error type for embedding/extraction operations.
#[derive(Debug)]
pub enum EmbedError {
    /// Unsupported or unrecognized format
    UnsupportedFormat,
    /// Malformed container file
    MalformedInput(&'static str),
    /// Existing origin metadata found and overwrite disabled
    ExistingOrigin,
    /// I/O error during processing
    Io(String),
}

impl core::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedFormat => write!(f, "unsupported media format"),
            Self::MalformedInput(detail) => write!(f, "malformed input: {}", detail),
            Self::ExistingOrigin => write!(f, "existing origin metadata and overwrite disabled"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

/// Configuration for embedding a .origin statement into a media file.
pub struct EmbeddingConfig {
    /// The target media format.
    pub format: MediaFormat,
    /// Whether to overwrite existing .origin metadata in the file.
    pub overwrite: bool,
}

/// Supported media formats for steganographic embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    /// JPEG — embed via APP15 marker
    Jpeg,
    /// PNG — embed via iTXt chunk
    Png,
    /// MP3 — embed via ID3v2 TXXX frame
    Mp3,
    /// PDF — embed via document metadata stream
    Pdf,
}

impl MediaFormat {
    /// Detect the media format from the first bytes of the file.
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
            return Some(Self::Jpeg);
        }
        if bytes.len() >= 8
            && bytes[0] == 0x89
            && bytes[1] == b'P'
            && bytes[2] == b'N'
            && bytes[3] == b'G'
        {
            return Some(Self::Png);
        }
        if bytes.len() >= 3 && &bytes[0..3] == b"ID3" {
            return Some(Self::Mp3);
        }
        if bytes.len() >= 5 && &bytes[0..5] == b"%PDF-" {
            return Some(Self::Pdf);
        }
        None
    }
}

/// Embed a .origin statement payload (256-byte PoO) into a media file.
///
/// `payload` is the raw 256-byte `ProofOfOrigin` bytes.
/// Returns a new `Vec<u8>` containing the artifact with the payload embedded.
pub fn embed(payload: &[u8], artifact: &[u8], config: &EmbeddingConfig) -> Result<Vec<u8>, EmbedError> {
    if payload.len() != 256 {
        return Err(EmbedError::MalformedInput("payload must be exactly 256 bytes"));
    }
    match config.format {
        MediaFormat::Jpeg => jpeg::embed(payload, artifact, config.overwrite),
        MediaFormat::Png => png::embed(payload, artifact, config.overwrite),
        MediaFormat::Mp3 => mp3::embed(payload, artifact, config.overwrite),
        MediaFormat::Pdf => pdf::embed(payload, artifact, config.overwrite),
    }
}

/// Extract a .origin statement payload (256-byte PoO) from a media file.
///
/// Returns `None` if no origin payload is found.
pub fn extract(artifact: &[u8]) -> Option<Vec<u8>> {
    let format = MediaFormat::detect(artifact)?;
    match format {
        MediaFormat::Jpeg => jpeg::extract(artifact),
        MediaFormat::Png => png::extract(artifact),
        MediaFormat::Mp3 => mp3::extract(artifact),
        MediaFormat::Pdf => pdf::extract(artifact),
    }
}

#[cfg(test)]
mod tests;
