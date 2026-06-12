//! PNG embedding via iTXt chunk.
//!
//! PNG structure:
//!   Signature: 8 bytes (0x89504E470D0A1A0A)
//!   IHDR chunk
//!   ... other chunks ...
//!   IDAT chunk(s)
//!   IEND chunk
//!
//! We embed the base64-encoded PoO in an iTXt chunk with keyword "origin"
//! inserted just before IEND. The PoO is base64-encoded because the iTXt
//! text field is UTF-8 and may not contain arbitrary binary.

use crate::EmbedError;

const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const ITXT_KEYWORD: &[u8] = b"origin";
const IEND_TYPE: [u8; 4] = *b"IEND";

/// Build an iTXt chunk payload.
/// iTXt: keyword\0 + compression_flag + compression_method + language\0 + translated\0 + text
fn build_itxt_chunk(payload: &[u8]) -> Vec<u8> {
    let base64_text = origin_core::base64_encode(payload);

    // keyword + null + comp_flag + comp_method + language\0 + translated\0 + text
    let data_len = ITXT_KEYWORD.len() + 1 + 1 + 1 + 1 + 1 + base64_text.len();
    let mut data = Vec::with_capacity(data_len);

    data.extend_from_slice(ITXT_KEYWORD);
    data.push(0x00); // null terminator for keyword
    data.push(0x00); // compression flag: uncompressed
    data.push(0x00); // compression method
    data.push(0x00); // null language tag
    data.push(0x00); // null translated keyword
    data.extend_from_slice(base64_text.as_bytes());

    // Build full chunk: length (4) + type (4) + data + CRC (4)
    let mut chunk = Vec::with_capacity(4 + 4 + data.len() + 4);
    let len = data.len() as u32;
    chunk.extend_from_slice(&len.to_be_bytes());
    chunk.extend_from_slice(b"iTXt");
    chunk.extend_from_slice(&data);

    // CRC covers type + data
    let crc = crc32(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    chunk
}

/// Simple CRC-32 implementation for PNG chunk checksums.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

/// Find IEND chunk position and return (before_iend, iend_chunk).
fn find_iend(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut i = 8; // skip signature
    while i + 12 <= bytes.len() {
        let chunk_len =
            u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let chunk_type = &bytes[i + 4..i + 8];
        let total = 4 + 4 + chunk_len + 4;
        if i + total > bytes.len() {
            break;
        }
        if chunk_type == IEND_TYPE {
            return Some((i, &bytes[i..i + total]));
        }
        i += total;
    }
    None
}

/// Find an existing iTXt chunk with keyword "origin". Returns (chunk_start, chunk_len).
fn find_itxt_origin(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut i = 8;
    while i + 12 <= bytes.len() {
        let chunk_len =
            u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let chunk_type = &bytes[i + 4..i + 8];
        let total = 4 + 4 + chunk_len + 4;
        if i + total > bytes.len() {
            break;
        }
        if chunk_type == b"iTXt" && chunk_len > ITXT_KEYWORD.len() {
            let data_start = i + 8;
            if &bytes[data_start..data_start + ITXT_KEYWORD.len()] == ITXT_KEYWORD
                && bytes[data_start + ITXT_KEYWORD.len()] == 0x00
            {
                return Some((i, total));
            }
        }
        i += total;
    }
    None
}

/// Embed payload into a PNG file via iTXt chunk.
pub fn embed(payload: &[u8], artifact: &[u8], overwrite: bool) -> Result<Vec<u8>, EmbedError> {
    if artifact.len() < 8 || artifact[0..8] != PNG_SIG {
        return Err(EmbedError::MalformedInput(
            "not a valid PNG (bad signature)",
        ));
    }

    let (iend_pos, iend_chunk) =
        find_iend(artifact).ok_or(EmbedError::MalformedInput("no IEND chunk found"))?;

    // Check for existing origin iTXt
    if let Some((pos, len)) = find_itxt_origin(artifact) {
        if !overwrite {
            return Err(EmbedError::ExistingOrigin);
        }
        // Remove existing iTXt, then insert new one before IEND
        let mut out = Vec::with_capacity(artifact.len());
        out.extend_from_slice(&artifact[..pos]);
        out.extend_from_slice(&artifact[pos + len..iend_pos]);
        let itxt = build_itxt_chunk(payload);
        out.extend_from_slice(&itxt);
        out.extend_from_slice(iend_chunk);
        return Ok(out);
    }

    // Insert iTXt chunk before IEND
    let itxt = build_itxt_chunk(payload);
    let mut out = Vec::with_capacity(artifact.len() + itxt.len());
    out.extend_from_slice(&artifact[..iend_pos]);
    out.extend_from_slice(&itxt);
    out.extend_from_slice(iend_chunk);
    Ok(out)
}

/// Extract origin payload from a PNG file.
pub fn extract(artifact: &[u8]) -> Option<Vec<u8>> {
    let (pos, _len) = find_itxt_origin(artifact)?;
    let data_start = pos + 8 + ITXT_KEYWORD.len() + 1 + 1 + 1 + 1 + 1;
    let chunk_len = u32::from_be_bytes([
        artifact[pos],
        artifact[pos + 1],
        artifact[pos + 2],
        artifact[pos + 3],
    ]) as usize;
    let text_end = pos + 8 + chunk_len;
    if data_start >= text_end {
        return None;
    }
    let b64_text = &artifact[data_start..text_end];
    let b64_str = core::str::from_utf8(b64_text).ok()?;
    origin_core::base64_decode(b64_str).ok()
}
