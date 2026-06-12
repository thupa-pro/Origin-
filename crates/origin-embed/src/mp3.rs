//! MP3 embedding via ID3v2 TXXX frame.
//!
//! ID3v2 structure:
//!   Header: "ID3" + version (2 bytes) + flags (1 byte) + size (4 bytes, syncsafe)
//!   Frames... (each with ID + size + flags + data)
//!   Padding (zeros)
//!
//! We add a TXXX frame with description "origin" containing the base64-encoded
//! 256-byte PoO. The tag size is updated accordingly.

use crate::EmbedError;

/// Magic header for ID3v2
const ID3_HEADER: &[u8] = b"ID3";
/// TXXX frame ID
const TXXX_ID: &[u8] = b"TXXX";
/// Frame description
const DESCRIPTION: &[u8] = b"origin";

/// Decode a syncsafe integer (4 bytes, 7 bits per byte, big-endian).
fn decode_syncsafe(buf: &[u8; 4]) -> u32 {
    ((buf[0] as u32) << 21)
        | ((buf[1] as u32) << 14)
        | ((buf[2] as u32) << 7)
        | (buf[3] as u32)
}

/// Encode a syncsafe integer (4 bytes, 7 bits per byte, big-endian).
fn encode_syncsafe(mut val: u32) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf[3] = (val & 0x7F) as u8;
    val >>= 7;
    buf[2] = (val & 0x7F) as u8;
    val >>= 7;
    buf[1] = (val & 0x7F) as u8;
    val >>= 7;
    buf[0] = (val & 0x7F) as u8;
    buf
}

/// Build a TXXX frame containing the base64-encoded payload.
/// Frame format: ID (4) + size (4, syncsafe) + flags (2) + encoding (1) + desc\0 + text
fn build_txxx_frame(payload: &[u8]) -> Vec<u8> {
    let b64_text = origin_core::base64_encode(payload);
    let text = b64_text.as_bytes();

    // Frame data: encoding byte + "origin\0" + text
    let frame_data_len = 1 + DESCRIPTION.len() + 1 + text.len();
    let mut frame = Vec::with_capacity(10 + frame_data_len);

    frame.extend_from_slice(TXXX_ID);
    frame.extend_from_slice(&encode_syncsafe(frame_data_len as u32));
    // Frame flags: 0x0000 (no flags)
    frame.extend_from_slice(&[0x00, 0x00]);
    // Encoding: 0x03 = UTF-8
    frame.push(0x03);
    // Description + null
    frame.extend_from_slice(DESCRIPTION);
    frame.push(0x00);
    // Text
    frame.extend_from_slice(text);

    frame
}

/// Embed payload into an MP3 file via ID3v2 TXXX frame.
pub fn embed(payload: &[u8], artifact: &[u8], overwrite: bool) -> Result<Vec<u8>, EmbedError> {
    if artifact.len() < 10 || &artifact[0..3] != ID3_HEADER {
        return Err(EmbedError::MalformedInput("not a valid MP3 (no ID3v2 header)"));
    }

    let header_size: u32 = {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&artifact[6..10]);
        decode_syncsafe(&arr)
    };
    let tag_size = 10 + header_size as usize;
    if tag_size > artifact.len() {
        return Err(EmbedError::MalformedInput("truncated ID3v2 tag"));
    }

    let new_frame = build_txxx_frame(payload);

    // Check for existing TXXX:origin frame
    if let Some((frame_start, frame_len)) = find_txxx_origin(&artifact[..tag_size]) {
        if !overwrite {
            return Err(EmbedError::ExistingOrigin);
        }
        // Replace the frame in-place (it may have different size)
        let old_frame_end = frame_start + frame_len;
        let remaining = &artifact[old_frame_end..];
        let mut out = Vec::with_capacity(artifact.len());
        out.extend_from_slice(&artifact[..frame_start]);
        out.extend_from_slice(&new_frame);
        out.extend_from_slice(remaining);
        // Update tag size
        let new_tag_size = 10 + header_size as usize - frame_len + new_frame.len();
        let new_size_syncsafe = encode_syncsafe(new_tag_size as u32 - 10);
        out[6..10].copy_from_slice(&new_size_syncsafe);
        return Ok(out);
    }

    // Add new frame before padding
    // ID3v2 padding is all zeros between the last frame and the end of the tag
    let insert_point = find_frame_insert_point(&artifact[..tag_size]);

    let mut out = Vec::with_capacity(artifact.len() + new_frame.len());
    out.extend_from_slice(&artifact[..insert_point]);
    out.extend_from_slice(&new_frame);
    out.extend_from_slice(&artifact[insert_point..]);

    // Update tag size
    let new_header_size = header_size as usize + new_frame.len();
    let new_size_syncsafe = encode_syncsafe(new_header_size as u32);
    out[6..10].copy_from_slice(&new_size_syncsafe);

    Ok(out)
}

/// Extract origin payload from an MP3 file.
pub fn extract(artifact: &[u8]) -> Option<Vec<u8>> {
    if artifact.len() < 10 || &artifact[0..3] != ID3_HEADER {
        return None;
    }

    let header_size: u32 = {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&artifact[6..10]);
        decode_syncsafe(&arr)
    };
    let tag_size = 10 + header_size as usize;
    if tag_size > artifact.len() {
        return None;
    }

    let (_, _frame_len) = find_txxx_origin(&artifact[..tag_size])?;
    // Extract the text after the description
    // Re-scan to get the frame data
    let mut i = 10; // skip ID3v2 header
    while i + 10 <= tag_size {
        let frame_id = &artifact[i..i + 4];
        let mut size_buf = [0u8; 4];
        size_buf.copy_from_slice(&artifact[i + 4..i + 8]);
        let frame_size = decode_syncsafe(&size_buf) as usize;
        let total_frame = 10 + frame_size;
        if i + total_frame > tag_size {
            break;
        }
        if frame_id == TXXX_ID {
            // TXXX frame: encoding (1) + description\0 + text
            let encoding = artifact[i + 10];
            if encoding != 0x03 {
                // Skip non-UTF-8 for simplicity
                i += total_frame;
                continue;
            }
            let data_start = i + 11;
            // Find description null terminator
            let null_pos = artifact[data_start..i + total_frame]
                .iter()
                .position(|&b| b == 0x00)?;
            let desc_end = data_start + null_pos;
            if &artifact[data_start..desc_end] == DESCRIPTION {
                let text_start = desc_end + 1;
                let text_end = i + total_frame;
                if text_start < text_end {
                    let b64_str = core::str::from_utf8(&artifact[text_start..text_end]).ok()?;
                    return origin_core::base64_decode(b64_str).ok();
                }
            }
        }
        i += total_frame;
    }
    None
}

/// Find an existing TXXX:origin frame in the tag. Returns (frame_start, frame_len).
fn find_txxx_origin(tag: &[u8]) -> Option<(usize, usize)> {
    let tag_end = tag.len();
    let mut i = 10; // skip ID3v2 header
    while i + 10 <= tag_end {
        let frame_id = &tag[i..i + 4];
        let mut size_buf = [0u8; 4];
        size_buf.copy_from_slice(&tag[i + 4..i + 8]);
        let frame_size = decode_syncsafe(&size_buf) as usize;
        let total_frame = 10 + frame_size;
        if i + total_frame > tag_end || frame_id.iter().all(|&b| b == 0) {
            // Reached padding
            break;
        }
        if frame_id == TXXX_ID {
            let data_start = i + 11;
            let data_end = i + total_frame;
            if data_start < data_end
                && let Some(null_pos) = tag[data_start..data_end]
                    .iter()
                    .position(|&b| b == 0x00)
                    && &tag[data_start..data_start + null_pos] == DESCRIPTION
            {
                return Some((i, total_frame));
            }
        }
        i += total_frame;
    }
    None
}

/// Find the point before padding to insert a new frame.
fn find_frame_insert_point(tag: &[u8]) -> usize {
    let tag_end = tag.len();
    let mut i = 10;
    while i + 10 <= tag_end {
        let frame_id = &tag[i..i + 4];
        let mut size_buf = [0u8; 4];
        size_buf.copy_from_slice(&tag[i + 4..i + 8]);
        let frame_size = decode_syncsafe(&size_buf) as usize;
        let total_frame = 10 + frame_size;
        if i + total_frame > tag_end || frame_id.iter().all(|&b| b == 0) {
            // Padding or invalid
            break;
        }
        i += total_frame;
    }
    i
}
