//! JPEG embedding via APP15 marker (0xFF 0xEF).
//!
//! JPEG structure:
//!   SOI (0xFF 0xD8)
//!   APP0..APP15 markers (0xFF 0xE0..0xFF 0xEF)
//!   DHT, DQT, SOF, SOS markers
//!   Compressed scan data
//!   EOI (0xFF 0xD9)
//!
//! We embed the 256-byte PoO in an APP15 marker with the magic prefix
//! b"origin\0" so it can be identified on extraction.

use crate::EmbedError;

/// Magic bytes identifying our APP15 payload: "origin\0"
const MAGIC: &[u8] = b"origin\0";
/// Total APP15 payload size: magic (7) + payload (256)
const APP15_DATA_LEN: usize = 7 + 256;
/// Marker header: 0xFF 0xEF + 2-byte big-endian length
const APP15_MARKER_LEN: usize = 2 + 2 + APP15_DATA_LEN;

/// Build an APP15 marker payload.
fn build_app15_marker(payload: &[u8]) -> [u8; APP15_MARKER_LEN] {
    let mut marker = [0u8; APP15_MARKER_LEN];
    marker[0] = 0xFF;
    marker[1] = 0xEF;
    let len = APP15_DATA_LEN as u16 + 2; // length includes itself
    marker[2] = (len >> 8) as u8;
    marker[3] = (len & 0xFF) as u8;
    marker[4..4 + 7].copy_from_slice(MAGIC);
    marker[4 + 7..].copy_from_slice(payload);
    marker
}

/// Embed payload into a JPEG file via APP15 marker.
pub fn embed(payload: &[u8], artifact: &[u8], overwrite: bool) -> Result<Vec<u8>, EmbedError> {
    if artifact.len() < 2 || artifact[0] != 0xFF || artifact[1] != 0xD8 {
        return Err(EmbedError::MalformedInput(
            "not a valid JPEG (no SOI marker)",
        ));
    }

    let marker = build_app15_marker(payload);

    // Scan for existing APP15 markers with our magic
    if let Some(pos) = find_app15_origin(artifact) {
        if !overwrite {
            return Err(EmbedError::ExistingOrigin);
        }
        // Replace existing APP15 marker
        let mut out = artifact.to_vec();
        out.splice(pos..pos + APP15_MARKER_LEN, marker);
        return Ok(out);
    }

    // Insert APP15 marker after SOI (or after the last segment marker before SOS)
    let insert_pos = find_insertion_point(artifact);
    let mut out = Vec::with_capacity(artifact.len() + APP15_MARKER_LEN);
    out.extend_from_slice(&artifact[..insert_pos]);
    out.extend_from_slice(&marker);
    out.extend_from_slice(&artifact[insert_pos..]);
    Ok(out)
}

/// Extract origin payload from a JPEG file.
pub fn extract(artifact: &[u8]) -> Option<Vec<u8>> {
    let (_, data) = find_app15_origin_data(artifact)?;
    Some(data.to_vec())
}

/// Find an existing APP15 marker with origin magic, return start position.
fn find_app15_origin(bytes: &[u8]) -> Option<usize> {
    find_app15_origin_data(bytes).map(|(pos, _)| pos)
}

/// Find an existing APP15 marker with origin magic, return (start, payload_data).
fn find_app15_origin_data(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        // Check for standalone markers (RST0-7, SOI, EOI, TEM)
        if matches!(marker, 0xD0..=0xD7 | 0xD8 | 0xD9 | 0x01) {
            i += 2;
            continue;
        }
        // Segment marker: 0xFF 0xMk followed by 2-byte big-endian length
        if i + 4 > bytes.len() {
            break;
        }
        let seg_len = ((bytes[i + 2] as usize) << 8) | (bytes[i + 3] as usize);
        if seg_len < 2 || i + 2 + seg_len > bytes.len() {
            break;
        }
        if marker == 0xEF {
            // APP15 marker
            let data_start = i + 4;
            let data_end = data_start + seg_len - 2;
            if data_end <= bytes.len()
                && data_end - data_start >= 7 + 256
                && &bytes[data_start..data_start + 7] == MAGIC
            {
                let payload_start = data_start + 7;
                return Some((i, &bytes[payload_start..payload_start + 256]));
            }
        }
        i += 2 + seg_len;
    }
    None
}

/// Find where to insert a new APP marker — right after SOI.
fn find_insertion_point(_bytes: &[u8]) -> usize {
    // SOI is at bytes[0..2]; insert immediately after it
    2
}
