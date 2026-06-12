//! PDF embedding via incremental update metadata stream.
//!
//! PDF structure:
//!   Header: "%PDF-1.x"
//!   Body: objects (indirect, numbered)
//!   Cross-reference table (xref)
//!   Trailer
//!   %%EOF
//!
//! We embed the base64-encoded PoO in the /Info dictionary as a custom
//! /Origin key using a PDF incremental update (append new objects + xref
//! + trailer, leaving the original file untouched).

use crate::EmbedError;

/// Known PDF header prefixes
const PDF_HEADER: &[u8] = b"%PDF-";

/// Build a new /Info dictionary with the /Origin key.
/// We create new object numbers that won't conflict by scanning for the highest
/// existing object number.
fn build_metadata_update(payload: &[u8], bytes: &[u8]) -> Result<Vec<u8>, EmbedError> {
    let b64_payload = origin_core::base64_encode(payload);

    // Find highest object number in existing file
    let max_obj = find_max_object(bytes);

    // Build the complete update as a byte stream and track positions.
    let mut update_bytes = Vec::new();

    // Object 1: /Info dictionary
    let info_obj_num = max_obj + 1;
    let info_obj_offset = 0; // will be at start of update
    let info_str = format!(
        "{} 0 obj\n<< /Origin ({}) >>\nendobj\n",
        info_obj_num, b64_payload
    );
    update_bytes.extend_from_slice(info_str.as_bytes());

    // xref
    let xref_offset = update_bytes.len() as u64;
    let num_entries = info_obj_num + 1; // one free + our objects
    let mut xref_str = format!("xref\n0 {}\n0000000000 65535 f \n", num_entries);

    // Add entry for our new object
    xref_str.push_str(&format!("{:010} 00000 n \n", info_obj_offset));

    // Trailer
    let trailer = format!(
        "trailer\n<< /Size {} /Root {} 0 R >>\nstartxref\n{}\n%%%%EOF\n",
        num_entries,
        info_obj_num,
        xref_offset
    );

    update_bytes.extend_from_slice(xref_str.as_bytes());
    update_bytes.extend_from_slice(trailer.as_bytes());

    Ok(update_bytes)
}

/// Find the highest object number in the PDF file.
fn find_max_object(bytes: &[u8]) -> u64 {
    let mut max_obj: u64 = 0;
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if bytes[i..].starts_with(b" 0 obj") {
            let mut j = i.saturating_sub(1);
            while j > 0 && bytes[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j < i
                && let Some(s) = core::str::from_utf8(&bytes[j..i]).ok()
                && let Ok(n) = s.trim().parse::<u64>()
                && n > max_obj
            {
                max_obj = n;
            }
        }
        i += 1;
    }
    max_obj
}

/// Embed payload into a PDF file via incremental update.
pub fn embed(payload: &[u8], artifact: &[u8], overwrite: bool) -> Result<Vec<u8>, EmbedError> {
    if artifact.len() < 8 || &artifact[0..5] != PDF_HEADER {
        return Err(EmbedError::MalformedInput("not a valid PDF (bad header)"));
    }

    // Check for existing /Origin in /Info by scanning trailing content
    if overwrite {
        // Remove existing /Origin entry if we're overwriting
        // For simplicity, just skip this optimization
    } else if has_origin_metadata(artifact) {
        return Err(EmbedError::ExistingOrigin);
    }

    let update = build_metadata_update(payload, artifact)?;

    // Append the incremental update to the existing file
    let mut out = Vec::with_capacity(artifact.len() + update.len());
    out.extend_from_slice(artifact);
    out.extend_from_slice(&update);
    Ok(out)
}

/// Check if the PDF already has /Origin metadata.
fn has_origin_metadata(bytes: &[u8]) -> bool {
    // Search for "/Origin (" in the last part of the file
    let search_start = bytes.len().saturating_sub(4096);
    let tail = &bytes[search_start..];
    // Look for the /Origin key in the file
    tail.windows(9).any(|w| w == b"/Origin (")
}

/// Extract origin payload from a PDF file.
pub fn extract(artifact: &[u8]) -> Option<Vec<u8>> {
    if artifact.len() < 8 || &artifact[0..5] != PDF_HEADER {
        return None;
    }

    // Search for /Origin (<base64>) pattern — return the LAST occurrence
    // to support incremental updates (the latest update wins).
    let origin_prefix = b"/Origin (";
    let mut last_result: Option<Vec<u8>> = None;
    let mut i = 0;
    while i + 10 <= artifact.len() {
        if &artifact[i..i + 9] == origin_prefix {
            let start = i + 9;
            let end = artifact[start..].iter().position(|&b| b == b')');
            let b64_str = end.and_then(|e| {
                core::str::from_utf8(&artifact[start..start + e]).ok()
            });
            if let Some(s) = b64_str
                && s.len() > 300 && s.len() < 400
                && !s.contains('(') && !s.contains('\\')
                && let Ok(decoded) = origin_core::base64_decode(s)
            {
                last_result = Some(decoded);
            }
        }
        i += 1;
    }
    last_result
}
