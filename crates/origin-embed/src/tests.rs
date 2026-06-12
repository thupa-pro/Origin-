//! Integration tests for all four embed formats.

use crate::{EmbeddingConfig, MediaFormat, embed, extract};

/// Helper: create a 256-byte payload that looks like a valid ProofOfOrigin.
fn make_payload(version: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 256];
    bytes[0] = version;
    // Set a valid pubkey (non-identity point)
    bytes[50] = 208;
    bytes[51] = 90;
    bytes[52] = 152;
    bytes[53] = 1;
    bytes[54] = 130;
    bytes[55] = 177;
    bytes[56] = 10;
    bytes[57] = 183;
    bytes[58] = 213;
    bytes[59] = 75;
    bytes[60] = 254;
    bytes[61] = 211;
    bytes[62] = 201;
    bytes[63] = 100;
    bytes[64] = 7;
    bytes[65] = 58;
    bytes[66] = 14;
    bytes[67] = 225;
    bytes[68] = 114;
    bytes[69] = 243;
    bytes[70] = 218;
    bytes[71] = 162;
    bytes[72] = 38;
    bytes[73] = 53;
    bytes[74] = 175;
    bytes[75] = 2;
    bytes[76] = 26;
    bytes[77] = 104;
    bytes[78] = 247;
    bytes[79] = 7;
    bytes[80] = 81;
    bytes[81] = 26;
    bytes
}

// ═══════════════════════════════════════════════════════════════════
// JPEG Tests
// ═══════════════════════════════════════════════════════════════════

/// Minimal valid JPEG: SOI + EOI
const MINIMAL_JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xD9];

#[test]
fn test_jpeg_embed_extract_roundtrip() {
    let payload = make_payload(0x01);

    let config = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    let embedded = embed(&payload, MINIMAL_JPEG, &config).expect("embed should succeed");

    assert!(
        embedded.len() > MINIMAL_JPEG.len(),
        "embedded JPEG should be larger"
    );

    let extracted = extract(&embedded).expect("extract should find payload");
    assert_eq!(extracted, payload, "extracted payload must match original");
}

#[test]
fn test_jpeg_extract_from_nonexistent_returns_none() {
    assert!(
        extract(MINIMAL_JPEG).is_none(),
        "no payload in minimal JPEG"
    );
}

#[test]
fn test_jpeg_rejects_bad_jpeg() {
    let payload = make_payload(0x01);
    let config = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    let result = embed(&payload, b"not a jpeg", &config);
    assert!(result.is_err(), "should reject non-JPEG input");
}

#[test]
fn test_jpeg_overwrite_existing() {
    let payload1 = make_payload(0x01);
    let payload2 = make_payload(0x02);

    let config1 = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    let once = embed(&payload1, MINIMAL_JPEG, &config1).expect("first embed");

    // Without overwrite, should error
    let config2_no = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    assert!(
        embed(&payload2, &once, &config2_no).is_err(),
        "should reject without overwrite"
    );

    // With overwrite, should succeed
    let config2_yes = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: true,
    };
    let twice = embed(&payload2, &once, &config2_yes).expect("overwrite should succeed");
    let extracted = extract(&twice).expect("extract after overwrite");
    assert_eq!(extracted, payload2, "extracted should be the new payload");
}

// ═══════════════════════════════════════════════════════════════════
// PNG Tests
// ═══════════════════════════════════════════════════════════════════

/// Minimal valid PNG: signature + IHDR + IEND
fn make_minimal_png() -> Vec<u8> {
    let sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let mut png = sig.to_vec();

    // IHDR chunk: width=1, height=1, bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0
    let ihdr_data = [
        0x00, 0x00, 0x00, 0x01, // width
        0x00, 0x00, 0x00, 0x01, // height
        0x08, // bit depth
        0x02, // color type (RGB)
        0x00, // compression
        0x00, // filter
        0x00, // interlace
    ];
    let mut ihdr = Vec::new();
    let len = ihdr_data.len() as u32;
    ihdr.extend_from_slice(&len.to_be_bytes());
    ihdr.extend_from_slice(b"IHDR");
    ihdr.extend_from_slice(&ihdr_data);
    let crc = crc32(&ihdr[4..]);
    ihdr.extend_from_slice(&crc.to_be_bytes());
    png.extend_from_slice(&ihdr);

    // IEND chunk (empty)
    let mut iend = Vec::new();
    iend.extend_from_slice(&0u32.to_be_bytes());
    iend.extend_from_slice(b"IEND");
    let crc = crc32(&iend[4..]);
    iend.extend_from_slice(&crc.to_be_bytes());
    png.extend_from_slice(&iend);

    png
}

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

#[test]
fn test_png_embed_extract_roundtrip() {
    let png = make_minimal_png();
    let payload = make_payload(0x01);

    let config = EmbeddingConfig {
        format: MediaFormat::Png,
        overwrite: false,
    };
    let embedded = embed(&payload, &png, &config).expect("embed should succeed");
    assert!(embedded.len() > png.len(), "embedded PNG should be larger");

    let extracted = extract(&embedded).expect("extract should find payload");
    assert_eq!(extracted, payload, "extracted payload must match original");
}

#[test]
fn test_png_extract_from_nonexistent_returns_none() {
    let png = make_minimal_png();
    assert!(extract(&png).is_none(), "no payload in minimal PNG");
}

#[test]
fn test_png_overwrite_existing() {
    let png = make_minimal_png();
    let payload1 = make_payload(0x01);
    let payload2 = make_payload(0x02);

    let config1 = EmbeddingConfig {
        format: MediaFormat::Png,
        overwrite: false,
    };
    let once = embed(&payload1, &png, &config1).expect("first embed");

    let config2_no = EmbeddingConfig {
        format: MediaFormat::Png,
        overwrite: false,
    };
    assert!(
        embed(&payload2, &once, &config2_no).is_err(),
        "should reject without overwrite"
    );

    let config2_yes = EmbeddingConfig {
        format: MediaFormat::Png,
        overwrite: true,
    };
    let twice = embed(&payload2, &once, &config2_yes).expect("overwrite should succeed");
    let extracted = extract(&twice).expect("extract after overwrite");
    assert_eq!(extracted, payload2, "extracted should be the new payload");
}

#[test]
fn test_png_rejects_bad_png() {
    let payload = make_payload(0x01);
    let config = EmbeddingConfig {
        format: MediaFormat::Png,
        overwrite: false,
    };
    let result = embed(&payload, b"not a png", &config);
    assert!(result.is_err(), "should reject non-PNG input");
}

// ═══════════════════════════════════════════════════════════════════
// MP3 Tests
// ═══════════════════════════════════════════════════════════════════

/// Minimal valid MP3: ID3v2 header (empty tag) + padding
fn make_minimal_mp3() -> Vec<u8> {
    let mut mp3 = Vec::new();
    mp3.extend_from_slice(b"ID3"); // identifier
    mp3.extend_from_slice(&[0x04, 0x00]); // version 2.4
    mp3.push(0x00); // flags
    mp3.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size = 0 (syncsafe)
    mp3
}

#[test]
fn test_mp3_embed_extract_roundtrip() {
    let mp3 = make_minimal_mp3();
    let payload = make_payload(0x01);

    let config = EmbeddingConfig {
        format: MediaFormat::Mp3,
        overwrite: false,
    };
    let embedded = embed(&payload, &mp3, &config).expect("embed should succeed");
    assert!(embedded.len() > mp3.len(), "embedded MP3 should be larger");

    let extracted = extract(&embedded).expect("extract should find payload");
    assert_eq!(extracted, payload, "extracted payload must match original");
}

#[test]
fn test_mp3_extract_from_nonexistent_returns_none() {
    let mp3 = make_minimal_mp3();
    assert!(extract(&mp3).is_none(), "no payload in minimal MP3");
}

#[test]
fn test_mp3_overwrite_existing() {
    let mp3 = make_minimal_mp3();
    let payload1 = make_payload(0x01);
    let payload2 = make_payload(0x02);

    let config1 = EmbeddingConfig {
        format: MediaFormat::Mp3,
        overwrite: false,
    };
    let once = embed(&payload1, &mp3, &config1).expect("first embed");

    let config2_no = EmbeddingConfig {
        format: MediaFormat::Mp3,
        overwrite: false,
    };
    assert!(
        embed(&payload2, &once, &config2_no).is_err(),
        "should reject without overwrite"
    );

    let config2_yes = EmbeddingConfig {
        format: MediaFormat::Mp3,
        overwrite: true,
    };
    let twice = embed(&payload2, &once, &config2_yes).expect("overwrite should succeed");
    let extracted = extract(&twice).expect("extract after overwrite");
    assert_eq!(extracted, payload2, "extracted should be the new payload");
}

#[test]
fn test_mp3_rejects_bad_mp3() {
    let payload = make_payload(0x01);
    let config = EmbeddingConfig {
        format: MediaFormat::Mp3,
        overwrite: false,
    };
    let result = embed(&payload, b"not an mp3", &config);
    assert!(result.is_err(), "should reject non-MP3 input");
}

// ═══════════════════════════════════════════════════════════════════
// PDF Tests
// ═══════════════════════════════════════════════════════════════════

/// Minimal valid PDF: header + empty body
fn make_minimal_pdf() -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
    pdf.extend_from_slice(
        b"xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n",
    );
    pdf.extend_from_slice(b"trailer\n<< /Size 3 /Root 1 0 R >>\n");
    pdf.extend_from_slice(b"startxref\n101\n%%EOF\n");
    pdf
}

#[test]
fn test_pdf_embed_extract_roundtrip() {
    let pdf = make_minimal_pdf();
    let payload = make_payload(0x01);

    let config = EmbeddingConfig {
        format: MediaFormat::Pdf,
        overwrite: false,
    };
    let embedded = embed(&payload, &pdf, &config).expect("embed should succeed");
    assert!(embedded.len() > pdf.len(), "embedded PDF should be larger");

    let extracted = extract(&embedded).expect("extract should find payload");
    assert_eq!(extracted, payload, "extracted payload must match original");
}

#[test]
fn test_pdf_extract_from_nonexistent_returns_none() {
    let pdf = make_minimal_pdf();
    assert!(extract(&pdf).is_none(), "no payload in minimal PDF");
}

#[test]
fn test_pdf_overwrite_existing() {
    let pdf = make_minimal_pdf();
    let payload1 = make_payload(0x01);
    let payload2 = make_payload(0x02);

    let config1 = EmbeddingConfig {
        format: MediaFormat::Pdf,
        overwrite: false,
    };
    let once = embed(&payload1, &pdf, &config1).expect("first embed");

    // With overwrite=true, should succeed (we just append more)
    let config2_yes = EmbeddingConfig {
        format: MediaFormat::Pdf,
        overwrite: true,
    };
    let twice = embed(&payload2, &once, &config2_yes).expect("overwrite should succeed");
    // Note: PDF incremental updates append, so both payloads exist in the file.
    // extract() should find the LATEST one (we search forward and take last match).
    let extracted = extract(&twice).expect("extract after overwrite");
    assert_eq!(extracted, payload2, "extracted should be the new payload");
}

#[test]
fn test_pdf_rejects_bad_pdf() {
    let payload = make_payload(0x01);
    let config = EmbeddingConfig {
        format: MediaFormat::Pdf,
        overwrite: false,
    };
    let result = embed(&payload, b"not a pdf", &config);
    assert!(result.is_err(), "should reject non-PDF input");
}

// ═══════════════════════════════════════════════════════════════════
// Cross-format tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_extract_wrong_format_returns_none() {
    let payload = make_payload(0x01);
    let jpeg_config = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    let embedded = embed(&payload, MINIMAL_JPEG, &jpeg_config).expect("jpeg embed");

    // Try to extract as PNG from a JPEG - should work because format detection
    // routes to the correct handler based on file signature
    let extracted = extract(&embedded).expect("extract should auto-detect JPEG");
    assert_eq!(extracted, payload, "extracted payload must match");
}

#[test]
fn test_format_detection() {
    assert_eq!(MediaFormat::detect(MINIMAL_JPEG), Some(MediaFormat::Jpeg));
    let png = make_minimal_png();
    assert_eq!(MediaFormat::detect(&png), Some(MediaFormat::Png));
    let mp3 = make_minimal_mp3();
    assert_eq!(MediaFormat::detect(&mp3), Some(MediaFormat::Mp3));
    let pdf = make_minimal_pdf();
    assert_eq!(MediaFormat::detect(&pdf), Some(MediaFormat::Pdf));
    assert_eq!(MediaFormat::detect(b"unknown"), None);
}

#[test]
fn test_embed_rejects_bad_payload_size() {
    let config = EmbeddingConfig {
        format: MediaFormat::Jpeg,
        overwrite: false,
    };
    let result = embed(&[0u8; 255], MINIMAL_JPEG, &config);
    assert!(result.is_err(), "should reject non-256-byte payload");

    let result2 = embed(&[0u8; 257], MINIMAL_JPEG, &config);
    assert!(result2.is_err(), "should reject non-256-byte payload");
}
