// SPDX-License-Identifier: MIT

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of the given byte slice.
///
/// **Canonical format**: The input bytes are hashed as-is with no normalization.
/// Artifact bytes must be in their canonical form before hashing. The protocol
/// does not perform any encoding conversion, line-ending normalization, or
/// byte-order transformation.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the SHA-256 hash and return it as a hex-encoded string.
pub fn hash_hex(data: &[u8]) -> alloc::string::String {
    hex::encode(hash_bytes(data))
}

/// Compute the SHA-256 hash of a reader incrementally (requires the `std` feature).
#[cfg(feature = "std")]
pub fn hash_reader(mut reader: impl std::io::Read) -> crate::error::Result<[u8; 32]> {
    use sha2::digest::Digest as _;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf).map_err(|e| crate::error::Error::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Compute the SHA-256 hash of a file at the given path (requires the `std` feature).
#[cfg(feature = "std")]
pub fn hash_file(path: &std::path::Path) -> crate::error::Result<alloc::string::String> {
    let file = std::fs::File::open(path).map_err(|e| crate::error::Error::Io(e.to_string()))?;
    let reader = std::io::BufReader::with_capacity(65536, file);
    let hash = hash_reader(reader)?;
    Ok(hex::encode(hash))
}

// ═══════════════════════════════════════════════
// PERCEPTUAL HASH (pHash) — Fix-Point DCT
// ═══════════════════════════════════════════════

/// Convert RGB pixel data to grayscale using exact BT.601 coefficients.
/// Input: width * height * 3 bytes (R, G, B interleaved).
/// Output: width * height grayscale bytes.
#[cfg(feature = "std")]
pub fn rgb_to_grayscale(pixels: &[u8], width: usize, height: usize) -> alloc::vec::Vec<u8> {
    let mut gray = alloc::vec![0u8; width * height];
    for y in 0..height {
        for x in 0..width {
            let idx = (y * width + x) * 3;
            let r = pixels[idx] as u32;
            let g = pixels[idx + 1] as u32;
            let b = pixels[idx + 2] as u32;
            let v = (299 * r + 587 * g + 114 * b) / 1000;
            gray[y * width + x] = v.min(255) as u8;
        }
    }
    gray
}

/// Bilinear interpolation to resize a grayscale image.
#[cfg(feature = "std")]
pub fn resize_bilinear(src: &[u8], src_w: usize, src_h: usize, dst_w: usize, dst_h: usize) -> alloc::vec::Vec<u8> {
    let mut dst = alloc::vec![0u8; dst_w * dst_h];
    for dy in 0..dst_h {
        for dx in 0..dst_w {
            let gx = (dx as f64 + 0.5) * src_w as f64 / dst_w as f64 - 0.5;
            let gy = (dy as f64 + 0.5) * src_h as f64 / dst_h as f64 - 0.5;
            let ix = gx.max(0.0).min((src_w - 1) as f64);
            let iy = gy.max(0.0).min((src_h - 1) as f64);
            let x0 = ix.floor() as usize;
            let y0 = iy.floor() as usize;
            let x1 = (x0 + 1).min(src_w - 1);
            let y1 = (y0 + 1).min(src_h - 1);
            let fx = ix - x0 as f64;
            let fy = iy - y0 as f64;
            let v00 = src[y0 * src_w + x0] as f64;
            let v10 = src[y0 * src_w + x1] as f64;
            let v01 = src[y1 * src_w + x0] as f64;
            let v11 = src[y1 * src_w + x1] as f64;
            let v = v00 * (1.0 - fx) * (1.0 - fy)
                + v10 * fx * (1.0 - fy)
                + v01 * (1.0 - fx) * fy
                + v11 * fx * fy;
            dst[dy * dst_w + dx] = v.round().min(255.0).max(0.0) as u8;
        }
    }
    dst
}

/// Compute a 64-bit perceptual hash of a 32x32 grayscale image.
/// Uses 2D DCT Type II with orthogonal normalization.
/// Returns a 64-bit hash where each bit represents a DCT coefficient
/// being above or below the mean (DC coefficient at [0,0] excluded).
#[cfg(feature = "std")]
pub fn phash_64(pixels_32x32: &[[u8; 32]; 32]) -> u64 {
    // Convert to i32 and subtract 128 for DCT centering
    let mut centered = [[0i32; 32]; 32];
    for (y, row) in pixels_32x32.iter().enumerate() {
        for (x, p) in row.iter().enumerate() {
            centered[y][x] = *p as i32 - 128;
        }
    }

    // 2D DCT Type II on 32x32, then extract top-left 8x8
    let dct = dct_2d_32x32(&centered);

    // Extract top-left 8x8 sub-matrix
    let mut coeffs_8x8 = [[0i32; 8]; 8];
    for y in 0..8 {
        for x in 0..8 {
            coeffs_8x8[y][x] = dct[y][x];
        }
    }

    // Compute mean of 64 values (excluding DC at [0,0])
    let mut sum: i64 = 0;
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue;
            }
            sum += coeffs_8x8[y][x] as i64;
        }
    }
    let mean = sum / 63;

    // Generate 64-bit hash: bit = 1 if DCT_value >= mean
    // Packed big-endian: byte 0 = MSB (coefficient[0][1]), byte 7 = LSB
    let mut hash: u64 = 0;
    let mut bit_idx = 0;
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue;
            }
            if coeffs_8x8[y][x] as i64 >= mean {
                hash |= 1u64 << (63 - bit_idx); // big-endian packing
            }
            bit_idx += 1;
        }
    }
    hash
}

/// 2D DCT Type II on a 32x32 block with orthogonal normalization.
#[cfg(feature = "std")]
fn dct_2d_32x32(input: &[[i32; 32]; 32]) -> [[i32; 32]; 32] {
    const N: usize = 32;
    let mut result = [[0i32; N]; N];

    // Precompute cosine table
    let mut cos_tab = [[0.0f64; N]; N];
    for i in 0..N {
        for j in 0..N {
            cos_tab[i][j] = (core::f64::consts::PI * (i as f64 + 0.5) * j as f64 / N as f64).cos();
        }
    }

    for u in 0..N {
        for v in 0..N {
            let mut sum = 0.0f64;
            for x in 0..N {
                for y in 0..N {
                    sum += input[x][y] as f64 * cos_tab[x][u] * cos_tab[y][v];
                }
            }
            // Orthogonal normalization: C(u) * C(v) where C(0) = 1/sqrt(2), C(k>0) = 1
            let cu = if u == 0 { 1.0 / core::f64::consts::SQRT_2 } else { 1.0 };
            let cv = if v == 0 { 1.0 / core::f64::consts::SQRT_2 } else { 1.0 };
            let norm = (2.0 / N as f64) * cu * cv;
            result[u][v] = (sum * norm).round() as i32;
        }
    }
    result
}

/// Compute the Hamming distance between two 64-bit perceptual hashes.
#[cfg(feature = "std")]
pub fn phash_hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Classification of perceptual hash match levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchLevel {
    Exact,
    Similar,
    Different,
}

/// Compute a 16-byte perceptual hash field for non-image artifacts (FORMAT_UNKNOWN).
///
/// For artifacts where image-based pHash is not applicable (e.g., source code,
/// binaries, text), this produces a deterministic 16-byte field suitable for
/// direct storage in `ProofOfOrigin::perceptual_hash`.
///
/// Formula: SHA-256(b"FORMAT_UNKNOWN" || content_hash)[0..16]
pub fn phash_format_unknown(content_hash: &[u8; 32]) -> [u8; 16] {
    let mut input = alloc::vec![0u8; 48];
    input[..16].copy_from_slice(b"FORMAT_UNKNOWN\0\0");
    input[16..48].copy_from_slice(content_hash);
    let h = hash_bytes(&input);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&h[..16]);
    bytes
}

/// Classify two perceptual hashes by their Hamming distance.
#[cfg(feature = "std")]
pub fn classify_match(a: u64, b: u64) -> MatchLevel {
    let d = phash_hamming_distance(a, b);
    if d == 0 {
        MatchLevel::Exact
    } else if d < 10 {
        MatchLevel::Similar
    } else {
        MatchLevel::Different
    }
}

// ═══════════════════════════════════════════════
// SEMANTIC HASH (SimHash) — Random Projection
// ═══════════════════════════════════════════════

const SIMHASH_SEED: &[u8] = b"origin-network-simhash-seed-v1";

/// Compute a 256-bit SimHash of a 512-dimensional feature vector.
#[cfg(feature = "std")]
pub fn simhash_256(features: &[f64; 512]) -> [u8; 32] {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rand_core::RngCore;

    let seed_bytes = hash_bytes(SIMHASH_SEED);
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    let mut hash = [0u8; 32];
    for bit_idx in 0..256 {
        let mut dot: f64 = 0.0;
        for feat_idx in 0..512 / 2 {
            let u1: f64 = (rng.next_u32() as f64) / (u32::MAX as f64);
            let u2: f64 = (rng.next_u32() as f64) / (u32::MAX as f64);
            if u1 < 1e-10 {
                continue;
            }
            let r = (-2.0 * u1.ln()).sqrt();
            let theta = 2.0 * core::f64::consts::PI * u2;
            let g1 = r * theta.cos();
            let g2 = r * theta.sin();
            dot += g1 * features[feat_idx * 2] + g2 * features[feat_idx * 2 + 1];
        }
        if dot > 0.0 {
            hash[bit_idx / 8] |= 1 << (bit_idx % 8);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_known_empty() {
        let hash = hash_bytes(b"");
        assert_eq!(
            hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn test_hash_hex_known() {
        assert_eq!(
            hash_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hash_file_streaming_matches_slice() {
        let data = b"streaming test data for hash verification";
        let dir = std::env::temp_dir();
        let path = dir.join("origin_hash_stream_test");
        std::fs::write(&path, data).unwrap();
        let file_hash = hash_file(&path).unwrap();
        let slice_hash = hash_hex(data);
        assert_eq!(file_hash, slice_hash);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hash_reader_matches_hash_bytes() {
        let data = b"hello hash_reader test";
        let reader = std::io::Cursor::new(data);
        let hash1 = hash_reader(reader).unwrap();
        let hash2 = hash_bytes(data);
        assert_eq!(hash1, hash2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_phash_deterministic_100_runs() {
        let mut pixels = [[0u8; 32]; 32];
        for (y, row) in pixels.iter_mut().enumerate() {
            for (x, cell) in row.iter_mut().enumerate() {
                *cell = if (x / 4 + y / 4) % 2 == 0 { 200 } else { 50 };
            }
        }

        let first = phash_64(&pixels);
        for _ in 0..100 {
            let hash = phash_64(&pixels);
            assert_eq!(hash, first, "pHash must be deterministic across runs");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_phash_hamming_similar_images() {
        let mut base = [[0u8; 32]; 32];
        for (y, row) in base.iter_mut().enumerate() {
            for (x, cell) in row.iter_mut().enumerate() {
                *cell = ((x * y) % 256) as u8;
            }
        }

        let mut modified = base;
        modified[15][15] = if base[15][15] > 128 {
            base[15][15] - 10
        } else {
            base[15][15] + 10
        };

        let hash_base = phash_64(&base);
        let hash_mod = phash_64(&modified);
        let dist = phash_hamming_distance(hash_base, hash_mod);
        assert!(dist < 10, "Similar images should have Hamming distance < 10, got {}", dist);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_rgb_to_grayscale() {
        let rgb = [10, 20, 30, 100, 150, 200];
        let gray = rgb_to_grayscale(&rgb, 1, 2);
        // gray = 0.299R + 0.587G + 0.114B
        let expected0 = ((299 * 10 + 587 * 20 + 114 * 30) / 1000) as u8;
        let expected1 = ((299 * 100 + 587 * 150 + 114 * 200) / 1000) as u8;
        assert_eq!(gray[0], expected0);
        assert_eq!(gray[1], expected1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_resize_bilinear() {
        let mut src = alloc::vec![0u8; 256]; // 16x16 checkerboard
            for i in 0..16 {
                for j in 0..16 {
                    src[i * 16 + j] = if (i / 2 + j / 2) % 2 == 0 { 255 } else { 0 };
                }
            }
        let dst = resize_bilinear(&src, 16, 16, 32, 32);
        assert_eq!(dst.len(), 1024); // 32 * 32
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_match_exact() {
        let mut pixels = [[0u8; 32]; 32];
        pixels[0][0] = 255;
        let h = phash_64(&pixels);
        assert_eq!(classify_match(h, h), MatchLevel::Exact);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_simhash_deterministic_100_runs() {
        let mut features = [0.0f64; 512];
        for (i, feat) in features.iter_mut().enumerate() {
            *feat = (i as f64) / 512.0;
        }
        let first = simhash_256(&features);
        for _ in 0..100 {
            let hash = simhash_256(&features);
            assert_eq!(hash, first, "SimHash must be deterministic");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_simhash_bit_count() {
        let mut features = [0.0f64; 512];
        features[0] = 1.0;
        let hash = simhash_256(&features);
        assert_eq!(hash.len(), 32, "SimHash must produce 32 bytes");
    }
}
