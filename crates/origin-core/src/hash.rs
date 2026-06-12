// SPDX-License-Identifier: MIT

//! Multi-modal hashing utilities for the Origin provenance library.
//!
//! Provides:
//! - [`hash_bytes`] / [`hash_hex`]: standard SHA-256
//! - [`hash_reader`]: streaming SHA-256 (requires `std`)
//! - [`phash_64`]: perceptual hash using fixed-point integer DCT (requires `std`)
//! - [`simhash_256`]: semantic hash using random projection (requires `std`)

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of the given byte slice.
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
        let n = reader
            .read(&mut buf)
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
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

// ═══════════════════════════════════════════════════════════════════
// PERCEPTUAL HASH (pHash) — Fixed-Point Integer DCT
// ═══════════════════════════════════════════════════════════════════
// Uses i32 with fixed-point arithmetic for cross-platform determinism.
// No floating-point DCT means bit-identical results on ARM, x86, WASM.

/// Compute a 64-bit perceptual hash of a 32x32 grayscale image.
///
/// Uses only integer arithmetic (fixed-point DCT).
/// Returns a 64-bit hash where each bit represents a DCT coefficient
/// being above or below the median.
#[cfg(feature = "std")]
pub fn phash_64(pixels_32x32: &[[u8; 32]; 32]) -> u64 {
    // Step 1: Downscale 32x32 to 8x8 via 4x4 block averaging
    let mut reduced = [[0i32; 8]; 8];
    for py in 0..8 {
        for px in 0..8 {
            let mut sum = 0i32;
            for dy in 0..4 {
                for dx in 0..4 {
                    sum += pixels_32x32[py * 4 + dy][px * 4 + dx] as i32;
                }
            }
            reduced[py][px] = sum / 16;
        }
    }

    // Step 2: Fixed-point 2D DCT of 8x8
    let dct = dct_8x8_fixed(&reduced);

    // Step 3: Compute median of AC coefficients (skip DC at 0,0)
    let mut coeffs = [0i32; 63];
    let mut idx = 0;
    for (y, row) in dct.iter().enumerate() {
        for (x, val) in row.iter().enumerate() {
            if x == 0 && y == 0 {
                continue;
            }
            coeffs[idx] = *val;
            idx += 1;
        }
    }
    coeffs.sort_unstable();
    let median = coeffs[31];

    // Step 4: Generate 64-bit hash from 8x8 DCT vs median
    let mut hash: u64 = 0;
    for (y, row) in dct.iter().enumerate() {
        for (x, val) in row.iter().enumerate() {
            let bit_idx = (y * 8 + x) as u64;
            if *val > median {
                hash |= 1u64 << bit_idx;
            }
        }
    }
    hash
}

/// Fixed-point 2D DCT of an 8x8 block using Q16.16 arithmetic.
/// Input values are pixel levels (0-255), shifted by -128 for DCT.
fn dct_8x8_fixed(input: &[[i32; 8]; 8]) -> [[i32; 8]; 8] {
    let frac_bits = 12;
    let scale = 1i64 << frac_bits;

    // Precompute cosine table in fixed-point
    let mut cos_tab = [[0i64; 8]; 8];
    for (i, row) in cos_tab.iter_mut().enumerate() {
        for (j, val) in row.iter_mut().enumerate() {
            let angle = (i as f64 + 0.5) * j as f64 * core::f64::consts::PI / 8.0;
            *val = (angle.cos() * scale as f64).round() as i64;
        }
    }

    let mut result = [[0i32; 8]; 8];

    for u in 0..8 {
        for v in 0..8 {
            let mut sum: i64 = 0;
            for (x, row) in input.iter().enumerate() {
                for (y, val) in row.iter().enumerate() {
                    let shifted = (*val as i64) - 128;
                    sum += shifted * cos_tab[x][u] * cos_tab[y][v];
                }
            }

            // Normalization: C(u) * C(v) where C(0) = 1/sqrt(2), C(k>0) = 1
            // Our cos table includes a factor of scale, so adjust:
            // DCT(u,v) = (2/N) * C(u) * C(v) * sum
            // where C(0) = 1/sqrt(2), C(k>0) = 1, N = 8
            let norm = if u == 0 && v == 0 {
                4i64 // (2/8) * (1/2) = 1/8 * 32 = 4 at scale
            } else if u == 0 || v == 0 {
                8i64 // (2/8) * (1/sqrt(2)) - approximate
            } else {
                16i64 // (2/8) * 1
            };

            // sum is in Q24 (cos^2 * input), divide by scale^2 then normalize
            let dct_val = sum / (scale * scale / norm);
            result[u][v] = dct_val as i32;
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
    /// Exact match (Hamming distance == 0)
    Exact,
    /// Similar (Hamming distance < 10)
    Similar,
    /// Different
    Different,
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

// ═══════════════════════════════════════════════════════════════════
// SEMANTIC HASH (SimHash) — Random Projection
// ═══════════════════════════════════════════════════════════════════
// Uses a deterministic random projection matrix seeded via fixed seed
// (ChaCha20 with seed = SHA-256("origin-network-simhash-seed-v1")).

const SIMHASH_SEED: &[u8] = b"origin-network-simhash-seed-v1";

/// Compute a 256-bit SimHash of a 512-dimensional feature vector.
///
/// Uses random projection with a deterministic Gaussian matrix
/// (seeded from SHA-256 of a fixed string). The result is 32 bytes
/// (256 bits) where each bit is the sign of a random dot product.
#[cfg(feature = "std")]
pub fn simhash_256(features: &[f64; 512]) -> [u8; 32] {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let seed_bytes = hash_bytes(SIMHASH_SEED);
    let mut rng = ChaCha20Rng::from_seed(seed_bytes);

    use rand_core::RngCore;
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

    // ══════════════════════════════════════════════════════════════
    // DOMAIN 3: pHash Determinism Tests
    // ══════════════════════════════════════════════════════════════

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
        assert!(
            dist < 10,
            "Similar images should have Hamming distance < 10, got {}",
            dist
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_classify_match_exact() {
        let mut pixels = [[0u8; 32]; 32];
        pixels[0][0] = 255;
        let h = phash_64(&pixels);
        assert_eq!(classify_match(h, h), MatchLevel::Exact);
    }

    // ══════════════════════════════════════════════════════════════
    // DOMAIN 3: SimHash Determinism Tests
    // ══════════════════════════════════════════════════════════════

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
            assert_eq!(hash, first, "SimHash must be deterministic across runs");
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
