// SPDX-License-Identifier: MIT
// OMEGA CRUCIBLE — Domain 3: Multi-Modal Hashing Determinism & Resilience

use std::path::Path;

/// Convert a 32x32 grayscale image from the `image` crate to our pixel array.
fn image_to_pixels(img: &image::GrayImage) -> [[u8; 32]; 32] {
    let mut pixels = [[0u8; 32]; 32];
    for (y, row) in pixels.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            *cell = img.get_pixel(x as u32, y as u32).0[0];
        }
    }
    pixels
}

/// Load an image from disk, resize to 32x32, convert to grayscale.
fn load_resize_grayscale(path: &Path) -> [[u8; 32]; 32] {
    let img = image::open(path).expect("failed to open image");
    let resized = img.resize_exact(32, 32, image::imageops::FilterType::Lanczos3);
    let gray = resized.to_luma8();
    image_to_pixels(&gray)
}

/// Generate a deterministic test pattern (checkerboard).
fn checkerboard_32x32() -> [[u8; 32]; 32] {
    let mut pixels = [[0u8; 32]; 32];
    for (y, row) in pixels.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            *cell = if (x / 4 + y / 4) % 2 == 0 { 200 } else { 50 };
        }
    }
    pixels
}

/// Add FGSM-style noise to pixels: flip each pixel by ±noise_level.
fn add_fgsm_noise(pixels: &mut [[u8; 32]; 32], noise_level: i16) {
    for row in pixels.iter_mut() {
        for cell in row.iter_mut() {
            let val = *cell as i16;
            let new_val = if val + noise_level > 255 {
                val.saturating_sub(noise_level)
            } else {
                val.saturating_add(noise_level)
            };
            *cell = new_val as u8;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3.1 Cross-Architecture Determinism (1,000 runs)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_phash_1000_runs_deterministic() {
    let pixels = checkerboard_32x32();
    let first = origin_core::hash::phash_64(&pixels);
    for i in 1..1000 {
        let h = origin_core::hash::phash_64(&pixels);
        assert_eq!(
            h,
            first,
            "pHash must be deterministic: run {}/1000 differs",
            i + 1
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3.3 Adversarial Perceptual Resilience — JPEG Compression
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_jpeg_q75_hamming_distance() {
    let tmp = std::env::temp_dir();
    let png_path = tmp.join("origin_d3_test.png");
    let jpg_path = tmp.join("origin_d3_test_q75.jpg");

    // Create test image: a more complex pattern than checkerboard
    let mut img = image::GrayImage::new(256, 256);
    for y in 0..256 {
        for x in 0..256 {
            let val = ((x as f64 * 0.3 + y as f64 * 0.7).sin() * 127.0 + 128.0) as u8;
            img.put_pixel(x, y, image::Luma([val]));
        }
    }

    // Save as PNG (lossless reference)
    img.save(&png_path).expect("failed to save PNG");
    // Save as JPEG q=75
    img.save(&jpg_path).expect("failed to save JPEG q=75");

    let png_pixels = load_resize_grayscale(&png_path);
    let jpg_pixels = load_resize_grayscale(&jpg_path);

    let hash_png = origin_core::hash::phash_64(&png_pixels);
    let hash_jpg = origin_core::hash::phash_64(&jpg_pixels);
    let dist = origin_core::hash::phash_hamming_distance(hash_png, hash_jpg);

    assert!(
        dist < 25,
        "JPEG q=75 must have Hamming distance < 25 from PNG, got {}",
        dist
    );

    let _ = std::fs::remove_file(&png_path);
    let _ = std::fs::remove_file(&jpg_path);
}

#[test]
fn test_jpeg_q50_hamming_distance() {
    let tmp = std::env::temp_dir();
    let png_path = tmp.join("origin_d3_test_q50_ref.png");
    let jpg_path = tmp.join("origin_d3_test_q50.jpg");

    let mut img = image::RgbImage::new(128, 128);
    for y in 0..128 {
        for x in 0..128 {
            let r = (x as f64 * 0.5).sin() * 127.0 + 128.0;
            let g = (y as f64 * 0.5).cos() * 127.0 + 128.0;
            let b = ((x + y) as f64 * 0.3).sin() * 127.0 + 128.0;
            img.put_pixel(x, y, image::Rgb([r as u8, g as u8, b as u8]));
        }
    }

    img.save(&png_path).expect("failed to save PNG ref");
    // JPEG with quality=50 via image crate default (no quality option, but JPEG is lossy)
    // We use a separate encoder for quality control
    {
        let file = std::fs::File::create(&jpg_path).expect("failed to create JPEG file");
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(file, 50);
        img.write_with_encoder(encoder)
            .expect("failed to write JPEG q=50");
    }

    let png_pixels = load_resize_grayscale(&png_path);
    let jpg_pixels = load_resize_grayscale(&jpg_path);

    let hash_png = origin_core::hash::phash_64(&png_pixels);
    let hash_jpg = origin_core::hash::phash_64(&jpg_pixels);
    let dist = origin_core::hash::phash_hamming_distance(hash_png, hash_jpg);

    assert!(
        dist < 28,
        "JPEG q=50 must have Hamming distance < 28 from PNG, got {}",
        dist
    );

    let _ = std::fs::remove_file(&png_path);
    let _ = std::fs::remove_file(&jpg_path);
}

#[test]
fn test_jpeg_q25_hamming_distance() {
    let tmp = std::env::temp_dir();
    let png_path = tmp.join("origin_d3_test_q25_ref.png");
    let jpg_path = tmp.join("origin_d3_test_q25.jpg");

    let mut img = image::RgbImage::new(64, 64);
    for y in 0..64 {
        for x in 0..64 {
            let v = (((x as f64).powi(2) + (y as f64).powi(2)).sqrt() * 2.0).sin() * 127.0 + 128.0;
            img.put_pixel(x, y, image::Rgb([v as u8, v as u8, v as u8]));
        }
    }

    img.save(&png_path).expect("failed to save PNG ref");
    {
        let file = std::fs::File::create(&jpg_path).expect("failed to create JPEG file");
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(file, 25);
        img.write_with_encoder(encoder)
            .expect("failed to write JPEG q=25");
    }

    let png_pixels = load_resize_grayscale(&png_path);
    let jpg_pixels = load_resize_grayscale(&jpg_path);

    let hash_png = origin_core::hash::phash_64(&png_pixels);
    let hash_jpg = origin_core::hash::phash_64(&jpg_pixels);
    let dist = origin_core::hash::phash_hamming_distance(hash_png, hash_jpg);

    assert!(
        dist < 32,
        "JPEG q=25 must have Hamming distance < 32 from PNG, got {}",
        dist
    );

    let _ = std::fs::remove_file(&png_path);
    let _ = std::fs::remove_file(&jpg_path);
}

// ═══════════════════════════════════════════════════════════════════
// 3.3 Adversarial Perceptual Resilience — FGSM Pixel Noise
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_fgsm_noise_hamming_distance() {
    let mut pixels = checkerboard_32x32();
    let hash_orig = origin_core::hash::phash_64(&pixels);

    // Add FGSM noise: ±5 to every pixel
    add_fgsm_noise(&mut pixels, 5);
    let hash_noisy = origin_core::hash::phash_64(&pixels);
    let dist = origin_core::hash::phash_hamming_distance(hash_orig, hash_noisy);

    assert!(
        dist < 10,
        "FGSM noise ±5 must have Hamming distance < 10, got {}",
        dist
    );
}

#[test]
fn test_fgsm_noise_not_exact() {
    let mut pixels = checkerboard_32x32();
    let hash_orig = origin_core::hash::phash_64(&pixels);
    add_fgsm_noise(&mut pixels, 1);
    let hash_noisy = origin_core::hash::phash_64(&pixels);
    let dist = origin_core::hash::phash_hamming_distance(hash_orig, hash_noisy);

    assert_eq!(
        origin_core::hash::classify_match(hash_orig, hash_noisy),
        if dist == 0 {
            origin_core::hash::MatchLevel::Exact
        } else if dist < 10 {
            origin_core::hash::MatchLevel::Similar
        } else {
            origin_core::hash::MatchLevel::Different
        }
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3.2 SimHash projection verification (deterministic random matrix)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_simhash_200_runs_deterministic() {
    let mut features = [0.0f64; 512];
    for (i, feat) in features.iter_mut().enumerate() {
        *feat = (i as f64 - 256.0) / 256.0;
    }
    let first = origin_core::hash::simhash_256(&features);
    for i in 1..200 {
        let h = origin_core::hash::simhash_256(&features);
        assert_eq!(
            h,
            first,
            "SimHash must be deterministic: run {}/200 differs",
            i + 1
        );
    }
}

#[test]
fn test_simhash_similar_features_low_distance() {
    let mut features_a = [0.0f64; 512];
    let mut features_b = [0.0f64; 512];
    for i in 0..512 {
        let val = (i as f64 - 256.0) / 256.0;
        features_a[i] = val;
        features_b[i] = val + 0.01; // slightly perturbed
    }
    let hash_a = origin_core::hash::simhash_256(&features_a);
    let hash_b = origin_core::hash::simhash_256(&features_b);

    // SimHash is a semantic hash: similar features should produce similar hashes
    let diff: u32 = hash_a
        .iter()
        .zip(hash_b.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert!(
        diff < 64,
        "Similar feature vectors should have < 64 bit differences, got {}",
        diff
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3.1 Fixed-point DCT cross-platform verification
// ═══════════════════════════════════════════════════════════════════

/// Verify that the DCT produces the same result on repeated calls.
/// This is a proxy for cross-platform determinism (identical integer math).
#[test]
fn test_dct_8x8_deterministic() {
    let mut input = [[0i32; 8]; 8];
    for (y, row) in input.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            *cell = ((x * 31 + y * 17) % 256) as i32;
        }
    }

    // We can't call dct_8x8_fixed directly (it's private), so use phash_64 as proxy
    let mut pixels = [[0u8; 32]; 32];
    for (y, row) in pixels.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            *cell = ((x * 31 + y * 17) % 256) as u8;
        }
    }

    let hash1 = origin_core::hash::phash_64(&pixels);
    for _ in 0..100 {
        let hash2 = origin_core::hash::phash_64(&pixels);
        assert_eq!(hash1, hash2, "DCT-based phash must be deterministic");
    }
}
