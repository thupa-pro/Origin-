#![no_main]

use std::sync::OnceLock;
use libfuzzer_sys::fuzz_target;

fn test_data() -> &'static (Vec<u8>, Vec<u8>, [u8; 32]) {
    static DATA: OnceLock<(Vec<u8>, Vec<u8>, [u8; 32])> = OnceLock::new();
    DATA.get_or_init(|| {
        let seed = [42u8; 32];
        let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
        let artifact = b"fuzz test artifact";
        let stmt = origin_core::build_statement(&secret, artifact, 100, None).unwrap();
        let pair = origin_core::generate_keypair_from_seed(&seed);
        (origin_core::encode_statement(&stmt), artifact.to_vec(), pair.public.0)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let (stmt_bytes, art_bytes, trusted_key) = test_data();

    let op = data[0] % 6;

    match op {
        0 | 1 => {
            let mut mutated = stmt_bytes.clone();
            let pos = (data[1] as usize) % mutated.len();
            mutated[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify(&mutated, art_bytes, &trusted_key);
        }
        2 | 3 => {
            let mut mutated = stmt_bytes.clone();
            let pos = (data[1] as usize) % mutated.len();
            mutated[pos] ^= data[2] ^ data[3];
            let wrong_key = origin_core::generate_keypair_from_seed(&[99u8; 32]).public.0;
            let _ = origin_core::verify(&mutated, art_bytes, &wrong_key);
        }
        4 => {
            let mut mutated = art_bytes.clone();
            let pos = (data[1] as usize) % mutated.len();
            mutated[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify(stmt_bytes, &mutated, &trusted_key);
        }
        5 => {
            let mut s = stmt_bytes.clone();
            let mut a = art_bytes.clone();
            let s_len = s.len();
            let a_len = a.len();
            s[(data[1] as usize) % s_len] ^= data[2];
            a[(data[3] as usize) % a_len] ^= data[2];
            let _ = origin_core::verify(&s, &a, &trusted_key);
        }
        _ => {}
    }
});
