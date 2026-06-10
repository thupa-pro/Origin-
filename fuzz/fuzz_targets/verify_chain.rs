#![no_main]

use std::sync::OnceLock;
use libfuzzer_sys::fuzz_target;

fn test_data() -> &'static (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]) {
    static DATA: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32])> = OnceLock::new();
    DATA.get_or_init(|| {
        let seed = [42u8; 32];
        let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
        let pair = origin_core::generate_keypair_from_seed(&seed);
        let parent_art = b"parent artifact";
        let child_art = b"child artifact";

        let parent = origin_core::build_statement(&secret, parent_art, 100, None).unwrap();
        let parent_enc = origin_core::encode_statement(&parent);

        let child = origin_core::build_statement(&secret, child_art, 200, Some(&parent.hash)).unwrap();
        let child_enc = origin_core::encode_statement(&child);

        (parent_enc, parent_art.to_vec(), child_enc, child_art.to_vec(), pair.public.0)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let (parent_enc, parent_art, child_enc, child_art, trusted_key) = test_data();

    let op = data[0] % 8;

    match op {
        0 | 1 => {
            let mut s = child_enc.clone();
            let pos = (data[1] as usize) % s.len();
            s[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify_chain(
                &s, &child_art, Some(&parent_enc), Some(&parent_art), &trusted_key,
            );
        }
        2 | 3 => {
            let mut s = parent_enc.clone();
            let pos = (data[1] as usize) % s.len();
            s[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify_chain(
                &child_enc, &child_art, Some(&s), Some(&parent_art), &trusted_key,
            );
        }
        4 => {
            let mut s = child_enc.clone();
            let pos = (data[1] as usize) % s.len();
            s[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify_chain(
                &s, &child_art, None, None, &trusted_key,
            );
        }
        5 | 6 => {
            let mut c = child_enc.clone();
            let mut p = parent_enc.clone();
            let c_len = c.len();
            let p_len = p.len();
            c[(data[1] as usize) % c_len] ^= data[2];
            p[(data[3] as usize) % p_len] ^= data[2];
            let _ = origin_core::verify_chain(
                &c, &child_art, Some(&p), Some(&parent_art), &trusted_key,
            );
        }
        7 => {
            let wrong_key = origin_core::generate_keypair_from_seed(&[99u8; 32]).public.0;
            let mut s = child_enc.clone();
            let pos = (data[1] as usize) % s.len();
            s[pos] ^= data[2] ^ data[3];
            let _ = origin_core::verify_chain(
                &s, &child_art, Some(&parent_enc), Some(&parent_art), &wrong_key,
            );
        }
        _ => {}
    }
});
