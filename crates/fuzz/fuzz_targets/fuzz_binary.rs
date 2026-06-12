#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 256 {
        return;
    }
    let bytes: &[u8; 256] = data[..256].try_into().unwrap();
    // Must never panic — only return Ok or Err.
    let _ = origin_core::ProofOfOrigin::from_bytes(bytes);
});
