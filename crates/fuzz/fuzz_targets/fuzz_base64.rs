#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        // Must never panic — only return Ok or Err from base64.
        let _ = origin_core::base64_decode(s);
    }
});
