#![allow(unsafe_code)]

extern crate alloc;

use crate::crypto::SecretKey;
use crate::statement::{build_statement, encode_statement, verify_statement};
use crate::Statement;

/// Allocate a buffer of `size` bytes in WASM linear memory.
/// Returns a pointer that the caller must free with `origin_free_buffer`.
#[unsafe(no_mangle)]
pub extern "C" fn origin_alloc(size: usize) -> *mut u8 {
    let layout = alloc::alloc::Layout::array::<u8>(size).unwrap();
    unsafe { alloc::alloc::alloc_zeroed(layout) }
}

/// Parse and verify a .origin statement.
/// Returns 0 on success, non-zero on failure.
#[unsafe(no_mangle)]
pub extern "C" fn origin_verify(
    statement_ptr: *const u8,
    statement_len: usize,
    artifact_ptr: *const u8,
    artifact_len: usize,
) -> i32 {
    let statement_bytes = unsafe { core::slice::from_raw_parts(statement_ptr, statement_len) };
    let artifact_bytes = unsafe { core::slice::from_raw_parts(artifact_ptr, artifact_len) };

    let stmt = match Statement::parse(statement_bytes) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    match verify_statement(&stmt, artifact_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Sign an artifact and return the encoded .origin statement as bytes.
/// The returned buffer must be freed with `origin_free_buffer`.
/// On failure, returns null and sets `out_len` to 0.
#[unsafe(no_mangle)]
pub extern "C" fn origin_sign(
    secret_ptr: *const u8,
    secret_len: usize,
    artifact_ptr: *const u8,
    artifact_len: usize,
    timestamp: u64,
    out_len: *mut usize,
) -> *mut u8 {
    let secret_bytes = unsafe { core::slice::from_raw_parts(secret_ptr, secret_len) };
    let artifact_bytes = unsafe { core::slice::from_raw_parts(artifact_ptr, artifact_len) };

    let secret = match SecretKey::from_bytes(secret_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe { *out_len = 0 };
            return core::ptr::null_mut();
        }
    };
    let stmt = match build_statement(&secret, artifact_bytes, timestamp) {
        Ok(s) => s,
        Err(_) => {
            unsafe { *out_len = 0 };
            return core::ptr::null_mut();
        }
    };

    let encoded = encode_statement(&stmt);
    let len = encoded.len();
    let layout = alloc::alloc::Layout::array::<u8>(len).unwrap();
    let buf = unsafe { alloc::alloc::alloc(layout) };
    if buf.is_null() {
        unsafe { *out_len = 0 };
        return core::ptr::null_mut();
    }
    unsafe { core::ptr::copy_nonoverlapping(encoded.as_ptr(), buf, len) };
    unsafe { *out_len = len };
    buf
}

/// Free a buffer previously returned by `origin_sign` or `origin_alloc`.
#[unsafe(no_mangle)]
pub extern "C" fn origin_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let layout = alloc::alloc::Layout::array::<u8>(len).unwrap();
    unsafe { alloc::alloc::dealloc(ptr, layout) }
}
