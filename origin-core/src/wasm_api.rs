#![allow(unsafe_code)]

use alloc::boxed::Box;
use alloc::vec;

use crate::crypto::SecretKey;
use crate::statement::{build_statement, encode_statement, verify_statement, Statement};

/// Allocate a buffer of `size` bytes in WASM linear memory.
/// Returns a pointer that the caller must free with `origin_free_buffer`.
#[unsafe(no_mangle)]
pub extern "C" fn origin_alloc(size: usize) -> *mut u8 {
    let mut buf = vec![0u8; size];
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
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
    let mut encoded = encode_statement(&stmt);
    encoded.shrink_to_fit();
    let len = encoded.len();
    let buf = encoded.leak().as_mut_ptr();
    unsafe { *out_len = len };
    buf
}

/// Free a buffer previously returned by `origin_sign` or `origin_alloc`.
#[unsafe(no_mangle)]
pub extern "C" fn origin_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(core::slice::from_raw_parts_mut(ptr, len));
    }
}
