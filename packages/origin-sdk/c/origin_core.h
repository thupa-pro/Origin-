#ifndef ORIGIN_CORE_H
#define ORIGIN_CORE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Allocate a buffer of `size` bytes in WASM linear memory.
 * Returns a pointer that the caller must free with `origin_free_buffer`.
 */
uint8_t *origin_alloc(uintptr_t size);

/**
 * Parse and verify a .origin statement.
 * Returns 0 on success, non-zero on failure.
 */
int32_t origin_verify(const uint8_t *statement_ptr,
                      uintptr_t statement_len,
                      const uint8_t *artifact_ptr,
                      uintptr_t artifact_len);

/**
 * Sign an artifact and return the encoded .origin statement as bytes.
 * The returned buffer must be freed with `origin_free_buffer`.
 * On failure, returns null and sets `out_len` to 0.
 */
uint8_t *origin_sign(const uint8_t *secret_ptr,
                     uintptr_t secret_len,
                     const uint8_t *artifact_ptr,
                     uintptr_t artifact_len,
                     uint64_t timestamp,
                     uintptr_t *out_len);

/**
 * Free a buffer previously returned by `origin_sign` or `origin_alloc`.
 */
void origin_free_buffer(uint8_t *ptr, uintptr_t len);

#endif  /* ORIGIN_CORE_H */
