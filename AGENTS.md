# AGENTS.md — Origin Network AI Agent Constitution

This file governs all AI coding agents (Claude, Cursor, Copilot, Codex, etc.)
operating on this repository. These rules are **not suggestions** — they are
**hard constraints**. Any agent that violates them produces invalid code.

---

## 1. CORE INVARIANTS (NEVER VIOLATE)

1. **`origin-core` is `#![no_std]`** — Never add `std`, `thiserror`, `serde`,
   `tokio`, `reqwest`, or any OS-dependent crate to `origin-core`. The core
   must compile to `wasm32-unknown-unknown` with zero imports.
2. **No `unwrap()` / `expect()` / `panic!()` in production code** — Use
   `?` operator and proper `Result` propagation. Panics are only allowed in
   test blocks and `cfg(test)`.
3. **No `unsafe` code in `origin-core`** — The crate has `#![deny(unsafe_code)]`.
   Never add `#[allow(unsafe_code)]` except in `binary.rs` for `bytemuck`
   impls (which are pre-approved).
4. **Constant-time comparisons** — All cryptographic comparisons must use
   `subtle::ConstantTimeEq`. Never use `==` on secret material.
5. **Fixed-width binary format** — The `ProofOfOrigin` struct is `#[repr(C, packed)]`
   and exactly 256 bytes. Never change the size, field order, or alignment.
6. **Streaming I/O for large artifacts** — Never load entire files into memory.
   Use `hash_reader` for SHA-256 hashing of potentially large artifacts.

## 2. DEPENDENCY RULES

1. **No GPL/AGPL dependencies** — `deny.toml` enforces this. Never add a crate
   with a copyleft license.
2. **No `serde` in core** — `origin-core` uses manual `Display` impls and
   `bytemuck` for serialization. Serde pulls in proc-macros and bloats WASM.
3. **No `thiserror` or `anyhow` in core** — Use manual `Display` + `From`
   impls. These crates are `std`-dependent.
4. **Prefer `hashbrown` over `std::collections`** — `hashbrown` works in
   `no_std` with the `alloc` feature.
5. **Pin all workspace dependencies** — Use exact versions or `workspace = true`
   references. Never use wildcard (`*`) or `>=` version constraints.

## 3. TESTING REQUIREMENTS

1. **Every public function must have a test** — No exceptions.
2. **Property-based tests for parsers** — Use `proptest` for fuzz-alike
   coverage on `Statement::parse` and `ProofOfOrigin::from_bytes`.
3. **Edge cases** — Always test: empty input, max-length input, null bytes,
   BOM, control characters, non-UTF-8, trailing newline variations, and
   canonical S (signature malleability).
4. **WASM target tested** — CI compiles for `wasm32-unknown-unknown` and runs
   Node.js SDK tests.

## 4. STYLE & FORMAT

1. **No doc comments on private items** — Only public API gets `///` docs.
2. **`cargo fmt` before every commit** — CI enforces `cargo fmt --check`.
3. **`cargo clippy` must pass with `-D warnings`** — All targets, all features.
4. **Error messages are user-facing** — Write clear, actionable error messages
   that begin with a lowercase letter and end without a period.
5. **Use `let`, not `static mut`** — Mutable statics are forbidden.

## 5. PROTOCOL CONSERVATISM

1. **The 5-line `.origin` format is frozen** — `origin: v1`, `hash:`,
   `time:`, `key:`, `sig:`. Never add fields. Never change field order.
2. **The 256-byte binary format is frozen** — Field offsets, sizes, and
   endianness are set in stone. Extensions use the `reserved`/`reserved2`
   fields.
3. **No version negotiation** — Protocol version `0x01` only. Future versions
   are separate crates.
4. **Backward compatibility is law** — Any `.origin` file created by v1.0.0
   must verify correctly in all future versions.

## 6. SECURITY REQUIREMENTS

1. **Zeroize secrets on drop** — All secret key types must derive or implement
   `ZeroizeOnDrop` / `Zeroize`.
2. **No `Debug` on secret types** — `SecretKey` does not implement `Debug`.
3. **Reject the identity point** — `validate_public_key` must reject
   `[0u8; 32]` with a clear error.
4. **Use `verify_strict`** — Ed25519 verification must use `verify_strict` to
   reject malleable signatures.
5. **Constant-time base64 decode** — Use `base64` crate's `URL_SAFE` engine
   (not naive lookup tables).
