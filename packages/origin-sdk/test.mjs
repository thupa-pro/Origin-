// SPDX-License-Identifier: MIT

import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const wasmPath = new URL("./bin/origin-core.wasm", import.meta.url).pathname;

async function loadWasm() {
  const bytes = readFileSync(wasmPath);
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module, {});
  return instance.exports;
}

describe("origin-core WASM", () => {
  it("exports expected symbols", async () => {
    const wasm = await loadWasm();
    assert.equal(typeof wasm.memory, "object");
    assert.equal(typeof wasm.origin_alloc, "function");
    assert.equal(typeof wasm.origin_free_buffer, "function");
    assert.equal(typeof wasm.origin_sign, "function");
    assert.equal(typeof wasm.origin_verify, "function");
  });

  it("alloc and free work", async () => {
    const wasm = await loadWasm();
    const p = wasm.origin_alloc(64);
    assert.ok(p > 0);
    wasm.origin_free_buffer(p, 64);
  });

  it("sign and verify round-trip", async () => {
    const wasm = await loadWasm();
    const secret = new Uint8Array(32).fill(42);
    const artifact = new TextEncoder().encode("Hello, World!");

    const secPtr = wasm.origin_alloc(32);
    const artPtr = wasm.origin_alloc(artifact.length);
    const outLenPtr = wasm.origin_alloc(4);

    const mem = new Uint8Array(wasm.memory.buffer);
    mem.set(secret, secPtr);
    mem.set(artifact, artPtr);

    const resultPtr = wasm.origin_sign(
      secPtr, 32, artPtr, artifact.length, BigInt(1000), outLenPtr,
    );

    assert.notEqual(resultPtr, 0, "sign should not return null");

    const outLen = new Uint32Array(wasm.memory.buffer, outLenPtr, 1)[0];
    const statement = new Uint8Array(wasm.memory.buffer, resultPtr, outLen).slice();

    wasm.origin_free_buffer(secPtr, 32);
    wasm.origin_free_buffer(artPtr, artifact.length);
    wasm.origin_free_buffer(resultPtr, outLen);
    wasm.origin_free_buffer(outLenPtr, 4);

    assert.ok(outLen > 100, "statement should be substantial");
    assert.ok(statement.includes(0x0a), "statement should contain newlines");

    // Verify
    const stmtPtr = wasm.origin_alloc(statement.length);
    const art2Ptr = wasm.origin_alloc(artifact.length);
    const mem2 = new Uint8Array(wasm.memory.buffer);
    mem2.set(statement, stmtPtr);
    mem2.set(artifact, art2Ptr);

    const verifyOk = wasm.origin_verify(
      stmtPtr, statement.length, art2Ptr, artifact.length,
    );
    assert.equal(verifyOk, 0, "verify should succeed");

    wasm.origin_free_buffer(stmtPtr, statement.length);
    wasm.origin_free_buffer(art2Ptr, artifact.length);
  });

  it("verify rejects tampered data", async () => {
    const wasm = await loadWasm();
    const secret = new Uint8Array(32).fill(7);
    const artifact = new TextEncoder().encode("original");

    const secPtr = wasm.origin_alloc(32);
    const artPtr = wasm.origin_alloc(8);
    const outLenPtr = wasm.origin_alloc(4);

    const mem = new Uint8Array(wasm.memory.buffer);
    mem.set(secret, secPtr);
    mem.set(artifact, artPtr);

    const resultPtr = wasm.origin_sign(
      secPtr, 32, artPtr, 8, BigInt(2000), outLenPtr,
    );

    const outLen = new Uint32Array(wasm.memory.buffer, outLenPtr, 1)[0];
    const statement = new Uint8Array(wasm.memory.buffer, resultPtr, outLen).slice();

    wasm.origin_free_buffer(secPtr, 32);
    wasm.origin_free_buffer(artPtr, 8);
    wasm.origin_free_buffer(resultPtr, outLen);
    wasm.origin_free_buffer(outLenPtr, 4);

    // Verify with wrong artifact
    const tampered = new TextEncoder().encode("tampered");
    const stmtPtr = wasm.origin_alloc(statement.length);
    const tamPtr = wasm.origin_alloc(tampered.length);
    const mem2 = new Uint8Array(wasm.memory.buffer);
    mem2.set(statement, stmtPtr);
    mem2.set(tampered, tamPtr);

    const verifyBad = wasm.origin_verify(
      stmtPtr, statement.length, tamPtr, tampered.length,
    );
    assert.notEqual(verifyBad, 0, "verify should fail for tampered data");

    wasm.origin_free_buffer(stmtPtr, statement.length);
    wasm.origin_free_buffer(tamPtr, tampered.length);
  });
});
