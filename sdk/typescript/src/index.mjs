import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasmPath = require.resolve("../bin/origin-core.wasm");

let loaded = null;

async function loadWasm() {
  if (loaded) return loaded;
  loaded = (async () => {
    const bytes = readFileSync(wasmPath);
    const module = await WebAssembly.compile(bytes);
    const instance = await WebAssembly.instantiate(module, {});
    return instance.exports;
  })();
  return loaded;
}

export async function verify(statementBytes, artifactBytes) {
  const wasm = await loadWasm();

  const stmtPtr = wasm.origin_alloc(statementBytes.length);
  const artPtr = wasm.origin_alloc(artifactBytes.length);

  // Capture buffer before any operations
  const mem = new Uint8Array(wasm.memory.buffer);
  mem.set(statementBytes, stmtPtr);
  mem.set(artifactBytes, artPtr);

  const result = wasm.origin_verify(
    stmtPtr,
    statementBytes.length,
    artPtr,
    artifactBytes.length,
  );

  // Free after the call completes
  wasm.origin_free_buffer(stmtPtr, statementBytes.length);
  wasm.origin_free_buffer(artPtr, artifactBytes.length);

  return result === 0;
}

export async function sign(secretKey, artifactBytes, timestamp) {
  const wasm = await loadWasm();

  const secretPtr = wasm.origin_alloc(secretKey.length);
  const artPtr = wasm.origin_alloc(artifactBytes.length);

  const mem = new Uint8Array(wasm.memory.buffer);
  mem.set(secretKey, secretPtr);
  mem.set(artifactBytes, artPtr);

  // Allocate space for output length (4 bytes for u32/32-bit usize on WASM)
  const outLenPtr = wasm.origin_alloc(4);

  const resultPtr = wasm.origin_sign(
    secretPtr,
    secretKey.length,
    artPtr,
    artifactBytes.length,
    BigInt(timestamp),
    outLenPtr,
  );

  wasm.origin_free_buffer(secretPtr, secretKey.length);
  wasm.origin_free_buffer(artPtr, artifactBytes.length);

  if (resultPtr === 0) {
    wasm.origin_free_buffer(outLenPtr, 4);
    throw new Error("signing failed");
  }

  // Read output length and result bytes with FRESH buffer views
  const freshMem = new Uint8Array(wasm.memory.buffer);
  const outLen = new Uint32Array(wasm.memory.buffer, outLenPtr, 1)[0];
  const result = freshMem.slice(resultPtr, resultPtr + outLen);

  wasm.origin_free_buffer(resultPtr, outLen);
  wasm.origin_free_buffer(outLenPtr, 4);

  return result;
}
