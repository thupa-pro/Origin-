import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasmPath = require.resolve("../bin/origin-core.wasm");

interface OriginExports {
  origin_alloc: (size: number) => number;
  origin_verify: (
    statementPtr: number,
    statementLen: number,
    artifactPtr: number,
    artifactLen: number,
  ) => number;
  origin_sign: (
    secretPtr: number,
    secretLen: number,
    artifactPtr: number,
    artifactLen: number,
    timestamp: number,
    outLen: number,
  ) => number;
  origin_free_buffer: (ptr: number, len: number) => void;
  memory: WebAssembly.Memory;
}

let loaded: Promise<OriginExports> | null = null;

function loadWasm(): Promise<OriginExports> {
  if (loaded) return loaded;
  loaded = (async () => {
    const bytes = readFileSync(wasmPath);
    const module = await WebAssembly.compile(bytes);
    const instance = await WebAssembly.instantiate(module, {});
    return instance.exports as unknown as OriginExports;
  })();
  return loaded;
}

export async function verify(
  statementBytes: Uint8Array,
  artifactBytes: Uint8Array,
): Promise<boolean> {
  const wasm = await loadWasm();

  const stmtPtr = wasm.origin_alloc(statementBytes.length);
  const artPtr = wasm.origin_alloc(artifactBytes.length);

  const mem = new Uint8Array(wasm.memory.buffer);
  mem.set(statementBytes, stmtPtr);
  mem.set(artifactBytes, artPtr);

  const result = wasm.origin_verify(
    stmtPtr,
    statementBytes.length,
    artPtr,
    artifactBytes.length,
  );

  wasm.origin_free_buffer(stmtPtr, statementBytes.length);
  wasm.origin_free_buffer(artPtr, artifactBytes.length);

  return result === 0;
}

export async function sign(
  secretKey: Uint8Array,
  artifactBytes: Uint8Array,
  timestamp: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();

  const secretPtr = wasm.origin_alloc(secretKey.length);
  const artPtr = wasm.origin_alloc(artifactBytes.length);

  const mem = new Uint8Array(wasm.memory.buffer);
  mem.set(secretKey, secretPtr);
  mem.set(artifactBytes, artPtr);

  // Allocate space for the output length value (8 bytes for usize)
  const outLenPtr = wasm.origin_alloc(8);
  const outLenView = new Uint32Array(wasm.memory.buffer, outLenPtr, 2);

  const resultPtr = wasm.origin_sign(
    secretPtr,
    secretKey.length,
    artPtr,
    artifactBytes.length,
    timestamp,
    outLenPtr,
  );

  wasm.origin_free_buffer(secretPtr, secretKey.length);
  wasm.origin_free_buffer(artPtr, artifactBytes.length);

  if (resultPtr === 0) {
    wasm.origin_free_buffer(outLenPtr, 8);
    throw new Error("signing failed");
  }

  const outLen = outLenView[0];
  const result = new Uint8Array(
    wasm.memory.buffer,
    resultPtr,
    outLen,
  ).slice();

  wasm.origin_free_buffer(resultPtr, outLen);
  wasm.origin_free_buffer(outLenPtr, 8);

  return result;
}
