// SPDX-License-Identifier: MIT

/**
 * Verify a .origin statement against an artifact.
 * @param statementBytes - The .origin statement as bytes
 * @param artifactBytes - The artifact data to verify
 * @returns true if the statement is valid for the given artifact
 */
export function verify(
  statementBytes: Uint8Array,
  artifactBytes: Uint8Array,
): Promise<boolean>;

/**
 * Sign an artifact, producing a .origin statement.
 * @param secretKey - 32-byte Ed25519 seed
 * @param artifactBytes - The artifact data to sign
 * @param timestamp - Unix timestamp
 * @returns The encoded .origin statement as bytes
 */
export function sign(
  secretKey: Uint8Array,
  artifactBytes: Uint8Array,
  timestamp: number | bigint,
): Promise<Uint8Array>;
