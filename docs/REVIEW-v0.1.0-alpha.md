# Protocol Primitive Review — v0.1.0-alpha

**Reviewer:** Origin Founding Team  
**Date:** 2026-06-08  
**Against:** `v0.1.0-alpha` (commit `84e64ad`)  
**Repository:** `github.com/thupa-pro/Origin`

---

## Core Question

> Is a signed provenance statement (hash + public key + timestamp + signature)
> the correct primitive?

**Verdict: Yes, with one open question about the timestamp.**

The quadruple `(hash, pubkey, time, sig)` is the minimum set of fields that
produces a meaningful provenance statement:

| Field | Removed? | Consequence |
|---|---|---|
| `hash` | Bind artifact to claim → broken | Statement proves nothing about any artifact |
| `pubkey` | Identify signer → broken | Verifier can't know who signed |
| `time` | Provide temporal context → weakened | Statement still proves "key X signed hash Y," but you lose all ordering |
| `sig` | Cryptographic binding → broken | Statement is just metadata, forgeable by anyone |

The timestamp is the only field worth debating. It is **self-asserted** (the
signer can lie about it), but it serves two purposes:

1. **Context**: "I signed this in 2024" vs. "no time claimed"
2. **Ordering**: Within a known key's statements, timestamps provide sequence

If timestamp were removed, `(hash, pubkey, sig)` would still be a valid
provenance statement — it just loses temporal information. **Keep it**,
because removing it would force every user to re-add it as application-level
metadata (which would be unsigned and forgeable). Having it signed is better.

**Recommendation**: Timestamp stays. Document the self-asserted nature more
prominently.

---

## What Can Be Removed?

| Component | Keep? | Rationale |
|---|---|---|
| Base64 padding requirement (`=` chars) | 🔶 Optional | Drop padding, accept both. Validated length is the same either way. |
| `hash_bytes` in `Statement` struct | 🔶 Recompute on demand | Currently stored redundantly. Can compute from `hash` field when needed. |
| `raw_lines` in `Statement` struct | ✅ Keep | Required for canonical body reconstruction that matches input byte-for-byte. |
| `origin-cli` vs. `origin-core` split | ✅ Keep | Library/binary separation is correct for ecosystem growth. |
| Timestamp max (year 9999) | ✅ Keep | Defense-in-depth bound. |
| Control character rejection | ✅ Keep | Security-critical — parser must be strict. |
| BOM rejection | ✅ Keep | Simplicity. |

## What Assumptions Exist?

| Assumption | Risk | Status |
|---|---|---|
| Ed25519 existential unforgeability | Standard crypto assumption. Quantum-insecure, but acceptable for alpha. | **Documented** |
| SHA-256 collision resistance | Standard crypto assumption. Acceptable for alpha. | **Documented** |
| Signer controls their clock | Timestamp lying. Accepted by design. | **Documented** |
| Verifier obtains the correct public key | Key distribution is out-of-scope. The protocol does not help. | **Documented** |
| Filesystem has not been tampered with between read and verify | TOCTOU race documented in threat model. | **Documented** |
| base64url decode produces exactly 32/64 bytes | Verified by decoded-length check (fixed in current HEAD). | **Tested** |
| The secret key seed is the same as the Ed25519 secret key | True per RFC 8032. ed25519-dalek expects the seed as input. | **Verified** |
| Ed25519 key derivation from seed is deterministic | True. Tested by `test_deterministic_key_generation`. | **Tested** |

## What Could Be Attacked?

| Attack | Severity | Mitigation |
|---|---|---|
| Signature forgery via weak Ed25519 implementation | Critical | `ed25519-dalek` — audited, constant-time, formally verified curve ops |
| Hash collision | Critical (if successful) | 128-bit collision bound — computationally infeasible |
| Parser injection (control chars, BOM, CR, null, non-UTF-8) | High | All rejected at parse time. 28 negative tests. |
| Decoded-length mismatch (44 chars → 33 bytes) | Medium | Fixed in `validate_base64url` (HEAD) |
| Side-channel via signature verification timing | Medium | `ed25519-dalek` constant-time. System-level timing remains. |
| TOCTOU (read file, hash file, verify against statement) | Medium | Documented. Core API operates on bytes, not paths. |
| Key compromise (stolen secret key file) | High | OS-level file permissions (0o600). Zeroized on drop. Env var alternative. |
| Replay: use statement with wrong artifact | None | Hash check binds statement to artifact |
| Replay: modify timestamp | None | Timestamp is part of canonical body — sig breaks |

## What Is Unnecessary?

| Component | Assessment |
|---|---|
| `audit` module's ISO 8601 conversion | Could move to CLI-only. Library is pure crypto. |
| `Keypair` struct in public API | Callers only need `SecretKey` and `PublicKey`. `Keypair` is a convenience for `keygen`. Keep for ergonomics. |
| `hash_bytes` return `[u8; 32]` | Fine. But `hash_hex` is what callers typically need. |
| `base64_encode`/`base64_decode` in public API | Exposed from lib.rs. Internal to the library. Could be private. |
| `Error::Message(String)` variant | Catch-all that bypasses structured error types. Remove or constrain. |

## What's Missing?

| Gap | Severity | Action |
|---|---|---|
| Fuzz testing (random bytes as input) | Medium | Add `cargo fuzz` target for parser |
| Property-based testing (proptest) | Low | Model-based tests: "for any valid statement, parse(encode(s)) == s" |
| No `--help` examples in CLI | Low | Add usage examples to clap help strings |
| No CI configuration | Medium | Add `.github/workflows/ci.yml` for `cargo test` on push |
| No `cargo audit` check | Medium | Add to CI: `cargo install cargo-audit && cargo audit` |
| No `ORIGIN_KEY` env var documented in `--help` | Low | Add to clap help |
| No `--key -` (stdin) documented in `--help` | Low | Add to clap help |

---

## Primitive Stability Assessment

```
Source format:           STABLE (text, colon-separated, 5 lines)
Canonical body format:   STABLE (lines 1-4 verbatim, no trailing newline)
Hash algorithm:          STABLE (SHA-256)
Signature algorithm:     STABLE (Ed25519)
Timestamp format:        STABLE (UNIX epoch integer)
API surface:             ALPHA (may change)
CLI interface:           ALPHA (may change)
```

The wire format (statement file) and canonical body construction should be
considered **frozen** from this alpha. Changing either would invalidate all
existing signatures. Hash and signature algorithms can be extended (not replaced)
in future protocol versions.

---

## Verdict

**Publish as alpha.** The primitive is correct. The implementation is sound.
The threat model is honest. The gaps (fuzz testing, CI, proptest) are
infrastructure, not protocol — they don't block a public alpha.

The timestamp debate is the only remaining protocol-level question worth
external review. That's exactly what Issue #1 should raise.

---

## Issue #1 Draft

```markdown
Title: Protocol Primitive Review: Is the signed statement the right primitive?

Question:

The protocol defines one primitive:

    A signed provenance statement (hash + pubkey + timestamp + sig)

Is this the correct atomic primitive for cryptographically verifiable
digital provenance?

Specific sub-questions:

1. Should the timestamp be part of the primitive, or should it be
   application-layer metadata? (It is currently self-asserted — signed
   but not verifiable against any external time source.)

2. Is the 5-line text format the right abstraction, or should the
   protocol define a more structured representation (e.g., JSON,
   CBOR, protobuf) with text as a display layer?

3. What primitives are we missing? (Provenance chains, key delegation,
   aggregate signatures, revocation?)

4. What primitives are we carrying that should be removed?

5. Is SHA-256 sufficient, or should the protocol be hash-agile from
   the start?
```

---

## Final Recommendation

1. ✅ The alpha is ready for public review
2. ✅ The primitive is correct (timestamp stays signed)
3. ✅ No fundamental flaws found in 53 tests
4. ⚠️ Add fuzz testing before beta
5. ⚠️ Add CI before beta
6. ❓ Open Issue #1 for community feedback
