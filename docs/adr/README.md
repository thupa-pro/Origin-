# ADR-0001: Text Format for Statements

**Status:** Accepted  
**Date:** 2026-06-07

## Context

The statement format must be:
- Human-readable
- Parseable without a schema
- Deterministic (byte-for-byte reproducible)
- Self-describing

## Decision

Use colon-separated key-value lines, one per field, with `\n` line endings. Format: `<key>: <value>\n`.

## Consequences

- Any language can parse with `split(": ")` and `split("\n")`
- Byte-for-byte reproducibility requires strict line ordering
- No schema, no parser generator, no codec
- Self-describing: a reader can infer meaning from key names

---

# ADR-0002: Advisory Timestamp

**Status:** Accepted  
**Date:** 2026-06-08

## Context

The timestamp is included in the statement but cannot be verified against any external source. Should it be signed?

## Decision

The timestamp is NOT included in the canonical body. It is format-validated (must be valid UNIX epoch within range) but not covered by the signature.

## Consequences

- Changing the timestamp does not invalidate the signature
- Honest: the protocol does not sign what it cannot prove
- The timestamp remains useful for context and ordering within a key's statements
- Verifiers can still reject obviously invalid timestamps

---

# ADR-0003: Parent Field for Provenance Chains

**Status:** Accepted  
**Date:** 2026-06-08

## Context

Single statements prove one thing: "key X signed hash Y." To prove "key X signed hash Y, which itself is a claim about artifact Z," we need chaining.

## Decision

Add an optional `parent` field containing the hash of a prior statement. When present, the canonical body includes the parent field.

## Consequences

- Creates verifiable provenance chains (DAGs)
- The parent field is covered by the signature
- Root statements (no parent) are valid — not every statement needs a parent
- Chain verification is not automated — user must collect and verify each link

---

# ADR-0004: Hash Agility

**Status:** Accepted  
**Date:** 2026-06-08

## Context

SHA-256 is sufficient today but may not be forever. A changing hash algorithm should not require a new protocol version.

## Decision

The hash field uses prefix notation: `<algorithm>:<hex>`. Supported: `sha256`, `sha384`, `sha512`. The signature covers the algorithm prefix.

## Consequences

- New hash algorithms can be added without format changes
- The verification algorithm reads the prefix to choose the hash function
- The canonical body includes the full hash string including prefix
- Not all algorithms are supported by all implementations (graceful error on unknown)

---

# ADR-0005: Type Field

**Status:** Accepted  
**Date:** 2026-06-08

## Context

The protocol needs to grow. New statement types (revocation, delegation, manifests) should not require a format break.

## Decision

Add a `type: provenance` field as line 2 of every statement. The type field is included in the canonical body. Only `provenance` is accepted in v1.1.0.

## Consequences

- Future statement types use the same format, same parser, same verification algorithm
- Existing parsers reject unknown types with a clear error
- Type is part of the signed canonical body — cannot be tampered
- Minimal cost: one line in the format, one check in the parser

---

# ADR-0006: No Revocation in Core

**Status:** Accepted  
**Date:** 2026-06-08

## Context

Key compromise is a real problem. Should the protocol include revocation as a built-in statement type?

## Decision

Revocation is NOT included in the core protocol. It is deferred to application-layer convention.

## Consequences

- The protocol stays minimal (one statement type, one verification path)
- Revocation can be implemented as: "create a provenance statement whose artifact is a revocation notice"
- No branching in the verifier, no time-window semantics, no cognitive load
- Revocation can be added later via the `type` field without breaking anything

---

# ADR-0007: Ed25519 and No Key Infrastructure

**Status:** Accepted  
**Date:** 2026-06-07

## Context

The protocol needs a signature scheme. It should NOT depend on any external infrastructure (CA, PKI, key servers).

## Decision

Use Ed25519 (RFC 8032) via the `ed25519-dalek` Rust crate. The public key is bare (no certificate, no chain). Key distribution is entirely outside the protocol.

## Consequences

- No dependency on CA infrastructure, certificate expiry, or revocation lists
- The verifier must obtain the trusted public key through an external channel
- Keys cannot be mapped to real-world identities within the protocol
- Key compromise is total — no recovery mechanism (by design)
