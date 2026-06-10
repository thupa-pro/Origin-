# Glossary

Terms used throughout the Origin protocol documentation.

---

### Advisory Timestamp

A timestamp that is format-validated (must be a valid UNIX epoch integer within range) but NOT covered by the cryptographic signature. Changing the timestamp does NOT invalidate the signature. This is intentional — signing a value you cannot verify is dishonest.

See also: [RFC-0001 §9.3](../RFC-0001.md#93-timestamp-advisory)

### Artifact

Any digital file or byte sequence that can be hashed and signed: a binary, document, container image, dataset, source archive, etc.

### Artifact Hash

A cryptographic digest of the artifact bytes. Origin uses SHA-256, encoded as lowercase hex with the `sha256:` prefix.

Example: `sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

### Canonical Body

The exact byte sequence that is signed and verified. Constructed from selected fields of the statement (origin, type, [parent], hash, key) joined by `\n` with no trailing newline.

Time and sig are excluded from the canonical body.

### Deterministic

Same inputs always produce the same output. For Origin: given the same secret key seed, same artifact bytes, and same timestamp, `build_statement` always produces the identical sequence of bytes. This is verified by tests.

### Ed25519

The Edwards-curve Digital Signature Algorithm per RFC 8032. Origin uses Ed25519 for signing and verification, via the `ed25519-dalek` Rust crate.

### Hash Agility

The ability to support multiple hash algorithms within the same protocol. Origin currently supports SHA-256, identified by the `sha256:` prefix in the hash field. (Earlier versions supported SHA-384 and SHA-512.)

### Provenance

The cryptographically verifiable claim that a specific public key asserts responsibility for a specific artifact at a specific claimed time.

### Provenance Chain

A sequence of provenance statements linked via the `parent` field. Each statement (child) references the hash of a prior statement (parent). The chain forms a DAG that can be traced back to a root statement with no parent.

### Statement

A complete provenance record: a UTF-8 text file containing 6 or 7 key-value lines, ending with `\n`. The statement contains all information needed for verification (hash, key, sig) and is self-contained.

### Statement File

The `.origin` file produced by `origin sign` and consumed by `origin verify`.

### Self-Asserted

A field whose value is claimed by the signer but cannot be independently verified. Origin timestamps are self-asserted — the signer can claim any time.

### Verifier

A party that runs `origin verify` to check whether a statement is cryptographically valid for a given artifact. The verifier must supply the trusted public key — the protocol does not provide it.

### Signer

A party that runs `origin sign` to produce a provenance statement. The signer controls the secret key and chooses the artifact and timestamp.
